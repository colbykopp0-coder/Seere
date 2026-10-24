from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from collections import defaultdict
import os
import subprocess
import threading

from .models import Finding, ScanReport
from .detection import inspect_text
from .security import authorize, load_key, key_id, safe_read, is_link

IGNORES = {'.git', '.hg', '.svn', 'node_modules', 'vendor', '.venv', 'venv', '__pycache__', 'dist', 'build', '.next', '.cache', '.seere'}

@dataclass
class ScanConfig:
    fingerprint_key: bytes = field(default_factory=load_key)
    max_file_bytes: int = 2_000_000
    scan_git_history: bool = False
    include_hidden: bool = True
    allowed_roots: tuple = ()
    max_commits: int = 100
    max_git_blobs: int = 5000
    git_timeout: int = 15


def bounded_git(root, args, limit, timeout):
    env = {**{k:v for k,v in os.environ.items() if not k.startswith('GIT_')}, 'GIT_NO_LAZY_FETCH':'1', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull,
           'GIT_TERMINAL_PROMPT': '0', 'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_OPTIONAL_LOCKS': '0'}
    for name in list(env):
        if name.startswith(('GIT_CONFIG_KEY_', 'GIT_CONFIG_VALUE_')) or name in {'GIT_CONFIG_COUNT', 'GIT_DIR', 'GIT_WORK_TREE', 'GIT_EXTERNAL_DIFF'}:
            env.pop(name)
    process = subprocess.Popen(['git', '--no-pager', '-c', 'safe.directory=' + str(root), '-C', str(root), *args],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
    output = bytearray()
    overflow = []
    def consume():
        while True:
            chunk = process.stdout.read(65536)
            if not chunk:
                break
            if len(output) + len(chunk) > limit:
                overflow.append(True)
                process.kill()
                break
            output.extend(chunk)
    reader = threading.Thread(target=consume, daemon=True)
    reader.start()
    try:
        process.wait(timeout=timeout)
        reader.join(timeout=timeout)
        if overflow or reader.is_alive() or process.returncode:
            raise ValueError('git_failed_or_limit_exceeded')
        return bytes(output)
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        reader.join(timeout=1)
        process.stdout.close()


class SeereScanner:
    def __init__(self, config=None):
        self.config = config or ScanConfig()
        if len(self.config.fingerprint_key) < 32:
            raise ValueError('Fingerprint key requires at least 32 bytes')

    def scan(self, root):
        root = authorize(root, self.config.allowed_roots or (root,))
        if not root.is_dir():
            raise ValueError('Scan root must be a directory')
        self.issues, self.exclusions, self.scanned = [], [], 0
        findings = []
        def walk_error(error):
            self.issues.append({'reason': 'directory_unreadable'})
        for base, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
            accepted = []
            for name in dirs:
                path = Path(base, name)
                try:
                    linked = is_link(path) or not path.resolve().is_relative_to(root)
                except OSError:
                    linked = True
                if linked:
                    self.issues.append({'reason': 'directory_link_excluded', 'path': str(path.relative_to(root))})
                elif name in IGNORES or (not self.config.include_hidden and name.startswith('.')):
                    self.exclusions.append(str(path.relative_to(root)))
                else:
                    accepted.append(name)
            dirs[:] = accepted
            for name in files:
                path = Path(base, name)
                rel = str(path.relative_to(root))
                if not self.config.include_hidden and name.startswith('.'):
                    self.exclusions.append(rel)
                    continue
                try:
                    data = safe_read(root, rel, self.config.max_file_bytes)
                    text = data.decode('utf-8-sig', errors='strict')
                    if '\x00' in text:
                        raise ValueError('binary_file_unsupported')
                except (OSError, ValueError) as error:
                    reason = str(error) if isinstance(error, ValueError) and not isinstance(error, UnicodeError) else 'unreadable_or_unsupported_encoding'
                    self.issues.append({'reason': reason, 'path': rel})
                    continue
                self.scanned += 1
                findings.extend(Finding(**f) for f in inspect_text(text, 'filesystem', rel, self.config.fingerprint_key))
        if self.config.scan_git_history:
            findings.extend(self._scan_git_history(root))
        by_fp = defaultdict(list)
        for finding in findings:
            by_fp[finding.fingerprint].append(finding)
        for group in by_fp.values():
            locations = {(f.source, f.path) for f in group}
            if len(locations) > 1:
                for finding in group:
                    finding.notes.append(f'Same credential appears in {len(locations)} locations.')
        stats = {'complete': not self.issues, 'issues': self.issues, 'excluded_paths': self.exclusions,
            'coverage': 'authorized UTF-8 files excluding declared policy exclusions', 'files_scanned': self.scanned,
            'key_id': key_id(self.config.fingerprint_key), 'total_findings': len(findings),
            'unique_fingerprints': len(by_fp), 'providers': sorted({f.provider for f in findings})}
        stats.update({s.lower(): sum(f.severity == s for f in findings) for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']})
        return ScanReport(str(root), findings, stats)

    def _scan_git_history(self, root):
        findings, seen = [], set()
        try:
            # Reject external worktree metadata and alternates: only mounted repo objects are authorized.
            if not (root / '.git').is_dir() or is_link(root / '.git'):
                raise ValueError('git_metadata_outside_scope_or_missing')
            for base, dirs, files in os.walk(root / '.git', followlinks=False):
                for name in dirs + files:
                    if is_link(Path(base, name)):
                        raise ValueError('git_metadata_link_excluded')
            if (root / '.git/objects/info/alternates').exists():
                raise ValueError('git_alternates_excluded')
            def git(args, limit):
                return bounded_git(root, args, limit, self.config.git_timeout)
            commits = git(['rev-list', '--all', f'--max-count={self.config.max_commits + 1}'], 100_000).decode().splitlines()
            if len(commits) > self.config.max_commits:
                self.issues.append({'reason': 'git_commit_limit'})
                commits = commits[:self.config.max_commits]
            for commit in commits:
                tree = git(['ls-tree', '-r', '-z', commit], 2_000_000)
                for record in tree.split(b'\0'):
                    if not record:
                        continue
                    info, path = record.split(b'\t', 1)
                    mode, kind, oid = info.split()
                    if kind != b'blob' or mode == b'120000':
                        continue
                    identity = (oid, path)
                    if identity in seen:
                        continue
                    seen.add(identity)
                    if len(seen) > self.config.max_git_blobs:
                        raise ValueError('git_blob_limit')
                    size = int(git(['cat-file', '-s', oid.decode()], 100))
                    if size > self.config.max_file_bytes:
                        self.issues.append({'reason': 'git_blob_too_large'})
                        continue
                    blob = git(['cat-file', 'blob', oid.decode()], self.config.max_file_bytes)
                    try:
                        text = blob.decode('utf-8-sig')
                    except UnicodeError:
                        self.issues.append({'reason': 'git_blob_unsupported_encoding'})
                        continue
                    findings.extend(Finding(**f) for f in inspect_text(text, 'git:' + commit,
                        path.decode('utf-8', 'replace'), self.config.fingerprint_key))
        except (OSError, ValueError, subprocess.SubprocessError):
            self.issues.append({'reason': 'git_history_incomplete'})
        return findings
