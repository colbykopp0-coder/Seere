"""Offline, one-shot module containers. Inputs and scope come from explicit mounts."""
import argparse
import json
import os
from pathlib import Path
from .core import ScanConfig, SeereScanner
from .detection import inspect_text
from .security import load_key, safe_read
from .rag import scan_rag, GuardedRAG
from .orchestration import envelope, correlate, load_reports


def runtime_gate(text, stage, key):
    return GuardedRAG(key).gate(text, stage)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('module', choices=['code','local','rag','runtime','coordinator'])
    parser.add_argument('--input', default='/scope')
    parser.add_argument('--output', required=True)
    parser.add_argument('--manifest', required=True)
    args = parser.parse_args()
    manifest_path = Path(args.manifest).absolute()
    manifest = json.loads(safe_read(manifest_path.parent, manifest_path.name, 65536))
    if args.module == 'coordinator':
        report = correlate(load_reports(args.input, manifest), manifest['expected_modules'], manifest['run_id'])
    else:
        key = load_key(os.environ['SEERE_FINGERPRINT_KEY_FILE'])
        if args.module in {'code','local'}:
            report = SeereScanner(ScanConfig(fingerprint_key=key, scan_git_history=args.module=='code',
                allowed_roots=(args.input,))).scan(args.input).to_dict()
        elif args.module == 'rag':
            report = scan_rag(args.input, key)
        else:
            path = Path(args.input).absolute()
            report = runtime_gate(safe_read(path.parent, path.name, 2_000_000).decode(), 'before_agent', key)
        report = envelope(args.module, manifest['run_id'], key, report)
    Path(args.output).write_text(json.dumps(report, indent=2), encoding='utf-8')
    if not report['complete']:
        raise SystemExit(2)


if __name__ == '__main__':
    main()
