"""Authorization, stable keys, and bounded reads; no model participates here."""
import hashlib
import os
from pathlib import Path
import secrets
import stat


class ScopeError(ValueError):
    pass


def authorize(path, roots):
    target = Path(path).absolute()
    resolved = target.resolve(strict=True)
    if not any(resolved == Path(r).resolve() or resolved.is_relative_to(Path(r).resolve()) for r in roots):
        raise ScopeError('outside_authorized_roots')
    return resolved


def key_id(key):
    return hashlib.sha256(key).hexdigest()[:16]


def load_key(path=None):
    path = Path(path or os.environ.get('SEERE_FINGERPRINT_KEY_FILE', '.seere/fingerprint.key')).absolute()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink():
        raise ScopeError('key_must_not_be_symlink')
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(fd, 'wb') as out:
            out.write(secrets.token_bytes(32))
    if os.name != 'nt' and path.stat().st_mode & 0o077:
        raise ScopeError('key_permissions_must_be_0600')
    value = safe_read(path.parent, path.name, 64)
    if len(value) != 32:
        raise ValueError('Fingerprint key must be exactly 32 random bytes')
    return value


def is_link(path):
    st = path.lstat()
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, 'st_file_attributes', 0) & 0x400)


def safe_read(root, relative, limit):
    """POSIX: anchor each open to an open directory; reject all symlinks.

    Windows: reject reparse points and verify the actual opened handle path
    before reading. Refuse hard links on both platforms.
    """
    root = Path(root).resolve(strict=True)
    rel = Path(relative)
    if rel.is_absolute() or '..' in rel.parts or not rel.parts:
        raise ScopeError('invalid_relative_path')
    if os.name == 'posix':
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for part in rel.parts[:-1]:
                following = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                os.close(directory)
                directory = following
            fd = os.open(rel.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        finally:
            os.close(directory)
    else:
        current = root
        for part in rel.parts:
            current = current / part
            if is_link(current):
                raise ScopeError('link_excluded')
        fd = os.open(current, os.O_RDONLY | getattr(os, 'O_BINARY', 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ScopeError('non_regular_or_hardlinked_file')
        if os.name == 'nt':
            import ctypes
            import msvcrt
            from ctypes import wintypes
            final_path = ctypes.WinDLL('kernel32', use_last_error=True).GetFinalPathNameByHandleW
            final_path.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
            final_path.restype = wintypes.DWORD
            buffer = ctypes.create_unicode_buffer(32768)
            size = final_path(msvcrt.get_osfhandle(fd), buffer, len(buffer), 0)
            if not size or size >= len(buffer):
                raise ScopeError('handle_path_unavailable')
            actual = buffer.value
            if actual.startswith('\\\\?\\UNC\\'):
                actual = '\\\\' + actual[8:]
            elif actual.startswith('\\\\?\\'):
                actual = actual[4:]
            if not Path(actual).resolve().is_relative_to(root):
                raise ScopeError('opened_handle_outside_scope')
        if info.st_size > limit:
            raise ScopeError('file_too_large')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            result = stream.read(limit + 1)
        if len(result) > limit:
            raise ScopeError('file_too_large')
        return result
    finally:
        os.close(fd)
