"""Make the SDK's one redundant timeout update idempotent, without extra grants."""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import sys
import tempfile

from host_launch import job_directory, owned_directory, owned_file, write_private

MAX_ADB = 64 * 1024**2
RECIPE = 1
WRAPPER = '#!/bin/sh\nexec {python} -I -B {script} "$@"\n'
RUNNER = '''"""Delegate to the original SDK ADB, preserving real errors and permissions."""
import hashlib, os, pathlib, re, stat, subprocess, sys
original = pathlib.Path(__ORIGINAL__)
info = original.lstat()
if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o022
        or not 0 < info.st_size <= __MAX_ADB__):
    raise SystemExit('The original SDK ADB changed; prepare a new owned adapter.')
descriptor = os.open(original, os.O_RDONLY | os.O_NOFOLLOW)
with os.fdopen(descriptor, 'rb') as source:
    opened = os.fstat(source.fileno())
    digest = hashlib.sha256(source.read(__MAX_ADB__ + 1)).hexdigest()
    after = os.fstat(source.fileno())
if (digest != __DIGEST__ or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)
        or any(getattr(opened, key) != getattr(after, key) for key in
               ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode', 'st_nlink'))):
    raise SystemExit('The original SDK ADB changed; prepare a new owned adapter.')
arguments = sys.argv[1:]
prefix = ['-s', __SERIAL__, 'shell', 'settings', 'put', 'system', 'screen_off_timeout']
if (len(arguments) == 8 and arguments[:7] == prefix
        and re.fullmatch(r'0|[1-9][0-9]{0,9}', arguments[7])
        and int(arguments[7]) <= 2147483647):
    try:
        result = subprocess.run([str(original), '-s', __SERIAL__, 'shell', 'settings', 'get',
                                 'system', 'screen_off_timeout'], stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip() == arguments[7]:
            raise SystemExit(0)
    except (OSError, subprocess.SubprocessError, UnicodeError):
        pass
os.execv(str(original), [str(original), *arguments])
'''


def _bytes(path, limit=MAX_ADB):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o022
            or not 0 < info.st_size <= limit):
        raise RuntimeError('Refused an unsafe SDK ADB adapter input: ' + str(path))
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    if ((info.st_dev, info.st_ino) != (opened.st_dev, opened.st_ino)
            or len(data) != info.st_size or any(getattr(opened, key) != getattr(after, key) for key in
                ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode', 'st_nlink'))):
        raise RuntimeError('SDK ADB adapter input changed during verification: ' + str(path))
    return data


def _script(original, digest, serial):
    replacements = {'__ORIGINAL__': repr(str(original)), '__DIGEST__': repr(digest),
                    '__SERIAL__': repr(serial), '__MAX_ADB__': str(MAX_ADB)}
    return re.sub(r'__ORIGINAL__|__DIGEST__|__SERIAL__|__MAX_ADB__',
                  lambda match: replacements[match[0]], RUNNER).encode()


def _publish_directory(source, destination):
    """Publish all three completed leaves together without replacing a racing path."""
    import ctypes
    library = ctypes.CDLL(None, use_errno=True)
    rename = getattr(library, 'renamex_np', None)
    if rename is None:
        raise RuntimeError('Atomic SDK ADB adapter publication requires macOS renamex_np.')
    rename.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    # macOS RENAME_EXCL fails even when a racing destination is an empty folder.
    if rename(os.fsencode(source), os.fsencode(destination), 0x4):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), str(destination))


def adapter(sdk, serial):
    """Return an offline private executable for the SDK's documented -adb-path."""
    if not isinstance(serial, str) or not re.fullmatch(r'emulator-[0-9]{4,5}', serial):
        raise RuntimeError('Invalid single-emulator ADB adapter identity.')
    state = job_directory()
    parent = state.parent / 'host-adb'
    owned_directory(parent, private=True)
    original = (Path(sdk).resolve() / 'platform-tools/adb').resolve(strict=True)
    if original.is_relative_to(parent):
        raise RuntimeError('Refused a recursive SDK ADB adapter.')
    data = _bytes(original)
    if not os.access(original, os.X_OK):
        raise RuntimeError('The original SDK ADB is not executable.')
    digest = hashlib.sha256(data).hexdigest()
    runner = _script(original, digest, serial)
    identity = {'schema': RECIPE, 'serial': serial, 'adb': str(original), 'adb_sha256': digest,
                'python': str(Path(sys.executable).resolve()),
                'wrapper_template_sha256': hashlib.sha256(WRAPPER.encode()).hexdigest(),
                'runner_sha256': hashlib.sha256(runner).hexdigest()}
    label = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
    directory = parent / label
    script, launcher, receipt = directory / 'runner.py', directory / 'adb', directory / 'receipt.json'
    wrapper = WRAPPER.format(python=shlex.quote(identity['python']), script=shlex.quote(str(script))).encode()
    expected = (json.dumps(dict(identity, launcher_sha256=hashlib.sha256(wrapper).hexdigest()),
                           sort_keys=True) + '\n').encode()
    if directory.exists() or directory.is_symlink():
        owned_directory(directory, private=True)
        for path, content, mode in ((script, runner, 0o600), (launcher, wrapper, 0o700),
                                    (receipt, expected, 0o600)):
            owned_file(path)
            if stat.S_IMODE(path.stat().st_mode) != mode or _bytes(path, 65536) != content:
                raise RuntimeError('Modified SDK ADB adapter cache was preserved: ' + str(path))
        if set(path.name for path in directory.iterdir()) != {'runner.py', 'adb', 'receipt.json'}:
            raise RuntimeError('Unknown SDK ADB adapter resources were preserved.')
        return launcher
    temporary = Path(tempfile.mkdtemp(prefix='.adb-', dir=parent))
    try:
        write_private(temporary / script.name, runner)
        write_private(temporary / launcher.name, wrapper)
        (temporary / launcher.name).chmod(0o700)
        write_private(temporary / receipt.name, expected)
        _publish_directory(temporary, directory)
    finally:
        # The only disposable path is this invocation's unpublished staging.
        if temporary.exists():
            shutil.rmtree(temporary)
    return launcher
