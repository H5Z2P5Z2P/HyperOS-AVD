"""Build and load the owned OS4 emulator's macOS sRGB window tag."""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile

from common import REPO_ROOT, sha256

LIBRARY = 'emulator_srgb.dylib'
RECEIPT = 'emulator_srgb.build.json'
INSTALL_NAME = '@rpath/' + LIBRARY


def validate_library(data):
    """Reject nonportable or malformed ARM64 Mach-O release attachments."""
    if (len(data) < 32 or struct.unpack_from('<I', data)[0] != 0xfeedfacf
            or struct.unpack_from('<I', data, 4)[0] != 0x100000c
            or struct.unpack_from('<I', data, 12)[0] != 6):
        raise RuntimeError('Invalid owned sRGB Mach-O dylib.')
    count, size = struct.unpack_from('<II', data, 16)
    end = 32 + size
    if end > len(data) or count > size // 8:
        raise RuntimeError('Invalid sRGB Mach-O load-command bounds.')
    names, offset = [], 32
    for _ in range(count):
        if offset + 8 > end:
            raise RuntimeError('Truncated sRGB Mach-O load command.')
        command, length = struct.unpack_from('<II', data, offset)
        if length < 8 or length % 8 or offset + length > end:
            raise RuntimeError('Invalid sRGB Mach-O load-command size.')
        if command == 0xd:  # LC_ID_DYLIB
            if length < 24:
                raise RuntimeError('Truncated sRGB dylib identity.')
            position = struct.unpack_from('<I', data, offset + 8)[0]
            if not 24 <= position < length:
                raise RuntimeError('Invalid sRGB dylib identity offset.')
            value = data[offset + position:offset + length]
            if b'\0' not in value:
                raise RuntimeError('Unterminated sRGB dylib identity.')
            names.append(value.split(b'\0', 1)[0])
        offset += length
    if offset != end or names != [INSTALL_NAME.encode()]:
        raise RuntimeError('Nonportable sRGB install name; rebuild the attachment.')
    if any(prefix in data for prefix in (b'/Users/', b'/Volumes/', b'/home/')):
        raise RuntimeError('Private host path in sRGB attachment; rebuild required.')
    return INSTALL_NAME


def build(root):
    """Reuse verified release binaries; only source builds need Command Line Tools."""
    source = REPO_ROOT / 'native/emulator_srgb.m'
    source_digest = hashlib.sha256(source.read_bytes()).hexdigest()
    directory = Path(root) / 'tools'
    library, receipt = directory / LIBRARY, directory / RECEIPT
    if library.is_symlink() or receipt.is_symlink():
        raise RuntimeError('Refused a symlink sRGB attachment.')
    if library.is_file() and receipt.is_file():
        try:
            data = library.read_bytes()
            validate_library(data)
            expected = {'source_sha256': source_digest,
                        'sha256': hashlib.sha256(data).hexdigest(), 'install_name': INSTALL_NAME}
            verified = json.loads(receipt.read_text()) == expected
        except (ValueError, RuntimeError):
            verified = False
        if verified:
            return library, receipt
    directory.mkdir(parents=True, exist_ok=True)
    # Build and verify away from the existing inode. A failed compiler or
    # malformed output leaves the previous library and receipt untouched.
    with tempfile.TemporaryDirectory(prefix='.emulator-srgb-', dir=directory) as folder:
        temporary = Path(folder) / LIBRARY
        subprocess.run(['xcrun', 'clang', '-dynamiclib', '-fobjc-arc', '-Wall', '-Wextra',
                        '-Werror', '-arch', 'arm64', '-mmacosx-version-min=12.0',
                        '-Wl,-install_name,' + INSTALL_NAME,
                        '-framework', 'AppKit', '-framework', 'QuartzCore', str(source),
                        '-o', str(temporary)], check=True)
        validate_library(temporary.read_bytes())
        metadata = {'source_sha256': source_digest, 'sha256': sha256(temporary),
                    'install_name': INSTALL_NAME}
        temporary_receipt = Path(folder) / RECEIPT
        temporary_receipt.write_text(json.dumps(metadata, indent=2) + '\n')
        temporary.replace(library)
        temporary_receipt.replace(receipt)
    return library, receipt


def cached_library(library, receipt):
    """Load only this verified hook from owned storage before app initialization."""
    from host_launch import job_directory, owned_directory, owned_file, write_private
    if library.is_symlink() or receipt.is_symlink():
        raise RuntimeError('Refused an aliased sRGB cache source.')
    data = library.read_bytes()
    validate_library(data)
    metadata = {'source_sha256': hashlib.sha256((REPO_ROOT / 'native/emulator_srgb.m').read_bytes()).hexdigest(),
                'sha256': hashlib.sha256(data).hexdigest(), 'install_name': INSTALL_NAME}
    if json.loads(receipt.read_text()) != metadata:
        raise RuntimeError('Unverified sRGB cache source receipt.')
    parent = job_directory().parent / 'host-color'
    owned_directory(parent, private=True)
    directory = parent / metadata['sha256']
    owned_directory(directory, private=True)
    cached, cached_receipt = directory / LIBRARY, directory / RECEIPT
    for path in (cached, cached_receipt):
        if path.exists() or path.is_symlink():
            owned_file(path)
    if cached.exists() and cached.read_bytes() != data:
        raise RuntimeError('Owned sRGB cache content was modified; it was preserved.')
    if cached_receipt.exists():
        try:
            recorded = json.loads(cached_receipt.read_text())
        except ValueError as error:
            raise RuntimeError('Owned sRGB cache receipt was modified; it was preserved.') from error
        if recorded != metadata:
            raise RuntimeError('Owned sRGB cache receipt was modified; it was preserved.')
    if not cached.exists():
        write_private(cached, data)
    if not cached_receipt.exists():
        write_private(cached_receipt, (json.dumps(metadata, sort_keys=True) + '\n').encode())
    return cached


def environment(root, name, enabled=True):
    """Keep the SDK and other emulator processes unchanged."""
    result = os.environ.copy()
    # A copied opt-in from an earlier launch cannot authorize another instance
    # or override this launch's explicit opt-out.
    result.pop('HYPEROS_AVD_SRGB', None)
    result.pop('HYPEROS_AVD_SRGB_AVD', None)
    if not enabled or not (Path(root) / 'local/build.json').is_file() or json.loads(
            (Path(root) / 'local/build.json').read_text()).get('source') not in (
                'official-hongkong-ota', 'official-yingtian-ota'):
        return result
    if not isinstance(name, str) or not name:
        raise RuntimeError('The sRGB tag requires the owned launch AVD name.')
    library, receipt = build(root)
    cached = cached_library(library, receipt)
    injected = result.get('DYLD_INSERT_LIBRARIES', '')
    # Replace/deduplicate only our authenticated hook. User-provided libraries
    # remain in their original order and are never copied or modified.
    owned_paths = {str(library.resolve()), str(cached.resolve())}
    remaining = [value for value in injected.split(':') if value not in owned_paths and value]
    result['DYLD_INSERT_LIBRARIES'] = ':'.join([str(cached.resolve()), *remaining])
    result['HYPEROS_AVD_SRGB'] = '1'
    result['HYPEROS_AVD_SRGB_AVD'] = name
    return result
