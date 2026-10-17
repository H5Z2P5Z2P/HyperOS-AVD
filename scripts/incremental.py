"""Create and apply authenticated, portable block deltas using the standard library.

The binary stream is MAGIC, two little-endian uint64 file sizes, then records:
``C offset length`` copies source bytes and ``D length bytes`` emits literals.
Offsets and lengths are uint64 values. ``E`` terminates the stream. Each record
produces at least one 4 KiB block, except the final partial block, so the
uncompressed stream is bounded by patch_limit(target_size). The gzip tar around
the streams provides compression; applying a delta needs no external binary.
"""
import hashlib
import io
import json
from pathlib import Path
import re
import stat
import struct
import tarfile
import tempfile

from common import sha256

PROTOCOL = 'block-delta-v1'
MAGIC = b'HAVDDELTA1\0'
BLOCK = 4 * 1024
MAX_INDEX_BLOCKS = 131072
HEADER_SIZE = len(MAGIC) + 16
UINT64_MAX = 2**64 - 1


def _size(value):
    if type(value) is not int or not 0 <= value <= UINT64_MAX:
        raise RuntimeError('Invalid incremental file size.')
    return value


def patch_limit(target_size):
    """Maximum uncompressed member size, including all record overhead."""
    target_size = _size(target_size)
    return HEADER_SIZE + 1 + target_size + 17 * ((target_size + BLOCK - 1) // BLOCK)


def validate_sources(old, new):
    """Accept forward releases only when their authenticated firmware base agrees."""
    from bundle_runtime import validate_envelope
    validate_envelope(old)
    validate_envelope(new)
    for manifest in (old, new):
        pin = manifest['build'].get('archive_sha256')
        if not isinstance(pin, str) or not re.fullmatch('[0-9a-f]{64}', pin):
            raise RuntimeError('Incremental updates require an authenticated base archive.')
    for key in ('variant', 'platform', 'source', 'source_device', 'android_api', 'hyperos'):
        if old.get(key) != new.get(key):
            raise RuntimeError('Incremental update changes its firmware base: ' + key)
    for key in ('archive_sha256', 'hardware_base_api', 'kernel_page_size', 'kernel_kmi'):
        if old['build'].get(key) != new['build'].get(key):
            raise RuntimeError('Incremental update changes its firmware base: ' + key)
    if old['compatibility']['userdata_family'] != new['compatibility']['userdata_family']:
        raise RuntimeError('Incremental update changes its userdata family.')
    if old['files']['images/encryptionkey.img'] != new['files']['images/encryptionkey.img']:
        raise RuntimeError('Incremental update changes its encryption template.')
    def version(value):
        match = re.match(r'(?:pad-)?v(\d+)\.(\d+)\.(\d+)', value)
        revision = re.search(r'-r(\d+(?:\.\d+)*)$', value)
        if match is None or revision is None:
            raise RuntimeError('Invalid incremental release version.')
        numbers = tuple(map(int, revision.group(1).split('.')))
        while len(numbers) > 1 and numbers[-1] == 0:
            numbers = numbers[:-1]
        return tuple(map(int, match.groups())), numbers
    if version(new['version']) <= version(old['version']):
        raise RuntimeError('Incremental updates require a newer release version.')


def _regular_file(path):
    path = Path(path)
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise RuntimeError('Incremental input must be a regular unaliased file: ' + str(path))
    return metadata.st_size


def _read_exact(stream, size):
    data = bytearray()
    while len(data) < size:
        chunk = stream.read(size - len(data))
        if not chunk:
            raise RuntimeError('Truncated incremental patch.')
        data.extend(chunk)
    return bytes(data)


def write_patch(source, target, output_stream):
    """Write a bounded-memory patch, including COPY runs at moved source offsets."""
    target = Path(target)
    target_size = _regular_file(target)
    source_size = _regular_file(source) if source is not None else 0
    _size(source_size)
    _size(target_size)
    output_stream.write(MAGIC + struct.pack('<QQ', source_size, target_size))
    # A sparse index caps Python object overhead even for multi-GiB images.
    # Target anchors retain 4 KiB alignment when EROFS data moves between builds.
    blocks = source_size // BLOCK
    stride = max(1, (blocks + MAX_INDEX_BLOCKS - 1) // MAX_INDEX_BLOCKS)
    index = {}
    with target.open('rb') as current:
        previous = Path(source).open('rb') if source is not None else io.BytesIO()
        try:
            for block in range(0, blocks, stride):
                offset = block * BLOCK
                previous.seek(offset)
                chunk = previous.read(BLOCK)
                key = hashlib.blake2b(chunk, digest_size=16).digest()
                index.setdefault(key, offset)
            position = 0
            while position < target_size:
                chunk = current.read(min(BLOCK, target_size - position))
                if not chunk:
                    raise RuntimeError('Incremental target changed while reading.')
                offset = index.get(hashlib.blake2b(chunk, digest_size=16).digest())
                length = 0
                if offset is not None:
                    previous.seek(offset)
                    if previous.read(len(chunk)) == chunk:
                        length = len(chunk)
                        while position + length < target_size:
                            candidate = current.read(min(BLOCK, target_size - position - length))
                            if not candidate:
                                raise RuntimeError('Incremental target changed while reading.')
                            if previous.read(len(candidate)) != candidate:
                                break
                            length += len(candidate)
                        current.seek(position + length)
                if length:
                    output_stream.write(b'C' + struct.pack('<QQ', offset, length))
                    position += length
                else:
                    output_stream.write(b'D' + struct.pack('<Q', len(chunk)) + chunk)
                    position += len(chunk)
            output_stream.write(b'E')
        finally:
            previous.close()


def apply_patch(source, patch_stream, output_stream, source_size, target_size):
    """Apply a bounded patch, rejecting malformed records and trailing content."""
    source_size, target_size = _size(source_size), _size(target_size)
    if source is None:
        if source_size:
            raise RuntimeError('Incremental patch requires its source file.')
    elif _regular_file(source) != source_size:
        raise RuntimeError('Incremental source size differs from its manifest.')
    header = _read_exact(patch_stream, HEADER_SIZE)
    if header[:len(MAGIC)] != MAGIC or struct.unpack('<QQ', header[len(MAGIC):]) != (source_size, target_size):
        raise RuntimeError('Incremental patch header differs from its manifest.')
    previous = Path(source).open('rb') if source is not None else io.BytesIO()
    try:
        produced = 0
        while True:
            opcode = _read_exact(patch_stream, 1)
            if opcode == b'E':
                if produced != target_size or patch_stream.read(1):
                    raise RuntimeError('Incremental patch has missing or trailing data.')
                return
            if opcode == b'C':
                offset, length = struct.unpack('<QQ', _read_exact(patch_stream, 16))
                if offset > source_size or length > source_size - offset:
                    raise RuntimeError('Incremental COPY is outside its source file.')
                previous.seek(offset)
                stream = previous
            elif opcode == b'D':
                length, = struct.unpack('<Q', _read_exact(patch_stream, 8))
                stream = patch_stream
            else:
                raise RuntimeError('Unknown incremental patch opcode.')
            remaining = target_size - produced
            if not min(BLOCK, remaining) <= length <= remaining or not length:
                raise RuntimeError('Incremental record is outside its target bounds.')
            count = length
            while count:
                chunk = _read_exact(stream, min(BLOCK, count))
                output_stream.write(chunk)
                count -= len(chunk)
            produced += length
    finally:
        previous.close()


def _verify(path, root, info):
    from bundle_runtime import regular
    regular(path, root)
    if path.stat().st_size != info['size'] or sha256(path) != info['sha256']:
        raise RuntimeError('Incremental input differs from its manifest: ' + str(path))


class _PatchMember(tarfile.TarInfo):
    """Keep USTAR path prefixes and encode large sizes without extra headers."""
    def tobuf(self, format=tarfile.USTAR_FORMAT, encoding=tarfile.ENCODING,
              errors='surrogateescape'):
        if self.size < 8**11:
            return super().tobuf(tarfile.USTAR_FORMAT, encoding, errors)
        info = self.get_info()
        info['size'] = 0
        header = bytearray(self.create_ustar_header(info, encoding, errors))
        # GNU base-256 sizes fit in the regular header and are understood by
        # tarfile without permitting PAX or GNU extension members in the reader.
        header[124:136] = tarfile.itn(self.size, 12, tarfile.GNU_FORMAT)
        header[148:156] = b'        '
        header[148:156] = f'{sum(header):06o}\0 '.encode('ascii')
        return bytes(header)


def write_delta(directory, manifest, paths, previous_manifest_path, part_mib=1536):
    """Archive changed target files as patches; unchanged files reuse the source."""
    from bundle_runtime import DELTA_DISTRIBUTION, manifest_digest, regular
    from package_release import PartsWriter
    directory, previous_manifest_path = Path(directory), Path(previous_manifest_path)
    if not 1 <= part_mib < 2048:
        raise RuntimeError('Every incremental asset must be smaller than 2 GiB.')
    if previous_manifest_path.name == 'installed-release.json' and previous_manifest_path.parent.name == 'local':
        source_root = previous_manifest_path.parent.parent
    elif previous_manifest_path.name == 'manifest.json':
        source_root = previous_manifest_path.parent
    else:
        raise RuntimeError('Use a source manifest beside unpacked release files.')
    regular(previous_manifest_path, source_root)
    if previous_manifest_path.stat().st_size > 16 * 1024**2:
        raise RuntimeError('Oversized incremental source manifest.')
    old = json.loads(previous_manifest_path.read_text())
    validation_target = manifest
    if manifest.get('distribution') == DELTA_DISTRIBUTION:
        if old.get('distribution') is not None or manifest.get('base_release') != {
                'manifest': old, 'manifest_sha256': manifest_digest(old)}:
            raise RuntimeError('A delta-only release requires its exact full base manifest.')
        # The complete delta descriptor is produced below. Validate the target
        # firmware envelope against the already authenticated full transport.
        validation_target = {key: value for key, value in manifest.items()
                             if key not in ('distribution', 'base_release', 'deltas')}
        validation_target['parts'] = old['parts']
    validate_sources(old, validation_target)
    if set(paths) != set(manifest['files']):
        raise RuntimeError('Incremental target inventory differs from its manifest.')
    writer = PartsWriter(directory,
        'HyperOS-AVD-' + manifest['version'] + '-from-' + old['version'] + '-delta', part_mib * 1024**2)
    try:
        with tempfile.TemporaryFile() as patch_file:
            with tarfile.open(fileobj=writer, mode='w|gz', compresslevel=6,
                              format=tarfile.USTAR_FORMAT) as archive:
                for name, info in sorted(manifest['files'].items()):
                    target = Path(paths[name])
                    _regular_file(target)
                    if target.stat().st_size != info['size'] or sha256(target) != info['sha256']:
                        raise RuntimeError('Incremental target differs from its manifest: ' + name)
                    source_info = old['files'].get(name)
                    source = source_root / name if source_info is not None else None
                    shared_input = source is not None and target == source
                    if shared_input:
                        regular(source, source_root)
                    elif source is not None:
                        _verify(source, source_root, source_info)
                    if source_info != info:
                        patch_file.seek(0)
                        patch_file.truncate()
                        write_patch(source, target, patch_file)
                        size = patch_file.tell()
                        if size > patch_limit(info['size']):
                            raise RuntimeError('Incremental producer exceeded its member bounds.')
                        patch_file.seek(0)
                        entry = _PatchMember(name)
                        entry.size, entry.mode = size, 0o644
                        archive.addfile(entry, patch_file)
                    if source is not None and not shared_input:
                        _verify(source, source_root, source_info)
                    _regular_file(target)
                    if target.stat().st_size != info['size'] or sha256(target) != info['sha256']:
                        raise RuntimeError('Incremental target changed while packaging: ' + name)
        writer.close_part()
        regular(previous_manifest_path, source_root)
        if json.loads(previous_manifest_path.read_text()) != old:
            raise RuntimeError('Incremental source manifest changed while packaging.')
        if (manifest.get('distribution') != DELTA_DISTRIBUTION
                and sum(item['size'] for item in writer.parts) >= sum(item['size'] for item in manifest['parts'])):
            for part in writer.parts:
                (directory / part['name']).unlink()
            return None
        return {'protocol': PROTOCOL, 'from_version': old['version'],
                'from_manifest_sha256': manifest_digest(old), 'parts': writer.parts}
    except BaseException:
        writer.close_part()
        for part in writer.parts:
            (directory / part['name']).unlink(missing_ok=True)
        raise
