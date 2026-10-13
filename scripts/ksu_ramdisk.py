"""Prepare an offline, content-audited KernelSU ramdisk override for OS4.

Frozen images are read only. An eligible ranchu 4K image with the exact audited
KernelSU LKM gets a separately authenticated local cache; unknown content is
retained with a diagnostic. Codecs and CPIO parsing have explicit size bounds.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import tempfile
import zlib

import patch_kernelsu
import kernelsu_release

KERNEL_SHA256 = 'b950027375a82427604eba65f41de7188737e444b01cb625c61056ffd14cf427'
MAX_RAMDISK = 64 * 1024**2
MAX_LZ4_BLOCK = 8 * 1024**2
LZ4_MAGIC = bytes.fromhex('02214c18')
MEMBER = b'kernelsu.ko'


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _extension(data, position, length, limit):
    while True:
        if position >= len(data):
            raise RuntimeError('Truncated LZ4 length extension.')
        value = data[position]
        position += 1
        length += value
        if length > limit:
            raise RuntimeError('LZ4 block exceeds its size bound.')
        if value != 255:
            return position, length


def _lz4_block(data):
    position, output = 0, bytearray()
    if not data:
        raise RuntimeError('Empty LZ4 block.')
    while position < len(data):
        token = data[position]
        position += 1
        literal = token >> 4
        if literal == 15:
            position, literal = _extension(data, position, literal, MAX_LZ4_BLOCK)
        if position + literal > len(data) or len(output) + literal > MAX_LZ4_BLOCK:
            raise RuntimeError('Invalid or oversized LZ4 literals.')
        output.extend(data[position:position + literal])
        position += literal
        if position == len(data):
            if token & 15:
                raise RuntimeError('Invalid final LZ4 literal token.')
            return bytes(output)
        if position + 2 > len(data):
            raise RuntimeError('Truncated LZ4 match offset.')
        distance = struct.unpack_from('<H', data, position)[0]
        position += 2
        if distance == 0 or distance > len(output):
            raise RuntimeError('Invalid LZ4 match offset.')
        length = (token & 15) + 4
        if token & 15 == 15:
            position, length = _extension(data, position, length, MAX_LZ4_BLOCK)
        if len(output) + length > MAX_LZ4_BLOCK:
            raise RuntimeError('LZ4 match exceeds its size bound.')
        pattern = bytes(output[-distance:])
        output.extend(pattern * (length // distance) + pattern[:length % distance])
    raise RuntimeError('LZ4 block has no final literal sequence.')


def unpack(data):
    """Decode one bounded supported ramdisk, rejecting concatenated streams."""
    if not isinstance(data, bytes) or not data or len(data) > MAX_RAMDISK:
        raise RuntimeError('Invalid ramdisk size or type.')
    if data.startswith(LZ4_MAGIC):
        position, output, blocks = 4, bytearray(), 0
        while position < len(data):
            if position + 4 > len(data):
                raise RuntimeError('Truncated legacy LZ4 block header.')
            size = struct.unpack_from('<I', data, position)[0]
            position += 4
            if not 0 < size <= MAX_LZ4_BLOCK + MAX_LZ4_BLOCK // 255 + 16:
                raise RuntimeError('Invalid legacy LZ4 block size.')
            if position + size > len(data):
                raise RuntimeError('Truncated legacy LZ4 block.')
            block = _lz4_block(data[position:position + size])
            position += size
            blocks += 1
            if blocks > MAX_RAMDISK // MAX_LZ4_BLOCK or len(output) + len(block) > MAX_RAMDISK:
                raise RuntimeError('Legacy LZ4 ramdisk exceeds its size bound.')
            output.extend(block)
        if not blocks or not output:
            raise RuntimeError('Empty legacy LZ4 ramdisk.')
        return 'lz4-legacy', bytes(output)
    if data.startswith(b'\x1f\x8b'):
        if len(data) < 18 or data[:4] != b'\x1f\x8b\x08\0':
            raise RuntimeError('Only simple single-member gzip ramdisks are supported.')
        decoder = zlib.decompressobj(-zlib.MAX_WBITS)
        try:
            output = decoder.decompress(data[10:-8], MAX_RAMDISK + 1)
        except zlib.error as error:
            raise RuntimeError('Invalid gzip ramdisk deflate stream.') from error
        if (len(output) > MAX_RAMDISK or not decoder.eof or decoder.unused_data
                or decoder.unconsumed_tail):
            raise RuntimeError('Oversized, truncated or concatenated gzip ramdisk.')
        crc, size = struct.unpack_from('<II', data, len(data) - 8)
        if crc != zlib.crc32(output) or size != len(output):
            raise RuntimeError('Gzip ramdisk checksum or size mismatch.')
        return 'gzip', output
    if data.startswith(b'070701'):
        return 'cpio', data
    raise RuntimeError('Unsupported ramdisk compression or archive format.')


def pack(kind, data):
    """Encode deterministically without native compression dependencies."""
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_RAMDISK:
        raise RuntimeError('Invalid unpacked ramdisk size or type.')
    if kind == 'cpio':
        return data
    if kind == 'lz4-legacy':
        output = bytearray(LZ4_MAGIC)
        for position in range(0, len(data), MAX_LZ4_BLOCK):
            block = data[position:position + MAX_LZ4_BLOCK]
            length = len(block)
            literal = bytearray([min(length, 15) << 4])
            if length >= 15:
                extra = length - 15
                literal.extend(b'\xff' * (extra // 255))
                literal.append(extra % 255)
            literal.extend(block)
            output.extend(struct.pack('<I', len(literal)))
            output.extend(literal)
        return bytes(output)
    if kind == 'gzip':
        # Fixed header and stored DEFLATE blocks avoid zlib-version output drift.
        output = bytearray(b'\x1f\x8b\x08\0\0\0\0\0\0\xff')
        for position in range(0, len(data), 65535):
            block = data[position:position + 65535]
            length = len(block)
            output.append(int(position + length == len(data)))
            output.extend(struct.pack('<HH', length, length ^ 0xffff))
            output.extend(block)
        output.extend(struct.pack('<II', zlib.crc32(data), len(data)))
        return bytes(output)
    raise RuntimeError('Unsupported ramdisk output format.')


def parse_cpio(data):
    """Locate entries in one newc archive without rebuilding its metadata."""
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_RAMDISK:
        raise RuntimeError('Invalid CPIO size or type.')
    position, entries, names = 0, [], set()
    while position < len(data):
        if len(entries) >= 65536 or position + 110 > len(data):
            raise RuntimeError('Truncated or oversized CPIO directory.')
        header = data[position:position + 110]
        if header[:6] != b'070701' or not re.fullmatch(b'[0-9a-fA-F]{104}', header[6:]):
            raise RuntimeError('Only one newc CPIO archive without CRC is supported.')
        fields = tuple(int(header[i:i + 8], 16) for i in range(6, 110, 8))
        size, name_size = fields[6], fields[11]
        if not 1 < name_size <= 4096 or fields[12] != 0:
            raise RuntimeError('Invalid newc CPIO name or checksum field.')
        name_end = position + 110 + name_size
        body = (name_end + 3) & ~3
        end = (body + size + 3) & ~3
        if end > len(data):
            raise RuntimeError('CPIO entry exceeds its archive.')
        encoded = data[position + 110:name_end]
        name = encoded[:-1]
        if encoded[-1:] != b'\0' or b'\0' in name:
            raise RuntimeError('Duplicate or malformed CPIO entry name.')
        if name.startswith(b'/') or any(part in (b'', b'..') for part in name.split(b'/')):
            raise RuntimeError('Unsafe CPIO entry path.')
        normalized = b'/'.join(part for part in name.split(b'/') if part != b'.') or b'.'
        if normalized in names:
            raise RuntimeError('Duplicate or aliased CPIO entry path.')
        names.add(normalized)
        entry = {'name': name, 'offset': position, 'body': body,
                 'size': size, 'end': end, 'fields': fields}
        entries.append(entry)
        if name == b'TRAILER!!!':
            if size or any(data[end:]):
                raise RuntimeError('Concatenated or trailing nonzero CPIO content.')
            return entries
        position = end
    raise RuntimeError('CPIO trailer is missing.')


def _parameters(member):
    return {part.decode().split('=', 1)[1].split(':', 1)[0]: part.decode().rsplit(':', 1)[1]
            for part in member.split(b'\0') if part.startswith(b'parmtype=')}


def _upgrade_config(archive, entries, source, target):
    """Keep the original init/config, requiring the target to accept its ABI."""
    before = [part for part in source.split(b'\0') if part.startswith(b'vermagic=')]
    after = [part for part in target.split(b'\0') if part.startswith(b'vermagic=')]
    if len(before) != 1 or before != after:
        raise RuntimeError('KernelSU replacement has a different kernel ABI/vermagic.')
    old, new = _parameters(source), _parameters(target)
    if any(new.get(key) != value for key, value in old.items()):
        raise RuntimeError('KernelSU replacement no longer accepts the original module parameters.')
    configs = [entry for entry in entries if entry['name'] == b'ksu_config']
    if not configs:
        return {'sha256': None, 'parameters': []}
    if len(configs) != 1:
        raise RuntimeError('Ambiguous original KernelSU config.')
    config = configs[0]
    fields = config['fields']
    if (stat.S_IFMT(fields[1]) != stat.S_IFREG or fields[2:5] != (0, 0, 1)
            or config['size'] > 4096):
        raise RuntimeError('Unknown original KernelSU config ownership or size.')
    if any(other is not config and (other['fields'][0], other['fields'][7:9]) == (fields[0], fields[7:9])
           for other in entries):
        raise RuntimeError('A KernelSU config CPIO inode alias is present.')
    content = archive[config['body']:config['body'] + config['size']]
    try:
        options = content.decode('ascii').split()
    except UnicodeError as error:
        raise RuntimeError('Unknown original KernelSU config encoding.') from error
    names = set()
    for option in options:
        matched = re.fullmatch(r'([a-z][a-z0-9_]*)=(0|1)', option)
        if not matched or matched[1] in names or old.get(matched[1]) != 'bool':
            raise RuntimeError('Custom KernelSU config cannot be proved compatible; it was retained.')
        names.add(matched[1])
    return {'sha256': _digest(content), 'parameters': sorted(names)}


def patch_ramdisk(data, target=None):
    """Quiet the original LKM, or replace it with an audited compatible target.

    The default keeps the historical source/receipt contract. An explicit
    target only changes the LKM body and its required newc size/padding.
    """
    kind, archive = unpack(data)
    entries = parse_cpio(archive)
    matches = [entry for entry in entries if entry['name'] == MEMBER]
    if len(matches) != 1:
        raise RuntimeError('Expected one owned kernelsu.ko CPIO entry.')
    entry = matches[0]
    fields = entry['fields']
    if (stat.S_IFMT(fields[1]) != stat.S_IFREG or fields[2:5] != (0, 0, 1)
            or fields[7:11] != (0, 0, 0, 0)):
        raise RuntimeError('Unknown KernelSU CPIO ownership, alias or file type.')
    member = archive[entry['body']:entry['body'] + entry['size']]
    checked = patch_kernelsu.audit(member)
    # Reject hidden aliases even if the canonical entry itself is unlinked.
    for other in entries:
        if other is entry:
            continue
        if (other['fields'][0], other['fields'][7:9]) == (fields[0], fields[7:9]):
            raise RuntimeError('A KernelSU CPIO inode alias is present.')
        body = archive[other['body']:other['body'] + other['size']]
        audited = {value for before, recipe in patch_kernelsu.RECIPES.items()
                   for value in (before, recipe['after'])}
        if _digest(body) in audited:
            raise RuntimeError('An extra KernelSU LKM alias is present in CPIO.')
    if target is None and checked['patched']:
        return None, {'already_patched': True, 'member': MEMBER.decode()}
    fixed = patch_kernelsu.patch_bytes(member if target is None else target)
    if target is not None and member == fixed:
        return None, {'already_patched': True, 'member': MEMBER.decode()}
    config = _upgrade_config(archive, entries, member, fixed) if target is not None else None
    if target is None:
        changed = archive[:entry['body']] + fixed + archive[entry['body'] + entry['size']:]
    else:
        size_position = entry['offset'] + 6 + 6 * 8
        prefix = (archive[:size_position] + f'{len(fixed):08x}'.encode()
                  + archive[size_position + 8:entry['body']])
        changed = prefix + fixed + b'\0' * (-(entry['body'] + len(fixed)) % 4) + archive[entry['end']:]
        # Every other header/body/padding survives byte for byte, even though
        # the larger member shifts later entries' aligned archive offsets.
        after = parse_cpio(changed)
        if len(after) != len(entries):
            raise RuntimeError('KernelSU replacement changed the CPIO directory.')
        for original, updated in zip(entries, after):
            if original is entry:
                continue
            if archive[original['offset']:original['end']] != changed[updated['offset']:updated['end']]:
                raise RuntimeError('KernelSU replacement changed another CPIO entry.')
    encoded = pack(kind, changed)
    if len(encoded) > MAX_RAMDISK or unpack(encoded) != (kind, changed):
        raise RuntimeError('Ramdisk derivative codec verification failed.')
    marker = {'schema': 1, 'recipe': checked['receipt'],
              'kernel_sha256': KERNEL_SHA256, 'compression': kind,
              'input_sha256': _digest(data), 'input_size': len(data),
              'input_cpio_sha256': _digest(archive),
              'output_sha256': _digest(encoded), 'output_size': len(encoded),
              'output_cpio_sha256': _digest(changed),
              'member': MEMBER.decode(), 'member_offset': entry['body'],
              'member_size': entry['size'], 'cpio_entries': len(entries)}
    if target is not None:
        target_receipt = patch_kernelsu.receipt(fixed)
        marker.update({'schema': 2, 'recipe': target_receipt, 'input_recipe': checked['receipt'],
                       'target_release': target_receipt['version'],
                       'target_official_sha256': target_receipt['before'],
                       'target_quiet_sha256': target_receipt['after'],
                       'input_member_sha256': _digest(member), 'output_member_size': len(fixed),
                       'original_config': config,
                       'capabilities': {'android_api': 37, 'hardware_base_api': 36,
                                        'kernel_page_size': 4096, 'abi': 'arm64-v8a',
                                        'kernel_sha256': KERNEL_SHA256}})
    return encoded, marker


def _regular(path, limit):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or not 0 < info.st_size <= limit):
        raise RuntimeError('Unsafe or oversized ramdisk input/cache leaf: ' + path.name)
    with path.open('rb') as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
                info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns):
            raise RuntimeError('Ramdisk input/cache changed while opening: ' + path.name)
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns',
                  'st_mode', 'st_uid', 'st_gid', 'st_nlink')
        if (len(data) != info.st_size
                or any(getattr(after, field) != getattr(opened, field) for field in fields)):
            raise RuntimeError('Ramdisk input/cache changed while reading: ' + path.name)
    return data


def _inputs(workspace):
    workspace = Path(workspace).resolve()
    build_bytes = _regular(workspace / 'local/build.json', 1024**2)
    try:
        build = json.loads(build_bytes)
    except (ValueError, UnicodeError) as error:
        raise RuntimeError('Invalid OS4 build provenance.') from error
    if (not isinstance(build, dict) or not isinstance(build.get('hyperos'), str)
            or not re.fullmatch(r'(?:OS)?4\.[0-9]+\.[0-9]+\.[0-9]+\.[A-Z0-9]+', build['hyperos'])
            or any(type(build.get(key)) is not int or build[key] != value for key, value in (
                ('android_api', 37), ('kernel_page_size', 4096), ('hardware_base_api', 36)))):
        raise RuntimeError('Unsupported OS4 ARM64 ranchu 4K build capabilities.')
    source = _regular(workspace / 'images/source.properties', 65536)
    try:
        pairs = [line.split('=', 1) for line in source.decode().splitlines()
                 if '=' in line and not line.startswith('#')]
    except UnicodeError as error:
        raise RuntimeError('Invalid hardware-base properties.') from error
    if len({key for key, _ in pairs}) != len(pairs):
        raise RuntimeError('Duplicate hardware-base property.')
    properties = dict(pairs)
    if (properties.get('SystemImage.Abi') != 'arm64-v8a'
            or properties.get('AndroidVersion.ApiLevel') != '36'):
        raise RuntimeError('Unsupported hardware-base ABI or API.')
    kernel = _regular(workspace / 'images/kernel-ranchu', MAX_RAMDISK)
    if _digest(kernel) != KERNEL_SHA256:
        raise RuntimeError('Unknown ranchu kernel content; its ABI/page size is unaudited.')
    ramdisk = _regular(workspace / 'images/ramdisk.img', MAX_RAMDISK)
    return workspace, ramdisk


def _cache_folder(workspace, create=False):
    folder = workspace / 'local/boot-patches'
    for directory in (workspace / 'local', folder):
        if directory.exists() or directory.is_symlink():
            if not stat.S_ISDIR(directory.lstat().st_mode):
                raise RuntimeError('Unsafe ramdisk cache directory.')
        elif create:
            directory.mkdir(mode=0o700)
        else:
            raise RuntimeError('Ramdisk cache directory is missing.')
    return folder


def _cache_paths(workspace, marker, create=False):
    folder = _cache_folder(workspace, create)
    base = 'ramdisk-' + marker['output_sha256']
    return folder / (base + '.img'), folder / (base + '.json')


def _marker_bytes(marker):
    return (json.dumps(marker, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def _verify_pair(path, marker_path, expected, marker):
    if _regular(path, MAX_RAMDISK) != expected:
        raise RuntimeError('Preserving an unknown or modified ramdisk cache image.')
    if _regular(marker_path, 65536) != _marker_bytes(marker):
        raise RuntimeError('Preserving an unknown or modified ramdisk cache receipt.')
    return path


def _cache_derivative(workspace, source, path):
    """Reproduce the saved target rule, independently of today's desired stack."""
    requested = Path(path).absolute()
    if not is_owned_cache_selection(workspace, requested):
        raise RuntimeError('Ramdisk override is not the authenticated local cache path.')
    try:
        saved = json.loads(_regular(requested.with_suffix('.json'), 65536))
    except (ValueError, UnicodeError) as error:
        raise RuntimeError('Preserving an unknown or modified ramdisk cache receipt.') from error
    if not isinstance(saved, dict) or type(saved.get('schema')) is not int:
        raise RuntimeError('Unknown saved ramdisk cache recipe was preserved.')
    if saved['schema'] == 1:
        return patch_ramdisk(source)
    if saved['schema'] != 2:
        raise RuntimeError('Unknown saved ramdisk target recipe was preserved.')
    target_receipt = patch_kernelsu.receipt(saved.get('target_official_sha256'))
    if saved.get('recipe') != target_receipt:
        raise RuntimeError('Saved ramdisk target provenance was modified.')
    _, archive = unpack(_regular(requested, MAX_RAMDISK))
    matches = [entry for entry in parse_cpio(archive) if entry['name'] == MEMBER]
    if len(matches) != 1:
        raise RuntimeError('Saved ramdisk cache has no sole audited target LKM.')
    entry = matches[0]
    target = archive[entry['body']:entry['body'] + entry['size']]
    if _digest(target) != target_receipt['after']:
        raise RuntimeError('Saved ramdisk target LKM differs from its audited quiet pin.')
    return patch_ramdisk(source, target=target)


def desired_target(workspace, current=True):
    """Return only a complete, pinned offline stack's official LKM."""
    if current and kernelsu_release.available(workspace):
        return _regular(kernelsu_release.asset(workspace, kernelsu_release.LKM), MAX_RAMDISK)
    return None


def desired_derivative(workspace, source, current=True):
    """Prefer the complete pinned offline stack; old bundles retain their LKM."""
    return patch_ramdisk(source, target=desired_target(workspace, current=current))


def verify_cache(workspace, path):
    """Read-only verification against current image content and capabilities."""
    workspace, source = _inputs(workspace)
    expected, marker = _cache_derivative(workspace, source, path)
    if expected is None:
        raise RuntimeError('Current image already contains the quiet KernelSU LKM.')
    canonical, receipt_path = _cache_paths(workspace, marker)
    if Path(path).absolute() != canonical:
        raise RuntimeError('Ramdisk override is not the authenticated local cache path.')
    return _verify_pair(canonical, receipt_path, expected, marker)


def is_owned_cache_selection(workspace, path):
    """Recognize only the reserved local namespace, without following aliases."""
    workspace, path = Path(workspace).resolve(), Path(path).absolute()
    return (path.parent == workspace / 'local/boot-patches'
            and re.fullmatch(r'ramdisk-[0-9a-f]{64}\.img', path.name) is not None)


def _frozen_source(workspace):
    """Locate one saved installed version; never search arbitrary old directories."""
    try:
        manager = json.loads(_regular(workspace / 'local/manager.json', 1024**2))
    except (OSError, ValueError, UnicodeError) as error:
        raise RuntimeError('Owned stale ramdisk has no readable saved runtime provenance.') from error
    if (not isinstance(manager, dict) or type(manager.get('schema')) is not int
            or manager['schema'] != 1 or not isinstance(manager.get('version'), str)
            or not re.fullmatch(r'(?:pad-)?v[0-9A-Za-z_.-]{1,127}', manager['version'])):
        raise RuntimeError('Owned stale ramdisk has invalid saved runtime provenance.')
    versions = workspace / 'versions'
    source = versions / manager['version']
    for path in (versions, source, source / 'local', source / 'images'):
        if not stat.S_ISDIR(path.lstat().st_mode):
            raise RuntimeError('Saved frozen ramdisk source contains a directory alias.')
    try:
        manifest = json.loads(_regular(source / 'local/installed-release.json', 2 * 1024**2))
    except (OSError, ValueError, UnicodeError) as error:
        raise RuntimeError('Saved frozen ramdisk source has no readable installed manifest.') from error
    if (not isinstance(manifest, dict) or manifest.get('project') != 'HyperOS-AVD'
            or manifest.get('version') != manager['version']
            or not isinstance(manifest.get('files'), dict)):
        raise RuntimeError('Saved frozen ramdisk source manifest does not match its runtime.')
    _, ramdisk = _inputs(source)
    for relative, limit in (('images/kernel-ranchu', MAX_RAMDISK),
                            ('images/ramdisk.img', MAX_RAMDISK),
                            ('images/source.properties', 65536)):
        data = ramdisk if relative == 'images/ramdisk.img' else _regular(source / relative, limit)
        entry = manifest['files'].get(relative)
        if (not isinstance(entry, dict) or type(entry.get('size')) is not int
                or entry['size'] != len(data) or entry.get('sha256') != _digest(data)):
            raise RuntimeError('Saved frozen ramdisk source differs from its installed manifest: ' + relative)
    return source, ramdisk


def verify_saved_cache(workspace, path):
    """Authenticate an old derivative against the one saved frozen source."""
    workspace = Path(workspace).resolve()
    requested = Path(path).absolute()
    if not is_owned_cache_selection(workspace, requested):
        raise RuntimeError('Ramdisk selection is outside the owned local cache namespace.')
    _cache_folder(workspace)
    _, old = _frozen_source(workspace)
    expected, marker = _cache_derivative(workspace, old, requested)
    if expected is None:
        raise RuntimeError('Saved frozen source cannot prove an owned ramdisk derivative.')
    canonical, receipt_path = _cache_paths(workspace, marker)
    if requested != canonical:
        raise RuntimeError('Owned stale ramdisk path does not match the saved source derivative.')
    return _verify_pair(canonical, receipt_path, expected, marker)


def rebase_cache_selection(workspace, selection, previous_image_directory):
    """Rebase only a proven moved workspace's exact old cache selection.

    The old absolute image.sysdir.1 binding and absent old workspace distinguish
    a relocation from copying another instance's cache or a custom ramdisk.
    """
    workspace = Path(workspace).resolve()
    if (not isinstance(previous_image_directory, str) or not previous_image_directory
            or '\0' in previous_image_directory):
        raise RuntimeError('Moved ramdisk selection has no valid previous image directory binding.')
    images = Path(previous_image_directory)
    if (not images.is_absolute() or images.name != 'images'
            or str(images) != previous_image_directory.rstrip('/')
            or str(images.resolve()) != str(images)):
        raise RuntimeError('Moved ramdisk selection has an aliased previous image directory binding.')
    previous = images.parent
    if previous == workspace:
        raise RuntimeError('Ramdisk selection is not a moved workspace binding.')
    try:
        previous.lstat()
    except FileNotFoundError:
        pass
    else:
        raise RuntimeError('The previous ramdisk workspace still exists; its selection was preserved.')
    selected = Path(selection).absolute()
    if not is_owned_cache_selection(previous, selected):
        raise RuntimeError('Moved ramdisk selection does not belong to its previous image directory.')
    rebased = workspace / 'local/boot-patches' / selected.name
    try:
        verify_cache(workspace, rebased)
    except (RuntimeError, OSError, ValueError):
        # A move may accompany an image switch. Its saved frozen input must
        # reproduce the whole old cache and receipt before any later refresh.
        verify_saved_cache(workspace, rebased)
    return rebased


def refresh_saved_cache(workspace, path):
    """Refresh an owned old derivative only with exact frozen/current source proof.

    Missing or modified provenance is a refusal, not permission to boot the old
    whole ramdisk with a new image. Original sources and old caches stay intact.
    """
    workspace, current = _inputs(workspace)
    verify_saved_cache(workspace, path)
    current_output, _ = desired_derivative(workspace, current)
    result = prepare_runtime(workspace)
    if result is None and current_output is not None:
        raise RuntimeError('Owned stale ramdisk refresh failed; existing selection was retained.')
    if result is not None:
        verify_cache(workspace, result)
    return result


def _publish(path, data):
    """Publish completed bytes without clobbering an unexpectedly created leaf."""
    descriptor, temporary = tempfile.mkstemp(prefix='.ramdisk-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o600)
        try:
            os.link(temporary, path)
        except FileExistsError:
            if _regular(path, MAX_RAMDISK) != data:
                raise RuntimeError('Preserving an unexpectedly created ramdisk cache leaf.')
    finally:
        Path(temporary).unlink(missing_ok=True)


def prepare_runtime(workspace, current=True, strict=False):
    """Prepare an offline override; strict callers retain their old config on error."""
    try:
        workspace, source = _inputs(workspace)
        target = desired_target(workspace, current=current)
        output, marker = patch_ramdisk(source, target=target)
        if current and target is None:
            print('Current KernelSU offline attachments are absent; retaining the source LKM version.')
        if output is None:
            print('KernelSU ramdisk already contains the audited task-scan log fix.')
            return None
        path, receipt_path = _cache_paths(workspace, marker, create=True)
        if receipt_path.exists() or receipt_path.is_symlink():
            return _verify_pair(path, receipt_path, output, marker)
        if path.exists() or path.is_symlink():
            if _regular(path, MAX_RAMDISK) != output:
                raise RuntimeError('Preserving an unknown ramdisk cache image.')
        else:
            _publish(path, output)
        _publish(receipt_path, _marker_bytes(marker))
        verified = _verify_pair(path, receipt_path, output, marker)
        print('Prepared audited KernelSU ' + marker['recipe']['version'] +
              ' task-scan log fix in a separate local ramdisk cache.')
        return verified
    except (RuntimeError, OSError, ValueError, KeyError, IndexError, struct.error) as error:
        if strict:
            raise RuntimeError('KernelSU ramdisk preparation failed; existing selection was retained: ' + str(error)) from error
        print('KernelSU ramdisk patch skipped; original image retained: ' + str(error))
        return None
