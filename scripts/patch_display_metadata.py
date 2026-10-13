#!/usr/bin/env python3
"""Take audited unsupported display-metadata paths on an exact ranchu mapper.

Two libui recipes return the mapper's existing -UNSUPPORTED result for type 24,
then retain the full original temporary-vector cleanup and -BAD_VALUE return.
One Dolby consumer takes its existing false/shared-reference cleanup before
requesting the unsupported XRING namespace. SDR drawing, supported metadata,
properties, locks, PAC, canaries, CFI and all unrelated bytes are preserved.

Core must also authenticate complete ranchu hardware and the exact mapper
capability below. Missing live metadata or a failed service lookup is not proof.
"""
import argparse
import hashlib
import lzma
import os
from pathlib import Path
import stat
import struct
import tempfile

from patch_rear_display import _sections

REQUIRES = 'ranchu-without-extended-hdr-metadata'
MAPPER = '/vendor/lib64/hw/mapper.ranchu.so'
MAPPER_SHA256 = '311ccf0653ab04154fa3c6acbfa99b81f0dc904f501228dee4dc8725e0a6b870'
MAPPER_SIZE = 69096
STANDARD_NAMESPACE = 'android.hardware.graphics.common.StandardMetadataType'
XRING_NAMESPACE = 'xring.graphics.XringMetadataType'
UNSUPPORTED_STANDARD_TYPES = (24,)
UNSUPPORTED_XRING_TYPES = (8,)
UI_SYMBOL = '_ZNK7android14Gralloc5Mapper15getSmpte2094_50EPK13native_handlePNSt3__18optionalINS4_6vectorIhNS4_9allocatorIhEEEEEE'
SF_SYMBOL = '_ZN7android12renderengine4skia13DolbyRenderer19requiresDolbyEffectERKNS0_13LayerSettingsEb'
RECIPES = {
    'f1c1a014fd0eb3d61454de184ecda76965127b91e3784a45a28c8ba151912fe4': {
        'path': '/system/lib64/libui.so', 'kind': 'metadata24', 'symbol': UI_SYMBOL,
        'size': 443992, 'after': 'e3021d742b57cc18e79ea9a21d136dc86a267f1f19218379bde6dbedf3ddc6f0',
        'text': (1, 6, 0x2c000, 0x2c000, 216492), 'symbols': 'dynamic',
        'immutable_sha256': '2e7fe835248e0379e5ca567238b7d6ac08ada0f955100ad7c2c6cd9d1d4bad78',
        'address': 0x3a2b8, 'function_size': 0x350,
        'function_before': 'ebe67a5b45b2807af551ed8edd8e87bfd92b69c1ba5e1bfafca3e6c146653006',
        'function_after': '9cb67c50a400834a410ffd85ce90ed5e1c12797568f4005f40191c521812abbe',
        'site': 0x3a32c, 'instruction': '20013fd6', 'replacement': 'c0008012',
        'negative_branch': 0x3a334, 'negative_target': 0x3a43c,
        'cleanup': 0x3a3ac, 'return_address': 0x3a434,
        'restore': 0x3a40c, 'restore_end': 0x3a434,
    },
    '6ae57e67eb27dea87f5b9775d94d75f2c490f3c5418d859b1cc37f5ee52dfc35': {
        'path': '/system/lib64/libui.so', 'kind': 'metadata24', 'symbol': UI_SYMBOL,
        'size': 444448, 'after': 'fdfc72690f541c2a60d1fc60bc52d02bac3e9ecf3ad8fa7335da4880bc0e7525',
        'text': (1, 6, 0x2c000, 0x2c000, 215752), 'symbols': 'dynamic',
        'immutable_sha256': '63aa43a745da6be36a9aa56b0564cda157ca79a1fcf2586a5b9e3fe017797b34',
        'address': 0x39fb4, 'function_size': 0x338,
        'function_before': 'd8122da0c406a6ae0e806c7388061828dc6060eb3054d313dbc5aa1f050d8cf8',
        'function_after': 'aa76389b0d9c5de1249d4422f0479aaa16a3df1a36cd64f0ffceb771a03ddaba',
        'site': 0x3a020, 'instruction': '20013fd6', 'replacement': 'c0008012',
        'negative_branch': 0x3a028, 'negative_target': 0x3a124,
        'cleanup': 0x3a0a0, 'return_address': 0x3a11c,
        'restore': 0x3a100, 'restore_end': 0x3a11c,
    },
    '8fdf4dfa2a53a8cc7dcf298be651b38cebe39cf8d5af7d94a6a689b766e2928c': {
        'path': '/system_ext/lib64/libsurfaceflinger.so', 'kind': 'xring8', 'symbol': SF_SYMBOL,
        'size': 13842344, 'after': 'bd9acd782cffe328c030e12e437e6e9bd7c266a1c1e0cb1c27c7cfc88b5ac598',
        'text': (1, 6, 0x350000, 0x350000, 9489236), 'symbols': 'debug',
        'debug_sha256': '4e0b32fcdc440ed256446f23962b4e9651e5367650a4ed84efaa73a17b61c3f3',
        'immutable_sha256': 'b7eff258d57dead2daec547b73108c96a0d2a598306929f89c93105f0dc87c92',
        'address': 0x678788, 'function_size': 0x38c,
        'function_before': 'a2ea459258f7a537d29bba8be4fcb8321027a2492a3dedb3eced593927b2bb5b',
        'function_after': '72c9f8ba58bb77478e690dbf328925d740efccf4b8b8aa9c9caa17256cc3c158',
        'site': 0x6787d0, 'instruction': '960400b4', 'replacement': '24000014',
        'cleanup': 0x678860, 'restore': 0x678890, 'restore_end': 0x6788c4,
        'namespace_offset': 0x19ce3e,
    },
}


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def mapper_capability():
    """Export canonical proof identity for the separate Core hardware gate."""
    return {'schema': 1, 'id': REQUIRES, 'path': MAPPER, 'sha256': MAPPER_SHA256,
            'size': MAPPER_SIZE, 'unsupported_standard_types': list(UNSUPPORTED_STANDARD_TYPES),
            'unsupported_namespace': XRING_NAMESPACE, 'unsupported_types': list(UNSUPPORTED_XRING_TYPES)}


def capability_recipe():
    """Keep the offline module's exact mapper identity in this producer."""
    return ('schema|1\nmapper|' + MAPPER + '|' + MAPPER_SHA256 + '\n').encode()


def audit_mapper(data):
    """Confirm the reviewed range and namespace rejection without changing it."""
    if len(data) != MAPPER_SIZE or _sha(data) != MAPPER_SHA256:
        raise RuntimeError('Unknown display metadata mapper capability.')
    _, names = _sections(data)
    if names[b'.text'][1:6] != (1, 6, 0x4000, 0x4000, 20460):
        raise RuntimeError('Unexpected display metadata mapper executable layout.')
    # Unsigned (type - 1) > 22 rejects every type outside 1..23, including 24.
    if (data[0x5bc0:0x5bd0] != bytes.fromhex('480400d1e70302aa1f5900f128030054')
            or data[0x5c60:0x5c64] != bytes.fromhex('c0008012')
            or data[0x59f4:0x59f8] != bytes.fromhex('c0008012')
            or data[0x1da1:0x1da1 + len(STANDARD_NAMESPACE) + 1] != STANDARD_NAMESPACE.encode() + b'\0'):
        raise RuntimeError('Changed unsupported display metadata mapper contract.')
    return mapper_capability()


def select_recipe(data):
    checksum = _sha(data) if isinstance(data, (bytes, bytearray)) else data
    for before, row in RECIPES.items():
        if checksum in (before, row['after']):
            return before, row, checksum == row['after']
    raise RuntimeError('Unsupported display metadata ELF SHA-256: ' + str(checksum))


def _symbol(data, sections, expected, kind):
    matches = []
    for section in sections:
        if section[1] != kind:
            continue
        if section[9] != 24 or section[5] % 24 or section[6] >= len(sections):
            raise RuntimeError('Unexpected display metadata symbol table.')
        strings = sections[section[6]]
        if strings[1] != 3:
            raise RuntimeError('Unexpected display metadata symbol names.')
        body = data[strings[4]:strings[4] + strings[5]]
        for offset in range(section[4], section[4] + section[5], 24):
            name, info, visibility, index, address, size = struct.unpack_from('<IBBHQQ', data, offset)
            end = body.find(b'\0', name)
            if name >= len(body) or end < 0:
                raise RuntimeError('Unterminated display metadata symbol.')
            if body[name:end] == expected.encode():
                matches.append((info, visibility, index, address, size))
    if len(matches) != 1:
        raise RuntimeError('Missing or ambiguous display metadata consumer function.')
    return matches[0]


def _branch_target(word, address, bits=26, shift=0):
    immediate = (word >> shift) & ((1 << bits) - 1)
    if immediate & (1 << (bits - 1)):
        immediate -= 1 << bits
    return address + immediate * 4


def audit(data):
    """Authenticate the exact consumer ABI and its complete original cleanup."""
    before, row, patched = select_recipe(data)
    if len(data) != row['size']:
        raise RuntimeError('Unexpected display metadata ELF length.')
    sections, names = _sections(data)
    code = names.get(b'.text')
    if code is None or code[1:6] != row['text'] or code[3] != code[4]:
        raise RuntimeError('Unexpected display metadata executable mapping.')
    symbol_data, symbol_sections, kind = data, sections, 11
    if row['symbols'] == 'debug':
        debug = names.get(b'.gnu_debugdata')
        if debug is None or _sha(data[debug[4]:debug[4] + debug[5]]) != row['debug_sha256']:
            raise RuntimeError('Changed display metadata function provenance.')
        try:
            symbol_data = lzma.decompress(data[debug[4]:debug[4] + debug[5]], memlimit=32 * 1024**2)
            if len(symbol_data) > 4 * 1024**2:
                raise RuntimeError('Unexpected display metadata symbol data size.')
            symbol_sections, _ = _sections(symbol_data)
        except (lzma.LZMAError, ValueError, struct.error) as error:
            raise RuntimeError('Invalid display metadata function provenance.') from error
        kind = 2
    match = _symbol(symbol_data, symbol_sections, row['symbol'], kind)
    start, size, site = row['address'], row['function_size'], row['site']
    expected_index = 1 if kind == 2 else sections.index(code)
    if (match != (0x12, 0, expected_index, start, size)
            or not code[3] <= start < site < row['cleanup'] < start + size <= code[3] + code[5]
            or _sha(data[:start] + data[start + size:]) != row['immutable_sha256']
            or _sha(data[start:start + size]) != row['function_after' if patched else 'function_before']):
        raise RuntimeError('Changed display metadata consumer, cleanup or unrelated ELF bytes.')
    original, replacement = bytes.fromhex(row['instruction']), bytes.fromhex(row['replacement'])
    if data[site:site + 4] != (replacement if patched else original):
        raise RuntimeError('Changed display metadata capability instruction.')
    if row['kind'] == 'metadata24':
        # The existing mapper -7 branch still constructs/destroys every local
        # vector, leaves the caller's optional untouched, and returns -74.
        negative, = struct.unpack_from('<I', data, row['negative_branch'])
        equality, = struct.unpack_from('<I', data, row['negative_target'] + 4)
        if (original != bytes.fromhex('20013fd6') or replacement != bytes.fromhex('c0008012')
                or data[site - 8:site - 4] != bytes.fromhex('01038052')
                or negative & 0xfff8001f != 0x37f80000
                or _branch_target(negative, row['negative_branch'], 14, 5) != row['negative_target']
                or data[row['negative_target']:row['negative_target'] + 4] != bytes.fromhex('7f1c0031')
                or equality & 0xff00001f != 0x54000000
                or _branch_target(equality, row['negative_target'] + 4, 19, 5) != row['cleanup']
                or data[row['return_address']:row['return_address'] + 4] != bytes.fromhex('20098012')):
            raise RuntimeError('Unverified original unsupported metadata cleanup contract.')
    elif row['kind'] == 'xring8':
        old_word, = struct.unpack('<I', original)
        new_word, = struct.unpack('<I', replacement)
        namespace = XRING_NAMESPACE.encode() + b'\0'
        offset = row['namespace_offset']
        if (old_word & 0xff00001f != 0xb4000016
                or _branch_target(old_word, site, 19, 5) != row['cleanup']
                or new_word >> 26 != 0x05 or _branch_target(new_word, site) != row['cleanup']
                or data[row['cleanup']:row['cleanup'] + 4] != bytes.fromhex('f4031f2a')
                or data[offset:offset + len(namespace)] != namespace):
            raise RuntimeError('Unverified original XRING false/reference cleanup contract.')
    else:
        raise RuntimeError('Unknown display metadata consumer kind.')
    return before, row, patched


def patch_bytes(data):
    _, row, patched = audit(data)
    if patched:
        return bytes(data)
    output = bytearray(data)
    output[row['site']:row['site'] + 4] = bytes.fromhex(row['replacement'])
    if _sha(output) != row['after'] or len(output) != len(data):
        raise RuntimeError('Display metadata deterministic derivative mismatch.')
    audit(output)
    return bytes(output)


def recipe_receipt(before):
    if before not in RECIPES:
        raise RuntimeError('Unknown display metadata source recipe.')
    row = RECIPES[before]
    return {'schema': 1, 'id': 'display-metadata-' + row['kind'] + '-v1',
            'path': row['path'], 'format': 'elf', 'before': before, 'after': row['after'],
            'size': row['size'], 'requires': REQUIRES, 'mapper_capability': mapper_capability(),
            'sites': [{'offset': row['site'], 'before': row['instruction'],
                       'after': row['replacement'], 'method': row['symbol']}]}


def catalog_recipes():
    return tuple(recipe_receipt(before) for before in RECIPES)


def receipt(data):
    before, _, _ = audit(data)
    return recipe_receipt(before)


def patch(source, destination):
    source, destination = Path(source), Path(destination)
    info = source.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or source.resolve() == destination.resolve()):
        raise RuntimeError('Keep the regular factory display ELF and derivative separate.')
    result = patch_bytes(source.read_bytes())

    def verify_existing():
        info = destination.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or destination.read_bytes() != result):
            raise RuntimeError('Preserving an unknown display metadata derivative output.')

    if destination.exists() or destination.is_symlink():
        verify_existing()
        return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.display-metadata-', dir=destination.parent)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            output.write(result)
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), 0o644)
        try:
            os.link(temporary, destination)
        except FileExistsError:
            verify_existing()
    finally:
        Path(temporary).unlink(missing_ok=True)
    return destination


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    print(patch(args.source, args.destination))
