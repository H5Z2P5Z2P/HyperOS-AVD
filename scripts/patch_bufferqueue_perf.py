#!/usr/bin/env python3
"""Skip an audited physical XRING BufferQueue hint on driver-free ranchu.

Only sendPerfSignal's gettid call becomes a branch to its original checked
return. Its frame, canary, all queue/throttle/render code, driver error paths,
logs, ELF metadata and relocations remain intact. The proprietary hint has no
result or queue state to synthesize. Core must authenticate the ranchu hardware
and canonical XQos driver absence separately before selecting this derivative.
"""
import argparse
import hashlib
import os
from pathlib import Path
import stat
import struct
import tempfile

from patch_rear_display import _sections
from patch_xqos import ABSENT_NODES, REQUIRES

NATIVE = '/system/lib64/libgui.so'
SYMBOL = b'_ZN7android19BufferQueueProducer14sendPerfSignalEii'
RECIPES = {
    'cb95f2a18debffeb3389b75b7366bddba2e9516d7130f73e35391524d931ec91': {
        'size': 2398424,
        'after': 'b6850085395b71c07d9ad1f6e7a2bcee1e655e973854381dc04323c2a1f16537',
        'text': (1, 6, 0xdc000, 0xdc000, 0x1250ac),
        'immutable_sha256': '1f49ce9c3ffe34dca29678df0723699bf41c40cc14a3c9ac7d778da83ef83890',
        'address': 0x153f80, 'function_size': 464,
        'function_before': '0394bd116688cc748d3d360c81b0cf7b85a3b088ce5f6140e2dee25d4f5c0e01',
        'function_after': 'aefcdfe3df0f161c15deec180344d5a0061136d2e584e1f612132b9c383ab1a6',
        'site': 0x153fb0, 'instruction': 'e8b60294', 'gettid_plt': 0x201b50,
        'target': 0x15409c, 'replacement': '3b000014',
        'prologue': 'ffc301d1fd7b03a9f85f04a9f65705a9f44f06a9fdc3009158d03bd5f403022af503012a081740f9f30300aaa8831ff8',
        'epilogue': '081740f9a9835ff81f0109eb21050054f44f46a9f65745a9f85f44a9fd7b43a9ffc30191c0035fd6',
        'driver_path_offset': 0x80826,
    },
}


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def select_recipe(data):
    checksum = _sha(data) if isinstance(data, (bytes, bytearray)) else data
    for before, recipe in RECIPES.items():
        if checksum in (before, recipe['after']):
            return before, recipe, checksum == recipe['after']
    raise RuntimeError('Unsupported BufferQueue Perf ELF SHA-256: ' + str(checksum))


def _branch_target(word, address):
    immediate = word & 0x3ffffff
    if immediate & 0x2000000:
        immediate -= 0x4000000
    return address + immediate * 4


def _signal_symbol(data, sections):
    """Resolve only the reviewed public symbol; unrelated aliases are valid."""
    matches = []
    for section in sections:
        if section[1] != 11:  # SHT_DYNSYM
            continue
        if section[9] != 24 or section[5] % 24 or section[6] >= len(sections):
            raise RuntimeError('Unexpected BufferQueue Perf dynamic symbol table.')
        strings = sections[section[6]]
        if strings[1] != 3:
            raise RuntimeError('Unexpected BufferQueue Perf symbol strings.')
        table = data[strings[4]:strings[4] + strings[5]]
        for offset in range(section[4], section[4] + section[5], 24):
            name, info, visibility, index, address, size = struct.unpack_from('<IBBHQQ', data, offset)
            end = table.find(b'\0', name)
            if name >= len(table) or end < 0:
                raise RuntimeError('Unterminated BufferQueue Perf symbol.')
            if table[name:end] == SYMBOL:
                matches.append((info, visibility, index, address, size))
    if len(matches) != 1:
        raise RuntimeError('Missing or ambiguous BufferQueue Perf signal function.')
    return matches[0]


def audit(data):
    """Bind the complete hint and every unchanged ELF byte to reviewed content."""
    before, recipe, patched = select_recipe(data)
    if len(data) != recipe['size']:
        raise RuntimeError('Unexpected BufferQueue Perf ELF length.')
    sections, names = _sections(data)
    code = names.get(b'.text')
    if code is None or code[1:6] != recipe['text']:
        raise RuntimeError('Unexpected BufferQueue Perf executable section.')
    start, length, site = recipe['address'], recipe['function_size'], recipe['site']
    if (_signal_symbol(data, sections) != (0x12, 0, sections.index(code), start, length)
            or not code[3] <= start < site < recipe['target'] < start + length <= code[3] + code[5]
            or code[3] != code[4]):
        raise RuntimeError('Unexpected BufferQueue Perf function extent or ABI.')
    if (_sha(data[:start] + data[start + length:]) != recipe['immutable_sha256']
            or _sha(data[start:start + length]) != recipe['function_after' if patched else 'function_before']):
        raise RuntimeError('Changed BufferQueue Perf body, queue code or ELF metadata.')
    prologue, epilogue = bytes.fromhex(recipe['prologue']), bytes.fromhex(recipe['epilogue'])
    target = recipe['target']
    if data[start:site] != prologue or data[target:target + len(epilogue)] != epilogue:
        raise RuntimeError('Changed BufferQueue Perf frame or checked return.')
    original = bytes.fromhex(recipe['instruction'])
    old_word, = struct.unpack('<I', original)
    replacement = bytes.fromhex(recipe['replacement'])
    word, = struct.unpack('<I', replacement)
    if (old_word >> 26 != 0x25 or _branch_target(old_word, site) != recipe['gettid_plt']
            or word >> 26 != 0x05 or _branch_target(word, site) != target
            or data[site:site + 4] != (replacement if patched else original)):
        raise RuntimeError('Invalid BufferQueue Perf original call or failure branch.')
    driver = b'/dev/xr_fbt\0'
    offset = recipe['driver_path_offset']
    if data[offset:offset + len(driver)] != driver:
        raise RuntimeError('Unexpected BufferQueue Perf physical driver provenance.')
    return before, recipe, patched


def patch_bytes(data):
    _, recipe, patched = audit(data)
    if patched:
        return bytes(data)
    result = bytearray(data)
    site = recipe['site']
    result[site:site + 4] = bytes.fromhex(recipe['replacement'])
    if len(result) != len(data) or _sha(result) != recipe['after']:
        raise RuntimeError('BufferQueue Perf deterministic derivative mismatch.')
    audit(result)
    return bytes(result)


def recipe_receipt(before):
    if before not in RECIPES:
        raise RuntimeError('Unknown BufferQueue Perf source recipe.')
    row = RECIPES[before]
    return {'schema': 1, 'id': 'bufferqueue-perf-missing-driver-v1', 'path': NATIVE, 'format': 'elf',
            'before': before, 'after': row['after'], 'size': row['size'], 'requires': REQUIRES,
            'absent_nodes': list(ABSENT_NODES),
            'sites': [{'offset': row['site'], 'before': row['instruction'],
                       'after': row['replacement'], 'method': SYMBOL.decode()}]}


def catalog_recipes():
    return tuple(recipe_receipt(before) for before in RECIPES)


def receipt(data):
    before, _, _ = audit(data)
    return recipe_receipt(before)


def patch(source, destination):
    """Publish a separate immutable derivative, retaining unknown outputs."""
    source, destination = Path(source), Path(destination)
    info = source.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or source.resolve() == destination.resolve()):
        raise RuntimeError('Keep the regular factory BufferQueue ELF and derivative separate.')
    result = patch_bytes(source.read_bytes())

    def verify_existing():
        info = destination.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or destination.read_bytes() != result):
            raise RuntimeError('Preserving an unknown BufferQueue Perf derivative output.')

    if destination.exists() or destination.is_symlink():
        verify_existing()
        return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.bufferqueue-perf-', dir=destination.parent)
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
