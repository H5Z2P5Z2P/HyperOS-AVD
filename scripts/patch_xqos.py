#!/usr/bin/env python3
"""Fail only the audited proprietary XQos backend on driver-free ranchu.

Each of seven exported physical QoS operations takes its original unsupported
return path before initialize(), retaining its stack/canary/PAC epilogue. Five
setters return false; the two getters return -1, never a fabricated valid level.
No generic scheduler, Android QoS, log function, ELF metadata or permission is
changed. Core must prove the reviewed vendor/kernel and absence of both driver
nodes separately; this offline producer never infers hardware from names.
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

NATIVE = '/system/lib64/libxqos.so'
ABSENT_NODES = ('/dev/xr_fbt', '/dev/xr_perf_actuator')
INITIALIZER = b'_ZL10initializev'
REQUIRES = 'ranchu-without-xring-qos'
# Each function row binds the entire body, first initializer call, original
# failure branch, return-value assignment, and unchanged epilogue through RET.
RECIPES = {
    '74165b8ff156ad24659e1568cf30e45253562ce1d0b1973f815474310895ac12': {
        'size': 51568,
        'after': '8c6f5133e445e2fe92f5cb3dfefde8a09a5c9105d9231be6f344d69132f2256c',
        'text_size': 0x994,
        'pac': True,
        'initialize': (0x4200, 0x20c, '13d2ca124cf0ad1af334fcbbef5a5d2c8756515e93456240c919717fe99ed124'),
        'functions': (
            {
                'symbol': 'setTidQos', 'address': 0x4020, 'size': 480,
                'before': '634dbac579f65e8bb3d409c3aae4c20c977cbb5b77427602de096e71863125fd',
                'after': '9a4619380ff1390f118584493e6e341639f45a32346c0b930612aab61eeb75c0',
                'site': 0x4044, 'instruction': '6f000094',
                'failure': 0x4178, 'target': 0x4178, 'return': 0,
                'epilogue': 'e0031f2af44f43a9f65742a9fd7b41a9ff030191bf2303d5c0035fd6',
            },
            {
                'symbol': 'setTaskRtg', 'address': 0x440c, 'size': 164,
                'before': '55988df3667dbff39d7f3d82ad06cc84a71de511f3f5be4890be24bf938eb1ee',
                'after': 'ae59fd7bb66ba1b767ba34e35d6b030a7f43ccc76cb7dbc461f04e248b723ba6',
                'site': 0x4428, 'instruction': '76ffff97',
                'failure': 0x4498, 'target': 0x4498, 'return': 0,
                'epilogue': 'e0031f2af44f42a9f50b40f9fd7bc3a8bf2303d5c0035fd6',
            },
            {
                'symbol': 'resetTaskRtg', 'address': 0x44b0, 'size': 164,
                'before': 'e6fea28d69013ed851485d2d13c87d08566acbe2282566e9d7398d1f7c209a56',
                'after': '1ed036f5f9eff852e9ad2c6dbf58d9a28e814b4f59b5e47ee9874bbfca6abda1',
                'site': 0x44c8, 'instruction': '4effff97',
                'failure': 0x453c, 'target': 0x453c, 'return': 0,
                'epilogue': 'e0031f2af44f42a9f50b40f9fd7bc3a8bf2303d5c0035fd6',
            },
            {
                'symbol': 'setTidQosLevel', 'address': 0x4554, 'size': 492,
                'before': 'e6f6e0bb0650bbf0b7e32c1838faea96138602118f400dfae454bbd31a87ecc3',
                'after': '4e5ea464a852d08d36e183250fcd26ef7e3eb5dfe0d28cc0327b71c6a9c02f4c',
                'site': 0x4578, 'instruction': '22ffff97',
                'failure': 0x4648, 'target': 0x4648, 'return': 0,
                'epilogue': 'e0031f2af44f43a9f65742a9fd7b41a9ff030191bf2303d5c0035fd6',
            },
            {
                'symbol': 'getPidQos', 'address': 0x4740, 'size': 176,
                'before': 'e74c7302d2aac3499ba4825c5bbc16fe4dc5ef10d15c3aea2aa87a97cfa336df',
                'after': '142475863800f2f364229b40a4ee4ae063fdffb631b31d24e3afc1aecd1c5025',
                'site': 0x4754, 'instruction': 'abfeff97',
                'failure': 0x47dc, 'target': 0x47dc, 'return': -1,
                'epilogue': '00008012f30b40f9fd7bc2a8bf2303d5c0035fd6',
            },
            {
                'symbol': 'getTidQos', 'address': 0x47f0, 'size': 176,
                'before': '4c16583300cfe5571f45c1250793f1c3a857338538175ad86eb471797c63c9ab',
                'after': '93a7680401ef038f8c248beb76aa00098b89f23ec4fd7bc8d119a91cb9cf97c3',
                'site': 0x4804, 'instruction': '7ffeff97',
                'failure': 0x488c, 'target': 0x488c, 'return': -1,
                'epilogue': '00008012f30b40f9fd7bc2a8bf2303d5c0035fd6',
            },
            {
                'symbol': 'enableAsyncBinderFlag', 'address': 0x48a0, 'size': 244,
                'before': '4f03bf78441380c3015649e65fef875aa0d72a6ab4b9633c5a6e82d7e81749c8',
                'after': '5ecf5ef264cdfd2d8546a93709f022a829ba47e676c6c8393e68bf197b4cef65',
                'site': 0x48b8, 'instruction': '52feff97',
                'failure': 0x48e8, 'target': 0x48e8, 'return': 0,
                'epilogue': 'e0031f2af44f42a9fd7b41a9ffc30091bf2303d5c0035fd6',
            },
        ),
    },
    '3847994ae15d66e41f2e96e6a0588461ef7044a4c5887c566c8c8b44ab8ae4c3': {
        'size': 51488,
        'after': '2b923cfc351e5dbe26811342765323ca7f1db2be1a9a30aeb8b47dc8d041c9e3',
        'text_size': 0x90c,
        'pac': False,
        'initialize': (0x412c, 0x180, 'f506ddcb1d59e2b932066f238bd1018d940e5ead82e75babd2644c5b6dbca937'),
        'functions': (
            {
                'symbol': 'setTidQos', 'address': 0x4014, 'size': 280,
                'before': '662d31979b190218b23af0c74ee319ddc61df79e96d5bd59ba982f8754a1db90',
                'after': 'feaaba802aaecade06fcbed080e15a126da386227dd351ba16719d4a31c16df3',
                'site': 0x4040, 'instruction': '3b000094',
                'failure': 0x4090, 'target': 0x40bc, 'return': 0,
                'epilogue': 'e0031f2ac81640f9e90740f91f0109ebe102005400000012f44f43a9f65742a9fd7b41a9ff030191c0035fd6',
            },
            {
                'symbol': 'setTaskRtg', 'address': 0x42ac, 'size': 220,
                'before': 'a795033d8c5144e9b2dd37a08d50f20c5f0ee84284d79a4fece2e6fc2a74757a',
                'after': '4c8498733ffe0dd79194d9553a209808adc750e3a7270a62ed5f99a950f52a40',
                'site': 0x42d4, 'instruction': '96ffff97',
                'failure': 0x4344, 'target': 0x435c, 'return': 0,
                'epilogue': 'e0031f2aa81640f9e90740f91f0109ebc1000054f44f43a9f65742a9fd7b41a9ff030191c0035fd6',
            },
            {
                'symbol': 'resetTaskRtg', 'address': 0x4388, 'size': 220,
                'before': '17b654f0ab669922ace2b922c6c7fc83d3769e8d28c7db82a62d75e939856526',
                'after': '9bd834104fa27d8ae602f49d3b6710a0e6547c3e8891df0223ee8e9470a2de93',
                'site': 0x43ac, 'instruction': '60ffff97',
                'failure': 0x4420, 'target': 0x4438, 'return': 0,
                'epilogue': 'e0031f2aa81640f9e90740f91f0109ebc1000054f44f43a9f65742a9fd7b41a9ff030191c0035fd6',
            },
            {
                'symbol': 'setTidQosLevel', 'address': 0x4464, 'size': 524,
                'before': 'f047b10626ddf43840be410328891b2b57ac89ae334dfc2890775dd1a2158518',
                'after': '0ea8a61866e241cf5d74c771e6a8aa8f1a4d18a060867b9a48fcd9670f1d4f68',
                'site': 0x4494, 'instruction': '26ffff97',
                'failure': 0x4510, 'target': 0x458c, 'return': 0,
                'epilogue': 'e0031f2ac81640f9e90740f91f0109eb81060054f44f44a9f71340f9f65743a9fd7b41a9ff430191c0035fd6',
            },
            {
                'symbol': 'getPidQos', 'address': 0x4670, 'size': 208,
                'before': '203a12f12e0cb57b24f6c32914872bd9dbce8f52bc1676f04e65c154ea9fe474',
                'after': 'df47ad161e812384804917fa5a8554acf73b5bfbb9b9982808eed5315d3fd41c',
                'site': 0x4690, 'instruction': 'a7feff97',
                'failure': 0x4718, 'target': 0x4718, 'return': -1,
                'epilogue': '00008012881640f9e90740f91f0109eba1000054f44f42a9fd7b41a9ffc30091c0035fd6',
            },
            {
                'symbol': 'getTidQos', 'address': 0x4740, 'size': 208,
                'before': 'f07589cae7b473d42864413d2dd800cab86173a53300ffa36e93a2e95779177e',
                'after': '487639957e488a19a2b95c9e4a5bc84fa2903dbba35286998a95697c9aa99d69',
                'site': 0x4760, 'instruction': '73feff97',
                'failure': 0x47e8, 'target': 0x47e8, 'return': -1,
                'epilogue': '00008012881640f9e90740f91f0109eba1000054f44f42a9fd7b41a9ffc30091c0035fd6',
            },
            {
                'symbol': 'enableAsyncBinderFlag', 'address': 0x4810, 'size': 252,
                'before': '7cfe70cb1073791d59e9efe26dc6f88041caeb7f0f3970aece0f9746f2badffb',
                'after': 'caf5dc8eea7e1f4f3c9cb9d812028df3d078ee0816a0ee26235e0c59fb60cc03',
                'site': 0x4834, 'instruction': '3efeff97',
                'failure': 0x4860, 'target': 0x4878, 'return': 0,
                'epilogue': 'e0031f2a881640f9e90740f91f0109eb01040054f44f43a9f51340f9fd7b41a9ff030191c0035fd6',
            },
        ),
    },
}


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def select_recipe(data):
    """Accept only a registered whole ELF or its exact deterministic derivative."""
    digest = _sha(data) if isinstance(data, (bytes, bytearray)) else data
    for before, recipe in RECIPES.items():
        if digest in (before, recipe['after']):
            return before, recipe, digest == recipe['after']
    raise RuntimeError('Unsupported XQos ELF SHA-256: ' + str(digest))


def _symbols(data, sections, kind):
    result = {}
    for section in sections:
        if section[1] != kind:
            continue
        if section[9] != 24 or section[5] % 24 or section[6] >= len(sections):
            raise RuntimeError('Unexpected XQos symbol layout.')
        strings = sections[section[6]]
        if strings[1] != 3:
            raise RuntimeError('Unexpected XQos symbol strings.')
        table = data[strings[4]:strings[4] + strings[5]]
        for offset in range(section[4], section[4] + section[5], 24):
            name, info, _, index, address, size = struct.unpack_from('<IBBHQQ', data, offset)
            end = table.find(b'\0', name)
            if name >= len(table) or end < 0:
                raise RuntimeError('Unterminated XQos symbol.')
            if not index or info != 0x12:
                continue
            symbol = bytes(table[name:end])
            if symbol in result or index >= len(sections):
                raise RuntimeError('Ambiguous XQos exported function.')
            result[symbol] = (index, address, size)
    return result


def _branch_target(word, address):
    immediate = word & 0x3ffffff
    if immediate & 0x2000000:
        immediate -= 0x4000000
    return address + immediate * 4


def _replacement(function):
    return struct.pack('<I', 0x14000000 | ((function['target'] - function['site']) // 4))


def audit(data):
    """Bind all exported operations to the authenticated failure return paths."""
    before, recipe, patched = select_recipe(data)
    if len(data) != recipe['size'] or struct.unpack_from('<Q', data, 32)[0] != 64:
        raise RuntimeError('Unexpected XQos ELF length/program table.')
    sections, names = _sections(data)
    code = names.get(b'.text')
    if code is None or code[1:6] != (1, 6, 0x4000, 0x4000, recipe['text_size']):
        raise RuntimeError('Unexpected XQos executable section.')
    expected = {f['symbol'].encode(): (sections.index(code), f['address'], f['size'])
                for f in recipe['functions']}
    if _symbols(data, sections, 11) != expected:
        raise RuntimeError('Unexpected complete XQos exported API.')
    header_size, count = struct.unpack_from('<HH', data, 54)
    if header_size != 56 or count not in (10, 12) or 64 + count * header_size > len(data):
        raise RuntimeError('Unexpected XQos executable mappings.')
    mappings = []
    for offset in range(64, 64 + count * header_size, header_size):
        kind, flags, start, virtual, _, size, _, _ = struct.unpack_from('<IIQQQQQQ', data, offset)
        if kind == 1 and flags == 5:
            mappings.append((start, virtual, size))
    if len(mappings) != 1 or mappings[0][:2] != (0x4000, 0x4000):
        raise RuntimeError('Unexpected XQos executable file mapping.')
    debug = names.get(b'.gnu_debugdata')
    if debug is None or debug[5] != 0x128:
        raise RuntimeError('Unexpected XQos initializer debug symbols.')
    try:
        decoder = lzma.LZMADecompressor(memlimit=4 * 1024 * 1024)
        symbols = decoder.decompress(data[debug[4]:debug[4] + debug[5]], max_length=737)
    except lzma.LZMAError as error:
        raise RuntimeError('Invalid XQos initializer debug data.') from error
    if not decoder.eof or decoder.unused_data or len(symbols) != 736:
        raise RuntimeError('Unbounded XQos initializer debug data.')
    debug_sections, _ = _sections(symbols)
    init_address, init_size, init_sha = recipe['initialize']
    if _symbols(symbols, debug_sections, 2).get(INITIALIZER) != (1, init_address, init_size):
        raise RuntimeError('Unexpected XQos initializer symbol extent.')
    if _sha(data[init_address:init_address + init_size]) != init_sha:
        raise RuntimeError('Unexpected XQos physical initializer body.')
    rodata = names.get(b'.rodata')
    strings = data[rodata[4]:rodata[4] + rodata[5]] if rodata else b''
    if not all(value + b'\0' in strings for value in
               (b'ro.vendor.qos.v1.enable', *(node.encode() for node in ABSENT_NODES))):
        raise RuntimeError('Missing XQos physical driver/property binding.')
    if (b'.note.gnu.property' in names) != recipe['pac']:
        raise RuntimeError('Unexpected XQos branch protection metadata.')
    for function in recipe['functions']:
        start, size = function['address'], function['size']
        site, target = function['site'], function['target']
        if not (start < site < function['failure'] <= target < start + size
                and site % 4 == target % 4 == 0
                and start + size <= mappings[0][1] + mappings[0][2]):
            raise RuntimeError('XQos failure branch leaves its audited function.')
        body = data[start:start + size]
        if _sha(body) != function['after' if patched else 'before']:
            raise RuntimeError('Unexpected XQos exported function body.')
        original = bytes.fromhex(function['instruction'])
        word = struct.unpack('<I', original)[0]
        if word >> 26 != 0x25 or _branch_target(word, site) != init_address:
            raise RuntimeError('Unexpected canonical XQos initializer call.')
        replacement = _replacement(function)
        if data[site:site + 4] != (replacement if patched else original):
            raise RuntimeError('Unexpected XQos capability instruction.')
        tbz, = struct.unpack_from('<I', data, site + 4)
        displacement = (tbz >> 5) & 0x3fff
        if displacement & 0x2000:
            displacement -= 0x4000
        if tbz & 0xfff8001f != 0x36000000 or site + 4 + displacement * 4 != function['failure']:
            raise RuntimeError('Unexpected XQos original initialize-failure gate.')
        epilogue = bytes.fromhex(function['epilogue'])
        assignment = bytes.fromhex('00008012' if function['return'] == -1 else 'e0031f2a')
        if (data[target:target + len(epilogue)] != epilogue
                or not epilogue.startswith(assignment)
                or not epilogue.endswith(bytes.fromhex('c0035fd6'))
                or (recipe['pac'] and (data[start:start + 4] != bytes.fromhex('3f2303d5')
                    or not epilogue.endswith(bytes.fromhex('bf2303d5c0035fd6'))))):
            raise RuntimeError('Unexpected XQos failure value/stack/PAC epilogue.')
    return before, recipe, patched


def patch_bytes(data):
    """Patch seven local calls, preserving all other bytes and loaded ABI."""
    _, recipe, patched = audit(data)
    if patched:
        return bytes(data)
    result = bytearray(data)
    for function in recipe['functions']:
        offset = function['site']
        result[offset:offset + 4] = _replacement(function)
    if len(result) != len(data) or _sha(result) != recipe['after']:
        raise RuntimeError('XQos deterministic derivative mismatch.')
    audit(result)
    return bytes(result)


def recipe_receipt(before):
    """Canonical equal-length sites for an offline, capability-gated consumer."""
    if before not in RECIPES:
        raise RuntimeError('Unknown XQos recipe source.')
    recipe = RECIPES[before]
    return {'schema': 1, 'id': 'xqos-physical-backend-v1', 'path': NATIVE,
            'format': 'elf', 'before': before, 'after': recipe['after'],
            'size': recipe['size'], 'requires': REQUIRES,
            'absent_nodes': list(ABSENT_NODES),
            'sites': [{'offset': f['site'], 'before': f['instruction'],
                       'after': _replacement(f).hex(), 'method': f['symbol']}
                      for f in recipe['functions']]}


def catalog_recipes():
    return tuple(recipe_receipt(before) for before in RECIPES)


def receipt(data):
    before, _, _ = audit(data)
    return recipe_receipt(before)


def patch(source, destination):
    """Atomically publish a separate derivative without replacing unknown files."""
    source, destination = Path(source), Path(destination)
    if source.resolve() == destination.resolve():
        raise RuntimeError('Keep the factory XQos ELF and derivative separate.')
    result = patch_bytes(source.read_bytes())

    def verify_existing():
        info = destination.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or destination.read_bytes() != result):
            raise RuntimeError('Preserving an unknown XQos derivative output.')

    if destination.exists() or destination.is_symlink():
        verify_existing()
        return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.xqos-', dir=destination.parent)
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
