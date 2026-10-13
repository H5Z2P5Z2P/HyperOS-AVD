#!/usr/bin/env python3
"""Return audited missing-HAL results without physical QTI Binder lookups.

Five lookup calls return their original false/null ABI values. The existing
failure branches, defaults, locks, refcounts, PAC, CFI, exception handling and
logs remain intact. In particular, HIDL's hidden android::sp<T> result is one
pointer at x8; leaving that return slot uninitialized would be unsafe.

Core must separately authenticate complete ranchu VINTF absence before using
this derivative. A failed live service lookup never establishes that absence.
No scheduler, boost parameters, permissions or ELF metadata are changed.
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
from patch_xqos import _symbols

NATIVE = '/system_ext/lib64/libqti-perfd-client_system.so'
REQUIRES = 'ranchu-without-qti-perf-hal'
ABSENT_HAL_PACKAGES = ('vendor.qti.hardware.perf', 'vendor.qti.hardware.perf2')
ABSENT_SERVICES = ('vendor.qti.hardware.perf2.IPerf/default',
                   'vendor.qti.hardware.perf@2.2::IPerf/default',
                   'vendor.qti.hardware.perf@2.3::IPerf/default')
RECIPES = {
    '8c51989df752a5b1524b8833cb380b6540f041d9fdf4187fdcdefceb94fc3cc7': {
        'size': 136176,
        'after': '0f2c5881210cc84479f6a8f93d142436b5635feda41534e3cbe1c0a4ded7351c',
        'text': (1, 0x200006, 0xc000, 0xc000, 0xe018),
        'immutable_sha256': 'c2ed025be882dbfd3055299bdef0f8356542884861fed97159bd9994325da173',
        'debug_sha256': 'ac83be0cb619264ea6a5bb79b4278eec1325fefa013dbce5967336e0bc04b657',
        'functions': (
            {'symbol': '_Z13isHalTypeAidlv.cfi', 'address': 0xd4e4, 'size': 440,
             'before': 'a6cbb9b800e5cac66a10528e68cf75c8755ffb16c3ee355efdf5e1f5f7a14777',
             'after': '8dd9aa232951c326bb12209413c491b8e608e6161d6acbb3538510dadf2713e5',
             'site': 0xd5dc, 'instruction': 'f3320094', 'replacement': 'e0031f2a',
             'result': 'declared-false', 'plt': 0x1a1a8},
            {'symbol': '_ZL25getPerfAidlAndLinkToDeathv', 'address': 0xd69c, 'size': 1404,
             'before': '1b6ea017dd190b5911825bd6f9e241a0177dc3fbc7849510b9e5818f0bd8137d',
             'after': '0a044aaaec9d4bbf9cad76f158d79dd1439eb49b7e683d3c34364314d9910a41',
             'site': 0xd7fc, 'instruction': '19330094', 'replacement': 'e0031faa',
             'result': 'binder-null', 'plt': 0x1a460},
            {'symbol': '_ZL28getPerfServiceAndLinkToDeathv', 'address': 0xe818, 'size': 1432,
             'before': 'c770550f43385efd486e1477cbb62c9f5ad23d3e0d564974a1c59e3d16a89c32',
             'after': '98bda7ea588b02b78002b1ce313ba619de80ce155b365055f3a7ea38c2b06e67',
             'site': 0xe954, 'instruction': '112f0094', 'replacement': '1f0100f9',
             'result': 'sp-null', 'plt': 0x1a598},
            {'symbol': '_ZL32getPerfServiceAndLinkToDeathV2_3v', 'address': 0x13908, 'size': 1528,
             'before': 'd2faf066aff0d81ba9f1d0cbcc2f6a1f8468c3e86722235de65e552b47fb78e7',
             'after': 'e635420ecd92a232fb0c90c6cf768355e39cabd5ea904c35c81c5035ace25d25',
             'site': 0x13aa8, 'instruction': '041b0094', 'replacement': '1f0100f9',
             'result': 'sp-null', 'plt': 0x1a6b8},
            {'symbol': 'perf_wait_get_prop.cfi', 'address': 0x16bc4, 'size': 1124,
             'before': '46ee9bf5fae309f1a8110de0ea2a03921cb80c4799bb4e865db7c56b6c93ed5e',
             'after': 'a5ba6d2f6ce51a4a6ab873a88c9a96a983eda53560de685efc5f7224c340ad9f',
             'site': 0x16ed8, 'instruction': '1a0d0094', 'replacement': '1f0100f9',
             'result': 'sp-null', 'plt': 0x1a340},
        ),
    },
}


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def select_recipe(data):
    checksum = _sha(data) if isinstance(data, (bytes, bytearray)) else data
    for before, recipe in RECIPES.items():
        if checksum in (before, recipe['after']):
            return before, recipe, checksum == recipe['after']
    raise RuntimeError('Unsupported QTI Perf ELF SHA-256: ' + str(checksum))


def _branch_target(word, address):
    displacement = word & 0x3ffffff
    if displacement & 0x2000000:
        displacement -= 0x4000000
    return address + displacement * 4


def audit(data):
    """Bind all five physical imports and their original failure-result ABI."""
    before, recipe, patched = select_recipe(data)
    if (len(data) != recipe['size'] or data[:7] != b'\x7fELF\x02\x01\x01'
            or struct.unpack_from('<H', data, 18)[0] != 183):
        raise RuntimeError('Unexpected QTI Perf ELF length or ABI.')
    sections, names = _sections(data)
    code = names.get(b'.text')
    if code is None or code[1:6] != recipe['text']:
        raise RuntimeError('Unexpected QTI Perf executable section.')
    offset, size = code[4:6]
    if _sha(data[:offset] + data[offset + size:]) != recipe['immutable_sha256']:
        raise RuntimeError('Changed QTI Perf metadata, CFI or relocation data.')
    debug = names.get(b'.gnu_debugdata')
    if debug is None or _sha(data[debug[4]:debug[4] + debug[5]]) != recipe['debug_sha256']:
        raise RuntimeError('Unexpected QTI Perf reviewed function provenance.')
    try:
        symbols = lzma.decompress(data[debug[4]:debug[4] + debug[5]], memlimit=32 * 1024**2)
        if len(symbols) > 2 * 1024**2:
            raise RuntimeError('Unexpected QTI Perf debug data size.')
        debug_sections, _ = _sections(symbols)
        functions = _symbols(symbols, debug_sections, 2)
    except (lzma.LZMAError, ValueError, struct.error) as error:
        raise RuntimeError('Invalid QTI Perf function provenance.') from error
    sites = recipe['functions']
    physical_targets = {row['plt'] for row in sites}
    calls = set()
    for address in range(code[3], code[3] + size, 4):
        word, = struct.unpack_from('<I', data, offset + address - code[3])
        if word >> 26 in (0x05, 0x25) and _branch_target(word, address) in physical_targets:
            calls.add(address)
    if calls != (set() if patched else {row['site'] for row in sites}):
        raise RuntimeError('Unreviewed or remaining physical QTI Perf lookup call.')
    for row in sites:
        start, length, site = row['address'], row['size'], row['site']
        if (functions.get(row['symbol'].encode()) != (1, start, length)
                or not code[3] <= start < site < start + length <= code[3] + size
                or _sha(data[start:start + length]) != row['after' if patched else 'before']
                or data[start:start + 4] != bytes.fromhex('3f2303d5')):
            raise RuntimeError('Changed QTI Perf lookup function body or PAC frame.')
        original = bytes.fromhex(row['instruction'])
        word, = struct.unpack('<I', original)
        if word >> 26 != 0x25 or _branch_target(word, site) != row['plt']:
            raise RuntimeError('Invalid canonical physical QTI Perf lookup.')
        replacement = bytes.fromhex(row['replacement'])
        if data[site:site + 4] != (replacement if patched else original):
            raise RuntimeError('Changed QTI Perf failure-result instruction.')
        if row['result'] == 'sp-null':
            # X8 points to one local android::sp<T> return pointer before the
            # call. The next instructions still move it into the old holder,
            # destroy the temporary, and take the original null-failure path.
            expected = 'e8230191' if row['symbol'] == 'perf_wait_get_prop.cfi' else 'a8630091'
            if data[site - 12:site - 8] != bytes.fromhex(expected) or replacement != bytes.fromhex('1f0100f9'):
                raise RuntimeError('Unverified QTI Perf hidden pointer return slot.')
        elif row['result'] == 'declared-false':
            if replacement != bytes.fromhex('e0031f2a') or data[site + 4:site + 8] != bytes.fromhex('1f000072'):
                raise RuntimeError('Unverified QTI Perf declaration-failure result.')
        elif row['result'] == 'binder-null':
            if replacement != bytes.fromhex('e0031faa') or data[site + 4:site + 12] != bytes.fromhex('e00700f9800800b4'):
                raise RuntimeError('Unverified QTI Perf null Binder failure branch.')
        else:
            raise RuntimeError('Unknown QTI Perf failure ABI.')
    return before, recipe, patched


def patch_bytes(data):
    _, recipe, patched = audit(data)
    if patched:
        return bytes(data)
    result = bytearray(data)
    for row in recipe['functions']:
        result[row['site']:row['site'] + 4] = bytes.fromhex(row['replacement'])
    if _sha(result) != recipe['after'] or len(result) != len(data):
        raise RuntimeError('QTI Perf deterministic derivative mismatch.')
    audit(result)
    return bytes(result)


def recipe_receipt(before):
    if before not in RECIPES:
        raise RuntimeError('Unknown QTI Perf recipe source.')
    recipe = RECIPES[before]
    return {'schema': 1, 'id': 'qti-perf-missing-hal-v1', 'path': NATIVE, 'format': 'elf',
            'before': before, 'after': recipe['after'], 'size': recipe['size'], 'requires': REQUIRES,
            'absent_hal_packages': list(ABSENT_HAL_PACKAGES), 'absent_services': list(ABSENT_SERVICES),
            'sites': [{'offset': row['site'], 'before': row['instruction'],
                       'after': row['replacement'], 'method': row['symbol']}
                      for row in recipe['functions']]}


def catalog_recipes():
    return tuple(recipe_receipt(before) for before in RECIPES)


def receipt(data):
    before, _, _ = audit(data)
    return recipe_receipt(before)


def patch(source, destination):
    """Publish a separate derivative without changing an unknown file or alias."""
    source, destination = Path(source), Path(destination)
    info = source.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or source.resolve() == destination.resolve()):
        raise RuntimeError('Keep the regular factory QTI Perf ELF and derivative separate.')
    result = patch_bytes(source.read_bytes())

    def verify_existing():
        info = destination.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or destination.read_bytes() != result):
            raise RuntimeError('Preserving an unknown QTI Perf derivative output.')

    if destination.exists() or destination.is_symlink():
        verify_existing()
        return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.qti-perf-', dir=destination.parent)
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
