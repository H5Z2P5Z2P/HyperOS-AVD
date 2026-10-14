#!/usr/bin/env python3
"""Return audited missing-HAL results without physical QTI Binder lookups.

Five lookup calls return their original false/null ABI values. The existing
failure branches, defaults, locks, refcounts, PAC, CFI, exception handling and
logs remain intact. In particular, HIDL's hidden android::sp<T> result is one
pointer at x8; leaving that return slot uninitialized would be unsafe.

Core must separately authenticate complete ranchu VINTF absence before using
this derivative. A failed live service lookup never establishes that absence.
No scheduler, boost parameters, permissions or ELF metadata are changed.
The separate V2 stage uses each caller's original unavailable branch before
entering these guards; the immutable V1 producer and receipts remain available.
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
V1_BEFORE = '8c51989df752a5b1524b8833cb380b6540f041d9fdf4187fdcdefceb94fc3cc7'
RECIPES = {
    V1_BEFORE: {
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


# V1 stays immutable. V2 bypasses its absent-HAL bool guards at each caller,
# preserving the original caller fallback without running discovery/locks again.
FALLBACK_BEFORE = RECIPES[V1_BEFORE]["after"]
FALLBACK_AFTER = '0eafc5f2dc1465a69f0b549413241518faa43e2bbe41aae753aec3c8ed70c90b'
FALLBACK_WORD = bytes.fromhex('e0031f2a')  # MOV W0,WZR; scalar false only.
FALLBACK_CALLS = (
    (0xd620, '1f000094', 0xd69c),
    (0xdf14, 'e2fdff97', 0xd69c),
    (0xdf20, '3e020094', 0xe818),
    (0xf700, 'e7f7ff97', 0xd69c),
    (0xf708, '44fcff97', 0xe818),
    (0xfde0, '2ff6ff97', 0xd69c),
    (0xfde8, '8cfaff97', 0xe818),
    (0x103d8, 'b1f4ff97', 0xd69c),
    (0x103e4, '0df9ff97', 0xe818),
    (0x11154, '52f1ff97', 0xd69c),
    (0x11160, 'aef5ff97', 0xe818),
    (0x11674, '0af0ff97', 0xd69c),
    (0x11680, '66f4ff97', 0xe818),
    (0x11ebc, 'f8edff97', 0xd69c),
    (0x11ec8, '54f2ff97', 0xe818),
    (0x126c8, 'f5ebff97', 0xd69c),
    (0x126d4, '51f0ff97', 0xe818),
    (0x12e28, '1deaff97', 0xd69c),
    (0x12e34, '79eeff97', 0xe818),
    (0x133b0, 'bbe8ff97', 0xd69c),
    (0x133bc, '53010094', 0x13908),
    (0x13f4c, 'd4e5ff97', 0xd69c),
    (0x13f58, '6cfeff97', 0x13908),
    (0x14390, 'c3e4ff97', 0xd69c),
    (0x1439c, '5bfdff97', 0x13908),
    (0x14944, '56e3ff97', 0xd69c),
    (0x14950, 'eefbff97', 0x13908),
    (0x14958, 'b0e7ff97', 0xe818),
    (0x14f04, 'e6e1ff97', 0xd69c),
    (0x14f10, '7efaff97', 0x13908),
    (0x14f18, '40e6ff97', 0xe818),
    (0x151a8, '3de1ff97', 0xd69c),
    (0x151b4, 'd5f9ff97', 0x13908),
    (0x151bc, '97e5ff97', 0xe818),
    (0x15658, '11e0ff97', 0xd69c),
    (0x15664, 'a9f8ff97', 0x13908),
    (0x1566c, '6be4ff97', 0xe818),
    (0x15b98, '20e3ff97', 0xe818),
    (0x15e00, '86e2ff97', 0xe818),
    (0x15f8c, 'c4ddff97', 0xd69c),
    (0x16744, 'd6dbff97', 0xd69c),
)
FALLBACK_OWNERS = (
    ('_Z13isHalTypeAidlv.cfi', 0xd4e4, 440,
     '8dd9aa232951c326bb12209413c491b8e608e6161d6acbb3538510dadf2713e5',
     'c99b5f14b1df3dd0eeedd3b4f68717ddd71768a9c0f287f8e353315912511f63'),
    ('perf_lock_acq.cfi', 0xded8, 2368,
     '3e730a26d459e77d0bff5ed52c097e3e02aacc62ddf94c8772874a7681c25b03',
     '67a0a5fa71b5c7b07fd66f8bb00ae84b0ed8449e3ca641433c648a7ade773c8a'),
    ('perf_lock_rel.cfi', 0xf6d4, 1260,
     '44b2f8abbd046ee1c2d0b1d83fc805e3ddbe2003863066fda65eb996aaf71df4',
     'd254f361fca43cf5769bacdd9d43092b367ac01e6fec2992fd9756432176eaa4'),
    ('perf_hint_rel.cfi', 0xfdb4, 1480,
     '9c20cfc940d482c13280ee4fd833d9b450401bc2572377fc9a928a48c78959ef',
     '8bca7a44830e632b6d8f2f209ca3767b9d7c9de9fdaeb56a83d9a98b32c05c25'),
    ('_ZL17perf_hint_privateiPKciiiiPi', 0x10390, 1424,
     'db022d85f7d7125f322cc9dd2ccb267369c0c74a4c32561650a6fc97eb8cd2be',
     '3d8b34d748c620f3d8600c268d627d281014fcc5b9e40ce4884a31aedf49b0d1'),
    ('perf_get_feedback_extn.cfi', 0x1111c, 1292,
     '405dd390521e972fe94bdba66df1e9b4646624253d6072baf67377dbc03d038b',
     'eed85a4c2d77b09f0436cc8a24891f32cb3d6b6732f152849b9939ee8d61a894'),
    ('perf_get_prop.cfi', 0x11628, 1796,
     '053dd11751c00516b37d087650cb1ce29c2ecdca74f418d9ebe774fd6f0dfc6a',
     '97987e8c61f3c2210f594a398bc9fc1c4dbb9e786c854be75152a4379dcbb480'),
    ('perf_sync_request.cfi', 0x11e88, 1904,
     'c5335b188a9cff45f768cd15121aa3e3a66c82c7e47b317c41874b844345c05a',
     '6fa6befaff4b881a97bf5755c8cca731044a5eb38a106eac2562a398f144266d'),
    ('perf_lock_acq_rel.cfi', 0x12688, 1872,
     'e40a99226e73a9f272904fc0fd612e48324fefdf05dfe6485e5b06e7f48115cf',
     'a4c686611c2eb06e9ee0ccd588bc8fc84be64178d10116fdb18f2265d34fb068'),
    ('_ZL18perf_event_privateiPKciiPi', 0x12dec, 1380,
     'a5b5cb9f612df21c79efbe0be5e912a86a82585e68dddaab031e07936ef2e0ae',
     '3f4fb87f5abd2257920703a9a1eab087c0d88d53a84722af0497465b4a83f0bd'),
    ('_ZL25perf_hint_acq_rel_privateiiPKciiiiPi', 0x13364, 1444,
     'e7f1389f26c3f4b7ef05c35fec347793376fb2a937bd4b6df26e58b5bd6178d7',
     '285fff0f2b181ce98066286b3f1ae042edbc613c2f5bf4eee466cdc0263913b8'),
    ('perf_hint_async.cfi', 0x13f00, 1096,
     '43596fe370ed45668d05ed714efb96b9580f7990cd8e96d00460c6c86faf14e5',
     '41adf68f1a2b308e964acf86e04b46ddcdd052fccf7b29c9daf921f8f1febd94'),
    ('perf_hint_renew.cfi', 0x14348, 1420,
     '2cf9d0bd728f9de94360c8c12205f09813a8db1684c0c45bf3fd22826c85c7bc',
     '07bfb0a15183904a61e389a15015afd65d4a926e245bfe76c6e2880512a24868'),
    ('perf_hint_offload.cfi', 0x148d4, 872,
     'd0a38c58dd139524b52a2615f4441d4debf6dfb77bc2252f8c5292851309797e',
     'fae57d08011438f0f11c1c21243ad4a12316b09a8be50cbf7cc813b1488efe0c'),
    ('perf_lock_rel_offload.cfi', 0x14ee0, 416,
     'e6088e2854f277383912e84f93442502e9e9198c7277b052c33b122374405460',
     'af87cd22aa44e8f80d5854d72f04e9aa5115681562e8f6633452df28a81cf5fd'),
    ('perf_hint_acq_rel_offload.cfi', 0x15134, 904,
     'b073c4a4e31f31bc3cd9a2e062f9df9abd3b4f922be36856e25de2981358ec6c',
     '9d0b3a5df1cb0a5e3df55e3d4e1fd303fc89a87e2614b3337329e4fc3e487d9d'),
    ('perf_event_offload.cfi', 0x155f8, 784,
     '93f3db062774dcfb615ebd1e7e5d1af8744d1be6e4d775922d0df49778f8da84',
     'bd70c32fc782b77e17292f98d50b9a76e18c38d99ccf6e013d7c34c22850e25c'),
    ('perf_lock_use_profile.cfi', 0x15a8c, 640,
     '2172c5a778590d6a1371e7d3d24c5bcb3f93ee3f083fc35ad7b20c87bf8c4c54',
     'ad14a1fb296a5e8f0b85d23cbaf321bce47a8480309c6b4635f20aa4dfe038ce'),
    ('perf_lock_cmd.cfi', 0x15d0c, 604,
     'bb74f52f5ccfacf6fd9c3878c41191ffad4555f595bd9350268aa6e517469367',
     '316c39b2a70b2a1f802d8c5b99bc9f9edc78cc57df9f4fa42e216a969ef04030'),
    ('perf_callback_register.cfi', 0x15f68, 744,
     '7ca9eb246cc3fcce1762b04d069187d67160d6bb0e28b25cc877248a65f9e6d2',
     'daba591c5a27eabf79a55266fb0666f0fa126387d4f932ac6639a148d67b5676'),
    ('perf_callback_deregister.cfi', 0x16724, 848,
     '58434d909f4d4f5f3b39ed9b6fe432253519f2a03ada4ce9a1adf5d2c9e1ea11',
     'eb9ae31c387fd3b8ff1a27d865bc3a0a8f97cff118f7fd0dee00b33de8237fa3'),
)


def _guard_boolean_consumer(data, site):
    """Audit the existing W0 bit-zero consumer; never synthesize a success value."""
    cursor = site + 4
    word, = struct.unpack_from('<I', data, cursor)
    if word >> 26 == 0x05:
        cursor = _branch_target(word, cursor)
        word, = struct.unpack_from('<I', data, cursor)
    register = 0
    if word == 0x2a0003e8:  # The release wrappers retain W0 in W8.
        words = struct.unpack_from('<3I', data, cursor + 4)
        if words[0] != 0x12800000 or words[1] >> 24 != 0x34 or words[1] & 31 != 19:
            raise RuntimeError('Changed QTI Perf release default/handle guard.')
        cursor += 12
        word = words[2]
        register = 8
    if word >> 24 not in (0x36, 0x37) or (word >> 19) & 31 or word & 31 != register:
        raise RuntimeError('Unverified QTI Perf scalar-bool fallback consumer.')
    return cursor


def fallback_audit(data):
    """Authenticate V2 independently while preserving the frozen V1 recipe."""
    if not isinstance(data, (bytes, bytearray)):
        raise RuntimeError('Unsupported QTI Perf fallback input.')
    data = bytes(data)
    identity = _sha(data)
    if identity not in (FALLBACK_BEFORE, FALLBACK_AFTER):
        raise RuntimeError('Unsupported QTI Perf fallback SHA-256: ' + identity)
    patched = identity == FALLBACK_AFTER
    base = bytearray(data)
    for site, original, target in FALLBACK_CALLS:
        expected = FALLBACK_WORD if patched else bytes.fromhex(original)
        if data[site:site + 4] != expected:
            raise RuntimeError('Changed QTI Perf unavailable guard call.')
        base[site:site + 4] = bytes.fromhex(original)
        word, = struct.unpack('<I', bytes.fromhex(original))
        if word >> 26 != 0x25 or _branch_target(word, site) != target:
            raise RuntimeError('Unverified QTI Perf guard target.')
    base = bytes(base)
    _, recipe, previous = audit(base)
    if not previous or _sha(base) != FALLBACK_BEFORE:
        raise RuntimeError('QTI Perf fallback requires the complete reviewed V1 derivative.')
    sections, names = _sections(base)
    debug = names[b'.gnu_debugdata']
    debug_data = lzma.decompress(base[debug[4]:debug[4] + debug[5]], memlimit=32 * 1024**2)
    debug_sections, _ = _sections(debug_data)
    functions = _symbols(debug_data, debug_sections, 2)
    for name, start, length, before, after in FALLBACK_OWNERS:
        if (functions.get(name.encode()) != (1, start, length)
                or _sha(data[start:start + length]) != (after if patched else before)
                or data[start:start + 4] != bytes.fromhex('3f2303d5')):
            raise RuntimeError('Changed QTI Perf fallback caller or PAC frame.')
    expected = {site for site, _, _ in FALLBACK_CALLS}
    targets = {row['address'] for row in recipe['functions'][1:4]}
    if targets != {target for _, _, target in FALLBACK_CALLS}:
        raise RuntimeError('Incomplete QTI Perf unavailable-guard coverage.')
    code = names[b'.text']
    calls = set()
    for address in range(code[3], code[3] + code[5], 4):
        word, = struct.unpack_from('<I', data, code[4] + address - code[3])
        if word >> 26 in (0x05, 0x25) and _branch_target(word, address) in targets:
            calls.add(address)
    if calls != (set() if patched else expected):
        raise RuntimeError('Remaining or unreviewed QTI Perf guard invocation.')
    for site, _, _ in FALLBACK_CALLS:
        owners = [(start, size) for _, start, size, _, _ in FALLBACK_OWNERS
                  if start <= site < start + size]
        consumer = _guard_boolean_consumer(base, site)
        if len(owners) != 1:
            raise RuntimeError('Unverified QTI Perf fallback caller boundary.')
        start, length = owners[0]
        if not start <= consumer < start + length:
            raise RuntimeError('Unverified QTI Perf fallback consumer boundary.')
    return patched


def fallback_patch_bytes(data):
    """Select each caller's original unavailable result before discovery work."""
    if fallback_audit(data):
        return bytes(data)
    output = bytearray(data)
    for site, _, _ in FALLBACK_CALLS:
        output[site:site + 4] = FALLBACK_WORD
    result = bytes(output)
    if len(result) != len(data) or _sha(result) != FALLBACK_AFTER or not fallback_audit(result):
        raise RuntimeError('QTI Perf fallback deterministic derivative mismatch.')
    return result


def fallback_recipe_receipt():
    return {'schema': 1, 'id': 'qti-perf-absent-guard-fallback-v2', 'path': NATIVE,
            'format': 'elf', 'before': FALLBACK_BEFORE, 'after': FALLBACK_AFTER,
            'size': RECIPES[V1_BEFORE]['size'], 'requires': REQUIRES,
            'absent_hal_packages': list(ABSENT_HAL_PACKAGES),
            'absent_services': list(ABSENT_SERVICES),
            'sites': [{'offset': site, 'before': original, 'after': FALLBACK_WORD.hex(),
                       'method': next(name for name, start, size, _, _ in FALLBACK_OWNERS
                                      if start <= site < start + size)}
                      for site, original, _ in FALLBACK_CALLS]}


def catalog_recipes():
    return (*tuple(recipe_receipt(before) for before in RECIPES), fallback_recipe_receipt())


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
