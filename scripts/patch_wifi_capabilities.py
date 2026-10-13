#!/usr/bin/env python3
"""Disable three audited physical WLAN capabilities in unsigned framework JARs.

These exact donor implementations query proprietary force-2chain/LPFCS
properties and initialize XRING SAR hardware absent from ranchu. Only their
boolean capability gates return false. Generic WiFi, radio and SAR code stays
byte-identical. Retain the original ZIP and DEX layout; repair only checksums.
Consumers can apply the canonical equal-length sites offline before boot.
Never apply this recipe to an APK or infer applicability from a device name.
"""
import argparse
import hashlib
import io
import os
from pathlib import Path
import stat
import struct
import tempfile
import zipfile
import zlib

PATH = '/system_ext/framework/miui-wifi-service.jar'
MIUI = 'Lcom/android/server/wifi/MiuiWifiService;'
XRING = 'Lcom/android/server/wifi/wifisar/XringWifiManagerCompatible;'
METHODS = (
    MIUI + '->isEnableForce2ChainDisableDtim()Z',
    MIUI + '->isEnableForceDisableLpFcs()Z',
    XRING + '->isNeeded()Z',
)
# The tuple binds code_item offset, access flags, complete header, and its body.
RECIPES = {
    'c6a34fa077983609ffb2ac25645334524cb16520bf9278f3591a48d0faffeff3': {
        'size': 4676474,
        'after': '432bb9a43edc94dc1e4314159d8596c3336df75a1311f777f0ee8b495468e125',
        'dex_before': '04168b8ee5617ca40a0c53fc754365e77a07c46308cd34c341d5d1f4f03cfd1c',
        'dex_after': '9daf7e7c567a392cd8a23d793d3a6ec1532734fe38197198f92d81785982c244',
        'dex_offset': 44,
        'crc_offsets': (14, 4676345),
        'crc': ('343adba9', '744c856d'),
        'dex_checksums': ('52c852411b681db6bcd2996a4f6d6d838ffd466d6fdeaa98',
                          '63aabebec92af6c597b27668b66f381664f9defdf34bd07b'),
        'instructions': (
            '1a00bc8f1a0143961a0200007120790420000c037120790421000c02120439020a001a057d391a066e217120f50465000f041a0597a26e20ab5b35000a0538050a007020741327000a053805040012140f040f04',
            '1a00bb8f1a0143961a0200007120790420000c037120790421000c02120439020a001a057d391a066e217120f50465000f041a0597a26e20ab5b35000a0538050a007020741327000a053805040012140f040f04',
            '7100904700000a0039000b0071008e4700000a003800030028031200280212100f00',
        ),
        'methods': (
            (0x105c5c, 2, (8, 1, 2, 0, 2857444, 42),
             'f1c5fa3f757aa1064157403850cc36dbf50958294e988e7603efb0d3816cf013'),
            (0x105cc0, 2, (8, 1, 2, 0, 2857486, 42),
             '851015fb1df224a7720f1aa8b43fc348fc7a3497fd52bb79cae1e7efe798cea9'),
            (0x25385c, 9, (1, 0, 0, 0, 3012480, 17),
             '75d7614b3c39cfe08436943e464bcd022f709b9690be79c3e7a6739845495046'),
        ),
    },
    'c20b31873bc656427321bec233a12d78315a63a22d68e71614c6f033e1f06823': {
        'size': 4431874,
        'after': '851d702a4e2974b577467f8b28d50439a52a391d32842f07ad3aaab6f91a8e84',
        'dex_before': '30e3a9d826d8809c058f726e193e29650c4bb235b2260fa5a7b41fd1827a3943',
        'dex_after': '59622bf64e0342c6dc58b4aea4eecaa5204ab739f02033d1daf05e14693fbfdf',
        'dex_offset': 44,
        'crc_offsets': (14, 4431745),
        'crc': ('d0bd9cee', '99dfca40'),
        'dex_checksums': ('d57cee53ce5150bc5d80e01f42db7ef6d2af37121ab01b8d',
                          '5b5e35225d7749c82ebb9ec3319c4a0506e68eb14a047aad'),
        'instructions': (
            '1a0015871a010f8d1a02000071206b0420000c0371206b0421000c02120439020a001a05ef351a062b1f7120e30465000f041a05a5986e207a5735000a0538050a007020ac1227000a053805040012140f040f04',
            '1a0014871a010f8d1a02000071206b0420000c0371206b0421000c02120439020a001a05ef351a062b1f7120e30465000f041a05a5986e207a5735000a0538050a007020ac1227000a053805040012140f040f04',
            '71007c4300000a0039000b0071007a4300000a003800030028031200280212100f00',
        ),
        'methods': (
            (0xf6c8c, 2, (8, 1, 2, 0, 2709775, 42),
             '8ecfc4e8c74d534e390e71e9af449bbede0b7a379e087c18f42b57c545992832'),
            (0xf6cf0, 2, (8, 1, 2, 0, 2709817, 42),
             '29cf3b508c41d119ca9ad25fe7bd19d9e3f66c0ab4e77c87aea8ee2d39290a19'),
            (0x231d38, 9, (1, 0, 0, 0, 2821883, 17),
             '2c9582982d5d0ead3ef709633e648e31b23c269c358502d8c594df4cb7afbba0'),
        ),
    },
}
FALSE_RETURN = bytes.fromhex('12000f00')  # const/4 v0, 0; return v0


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def select_recipe(data):
    """Authenticate a complete known input or its exact registered derivative."""
    digest = _sha(data) if isinstance(data, bytes) else data
    if not isinstance(digest, str):
        raise RuntimeError('Unsupported WiFi framework JAR input.')
    for before, recipe in RECIPES.items():
        if digest == before or (recipe['after'] and digest == recipe['after']):
            return before, recipe, digest != before
    raise RuntimeError('Unsupported WiFi framework JAR input.')


def _unpack(data, offset, fmt):
    if offset < 0 or offset + struct.calcsize(fmt) > len(data):
        raise RuntimeError('WiFi record lies outside the authenticated input.')
    return struct.unpack_from(fmt, data, offset)


def _uleb(data, offset):
    value = 0
    for index in range(5):
        byte, = _unpack(data, offset, '<B')
        offset += 1
        if index == 4 and byte > 15:
            raise RuntimeError('Overflowing WiFi DEX ULEB128.')
        value |= (byte & 127) << (7 * index)
        if not byte & 128:
            return value, offset
    raise RuntimeError('Invalid WiFi DEX ULEB128.')


def _dex_methods(data):
    """Resolve the three code_items through DEX class/method tables."""
    if (data[:8] != b'dex\n039\0'
            or _unpack(data, 32, '<III') != (len(data), 112, 0x12345678)
            or data[12:32] != hashlib.sha1(data[32:]).digest()
            or _unpack(data, 8, '<I')[0] != zlib.adler32(data[12:]) & 0xffffffff):
        raise RuntimeError('Invalid authenticated WiFi DEX header/checksums.')

    def table(offset, width):
        count, start = _unpack(data, offset, '<II')
        if count > len(data) // width or start + count * width > len(data):
            raise RuntimeError('Invalid WiFi DEX table bounds.')
        return count, start

    strings, string_start = table(56, 4)
    types, type_start = table(64, 4)
    protos, proto_start = table(72, 12)
    methods, method_start = table(88, 8)
    classes, class_start = table(96, 32)

    def string(index):
        if index >= strings:
            raise RuntimeError('Invalid WiFi DEX string index.')
        offset, = _unpack(data, string_start + 4 * index, '<I')
        _, offset = _uleb(data, offset)
        end = data.find(b'\0', offset)
        if end < 0:
            raise RuntimeError('Unterminated WiFi DEX string.')
        # Only ASCII class/method descriptors are selected by this parser.
        return data[offset:end].decode('ascii', errors='replace')

    def typename(index):
        if index >= types:
            raise RuntimeError('Invalid WiFi DEX type index.')
        return string(_unpack(data, type_start + 4 * index, '<I')[0])

    result = {}
    for index in range(classes):
        class_id, _, _, _, _, _, offset, _ = _unpack(data, class_start + 32 * index, '<8I')
        owner = typename(class_id)
        if owner not in (MIUI, XRING):
            continue
        counts = []
        for _ in range(4):
            value, offset = _uleb(data, offset)
            counts.append(value)
        if sum(counts) > len(data):
            raise RuntimeError('Invalid WiFi DEX class-data counts.')
        for _ in range(counts[0] + counts[1]):
            _, offset = _uleb(data, offset)
            _, offset = _uleb(data, offset)
        for count in counts[2:]:
            method_id = 0
            for _ in range(count):
                delta, offset = _uleb(data, offset)
                method_id += delta
                access, offset = _uleb(data, offset)
                code, offset = _uleb(data, offset)
                if method_id >= methods:
                    raise RuntimeError('Invalid WiFi DEX method index.')
                class_ref, proto_ref, name_ref = _unpack(data, method_start + 8 * method_id, '<HHI')
                candidate = owner + '->' + string(name_ref) + '()Z'
                if candidate not in METHODS:
                    continue
                if class_ref != class_id or proto_ref >= protos:
                    raise RuntimeError('Unexpected WiFi DEX method owner/prototype.')
                _, return_type, parameters = _unpack(data, proto_start + 12 * proto_ref, '<III')
                if typename(return_type) != 'Z' or parameters or candidate in result:
                    raise RuntimeError('Ambiguous WiFi DEX capability method.')
                result[candidate] = (code, access)
    if set(result) != set(METHODS):
        raise RuntimeError('Missing audited WiFi DEX capability methods.')
    return result


def _zip_layout(data):
    """Locate only the unsigned, stored classes.dex and its two CRC fields."""
    end = len(data) - 22
    if data[end:end + 4] != b'PK\x05\x06':
        raise RuntimeError('Unexpected WiFi ZIP end record.')
    disk, cd_disk, count_disk, count, size, directory, comment = _unpack(data, end + 4, '<4H2IH')
    if (disk or cd_disk or count != 2 or count_disk != count or comment
            or directory + size != end or b'APK Sig Block 42' in data[directory - 24:directory]):
        raise RuntimeError('Unsupported or signed WiFi framework archive.')
    current, dex_entry = directory, None
    names = []
    for _ in range(count):
        fields = _unpack(data, current, '<4s6H3I5H2I')
        if fields[0] != b'PK\x01\x02':
            raise RuntimeError('Invalid WiFi ZIP directory entry.')
        name_length, extra_length, comment_length = fields[10:13]
        name = data[current + 46:current + 46 + name_length]
        names.append(name)
        if name == b'classes.dex':
            if dex_entry is not None or fields[3:5] != (0, 0) or fields[8] != fields[9]:
                raise RuntimeError('Unsupported WiFi DEX ZIP storage.')
            local = fields[16]
            lfh = _unpack(data, local, '<4s5H3I2H')
            if (lfh[0] != b'PK\x03\x04' or lfh[2:4] != (0, 0)
                    or lfh[6:9] != fields[7:10] or lfh[9] != name_length
                    or data[local + 30:local + 30 + name_length] != name):
                raise RuntimeError('WiFi ZIP local/directory mismatch.')
            start = local + 30 + lfh[9] + lfh[10]
            if start + fields[9] > directory:
                raise RuntimeError('Invalid WiFi DEX ZIP bounds.')
            dex_entry = (start, fields[9], local + 14, current + 16)
        current += 46 + name_length + extra_length + comment_length
    if current != end or set(names) != {b'classes.dex', b'META-INF/MANIFEST.MF'} or not dex_entry:
        raise RuntimeError('Unexpected WiFi framework archive entries.')
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        if archive.testzip() is not None:
            raise RuntimeError('Invalid WiFi ZIP checksum.')
        start, length, _, _ = dex_entry
        if archive.read('classes.dex') != data[start:start + length]:
            raise RuntimeError('WiFi stored DEX does not match archive reader.')
    return dex_entry


def _rewrite(data, recipe, patched=False):
    start, length, local_crc, directory_crc = _zip_layout(data)
    if (start, local_crc, directory_crc) != (recipe['dex_offset'], *recipe['crc_offsets']):
        raise RuntimeError('Unexpected WiFi ZIP checksum/data offsets.')
    dex = data[start:start + length]
    expected_dex = recipe['dex_after'] if patched else recipe['dex_before']
    if _sha(dex) != expected_dex:
        raise RuntimeError('Unexpected WiFi DEX content.')
    methods = _dex_methods(dex)
    output = bytearray(data)
    sites = []
    for name, (code, access, header, body_sha) in zip(METHODS, recipe['methods']):
        if methods[name] != (code, access) or _unpack(dex, code, '<4H2I') != header:
            raise RuntimeError('Unexpected WiFi DEX capability code_item: ' + name)
        size = 16 + 2 * header[5]
        item = dex[code:code + size]
        replacement = FALSE_RETURN + b'\0' * (2 * header[5] - 4)
        if header[0] < 1 or header[3] or header[5] < 2 or len(item) != size:
            raise RuntimeError('Unsupported WiFi capability control flow.')
        body_matches = item[16:] == replacement if patched else _sha(item) == body_sha
        if not body_matches:
            raise RuntimeError('Unexpected WiFi capability method body: ' + name)
        offset = start + code + 16
        before = data[offset:offset + len(replacement)]
        output[offset:offset + len(replacement)] = replacement
        sites.append({'offset': offset, 'before': before.hex(), 'after': replacement.hex(), 'method': name})
    changed_dex = bytearray(output[start:start + length])
    changed_dex[12:32] = hashlib.sha1(changed_dex[32:]).digest()
    struct.pack_into('<I', changed_dex, 8, zlib.adler32(changed_dex[12:]) & 0xffffffff)
    checksum = changed_dex[8:32]
    sites.append({'offset': start + 8, 'before': dex[8:32].hex(), 'after': checksum.hex()})
    output[start:start + length] = changed_dex
    crc = struct.pack('<I', zlib.crc32(changed_dex) & 0xffffffff)
    for offset in (local_crc, directory_crc):
        sites.append({'offset': offset, 'before': data[offset:offset + 4].hex(), 'after': crc.hex()})
        output[offset:offset + 4] = crc
    return bytes(output), _sha(changed_dex), tuple(sorted(sites, key=lambda site: site['offset']))


def patch_bytes(data):
    before, recipe, patched = select_recipe(data)
    if len(data) != recipe['size']:
        raise RuntimeError('Unexpected WiFi framework size.')
    output, dex_hash, _ = _rewrite(data, recipe, patched)
    if _sha(output) != recipe['after'] or dex_hash != recipe['dex_after']:
        raise RuntimeError('WiFi capability derivative checksum mismatch: ' + before)
    return output


def recipe_receipt(before):
    """Export canonical sites without requiring a donor file or build tools."""
    if before not in RECIPES:
        raise RuntimeError('Unsupported WiFi recipe receipt.')
    recipe = RECIPES[before]
    sites = [{'offset': offset, 'before': recipe['crc'][0], 'after': recipe['crc'][1]}
             for offset in recipe['crc_offsets']]
    sites.append({'offset': recipe['dex_offset'] + 8, 'before': recipe['dex_checksums'][0],
                  'after': recipe['dex_checksums'][1]})
    for name, original, (code, _, header, _) in zip(METHODS, recipe['instructions'], recipe['methods']):
        replacement = FALSE_RETURN + b'\0' * (2 * header[5] - 4)
        if len(original) != len(replacement) * 2:
            raise RuntimeError('Invalid canonical WiFi instruction site.')
        sites.append({'offset': recipe['dex_offset'] + code + 16, 'before': original,
                      'after': replacement.hex(), 'method': name})
    return {'schema': 1, 'id': 'wifi-physical-capabilities-v1', 'path': PATH,
            'format': 'framework-jar', 'before': before, 'after': recipe['after'],
            'size': recipe['size'], 'dex_before': recipe['dex_before'],
            'dex_after': recipe['dex_after'], 'methods': list(METHODS),
            'sites': sorted(sites, key=lambda site: site['offset']),
            'requires': 'ranchu-without-proprietary-wlan-sar'}


def catalog_recipes():
    """Enumerate exact content recipes for offline module packaging."""
    return tuple(recipe_receipt(before) for before in RECIPES)


def receipt(data):
    """Verify the original and the exported offline site recipe together."""
    before, recipe, patched = select_recipe(data)
    if patched:
        raise RuntimeError('A WiFi byte-site receipt requires the original input.')
    output, dex_hash, sites = _rewrite(data, recipe)
    canonical = recipe_receipt(before)
    if (_sha(output) != recipe['after'] or dex_hash != recipe['dex_after']
            or list(sites) != canonical['sites']):
        raise RuntimeError('WiFi receipt derivative mismatch.')
    return canonical


def patch(source, destination):
    """Publish a derivative atomically, preserving sources and unknown outputs."""
    source, destination = Path(source), Path(destination)
    if source.resolve() == destination.resolve():
        raise RuntimeError('Keep the factory WiFi JAR and derivative separate.')
    result = patch_bytes(source.read_bytes())

    def verify_existing():
        info = destination.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or destination.read_bytes() != result):
            raise RuntimeError('Preserving an unknown WiFi derivative output.')

    if destination.exists() or destination.is_symlink():
        verify_existing()
        return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.wifi-capabilities-', dir=destination.parent)
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
