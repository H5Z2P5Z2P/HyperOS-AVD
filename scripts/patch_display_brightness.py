#!/usr/bin/env python3
"""Respect audited display brightness capability before OEM rear overrides.

The OEM rear branch bypasses SurfaceControl's false brightness capability and
queues unsupported HWC commands. Remove only that bypass in both overloads;
retain the existing capability, explicit force, Lights and null-light paths.
This does not implement software dimming or claim hardware brightness support.
"""
import argparse
import hashlib
import io
import lzma
import os
from pathlib import Path
import stat
import struct
import tempfile
import zipfile
import zlib

from patch_rear_input_policy import AFTER as BEFORE, SIZE
from patch_wifi_capabilities import _unpack, _uleb

COMPOSER_CAPABILITY = {
    'symbol': '_ZN4aidl7android8hardware8graphics9composer34impl7Display22getDisplayCapabilitiesEPNSt3__16vectorINS3_17DisplayCapabilityENS6_9allocatorIS8_EEEE',
    'address': 0x26a8c, 'size': 0x170,
    'sha256': 'a2f64fb610b00dc2d7daed391e19dbd0f2f80862aa0a2b63ca71baed7f095430',
    'values': (1, 8), 'brightness': False,
}

PATH = '/system/framework/services.jar'
CLASS = 'Lcom/android/server/display/LocalDisplayAdapter$BacklightAdapter;'
AFTER = 'e0126b6cb2edec3cbb9390a860ea27a0510de7ed203295194e6b02f0ca898efb'
MEMBER, MEMBER_COUNT = 'classes2.dex', 65
DEX_OFFSET, DEX_SIZE = 11602823, 10040480
DEX_BEFORE = '1c0425cbda18cc9051e12032df9a5ff9c9a6967f0d0bc84832e4341f539552d7'
DEX_AFTER = '6a1aea18402fbbddc9443d96cdfd605923cb8ac37b56bd2f22adea8cb7bb48a3'
# Keep code units, registers, instructions following the gate and all metadata.
# The capability and explicit force branches at units 2/6 still reach HWC.
GATE_UNIT = 0xa
GATE_BEFORE, GATE_AFTER = bytes.fromhex('38000300'), bytes.fromhex('29000300')
METHODS = (
    (CLASS + '->setBacklight(FFFF)V', 25315, 0x6b6190,
     (12, 5, 6, 0, 5067416, 62),
     bytes.fromhex('55702c2339001e005570292339001a0055702a233800030028145470272338000c00'
                   '547027236e20d59ea0000183019401a501b628230183019401a501b6281e1500c07f'
                   '7120ae2008000a0054712b2338000c00547028236e308e63010a0183019401a501b628'
                   '0a547228230183019401a501b674068f6301000e00')),
    (CLASS + '->setBacklight(FFFFZ)V', 25316, 0x6b621c,
     (14, 6, 7, 0, 5067478, 66),
     bytes.fromhex('55802c23390020005580292339001c0055802a233800030028165480272338000d00'
                   '548027236e20d59eb000019301a401b501c601d72826019301a401b501c601d72820'
                   '1500c07f7120ae2009000a0054812b2338000d00548028236e308e63010b019301a401'
                   'b501c601d7280b54822823019301a401b501c601d77407906301000e00')),
)
SITES = (
    (11602795, '80710fb5', '2d517215'),
    (DEX_OFFSET + 8, 'bca9551960305c5293d66b7f279b6c9b6ddcf7bf34748446',
     '18abaef97d33b5bad69d7bbcb5e68770ab4e42f6990c789c'),
    *((DEX_OFFSET + code + 16 + GATE_UNIT * 2, GATE_BEFORE.hex(), GATE_AFTER.hex())
      for _, _, code, _, _ in METHODS),
    (40101655, '80710fb5', '2d517215'),
)


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def composer_identities():
    import patch_composer as alpha
    import patch_rear_display as rear
    return (alpha.BEFORE, alpha.AFTER, rear.AFTER)


def capability_recipe():
    import patch_composer as alpha
    return ('schema|1\n' + ''.join('composer|' + alpha.NATIVE + '|' + checksum + '\n'
                                 for checksum in composer_identities())).encode()


def audit_composer(data):
    """Bind the absent capability to the same exact HWC inventory Core uses."""
    import patch_rear_display as rear
    from patch_xqos import _symbols
    if _sha(data) not in composer_identities():
        raise RuntimeError('Unsupported display-brightness composer capability.')
    _, names = rear._sections(data)
    code, debug = names.get(b'.text'), names.get(b'.gnu_debugdata')
    if code is None or debug is None:
        raise RuntimeError('Missing display-brightness composer provenance.')
    symbols = lzma.decompress(data[debug[4]:debug[4] + debug[5]], memlimit=32 * 1024**2)
    sections, _ = rear._sections(symbols)
    function = COMPOSER_CAPABILITY
    address, size = function['address'], function['size']
    if _symbols(symbols, sections, 2).get(function['symbol'].encode()) != (1, address, size):
        raise RuntimeError('Changed display-brightness composer symbol.')
    offset = code[4] + address - code[3]
    if (not code[3] <= address < address + size <= code[3] + code[5]
            or _sha(data[offset:offset + size]) != function['sha256']):
        raise RuntimeError('Changed display-brightness composer capability body.')
    return {**function, 'values': list(function['values'])}


def _layout(data):
    """Verify the unsigned stored DEX and both CRC locations without repacking."""
    end = len(data) - 22
    fields = _unpack(data, end, '<4s4H2IH')
    sig, disk, cd_disk, disk_count, count, size, directory, comment = fields
    if (sig != b'PK\x05\x06' or disk or cd_disk or comment or count != MEMBER_COUNT
            or disk_count != count or directory + size != end
            or b'APK Sig Block 42' in data[max(0, directory - 24):directory]):
        raise RuntimeError('Unsupported or signed display-brightness framework ZIP.')
    current, selected, names = directory, None, set()
    for _ in range(count):
        entry = _unpack(data, current, '<4s6H3I5H2I')
        nl, el, cl = entry[10:13]
        stop = current + 46 + nl + el + cl
        name = data[current + 46:current + 46 + nl]
        upper = name.upper()
        if (entry[0] != b'PK\x01\x02' or stop > end or name in names or entry[13]
                or entry[8] == 0xffffffff or entry[9] == 0xffffffff or entry[16] >= directory
                or (upper.startswith(b'META-INF/') and
                    (upper.endswith((b'.SF', b'.RSA', b'.DSA', b'.EC'))
                     or upper.startswith(b'META-INF/SIG-')))):
            raise RuntimeError('Invalid or signed display-brightness ZIP entry.')
        names.add(name)
        if name == MEMBER.encode():
            local = entry[16]
            header = _unpack(data, local, '<4s5H3I2H')
            if (selected is not None or entry[3:5] != (0, 0) or entry[8] != entry[9]
                    or header[0] != b'PK\x03\x04' or header[2:4] != (0, 0)
                    or header[6:9] != entry[7:10] or header[9] != nl
                    or data[local + 30:local + 30 + nl] != name):
                raise RuntimeError('Unsupported display-brightness DEX storage.')
            start = local + 30 + header[9] + header[10]
            if start + entry[9] > directory:
                raise RuntimeError('Invalid display-brightness DEX bounds.')
            selected = (start, entry[9], local + 14, current + 16)
        current = stop
    if current != end or selected is None:
        raise RuntimeError('Missing display-brightness DEX member.')
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            if (len(archive.infolist()) != count or archive.testzip() is not None
                    or sum(item.file_size for item in archive.infolist()) > 64 * 1024 * 1024
                    or archive.read(MEMBER) != data[selected[0]:selected[0] + selected[1]]):
                raise RuntimeError('Invalid display-brightness ZIP checksums.')
    except (zipfile.BadZipFile, ValueError, NotImplementedError) as error:
        raise RuntimeError('Invalid display-brightness framework ZIP.') from error
    return selected


def _methods(dex):
    """Resolve both overloads and their exact owner, access and parameter ABI."""
    def table(offset, width):
        count, start = _unpack(dex, offset, '<II')
        if count > len(dex) // width or start + count * width > len(dex):
            raise RuntimeError('Invalid display-brightness DEX table.')
        return count, start

    strings, string_start = table(56, 4)
    types, type_start = table(64, 4)
    protos, proto_start = table(72, 12)
    methods, method_start = table(88, 8)
    classes, class_start = table(96, 32)

    def string(index):
        if index >= strings:
            raise RuntimeError('Invalid display-brightness string index.')
        offset, = _unpack(dex, string_start + index * 4, '<I')
        _, offset = _uleb(dex, offset)
        end = dex.find(b'\0', offset)
        if end < 0:
            raise RuntimeError('Unterminated display-brightness string.')
        return dex[offset:end].decode('ascii', errors='replace')

    def typename(index):
        if index >= types:
            raise RuntimeError('Invalid display-brightness type index.')
        return string(_unpack(dex, type_start + index * 4, '<I')[0])

    result = {}
    for index in range(classes):
        owner, _, _, _, _, _, offset, _ = _unpack(dex, class_start + index * 32, '<8I')
        if typename(owner) != CLASS:
            continue
        counts = []
        for _ in range(4):
            value, offset = _uleb(dex, offset)
            counts.append(value)
        if sum(counts) > len(dex):
            raise RuntimeError('Invalid display-brightness class-data counts.')
        for _ in range(counts[0] + counts[1]):
            _, offset = _uleb(dex, offset)
            _, offset = _uleb(dex, offset)
        for count in counts[2:]:
            method = 0
            for _ in range(count):
                delta, offset = _uleb(dex, offset)
                method += delta
                access, offset = _uleb(dex, offset)
                code, offset = _uleb(dex, offset)
                if method >= methods:
                    raise RuntimeError('Invalid display-brightness method index.')
                class_id, proto, name = _unpack(dex, method_start + method * 8, '<HHI')
                if string(name) != 'setBacklight':
                    continue
                if class_id != owner or proto >= protos:
                    raise RuntimeError('Invalid display-brightness method owner/prototype.')
                _, ret, params = _unpack(dex, proto_start + proto * 12, '<III')
                size = _unpack(dex, params, '<I')[0] if params else 0
                if size > len(dex) // 2:
                    raise RuntimeError('Invalid display-brightness parameter list.')
                args = ''.join(typename(_unpack(dex, params + 4 + item * 2, '<H')[0])
                               for item in range(size))
                descriptor = CLASS + '->setBacklight(' + args + ')' + typename(ret)
                if descriptor in result:
                    raise RuntimeError('Duplicate display-brightness overload.')
                result[descriptor] = (code, access, method)
    expected = {name: (code, 0, method) for name, method, code, _, _ in METHODS}
    if result != expected:
        raise RuntimeError('Missing or unsupported display-brightness overload ABI.')
    return result


def patched_body(body):
    start = GATE_UNIT * 2
    return body[:start] + GATE_AFTER + body[start + len(GATE_BEFORE):]


def audit(data):
    if not isinstance(data, (bytes, bytearray)):
        raise RuntimeError('Unsupported display-brightness framework input.')
    data = bytes(data)
    identity = _sha(data)
    if identity not in (BEFORE, AFTER):
        raise RuntimeError('Unsupported display-brightness framework SHA-256: ' + identity)
    patched = identity == AFTER
    if (len(data) != SIZE or _layout(data) !=
            (DEX_OFFSET, DEX_SIZE, SITES[0][0], SITES[-1][0])):
        raise RuntimeError('Unexpected display-brightness framework layout.')
    dex = data[DEX_OFFSET:DEX_OFFSET + DEX_SIZE]
    if (dex[:8] != b'dex\n035\0' or _unpack(dex, 32, '<III') != (DEX_SIZE, 112, 0x12345678)
            or _sha(dex) != (DEX_AFTER if patched else DEX_BEFORE)
            or dex[12:32] != hashlib.sha1(dex[32:]).digest()
            or _unpack(dex, 8, '<I')[0] != zlib.adler32(dex[12:]) & 0xffffffff):
        raise RuntimeError('Unexpected display-brightness DEX checksum/header.')
    _methods(dex)
    for _, _, code, header, body in METHODS:
        if (_unpack(dex, code, '<4H2I') != header or len(body) != header[5] * 2
                or body[GATE_UNIT * 2:GATE_UNIT * 2 + 4] != GATE_BEFORE
                or dex[code + 16:code + 16 + len(body)] !=
                    (patched_body(body) if patched else body)):
            raise RuntimeError('Unexpected display-brightness method body/header.')
    for offset, original, replacement in SITES:
        value = bytes.fromhex(replacement if patched else original)
        if data[offset:offset + len(value)] != value:
            raise RuntimeError('Unexpected display-brightness canonical site.')
    return patched


def patch_bytes(data):
    if audit(data):
        return bytes(data)
    output = bytearray(data)
    for offset, _, replacement in SITES:
        value = bytes.fromhex(replacement)
        output[offset:offset + len(value)] = value
    result = bytes(output)
    if len(result) != len(data) or _sha(result) != AFTER or not audit(result):
        raise RuntimeError('Display-brightness deterministic derivative mismatch.')
    return result


def recipe_receipt(before=BEFORE):
    if before != BEFORE:
        raise RuntimeError('Unsupported display-brightness receipt source.')
    return {'schema': 1, 'id': 'display-brightness-capability-v1', 'path': PATH,
            'format': 'framework-jar', 'before': BEFORE, 'after': AFTER, 'size': SIZE,
            'dex_before': DEX_BEFORE, 'dex_after': DEX_AFTER,
            'methods': [row[0] for row in METHODS],
            'requires': 'ranchu-without-display-brightness',
            'composer_capability': {**COMPOSER_CAPABILITY, 'values': list(COMPOSER_CAPABILITY['values'])},
            'sites': [{'offset': offset, 'before': original, 'after': replacement}
                      for offset, original, replacement in SITES]}


def catalog_recipes():
    return (recipe_receipt(),)


def receipt(data):
    audit(data)
    return recipe_receipt()


def patch(source, destination):
    """Publish exclusively; retain unknown files, aliases and loaded inodes."""
    source, destination = Path(source), Path(destination)
    if source.resolve() == destination.resolve():
        raise RuntimeError('Keep the source framework and display-brightness derivative separate.')
    output = patch_bytes(source.read_bytes())

    def verify_existing():
        info = destination.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or destination.read_bytes() != output:
            raise RuntimeError('Preserving an unknown display-brightness output.')

    if destination.exists() or destination.is_symlink():
        verify_existing()
        return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.display-brightness-', dir=destination.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(output)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o644)
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
