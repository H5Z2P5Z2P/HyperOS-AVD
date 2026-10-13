#!/usr/bin/env python3
"""Fail one audited unsigned-framework physical Uniperf capability before locking.

The stock bool helper repeatedly queries a proprietary HAL absent from ranchu.
Replace only its first complete two DEX instructions with false/return/NOP;
retain every following instruction, try/handler/debug record and ZIP byte.
Core separately proves physical HAL absence. Never apply this rule to an APK.
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

from patch_wifi_capabilities import _unpack, _uleb, _zip_layout
from patch_boot_services import AFTER as BOOT_SERVICES_AFTER

NATIVE = PATH = '/system_ext/framework/UniperfClient.jar'
HAL = 'vendor.xiaomi.hardware.uniperf.IUniperf/default'
CLASS = 'Lcom/xiaomi/uniperf/UniperfClient;'
METHOD = CLASS + '->getUniperfservice()Z'
BEFORE = 'd002c55e9b661b4dfdfde07cfae9c2814a3451f66e3ddfad033ff2dfcf3bf297'
AFTER = 'c1f9739ddaf1b92e0047869eb1025e98106106d7cdda50a6124c03e5a3cedb47'
SIZE = 22506
DEX_BEFORE = '66019e852564005b505fe510f81dfeb9e74f337fa0a2a069c43a55ea627a8cec'
DEX_AFTER = '1c37e5193083ea2b55238d077099b2cd00e767244f51fb73f72bef900d8b0c22'
DEX_OFFSET, DEX_SIZE = 44, 22204
CODE_OFFSET = 0x1030
CODE_HEADER = (7, 0, 3, 7, 12185, 151)
BODY_BEFORE = '01ede0ad10650f66cc057a422684072d26e7a8e530e5213342410b76fdbebde4'
BODY_AFTER = '8ec41d9630b2bce80d3adc0ff8a2cf155e282f1fa1d540be9783ae970670b9d1'
ORIGINAL = bytes.fromhex('120062010900')  # const/4 v0,0; sget-object v1,field@0009.
FALSE_RETURN = bytes.fromhex('12000f000000')  # const/4 v0,0; return v0; NOP.
SITES = (
    (14, 'ae5341fd', '55ce93c7'),
    (DEX_OFFSET + 8, 'bccb2f0d834d3a89f38c79b839b9d935d32106d77802b9a7',
     '15ccb0105996c7dcce83151b967047c24dedfec599316d4e'),
    (DEX_OFFSET + CODE_OFFSET + 16, ORIGINAL.hex(), FALSE_RETURN.hex()),
    (22377, 'ae5341fd', '55ce93c7'),
)
MIUI_SERVICES = '/system_ext/framework/miui-services.jar'
# Preserve the standalone recipe and receipt exactly for frozen Core 10.
# The system-server copy is loaded from classes2.dex in miui-services.jar.
# Its Phone source is already a reviewed boot-services derivative, not an OTA
# factory input; refer to that canonical pin rather than changing its history.
RECIPES = {
    BEFORE: {'path': PATH, 'size': SIZE, 'after': AFTER, 'member': 'classes.dex', 'dex_magic': b'dex\n039\0',
             'count': 2, 'dex_offset': DEX_OFFSET, 'dex_size': DEX_SIZE,
             'dex_before': DEX_BEFORE, 'dex_after': DEX_AFTER,
             'code_offset': CODE_OFFSET, 'code_header': CODE_HEADER,
             'body_before': BODY_BEFORE, 'body_after': BODY_AFTER,
             'original': ORIGINAL.hex(), 'sites': SITES},
    BOOT_SERVICES_AFTER['miui-services']: {
        'path': MIUI_SERVICES, 'size': 20737847,
        'after': '3f7182f39f7c3d40af9d706cba3087e08c87c9e6dec32802ef296192c4707e40',
        'member': 'classes2.dex', 'dex_magic': b'dex\n035\0', 'count': 9, 'dex_offset': 12019655,
        'dex_size': 8713264,
        'dex_before': '637b99a0a5b643f360793e01026ac38262a917489fcc311aad3de5877cf6f958',
        'dex_after': '24f348431b77e671fc3fa3d7b8c595c89567fbb56334754dc5e3829b49abfe0f',
        'code_offset': 0x6daeec, 'code_header': (7, 0, 3, 7, 4668714, 152),
        'body_before': '79c3bfc01939c86476d77a51c5dac4055bb95235c43bd3bca80661f51e6ad94e',
        'body_after': 'fb82a7c2287897002ef633a1a6f5022d47abb8de7339023137602d18c778599c',
        'original': '120062017441',
        'sites': ((12019627, '182264b1', 'e2e43050'),
                  (12019663, 'dcbbad9067e60fcd7df16946b8a69cf24c21bb3b1acffaa4',
                   'f7bafafde6f85cd525a35c90f0e44592776079df2a3487be'),
                  (19207875, '120062017441', '12000f000000'),
                  (20737164, '182264b1', 'e2e43050')),
    },
    'a15133a28eb0d336832957908aa3461f76dab679c7be2ed0809dabdd789dc941': {
        'path': MIUI_SERVICES, 'size': 19635601,
        'after': '9817dbd23cda60edc72c9dfac9c586d44fd9932c2cce95900a8531d6c1fff817',
        'member': 'classes2.dex', 'dex_magic': b'dex\n039\0', 'count': 11, 'dex_offset': 12063500,
        'dex_size': 7564720,
        'dex_before': '36f055eb6a08ec8c168df827340da5fb148e6d4e9f72f7d52c30a7277dbd5814',
        'dex_after': '5757856cfed201adb5c97fe56c1ad0143b550de3820dabd6627510fd5fda7a21',
        'code_offset': 0x2a09c0, 'code_header': (7, 0, 3, 7, 4234806, 151),
        'body_before': '05fea39047135934fe7aead65218ada87a9f04c7b328a05ef65a96cf172fa340',
        'body_after': 'f2cbf2c8e9a02303693fb0dc67a4e7830967ab22fbe66b82527ac79d628946c1',
        'original': '120062015835',
        'sites': ((12063470, '2719ea30', '0d88e7a9'),
                  (12063508, 'b8ec77edbf4f16803cf927e10283b41615d78a31fb15cc25',
                   '3ded6f17a9491004dbcb3b7257bebdacc3f51ddcac2024c6'),
                  (14818524, '120062015835', '12000f000000'),
                  (19634723, '2719ea30', '0d88e7a9')),
    },
}


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def select_recipe(data):
    """Select only a fully authenticated original or deterministic derivative."""
    digest = _sha(data) if isinstance(data, (bytes, bytearray)) else data
    for before, rule in RECIPES.items():
        if digest in (before, rule['after']):
            return before, rule, digest != before
    raise RuntimeError('Unsupported Uniperf framework JAR SHA-256: ' + str(digest))


def _stored_dex_layout(data, member, expected_count):
    """Locate one stored DEX without re-encoding other compressed ZIP entries.

    Only the selected entry must have no descriptor/encryption/compression.
    The Pad metadata entries have normal data descriptors, which stay intact.
    Whole-file selection precedes this bounded secondary structure audit.
    """
    end = len(data) - 22
    if data[end:end + 4] != b'PK\x05\x06':
        raise RuntimeError('Unexpected Uniperf ZIP end record.')
    disk, cd_disk, count_disk, count, size, directory, comment = _unpack(data, end + 4, '<4H2IH')
    if (disk or cd_disk or count != expected_count or not 0 < count <= 32
            or count_disk != count or comment or directory + size != end
            or b'APK Sig Block 42' in data[max(0, directory - 24):directory]):
        raise RuntimeError('Unsupported or signed Uniperf framework archive.')
    names, selected, current = [], None, directory
    for _ in range(count):
        fields = _unpack(data, current, '<4s6H3I5H2I')
        if fields[0] != b'PK\x01\x02':
            raise RuntimeError('Invalid Uniperf ZIP directory entry.')
        name_length, extra_length, comment_length = fields[10:13]
        stop = current + 46 + name_length + extra_length + comment_length
        if stop > end:
            raise RuntimeError('Invalid Uniperf ZIP directory bounds.')
        name = data[current + 46:current + 46 + name_length]
        upper = name.upper()
        if (name in names or fields[13] or fields[8] == 0xffffffff or fields[9] == 0xffffffff
                or fields[16] >= directory or (upper.startswith(b'META-INF/') and
                (upper.endswith((b'.SF', b'.RSA', b'.DSA', b'.EC')) or upper.startswith(b'META-INF/SIG-')))):
            raise RuntimeError('Duplicate, signed or unsupported Uniperf ZIP entry.')
        names.append(name)
        if name == member.encode('ascii'):
            if selected is not None or fields[3:5] != (0, 0) or fields[8] != fields[9]:
                raise RuntimeError('Unsupported Uniperf DEX ZIP storage.')
            local = fields[16]
            lfh = _unpack(data, local, '<4s5H3I2H')
            if (lfh[0] != b'PK\x03\x04' or lfh[2:4] != (0, 0)
                    or lfh[6:9] != fields[7:10] or lfh[9] != name_length
                    or data[local + 30:local + 30 + name_length] != name):
                raise RuntimeError('Uniperf ZIP local/directory mismatch.')
            start = local + 30 + lfh[9] + lfh[10]
            if start + fields[9] > directory:
                raise RuntimeError('Invalid Uniperf DEX ZIP bounds.')
            selected = (start, fields[9], local + 14, current + 16)
        current = stop
    if current != end or selected is None:
        raise RuntimeError('Missing or ambiguous Uniperf ZIP DEX.')
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            if (len(infos) != count or sum(item.file_size for item in infos) > 64 * 1024 * 1024
                    or archive.testzip() is not None
                    or archive.read(member) != data[selected[0]:selected[0] + selected[1]]):
                raise RuntimeError('Invalid Uniperf archive checksums/layout.')
    except (zipfile.BadZipFile, RuntimeError, ValueError, NotImplementedError) as error:
        raise RuntimeError('Invalid Uniperf unsigned archive.') from error
    return selected


def _method(dex, expected_code=CODE_OFFSET):
    """Resolve the exact public static no-argument bool through DEX tables."""
    def table(offset, width):
        count, start = _unpack(dex, offset, '<II')
        if count > len(dex) // width or start + count * width > len(dex):
            raise RuntimeError('Invalid Uniperf DEX table.')
        return count, start

    strings, string_start = table(56, 4)
    types, type_start = table(64, 4)
    protos, proto_start = table(72, 12)
    methods, method_start = table(88, 8)
    classes, class_start = table(96, 32)

    def string(index):
        if index >= strings:
            raise RuntimeError('Invalid Uniperf string reference.')
        offset, = _unpack(dex, string_start + index * 4, '<I')
        _, offset = _uleb(dex, offset)
        end = dex.find(b'\0', offset)
        if end < 0:
            raise RuntimeError('Unterminated Uniperf DEX string.')
        return dex[offset:end].decode('ascii', errors='replace')

    def typename(index):
        if index >= types:
            raise RuntimeError('Invalid Uniperf type reference.')
        return string(_unpack(dex, type_start + index * 4, '<I')[0])

    matches = []
    for index in range(classes):
        class_id, _, _, _, _, _, offset, _ = _unpack(dex, class_start + index * 32, '<8I')
        if typename(class_id) != CLASS:
            continue
        counts = []
        for _ in range(4):
            value, offset = _uleb(dex, offset)
            counts.append(value)
        if sum(counts) > len(dex):
            raise RuntimeError('Invalid Uniperf class-data counts.')
        for _ in range(counts[0] + counts[1]):
            _, offset = _uleb(dex, offset)
            _, offset = _uleb(dex, offset)
        for count in counts[2:]:
            method_id = 0
            for _ in range(count):
                delta, offset = _uleb(dex, offset)
                method_id += delta
                access, offset = _uleb(dex, offset)
                code, offset = _uleb(dex, offset)
                if method_id >= methods:
                    raise RuntimeError('Invalid Uniperf method reference.')
                owner, proto, name = _unpack(dex, method_start + method_id * 8, '<HHI')
                if string(name) != 'getUniperfservice':
                    continue
                if owner != class_id or proto >= protos:
                    raise RuntimeError('Invalid Uniperf method owner/prototype.')
                _, result_type, parameters = _unpack(dex, proto_start + proto * 12, '<III')
                if typename(result_type) != 'Z' or parameters or access != 9:
                    raise RuntimeError('Unexpected Uniperf capability ABI.')
                matches.append(code)
    if matches != [expected_code]:
        raise RuntimeError('Missing or ambiguous Uniperf capability method.')
    return matches[0]


def audit(data):
    if not isinstance(data, (bytes, bytearray)):
        raise RuntimeError('Unsupported Uniperf framework JAR input.')
    data = bytes(data)
    before, rule, patched = select_recipe(data)
    dex_offset, dex_size = rule['dex_offset'], rule['dex_size']
    layout = (_zip_layout(data) if before == BEFORE else
              _stored_dex_layout(data, rule['member'], rule['count']))
    if len(data) != rule['size'] or layout != (
            dex_offset, dex_size, rule['sites'][0][0], rule['sites'][3][0]):
        raise RuntimeError('Unexpected Uniperf unsigned ZIP layout.')
    dex = data[dex_offset:dex_offset + dex_size]
    if (dex[:8] != rule['dex_magic'] or _unpack(dex, 32, '<III') != (dex_size, 112, 0x12345678)
            or _sha(dex) != rule['dex_after' if patched else 'dex_before']
            or dex[12:32] != hashlib.sha1(dex[32:]).digest()
            or _unpack(dex, 8, '<I')[0] != zlib.adler32(dex[12:]) & 0xffffffff):
        raise RuntimeError('Unexpected Uniperf DEX checksums/header.')
    code = _method(dex, rule['code_offset'])
    header = _unpack(dex, code, '<4H2I')
    body = dex[code + 16:code + 16 + 2 * rule['code_header'][5]]
    if (header != rule['code_header'] or _sha(body) != rule['body_after' if patched else 'body_before']
            or body[:6] != (FALSE_RETURN if patched else bytes.fromhex(rule['original']))):
        raise RuntimeError('Unexpected Uniperf capability body/try layout.')
    for offset, original, replacement in rule['sites']:
        expected = bytes.fromhex(replacement if patched else original)
        if data[offset:offset + len(expected)] != expected:
            raise RuntimeError('Unexpected Uniperf canonical checksum/instruction site.')
    return patched


def patch_bytes(data):
    """Preserve the archive and DEX layout, changing four equal-length sites."""
    if audit(data):
        return bytes(data)
    _, rule, _ = select_recipe(data)
    output = bytearray(data)
    for offset, _, replacement in rule['sites']:
        value = bytes.fromhex(replacement)
        output[offset:offset + len(value)] = value
    result = bytes(output)
    if len(result) != len(data) or _sha(result) != rule['after'] or not audit(result):
        raise RuntimeError('Uniperf deterministic derivative mismatch.')
    return result


def recipe_receipt(before=BEFORE):
    if before not in RECIPES:
        raise RuntimeError('Unsupported Uniperf receipt source.')
    rule = RECIPES[before]
    return {'schema': 1, 'id': 'uniperf-physical-capability-v1', 'path': rule['path'],
            'format': 'framework-jar', 'before': before, 'after': rule['after'], 'size': rule['size'],
            'dex_before': rule['dex_before'], 'dex_after': rule['dex_after'], 'methods': [METHOD],
            'requires': 'ranchu-without-physical-uniperf', 'absent_hal': HAL,
            'sites': [{'offset': offset, 'before': original, 'after': replacement,
                       **({'method': METHOD} if offset == rule['dex_offset'] + rule['code_offset'] + 16 else {})}
                      for offset, original, replacement in rule['sites']]}


def catalog_recipes():
    return tuple(recipe_receipt(before) for before in RECIPES)


def receipt(data):
    audit(data)
    return recipe_receipt(select_recipe(data)[0])


def patch(source, destination):
    """Publish exclusively; preserve the factory JAR and unknown outputs."""
    source, destination = Path(source), Path(destination)
    if source.resolve() == destination.resolve():
        raise RuntimeError('Keep the factory Uniperf JAR and derivative separate.')
    output = patch_bytes(source.read_bytes())

    def verify_existing():
        info = destination.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or destination.read_bytes() != output):
            raise RuntimeError('Preserving an unknown Uniperf derivative output.')

    if destination.exists() or destination.is_symlink():
        verify_existing()
        return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.uniperf-', dir=destination.parent)
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
