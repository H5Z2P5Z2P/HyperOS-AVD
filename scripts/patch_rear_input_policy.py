#!/usr/bin/env python3
"""Block ordinary rear motion before OEM noninteractive dispatch and wake routes.

The audited motion entry currently lets AOD events reach rear applications via
keyguard, FOD and subdisplay exceptions. Gate only the verified rear display at
this entry; retain the original primary/external-display and key-event policy.
The independent raw double-tap listener and power Binder remain unaffected.
Keep the unsigned archive, DEX tables, method header and code size unchanged.
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

from patch_boot_services import SERVICE_RECIPES
from patch_gnss import OS4_18_SHA256, output_receipt
from patch_wifi_capabilities import _unpack, _uleb

PATH = '/system/framework/services.jar'
CLASS = 'Lcom/android/server/policy/PhoneWindowManager;'
METHOD = CLASS + '->interceptMotionBeforeQueueingNonInteractive(IIIJI)I'
HELPER = CLASS + '->shouldDispatchInputWhenNonInteractive(II)Z'
DISPLAY_ID = 1
# This is the already-reviewed boot-services derivative, not a factory image
# or a runtime version/model selector. Preserve its producer's canonical pin.
BEFORE = SERVICE_RECIPES[output_receipt(OS4_18_SHA256)['after']]
AFTER = '5636d03104e5c880fc516479d9c8a715a95fe509fa20ec50634ef32c1c7bdcbd'
SIZE = 40108515
MEMBER, MEMBER_COUNT = 'classes3.dex', 65
DEX_OFFSET, DEX_SIZE = 21643345, 11765312
DEX_BEFORE = '510d7cfb2a2833c26030a736550fb4592605f9e9dd0e7f4a2a7f92bdf8607ae7'
DEX_AFTER = 'de229775df55916e4917b625b4a723ee9b9ed560bff20c42cf1b042022eca77a'
CODE_OFFSET, CODE_HEADER = 0x391d68, (17, 7, 7, 0, 6595639, 37)
HELPER_OFFSET, HELPER_HEADER = 0x390110, (12, 3, 3, 1, 6593812, 113)
HELPER_SHA256 = '003f5ef6eeb041207df89008e6f034a76e5eccd07a430539fe207cfb0be4bc8b'
BODY_BEFORE = bytes.fromhex(
    'dd001001120112123800190054a38b26170440420f009e050e04390d0400012828'
    '02011855a9fc2501b401c77407438c03000a00380003000f027030898aba010a00'
    '380003000f020f01')
# Existing v1=0/v2=1 are retained. IF_NE p1(v11),v2 skips RETURN v1,
# before the original motion-wake branch. Compact only the final ()Z result's
# if/return-1/return-0 into RETURN v0, recovering the three added code units.
GATE = bytes.fromhex('332b03000f01')
BODY_AFTER = BODY_BEFORE[:8] + GATE + BODY_BEFORE[8:0x21 * 2] + bytes.fromhex('0f00')
SITES = (
    (21643317, '1a3534f0', 'e59189c4'),
    (DEX_OFFSET + 8, 'f6644ed30c8546e0bda77c19e46b53b10dc20203ce7d2e8f',
     '69665da78ba42826d2407f4a13e54afabcfa2885e40779d3'),
    (DEX_OFFSET + CODE_OFFSET + 16, BODY_BEFORE.hex(), BODY_AFTER.hex()),
    (40101713, '1a3534f0', 'e59189c4'),
)


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _layout(data):
    """Locate one stored DEX and its CRC fields without repacking the archive."""
    end = len(data) - 22
    fields = _unpack(data, end, '<4s4H2IH')
    signature, disk, cd_disk, disk_count, count, size, directory, comment = fields
    if (signature != b'PK\x05\x06' or disk or cd_disk or comment
            or count != MEMBER_COUNT or disk_count != count or directory + size != end
            or b'APK Sig Block 42' in data[max(0, directory - 24):directory]):
        raise RuntimeError('Unsupported or signed rear-input framework ZIP.')
    current, selected, names = directory, None, set()
    for _ in range(count):
        fields = _unpack(data, current, '<4s6H3I5H2I')
        name_length, extra_length, comment_length = fields[10:13]
        stop = current + 46 + name_length + extra_length + comment_length
        if fields[0] != b'PK\x01\x02' or stop > end:
            raise RuntimeError('Invalid rear-input ZIP directory entry.')
        name = data[current + 46:current + 46 + name_length]
        upper = name.upper()
        if (name in names or fields[13] or fields[8] == 0xffffffff or fields[9] == 0xffffffff
                or fields[16] >= directory or (upper.startswith(b'META-INF/') and
                (upper.endswith((b'.SF', b'.RSA', b'.DSA', b'.EC')) or upper.startswith(b'META-INF/SIG-')))):
            raise RuntimeError('Duplicate, signed or unsupported rear-input ZIP entry.')
        names.add(name)
        if name == MEMBER.encode():
            local = fields[16]
            header = _unpack(data, local, '<4s5H3I2H')
            if (selected is not None or fields[3:5] != (0, 0) or fields[8] != fields[9]
                    or header[0] != b'PK\x03\x04' or header[2:4] != (0, 0)
                    or header[6:9] != fields[7:10] or header[9] != name_length
                    or data[local + 30:local + 30 + name_length] != name):
                raise RuntimeError('Unsupported rear-input DEX storage/layout.')
            start = local + 30 + header[9] + header[10]
            if start + fields[9] > directory:
                raise RuntimeError('Invalid rear-input DEX bounds.')
            selected = (start, fields[9], local + 14, current + 16)
        current = stop
    if current != end or selected is None:
        raise RuntimeError('Missing rear-input DEX member.')
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            if (len(archive.infolist()) != count
                    or sum(item.file_size for item in archive.infolist()) > 64 * 1024 * 1024
                    or archive.testzip() is not None
                    or archive.read(MEMBER) != data[selected[0]:selected[0] + selected[1]]):
                raise RuntimeError('Invalid rear-input archive checksums.')
    except (zipfile.BadZipFile, ValueError, NotImplementedError) as error:
        raise RuntimeError('Invalid rear-input unsigned archive.') from error
    return selected


def _methods(dex):
    """Resolve the exact motion entry and untouched bool helper through DEX tables."""
    def table(offset, width):
        count, start = _unpack(dex, offset, '<II')
        if count > len(dex) // width or start + count * width > len(dex):
            raise RuntimeError('Invalid rear-input DEX table.')
        return count, start

    strings, string_start = table(56, 4)
    types, type_start = table(64, 4)
    protos, proto_start = table(72, 12)
    methods, method_start = table(88, 8)
    classes, class_start = table(96, 32)

    def string(index):
        if index >= strings:
            raise RuntimeError('Invalid rear-input string index.')
        offset, = _unpack(dex, string_start + index * 4, '<I')
        _, offset = _uleb(dex, offset)
        end = dex.find(b'\0', offset)
        if end < 0:
            raise RuntimeError('Unterminated rear-input DEX string.')
        return dex[offset:end].decode('ascii', errors='replace')

    def typename(index):
        if index >= types:
            raise RuntimeError('Invalid rear-input type index.')
        return string(_unpack(dex, type_start + index * 4, '<I')[0])

    result = {}
    for index in range(classes):
        class_id, _, _, _, _, _, offset, _ = _unpack(dex, class_start + index * 32, '<8I')
        if typename(class_id) != CLASS:
            continue
        counts = []
        for _ in range(4):
            value, offset = _uleb(dex, offset)
            counts.append(value)
        if sum(counts) > len(dex):
            raise RuntimeError('Invalid rear-input class-data counts.')
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
                    raise RuntimeError('Invalid rear-input method index.')
                owner, proto, name = _unpack(dex, method_start + method_id * 8, '<HHI')
                name = string(name)
                if name not in ('interceptMotionBeforeQueueingNonInteractive',
                                'shouldDispatchInputWhenNonInteractive'):
                    continue
                if owner != class_id or proto >= protos:
                    raise RuntimeError('Invalid rear-input method owner/prototype.')
                _, return_type, parameters = _unpack(dex, proto_start + proto * 12, '<III')
                size = _unpack(dex, parameters, '<I')[0] if parameters else 0
                if size > len(dex) // 2:
                    raise RuntimeError('Invalid rear-input parameter list.')
                args = ''.join(typename(_unpack(dex, parameters + 4 + item * 2, '<H')[0])
                               for item in range(size))
                descriptor = CLASS + '->' + name + '(' + args + ')' + typename(return_type)
                if descriptor not in (METHOD, HELPER) or descriptor in result:
                    raise RuntimeError('Unexpected rear-input motion ABI.')
                result[descriptor] = (code, access, method_id)
    if result != {METHOD: (CODE_OFFSET, 1, 35344), HELPER: (HELPER_OFFSET, 2, 35465)}:
        raise RuntimeError('Missing or ambiguous audited rear-input methods.')
    return result


def audit(data):
    if not isinstance(data, (bytes, bytearray)):
        raise RuntimeError('Unsupported rear-input framework JAR input.')
    data = bytes(data)
    identity = _sha(data)
    if identity not in (BEFORE, AFTER):
        raise RuntimeError('Unsupported rear-input framework JAR SHA-256: ' + identity)
    patched = identity == AFTER
    if (len(data) != SIZE or _layout(data) !=
            (DEX_OFFSET, DEX_SIZE, SITES[0][0], SITES[3][0])):
        raise RuntimeError('Unexpected rear-input ZIP layout.')
    dex = data[DEX_OFFSET:DEX_OFFSET + DEX_SIZE]
    if (dex[:8] != b'dex\n039\0' or _unpack(dex, 32, '<III') != (DEX_SIZE, 112, 0x12345678)
            or _sha(dex) != (DEX_AFTER if patched else DEX_BEFORE)
            or dex[12:32] != hashlib.sha1(dex[32:]).digest()
            or _unpack(dex, 8, '<I')[0] != zlib.adler32(dex[12:]) & 0xffffffff):
        raise RuntimeError('Unexpected rear-input DEX checksum/header.')
    _methods(dex)
    if (_unpack(dex, CODE_OFFSET, '<4H2I') != CODE_HEADER
            or dex[CODE_OFFSET + 16:CODE_OFFSET + 16 + CODE_HEADER[5] * 2] !=
                (BODY_AFTER if patched else BODY_BEFORE)
            or _unpack(dex, HELPER_OFFSET, '<4H2I') != HELPER_HEADER
            or _sha(dex[HELPER_OFFSET + 16:HELPER_OFFSET + 16 + HELPER_HEADER[5] * 2]) != HELPER_SHA256):
        raise RuntimeError('Unexpected rear-input method ABI/body.')
    for offset, original, replacement in SITES:
        value = bytes.fromhex(replacement if patched else original)
        if data[offset:offset + len(value)] != value:
            raise RuntimeError('Unexpected rear-input canonical patch site.')
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
        raise RuntimeError('Rear-input deterministic derivative mismatch.')
    return result


def recipe_receipt(before=BEFORE):
    if before != BEFORE:
        raise RuntimeError('Unsupported rear-input receipt source.')
    return {'schema': 1, 'id': 'rear-noninteractive-motion-v1', 'path': PATH,
            'format': 'framework-jar', 'before': BEFORE, 'after': AFTER, 'size': SIZE,
            'dex_before': DEX_BEFORE, 'dex_after': DEX_AFTER, 'methods': [METHOD],
            'requires': 'ranchu-audited-rear-display-one', 'display_id': DISPLAY_ID,
            'sites': [{'offset': offset, 'before': original, 'after': replacement,
                       **({'method': METHOD} if offset == DEX_OFFSET + CODE_OFFSET + 16 else {})}
                      for offset, original, replacement in SITES]}


def catalog_recipes():
    return (recipe_receipt(),)


def receipt(data):
    audit(data)
    return recipe_receipt()


def patch(source, destination):
    """Publish exclusively; preserve factory bytes, aliases and unknown outputs."""
    source, destination = Path(source), Path(destination)
    if source.resolve() == destination.resolve():
        raise RuntimeError('Keep the source rear-input framework and derivative separate.')
    output = patch_bytes(source.read_bytes())

    def verify_existing():
        info = destination.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or destination.read_bytes() != output:
            raise RuntimeError('Preserving an unknown rear-input derivative output.')

    if destination.exists() or destination.is_symlink():
        verify_existing()
        return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.rear-input-', dir=destination.parent)
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
