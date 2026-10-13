#!/usr/bin/env python3
"""Keep the audited vendor-only IMS connector disconnected on HAL-free ranchu.

The complete unsigned framework JAR and its public connect()V code_item are
authenticated. Replace only the first iget-object with return-void and one
NOP; retain constructors, listeners, generic Android IMS, DEX layout and every
other instruction. Core separately proves the reviewed OEM IMS HAL absence.
"""
import argparse
import hashlib
import os
from pathlib import Path
import stat
import struct
import tempfile
import zlib

from patch_wifi_capabilities import _uleb, _unpack, _zip_layout

PATH = '/system_ext/framework/xiaomi-opt-ims.jar'
BEFORE = 'a855c48245d46b48602fffb722543ea83d19c863a1187d2d88f889265e2a81d4'
AFTER = '38c36800d6217ea1c9d5f0b97c0f317212df4ae67769ff660f1379c8b081247f'
SIZE = 54830
DEX_BEFORE = '399598de577403ac20c01f0a1b066afa92a1c46ab50a57ca6e14188f812a3c42'
DEX_AFTER = 'd51db813e6e3b3977e20c218b9809f5994f62ea88ab1ec09774c6c57d6c8827f'
OWNER = 'Lcom/xiaomi/ims/internal/XmImsConnector;'
METHOD = OWNER + '->connect()V'
CODE_OFFSET = 16660
CODE_HEADER = (3, 1, 2, 0, 28720, 26)
CODE_BEFORE = '81d396afc0306aa2819df75fc8f4827c4f7dd061208f1b05771b2d23d9aa77df'
CODE_AFTER = '5def664abec4aed8c44fc0d00ca5dddee223bde9a206fe237ee249158e22c68e'
DEX_OFFSET = 44
CRC_OFFSETS = (14, 54701)
ENTRY = (16720, '54202200', '0e000000')  # return-void; nop
CHECKSUMS = ('7f25b89c1b4a2a507c7c67138d9ca78c9e6aa4c4de49eb19',
             'd925e21f68928c0fd982e07129cc89ff58ff496ed2030d7c')
CRC = ('0ee49e09', 'dd7b18dd')


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _method(dex):
    """Resolve the exact owner/name/void prototype through bounded DEX tables."""
    if (dex[:8] != b'dex\n039\0' or _unpack(dex, 32, '<III') != (len(dex), 112, 0x12345678)
            or dex[12:32] != hashlib.sha1(dex[32:]).digest()
            or _unpack(dex, 8, '<I')[0] != zlib.adler32(dex[12:]) & 0xffffffff):
        raise RuntimeError('Invalid authenticated IMS DEX header/checksums.')

    def table(offset, width):
        count, start = _unpack(dex, offset, '<II')
        if count > len(dex) // width or start + count * width > len(dex):
            raise RuntimeError('Invalid IMS DEX table bounds.')
        return count, start

    strings, string_start = table(56, 4)
    types, type_start = table(64, 4)
    protos, proto_start = table(72, 12)
    methods, method_start = table(88, 8)
    classes, class_start = table(96, 32)

    def string(index):
        if index >= strings:
            raise RuntimeError('Invalid IMS DEX string index.')
        offset, = _unpack(dex, string_start + 4 * index, '<I')
        _, offset = _uleb(dex, offset)
        end = dex.find(b'\0', offset)
        if end < 0:
            raise RuntimeError('Unterminated IMS DEX string.')
        return dex[offset:end].decode('ascii', errors='replace')

    def typename(index):
        if index >= types:
            raise RuntimeError('Invalid IMS DEX type index.')
        return string(_unpack(dex, type_start + 4 * index, '<I')[0])

    found = []
    for index in range(classes):
        owner, _, _, _, _, _, offset, _ = _unpack(dex, class_start + 32 * index, '<8I')
        if typename(owner) != OWNER:
            continue
        counts = []
        for _ in range(4):
            value, offset = _uleb(dex, offset)
            counts.append(value)
        if sum(counts) > len(dex):
            raise RuntimeError('Invalid IMS DEX class-data counts.')
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
                    raise RuntimeError('Invalid IMS DEX method index.')
                owner_ref, proto_ref, name_ref = _unpack(dex, method_start + 8 * method_id, '<HHI')
                if string(name_ref) != 'connect':
                    continue
                if owner_ref != owner or proto_ref >= protos:
                    raise RuntimeError('Unexpected IMS DEX method owner/prototype.')
                _, return_type, arguments = _unpack(dex, proto_start + 12 * proto_ref, '<III')
                if typename(return_type) != 'V' or arguments:
                    raise RuntimeError('Unexpected IMS connector prototype.')
                found.append((code, access))
    if found != [(CODE_OFFSET, 1)]:
        raise RuntimeError('Missing or ambiguous audited IMS connect method.')
    return found[0]


def audit(data):
    """Authenticate full ZIP/DEX content and the complete target code_item."""
    if not isinstance(data, (bytes, bytearray)):
        raise RuntimeError('Unsupported Xiaomi IMS framework JAR input.')
    data = bytes(data)
    digest = _sha(data)
    if digest not in (BEFORE, AFTER) or len(data) != SIZE:
        raise RuntimeError('Unsupported Xiaomi IMS framework JAR input.')
    patched = digest == AFTER
    start, length, local_crc, central_crc = _zip_layout(data)
    if (start, local_crc, central_crc) != (DEX_OFFSET, *CRC_OFFSETS):
        raise RuntimeError('Unexpected IMS framework ZIP layout.')
    dex = data[start:start + length]
    if _sha(dex) != (DEX_AFTER if patched else DEX_BEFORE):
        raise RuntimeError('Unexpected IMS framework DEX content.')
    _method(dex)
    if _unpack(dex, CODE_OFFSET, '<4H2I') != CODE_HEADER:
        raise RuntimeError('Unexpected IMS connector code_item header.')
    body = dex[CODE_OFFSET:CODE_OFFSET + 16 + 2 * CODE_HEADER[5]]
    if _sha(body) != (CODE_AFTER if patched else CODE_BEFORE):
        raise RuntimeError('Unexpected IMS connector method body.')
    offset, before, after = ENTRY
    if data[offset:offset + 4] != bytes.fromhex(after if patched else before):
        raise RuntimeError('Unexpected IMS connector entry instruction.')
    return patched


def recipe_receipt(before=BEFORE):
    """Finite equal-length sites for the offline, early framework consumer."""
    if before != BEFORE:
        raise RuntimeError('Unsupported original IMS recipe identity.')
    sites = [{'offset': offset, 'before': CRC[0], 'after': CRC[1]} for offset in CRC_OFFSETS]
    sites.append({'offset': DEX_OFFSET + 8, 'before': CHECKSUMS[0], 'after': CHECKSUMS[1]})
    sites.append({'offset': ENTRY[0], 'before': ENTRY[1], 'after': ENTRY[2], 'method': METHOD})
    return {'schema': 1, 'id': 'vendor-ims-disconnected-connector-v1', 'path': PATH,
            'format': 'framework-jar', 'before': BEFORE, 'after': AFTER, 'size': SIZE,
            'dex_before': DEX_BEFORE, 'dex_after': DEX_AFTER, 'methods': [METHOD],
            'sites': sorted(sites, key=lambda site: site['offset']),
            'requires': 'ranchu-without-proprietary-ims'}


def catalog_recipes():
    return (recipe_receipt(),)


def patch_bytes(data):
    if audit(data):
        return bytes(data)
    output = bytearray(data)
    for site in recipe_receipt()['sites']:
        offset = site['offset']
        original, changed = bytes.fromhex(site['before']), bytes.fromhex(site['after'])
        if output[offset:offset + len(original)] != original:
            raise RuntimeError('Unexpected canonical IMS byte site.')
        output[offset:offset + len(changed)] = changed
    if _sha(output) != AFTER:
        raise RuntimeError('IMS connector derivative checksum mismatch.')
    audit(output)
    return bytes(output)


def receipt(data):
    if audit(data):
        raise RuntimeError('An IMS byte-site receipt requires the original input.')
    patch_bytes(data)
    return recipe_receipt()


def patch(source, destination):
    """Publish separately without replacing unknown files or loaded inodes."""
    source, destination = Path(source), Path(destination)
    if source.resolve() == destination.resolve():
        raise RuntimeError('Keep factory IMS framework and derivative separate.')
    result = patch_bytes(source.read_bytes())

    def verify_existing():
        info = destination.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or destination.read_bytes() != result):
            raise RuntimeError('Preserving an unknown IMS derivative output.')

    if destination.exists() or destination.is_symlink():
        verify_existing()
        return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.ims-connector-', dir=destination.parent)
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
