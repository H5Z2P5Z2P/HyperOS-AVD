#!/usr/bin/env python3
"""Use the exact unsigned XRING client's existing unsupported HAL returns.

Core must independently prove the complete ranchu inventory lacks this physical
HAL. Skip service discovery and the observed hint entry before locking/Binder
work; preserve every remaining instruction, exception table, ABI and ZIP byte.
"""
import argparse
import hashlib
import os
from pathlib import Path
import stat
import struct
import tempfile
import zlib

from patch_uniperf import _stored_dex_layout
from patch_wifi_capabilities import _unpack, _uleb

PATH = '/system_ext/framework/PerfFlingerClient.jar'
HAL = 'vendor.xring.hardware.perfflinger.IPerfFlinger/default'
CLASS = 'Lcom/xring/perf/PerfFlingerClient;'
METHODS = (CLASS + '->getPerfService()Z',
           CLASS + '->perfHintAcquireV2(JIILjava/lang/String;)J')
BEFORE = '5fa9fd757cddac7ccad03948f3ad2183dea972d7f92b15f4520acc90fedeef76'
# BEGIN AUDITED CONSTANTS
AFTER = 'd1c387b2fce0a75723fd69329d4599b9391acbdacfc730c8f5d3da43e343b893'
SIZE = 33538
MEMBER_COUNT = 2
DEX_OFFSET, DEX_SIZE = (44, 33236)
DEX_BEFORE, DEX_AFTER = ('f11401d699cc52347cf509779f9dadc4e9a4671dbcdf88f91b4b70e89908383f', '015aeb4725ff66c530840bebfd27b7ab5a049e8be5130945fd5b568db0a27864')
CODE = (('Lcom/xring/perf/PerfFlingerClient;->getPerfService()Z',
  9,
  5608,
  (7, 0, 3, 7, 18951, 161),
  'b7f651b7d83368dc71ea2cbb5e8c82d2030ef7e080c27c2f0aff6f9de0744e1c',
  'bb83f8731bb5c11a2d837a63fbe8b5d081b97e4751669caf169829fcfe58157e',
  '120062010700',
  '12000f000000'),
 ('Lcom/xring/perf/PerfFlingerClient;->perfHintAcquireV2(JIILjava/lang/String;)J',
  1,
  9204,
  (19, 6, 9, 5, 19727, 183),
  '9f53451d7d8744eff96a6bc750ec70064b1404e8d7ebb201e65f954dd1a4db5f',
  '105ea8693ee2627e61dd7a0c5741f9eed274ce9a4795ce8ee44821a2747b9919',
  '71002e0000000a00',
  '1600ffff10000000'))
SITES = ((14, '70367dbf', '2f70c96e'),
 (52, 'faca182c389e0062ed970189998020388805e7121bd8e233', '6ccf07b0fab4dd63c2cac8dcd68349c40e4e572784ce5097'),
 (5668, '120062010700', '12000f000000'),
 (9264, '71002e0000000a00', '1600ffff10000000'),
 (33409, '70367dbf', '2f70c96e'))
# END AUDITED CONSTANTS


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _methods(dex):
    """Resolve both exact descriptors and access flags from authenticated DEX."""
    def table(offset, width):
        count, start = _unpack(dex, offset, '<II')
        if count > len(dex) // width or start + count * width > len(dex):
            raise RuntimeError('Invalid PerfFlinger DEX table.')
        return count, start

    strings, string_start = table(56, 4)
    types, type_start = table(64, 4)
    protos, proto_start = table(72, 12)
    methods, method_start = table(88, 8)
    classes, class_start = table(96, 32)

    def string(index):
        if index >= strings:
            raise RuntimeError('Invalid PerfFlinger string index.')
        offset, = _unpack(dex, string_start + index * 4, '<I')
        _, offset = _uleb(dex, offset)
        end = dex.find(b'\0', offset)
        if end < 0:
            raise RuntimeError('Unterminated PerfFlinger DEX string.')
        return dex[offset:end].decode('ascii', errors='replace')

    def typename(index):
        if index >= types:
            raise RuntimeError('Invalid PerfFlinger type index.')
        return string(_unpack(dex, type_start + index * 4, '<I')[0])

    result = {}
    for index in range(classes):
        owner, _, _, _, _, _, cursor, _ = _unpack(dex, class_start + index * 32, '<8I')
        if typename(owner) != CLASS:
            continue
        counts = []
        for _ in range(4):
            count, cursor = _uleb(dex, cursor); counts.append(count)
        if sum(counts) > len(dex):
            raise RuntimeError('Invalid PerfFlinger class-data counts.')
        for _ in range(counts[0] + counts[1]):
            _, cursor = _uleb(dex, cursor); _, cursor = _uleb(dex, cursor)
        for count in counts[2:]:
            method_id = 0
            for _ in range(count):
                delta, cursor = _uleb(dex, cursor); method_id += delta
                access, cursor = _uleb(dex, cursor); code, cursor = _uleb(dex, cursor)
                if method_id >= methods:
                    raise RuntimeError('Invalid PerfFlinger method index.')
                class_id, proto, name = _unpack(dex, method_start + method_id * 8, '<HHI')
                if string(name) not in ('getPerfService', 'perfHintAcquireV2'):
                    continue
                if class_id != owner or proto >= protos:
                    raise RuntimeError('Invalid PerfFlinger method owner/prototype.')
                _, return_type, parameters = _unpack(dex, proto_start + proto * 12, '<III')
                args = ''
                if parameters:
                    length, = _unpack(dex, parameters, '<I')
                    if length > 32:
                        raise RuntimeError('Invalid PerfFlinger parameter count.')
                    args = ''.join(typename(_unpack(dex, parameters + 4 + i * 2, '<H')[0])
                                   for i in range(length))
                descriptor = CLASS + '->' + string(name) + '(' + args + ')' + typename(return_type)
                if descriptor not in METHODS or descriptor in result:
                    raise RuntimeError('Unexpected PerfFlinger capability ABI.')
                result[descriptor] = (code, access)
    if set(result) != set(METHODS):
        raise RuntimeError('Missing PerfFlinger capability entries.')
    return result


def audit(data):
    if not isinstance(data, (bytes, bytearray)):
        raise RuntimeError('Unsupported PerfFlinger framework input.')
    data = bytes(data)
    checksum = _sha(data)
    if checksum not in (BEFORE, AFTER):
        raise RuntimeError('Unsupported PerfFlinger unsigned JAR SHA-256: ' + checksum)
    patched = checksum == AFTER
    if len(data) != SIZE or _stored_dex_layout(data, 'classes.dex', MEMBER_COUNT) != (
            DEX_OFFSET, DEX_SIZE, SITES[0][0], SITES[-1][0]):
        raise RuntimeError('Unexpected PerfFlinger unsigned ZIP layout.')
    dex = data[DEX_OFFSET:DEX_OFFSET + DEX_SIZE]
    if (dex[:8] != b'dex\n039\0' or _unpack(dex, 32, '<III') != (DEX_SIZE, 112, 0x12345678)
            or _sha(dex) != (DEX_AFTER if patched else DEX_BEFORE)
            or dex[12:32] != hashlib.sha1(dex[32:]).digest()
            or _unpack(dex, 8, '<I')[0] != zlib.adler32(dex[12:]) & 0xffffffff):
        raise RuntimeError('Invalid PerfFlinger DEX checksum/header.')
    resolved = _methods(dex)
    for method, access, offset, header, before, after, original, replacement in CODE:
        body = dex[offset + 16:offset + 16 + header[5] * 2]
        if (resolved[method] != (offset, access) or _unpack(dex, offset, '<4H2I') != header
                or _sha(body) != (after if patched else before)
                or body[:len(bytes.fromhex(original))] != bytes.fromhex(replacement if patched else original)):
            raise RuntimeError('Unexpected PerfFlinger method/try/body layout.')
    for offset, before, after in SITES:
        value = bytes.fromhex(after if patched else before)
        if data[offset:offset + len(value)] != value:
            raise RuntimeError('Unexpected PerfFlinger checksum/instruction site.')
    return patched


def patch_bytes(data):
    if audit(data):
        return bytes(data)
    output = bytearray(data)
    for offset, _, after in SITES:
        replacement = bytes.fromhex(after)
        output[offset:offset + len(replacement)] = replacement
    result = bytes(output)
    if len(result) != len(data) or _sha(result) != AFTER or not audit(result):
        raise RuntimeError('PerfFlinger deterministic derivative mismatch.')
    return result


def recipe_receipt(before=BEFORE):
    if before != BEFORE:
        raise RuntimeError('Unsupported PerfFlinger receipt source.')
    return {'schema': 1, 'id': 'perfflinger-physical-capability-v1', 'path': PATH,
            'format': 'framework-jar', 'before': BEFORE, 'after': AFTER, 'size': SIZE,
            'dex_before': DEX_BEFORE, 'dex_after': DEX_AFTER, 'methods': list(METHODS),
            'requires': 'ranchu-without-physical-perfflinger', 'absent_hal': HAL,
            'sites': [{'offset': offset, 'before': old, 'after': new} for offset, old, new in SITES]}


def catalog_recipes():
    return (recipe_receipt(),)


def receipt(data):
    audit(data)
    return recipe_receipt()


def patch(source, destination):
    """Publish exclusively and preserve factory, alias and customized outputs."""
    source, destination = Path(source), Path(destination)
    if source.resolve() == destination.resolve():
        raise RuntimeError('Keep the PerfFlinger source and derivative separate.')
    output = patch_bytes(source.read_bytes())

    def verify_existing():
        info = destination.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or destination.read_bytes() != output:
            raise RuntimeError('Preserving an unknown PerfFlinger derivative.')

    if destination.exists() or destination.is_symlink():
        verify_existing(); return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.perfflinger-', dir=destination.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(output); stream.flush(); os.fsync(stream.fileno()); os.fchmod(stream.fileno(), 0o644)
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
