#!/usr/bin/env python3
"""Remove the audited KernelSU full-task-scan log, preserving task marking.

The reviewed upstream source has two per-task pr_info calls under tasklist_lock
and an outer IRQ-saving spinlock. This official LKM merges them into one call.
Branch over only its argument setup and call; do not NOP a relocated CALL26,
which the kernel loader would reconstruct. All relocations and other logs stay
unchanged. The reviewed source commit is provenance, not an asserted build
commit for the independently authenticated official release asset.
"""
import argparse
import hashlib
import os
from pathlib import Path
import stat
import struct
import tempfile

from common import KSU_ASSETS, KSU_VERSION
import kernelsu_release

ASSET = 'lkm-aarch64-android15-6.6_kernelsu.ko'
BEFORE = KSU_ASSETS[ASSET]
AFTER = 'f4cb155c5d6111867a73a7996e56e95e73bc87b73637c6abc5cb9c3e8b8b2fbd'
SOURCE_REVIEW_COMMIT = '932014ab5b2c9b74a3d11e2ec4d17dd10fc9442e'
SOURCE_REVIEW_URL = ('https://github.com/tiann/KernelSU/blob/'
                     + SOURCE_REVIEW_COMMIT + '/kernel/hook/tp_marker.c#L80-L117')
FUNCTION = 'ksu_mark_running_process_locked'
FUNCTION_START, FUNCTION_SIZE = 0x2028, 0x1e4
FUNCTION_HASHES = {
    BEFORE: '74683bc35a8b29bfcb8f9bf7af0cffca6a595180304a78d06a32ef01a5fddfd0',
    AFTER: '756e48ddb3de460b77d46e2fbd57c51c14d512a4d386b38145d8f117876ee5d6',
}
SITE, RESUME, PRINTK = 0x2164, 0x2174, 0x2170
ORIGINAL = bytes.fromhex('e10254b8')  # ldur w1, [x23, #-0xc0]
BRANCH = bytes.fromhex('04000014')  # b .+0x10
FLOW_GUARD = bytes.fromhex(
    '1a000014bf1239f8e0031caa040000141c000014bf3239f8e0031aaa'
    'e10254b8e3620591e203142a0000009413faffb405000014')

# Keep the original aliases and default receipt immutable for frozen images.
# Current official download identities come only from kernelsu_release.
RECIPES = {
    BEFORE: {
        'version': KSU_VERSION, 'after': AFTER,
        'source_review_commit': SOURCE_REVIEW_COMMIT,
        'source_review_url': SOURCE_REVIEW_URL,
        'function_start': FUNCTION_START, 'function_size': FUNCTION_SIZE,
        'site': SITE, 'resume': RESUME, 'printk': PRINTK,
        'function_before': FUNCTION_HASHES[BEFORE],
        'function_after': FUNCTION_HASHES[AFTER],
        'sections': {
            '.text': (1, 6, 0, 20480, 70492, 0, 0, 4, 0),
            '.rodata.str1.1': (1, 50, 0, 99322, 20575, 0, 0, 1, 1),
            '.symtab': (2, 0, 0, 237736, 39984, 51, 1222, 8, 24),
            '.strtab': (3, 0, 0, 278243, 13444, 0, 0, 1, 0),
            '.rela.text': (4, 64, 0, 147784, 85296, 49, 13, 8, 24),
        },
        'format_addends': (0x1738, 0x14f7),
    },
    kernelsu_release.ASSETS[ASSET]: {
        'version': kernelsu_release.VERSION,
        'after': '055a4fc38fa8a8f55233b7c576cadcc54a3a79ba080bc073b8aacf0b85b82305',
        'source_review_commit': kernelsu_release.REVIEW_COMMIT,
        'source_review_url': ('https://github.com/tiann/KernelSU/blob/'
                              + kernelsu_release.REVIEW_COMMIT
                              + '/kernel/hook/tp_marker.c#L73-L110'),
        'function_start': 0x20a0, 'function_size': 0x1e4,
        'site': 0x21dc, 'resume': 0x21ec, 'printk': 0x21e8,
        # Independently audited 3.3.1 has identical unrelocated function bytes.
        'function_before': FUNCTION_HASHES[BEFORE],
        'function_after': FUNCTION_HASHES[AFTER],
        'sections': {
            '.text': (1, 6, 0, 20480, 74436, 0, 0, 4, 0),
            '.rodata.str1.1': (1, 50, 0, 103968, 21597, 0, 0, 1, 1),
            '.symtab': (2, 0, 0, 249936, 42072, 51, 1293, 8, 24),
            '.strtab': (3, 0, 0, 292531, 14256, 0, 0, 1, 0),
            '.rela.text': (4, 64, 0, 154920, 90096, 49, 13, 8, 24),
        },
        'format_addends': (0x18f6, 0x16b3),
    },
}


def select_recipe(source=None):
    """Select only an authenticated official LKM or its exact quiet derivative."""
    digest = BEFORE if source is None else hashlib.sha256(source).hexdigest() if isinstance(source, bytes) else source
    if not isinstance(digest, str):
        raise RuntimeError('Unsupported KernelSU module input.')
    for before, recipe in RECIPES.items():
        if digest in (before, recipe['after']):
            return before, recipe, digest == recipe['after']
    raise RuntimeError('Unsupported KernelSU module input.')


def receipt(source=None):
    """Describe the derivative without replacing official download pins."""
    before, recipe, _ = select_recipe(source)
    return {'schema': 1, 'id': 'kernelsu-marker-loop-v1', 'asset': ASSET,
            'version': recipe['version'], 'before': before, 'after': recipe['after'],
            'source_review_commit': recipe['source_review_commit'],
            'source_review_url': recipe['source_review_url'],
            'function': FUNCTION, 'site': recipe['site'], 'resume': recipe['resume']}


def _unpack(data, offset, layout):
    size = struct.calcsize(layout)
    if offset < 0 or offset + size > len(data):
        raise RuntimeError('KernelSU ELF record is outside the authenticated file.')
    return struct.unpack_from(layout, data, offset)


def _string(data, offset):
    if offset < 0 or offset >= len(data):
        raise RuntimeError('Invalid KernelSU ELF string offset.')
    end = data.find(b'\0', offset)
    if end < 0:
        raise RuntimeError('Unterminated KernelSU ELF string.')
    return data[offset:end]


def audit(data):
    """Authenticate both full content and the precise non-relocated edit."""
    if not isinstance(data, bytes):
        raise RuntimeError('Unsupported KernelSU module input.')
    digest = hashlib.sha256(data).hexdigest()
    before, recipe, patched = select_recipe(digest)
    function_start, function_size = recipe['function_start'], recipe['function_size']
    site, resume, printk = recipe['site'], recipe['resume'], recipe['printk']
    header = _unpack(data, 0, '<16sHHIQQQIHHHHHH')
    if (header[:4] != (b'\x7fELF\x02\x01\x01' + b'\0' * 9, 1, 183, 1)
            or header[4:6] != (0, 0) or header[7:] != (0, 64, 0, 0, 64, 53, 50)
            or header[6] + header[12] * 64 != len(data)):
        raise RuntimeError('Unexpected KernelSU ARM64 ET_REL layout.')
    sections = [_unpack(data, header[6] + i * 64, '<IIQQQQIIQQ')
                for i in range(header[12])]
    names = sections[header[13]]
    name_data = data[names[4]:names[4] + names[5]]

    def section(name, expected):
        matches = [(i, item) for i, item in enumerate(sections)
                   if _string(name_data, item[0]) == name.encode()]
        if len(matches) != 1:
            raise RuntimeError('Ambiguous KernelSU ELF section: ' + name)
        index, item = matches[0]
        if item[1:] != expected or item[4] + item[5] > header[6]:
            raise RuntimeError('Unexpected KernelSU ELF section: ' + name)
        return index, item, data[item[4]:item[4] + item[5]]

    text_index, text, code = section('.text', recipe['sections']['.text'])
    ro_index, _, rodata = section('.rodata.str1.1', recipe['sections']['.rodata.str1.1'])
    sym_index, symtab, symbols_data = section('.symtab', recipe['sections']['.symtab'])
    _, _, strings = section('.strtab', recipe['sections']['.strtab'])
    _, _, reladata = section('.rela.text', recipe['sections']['.rela.text'])
    symbols = [_unpack(symbols_data, i, '<IBBHQQ')
               for i in range(0, symtab[5], 24)]

    def symbol(name, expected):
        matches = [(i, item) for i, item in enumerate(symbols)
                   if _string(strings, item[0]) == name.encode()]
        if len(matches) != 1 or matches[0][1][1:] != expected:
            raise RuntimeError('Unexpected KernelSU ELF symbol: ' + name)
        return matches[0][0]

    symbol(FUNCTION, (18, 0, text_index, function_start, function_size))
    printk_index = symbol('_printk', (16, 0, 0, 0, 0))
    body = code[function_start:function_start + function_size]
    if hashlib.sha256(body).hexdigest() != recipe['function_after' if patched else 'function_before']:
        raise RuntimeError('KernelSU marker function checksum mismatch.')
    expected_flow = bytearray(FLOW_GUARD)
    flow_start = site - 0x1c
    if patched:
        expected_flow[0x1c:0x20] = BRANCH
    if code[flow_start:flow_start + len(FLOW_GUARD)] != expected_flow:
        raise RuntimeError('KernelSU marker/refcount control flow mismatch.')
    relas = [_unpack(reladata, i, '<QQq') for i in range(0, len(reladata), 24)]
    if any(site <= item[0] < site + 4 for item in relas):
        raise RuntimeError('KernelSU marker branch has a loader relocation.')
    logs = [item for item in relas if function_start <= item[0] < function_start + function_size
            and item[1] >> 32 == printk_index]
    if logs != [(printk, (printk_index << 32) | 283, 0)]:
        raise RuntimeError('Unexpected KernelSU marker printk binding.')
    for start, addend, message in (
            (function_start + 0x48, recipe['format_addends'][0],
             b'\x016KernelSU: tp_marker: mark process: pid:%d, uid: %d, comm:%s\n'),
            (function_start + 0x54, recipe['format_addends'][1],
             b'\x016KernelSU: tp_marker: unmark process: pid:%d, uid: %d, comm:%s\n')):
        matches = [item for item in relas if item[0] in (start, start + 4)]
        if len(matches) != 2:
            raise RuntimeError('Missing KernelSU marker format relocations.')
        for item, location, kind in zip(matches, (start, start + 4), (275, 277)):
            target = symbols[item[1] >> 32]
            if (item[0] != location or item[1] & 0xffffffff != kind or item[2] != addend
                    or target[1:] != (3, 0, ro_index, 0, 0)
                    or _string(strings, target[0]) != b''):
                raise RuntimeError('Unexpected KernelSU marker format binding.')
        if _string(rodata, addend) != message:
            raise RuntimeError('KernelSU marker format string mismatch.')
    instruction, = _unpack(BRANCH, 0, '<I')
    if site + (instruction & 0x3ffffff) * 4 != resume:
        raise RuntimeError('KernelSU marker branch does not converge on credential cleanup.')
    return {'sha256': digest, 'patched': patched,
            'offset': text[4] + site, 'receipt': receipt(before)}


def patch_bytes(data):
    """Apply one four-byte branch without a compiler or binary tools."""
    verified = audit(data)
    if verified['patched']:
        return data
    output = bytearray(data)
    offset = verified['offset']
    if output[offset:offset + 4] != ORIGINAL:
        raise RuntimeError('KernelSU marker instruction mismatch.')
    output[offset:offset + 4] = BRANCH
    result = bytes(output)
    if audit(result)['sha256'] != verified['receipt']['after']:
        raise RuntimeError('KernelSU marker derivative checksum mismatch.')
    return result


def patch(source, destination):
    """Write a verified derivative atomically, preserving unknown outputs."""
    source, destination = Path(source), Path(destination)
    if source.resolve() == destination.resolve():
        raise RuntimeError('Keep the official KernelSU source and derivative separate.')
    result = patch_bytes(source.read_bytes())
    if destination.exists() or destination.is_symlink():
        info = destination.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RuntimeError('Unsafe KernelSU derivative output.')
        if destination.read_bytes() != result:
            raise RuntimeError('Preserving an unknown KernelSU derivative output.')
        return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.ksu-marker-', dir=destination.parent)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            output.write(result)
            output.flush()
            os.fsync(output.fileno())
            os.fchmod(output.fileno(), 0o644)
        # Publish completed bytes exclusively; a new unknown leaf must not be
        # overwritten if it appears after the earlier existence check.
        try:
            os.link(temporary, destination)
        except FileExistsError:
            info = destination.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or destination.read_bytes() != result):
                raise RuntimeError('Preserving an unexpectedly created KernelSU derivative output.')
    finally:
        Path(temporary).unlink(missing_ok=True)
    return destination


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('destination', type=Path)
    arguments = parser.parse_args()
    print(patch(arguments.source, arguments.destination))
