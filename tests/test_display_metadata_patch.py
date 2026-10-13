"""Exercise exact unsupported contracts and their real cleanup instructions."""
import hashlib
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'scripts'))
import patch_display_metadata as metadata
from patch_rear_display import _sections


def execute_ui_failure(data, layout, heap=False):
    """Decode the real scalar failure path with a protected caller optional.

    Local vectors have already been constructed at the exact replaced call.
    Both inline and allocated temporaries are exercised; no output write, mapper
    call, fabricated decoded payload or unrelated helper call is permitted.
    """
    site, negative, cleanup, restore, vector, inline, free_call, frame = layout
    registers = {i: 0x5000 + i for i in range(31)}
    stack, caller = 0x10000, 0x80000
    registers[19], registers[29] = caller, stack + frame
    inline_pointer = stack + inline + 0x20
    pointer = 0x90000 if heap else inline_pointer
    memory = {stack + vector: pointer, stack + inline: inline_pointer}
    output = bytes(range(32))
    memory.update({caller + i: value for i, value in enumerate(output)})
    visited, freed, equal, pc = [], [], False, site

    def read(index, sp=False):
        return stack if sp and index == 31 else registers.get(index, 0)

    def write(address, value):
        if caller <= address < caller + len(output):
            raise AssertionError('Unsupported metadata changed the caller optional.')
        memory[address] = value

    def branch(word, bits, shift):
        immediate = (word >> shift) & ((1 << bits) - 1)
        if immediate & (1 << (bits - 1)):
            immediate -= 1 << bits
        return visited[-1] + immediate * 4

    for _ in range(50):
        if pc == restore:
            return registers[0], bytes(memory[caller + i] for i in range(32)), freed, visited
        visited.append(pc)
        word, = struct.unpack_from('<I', data, pc)
        pc += 4
        rd, rn, rm = word & 31, (word >> 5) & 31, (word >> 16) & 31
        if word & 0xff800000 == 0x12800000:  # MOVN Wd,#imm16.
            registers[rd] = (~(((word >> 5) & 0xffff) << (((word >> 21) & 3) * 16))) & 0xffffffff
        elif word & 0xffe0ffe0 in (0x2a0003e0, 0xaa0003e0):  # MOV W/X register.
            registers[rd] = read(rm) & (0xffffffffffffffff if word & (1 << 31) else 0xffffffff)
        elif word & 0x7e000000 == 0x36000000:  # TBZ/TBNZ.
            bit = ((word >> 19) & 31) | ((word >> 26) & 32)
            if bool(read(rd) & (1 << bit)) == bool(word & (1 << 24)):
                pc = branch(word, 14, 5)
        elif word & 0x7e000000 == 0x34000000:  # CBZ/CBNZ.
            if bool(read(rd)) == bool(word & (1 << 24)):
                pc = branch(word, 19, 5)
        elif word & 0xffc003ff == 0x3100007f:  # CMN W3,#immediate.
            equal = (read(rn) + ((word >> 10) & 0xfff)) & 0xffffffff == 0
        elif word & 0xff000010 == 0x54000000:  # B.EQ/B.NE.
            condition = word & 15
            if condition not in (0, 1):
                raise AssertionError('Unreviewed failure branch condition.')
            if equal == (condition == 0):
                pc = branch(word, 19, 5)
        elif word >> 26 == 0x05:  # B
            pc = branch(word, 26, 0)
        elif word >> 26 == 0x25:  # Only the original owned temporary free may execute.
            if branch(word, 26, 0) != free_call:
                raise AssertionError('Unreviewed call on unsupported metadata path.')
            freed.append(registers[0])
            registers[0], registers[8], registers[9] = 0xdead, 0xbad, 0xbeef
        elif word & 0xffc00000 in (0x39000000, 0xb9000000, 0xf9000000):
            scale = (word >> 30) & 3
            write(read(rn, sp=True) + ((word >> 10) & 0xfff) * (1 << scale), read(rd))
        elif word & 0xffc00000 in (0xb9400000, 0xf9400000):
            scale = (word >> 30) & 3
            registers[rd] = memory[read(rn, sp=True) + ((word >> 10) & 0xfff) * (1 << scale)]
        elif word & 0xffe0fc1f == 0xeb00001f:  # CMP Xn,Xm.
            equal = read(rn) == read(rm)
        else:
            raise AssertionError('Unreviewed instruction %08x at %x.' % (word, pc - 4))
    raise AssertionError('Metadata failure did not reach original restore.')


class DisplayMetadataPatchTests(unittest.TestCase):
    def artifact(self, name):
        key = 'HYPEROS_AVD_METADATA_' + name.replace('-', '_').replace('.', '_').upper()
        source = Path(os.environ.get(key, str(
            REPO / 'work/feedback-investigation-20261013/pad-metadata-caller-audit' / name)))
        if not source.is_file():
            self.skipTest('Audited private display ELF unavailable; no download attempted.')
        return source.read_bytes()

    def consumers(self):
        return [('libui.so', self.artifact('libui.so')),
                ('phone-libui.so', self.artifact('phone-libui.so')),
                ('libsurfaceflinger.so', self.artifact('libsurfaceflinger.so'))]

    def test_exact_mapper_rejects_standard24_and_custom_namespace_without_modification(self):
        source = self.artifact('mapper.ranchu.so')
        proof = metadata.audit_mapper(source)
        self.assertEqual(hashlib.sha256(source).hexdigest(), proof['sha256'])
        self.assertEqual(proof['unsupported_standard_types'], [24])
        self.assertEqual(proof['unsupported_namespace'], 'xring.graphics.XringMetadataType')
        # Independently decode (type-1)>22; 24 reaches the actual -7 return.
        subtract, _, compare, branch = struct.unpack_from('<IIII', source, 0x5bc0)
        self.assertEqual(subtract, 0xd1000448)
        self.assertEqual((compare >> 10) & 0xfff, 22)
        self.assertEqual(branch & 15, 8)  # B.HI unsigned comparison.
        self.assertEqual(metadata._branch_target(branch, 0x5bcc, 19, 5), 0x5c30)
        self.assertEqual(source[0x5c60:0x5c64], bytes.fromhex('c0008012'))
        # Nonstandard namespace strcmp failure returns -7 without decoding data.
        self.assertEqual(source[0x59bc:0x59c0], bytes.fromhex('e90d0094'))
        self.assertEqual(source[0x59c0:0x59c4], bytes.fromhex('60020034'))
        self.assertEqual(source[0x59f4:0x59f8], bytes.fromhex('c0008012'))
        self.assertEqual(metadata.capability_recipe(), (
            'schema|1\nmapper|' + metadata.MAPPER + '|' + metadata.MAPPER_SHA256 + '\n').encode())
        modified = bytearray(source); modified[0x5bc8] ^= 1
        with self.assertRaises(RuntimeError):
            metadata.audit_mapper(modified)

    def test_each_content_recipe_changes_only_its_one_word_and_is_idempotent(self):
        for name, source in self.consumers():
            with self.subTest(artifact=name):
                _, row, patched = metadata.audit(source)
                self.assertFalse(patched)
                output = metadata.patch_bytes(source)
                self.assertEqual(len(output), len(source))
                self.assertEqual(hashlib.sha256(output).hexdigest(), row['after'])
                site = row['site']
                self.assertEqual(output[:site], source[:site])
                self.assertEqual(output[site + 4:], source[site + 4:])
                self.assertEqual(output[site:site + 4], bytes.fromhex(row['replacement']))
                self.assertEqual(metadata.patch_bytes(output), output)
                self.assertTrue(metadata.audit(output)[2])

    def test_actual_ui_cleanup_keeps_optional_untouched_and_frees_only_its_temporary(self):
        fixtures = [('libui.so', (0x3a32c, 0x3a43c, 0x3a3ac, 0x3a40c, 0x90, 0xa8, 0x61020, 0x140)),
                    ('phone-libui.so', (0x3a020, 0x3a124, 0x3a0a0, 0x3a100, 0x38, 0x50, 0x60e68, 0x130))]
        for name, layout in fixtures:
            output = metadata.patch_bytes(self.artifact(name))
            for heap in (False, True):
                with self.subTest(artifact=name, allocated=heap):
                    result, optional, frees, visited = execute_ui_failure(output, layout, heap)
                    self.assertEqual(result, (-74) & 0xffffffff)
                    self.assertEqual(optional, bytes(range(32)))
                    self.assertEqual(frees, [0x90000] if heap else [])
                    self.assertIn(layout[1], visited)
                    self.assertIn(layout[2], visited)
                    # Capacity retry and optional mutation never execute.
                    self.assertNotIn(0x3a484 if name == 'libui.so' else 0x3a168, visited)

    def test_ui_pac_canary_return_frames_and_supported_metadata_remain_identical(self):
        for name in ('libui.so', 'phone-libui.so'):
            source = self.artifact(name); output = metadata.patch_bytes(source)
            _, row, _ = metadata.audit(source)
            start, site = row['address'], row['site']
            self.assertEqual(output[start:site], source[start:site])
            self.assertEqual(output[site + 4:start + row['function_size']], source[site + 4:start + row['function_size']])
            if name.startswith('phone'):
                self.assertEqual(output[start:start + 4], bytes.fromhex('3f2303d5'))
                self.assertEqual(output[row['restore_end'] - 8:row['restore_end']], bytes.fromhex('bf2303d5c0035fd6'))
            else:
                self.assertEqual(output[row['restore']:row['restore'] + 16],
                                 bytes.fromhex('a81640f9a9835ff81f0109eb81020054'))
            # Full immutable hash includes every supported getter, all setters,
            # metadata readers, strings, CFI and relocation data.
            self.assertEqual(hashlib.sha256(output[:start] + output[start + row['function_size']:]).hexdigest(),
                             row['immutable_sha256'])

    def test_dolby_false_path_balances_original_shared_reference_before_buffer_acquire(self):
        source = self.artifact('libsurfaceflinger.so'); output = metadata.patch_bytes(source)
        # Original shared-control acquire remains before the new unconditional
        # branch. GraphicBuffer's later incStrong must never be skipped midway.
        self.assertEqual(output[0x6787c0:0x6787d0], source[0x6787c0:0x6787d0])
        self.assertEqual(output[0x6787cc:0x6787d0], bytes.fromhex('b57cf397'))
        word, = struct.unpack_from('<I', output, 0x6787d0)
        self.assertEqual(word >> 26, 5)
        self.assertEqual(metadata._branch_target(word, 0x6787d0), 0x678860)
        self.assertEqual(output[0x678860:0x678864], bytes.fromhex('f4031f2a'))  # W20=false.
        # Null controls skip release; live controls retain their original
        # decrement, zero-count destruction and shared-weak release branches.
        self.assertEqual(output[0x678864:0x678890], source[0x678864:0x678890])
        self.assertEqual(output[0x678870:0x678874], bytes.fromhex('a07bf397'))
        self.assertEqual(output[0x67888c:0x678890], bytes.fromhex('15921794'))
        self.assertEqual(output[0x6788a0:0x6788a4], bytes.fromhex('e003142a'))  # W0=W20.
        self.assertEqual(output[0x678890:0x6788c4], source[0x678890:0x6788c4])
        self.assertEqual(output[0x6787f4:0x6787f8], source[0x6787f4:0x6787f8])  # Unexecuted incStrong.
        self.assertEqual(output[0x678ac0:0x678b08], source[0x678ac0:0x678b08])  # Original acquired-buffer cleanup.

    def test_all_properties_logs_elf_metadata_and_other_phone_dolby_abi_are_preserved(self):
        for name, source in self.consumers():
            output = metadata.patch_bytes(source)
            _, sections = _sections(source)
            for label, section in sections.items():
                if label == b'.text' or section[1] == 8:
                    continue
                offset, length = section[4:6]
                self.assertEqual(source[offset:offset + length], output[offset:offset + length], label)
            self.assertIn(b'__android_log_print\0', output)
            if name == 'libsurfaceflinger.so':
                for site in (0x4b7800, 0x4b7dd8):
                    self.assertEqual(source[site - 20:site + 20], output[site - 20:site + 20])
                self.assertIn(b'ro.vendor.display.bt2020.supported\0', output)
        phone = self.artifact('phone-libsurfaceflinger.so')
        self.assertEqual(hashlib.sha256(phone).hexdigest(),
                         'fef17e489200a456fcff3cc32fc3e8f6b692526fe72afbdd30d313286c809559')
        with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
            metadata.patch_bytes(phone)

    def test_offline_receipts_reproduce_every_exact_derivative_and_bind_mapper_proof(self):
        self.assertEqual(len(metadata.catalog_recipes()), 3)
        for _, source in self.consumers():
            receipt = metadata.receipt(source)
            self.assertEqual(receipt['mapper_capability'], metadata.mapper_capability())
            self.assertEqual(receipt['requires'], metadata.REQUIRES)
            output = bytearray(source)
            for site in receipt['sites']:
                self.assertEqual(output[site['offset']:site['offset'] + 4], bytes.fromhex(site['before']))
                output[site['offset']:site['offset'] + 4] = bytes.fromhex(site['after'])
            self.assertEqual(hashlib.sha256(output).hexdigest(), receipt['after'])
            self.assertEqual(metadata.receipt(output), receipt)

    def test_unknown_and_structure_tampering_is_refused(self):
        for _, source in self.consumers():
            selected = metadata.select_recipe(source); row = selected[1]
            for offset in (4, 18, row['site'], row['cleanup'], row['restore'], len(source) - 1):
                with self.subTest(source=selected[0], offset=offset):
                    modified = bytearray(source); modified[offset] ^= 1
                    with self.assertRaises(RuntimeError):
                        metadata.patch_bytes(modified)
                    with patch.object(metadata, 'select_recipe', return_value=selected), self.assertRaises(RuntimeError):
                        metadata.audit(modified)
        with self.assertRaises(RuntimeError):
            metadata.patch_bytes(b'user customized input')
        with self.assertRaises(RuntimeError):
            metadata.recipe_receipt('0' * 64)

    def test_atomic_derivative_publication_retains_factory_and_unknown_aliases(self):
        source_data = self.artifact('libui.so')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source = root / 'factory.so'; target = root / 'result.so'
            source.write_bytes(source_data)
            metadata.patch(source, target)
            original_inode = target.stat().st_ino
            self.assertEqual(target.stat().st_nlink, 1)
            self.assertEqual(target.stat().st_mode & 0o777, 0o644)
            metadata.patch(source, target)
            self.assertEqual(target.stat().st_ino, original_inode)
            self.assertEqual(source.read_bytes(), source_data)
            alias = root / 'alias.so'; alias.symlink_to(source)
            for src, dst in ((source, source), (alias, target), (source, alias)):
                with self.assertRaises(RuntimeError):
                    metadata.patch(src, dst)
            target.write_bytes(b'custom output')
            with self.assertRaisesRegex(RuntimeError, 'unknown'):
                metadata.patch(source, target)
            self.assertEqual(target.read_bytes(), b'custom output')
            self.assertFalse(list(root.glob('.display-metadata-*')))

    def test_failed_publication_or_race_does_not_replace_user_content(self):
        data = self.artifact('libui.so')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source = root / 'factory.so'; target = root / 'result.so'
            source.write_bytes(data)
            with patch.object(metadata.os, 'fsync', side_effect=OSError('disk full')), self.assertRaises(OSError):
                metadata.patch(source, target)
            self.assertFalse(target.exists())
            def race(*_):
                target.write_bytes(b'user content')
                raise FileExistsError()
            with patch.object(metadata.os, 'link', side_effect=race), self.assertRaisesRegex(RuntimeError, 'unknown'):
                metadata.patch(source, target)
            self.assertEqual(target.read_bytes(), b'user content')
            self.assertEqual(source.read_bytes(), data)
            self.assertFalse(list(root.glob('.display-metadata-*')))


if __name__ == '__main__':
    unittest.main()
