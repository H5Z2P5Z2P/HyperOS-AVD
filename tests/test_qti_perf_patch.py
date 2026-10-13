"""Audit the physical QTI lookup ABI, coverage and immutable failure paths."""
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
import patch_qti_perf as qti
from patch_rear_display import _sections


class QtiPerfPatchTests(unittest.TestCase):
    def artifact(self):
        source = Path(os.environ.get('HYPEROS_AVD_QTI_PERF_ARTIFACT', str(
            REPO / 'work/feedback-investigation-20261013/phone-perf-callers/libqti-perfd-client_system.so')))
        if not source.is_file():
            self.skipTest('Audited private QTI Perf ELF unavailable; no download attempted.')
        return source.read_bytes()

    def test_all_five_physical_lookup_calls_are_removed_and_only_their_words_change(self):
        source = self.artifact()
        before, recipe, already = qti.audit(source)
        self.assertFalse(already)
        output = qti.patch_bytes(source)
        self.assertEqual(hashlib.sha256(output).hexdigest(), recipe['after'])
        self.assertEqual(len(output), len(source))
        self.assertEqual(qti.patch_bytes(output), output)
        self.assertTrue(qti.audit(output)[2])
        expected = {row['site'] for row in recipe['functions']}
        self.assertEqual(expected, {0xd5dc, 0xd7fc, 0xe954, 0x13aa8, 0x16ed8})
        allowed = {site + index for site in expected for index in range(4)}
        changed = {i for i, (old, new) in enumerate(zip(source, output)) if old != new}
        self.assertEqual(len(changed), 17)
        self.assertLessEqual(changed, allowed)
        physical = {row['plt'] for row in recipe['functions']}
        for row in recipe['functions']:
            word, = struct.unpack_from('<I', source, row['site'])
            self.assertEqual(word >> 26, 0x25)
            self.assertEqual(qti._branch_target(word, row['site']), row['plt'])
        _, sections = _sections(output)
        text = sections[b'.text']
        calls = set()
        for address in range(text[3], text[3] + text[5], 4):
            word, = struct.unpack_from('<I', output, text[4] + address - text[3])
            if word >> 26 in (0x05, 0x25) and qti._branch_target(word, address) in physical:
                calls.add(address)
        self.assertEqual(calls, set())

    def test_hidden_sp_returns_store_exactly_one_null_pointer_without_register_clobber(self):
        source = self.artifact()
        _, recipe, _ = qti.audit(source)
        output = qti.patch_bytes(source)
        for row in recipe['functions']:
            if row['result'] != 'sp-null':
                continue
            with self.subTest(function=row['symbol']):
                word, = struct.unpack_from('<I', output, row['site'])
                # Decode STR's actual AArch64 ABI operands independently. A
                # NOP or MOV W0,0 would leave this callee-constructed sp dirty.
                self.assertEqual(word & 0xffc00000, 0xf9000000)
                self.assertEqual(word & 31, 31)  # Rt=XZR.
                self.assertEqual((word >> 5) & 31, 8)  # Rn=X8 hidden return slot.
                self.assertEqual((word >> 10) & 0xfff, 0)
                width = 1 << (word >> 30)
                self.assertEqual(width, 8)
                frame = bytearray(b'left-boundary---' + b'poisoned' + b'--right-boundary')
                registers = {i: 0x100 + i for i in range(31)}
                registers[8] = 16
                previous = dict(registers)
                destination = registers[(word >> 5) & 31]
                frame[destination:destination + width] = (0).to_bytes(width, 'little')
                self.assertEqual(frame[:16], b'left-boundary---')
                self.assertEqual(frame[16:24], b'\0' * 8)
                self.assertEqual(frame[24:], b'--right-boundary')
                self.assertEqual(registers, previous)
                start, end = row['address'], row['address'] + row['size']
                self.assertEqual(source[start:row['site']], output[start:row['site']])
                self.assertEqual(source[row['site'] + 4:end], output[row['site'] + 4:end])

    def test_scalar_null_results_preserve_existing_failure_branches(self):
        source = self.artifact()
        output = qti.patch_bytes(source)
        self.assertEqual(output[0xd5dc:0xd5e0], bytes.fromhex('e0031f2a'))  # MOV W0,WZR.
        self.assertEqual(output[0xd5e0:0xd5e4], bytes.fromhex('1f000072'))  # TST W0,#1.
        self.assertEqual(output[0xd7fc:0xd800], bytes.fromhex('e0031faa'))  # MOV X0,XZR.
        self.assertEqual(output[0xd800:0xd804], bytes.fromhex('e00700f9'))  # Store returned Binder.
        branch, = struct.unpack_from('<I', output, 0xd804)
        self.assertEqual(branch & 0xff00001f, 0xb4000000)  # CBZ X0.
        displacement = (branch >> 5) & 0x7ffff
        if displacement & 0x40000:
            displacement -= 0x80000
        self.assertEqual(0xd804 + displacement * 4, 0xd914)
        # The original null branch preserves failure, cleanup and diagnostic.
        self.assertEqual(source[0xd914:0xd938], output[0xd914:0xd938])

    def test_all_metadata_cfi_pac_frames_logs_and_nonlookup_code_remain_identical(self):
        source = self.artifact()
        _, recipe, _ = qti.audit(source)
        output = qti.patch_bytes(source)
        _, sections = _sections(source)
        for name, section in sections.items():
            if name == b'.text' or section[1] == 8:
                continue
            with self.subTest(section=name):
                offset, length = section[4:6]
                self.assertEqual(source[offset:offset + length], output[offset:offset + length])
        self.assertIn(b'__cfi_slowpath\0', output)
        self.assertIn(b'__android_log_print\0', output)
        for row in recipe['functions']:
            body = output[row['address']:row['address'] + row['size']]
            self.assertTrue(body.startswith(bytes.fromhex('3f2303d5')))  # PACIASP.
            self.assertIn(bytes.fromhex('bf2303d5c0035fd6'), body)  # Original AUTIASP/RET.
        # CFI dispatch and every exported trampoline are outside the five sites.
        self.assertEqual(source[0x18000:0x1a018], output[0x18000:0x1a018])

    def test_canonical_offline_catalog_binds_capability_and_reproduces_exact_derivative(self):
        self.assertEqual(len(qti.catalog_recipes()), 1)
        receipt = qti.catalog_recipes()[0]
        self.assertEqual(receipt['path'], qti.NATIVE)
        self.assertEqual(receipt['requires'], 'ranchu-without-qti-perf-hal')
        self.assertEqual(receipt['absent_hal_packages'], list(qti.ABSENT_HAL_PACKAGES))
        self.assertEqual(receipt['absent_services'], list(qti.ABSENT_SERVICES))
        self.assertEqual(len(receipt['sites']), 5)
        source = self.artifact()
        output = bytearray(source)
        for site in receipt['sites']:
            old, new = bytes.fromhex(site['before']), bytes.fromhex(site['after'])
            self.assertEqual(len(old), 4); self.assertEqual(len(new), 4)
            self.assertEqual(output[site['offset']:site['offset'] + 4], old)
            output[site['offset']:site['offset'] + 4] = new
        self.assertEqual(hashlib.sha256(output).hexdigest(), receipt['after'])
        self.assertEqual(qti.receipt(output), receipt)

    def test_unknown_and_partial_files_and_unverified_structure_are_refused(self):
        source = self.artifact()
        selected = qti.select_recipe(source)
        for offset in (4, 18, 0xd4e4, 0xe948, 0xd804, 0x1a598, len(source) - 1):
            with self.subTest(offset=offset):
                modified = bytearray(source); modified[offset] ^= 1
                with self.assertRaises(RuntimeError):
                    qti.patch_bytes(modified)
                with patch.object(qti, 'select_recipe', return_value=selected), self.assertRaises(RuntimeError):
                    qti.audit(modified)
        partial = bytearray(source)
        partial[0xd5dc:0xd5e0] = bytes.fromhex('e0031f2a')
        with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
            qti.patch_bytes(partial)
        with self.assertRaises(RuntimeError):
            qti.patch_bytes(b'unknown ELF')
        with self.assertRaises(RuntimeError):
            qti.recipe_receipt('0' * 64)

    def test_atomic_separate_publication_preserves_factory_aliases_and_unknown_output(self):
        source = self.artifact()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); factory = root / 'factory.so'; target = root / 'result.so'
            factory.write_bytes(source)
            qti.patch(factory, target)
            old = target.stat()
            self.assertEqual(old.st_mode & 0o777, 0o644)
            self.assertEqual(old.st_nlink, 1)
            qti.patch(factory, target)
            self.assertEqual(target.stat().st_ino, old.st_ino)
            self.assertEqual(factory.read_bytes(), source)
            with self.assertRaises(RuntimeError):
                qti.patch(factory, factory)
            alias = root / 'alias.so'; alias.symlink_to(factory)
            with self.assertRaises(RuntimeError):
                qti.patch(alias, target)
            with self.assertRaises(RuntimeError):
                qti.patch(factory, alias)
            target.write_bytes(b'custom output')
            with self.assertRaisesRegex(RuntimeError, 'unknown'):
                qti.patch(factory, target)
            self.assertEqual(target.read_bytes(), b'custom output')
            self.assertFalse(list(root.glob('.qti-perf-*')))

    def test_racing_unknown_destination_is_not_replaced(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source = root / 'factory.so'; target = root / 'result.so'
            source.write_bytes(self.artifact())
            def race(*_):
                target.write_bytes(b'user content')
                raise FileExistsError()
            with patch.object(qti.os, 'link', side_effect=race), self.assertRaisesRegex(RuntimeError, 'unknown'):
                qti.patch(source, target)
            self.assertEqual(target.read_bytes(), b'user content')
            self.assertFalse(list(root.glob('.qti-perf-*')))


if __name__ == '__main__':
    unittest.main()
