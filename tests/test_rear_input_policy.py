"""Audit the rear-only noninteractive motion gate without repacking framework code."""
import hashlib
import io
import itertools
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import patch_rear_input_policy as policy


def motion(body, display, flags, wake, dispatch, action, sleeping):
    """Execute the audited method's finite DEX subset, recording policy calls."""
    units = struct.unpack('<' + 'H' * (len(body) // 2), body)
    registers = {10: 'this', 11: display, 12: 0x1002, 13: action,
                 14: 4000000000, 15: 0, 16: flags}
    pc, last, calls = 0, None, []
    for _ in range(100):
        unit = units[pc]
        opcode, high = unit & 0xff, unit >> 8
        if opcode == 0xdd:  # and-int/lit8
            operand = units[pc + 1]
            registers[high] = registers[operand & 0xff] & (operand >> 8)
            pc += 2
        elif opcode == 0x12:  # const/4
            value = high >> 4
            registers[high & 15] = value if value < 8 else value - 16
            pc += 1
        elif opcode in (0x38, 0x39, 0x33):  # if-eqz, if-nez, if-ne
            delta = units[pc + 1]
            delta = delta if delta < 32768 else delta - 65536
            if opcode == 0x33:
                take = registers[high & 15] != registers[high >> 4]
            else:
                take = (registers[high] == 0) == (opcode == 0x38)
            pc += delta if take else 2
        elif opcode == 0x0f:
            return registers[high], calls
        elif opcode == 0x54:  # iget-object mWindowWakeUpPolicy
            registers[high & 15] = 'wake-policy'
            pc += 2
        elif opcode == 0x17:  # const-wide/32
            registers[high] = units[pc + 1] | units[pc + 2] << 16
            pc += 3
        elif opcode == 0x9e:  # div-long
            operand = units[pc + 1]
            registers[high] = registers[operand & 0xff] // registers[operand >> 8]
            pc += 2
        elif opcode == 0x01:  # move
            registers[high & 15] = registers[high >> 4]
            pc += 1
        elif opcode == 0x28:  # goto
            pc += high if high < 128 else high - 256
        elif opcode == 0x55:  # iget-boolean mDeviceGoingToSleep
            registers[high & 15] = sleeping
            pc += 2
        elif opcode == 0x74:  # invoke-virtual/range wakeUpFromMotion
            assert high == 7
            start = units[pc + 2]
            calls.append(('wake', registers[start + 1], registers[start + 2],
                          registers[start + 4], registers[start + 5], registers[start + 6]))
            last = int(wake)
            pc += 3
        elif opcode == 0x70:  # invoke-direct shouldDispatchInputWhenNonInteractive
            assert high == 0x30 and units[pc + 1] == 35465
            operands = units[pc + 2]
            calls.append(('dispatch', registers[(operands >> 4) & 15],
                          registers[(operands >> 8) & 15]))
            last = int(dispatch)
            pc += 3
        elif opcode == 0x0a:  # move-result
            registers[high] = last
            pc += 1
        else:
            raise AssertionError('Unexpected audited opcode: ' + hex(opcode))
    raise AssertionError('Audited motion method did not terminate.')


class RearInputRecipeTests(unittest.TestCase):
    def test_gate_precedes_every_wake_and_dispatch_path_and_preserves_other_displays(self):
        cases = itertools.product((-1, 0, 1, 2, 3, 999), (0, 1, 3, 254),
                                  (False, True), (False, True), (0, 1, 2), (False, True))
        for values in cases:
            display, flags, wake, dispatch, action, sleeping = values
            before = motion(policy.BODY_BEFORE, *values)
            after = motion(policy.BODY_AFTER, *values)
            if display == policy.DISPLAY_ID:
                self.assertEqual(after, (0, []), values)
            else:
                self.assertEqual(after, before, values)

    def test_recipe_is_one_canonical_early_unsigned_framework_edge(self):
        from native_patch_catalog import catalog
        recipe = policy.recipe_receipt()
        self.assertEqual(policy.catalog_recipes(), (recipe,))
        self.assertEqual(recipe['display_id'], 1)
        self.assertEqual(recipe['methods'], [policy.METHOD])
        self.assertEqual(recipe['format'], 'framework-jar')
        profile = next(row for row in catalog()['profiles'] if row['feature'] == 'rear-input')
        self.assertEqual(profile['before'], recipe['before'])
        self.assertEqual(profile['after'], recipe['after'])
        self.assertEqual(profile['sites'], [list(site) for site in policy.SITES])
        target = next(row for row in catalog()['targets'] if row['feature'] == 'rear-input')
        self.assertEqual((target['path'], target['phase'], target['kind']), (policy.PATH, 'early', 'system'))
        recipe['sites'].clear()
        self.assertEqual(len(policy.recipe_receipt()['sites']), 4)

    def test_unknown_content_never_creates_output_or_guesses_a_site(self):
        for data in (b'', b'PK\x03\x04', b'unknown signed framework'):
            with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
                policy.patch_bytes(data)
        with self.assertRaises(RuntimeError):
            policy.recipe_receipt(policy.AFTER)
        with tempfile.TemporaryDirectory() as temporary:
            source, output = Path(temporary) / 'custom.jar', Path(temporary) / 'new/derivative.jar'
            source.write_bytes(b'customized firmware')
            with self.assertRaises(RuntimeError):
                policy.patch(source, output)
            self.assertFalse(output.parent.exists())
            self.assertEqual(source.read_bytes(), b'customized firmware')


class RearInputAuditedArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        default = ROOT / ('work/feedback-investigation-20261013/rear-state-sync/'
                         'phone-services-' + policy.BEFORE + '.jar')
        cls.path = Path(os.environ.get('HYPEROS_AVD_REAR_INPUT_ARTIFACT', str(default)))
        if not cls.path.is_file():
            raise unittest.SkipTest('Private audited services JAR unavailable; no download attempted.')
        cls.original = cls.path.read_bytes()
        cls.output = policy.patch_bytes(cls.original)

    def test_full_content_selection_idempotence_and_generic_catalog_application_agree(self):
        self.assertFalse(policy.audit(self.original))
        self.assertTrue(policy.audit(self.output))
        self.assertEqual(policy.patch_bytes(self.output), self.output)
        self.assertEqual(policy.receipt(self.original), policy.recipe_receipt())
        self.assertEqual(policy.receipt(self.output), policy.recipe_receipt())
        replay = bytearray(self.original)
        for offset, before, after in policy.SITES:
            self.assertEqual(replay[offset:offset + len(bytes.fromhex(before))].hex(), before)
            replay[offset:offset + len(bytes.fromhex(after))] = bytes.fromhex(after)
        self.assertEqual(bytes(replay), self.output)
        self.assertEqual(hashlib.sha256(self.output).hexdigest(), policy.AFTER)

    def test_only_four_exact_sites_change_and_other_dex_members_keep_their_bytes(self):
        self.assertEqual(len(self.original), len(self.output))
        cursor = 0
        for offset, before, after in policy.SITES:
            self.assertEqual(self.original[cursor:offset], self.output[cursor:offset])
            self.assertEqual(self.original[offset:offset + len(bytes.fromhex(before))].hex(), before)
            self.assertEqual(self.output[offset:offset + len(bytes.fromhex(after))].hex(), after)
            cursor = offset + len(bytes.fromhex(before))
        self.assertEqual(self.original[cursor:], self.output[cursor:])
        with zipfile.ZipFile(io.BytesIO(self.original)) as original, zipfile.ZipFile(io.BytesIO(self.output)) as output:
            self.assertIsNone(output.testzip())
            self.assertEqual(original.namelist(), output.namelist())
            for first, second in zip(original.infolist(), output.infolist()):
                for field in ('filename', 'compress_type', 'header_offset', 'file_size', 'compress_size',
                              'flag_bits', 'date_time', 'extra', 'comment', 'external_attr', 'internal_attr'):
                    self.assertEqual(getattr(first, field), getattr(second, field))
                if first.filename != policy.MEMBER:
                    self.assertEqual(original.read(first.filename), output.read(first.filename))

    def test_method_header_tables_try_debug_and_helper_are_retained_with_valid_checksums(self):
        old = self.original[policy.DEX_OFFSET:policy.DEX_OFFSET + policy.DEX_SIZE]
        new = self.output[policy.DEX_OFFSET:policy.DEX_OFFSET + policy.DEX_SIZE]
        start = policy.CODE_OFFSET + 16
        self.assertEqual(old[32:start], new[32:start])
        self.assertEqual(old[start + 74:], new[start + 74:])
        self.assertEqual(policy._methods(old), policy._methods(new))
        self.assertEqual(struct.unpack_from('<4H2I', new, policy.CODE_OFFSET), policy.CODE_HEADER)
        self.assertEqual(new[12:32], hashlib.sha1(new[32:]).digest())
        self.assertEqual(struct.unpack_from('<I', new, 8)[0], zlib.adler32(new[12:]) & 0xffffffff)
        self.assertEqual(hashlib.sha256(new).hexdigest(), policy.DEX_AFTER)

    def test_unknown_tampered_partial_or_signed_framework_is_preserved(self):
        for offset in (0, policy.SITES[0][0], policy.DEX_OFFSET + 8,
                       policy.DEX_OFFSET + policy.CODE_OFFSET + 16, len(self.original) - 1):
            changed = bytearray(self.original)
            changed[offset] ^= 1
            with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
                policy.patch_bytes(changed)
        partial = bytearray(self.original)
        offset, _, replacement = policy.SITES[2]
        partial[offset:offset + 74] = bytes.fromhex(replacement)
        with self.assertRaises(RuntimeError):
            policy.patch_bytes(partial)
        with self.assertRaises(RuntimeError):
            policy.patch_bytes(self.original + b'APK Sig Block 42')

    def test_atomic_outputs_keep_existing_inodes_unknown_files_and_aliases(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'derivative.jar'
            policy.patch(self.path, output)
            inode = output.stat().st_ino
            policy.patch(self.path, output)
            self.assertEqual(output.stat().st_ino, inode)
            alias = Path(temporary) / 'alias.jar'
            alias.symlink_to(output)
            with self.assertRaises(RuntimeError):
                policy.patch(self.path, alias)
            output.write_bytes(b'custom user derivative')
            with self.assertRaises(RuntimeError):
                policy.patch(self.path, output)
            self.assertEqual(output.read_bytes(), b'custom user derivative')
            self.assertFalse(list(Path(temporary).glob('.rear-input-*')))

    def test_racing_output_is_preserved_and_temporary_file_is_removed(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'derivative.jar'

            def occupied(*_):
                output.write_bytes(b'racing user output')
                raise FileExistsError()

            with patch.object(policy.os, 'link', side_effect=occupied), self.assertRaises(RuntimeError):
                policy.patch(self.path, output)
            self.assertEqual(output.read_bytes(), b'racing user output')
            self.assertFalse(list(Path(temporary).glob('.rear-input-*')))


if __name__ == '__main__':
    unittest.main()
