"""Verify truthful capability fallback without changing HWC or display power."""
import hashlib
import io
import itertools
import math
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
import patch_display_brightness as brightness
import patch_rear_input_policy as policy


def execute(body, header, support, force, rear, light, sdr, boost):
    """Execute the actual bounded DEX subset and capture every setter argument."""
    units = struct.unpack('<' + 'H' * (len(body) // 2), body)
    first = header[0] - header[1]
    registers = {first: 'adapter', first + 1: sdr, first + 2: 8.0,
                 first + 3: 0.3, first + 4: 12.0, first + 5: boost}
    fields = {0x232c: support, 0x2329: force, 0x232a: rear,
              0x2327: 'light' if light else None, 0x232b: 'proxy', 0x2328: 'token'}
    pc, last, calls = 0, None, []
    for _ in range(100):
        unit = units[pc]
        opcode, high = unit & 255, unit >> 8
        if opcode in (0x54, 0x55):  # iget-object/boolean
            assert registers[high >> 4] == 'adapter'
            registers[high & 15] = fields[units[pc + 1]]
            pc += 2
        elif opcode in (0x38, 0x39):  # if-eqz/nez
            zero = registers[high] is None or registers[high] == 0
            delta = units[pc + 1]
            pc += (delta if delta < 32768 else delta - 65536) if zero == (opcode == 0x38) else 2
        elif opcode == 0x28:  # goto
            pc += high if high < 128 else high - 256
        elif opcode == 0x29:  # goto/16
            assert high == 0
            delta = units[pc + 1]
            pc += delta if delta < 32768 else delta - 65536
        elif opcode == 0x15:  # const/high16 float NaN
            registers[high] = struct.unpack('<f', struct.pack('<I', units[pc + 1] << 16))[0]
            pc += 2
        elif opcode == 0x01:  # move
            registers[high & 15] = registers[high >> 4]
            pc += 1
        elif opcode in (0x6e, 0x71):  # invoke-virtual/static
            count = high >> 4
            operand = units[pc + 2]
            indices = [(operand >> shift) & 15 for shift in (0, 4, 8, 12)] + [high & 15]
            args = [registers[index] for index in indices[:count]]
            method = units[pc + 1]
            if opcode == 0x71:
                assert method == 0x20ae
                last = args[0] == args[1] or (math.isnan(args[0]) and math.isnan(args[1]))
            else:
                assert method in (0x9ed5, 0x638e)
                calls.append((method, *args))
            pc += 3
        elif opcode == 0x74:  # invoke-virtual/range
            assert units[pc + 1] in (0x638f, 0x6390)
            start = units[pc + 2]
            calls.append((units[pc + 1], *(registers[index] for index in range(start, start + high))))
            pc += 3
        elif opcode == 0x0a:  # move-result
            registers[high] = last
            pc += 1
        elif opcode == 0x0e:  # return-void
            return calls
        else:
            raise AssertionError('Unexpected brightness opcode: ' + hex(opcode))
    raise AssertionError('Brightness method did not terminate.')


class DisplayBrightnessBehaviorTests(unittest.TestCase):
    def test_all_three_reviewed_composers_keep_the_same_nonbrightness_capability(self):
        import patch_composer as alpha
        import patch_rear_display as rear
        import patch_display_privacy as privacy
        pins = {line.split('|')[2] for line in brightness.capability_recipe().decode().splitlines()
                if line.startswith('composer|')}
        inventory = {line.split('|')[2] for line in privacy.capability_recipe().decode().splitlines()
                     if line.startswith('composer|')}
        self.assertEqual(pins, set(brightness.composer_identities()))
        self.assertEqual(pins, inventory)
        source = ROOT / 'work/feedback-investigation-20261013/pad-metadata-caller-audit/composer.ranchu'
        if not source.is_file():
            self.skipTest('Private audited composer is unavailable; no download attempted.')
        data = bytearray(source.read_bytes())
        for offset, original, _ in alpha.SITES:
            data[offset:offset + len(original)] = original
        for offset, original, _ in rear.SITES:
            data[offset:offset + len(original)] = original
        canonical = bytes(data)
        self.assertEqual(hashlib.sha256(canonical).hexdigest(), alpha.BEFORE)
        fixed = alpha.patch(canonical)
        for value in (canonical, fixed, rear.patch(fixed)):
            proof = brightness.audit_composer(value)
            self.assertEqual(proof['values'], [1, 8])
            self.assertFalse(proof['brightness'])
        unknown = bytearray(fixed); unknown[0x26a8c] ^= 1
        with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
            brightness.audit_composer(bytes(unknown))

    def test_actual_overloads_keep_capability_force_lights_and_null_fallback(self):
        cases = itertools.product((False, True), repeat=5)
        cases = list(cases)
        for _, _, _, header, original in brightness.METHODS:
            modified = brightness.patched_body(original)
            for support, force, rear, light, boost in cases:
                for sdr in (0.4, float('nan')):
                    values = support, force, rear, light, sdr, boost
                    before = execute(original, header, *values)
                    after = execute(modified, header, *values)
                    if support or force or not rear:
                        self.assertEqual(after, before, values)
                    else:
                        self.assertEqual(after, [(0x9ed5, 'light', 0.3)] if light else [], values)
                    if support or force:
                        self.assertEqual(len(after), 1)
                        self.assertEqual(after[0][1:3], ('proxy', 'token'))
                        self.assertIn(after[0][0], (0x638e, 0x638f, 0x6390))
                    else:
                        self.assertFalse(any(call[0] in (0x638e, 0x638f, 0x6390) for call in after))

    def test_recipe_is_one_canonical_unsigned_edge_with_a_real_capability_requirement(self):
        receipt = brightness.recipe_receipt()
        self.assertEqual(brightness.BEFORE, policy.AFTER)
        self.assertEqual(brightness.SIZE, policy.SIZE)
        self.assertEqual(receipt['requires'], 'ranchu-without-display-brightness')
        self.assertEqual(receipt['format'], 'framework-jar')
        self.assertEqual(receipt['methods'], [row[0] for row in brightness.METHODS])
        self.assertEqual(brightness.catalog_recipes(), (receipt,))
        self.assertEqual(len(receipt['sites']), 5)
        receipt['sites'].clear()
        self.assertEqual(len(brightness.recipe_receipt()['sites']), 5)
        with self.assertRaises(RuntimeError):
            brightness.recipe_receipt(policy.BEFORE)

    def test_unknown_inputs_do_not_create_or_replace_outputs(self):
        for content in (b'', b'PK\x03\x04', b'unknown signed framework'):
            with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
                brightness.patch_bytes(content)
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / 'custom.jar'
            output = Path(temporary) / 'new/derivative.jar'
            source.write_bytes(b'custom user content')
            with self.assertRaises(RuntimeError):
                brightness.patch(source, output)
            self.assertFalse(output.parent.exists())
            self.assertEqual(source.read_bytes(), b'custom user content')


class DisplayBrightnessArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        default = ROOT / ('work/feedback-investigation-20261013/rear-state-sync/'
                         'phone-services-' + policy.BEFORE + '.jar')
        source = Path(os.environ.get('HYPEROS_AVD_DISPLAY_BRIGHTNESS_ARTIFACT', str(default)))
        if not source.is_file():
            raise unittest.SkipTest('Private audited services JAR unavailable; no download attempted.')
        content = source.read_bytes()
        cls.original = policy.patch_bytes(content) if hashlib.sha256(content).hexdigest() == policy.BEFORE else content
        cls.output = brightness.patch_bytes(cls.original)

    def test_content_method_selection_idempotence_and_offline_recipe_agree(self):
        self.assertFalse(brightness.audit(self.original))
        self.assertTrue(brightness.audit(self.output))
        self.assertEqual(brightness.patch_bytes(self.output), self.output)
        self.assertEqual(brightness.receipt(self.original), brightness.receipt(self.output))
        replay = bytearray(self.original)
        for offset, before, after in brightness.SITES:
            self.assertEqual(replay[offset:offset + len(bytes.fromhex(before))].hex(), before)
            replay[offset:offset + len(bytes.fromhex(after))] = bytes.fromhex(after)
        self.assertEqual(bytes(replay), self.output)
        self.assertEqual(hashlib.sha256(self.output).hexdigest(), brightness.AFTER)
        old = self.original[brightness.DEX_OFFSET:brightness.DEX_OFFSET + brightness.DEX_SIZE]
        new = self.output[brightness.DEX_OFFSET:brightness.DEX_OFFSET + brightness.DEX_SIZE]
        self.assertEqual(brightness._methods(old), brightness._methods(new))
        for _, _, code, header, body in brightness.METHODS:
            self.assertEqual(struct.unpack_from('<4H2I', new, code), header)
            self.assertEqual(new[code + 16:code + 16 + len(body)], brightness.patched_body(body))
        self.assertEqual(new[12:32], hashlib.sha1(new[32:]).digest())
        self.assertEqual(struct.unpack_from('<I', new, 8)[0], zlib.adler32(new[12:]) & 0xffffffff)

    def test_only_two_branch_words_and_required_checksums_change(self):
        self.assertEqual(len(self.original), len(self.output))
        cursor = 0
        for offset, before, after in brightness.SITES:
            self.assertEqual(self.original[cursor:offset], self.output[cursor:offset])
            self.assertEqual(self.original[offset:offset + len(bytes.fromhex(before))].hex(), before)
            self.assertEqual(self.output[offset:offset + len(bytes.fromhex(after))].hex(), after)
            cursor = offset + len(bytes.fromhex(before))
        self.assertEqual(self.original[cursor:], self.output[cursor:])
        with zipfile.ZipFile(io.BytesIO(self.original)) as before, zipfile.ZipFile(io.BytesIO(self.output)) as after:
            self.assertIsNone(after.testzip())
            self.assertEqual(before.namelist(), after.namelist())
            for first, second in zip(before.infolist(), after.infolist()):
                for field in ('filename', 'compress_type', 'header_offset', 'file_size', 'compress_size',
                              'flag_bits', 'date_time', 'extra', 'comment', 'external_attr', 'internal_attr'):
                    self.assertEqual(getattr(first, field), getattr(second, field))
                if first.filename != brightness.MEMBER:
                    self.assertEqual(before.read(first.filename), after.read(second.filename))
            self.assertEqual(before.read(policy.MEMBER), after.read(policy.MEMBER))

    def test_foreign_tampered_partial_signed_or_predecessor_input_is_refused(self):
        for offset in (0, brightness.DEX_OFFSET + 8, brightness.SITES[2][0], len(self.original) - 1):
            modified = bytearray(self.original)
            modified[offset] ^= 1
            with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
                brightness.patch_bytes(modified)
        partial = bytearray(self.original)
        offset = brightness.SITES[2][0]
        partial[offset:offset + 4] = brightness.GATE_AFTER
        with self.assertRaises(RuntimeError):
            brightness.patch_bytes(partial)
        with self.assertRaises(RuntimeError):
            brightness.patch_bytes(self.original + b'APK Sig Block 42')

    def test_outputs_preserve_loaded_inodes_unknown_files_and_aliases(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, output = Path(temporary) / 'source.jar', Path(temporary) / 'derivative.jar'
            source.write_bytes(self.original)
            brightness.patch(source, output)
            inode = output.stat().st_ino
            brightness.patch(source, output)
            self.assertEqual(output.stat().st_ino, inode)
            alias = Path(temporary) / 'alias.jar'
            alias.symlink_to(output)
            with self.assertRaises(RuntimeError):
                brightness.patch(source, alias)
            hardlink = Path(temporary) / 'hardlink.jar'
            os.link(output, hardlink)
            with self.assertRaises(RuntimeError):
                brightness.patch(source, output)
            hardlink.unlink()
            output.write_bytes(b'user derivative')
            with self.assertRaises(RuntimeError):
                brightness.patch(source, output)
            self.assertEqual(output.read_bytes(), b'user derivative')
            self.assertFalse(list(Path(temporary).glob('.display-brightness-*')))

    def test_racing_output_is_preserved_and_temporary_is_removed(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, output = Path(temporary) / 'source.jar', Path(temporary) / 'derivative.jar'
            source.write_bytes(self.original)

            def occupied(*_):
                output.write_bytes(b'racing user output')
                raise FileExistsError()

            with patch.object(brightness.os, 'link', side_effect=occupied), self.assertRaises(RuntimeError):
                brightness.patch(source, output)
            self.assertEqual(output.read_bytes(), b'racing user output')
            self.assertFalse(list(Path(temporary).glob('.display-brightness-*')))


if __name__ == '__main__':
    unittest.main()
