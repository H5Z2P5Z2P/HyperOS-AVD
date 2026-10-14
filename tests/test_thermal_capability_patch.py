"""Keep missing board-temperature hardware out of the audited monitor startup."""
import hashlib
import io
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import zlib

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'scripts'))
import patch_thermal_capability as thermal
import patch_uniperf as uniperf


class ThermalCapabilityPatchTests(unittest.TestCase):
    def artifacts(self):
        paths = [Path(os.environ.get('HYPEROS_AVD_THERMAL_' + form.upper() + '_ARTIFACT', str(
            REPO / 'work/feedback-investigation-20261013' /
            (form + '-uniperf-loaded-caller') / 'miui-services-gated.jar')))
                 for form in ('phone', 'pad')]
        if not all(path.is_file() for path in paths):
            self.skipTest('Audited proprietary unsigned Phone/Pad JARs are not distributed in Git.')
        return [path.read_bytes() for path in paths]

    def test_rules_share_prerequisite_identities_and_require_actual_missing_node(self):
        self.assertEqual(len(thermal.RECIPES), 2)
        self.assertEqual({row['after'] for row in uniperf.RECIPES.values()
                          if row['path'] == thermal.PATH}, set(thermal.RECIPES))
        for row in thermal.catalog_recipes():
            self.assertEqual(row['requires'], 'ranchu-without-board-temperature-node')
            self.assertEqual(row['absent_node'], thermal.NODE)
            self.assertEqual(row['methods'][0], thermal.METHOD)
            self.assertTrue(set(row['methods']) <= {thermal.METHOD, thermal.SCENE_METHOD})
            self.assertEqual(row['path'], thermal.PATH)
            self.assertEqual(row['format'], 'framework-jar')
            self.assertEqual(len(row['sites']), 3 + len(row['methods']))
            self.assertEqual(sum(len(bytes.fromhex(site['before'])) for site in row['sites']),
                             36 + (12 if thermal.SCENE_METHOD in row['methods'] else 0))
            self.assertNotIn('avd', row['path'].lower())

    def test_unknown_input_is_rejected_without_any_output(self):
        for value in (b'unknown', b'', None, 'not bytes'):
            with self.subTest(value=value), self.assertRaisesRegex(RuntimeError, 'Unsupported'):
                thermal.patch_bytes(value)
        with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
            thermal.recipe_receipt('unknown')
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / 'source.jar', Path(directory) / 'out.jar'
            source.write_bytes(b'unknown')
            with self.assertRaises(RuntimeError):
                thermal.patch(source, output)
            self.assertFalse(output.exists())

    def test_both_real_derivatives_are_exact_idempotent_and_only_change_declared_sites(self):
        for original in self.artifacts():
            before, rule, patched = thermal.select_recipe(original)
            self.assertFalse(patched)
            result = thermal.patch_bytes(original)
            self.assertFalse(thermal.audit(original))
            self.assertTrue(thermal.audit(result))
            self.assertEqual(hashlib.sha256(result).hexdigest(), rule['after'])
            self.assertEqual(thermal.patch_bytes(result), result)
            self.assertEqual(thermal.receipt(original), thermal.recipe_receipt(before))
            self.assertEqual(thermal.receipt(result), thermal.receipt(original))
            self.assertEqual(len(result), len(original))
            allowed = {offset + index for offset, old, _ in rule['sites']
                       for index in range(len(bytes.fromhex(old)))}
            actual = {index for index, (old, new) in enumerate(zip(original, result)) if old != new}
            self.assertLessEqual(actual, allowed)

    def test_return_precedes_lock_handler_and_sampler_without_fabricating_a_reading(self):
        for original in self.artifacts():
            _, rule, _ = thermal.select_recipe(original)
            result = thermal.patch_bytes(original)
            offset, code = rule['dex_offset'], rule['code_offset']
            old = original[offset:offset + rule['dex_size']]
            new = result[offset:offset + rule['dex_size']]
            self.assertEqual(thermal._method(old, rule), code)
            self.assertEqual(thermal._method(new, rule), code)
            self.assertEqual(struct.unpack_from('<4H2I', new, code), rule['code_header'])
            # IGET_OBJECT takes two code units; replace it fully before MONITOR_ENTER.
            self.assertEqual(old[code + 16], 0x54)
            self.assertEqual(new[code + 16:code + 20], b'\x0e\0\0\0')
            if 'scene' in rule:
                site = rule['scene']['code_offset'] + 16
                self.assertEqual(old[32:site], new[32:site])
                self.assertEqual(old[site + 12:code + 16], new[site + 12:code + 16])
            else:
                self.assertEqual(old[32:code + 16], new[32:code + 16])
            self.assertEqual(old[code + 20:], new[code + 20:])
            self.assertEqual(new[code + 20], 0x1d)
            # Preserve the OEM method's complete body/tables, including parsing
            # and INVALID_TEMPERATURE fallback, rather than inventing a value.
            self.assertIn(thermal.NODE.encode() + b'\0', new)

    def test_scene_uses_original_failure_sentinel_and_retains_thermal_zone_fallback(self):
        seen = 0
        for original in self.artifacts():
            _, rule, _ = thermal.select_recipe(original)
            if 'scene' not in rule:
                continue
            seen += 1
            scene = rule['scene']
            old = original[rule['dex_offset']:rule['dex_offset'] + rule['dex_size']]
            result = thermal.patch_bytes(original)
            new = result[rule['dex_offset']:rule['dex_offset'] + rule['dex_size']]
            code = thermal._method(new, scene, scene=True)
            self.assertEqual(code, scene['code_offset'])
            self.assertEqual(struct.unpack_from('<4H2I', new, code), scene['code_header'])
            self.assertEqual(new[code + 16:code + 28], thermal.UNAVAILABLE_BOARD)
            # CONST/4 v0,-1 then five NOPs replaces complete fixed-node
            # CONST_STRING, INVOKE_STATIC and MOVE_RESULT instructions.
            # IF_LTZ and the original optional thermal-zone read stay intact.
            self.assertEqual(new[code + 28:code + 60], old[code + 28:code + 60])
            self.assertEqual(new[code + 28:code + 32], bytes.fromhex('3a000300'))
            self.assertEqual(old[code + 16:code + 28], bytes.fromhex(scene['original']))
            self.assertEqual(new[code + 58:code + 60], bytes.fromhex('0f01'))
        self.assertEqual(seen, 1)

    def test_dex_and_zip_checksums_metadata_and_other_members_are_preserved(self):
        for original in self.artifacts():
            _, rule, _ = thermal.select_recipe(original)
            result = thermal.patch_bytes(original)
            with zipfile.ZipFile(io.BytesIO(original)) as old, zipfile.ZipFile(io.BytesIO(result)) as new:
                self.assertIsNone(new.testzip())
                self.assertEqual(old.namelist(), new.namelist())
                for left, right in zip(old.infolist(), new.infolist()):
                    for attribute in ('filename', 'compress_type', 'header_offset', 'file_size',
                                      'compress_size', 'flag_bits', 'date_time', 'extra', 'comment',
                                      'external_attr', 'internal_attr'):
                        self.assertEqual(getattr(left, attribute), getattr(right, attribute))
                    if left.filename != rule['member']:
                        self.assertEqual(old.read(left), new.read(right))
                dex = new.read(rule['member'])
            self.assertEqual(dex[12:32], hashlib.sha1(dex[32:]).digest())
            self.assertEqual(struct.unpack_from('<I', dex, 8)[0], zlib.adler32(dex[12:]) & 0xffffffff)

    def test_tampered_signed_and_partial_inputs_fail_closed(self):
        for original in self.artifacts():
            _, rule, _ = thermal.select_recipe(original)
            for position in (0, 14, rule['dex_offset'] + 8,
                             rule['dex_offset'] + rule['code_offset'] + 16, len(original) - 1):
                corrupt = bytearray(original)
                corrupt[position] ^= 1
                with self.subTest(position=position), self.assertRaisesRegex(RuntimeError, 'Unsupported'):
                    thermal.patch_bytes(corrupt)
            with self.assertRaises(RuntimeError):
                thermal.patch_bytes(original + b'APK Sig Block 42')
            partial = bytearray(original)
            start = rule['dex_offset'] + rule['code_offset'] + 16
            partial[start:start + 4] = thermal.RETURN_VOID
            with self.assertRaises(RuntimeError):
                thermal.patch_bytes(partial)

    def test_atomic_output_preserves_factory_customized_content_and_aliases(self):
        original = self.artifacts()[0]
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            source, output = folder / 'source.jar', folder / 'out.jar'
            source.write_bytes(original)
            thermal.patch(source, output)
            inode = output.stat().st_ino
            thermal.patch(source, output)
            self.assertEqual(output.stat().st_ino, inode)
            self.assertEqual(source.read_bytes(), original)
            with self.assertRaises(RuntimeError):
                thermal.patch(source, source)
            alias = folder / 'alias.jar'
            alias.symlink_to(output)
            with self.assertRaises(RuntimeError):
                thermal.patch(source, alias)
            output.write_bytes(b'customized')
            with self.assertRaisesRegex(RuntimeError, 'unknown'):
                thermal.patch(source, output)
            self.assertEqual(output.read_bytes(), b'customized')
            self.assertFalse(list(folder.glob('.thermal-*')))

    def test_racing_output_is_preserved_and_temporary_file_is_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            source, output = folder / 'source.jar', folder / 'out.jar'
            source.write_bytes(self.artifacts()[0])

            def race(*_):
                output.write_bytes(b'user content')
                raise FileExistsError()

            with patch.object(thermal.os, 'link', side_effect=race):
                with self.assertRaisesRegex(RuntimeError, 'unknown'):
                    thermal.patch(source, output)
            self.assertEqual(output.read_bytes(), b'user content')
            self.assertFalse(list(folder.glob('.thermal-*')))


if __name__ == '__main__':
    unittest.main()
