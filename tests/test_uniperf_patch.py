"""Keep the missing physical Uniperf HAL out of one unsigned-JAR capability."""
import hashlib
import io
import json
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
import patch_uniperf as uniperf


class UniperfPatchTests(unittest.TestCase):
    def artifact(self):
        path = Path(os.environ.get('HYPEROS_AVD_UNIPERF_ARTIFACT', str(
            REPO / 'work/feedback-investigation-20261013/phone-perf-callers/UniperfClient.jar')))
        if not path.is_file():
            self.skipTest('Audited proprietary unsigned Uniperf JAR is not distributed in Git.')
        return path.read_bytes()

    def test_real_derivative_is_exact_idempotent_and_only_changes_four_sites(self):
        original = self.artifact()
        output = uniperf.patch_bytes(original)
        self.assertEqual(hashlib.sha256(output).hexdigest(), uniperf.AFTER)
        self.assertFalse(uniperf.audit(original))
        self.assertTrue(uniperf.audit(output))
        self.assertEqual(uniperf.patch_bytes(output), output)
        self.assertEqual(len(original), len(output))
        allowed = {offset + index for offset, before, _ in uniperf.SITES
                   for index in range(len(bytes.fromhex(before)))}
        changed = {index for index, (old, new) in enumerate(zip(original, output)) if old != new}
        self.assertLessEqual(changed, allowed)
        self.assertEqual(len(uniperf.SITES), 4)
        self.assertEqual(sum(len(bytes.fromhex(row[1])) for row in uniperf.SITES), 38)

    def test_false_return_covers_complete_instructions_before_any_lock(self):
        original = self.artifact()
        start = uniperf.DEX_OFFSET + uniperf.CODE_OFFSET + 16
        self.assertEqual(original[start:start + 6], bytes.fromhex('120062010900'))
        result = uniperf.patch_bytes(original)
        self.assertEqual(result[start:start + 6], bytes.fromhex('12000f000000'))
        # CONST/4 is one code unit; SGET_OBJECT is two. A four-byte patch
        # would strand operand0009 as a different multi-unit instruction.
        self.assertEqual(uniperf.ORIGINAL[2] & 0xff, 0x62)
        self.assertEqual(uniperf.ORIGINAL[4:6], b'\x09\0')
        self.assertEqual(list(struct.unpack('<3H', result[start:start + 6])), [0x12, 0xf, 0])
        self.assertEqual(original[start + 6:start + 16], result[start + 6:start + 16])

    def test_entire_following_code_try_handlers_debug_and_dex_tables_survive(self):
        original = self.artifact()
        output = uniperf.patch_bytes(original)
        offset = uniperf.DEX_OFFSET
        old = original[offset:offset + uniperf.DEX_SIZE]
        new = output[offset:offset + uniperf.DEX_SIZE]
        code = uniperf._method(old)
        self.assertEqual(code, uniperf.CODE_OFFSET)
        self.assertEqual(uniperf._method(new), code)
        self.assertEqual(struct.unpack_from('<4H2I', new, code), uniperf.CODE_HEADER)
        self.assertEqual(old[32:code + 16], new[32:code + 16])
        self.assertEqual(old[code + 22:], new[code + 22:])
        # There are seven unchanged try_item records after the 151-unit body.
        tries = code + 16 + 2 * uniperf.CODE_HEADER[5]
        tries += tries % 4
        self.assertEqual(old[tries:tries + 7 * 8], new[tries:tries + 7 * 8])
        self.assertIn(uniperf.HAL.encode() + b'\0', new)

    def test_dex_and_zip_checksums_are_valid_without_archive_repacking(self):
        original = self.artifact()
        output = uniperf.patch_bytes(original)
        with zipfile.ZipFile(io.BytesIO(original)) as before, zipfile.ZipFile(io.BytesIO(output)) as after:
            self.assertIsNone(after.testzip())
            self.assertEqual(before.namelist(), after.namelist())
            self.assertEqual(before.read('META-INF/MANIFEST.MF'), after.read('META-INF/MANIFEST.MF'))
            for old, new in zip(before.infolist(), after.infolist()):
                for attribute in ('filename', 'compress_type', 'header_offset', 'file_size',
                                  'compress_size', 'flag_bits', 'date_time', 'extra', 'comment',
                                  'external_attr', 'internal_attr'):
                    self.assertEqual(getattr(old, attribute), getattr(new, attribute))
            dex = after.read('classes.dex')
        self.assertEqual(hashlib.sha256(dex).hexdigest(), uniperf.DEX_AFTER)
        self.assertEqual(dex[12:32], hashlib.sha1(dex[32:]).digest())
        self.assertEqual(struct.unpack_from('<I', dex, 8)[0], zlib.adler32(dex[12:]) & 0xffffffff)
        self.assertNotIn(b'APK Sig Block 42', output)

    def test_catalog_is_one_source_for_both_hal_free_device_forms(self):
        data = self.artifact()
        recipe = uniperf.recipe_receipt()
        self.assertEqual(uniperf.catalog_recipes()[0], recipe)
        self.assertEqual(uniperf.receipt(data), recipe)
        self.assertEqual(recipe['path'], uniperf.PATH)
        self.assertEqual(recipe['absent_hal'], uniperf.HAL)
        output = bytearray(data)
        for site in recipe['sites']:
            offset = site['offset']
            before, after = bytes.fromhex(site['before']), bytes.fromhex(site['after'])
            self.assertEqual(len(before), len(after))
            self.assertEqual(output[offset:offset + len(before)], before)
            output[offset:offset + len(after)] = after
        self.assertEqual(hashlib.sha256(output).hexdigest(), uniperf.AFTER)
        self.assertEqual(uniperf.receipt(output), recipe)
        self.assertEqual(recipe['methods'], [uniperf.METHOD])

    def test_unknown_tampered_signed_or_partial_content_is_never_patched(self):
        data = self.artifact()
        for position in (0, 14, uniperf.DEX_OFFSET + 8, uniperf.DEX_OFFSET + uniperf.CODE_OFFSET + 16,
                         len(data) - 1):
            modified = bytearray(data)
            modified[position] ^= 1
            with self.subTest(position=position), self.assertRaisesRegex(RuntimeError, 'Unsupported'):
                uniperf.patch_bytes(modified)
        with self.assertRaises(RuntimeError):
            uniperf.patch_bytes(data + b'APK Sig Block 42')
        offset, _, after = uniperf.SITES[2]
        partial = bytearray(data)
        partial[offset:offset + 6] = bytes.fromhex(after)
        with self.assertRaises(RuntimeError):
            uniperf.patch_bytes(partial)
        with self.assertRaises(RuntimeError):
            uniperf.recipe_receipt('unknown input')

    def test_atomic_output_preserves_factory_unknown_content_and_aliases(self):
        data = self.artifact()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, output = root / 'factory.jar', root / 'gated.jar'
            source.write_bytes(data)
            uniperf.patch(source, output)
            inode = output.stat().st_ino
            uniperf.patch(source, output)
            self.assertEqual(output.stat().st_ino, inode)
            self.assertEqual(source.read_bytes(), data)
            with self.assertRaises(RuntimeError):
                uniperf.patch(source, source)
            alias = root / 'alias.jar'
            alias.symlink_to(output)
            with self.assertRaises(RuntimeError):
                uniperf.patch(source, alias)
            output.write_bytes(b'custom state')
            with self.assertRaisesRegex(RuntimeError, 'unknown'):
                uniperf.patch(source, output)
            self.assertEqual(output.read_bytes(), b'custom state')
            self.assertFalse(list(root.glob('.uniperf-*')))

    def test_racing_output_is_preserved_without_partial_temporary_leaves(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, output = root / 'factory.jar', root / 'gated.jar'
            source.write_bytes(self.artifact())

            def race(*_):
                output.write_bytes(b'user content')
                raise FileExistsError()

            with patch.object(uniperf.os, 'link', side_effect=race), self.assertRaises(RuntimeError):
                uniperf.patch(source, output)
            self.assertEqual(output.read_bytes(), b'user content')
            self.assertFalse(list(root.glob('.uniperf-*')))


class SystemServerUniperfPatchTests(unittest.TestCase):
    def artifacts(self):
        result = []
        for form in ('phone', 'pad'):
            default = (REPO / 'work/feedback-investigation-20261013' /
                       (form + '-uniperf-loaded-caller') / 'miui-services.jar')
            path = Path(os.environ.get('HYPEROS_AVD_' + form.upper() + '_UNIPERF_SERVICES', str(default)))
            if not path.is_file():
                self.skipTest('Audited proprietary system-server JARs are not distributed in Git.')
            data = path.read_bytes()
            before, rule, patched = uniperf.select_recipe(data)
            self.assertFalse(patched)
            self.assertEqual(rule['path'], uniperf.MIUI_SERVICES)
            result.append((form, before, rule, data))
        return result

    def test_loaded_copies_patch_exactly_and_repeat_without_touching_other_archive_bytes(self):
        for form, before, rule, data in self.artifacts():
            with self.subTest(form=form):
                output = uniperf.patch_bytes(data)
                self.assertEqual(hashlib.sha256(output).hexdigest(), rule['after'])
                self.assertEqual(uniperf.patch_bytes(output), output)
                self.assertFalse(uniperf.audit(data))
                self.assertTrue(uniperf.audit(output))
                self.assertEqual(len(output), len(data))
                start = 0
                for offset, old, new in rule['sites']:
                    self.assertEqual(data[start:offset], output[start:offset])
                    self.assertEqual(data[offset:offset + len(bytes.fromhex(old))], bytes.fromhex(old))
                    self.assertEqual(output[offset:offset + len(bytes.fromhex(new))], bytes.fromhex(new))
                    start = offset + len(bytes.fromhex(old))
                self.assertEqual(data[start:], output[start:])
                self.assertEqual(sum(len(bytes.fromhex(site[1])) for site in rule['sites']), 38)
                self.assertEqual(uniperf.receipt(output), uniperf.recipe_receipt(before))

    def test_embedded_public_static_boolean_stops_before_lock_preserving_try_debug_and_all_other_code(self):
        for form, _, rule, data in self.artifacts():
            with self.subTest(form=form):
                output = uniperf.patch_bytes(data)
                offset, size = rule['dex_offset'], rule['dex_size']
                old, new = data[offset:offset + size], output[offset:offset + size]
                code = uniperf._method(old, rule['code_offset'])
                self.assertEqual(uniperf._method(new, code), code)
                self.assertEqual(struct.unpack_from('<4H2I', new, code), rule['code_header'])
                self.assertEqual(old[32:code + 16], new[32:code + 16])
                self.assertEqual(old[code + 22:], new[code + 22:])
                self.assertEqual(old[code + 16:code + 22].hex(), rule['original'])
                self.assertEqual(struct.unpack_from('<3H', new, code + 16), (0x12, 0xf, 0))
                self.assertEqual(old[code + 22:code + 26], new[code + 22:code + 26])
                self.assertEqual(new[12:32], hashlib.sha1(new[32:]).digest())
                self.assertEqual(struct.unpack_from('<I', new, 8)[0], zlib.adler32(new[12:]) & 0xffffffff)
                self.assertIn(uniperf.HAL.encode() + b'\0', new)

    def test_multidex_and_compressed_metadata_are_preserved_with_valid_selected_member_crc(self):
        for form, _, rule, data in self.artifacts():
            with self.subTest(form=form):
                output = uniperf.patch_bytes(data)
                with zipfile.ZipFile(io.BytesIO(data)) as before, zipfile.ZipFile(io.BytesIO(output)) as after:
                    self.assertIsNone(after.testzip())
                    self.assertEqual(before.namelist(), after.namelist())
                    self.assertEqual(len(before.infolist()), rule['count'])
                    self.assertEqual(before.getinfo(rule['member']).compress_type, zipfile.ZIP_STORED)
                    self.assertTrue(any(item.compress_type == zipfile.ZIP_DEFLATED for item in before.infolist()))
                    for old, new in zip(before.infolist(), after.infolist()):
                        for attribute in ('filename', 'compress_type', 'header_offset', 'file_size',
                                          'compress_size', 'flag_bits', 'date_time', 'extra', 'comment',
                                          'external_attr', 'internal_attr'):
                            self.assertEqual(getattr(old, attribute), getattr(new, attribute))
                        if old.filename != rule['member']:
                            self.assertEqual(old.CRC, new.CRC)
                            self.assertEqual(before.read(old.filename), after.read(new.filename))
                    self.assertEqual(hashlib.sha256(after.read(rule['member'])).hexdigest(), rule['dex_after'])

    def test_canonical_offline_sites_cover_both_boot_artifacts_without_changing_legacy_receipt(self):
        from patch_boot_services import AFTER as boot_after
        self.assertIn(boot_after['miui-services'], uniperf.RECIPES)
        rows = uniperf.catalog_recipes()
        self.assertEqual(len(rows), 3)
        legacy = uniperf.recipe_receipt()
        self.assertEqual(legacy['before'], uniperf.BEFORE)
        self.assertEqual(legacy['after'], uniperf.AFTER)
        self.assertEqual(legacy['sites'], [
            {'offset': offset, 'before': old, 'after': new,
             **({'method': uniperf.METHOD} if index == 2 else {})}
            for index, (offset, old, new) in enumerate(uniperf.SITES)])
        # Frozen Core 10 authenticates this complete standalone recipe.
        fixture = json.loads((REPO / 'tests/fixtures/native-compat-v10-final-manifest.json').read_text())
        for index, site in enumerate(legacy['sites']):
            for state in ('before', 'after'):
                key = 'sites/uniperf-d002c55e9b66/%03d.%s' % (index, state)
                self.assertEqual(hashlib.sha256(bytes.fromhex(site[state])).hexdigest(),
                                 fixture['files_sha256'][key])
        for form, digest, _, data in self.artifacts():
            with self.subTest(form=form):
                recipe = uniperf.recipe_receipt(digest)
                output = bytearray(data)
                for site in recipe['sites']:
                    offset = site['offset']
                    old, new = bytes.fromhex(site['before']), bytes.fromhex(site['after'])
                    self.assertEqual(len(old), len(new))
                    self.assertEqual(output[offset:offset + len(old)], old)
                    output[offset:offset + len(new)] = new
                self.assertEqual(hashlib.sha256(output).hexdigest(), recipe['after'])
                self.assertEqual(recipe['methods'], [uniperf.METHOD])

    def test_unknown_partial_checksum_or_boot_derivatives_are_retained(self):
        for form, _, rule, data in self.artifacts():
            with self.subTest(form=form):
                for site in rule['sites']:
                    offset, _, new = site
                    partial = bytearray(data)
                    partial[offset:offset + len(bytes.fromhex(new))] = bytes.fromhex(new)
                    with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
                        uniperf.patch_bytes(partial)
                # An unrelated boot-services edit must not be treated as this known input.
                unknown = bytearray(data)
                unknown[45] ^= 1
                with self.assertRaises(RuntimeError):
                    uniperf.patch_bytes(unknown)
                with self.assertRaises(RuntimeError):
                    uniperf.patch_bytes(data + b'APK Sig Block 42')

    def test_layout_explicitly_refuses_compressed_signed_or_descriptor_selected_dex(self):
        for compression, name in ((zipfile.ZIP_DEFLATED, 'README.txt'),
                                  (zipfile.ZIP_STORED, 'META-INF/factory.RSA')):
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, 'w') as archive:
                archive.writestr('classes2.dex', b'dex placeholder', compress_type=compression)
                archive.writestr(name, b'unchanged metadata')
            with self.assertRaises(RuntimeError):
                uniperf._stored_dex_layout(stream.getvalue(), 'classes2.dex', 2)
        for form, _, rule, data in self.artifacts():
            with self.subTest(form=form):
                altered = bytearray(data)
                local = rule['sites'][0][0] - 14
                directory = rule['sites'][3][0] - 16
                struct.pack_into('<H', altered, local + 6, 8)
                struct.pack_into('<H', altered, directory + 8, 8)
                with self.assertRaisesRegex(RuntimeError, 'storage'):
                    uniperf._stored_dex_layout(altered, rule['member'], rule['count'])


if __name__ == '__main__':
    unittest.main()
