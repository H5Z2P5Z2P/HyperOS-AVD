"""Content and byte-preservation checks for the physical WLAN capability gates."""
import hashlib
import io
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock
import zipfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import patch_wifi_capabilities as wifi


SOURCES = (
    ROOT / 'work/feedback-investigation-20261013/phone-wifi-service.jar',
    ROOT / 'work/feedback-investigation-20261013/pad-producer-audit/miui-wifi-service.jar',
)


def actual_sources():
    found = {}
    for path in SOURCES:
        if path.is_file():
            data = path.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            if digest in wifi.RECIPES:
                found[digest] = data
    return found


class CatalogTests(unittest.TestCase):
    def test_canonical_receipts_have_only_audited_capability_methods(self):
        receipts = wifi.catalog_recipes()
        self.assertEqual(len(receipts), 2)
        for receipt in receipts:
            self.assertEqual(receipt['path'], wifi.PATH)
            self.assertEqual(receipt['format'], 'framework-jar')
            self.assertEqual(receipt['methods'], list(wifi.METHODS))
            self.assertNotIn('isWifiSarNeeded', '\n'.join(receipt['methods']))
            self.assertEqual(receipt['requires'], 'ranchu-without-proprietary-wlan-sar')
            self.assertEqual(len(receipt['sites']), 6)
            previous = 0
            for site in receipt['sites']:
                self.assertGreaterEqual(site['offset'], previous)
                original, changed = bytes.fromhex(site['before']), bytes.fromhex(site['after'])
                self.assertEqual(len(original), len(changed))
                self.assertNotEqual(original, changed)
                previous = site['offset'] + len(original)
                self.assertLessEqual(previous, receipt['size'])
                if 'method' in site:
                    self.assertEqual(changed[:4], wifi.FALSE_RETURN)
                    self.assertEqual(set(changed[4:]), {0})

    def test_receipts_are_independent_and_do_not_mutate_constants(self):
        first = wifi.catalog_recipes()
        first[0]['sites'][0]['before'] = '00'
        first[0]['methods'].clear()
        second = wifi.catalog_recipes()
        self.assertNotEqual(second[0]['sites'][0]['before'], '00')
        self.assertEqual(second[0]['methods'], list(wifi.METHODS))

    def test_unknown_or_tampered_input_refuses_before_output_creation(self):
        for data in (b'', b'PK\x03\x04', b'fake framework.jar'):
            with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
                wifi.patch_bytes(data)
        for value in (None, True, 1, [], 'unknown'):
            with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
                wifi.select_recipe(value)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'factory.jar'
            target = Path(directory) / 'absent/output.jar'
            source.write_bytes(b'unknown custom content')
            with self.assertRaises(RuntimeError):
                wifi.patch(source, target)
            self.assertEqual(source.read_bytes(), b'unknown custom content')
            self.assertFalse(target.parent.exists())

    def test_unknown_receipt_cannot_reuse_an_output_identity(self):
        for recipe in wifi.RECIPES.values():
            with self.assertRaises(RuntimeError):
                wifi.recipe_receipt(recipe['after'])


class AuditedInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources = actual_sources()
        if not cls.sources:
            raise unittest.SkipTest('Audited private JAR inputs unavailable; no download attempted.')

    def test_repeat_is_exact_and_byte_sites_reproduce_derivative(self):
        for before, data in self.sources.items():
            with self.subTest(before=before):
                receipt = wifi.receipt(data)
                output = wifi.patch_bytes(data)
                self.assertEqual(hashlib.sha256(output).hexdigest(), receipt['after'])
                self.assertEqual(wifi.patch_bytes(output), output)
                self.assertEqual(wifi.patch_bytes(data), output)
                replay = bytearray(data)
                for site in receipt['sites']:
                    offset = site['offset']
                    original, changed = bytes.fromhex(site['before']), bytes.fromhex(site['after'])
                    self.assertEqual(replay[offset:offset + len(original)], original)
                    replay[offset:offset + len(changed)] = changed
                self.assertEqual(bytes(replay), output)
                with self.assertRaisesRegex(RuntimeError, 'original input'):
                    wifi.receipt(output)

    def test_every_other_byte_and_zip_entry_remains_unchanged(self):
        for before, data in self.sources.items():
            with self.subTest(before=before):
                output = wifi.patch_bytes(data)
                sites = wifi.recipe_receipt(before)['sites']
                cursor = 0
                for site in sites:
                    self.assertEqual(data[cursor:site['offset']], output[cursor:site['offset']])
                    cursor = site['offset'] + len(bytes.fromhex(site['before']))
                self.assertEqual(data[cursor:], output[cursor:])
                self.assertEqual(len(data), len(output))
                with zipfile.ZipFile(io.BytesIO(data)) as original, zipfile.ZipFile(io.BytesIO(output)) as changed:
                    self.assertIsNone(changed.testzip())
                    self.assertEqual(original.namelist(), ['classes.dex', 'META-INF/MANIFEST.MF'])
                    self.assertEqual(original.namelist(), changed.namelist())
                    self.assertEqual(original.read('META-INF/MANIFEST.MF'), changed.read('META-INF/MANIFEST.MF'))
                    for a, b in zip(original.infolist(), changed.infolist()):
                        for attribute in ('filename', 'date_time', 'compress_type', 'flag_bits', 'extra',
                                          'comment', 'file_size', 'compress_size', 'external_attr',
                                          'internal_attr', 'header_offset', 'create_system', 'create_version'):
                            self.assertEqual(getattr(a, attribute), getattr(b, attribute), attribute)

    def test_dex_checksums_tables_headers_and_only_three_bodies(self):
        for before, data in self.sources.items():
            with self.subTest(before=before):
                output = wifi.patch_bytes(data)
                recipe = wifi.RECIPES[before]
                start, length, _, _ = wifi._zip_layout(data)
                original, changed = data[start:start + length], output[start:start + length]
                self.assertEqual(wifi._dex_methods(original), wifi._dex_methods(changed))
                self.assertEqual(changed[:8], original[:8])
                self.assertEqual(changed[12:32], hashlib.sha1(changed[32:]).digest())
                self.assertEqual(struct.unpack_from('<I', changed, 8)[0], zlib.adler32(changed[12:]) & 0xffffffff)
                cursor = 32
                for code, _, header, _ in recipe['methods']:
                    self.assertEqual(original[cursor:code + 16], changed[cursor:code + 16])
                    size = 2 * header[5]
                    self.assertEqual(changed[code + 16:code + 20], wifi.FALSE_RETURN)
                    self.assertEqual(changed[code + 20:code + 16 + size], b'\0' * (size - 4))
                    cursor = code + 16 + size
                self.assertEqual(original[cursor:], changed[cursor:])

    def test_target_method_guard_rejects_code_header_or_body_tampering(self):
        for before, data in self.sources.items():
            recipe = wifi.RECIPES[before]
            start, length, local_crc, central_crc = wifi._zip_layout(data)
            for relative in (recipe['methods'][0][0], recipe['methods'][0][0] + 16):
                altered = bytearray(data)
                altered[start + relative] ^= 1
                dex = bytearray(altered[start:start + length])
                dex[12:32] = hashlib.sha1(dex[32:]).digest()
                struct.pack_into('<I', dex, 8, zlib.adler32(dex[12:]) & 0xffffffff)
                altered[start:start + length] = dex
                for offset in (local_crc, central_crc):
                    struct.pack_into('<I', altered, offset, zlib.crc32(dex) & 0xffffffff)
                with self.assertRaises(RuntimeError):
                    wifi.patch_bytes(bytes(altered))
                with self.assertRaisesRegex(RuntimeError, 'DEX content'):
                    wifi._rewrite(bytes(altered), recipe)

    def test_repeated_output_preserves_inode_and_factory_input(self):
        before, data = next(iter(self.sources.items()))
        with tempfile.TemporaryDirectory() as directory:
            source, target = Path(directory) / 'factory.jar', Path(directory) / 'patched.jar'
            source.write_bytes(data)
            wifi.patch(source, target)
            initial = target.stat()
            wifi.patch(source, target)
            self.assertEqual((target.stat().st_ino, target.stat().st_mtime_ns),
                             (initial.st_ino, initial.st_mtime_ns))
            self.assertEqual(source.read_bytes(), data)
            self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), wifi.RECIPES[before]['after'])
            with self.assertRaisesRegex(RuntimeError, 'separate'):
                wifi.patch(source, source)

    def test_unknown_existing_output_symlink_and_hardlink_are_preserved(self):
        data = next(iter(self.sources.values()))
        with tempfile.TemporaryDirectory() as directory:
            source, target, other = [Path(directory) / name for name in ('factory.jar', 'patched.jar', 'other')]
            source.write_bytes(data)
            target.write_bytes(b'custom output')
            with self.assertRaises(RuntimeError):
                wifi.patch(source, target)
            self.assertEqual(target.read_bytes(), b'custom output')
            target.unlink()
            other.write_bytes(wifi.patch_bytes(data))
            target.symlink_to(other)
            with self.assertRaises(RuntimeError):
                wifi.patch(source, target)
            self.assertTrue(target.is_symlink())
            target.unlink()
            os.link(other, target)
            with self.assertRaises(RuntimeError):
                wifi.patch(source, target)
            self.assertEqual(target.stat().st_nlink, 2)

    def test_racing_unknown_output_is_not_overwritten(self):
        data = next(iter(self.sources.values()))
        with tempfile.TemporaryDirectory() as directory:
            source, target = Path(directory) / 'factory.jar', Path(directory) / 'patched.jar'
            source.write_bytes(data)

            def occupied(_source, destination):
                Path(destination).write_bytes(b'new user output')
                raise FileExistsError()

            with mock.patch.object(wifi.os, 'link', side_effect=occupied):
                with self.assertRaises(RuntimeError):
                    wifi.patch(source, target)
            self.assertEqual(target.read_bytes(), b'new user output')
            self.assertFalse(list(Path(directory).glob('.wifi-capabilities-*')))


if __name__ == '__main__':
    unittest.main()
