"""Guard the vendor-only IMS entry and preserve the remaining unsigned JAR."""
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
import patch_xiaomi_ims as ims


def actual_input():
    path = Path(os.environ.get('HYPEROS_AVD_IMS_FRAMEWORK_ARTIFACT', str(
        ROOT / 'work/feedback-investigation-20261013/vendor-ims-caller-audit/pad-xiaomi-opt-ims.jar')))
    if path.is_file():
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() == ims.BEFORE:
            return data
    return None


class ReceiptTests(unittest.TestCase):
    def test_one_vendor_only_void_entry_has_four_equal_length_sites(self):
        receipt = ims.recipe_receipt()
        self.assertEqual(ims.catalog_recipes(), (receipt,))
        self.assertEqual(receipt['path'], '/system_ext/framework/xiaomi-opt-ims.jar')
        self.assertEqual(receipt['methods'], ['Lcom/xiaomi/ims/internal/XmImsConnector;->connect()V'])
        self.assertEqual(receipt['format'], 'framework-jar')
        self.assertEqual(receipt['requires'], 'ranchu-without-proprietary-ims')
        self.assertEqual(len(receipt['sites']), 4)
        entry = next(site for site in receipt['sites'] if 'method' in site)
        self.assertEqual(entry, {'offset': ims.ENTRY[0], 'before': ims.ENTRY[1],
                                 'after': '0e000000', 'method': ims.METHOD})
        previous = 0
        for site in receipt['sites']:
            self.assertGreaterEqual(site['offset'], previous)
            self.assertEqual(len(site['before']), len(site['after']))
            self.assertNotEqual(site['before'], site['after'])
            previous = site['offset'] + len(bytes.fromhex(site['before']))
            self.assertLessEqual(previous, receipt['size'])
        receipt['sites'].clear()
        self.assertEqual(len(ims.recipe_receipt()['sites']), 4)

    def test_unknown_or_signed_content_never_creates_an_output(self):
        for data in (b'', b'PK\x03\x04', b'unknown signed APK'):
            with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
                ims.patch_bytes(data)
        with self.assertRaises(RuntimeError):
            ims.recipe_receipt(ims.AFTER)
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / 'unknown.jar', Path(directory) / 'absent/derivative.jar'
            source.write_bytes(b'unknown customized framework')
            with self.assertRaises(RuntimeError):
                ims.patch(source, output)
            self.assertFalse(output.parent.exists())
            self.assertEqual(source.read_bytes(), b'unknown customized framework')


class AuditedInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = actual_input()
        if cls.original is None:
            raise unittest.SkipTest('Private audited IMS JAR unavailable; no download attempted.')

    def test_full_audit_idempotence_and_canonical_sites_agree(self):
        original = self.original
        self.assertFalse(ims.audit(original))
        output = ims.patch_bytes(original)
        self.assertTrue(ims.audit(output))
        self.assertEqual(hashlib.sha256(output).hexdigest(), ims.AFTER)
        self.assertEqual(ims.patch_bytes(output), output)
        self.assertEqual(ims.patch_bytes(original), output)
        self.assertEqual(ims.receipt(original), ims.recipe_receipt())
        with self.assertRaisesRegex(RuntimeError, 'original input'):
            ims.receipt(output)
        replay = bytearray(original)
        for site in ims.recipe_receipt()['sites']:
            offset = site['offset']
            before, after = bytes.fromhex(site['before']), bytes.fromhex(site['after'])
            self.assertEqual(replay[offset:offset + len(before)], before)
            replay[offset:offset + len(after)] = after
        self.assertEqual(bytes(replay), output)

    def test_every_other_byte_zip_entry_and_method_instruction_is_preserved(self):
        original, output = self.original, ims.patch_bytes(self.original)
        cursor = 0
        for site in ims.recipe_receipt()['sites']:
            self.assertEqual(original[cursor:site['offset']], output[cursor:site['offset']])
            cursor = site['offset'] + len(bytes.fromhex(site['before']))
        self.assertEqual(original[cursor:], output[cursor:])
        self.assertEqual(len(original), len(output))
        with zipfile.ZipFile(io.BytesIO(original)) as a, zipfile.ZipFile(io.BytesIO(output)) as b:
            self.assertIsNone(b.testzip())
            self.assertEqual(a.namelist(), ['classes.dex', 'META-INF/MANIFEST.MF'])
            self.assertEqual(a.namelist(), b.namelist())
            self.assertEqual(a.read('META-INF/MANIFEST.MF'), b.read('META-INF/MANIFEST.MF'))
            first, changed = a.read('classes.dex'), b.read('classes.dex')
            self.assertEqual(ims._method(first), ims._method(changed))
            self.assertEqual(first[:8], changed[:8])
            self.assertEqual(first[32:ims.CODE_OFFSET + 16], changed[32:ims.CODE_OFFSET + 16])
            self.assertEqual(changed[ims.CODE_OFFSET + 16:ims.CODE_OFFSET + 20], bytes.fromhex('0e000000'))
            self.assertEqual(first[ims.CODE_OFFSET + 20:], changed[ims.CODE_OFFSET + 20:])
            self.assertEqual(changed[12:32], hashlib.sha1(changed[32:]).digest())
            self.assertEqual(struct.unpack_from('<I', changed, 8)[0], zlib.adler32(changed[12:]) & 0xffffffff)
            for x, y in zip(a.infolist(), b.infolist()):
                for attribute in ('filename', 'date_time', 'compress_type', 'flag_bits', 'extra',
                                  'comment', 'file_size', 'compress_size', 'external_attr',
                                  'header_offset', 'create_system', 'create_version'):
                    self.assertEqual(getattr(x, attribute), getattr(y, attribute))

    def test_tampered_code_tables_headers_and_signed_archives_are_rejected(self):
        for offset in (ims.ENTRY[0], ims.DEX_OFFSET + ims.CODE_OFFSET,
                       ims.DEX_OFFSET + 96, len(self.original) - 1):
            data = bytearray(self.original); data[offset] ^= 1
            with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
                ims.patch_bytes(bytes(data))
        with zipfile.ZipFile(io.BytesIO(self.original)) as archive:
            signed = io.BytesIO()
            with zipfile.ZipFile(signed, 'w') as output:
                for name in archive.namelist():
                    output.writestr(name, archive.read(name))
                output.writestr('META-INF/CERT.SF', b'signed archive')
        with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
            ims.patch_bytes(signed.getvalue())

    def test_existing_output_keeps_inodes_and_unknown_aliases_or_races_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output, other = [Path(directory) / name for name in ('original.jar', 'derived.jar', 'other')]
            source.write_bytes(self.original)
            ims.patch(source, output); identity = output.stat().st_ino, output.stat().st_mtime_ns
            ims.patch(source, output)
            self.assertEqual((output.stat().st_ino, output.stat().st_mtime_ns), identity)
            self.assertEqual(source.read_bytes(), self.original)
            with self.assertRaises(RuntimeError):
                ims.patch(source, source)
            output.write_bytes(b'custom derivative')
            with self.assertRaises(RuntimeError):
                ims.patch(source, output)
            self.assertEqual(output.read_bytes(), b'custom derivative')
            output.unlink(); other.write_bytes(ims.patch_bytes(self.original)); output.symlink_to(other)
            with self.assertRaises(RuntimeError):
                ims.patch(source, output)
            self.assertTrue(output.is_symlink())
            output.unlink(); os.link(other, output)
            with self.assertRaises(RuntimeError):
                ims.patch(source, output)
            self.assertEqual(output.stat().st_nlink, 2)
            output.unlink()

            def occupied(_source, destination):
                Path(destination).write_bytes(b'new user output')
                raise FileExistsError()

            with mock.patch.object(ims.os, 'link', side_effect=occupied), self.assertRaises(RuntimeError):
                ims.patch(source, output)
            self.assertEqual(output.read_bytes(), b'new user output')
            self.assertFalse(list(Path(directory).glob('.ims-connector-*')))


if __name__ == '__main__':
    unittest.main()
