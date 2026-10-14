"""Preserve the XRING client's original missing-HAL ABI without Binder retries."""
import hashlib
import io
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import zipfile
import zlib

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'scripts'))
import patch_perfflinger as producer


class PerfFlingerPatchTests(unittest.TestCase):
    def artifact(self):
        path = Path(os.environ.get('HYPEROS_AVD_PERFFLINGER_ARTIFACT', str(REPO /
            'work/feedback-investigation-20261014/final-audit/remaining-capability-audit/pad-PerfFlingerClient.jar')))
        if not path.is_file():
            self.skipTest('Audited proprietary unsigned framework is not distributed in Git.')
        return path.read_bytes()

    def test_exact_idempotent_derivative_and_only_declared_sites_change(self):
        source = self.artifact(); output = producer.patch_bytes(source)
        self.assertFalse(producer.audit(source)); self.assertTrue(producer.audit(output))
        self.assertEqual(hashlib.sha256(output).hexdigest(), producer.AFTER)
        self.assertEqual(producer.patch_bytes(output), output)
        self.assertEqual(len(source), len(output))
        allowed = {offset+i for offset, old, _ in producer.SITES for i in range(len(bytes.fromhex(old)))}
        self.assertLessEqual({i for i, (a, b) in enumerate(zip(source, output)) if a != b}, allowed)
        self.assertEqual(len(producer.SITES), 5)

    def test_entry_prefixes_cover_complete_instructions_and_preserve_return_abi(self):
        # Getter: CONST/4 + SGET_OBJECT, replaced by false/return/NOP.
        self.assertEqual(producer.CODE[0][-2:], ('120062010700', '12000f000000'))
        # Hint: INVOKE_STATIC + MOVE_RESULT, replaced by wide -1/return/NOP.
        # Covering MOVE_RESULT avoids stranding an unmatched result opcode.
        self.assertEqual(producer.CODE[1][-2:], ('71002e0000000a00', '1600ffff10000000'))
        self.assertEqual(struct.unpack('<4H', bytes.fromhex(producer.CODE[1][-1])), (0x16, 0xffff, 0x10, 0))
        self.assertEqual([row[1] for row in producer.CODE], [9, 1])
        self.assertEqual([row[3][:3] for row in producer.CODE], [(7, 0, 3), (19, 6, 9)])

    def test_all_other_code_tables_debug_and_exception_handlers_are_preserved(self):
        source = self.artifact(); output = producer.patch_bytes(source)
        start, size = producer.DEX_OFFSET, producer.DEX_SIZE
        old, new = source[start:start+size], output[start:start+size]
        self.assertEqual(producer._methods(old), producer._methods(new))
        allowed = set(range(8, 32))
        for _, _, offset, header, *_, before, after in producer.CODE:
            self.assertEqual(struct.unpack_from('<4H2I', new, offset), header)
            body_end = offset+16+header[5]*2
            handler_start = (body_end+3)&~3
            self.assertEqual(old[handler_start:handler_start+header[3]*8], new[handler_start:handler_start+header[3]*8])
            allowed.update(range(offset+16, offset+16+len(bytes.fromhex(before))))
        self.assertLessEqual({i for i, (a, b) in enumerate(zip(old, new)) if a != b}, allowed)
        self.assertIn(producer.HAL.encode()+b'\0', new)

    def test_archive_and_dex_checksums_remain_valid_without_repacking(self):
        source = self.artifact(); output = producer.patch_bytes(source)
        with zipfile.ZipFile(io.BytesIO(source)) as before, zipfile.ZipFile(io.BytesIO(output)) as after:
            self.assertIsNone(after.testzip()); self.assertEqual(before.namelist(), after.namelist())
            self.assertEqual(before.read('META-INF/MANIFEST.MF'), after.read('META-INF/MANIFEST.MF'))
            for a, b in zip(before.infolist(), after.infolist()):
                for key in ('filename', 'header_offset', 'flag_bits', 'compress_type', 'file_size',
                            'compress_size', 'date_time', 'extra', 'comment', 'external_attr', 'internal_attr'):
                    self.assertEqual(getattr(a, key), getattr(b, key))
            dex = after.read('classes.dex')
        self.assertEqual(hashlib.sha256(dex).hexdigest(), producer.DEX_AFTER)
        self.assertEqual(dex[12:32], hashlib.sha1(dex[32:]).digest())
        self.assertEqual(struct.unpack_from('<I', dex, 8)[0], zlib.adler32(dex[12:])&0xffffffff)
        self.assertNotIn(b'APK Sig Block 42', output)

    def test_unknown_or_corrupt_content_is_not_admitted(self):
        source = self.artifact()
        for offset in (0, 14, 52, producer.SITES[2][0], producer.SITES[3][0], len(source)-1):
            with self.subTest(offset=offset):
                value = bytearray(source); value[offset] ^= 1
                with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
                    producer.patch_bytes(value)
        for value in (b'', b'custom framework', source+b'x'):
            with self.assertRaises(RuntimeError): producer.patch_bytes(value)

    def test_offline_receipt_has_exact_hardware_requirement_and_canonical_sites(self):
        receipt = producer.recipe_receipt()
        self.assertEqual(receipt['path'], producer.PATH)
        self.assertEqual(receipt['requires'], 'ranchu-without-physical-perfflinger')
        self.assertEqual(receipt['absent_hal'], producer.HAL)
        self.assertEqual(receipt['methods'], list(producer.METHODS))
        self.assertEqual(producer.catalog_recipes(), (receipt,))
        self.assertEqual([(x['offset'], x['before'], x['after']) for x in receipt['sites']], list(producer.SITES))
        with self.assertRaises(RuntimeError): producer.recipe_receipt('0'*64)

    def test_inplace_unknown_outputs_aliases_and_hardlinks_are_preserved(self):
        source = self.artifact()
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp); original = folder/'source.jar'; original.write_bytes(source)
            output = folder/'patched.jar'; producer.patch(original, output)
            self.assertEqual(producer.patch(original, output), output)
            with self.assertRaises(RuntimeError): producer.patch(original, original)
            self.assertEqual(original.read_bytes(), source)
            output.write_bytes(b'User customized output')
            with self.assertRaises(RuntimeError): producer.patch(original, output)
            self.assertEqual(output.read_bytes(), b'User customized output')
            output.unlink(); output.symlink_to(original)
            with self.assertRaises(RuntimeError): producer.patch(original, output)
            self.assertEqual(original.read_bytes(), source)
            output.unlink(); output.write_bytes(producer.patch_bytes(source)); os.link(output, folder/'hardlink')
            with self.assertRaises(RuntimeError): producer.patch(original, output)
            self.assertEqual(output.read_bytes(), producer.patch_bytes(source))
