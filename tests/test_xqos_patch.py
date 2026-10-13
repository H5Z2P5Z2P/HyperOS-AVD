"""Audit the narrow physical XQos failure paths with optional donor ELFs."""
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
import patch_xqos as xqos
from patch_rear_display import _sections


class XQosPatchTests(unittest.TestCase):
    def artifacts(self):
        paths = [Path(os.environ.get('HYPEROS_AVD_XQOS_' + name.upper(), str(
            REPO / 'work/feedback-investigation-20261013' / (name + '-libxqos.so'))))
                 for name in ('phone', 'pad')]
        if not all(path.is_file() for path in paths):
            self.skipTest('Audited proprietary XQos ELFs are not distributed in Git.')
        return [path.read_bytes() for path in paths]

    def test_both_real_derivatives_change_only_seven_local_initialize_calls(self):
        for data in self.artifacts():
            before, recipe, already = xqos.audit(data)
            with self.subTest(before=before):
                self.assertFalse(already)
                result = xqos.patch_bytes(data)
                self.assertEqual(hashlib.sha256(result).hexdigest(), recipe['after'])
                self.assertEqual(xqos.patch_bytes(result), result)
                self.assertTrue(xqos.audit(result)[2])
                self.assertEqual(len(result), len(data))
                positions = {f['site'] + index for f in recipe['functions'] for index in range(4)}
                self.assertEqual(len(positions), 28)
                changed = {index for index, (old, new) in enumerate(zip(data, result)) if old != new}
                self.assertEqual(len(changed), 26)
                self.assertLessEqual(changed, positions)
                for function in recipe['functions']:
                    site = function['site']
                    old, = struct.unpack_from('<I', data, site)
                    new, = struct.unpack_from('<I', result, site)
                    self.assertEqual(old >> 26, 0x25)  # BL local initialize.
                    self.assertEqual(new >> 26, 0x05)  # B existing failure tail.
                    self.assertEqual(xqos._branch_target(old, site), recipe['initialize'][0])
                    self.assertEqual(xqos._branch_target(new, site), function['target'])
                    start, end = function['address'], function['address'] + function['size']
                    self.assertEqual(data[start:site], result[start:site])
                    self.assertEqual(data[site + 4:end], result[site + 4:end])

    def test_original_failure_values_frames_canaries_and_pac_are_preserved(self):
        for data in self.artifacts():
            _, recipe, _ = xqos.audit(data)
            result = xqos.patch_bytes(data)
            for function in recipe['functions']:
                with self.subTest(symbol=function['symbol'], pac=recipe['pac']):
                    value = -1 if function['symbol'].startswith('get') else 0
                    self.assertEqual(function['return'], value)
                    target = function['target']
                    expected = bytes.fromhex('00008012' if value == -1 else 'e0031f2a')
                    self.assertEqual(result[target:target + 4], expected)
                    epilogue = bytes.fromhex(function['epilogue'])
                    self.assertEqual(result[target:target + len(epilogue)], epilogue)
                    self.assertTrue(epilogue.endswith(bytes.fromhex('c0035fd6')))
                    if recipe['pac']:
                        start = function['address']
                        self.assertEqual(result[start:start + 4], bytes.fromhex('3f2303d5'))
                        self.assertTrue(epilogue.endswith(bytes.fromhex('bf2303d5c0035fd6')))
                    else:
                        # All Pad failure tails keep their TLS stack-cookie check.
                        self.assertIn(bytes.fromhex('e90740f9'), epilogue)
                        self.assertIn(bytes.fromhex('1f0109eb'), epilogue)

    def test_all_elf_metadata_relocations_logs_and_initializer_are_unchanged(self):
        for data in self.artifacts():
            _, recipe, _ = xqos.audit(data)
            result = xqos.patch_bytes(data)
            _, sections = _sections(data)
            for name, section in sections.items():
                if name == b'.text' or section[1] == 8:
                    continue
                with self.subTest(section=name):
                    offset, size = section[4:6]
                    self.assertEqual(data[offset:offset + size], result[offset:offset + size])
            address, size, digest = recipe['initialize']
            self.assertEqual(hashlib.sha256(result[address:address + size]).hexdigest(), digest)
            self.assertIn(b'__android_log_print\0', result)
            self.assertIn(b'ioctl\0', result)
            for node in xqos.ABSENT_NODES:
                self.assertIn(node.encode() + b'\0', result)

    def test_offline_catalog_sites_reproduce_exact_derivatives(self):
        self.assertEqual(len(xqos.catalog_recipes()), 2)
        for data in self.artifacts():
            receipt = xqos.receipt(data)
            self.assertEqual(receipt, xqos.recipe_receipt(hashlib.sha256(data).hexdigest()))
            self.assertIn(receipt, xqos.catalog_recipes())
            self.assertEqual(receipt['path'], '/system/lib64/libxqos.so')
            self.assertEqual(receipt['requires'], xqos.REQUIRES)
            self.assertEqual(receipt['absent_nodes'], list(xqos.ABSENT_NODES))
            output = bytearray(data)
            for site in receipt['sites']:
                offset = site['offset']
                original, replacement = bytes.fromhex(site['before']), bytes.fromhex(site['after'])
                self.assertEqual(len(original), 4)
                self.assertEqual(len(replacement), 4)
                self.assertEqual(output[offset:offset + 4], original)
                output[offset:offset + 4] = replacement
            self.assertEqual(hashlib.sha256(output).hexdigest(), receipt['after'])
            self.assertEqual(xqos.receipt(output), receipt)

    def test_unknown_tampered_or_partially_patched_files_are_refused(self):
        for data in self.artifacts():
            _, recipe, _ = xqos.audit(data)
            for position in (4, 40, recipe['functions'][0]['site'], len(data) - 1):
                modified = bytearray(data)
                modified[position] ^= 1
                with self.subTest(position=position), self.assertRaisesRegex(RuntimeError, 'Unsupported'):
                    xqos.patch_bytes(modified)
            function = recipe['functions'][0]
            partial = bytearray(data)
            partial[function['site']:function['site'] + 4] = xqos._replacement(function)
            with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
                xqos.patch_bytes(partial)
        with self.assertRaises(RuntimeError):
            xqos.patch_bytes(b'not an ELF')
        with self.assertRaises(RuntimeError):
            xqos.recipe_receipt('0' * 64)

    def test_explicit_structure_guards_reject_wrong_functions_failure_paths_and_pac(self):
        for data in self.artifacts():
            selected = xqos.select_recipe(data)
            _, recipe, _ = selected
            function = recipe['functions'][0]
            positions = (40, function['address'], function['site'] + 4,
                         function['target'], recipe['initialize'][0])
            for position in positions:
                modified = bytearray(data)
                modified[position] ^= 1
                # Bypass only the whole-file pin to exercise deeper guards.
                with self.subTest(position=position), patch.object(xqos, 'select_recipe', return_value=selected):
                    with self.assertRaises(RuntimeError):
                        xqos.audit(modified)

    def test_atomic_publication_is_separate_idempotent_and_preserves_unknowns(self):
        data = self.artifacts()[0]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, output = root / 'factory.so', root / 'derivative.so'
            source.write_bytes(data)
            xqos.patch(source, output)
            info = output.stat()
            self.assertEqual(info.st_mode & 0o777, 0o644)
            self.assertEqual(info.st_nlink, 1)
            xqos.patch(source, output)
            self.assertEqual(output.stat().st_ino, info.st_ino)
            self.assertEqual(source.read_bytes(), data)
            with self.assertRaises(RuntimeError):
                xqos.patch(source, source)
            alias = root / 'source-alias.so'
            alias.symlink_to(source)
            with self.assertRaises(RuntimeError):
                xqos.patch(source, alias)
            output.write_bytes(b'custom output')
            with self.assertRaisesRegex(RuntimeError, 'unknown'):
                xqos.patch(source, output)
            self.assertEqual(output.read_bytes(), b'custom output')
            self.assertFalse(list(root.glob('.xqos-*')))

    def test_racing_unknown_output_is_not_replaced(self):
        data = self.artifacts()[0]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, output = root / 'factory.so', root / 'result.so'
            source.write_bytes(data)

            def race(*_):
                output.write_bytes(b'user content')
                raise FileExistsError()

            with patch.object(xqos.os, 'link', side_effect=race), self.assertRaisesRegex(RuntimeError, 'unknown'):
                xqos.patch(source, output)
            self.assertEqual(output.read_bytes(), b'user content')
            self.assertFalse(list(root.glob('.xqos-*')))


if __name__ == '__main__':
    unittest.main()
