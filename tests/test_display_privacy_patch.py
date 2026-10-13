"""Verify the privacy fallback patch against optional audited ELF artifacts."""
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import unittest
import xml.etree.ElementTree as ET

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'scripts'))
import patch_display_privacy as privacy


class DisplayPrivacyPatchTests(unittest.TestCase):
    def artifact(self):
        path = Path(os.environ.get('HYPEROS_AVD_PRIVACY_ARTIFACT', str(
            REPO / 'work/feedback-investigation-20261013/phone-libmisurfaceflinger.so')))
        if not path.is_file():
            self.skipTest('Audited proprietary display ELF is not distributed in Git.')
        return path.read_bytes()

    def test_real_patch_changes_only_the_absent_hal_baseline_and_is_idempotent(self):
        before = self.artifact(); after = privacy.patch(before)
        self.assertEqual(privacy.privacy_symbol(before), (privacy.FUNCTION_ADDRESS,
                                                       privacy.FUNCTION_SIZE, privacy.FUNCTION_ADDRESS))
        self.assertEqual(hashlib.sha256(after).hexdigest(), privacy.AFTER)
        self.assertEqual(privacy.patch(after), after)
        site, original, replacement = privacy.SITES[0]
        self.assertEqual(before[:site], after[:site])
        self.assertEqual(before[site + 4:], after[site + 4:])
        instruction = struct.unpack('<I', replacement)[0]
        self.assertEqual(instruction & 0xffc00000, 0xb9000000)
        self.assertEqual(instruction & 31, 31)  # WZR, never the requested mode.
        self.assertEqual((instruction >> 5) & 31, 19)
        self.assertEqual(((instruction >> 10) & 0xfff) * 4, 0x4b8)
        # The original equality gate, real-HAL null branch and success store
        # continue to execute unchanged. No call/log function is bypassed.
        for address, expected in ((0x635b8, '68ba44b9'), (0x63658, 'b70300b4'),
                                  (0x63698, '74ba04b9')):
            self.assertEqual(after[address:address + 4].hex(), expected)

    def test_unknown_or_tampered_full_elf_is_never_patched(self):
        before = self.artifact()
        for position in (4, 40, 0x634c4, 0x636cc, len(before) - 1):
            data = bytearray(before); data[position] ^= 1
            with self.subTest(position=position), self.assertRaisesRegex(RuntimeError, 'Unsupported'):
                privacy.patch(data)

    def test_function_resolver_refuses_malformed_exported_layout(self):
        before = self.artifact()
        for position in (4, 40):
            data = bytearray(before); data[position] ^= 1
            with self.subTest(position=position), self.assertRaises(RuntimeError):
                privacy.privacy_symbol(data)
        with self.assertRaises(RuntimeError):
            privacy.privacy_symbol(before[:-1])

    def test_full_reviewed_vendor_inventory_proves_no_declared_privacy_hal(self):
        root = Path(os.environ.get('HYPEROS_AVD_PRIVACY_VINTF', str(
            REPO / 'work/feedback-investigation-20261013/phone-vintf')))
        if not root.is_dir():
            self.skipTest('Audited vendor VINTF fixture is not distributed in Git.')
        files = {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                 for path in root.rglob('*') if path.is_file()}
        self.assertEqual(files, privacy.VINTF_FILES)
        for relative in files:
            tree = ET.fromstring((root / relative).read_bytes())
            self.assertNotIn('vendor.xiaomi.hardware.display.mihwcextension',
                             [node.text for node in tree.iter('name')])

    def test_reviewed_apex_packages_and_active_fragments_prove_declaration_absence(self):
        root = REPO / 'work/feedback-investigation-20261013/privacy-extra-inventory'
        if not root.is_dir():
            self.skipTest('Audited vendor APEX evidence is not distributed in Git.')
        receipt = json.loads((root / 'receipt.json').read_text())
        self.assertEqual(receipt['vendor_apex_packages'], privacy.APEX_PACKAGES)
        self.assertEqual(receipt['apex_fragments'], privacy.APEX_FRAGMENTS)
        for name, checksum in privacy.APEX_FRAGMENTS.items():
            data = (root / name.lstrip('/')).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), checksum)
            tree = ET.fromstring(data)
            self.assertEqual(tree.attrib['type'], 'device')
            self.assertNotIn('vendor.xiaomi.hardware.display.mihwcextension',
                             [node.text for node in tree.iter('name')])


if __name__ == '__main__':
    unittest.main()
