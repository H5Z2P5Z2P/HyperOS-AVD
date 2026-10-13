"""Audit exact GNSS/boot-service recipes and optional independent Java producers.

Set HYPEROS_AVD_GNSS_TEST_SOURCE to the original authenticated services.jar to
rebuild twice in separate workspaces and audit every classes.dex method.
"""
import copy
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'scripts'))
import apply_boot_service_fix as historical
import patch_boot_services as boot
import patch_gnss as gnss


def smali_scope(text):
    """Normalize DEX round-trip labels while retaining non-method class content."""
    methods = {}
    rest = text
    for match in re.finditer(r'^\.method [^\n]*\n.*?^\.end method', text, re.M | re.S):
        signature = match.group().splitlines()[0].split()[-1]
        if signature in methods:
            raise AssertionError('Duplicate DEX method signature: ' + signature)
        methods[signature] = boot.method_code(match.group(), signature)
        rest = rest.replace(match.group(), '', 1)
    content = []
    for line in rest.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # DEX drops trailing static initializers equal to the type's default.
        # This changes serialization while retaining exactly the same value.
        line = re.sub(r'^(\.field [^\n]*:Z) = false$', r'\1', line)
        line = re.sub(r'^(\.field [^\n]*:[BCIJSZ]) = 0x0(?:[LSt])?$', r'\1', line)
        line = re.sub(r'^(\.field [^\n]*:F) = 0\.0f$', r'\1', line)
        line = re.sub(r'^(\.field [^\n]*:D) = 0\.0$', r'\1', line)
        line = re.sub(r'^(\.field [^\n]*:(?:L[^;]+;|\[[^ ]+)) = null$', r'\1', line)
        content.append(line)
    return content, methods


class ReproducibleRecipeTests(unittest.TestCase):
    def test_scope_normalizes_only_exact_type_defaults(self):
        self.assertEqual(smali_scope('.field private static FLAG:Z = false'),
                         smali_scope('.field private static FLAG:Z'))
        self.assertNotEqual(smali_scope('.field private static FLAG:Z = true'),
                            smali_scope('.field private static FLAG:Z'))
        self.assertNotEqual(smali_scope('.field private static VALUE:F = -0.0f'),
                            smali_scope('.field private static VALUE:F = 0.0f'))

    def test_history_is_frozen_and_modern_receipt_uses_the_shared_gnss_output(self):
        self.assertEqual(boot.TARGETS['services'][1],
                         '37cf6a7b69d9849e2f13142835218ffe250d9fc3dc51f3ecbe4b342834ccb536')
        self.assertEqual(boot.AFTER['services'],
                         '3b1c22fbae3262187af8e040e02962edd7f80ae7369d9bcd724457384a4fd6b1')
        self.assertEqual(boot.image_receipt(), historical.receipt())
        gnss_receipt = gnss.output_receipt(gnss.OS4_18_SHA256)
        modern = boot.image_receipt(gnss_receipt['after'])
        self.assertEqual(modern['targets']['services'],
                         {key: boot.select_recipe('services', gnss_receipt['after'])[key]
                          for key in ('path', 'before', 'after')})
        self.assertNotEqual(modern['targets']['services']['after'], boot.AFTER['services'])
        for name in boot.TARGETS.keys() - {'services'}:
            self.assertEqual(modern['targets'][name], historical.receipt()['targets'][name])
        for receipt in boot.image_receipts():
            self.assertEqual(boot.validate_image_receipt(receipt), receipt)
        modern['targets']['services']['before'] = '0' * 64
        self.assertNotEqual(boot.image_receipt(gnss_receipt['after']), modern)

    def test_receipt_rejects_mixed_history_wrong_types_and_extra_fields(self):
        modern = boot.image_receipt(gnss.output_receipt(gnss.OS4_18_SHA256)['after'])
        mutations = []
        for key, value in (('schema', True), ('schema', 1.0), ('schema', 2),
                           ('firmware', 'OS4.0.999.0.XFRCNXM'), ('probe_sha256', '0' * 64)):
            mutations.append(dict(modern, **{key: value}))
        changed = copy.deepcopy(modern)
        changed['targets']['services']['after'] = boot.AFTER['services']
        mutations.append(changed)
        changed = copy.deepcopy(modern)
        del changed['targets']['qualcomm']
        mutations.append(changed)
        changed = copy.deepcopy(modern)
        changed['targets']['services']['path'] = '/data/foreign/services.jar'
        mutations.append(changed)
        mutations.extend((None, {}, dict(modern, bypass=True)))
        for changed in mutations:
            with self.subTest(marker=changed), self.assertRaisesRegex(RuntimeError, 'image receipt'):
                boot.validate_image_receipt(changed)

    def test_recipe_rejects_unknown_content_and_producer_input(self):
        for source in ('0' * 64, b'foreign services', None, [], ''):
            with self.subTest(source=source), self.assertRaisesRegex(RuntimeError, 'Unsupported boot service input'):
                boot.select_recipe('services', source)
        with self.assertRaisesRegex(RuntimeError, 'Unsupported boot service input'):
            boot.image_receipt('')
        with self.assertRaisesRegex(RuntimeError, 'reproducible GNSS source'):
            gnss.output_receipt(gnss.PAD_SHA256)

    def test_gnss_tool_receipt_is_a_fresh_complete_copy(self):
        receipt = gnss.output_receipt(gnss.OS4_18_SHA256)
        self.assertEqual(receipt['before'], gnss.OS4_18_SHA256)
        self.assertEqual(receipt['dex'], 'classes2.dex')
        self.assertEqual(receipt['assembly_jobs'], 1)
        self.assertEqual(receipt['tools'],
                         {name: checksum for name, (_, checksum) in gnss.ARTIFACTS.items()})
        receipt['tools']['smali'] = '0' * 64
        self.assertNotEqual(gnss.output_receipt(gnss.OS4_18_SHA256), receipt)


class IndependentProducerTests(unittest.TestCase):
    def test_two_clean_producers_match_and_boot_changes_only_its_audited_method(self):
        source_value = os.environ.get('HYPEROS_AVD_GNSS_TEST_SOURCE')
        if not source_value:
            self.skipTest('Authenticated original services.jar was not supplied.')
        source = Path(source_value)
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), gnss.OS4_18_SHA256)
        receipt = gnss.output_receipt(gnss.OS4_18_SHA256)
        produced = []
        with tempfile.TemporaryDirectory(prefix='gnss-reproducibility-') as directory:
            folder = Path(directory)
            for number in (1, 2):
                workspace = folder / ('producer-' + str(number))
                (workspace / 'tools').mkdir(parents=True)
                (workspace / 'tools/smali').symlink_to(REPO / 'tools/smali', target_is_directory=True)
                gnss_output, boot_output = workspace / 'gnss.jar', workspace / 'boot.jar'
                with patch.object(gnss, 'ROOT', workspace), patch.object(boot, 'ROOT', workspace), \
                        patch.object(gnss, 'secure_urlretrieve', side_effect=AssertionError('Unexpected download')):
                    data = gnss.patch(source, gnss_output)
                    boot.patch('services', gnss_output, boot_output)
                self.assertEqual(hashlib.sha256(data).hexdigest(), receipt['after'])
                self.assertEqual(boot.sha256(boot_output),
                                 boot.select_recipe('services', receipt['after'])['after'])
                with zipfile.ZipFile(source) as original, zipfile.ZipFile(gnss_output) as rewritten, \
                        zipfile.ZipFile(boot_output) as fixed:
                    self.assertEqual(original.namelist(), rewritten.namelist())
                    self.assertEqual(rewritten.namelist(), fixed.namelist())
                    self.assertIsNone(rewritten.testzip())
                    self.assertIsNone(fixed.testzip())
                    self.assertEqual(hashlib.sha256(rewritten.read('classes2.dex')).hexdigest(), receipt['dex_after'])
                    for entry in original.namelist():
                        if entry != 'classes2.dex':
                            self.assertEqual(original.read(entry), rewritten.read(entry), entry)
                        if entry != 'classes.dex':
                            self.assertEqual(rewritten.read(entry), fixed.read(entry), entry)
                produced.append((data, boot_output.read_bytes()))
            self.assertEqual(produced[0], produced[1])
            command = [gnss.java(), '-cp', str(REPO / 'tools/smali/*'),
                       'org.jf.baksmali.Main', 'disassemble', '-j', '1']
            before, after = folder / 'before', folder / 'after'
            for archive, destination in ((source, before), (folder / 'producer-2/boot.jar', after)):
                subprocess.run(command + [str(archive) + '/classes.dex', '-o', str(destination)],
                               check=True, capture_output=True, timeout=120)
            originals = {str(path.relative_to(before)): path for path in before.rglob('*.smali')}
            modified = {str(path.relative_to(after)): path for path in after.rglob('*.smali')}
            self.assertEqual(originals.keys(), modified.keys())
            target, signature, method_sha256, edit = boot.EDITS['services'][0]
            for relative, path in originals.items():
                expected_text = path.read_text()
                if relative == target:
                    expected_text = boot.edit_method(expected_text, signature, method_sha256, edit)
                self.assertEqual(smali_scope(expected_text), smali_scope(modified[relative].read_text()), relative)


if __name__ == '__main__':
    unittest.main()
