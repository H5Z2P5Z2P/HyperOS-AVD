"""Consolidated unit tests for OS4 GNSS location patch & byte-level reproducibility."""
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
ROOT = REPO
sys.path.insert(0, str(REPO / 'scripts'))

import apply_boot_service_fix as historical
import patch_boot_services as boot
import patch_gnss
import patch_gnss as gnss



# --- tests/test_gnss_patch.py ---

'Check fail-closed GNSS input guards and optional real 4.0.18 DEX evidence.\n\nSet HYPEROS_AVD_GNSS_TEST_SOURCE and HYPEROS_AVD_GNSS_TEST_PATCHED to audit a\nlocally supplied original services.jar and its patched output without an AVD.\n'

CALLBACKS = {'reportStatus(I)V': 2, 'reportSvStatus(I[I[I[I[F[F[F[F[F[Ljava/lang/String;[J[D)V': 13, 'reportLocation(ZLandroid/location/Location;)V': 3}

BINDER_CALL = 'invoke-static {v0}, Landroid/os/Binder;->withCleanCallingIdentity(Lcom/android/internal/util/FunctionalUtils$ThrowingRunnable;)V'

def callback_method(text, signature):
    """Require a single exact callback and retain its complete method body."""
    marker = '.method ' + signature + '\n'
    if text.count(marker) != 1:
        raise AssertionError('Callback signature changed: ' + signature)
    start = text.index(marker)
    end = text.index('.end method', start) + len('.end method')
    return text[start:end]

class GnssInputGuardTests(unittest.TestCase):

    def test_unknown_input_is_rejected_before_any_tool_or_workspace_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'services.jar'
            source.write_bytes(b'unverified framework')
            destination = root / 'never-created.jar'
            work = root / 'untouched-workspace'
            with patch.object(patch_gnss, 'ROOT', work), patch.object(patch_gnss.urllib.request, 'urlretrieve') as download, patch.object(patch_gnss.subprocess, 'run') as command:
                with self.assertRaisesRegex(RuntimeError, 'Unsupported services.jar'):
                    patch_gnss.patch(source, destination)
                download.assert_not_called()
                command.assert_not_called()
            self.assertFalse(destination.exists())
            self.assertFalse(work.exists())
            self.assertEqual(source.read_bytes(), b'unverified framework')

class Gnss18ArtifactTests(unittest.TestCase):

    def test_only_callbacks_and_runnable_adapters_change_in_the_real_framework(self):
        source_value = os.environ.get('HYPEROS_AVD_GNSS_TEST_SOURCE')
        output_value = os.environ.get('HYPEROS_AVD_GNSS_TEST_PATCHED')
        if not source_value or not output_value:
            self.skipTest('Original and patched 4.0.18 GNSS artifacts were not supplied.')
        source, output = (Path(source_value), Path(output_value))
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), patch_gnss.OS4_18_SHA256)
        cache = REPO / 'tools/smali'
        for name, (_, expected) in patch_gnss.ARTIFACTS.items():
            self.assertEqual(hashlib.sha256((cache / (name + '.jar')).read_bytes()).hexdigest(), expected)
        with zipfile.ZipFile(source) as original, zipfile.ZipFile(output) as rewritten:
            self.assertEqual(original.namelist(), rewritten.namelist())
            self.assertNotEqual(original.read('classes2.dex'), rewritten.read('classes2.dex'))
            for entry in original.namelist():
                if entry != 'classes2.dex':
                    self.assertEqual(original.read(entry), rewritten.read(entry), entry)
        command = [patch_gnss.java(), '-cp', str(cache / '*'), 'org.jf.baksmali.Main', 'disassemble', '-j', '2']
        native_class = 'Lcom/android/server/location/gnss/hal/GnssNative;'
        native_path = Path('com/android/server/location/gnss/hal/GnssNative.smali')
        with tempfile.TemporaryDirectory(prefix='gnss-18-dex-audit-') as temporary:
            folder = Path(temporary)
            before, after = (folder / 'before', folder / 'after')
            subprocess.run(command + ['--classes', native_class, str(source) + '/classes2.dex', '-o', str(before)], check=True, capture_output=True, timeout=120)
            original_native = (before / native_path).read_text()
            adapters = {}
            for signature in CALLBACKS:
                method = callback_method(original_native, signature)
                self.assertEqual(method.count(BINDER_CALL), 1)
                names = re.findall('new-instance v0, Lcom/android/server/location/gnss/hal/([^;]+);', method)
                self.assertEqual(len(names), 1)
                adapters[signature] = names[0]
            adapter_classes = ','.join(('Lcom/android/server/location/gnss/hal/' + name + ';' for name in adapters.values()))
            subprocess.run(command + ['--classes', adapter_classes, str(source) + '/classes2.dex', '-o', str(before)], check=True, capture_output=True, timeout=120)
            subprocess.run(command + ['--classes', native_class + ',' + adapter_classes, str(output) + '/classes2.dex', '-o', str(after)], check=True, capture_output=True, timeout=120)
            patched_native = (after / native_path).read_text()
            original_rest, patched_rest = (original_native, patched_native)
            for signature, parameter_words in CALLBACKS.items():
                old = callback_method(original_native, signature)
                new = callback_method(patched_native, signature)
                self.assertNotIn(BINDER_CALL, new)
                self.assertEqual(new.count('Lcom/android/server/FgThread;->getHandler()'), 1)
                self.assertEqual(new.count('Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z'), 1)
                registers = int(re.search('\\.registers (\\d+)', new).group(1))
                self.assertGreaterEqual(registers - parameter_words, 2)
                constructor = re.search('invoke-direct(?:/range)?[^\\n]+;-><init>[^\\n]+', old).group()
                self.assertIn(constructor, new)
                original_rest = original_rest.replace(old, '', 1)
                patched_rest = patched_rest.replace(new, '', 1)
                adapter_path = native_path.parent / (adapters[signature] + '.smali')
                old_adapter = (before / adapter_path).read_text()
                new_adapter = (after / adapter_path).read_text()
                self.assertEqual(old_adapter.count('.implements Lcom/android/internal/util/FunctionalUtils$ThrowingRunnable;'), 1)
                self.assertNotIn('.implements Ljava/lang/Runnable;', old_adapter)
                self.assertEqual(new_adapter.count('.implements Ljava/lang/Runnable;'), 1)
                run_method = re.findall('\\.method public final run\\(\\)V\\n.*?\\.end method', new_adapter, re.DOTALL)
                self.assertEqual(len(run_method), 1)
                self.assertIn('invoke-static {p0}, Landroid/os/Binder;->withCleanCallingIdentity', run_method[0])
                self.assertIn('return-void', run_method[0])
                restored = new_adapter.replace('.implements Ljava/lang/Runnable;\n', '', 1)
                restored = restored.replace(run_method[0], '', 1).rstrip()
                self.assertEqual([line for line in restored.splitlines() if line.strip()], [line for line in old_adapter.splitlines() if line.strip()])
            self.assertEqual([line for line in patched_rest.splitlines() if line.strip()], [line for line in original_rest.splitlines() if line.strip()])

if __name__ == '__main__':
    unittest.main()


# --- tests/test_gnss_reproducibility.py ---

'Audit exact GNSS/boot-service recipes and optional independent Java producers.\n\nSet HYPEROS_AVD_GNSS_TEST_SOURCE to the original authenticated services.jar to\nrebuild twice in separate workspaces and audit every classes.dex method.\n'

def smali_scope(text):
    """Normalize DEX round-trip labels while retaining non-method class content."""
    methods = {}
    rest = text
    for match in re.finditer('^\\.method [^\\n]*\\n.*?^\\.end method', text, re.M | re.S):
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
        line = re.sub('^(\\.field [^\\n]*:Z) = false$', '\\1', line)
        line = re.sub('^(\\.field [^\\n]*:[BCIJSZ]) = 0x0(?:[LSt])?$', '\\1', line)
        line = re.sub('^(\\.field [^\\n]*:F) = 0\\.0f$', '\\1', line)
        line = re.sub('^(\\.field [^\\n]*:D) = 0\\.0$', '\\1', line)
        line = re.sub('^(\\.field [^\\n]*:(?:L[^;]+;|\\[[^ ]+)) = null$', '\\1', line)
        content.append(line)
    return (content, methods)

class ReproducibleRecipeTests(unittest.TestCase):

    def test_scope_normalizes_only_exact_type_defaults(self):
        self.assertEqual(smali_scope('.field private static FLAG:Z = false'), smali_scope('.field private static FLAG:Z'))
        self.assertNotEqual(smali_scope('.field private static FLAG:Z = true'), smali_scope('.field private static FLAG:Z'))
        self.assertNotEqual(smali_scope('.field private static VALUE:F = -0.0f'), smali_scope('.field private static VALUE:F = 0.0f'))

    def test_history_is_frozen_and_modern_receipt_uses_the_shared_gnss_output(self):
        self.assertEqual(boot.TARGETS['services'][1], '37cf6a7b69d9849e2f13142835218ffe250d9fc3dc51f3ecbe4b342834ccb536')
        self.assertEqual(boot.AFTER['services'], '3b1c22fbae3262187af8e040e02962edd7f80ae7369d9bcd724457384a4fd6b1')
        self.assertEqual(boot.image_receipt(), historical.receipt())
        gnss_receipt = gnss.output_receipt(gnss.OS4_18_SHA256)
        modern = boot.image_receipt(gnss_receipt['after'])
        self.assertEqual(modern['targets']['services'], {key: boot.select_recipe('services', gnss_receipt['after'])[key] for key in ('path', 'before', 'after')})
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
        for key, value in (('schema', True), ('schema', 1.0), ('schema', 2), ('firmware', 'OS4.0.999.0.XFRCNXM'), ('probe_sha256', '0' * 64)):
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
        self.assertEqual(receipt['tools'], {name: checksum for name, (_, checksum) in gnss.ARTIFACTS.items()})
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
                gnss_output, boot_output = (workspace / 'gnss.jar', workspace / 'boot.jar')
                with patch.object(gnss, 'ROOT', workspace), patch.object(boot, 'ROOT', workspace), patch.object(gnss, 'secure_urlretrieve', side_effect=AssertionError('Unexpected download')):
                    data = gnss.patch(source, gnss_output)
                    boot.patch('services', gnss_output, boot_output)
                self.assertEqual(hashlib.sha256(data).hexdigest(), receipt['after'])
                self.assertEqual(boot.sha256(boot_output), boot.select_recipe('services', receipt['after'])['after'])
                with zipfile.ZipFile(source) as original, zipfile.ZipFile(gnss_output) as rewritten, zipfile.ZipFile(boot_output) as fixed:
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
            command = [gnss.java(), '-cp', str(REPO / 'tools/smali/*'), 'org.jf.baksmali.Main', 'disassemble', '-j', '1']
            before, after = (folder / 'before', folder / 'after')
            for archive, destination in ((source, before), (folder / 'producer-2/boot.jar', after)):
                subprocess.run(command + [str(archive) + '/classes.dex', '-o', str(destination)], check=True, capture_output=True, timeout=120)
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
