"""Consolidated unit tests for native module packaging & installation:
archive assembly, integrity manifest validation, and shell installation guards.
"""
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

REPO = Path(__file__).resolve().parents[1]
ROOT = REPO
sys.path.insert(0, str(REPO / 'scripts'))

import apply_native_compat as install
import dex2oat_cpu_policy as cpu_policy
import native_module_history as history
import package_native_module as package



# --- tests/test_native_module_package.py ---

'Exercise standard KernelSU delivery without a guest or proprietary payload.'

class NativeModulePackageTests(unittest.TestCase):

    def test_privacy_capability_recipe_is_canonical_and_integrity_bound(self):
        import dolby_codecs
        import patch_display_privacy as privacy
        files = package.module_files()
        name = 'display-privacy-capability.tsv'
        self.assertEqual(files[name], privacy.capability_recipe())
        rows = [row.split('|') for row in files[name].decode().splitlines()]
        self.assertEqual(rows[:3], [['schema', '1'], ['root', privacy.VINTF_ROOT], ['absent', privacy.ABSENT_VINTF]])
        self.assertEqual([row[1] for row in rows if row[0] == 'absent'], list(privacy.ABSENT_DECLARATIONS))
        self.assertEqual([row[1:] for row in rows if row[0] == 'compat-link'], [list(privacy.ODM_COMPAT_LINK), list(privacy.ODM_APEX_COMPAT_LINK)])
        self.assertEqual({row[1]: row[2] for row in rows if row[0] == 'apex-package'}, privacy.APEX_PACKAGES)
        self.assertEqual({row[1]: row[2] for row in rows if row[0] == 'apex-fragment'}, privacy.APEX_FRAGMENTS)
        expected_trees = {'/vendor/apex', *[str(Path(path).parent) for path in privacy.APEX_FRAGMENTS]}
        self.assertEqual({row[1] for row in rows if row[0] == 'tree'}, expected_trees)
        self.assertEqual([row[1] for row in rows if row[0] == 'expected-trees'], [str(len(expected_trees))])
        pins = {row[1]: row[2] for row in rows if row[0] == 'file'}
        self.assertEqual(pins, {privacy.VINTF_ROOT + '/' + path: checksum for path, checksum in privacy.VINTF_FILES.items()})
        self.assertEqual(len(pins), 26)
        self.assertEqual([row[1:] for row in rows if row[0] == 'optional-file'],
                         [[dolby_codecs.VINTF_PATH, dolby_codecs.VINTF_SHA256]])
        manifest = json.loads(files['manifest.json'])
        self.assertEqual(manifest['files_sha256'][name], hashlib.sha256(files[name]).hexdigest())
        self.assertIn('display-privacy', manifest['features'])

    def test_boot_catalog_uses_complete_canonical_image_receipts(self):
        from patch_boot_services import image_receipts
        files = package.module_files()
        rows = [row.split('|') for row in files['boot-prerequisites.tsv'].decode().splitlines()]
        self.assertEqual(rows.pop(0), ['schema', '1'])
        declared = {row[1]: int(row[2]) for row in rows if row[0] == 'recipe'}
        groups = {identity: {} for identity in declared}
        for row in rows:
            if row[0] == 'file':
                self.assertNotIn(row[2], groups[row[1]])
                groups[row[1]][row[2]] = row[3]
        expected = []
        for receipt in image_receipts():
            pins = {item['path']: item['after'] for item in receipt['targets'].values()}
            pins['/system/bin/hyperos_kernel_probe'] = receipt['probe_sha256']
            expected.append(pins)
        self.assertCountEqual(list(groups.values()), expected)
        self.assertTrue(all((len(group) == declared[identity] == 5 for identity, group in groups.items())))
        self.assertEqual(hashlib.sha256(files['boot-prerequisites.tsv']).hexdigest(), json.loads(files['manifest.json'])['files_sha256']['boot-prerequisites.tsv'])

    def test_boot_catalog_cannot_broaden_unknown_or_duplicate_receipts(self):
        import patch_boot_services
        receipt = patch_boot_services.image_receipt()
        with patch.object(patch_boot_services, 'image_receipts', return_value=(receipt, receipt)):
            with self.assertRaisesRegex(RuntimeError, 'Duplicate'):
                package.boot_prerequisites()
        receipt['probe_sha256'] = 'a' * 64
        with patch.object(patch_boot_services, 'image_receipts', return_value=(receipt,)), patch.object(patch_boot_services, 'validate_image_receipt', side_effect=RuntimeError('Unsupported boot service image receipt.')) as validate:
            with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
                package.boot_prerequisites()
            validate.assert_called_once_with(receipt)

    def test_deterministic_zip_is_self_contained_and_checked(self):
        with tempfile.TemporaryDirectory() as temporary:
            first, second = (Path(temporary) / 'a.zip', Path(temporary) / 'b.zip')
            one, two = (package.package(first), package.package(second))
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(one['sha256'], two['sha256'])
            with zipfile.ZipFile(first) as archive:
                names = archive.namelist()
                self.assertEqual(len(names), len(set(names)))
                self.assertIn('customize.sh', names)
                self.assertIn('post-fs-data.sh', names)
                self.assertIn('service.sh', names)
                self.assertIn('skip_mount', names)
                self.assertFalse(any((name.startswith('system/') for name in names)))
                self.assertEqual([name for name in names if name.endswith(('.so', '.apk', '.jar'))], ['device-credential.jar', 'rear-wake.jar'])
                from device_credential_runtime import files as credential_files
                for name, expected in credential_files().items():
                    self.assertEqual(archive.read(name), expected)
                for row in archive.read('SHA256SUMS').decode().splitlines():
                    expected, name = row.split('  ', 1)
                    self.assertEqual(hashlib.sha256(archive.read(name)).hexdigest(), expected)
                    self.assertNotEqual(name, 'customize.sh')
                manifest = json.loads(archive.read('manifest.json'))
                self.assertEqual(manifest['id'], package.MODULE_ID)
                self.assertFalse(manifest['automatic_reboot'])
                self.assertEqual(manifest['catalog_sha256'], hashlib.sha256(archive.read('catalog.json')).hexdigest())
                for name in names:
                    self.assertFalse(Path(name).is_absolute())
                    self.assertNotIn('..', Path(name).parts)
                    if name.endswith('.sh'):
                        self.assertEqual(archive.getinfo(name).external_attr >> 16 & 511, 493)

    def test_every_packaged_shell_script_parses(self):
        with tempfile.TemporaryDirectory() as temporary:
            for name, body in package.module_files().items():
                if name.endswith('.sh'):
                    target = Path(temporary) / Path(name).name
                    target.write_bytes(body)
                    result = subprocess.run(['sh', '-n', str(target)], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_cpu_helper_is_self_contained_and_bound_to_installed_integrity_manifest(self):
        files = package.module_files()
        name = 'dex2oat-cpu-policy.sh'
        self.assertEqual(files[name], cpu_policy.policy_script())
        manifest = json.loads(files['manifest.json'])
        self.assertEqual(manifest['revision'], package.REVISION)
        self.assertEqual(manifest['files_sha256'][name], hashlib.sha256(files[name]).hexdigest())
        checked = dict((row.split('  ', 1)[::-1] for row in files['SHA256SUMS'].decode().splitlines()))
        self.assertEqual(checked[name], manifest['files_sha256'][name])
        self.assertNotIn(name, manifest['install_only_files'])
        self.assertFalse((REPO / 'modules/native-compat' / name).exists(), 'The module must reuse the canonical CPU helper, not a second copy.')

    def test_rear_helper_is_offline_canonical_and_integrity_bound(self):
        from rear_display_wake_runtime import files as rear_files
        files = package.module_files()
        assets = rear_files()
        self.assertEqual(set(assets), {'rear-wake.jar', 'rear-wake.tsv'})
        manifest = json.loads(files['manifest.json'])
        checked = dict((row.split('  ', 1)[::-1] for row in files['SHA256SUMS'].decode().splitlines()))
        for name, body in assets.items():
            self.assertEqual(files[name], body)
            self.assertEqual(checked[name], hashlib.sha256(body).hexdigest())
            self.assertEqual(manifest['files_sha256'][name], checked[name])
            self.assertNotIn(name, manifest['install_only_files'])
        self.assertEqual(files['rear-wake.tsv'].decode().splitlines()[2], 'jar|rear-wake.jar|' + checked['rear-wake.jar'])

    def test_foreign_template_ownership_is_rejected_before_cpu_policy_delivery(self):
        import shutil
        with tempfile.TemporaryDirectory() as temporary:
            template = Path(temporary) / 'template'
            shutil.copytree(REPO / 'modules/native-compat', template)
            props = template / 'module.prop'
            props.write_text(props.read_text().replace('id=' + package.MODULE_ID, 'id=unrelated_module'))
            output = Path(temporary) / 'module.zip'
            with self.assertRaisesRegex(RuntimeError, 'ownership'):
                package.package(output, template=template)
            self.assertFalse(output.exists())
            self.assertFalse(output.with_name(output.name + '.next').exists())

    def test_package_does_not_follow_an_output_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            original = Path(temporary) / 'original'
            original.write_text('preserved')
            link = Path(temporary) / 'module.zip'
            link.symlink_to(original)
            with self.assertRaisesRegex(RuntimeError, 'non-regular'):
                package.package(link)
            self.assertEqual(original.read_text(), 'preserved')

    def test_release_source_list_carries_module_templates(self):
        import package_release
        paths = package_release.runtime_files()
        for name in ('runtime.sh', 'module.prop', 'customize.sh', 'post-fs-data.sh', 'service.sh'):
            self.assertEqual(paths['modules/native-compat/' + name], REPO / 'modules/native-compat' / name)
        self.assertEqual(paths['config/dex2oat_cpu_policy.sh'], cpu_policy.POLICY)
        self.assertEqual(paths['scripts/dex2oat_cpu_policy.py'], REPO / 'scripts/dex2oat_cpu_policy.py')

    def test_lost_staging_race_preserves_the_other_packager_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'module.zip'
            staging = output.with_name(output.name + '.next')
            original_open = Path.open

            def racing_open(path, mode='r', *args, **kwargs):
                if path == staging and mode == 'xb':
                    with original_open(path, 'wb') as other:
                        other.write(b'other operation')
                    raise FileExistsError(str(path))
                return original_open(path, mode, *args, **kwargs)
            with patch.object(Path, 'open', racing_open):
                with self.assertRaises(FileExistsError):
                    package.package(output)
            self.assertEqual(staging.read_bytes(), b'other operation')
            self.assertFalse(output.exists())

    def test_installed_checksums_survive_kernel_su_customizer_removal(self):
        import shutil
        checker = shutil.which('sha256sum') or shutil.which('gsha256sum')
        if checker is None:
            self.skipTest('A SHA256SUMS-compatible host verifier is unavailable.')
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name, data in package.module_files().items():
                path = directory / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            (directory / 'customize.sh').unlink()
            result = subprocess.run([checker, '-c', 'SHA256SUMS'], cwd=directory, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

if __name__ == '__main__':
    unittest.main()


# --- tests/test_native_module_install.py ---

'Check native module lifecycle and preservation without touching a real AVD.'

PROPERTY = f'id={install.MODULE_ID}\nauthor=HyperOS-AVD\nversionCode={install.REVISION}'

class NativeModuleInstallTests(unittest.TestCase):

    def run_install(self, active=None, pending=None, abi='arm64-v8a', verify=None):
        commands = []
        modules = {install.MODULE: active, install.PENDING: pending}

        def guest(config, command):
            commands.append(command)
            if command.startswith('getprop'):
                return 'ranchu\n' + abi
            directory = install.PENDING if install.PENDING in command else install.MODULE
            state = modules[directory]
            if command.startswith('if ') and "printf 'present" in command:
                return 'absent' if state is None else 'present\n' + state.get('ownership', PROPERTY)
            if command.startswith('for flag in disable remove;'):
                return '\n'.join(state.get('flags', ()))
            if command.startswith('if ') and '/manifest.json' in command:
                return state.get('manifest', '')
            if 'sha256sum -c SHA256SUMS' in command and verify:
                return verify(command)
            return ''
        with patch.object(install, 'root', side_effect=guest), patch.object(install, 'adb') as adb:
            result = install.install({'name': 'Renamed_By_User', 'port': 5590})
        return (result, commands, adb)

    def current_manifest(self):
        return package.module_files()['manifest.json'].decode()

    def test_standard_install_has_no_implicit_restart_or_legacy_changes(self):
        result, commands, adb = self.run_install()
        self.assertTrue(result['reboot_required'])
        self.assertEqual(adb.call_count, 1)
        staged = next((command for command in commands if '/data/adb/ksud module install ' in command))
        self.assertIn(f'[ ! -e {install.PENDING} ] && [ ! -L {install.PENDING} ]', staged)
        self.assertTrue(commands[-1].startswith('rm -f /data/local/tmp/hyperos-native-compat-'))
        self.assertFalse(any(('reboot' in command or 'ctl.restart' in command or 'force-stop' in command or ('hyperos_avd_flutter_render' in command) for command in commands)))

    def test_active_or_pending_lifecycle_choice_is_preserved_before_packaging(self):
        for directory in ('active', 'pending'):
            for flag in ('disable', 'remove'):
                with self.subTest(directory=directory, flag=flag), patch.object(install, 'package') as pack:
                    result, _, adb = self.run_install(**{directory: {'flags': [flag]}})
                    self.assertTrue(result['disabled'])
                    self.assertEqual(result['flags'], [flag])
                    pack.assert_not_called()
                    adb.assert_not_called()

    def test_existing_identical_manifest_authenticates_expected_checksum_list(self):
        result, commands, adb = self.run_install(active={'manifest': self.current_manifest()})
        self.assertTrue(result['reused'])
        verification = next((command for command in commands if 'sha256sum -c SHA256SUMS' in command))
        checksum = hashlib.sha256(package.module_files()['SHA256SUMS']).hexdigest()
        self.assertIn(f'sha256sum {install.MODULE}/SHA256SUMS', verification)
        self.assertIn(' = ' + checksum, verification)
        self.assertLess(verification.index(' = ' + checksum), verification.index('sha256sum -c SHA256SUMS'))
        adb.assert_not_called()

    def test_identical_pending_stage_is_reused_until_normal_reboot(self):
        result, commands, adb = self.run_install(active={'manifest': '{}'}, pending={'manifest': self.current_manifest()})
        self.assertTrue(result['reused'])
        self.assertTrue(result['pending'])
        self.assertTrue(result['reboot_required'])
        self.assertFalse(result['deferred'])
        self.assertTrue(any((f'cd {install.PENDING}' in command for command in commands)))
        self.assertFalse(any((f'cat {install.MODULE}/manifest.json' in command for command in commands)))
        adb.assert_not_called()

    def test_different_pending_stage_and_its_choices_are_never_replaced(self):
        value = json.loads(self.current_manifest())
        value['catalog_sha256'] = '0' * 64
        result, commands, adb = self.run_install(active={'manifest': self.current_manifest()}, pending={'manifest': json.dumps(value)})
        self.assertTrue(result['deferred'])
        self.assertTrue(result['pending'])
        self.assertTrue(result['reboot_required'])
        self.assertFalse(result['reused'])
        self.assertFalse(any(('features.disabled' in command or 'module install' in command or command.startswith('rm ') for command in commands)))
        adb.assert_not_called()

    def test_incomplete_pending_stage_is_deferred_without_repairing_it(self):
        result, _, adb = self.run_install(pending={})
        self.assertTrue(result['deferred'])
        self.assertTrue(result['reboot_required'])
        adb.assert_not_called()

    def test_unknown_owner_or_newer_revision_in_either_location_is_not_overwritten(self):
        for directory in ('active', 'pending'):
            for prop in ('id=another-module\nauthor=HyperOS-AVD\nversionCode=1', f'id={install.MODULE_ID}\nauthor=Another\nversionCode=1', f'id={install.MODULE_ID}\nauthor=HyperOS-AVD\nversionCode=999', PROPERTY + '\nversionCode=1'):
                with self.subTest(directory=directory, prop=prop), patch.object(install, 'package') as pack, self.assertRaisesRegex(RuntimeError, 'Refused'):
                    self.run_install(**{directory: {'ownership': prop}})
                pack.assert_not_called()

    def test_unknown_manifest_is_preserved_in_either_location(self):
        for directory in ('active', 'pending'):
            for value in ('invalid-json', '{}', '[]', json.dumps({'schema': 99, 'id': install.MODULE_ID, 'revision': 1})):
                with self.subTest(directory=directory, value=value), self.assertRaisesRegex(RuntimeError, 'Refused'):
                    self.run_install(**{directory: {'manifest': value}})

    def test_other_abi_is_not_modified(self):
        with self.assertRaisesRegex(RuntimeError, 'ARM64 ranchu'):
            self.run_install(abi='x86_64')

    def test_guest_compatibility_does_not_query_firmware_identity(self):
        with patch.object(install, 'root', return_value='ranchu\narm64-v8a') as guest:
            install.guest_supported({})
        self.assertEqual(guest.call_args.args[1],
                         'getprop ro.boot.hardware; getprop ro.product.cpu.abi')

    def test_script_updates_change_the_manifest_identity(self):
        original = json.loads(self.current_manifest())
        self.assertIn('runtime.sh', original['files_sha256'])
        self.assertIn('customize.sh', original['files_sha256'])
        self.assertEqual(original['revision'], install.REVISION)

    def test_core18_controls_remain_authenticated_after_abi_guard_update(self):
        previous = (REPO / 'tests/fixtures/native-compat-v18-final-manifest.json').read_text()
        saved = json.loads(previous)
        expected = '1d7856b5b812ccf309f8d20e1393f4c1d6455a82117a6fb18651f55f3aa73514'
        self.assertEqual(history.checksum_for(saved), expected)
        record = next(row for row in history.REVIEWED if row['revision'] == 18)
        for feature, controls in record['policy_controls'].items():
            self.assertEqual(controls['helper'], saved['files_sha256'][feature + '-policy.sh'])
            self.assertEqual(controls['recovery'], saved['files_sha256'][feature + '-recovery.sh'])
        prop = PROPERTY.rsplit('=', 1)[0] + '=18'
        result, commands, _ = self.run_install(active={'ownership': prop, 'manifest': previous})
        self.assertTrue(result['installed'])
        self.assertTrue(any(expected in command for command in commands))

    def test_core19_controls_authenticate_before_image_codec_support(self):
        previous = (REPO / 'tests/fixtures/native-compat-v19-final-manifest.json').read_text()
        saved = json.loads(previous)
        expected = 'bce0dedee9a79e538d32b28b36ccd9721e81adc9fb4f8ed75dd12d46835573ec'
        record = next(row for row in history.REVIEWED if row['revision'] == 19)
        self.assertEqual(history.checksum_for(saved), expected)
        self.assertEqual(record['manifest_sha256'], hashlib.sha256(previous.encode()).hexdigest())
        self.assertEqual(record['package_sha256'],
                         '9bdb1d8293160295199f0198b5c12edff39aa92577b652fc348b030b5b97275b')
        for feature, controls in record['policy_controls'].items():
            self.assertEqual(controls['helper'], saved['files_sha256'][feature + '-policy.sh'])
            self.assertEqual(controls['recovery'], saved['files_sha256'][feature + '-recovery.sh'])
        prop = PROPERTY.rsplit('=', 1)[0] + '=19'
        result, commands, _ = self.run_install(active={'ownership': prop, 'manifest': previous})
        self.assertTrue(result['installed'])
        self.assertTrue(any(expected in command for command in commands))
        saved['files_sha256']['platform.sh'] = '0' * 64
        self.assertIsNone(history.checksum_for(saved))
        result, commands, adb = self.run_install(active={
            'ownership': prop, 'manifest': json.dumps(saved)})
        self.assertEqual(result['reason'], 'unreviewed-core-controls')
        self.assertFalse(any('/data/adb/ksud module install ' in command for command in commands))
        adb.assert_not_called()

    def previous_manifest(self):
        return (REPO / 'tests/fixtures/native-compat-v2-manifest.json').read_text()

    def test_reviewed_previous_core_verifies_its_original_assets_before_staging(self):
        previous = self.previous_manifest()
        checksum = history.checksum_for(json.loads(previous))
        self.assertEqual(checksum, history.REVIEWED[0]['checksums_sha256'])
        prop = PROPERTY.rsplit('=', 1)[0] + '=2'
        result, commands, adb = self.run_install(active={'ownership': prop, 'manifest': previous})
        self.assertTrue(result['installed'])
        self.assertTrue(result['reboot_required'])
        verification = next((command for command in commands if 'sha256sum -c SHA256SUMS' in command))
        self.assertIn(checksum, verification)
        stage = next((command for command in commands if 'module install' in command))
        self.assertLess(commands.index(verification), commands.index(stage))
        self.assertEqual(adb.call_count, 1)

    def test_core3_standard_update_uses_frozen_webui_controls_after_core4_change(self):
        previous = (REPO / 'tests/fixtures/native-compat-v3-manifest.json').read_text()
        saved = json.loads(previous)
        self.assertEqual(saved['revision'], 3)
        checksum = history.checksum_for(saved)
        self.assertEqual(checksum, 'fa204e270753618e9ff114c1131d118265eb359da682801679c546105833f355')
        current = json.loads(self.current_manifest())
        self.assertEqual(current['revision'], install.REVISION)
        self.assertNotEqual(saved['files_sha256']['webroot/app.js'], current['files_sha256']['webroot/app.js'])
        prop = PROPERTY.rsplit('=', 1)[0] + '=3'
        result, commands, adb = self.run_install(active={'ownership': prop, 'manifest': previous})
        self.assertTrue(result['installed'])
        self.assertTrue(result['reboot_required'])
        stage = next((command for command in commands if 'module install' in command))
        self.assertIn(checksum, stage)
        self.assertEqual(adb.call_count, 1)

    def test_core4_standard_update_authenticates_the_frozen_package_before_core5(self):
        previous = (REPO / 'tests/fixtures/native-compat-v4-manifest.json').read_text()
        saved = json.loads(previous)
        self.assertEqual(saved['revision'], 4)
        checksum = history.checksum_for(saved)
        self.assertEqual(checksum, 'd50c1ea813e3933dd6e0fb23e1a0a6fd10ea5235151e4cd59d790ae67ed5b036')
        current = json.loads(self.current_manifest())
        self.assertEqual(current['revision'], install.REVISION)
        self.assertNotIn('boot-prerequisites.tsv', saved['files_sha256'])
        self.assertIn('boot-prerequisites.tsv', current['files_sha256'])
        prop = PROPERTY.rsplit('=', 1)[0] + '=4'
        result, commands, adb = self.run_install(active={'ownership': prop, 'manifest': previous})
        self.assertTrue(result['installed'])
        self.assertTrue(result['reboot_required'])
        verification = next((command for command in commands if 'sha256sum -c SHA256SUMS' in command))
        stage = next((command for command in commands if 'module install' in command))
        self.assertIn(checksum, verification)
        self.assertIn(checksum, stage)
        self.assertLess(commands.index(verification), commands.index(stage))
        self.assertEqual(adb.call_count, 1)
        saved['files_sha256']['platform.sh'] = 'a' * 64
        self.assertIsNone(history.checksum_for(saved))
        result, commands, adb = self.run_install(active={'ownership': prop, 'manifest': json.dumps(saved)})
        self.assertEqual(result['reason'], 'unreviewed-core-controls')
        self.assertFalse(any(('module install' in command for command in commands)))
        adb.assert_not_called()

    def test_reviewed_previous_receipt_with_changed_controls_is_preserved(self):

        def changed(command):
            raise RuntimeError('Modified hook under the original receipt')
        prop = PROPERTY.rsplit('=', 1)[0] + '=2'
        result, commands, adb = self.run_install(active={'ownership': prop, 'manifest': self.previous_manifest()}, verify=changed)
        self.assertEqual(result['reason'], 'changed-core-controls')
        self.assertFalse(any(('module install' in command or 'rm -f' in command for command in commands)))
        adb.assert_not_called()

    def test_core5_migration_authenticates_frozen_controls_and_preserves_changes(self):
        previous = (REPO / 'tests/fixtures/native-compat-v5-manifest.json').read_text()
        saved = json.loads(previous)
        self.assertEqual(saved['revision'], 5)
        checksum = history.checksum_for(saved)
        self.assertEqual(checksum, '5981c413d1654fb83959b37b5bed9ede2fb38ecaa95dbd1c87a95a6e30fcfa61')
        current = json.loads(self.current_manifest())
        self.assertNotIn('display-privacy', saved['features'])
        self.assertIn('display-privacy', current['features'])
        prop = PROPERTY.rsplit('=', 1)[0] + '=5'
        result, commands, adb = self.run_install(active={'ownership': prop, 'manifest': previous})
        self.assertTrue(result['installed'])
        self.assertTrue(result['reboot_required'])
        verification = next((command for command in commands if 'sha256sum -c SHA256SUMS' in command))
        stage = next((command for command in commands if 'module install' in command))
        self.assertIn(checksum, verification)
        self.assertIn(checksum, stage)
        self.assertLess(commands.index(verification), commands.index(stage))
        self.assertEqual(adb.call_count, 1)
        saved['files_sha256']['runtime.sh'] = 'a' * 64
        self.assertIsNone(history.checksum_for(saved))
        result, commands, adb = self.run_install(active={'ownership': prop, 'manifest': json.dumps(saved)})
        self.assertEqual(result['reason'], 'unreviewed-core-controls')
        self.assertFalse(any(('module install' in command for command in commands)))
        adb.assert_not_called()

    def test_frozen_development_core6_migrates_only_its_exact_verified_controls(self):
        previous = (REPO / 'tests/fixtures/native-compat-v6-development-manifest.json').read_text()
        saved = json.loads(previous)
        self.assertEqual(saved['revision'], 6)
        expected = '2ed45419f0d19c78d4f1e1665ed49042df51dd9f42ee9ab1019a54bd024384d6'
        self.assertEqual(history.checksum_for(saved), expected)
        self.assertNotEqual(saved, json.loads(self.current_manifest()))
        result, commands, adb = self.run_install(active={'ownership': PROPERTY.rsplit('=', 1)[0] + '=6', 'manifest': previous})
        self.assertTrue(result['installed'])
        self.assertTrue(result['reboot_required'])
        verification = next((command for command in commands if 'sha256sum -c SHA256SUMS' in command))
        stage = next((command for command in commands if 'module install' in command))
        self.assertIn(expected, verification)
        self.assertIn(expected, stage)
        self.assertLess(commands.index(verification), commands.index(stage))
        self.assertEqual(adb.call_count, 1)
        saved['files_sha256']['display-privacy-capability.tsv'] = '0' * 64
        self.assertIsNone(history.checksum_for(saved))
        result, commands, adb = self.run_install(active={'ownership': PROPERTY.rsplit('=', 1)[0] + '=6', 'manifest': json.dumps(saved)})
        self.assertEqual(result['reason'], 'unreviewed-core-controls')
        adb.assert_not_called()

    def test_final_frozen_core7_controls_are_authenticated_before_core8_policies(self):
        previous = (REPO / 'tests/fixtures/native-compat-v7-final-manifest.json').read_text()
        saved = json.loads(previous)
        self.assertEqual(saved['revision'], 7)
        expected = '2e671f8403f731eadd3a03d02458ef5d35c72fe2c5b099bbda01bc294d97d56e'
        self.assertEqual(history.checksum_for(saved), expected)
        record = next((row for row in history.REVIEWED if row['revision'] == 7))
        for feature, controls in record['policy_controls'].items():
            self.assertEqual(controls['helper'], saved['files_sha256'][feature + '-policy.sh'])
            self.assertEqual(controls['recovery'], saved['files_sha256'][feature + '-recovery.sh'])
        prop = PROPERTY.rsplit('=', 1)[0] + '=7'
        result, commands, adb = self.run_install(active={'ownership': prop, 'manifest': previous})
        self.assertTrue(result['installed'])
        self.assertTrue(result['reboot_required'])
        self.assertTrue(any((expected in command for command in commands if 'sha256sum -c SHA256SUMS' in command)))
        self.assertEqual(adb.call_count, 1)
        saved['files_sha256']['finddevice-policy.sh'] = 'a' * 64
        self.assertIsNone(history.checksum_for(saved))

    def test_final_frozen_core8_controls_are_authenticated_before_snapshot_migration(self):
        previous = (REPO / 'tests/fixtures/native-compat-v8-final-manifest.json').read_text()
        saved = json.loads(previous)
        self.assertEqual(saved['revision'], 8)
        expected = '35b825474def8b02bdfdd412998436c0bc4a4522b2f278712632399488c401fa'
        self.assertEqual(history.checksum_for(saved), expected)
        record = next((row for row in history.REVIEWED if row['revision'] == 8))
        for feature, controls in record['policy_controls'].items():
            self.assertEqual(controls['helper'], saved['files_sha256'][feature + '-policy.sh'])
            self.assertEqual(controls['recovery'], saved['files_sha256'][feature + '-recovery.sh'])
        prop = PROPERTY.rsplit('=', 1)[0] + '=8'
        result, commands, adb = self.run_install(active={'ownership': prop, 'manifest': previous})
        self.assertTrue(result['installed'])
        self.assertTrue(result['reboot_required'])
        verification = next((command for command in commands if 'sha256sum -c SHA256SUMS' in command))
        stage = next((command for command in commands if 'module install' in command))
        self.assertIn(expected, verification)
        self.assertIn(expected, stage)
        self.assertLess(commands.index(verification), commands.index(stage))
        self.assertEqual(adb.call_count, 1)
        saved['files_sha256']['vendor-ims-policy.sh'] = 'a' * 64
        self.assertIsNone(history.checksum_for(saved))
        result, commands, adb = self.run_install(active={'ownership': prop, 'manifest': json.dumps(saved)})
        self.assertEqual(result['reason'], 'unreviewed-core-controls')
        self.assertFalse(any(('module install' in command for command in commands)))
        adb.assert_not_called()

    def test_final_frozen_core9_controls_are_authenticated_before_vendor_ims_gate(self):
        previous = (REPO / 'tests/fixtures/native-compat-v9-final-manifest.json').read_text()
        saved = json.loads(previous)
        self.assertEqual(saved['revision'], 9)
        expected = 'b8cd95fd879c49eb07d6d59c9cc9bf8c5b8b08361fda4d9a71c403f6853b1b6e'
        self.assertEqual(history.checksum_for(saved), expected)
        record = next((row for row in history.REVIEWED if row['revision'] == 9))
        for feature, controls in record['policy_controls'].items():
            self.assertEqual(controls['helper'], saved['files_sha256'][feature + '-policy.sh'])
            self.assertEqual(controls['recovery'], saved['files_sha256'][feature + '-recovery.sh'])
        prop = PROPERTY.rsplit('=', 1)[0] + '=9'
        result, commands, adb = self.run_install(active={'ownership': prop, 'manifest': previous})
        self.assertTrue(result['installed'])
        self.assertTrue(result['reboot_required'])
        verification = next((command for command in commands if 'sha256sum -c SHA256SUMS' in command))
        stage = next((command for command in commands if 'module install' in command))
        self.assertIn(expected, verification)
        self.assertIn(expected, stage)
        self.assertLess(commands.index(verification), commands.index(stage))
        self.assertEqual(adb.call_count, 1)
        saved['files_sha256']['finddevice-policy.sh'] = 'a' * 64
        self.assertIsNone(history.checksum_for(saved))
        result, commands, adb = self.run_install(active={'ownership': prop, 'manifest': json.dumps(saved)})
        self.assertEqual(result['reason'], 'unreviewed-core-controls')
        self.assertFalse(any(('module install' in command for command in commands)))
        adb.assert_not_called()

    def test_final_frozen_core10_controls_are_authenticated_before_graphics_perf_gate(self):
        previous = (REPO / 'tests/fixtures/native-compat-v10-final-manifest.json').read_text()
        saved = json.loads(previous)
        self.assertEqual(saved['revision'], 10)
        expected = 'eafe2c308408582aa9e89d6b37afb4baee2a5b74905afaabaf5840efc36d4af8'
        self.assertEqual(history.checksum_for(saved), expected)
        record = next((row for row in history.REVIEWED if row['revision'] == 10))
        for feature, controls in record['policy_controls'].items():
            self.assertEqual(controls['helper'], saved['files_sha256'][feature + '-policy.sh'])
            self.assertEqual(controls['recovery'], saved['files_sha256'][feature + '-recovery.sh'])
        prop = PROPERTY.rsplit('=', 1)[0] + '=10'
        result, commands, adb = self.run_install(active={'ownership': prop, 'manifest': previous})
        self.assertTrue(result['installed'])
        self.assertTrue(result['reboot_required'])
        verification = next((command for command in commands if 'sha256sum -c SHA256SUMS' in command))
        stage = next((command for command in commands if 'module install' in command))
        self.assertIn(expected, verification)
        self.assertIn(expected, stage)
        self.assertLess(commands.index(verification), commands.index(stage))
        self.assertEqual(adb.call_count, 1)
        saved['files_sha256']['runtime.sh'] = 'a' * 64
        self.assertIsNone(history.checksum_for(saved))
        result, commands, adb = self.run_install(active={'ownership': prop, 'manifest': json.dumps(saved)})
        self.assertEqual(result['reason'], 'unreviewed-core-controls')
        self.assertFalse(any(('module install' in command for command in commands)))
        adb.assert_not_called()

    def test_final_frozen_core11_controls_are_authenticated_before_rear_gesture_helper(self):
        previous = (REPO / 'tests/fixtures/native-compat-v11-final-manifest.json').read_text()
        saved = json.loads(previous)
        self.assertEqual(saved['revision'], 11)
        expected = '340f419d0cd201e96c9af1b62ec9338b6a1ba883d96ed795c8a6008139e87f23'
        self.assertEqual(history.checksum_for(saved), expected)
        record = next((row for row in history.REVIEWED if row['revision'] == 11))
        for feature, controls in record['policy_controls'].items():
            self.assertEqual(controls['helper'], saved['files_sha256'][feature + '-policy.sh'])
            self.assertEqual(controls['recovery'], saved['files_sha256'][feature + '-recovery.sh'])
        prop = PROPERTY.rsplit('=', 1)[0] + '=11'
        result, commands, adb = self.run_install(active={'ownership': prop, 'manifest': previous})
        self.assertTrue(result['installed'])
        self.assertTrue(result['reboot_required'])
        verification = next((command for command in commands if 'sha256sum -c SHA256SUMS' in command))
        stage = next((command for command in commands if 'module install' in command))
        self.assertIn(expected, verification)
        self.assertIn(expected, stage)
        self.assertLess(commands.index(verification), commands.index(stage))
        self.assertEqual(adb.call_count, 1)
        saved['files_sha256']['runtime.sh'] = 'a' * 64
        self.assertIsNone(history.checksum_for(saved))
        result, commands, adb = self.run_install(active={'ownership': prop, 'manifest': json.dumps(saved)})
        self.assertEqual(result['reason'], 'unreviewed-core-controls')
        self.assertFalse(any(('module install' in command for command in commands)))
        adb.assert_not_called()

    def test_final_frozen_core12_controls_are_authenticated_before_rear_input_state_recovery(self):
        previous = (REPO / 'tests/fixtures/native-compat-v12-final-manifest.json').read_text()
        saved = json.loads(previous)
        self.assertEqual(saved['revision'], 12)
        expected = 'c7bbf4a27b0226318be7d2d9fb3ffc384cb798db0f836dcab2ecb3ebcb272cc7'
        self.assertEqual(history.checksum_for(saved), expected)
        record = next((row for row in history.REVIEWED if row['revision'] == 12))
        for feature, controls in record['policy_controls'].items():
            self.assertEqual(controls['helper'], saved['files_sha256'][feature + '-policy.sh'])
            self.assertEqual(controls['recovery'], saved['files_sha256'][feature + '-recovery.sh'])
        prop = PROPERTY.rsplit('=', 1)[0] + '=12'
        result, commands, adb = self.run_install(active={'ownership': prop, 'manifest': previous})
        self.assertTrue(result['installed'])
        self.assertTrue(result['reboot_required'])
        verification = next((command for command in commands if 'sha256sum -c SHA256SUMS' in command))
        stage = next((command for command in commands if 'module install' in command))
        self.assertIn(expected, verification)
        self.assertIn(expected, stage)
        self.assertLess(commands.index(verification), commands.index(stage))
        self.assertEqual(adb.call_count, 1)
        saved['files_sha256']['rear-wake.jar'] = 'a' * 64
        self.assertIsNone(history.checksum_for(saved))
        result, commands, adb = self.run_install(active={'ownership': prop, 'manifest': json.dumps(saved)})
        self.assertEqual(result['reason'], 'unreviewed-core-controls')
        self.assertFalse(any(('module install' in command for command in commands)))
        adb.assert_not_called()

    def test_final_frozen_core13_controls_authenticate_before_hardware_capability_changes(self):
        previous = (REPO / 'tests/fixtures/native-compat-v13-final-manifest.json').read_text()
        saved = json.loads(previous)
        expected = 'dc5017041281acfb0b4d5df0fdcabdda17803789c818658fa18b7b7b1b2d52c7'
        self.assertEqual(saved['revision'], 13)
        self.assertEqual(history.checksum_for(saved), expected)
        record = next((row for row in history.REVIEWED if row['revision'] == 13))
        for feature, controls in record['policy_controls'].items():
            self.assertEqual(controls['helper'], saved['files_sha256'][feature + '-policy.sh'])
            self.assertEqual(controls['recovery'], saved['files_sha256'][feature + '-recovery.sh'])
        prop = PROPERTY.rsplit('=', 1)[0] + '=13'
        result, commands, adb = self.run_install(active={'ownership': prop, 'manifest': previous})
        self.assertTrue(result['installed'])
        self.assertTrue(result['reboot_required'])
        verification = next((command for command in commands if 'sha256sum -c SHA256SUMS' in command))
        stage = next((command for command in commands if 'module install' in command))
        self.assertIn(expected, verification)
        self.assertIn(expected, stage)
        self.assertLess(commands.index(verification), commands.index(stage))
        self.assertEqual(adb.call_count, 1)
        saved['files_sha256']['platform.sh'] = 'a' * 64
        self.assertIsNone(history.checksum_for(saved))
        result, commands, adb = self.run_install(active={'ownership': prop, 'manifest': json.dumps(saved)})
        self.assertEqual(result['reason'], 'unreviewed-core-controls')
        self.assertFalse(any(('module install' in command for command in commands)))
        adb.assert_not_called()

    def test_final_deployed_core14_controls_authenticate_before_stacked_bind_fix(self):
        previous = (REPO / 'tests/fixtures/native-compat-v14-final-manifest.json').read_text()
        saved = json.loads(previous)
        expected = 'f49c3f709991edb809dece1997e0693bae5385b4031ab3fe64679b7da9f0888e'
        self.assertEqual(saved['revision'], 14)
        self.assertEqual(history.checksum_for(saved), expected)
        record = next((row for row in history.REVIEWED if row['revision'] == 14))
        for feature, controls in record['policy_controls'].items():
            self.assertEqual(controls['helper'], saved['files_sha256'][feature + '-policy.sh'])
            self.assertEqual(controls['recovery'], saved['files_sha256'][feature + '-recovery.sh'])
        prop = PROPERTY.rsplit('=', 1)[0] + '=14'
        result, commands, adb = self.run_install(active={'ownership': prop, 'manifest': previous})
        self.assertTrue(result['installed'])
        self.assertTrue(result['reboot_required'])
        verification = next((command for command in commands if 'sha256sum -c SHA256SUMS' in command))
        stage = next((command for command in commands if 'module install' in command))
        self.assertIn(expected, verification)
        self.assertIn(expected, stage)
        self.assertLess(commands.index(verification), commands.index(stage))
        self.assertEqual(adb.call_count, 1)
        saved['files_sha256']['platform.sh'] = 'a' * 64
        self.assertIsNone(history.checksum_for(saved))
        result, commands, adb = self.run_install(active={'ownership': prop, 'manifest': json.dumps(saved)})
        self.assertEqual(result['reason'], 'unreviewed-core-controls')
        self.assertFalse(any(('module install' in command for command in commands)))
        adb.assert_not_called()

    def test_final_deployed_core15_controls_authenticate_before_scene_sensor_guard(self):
        fixture = REPO / 'tests/fixtures/native-compat-v15-final-manifest.json'
        previous_bytes = fixture.read_bytes()
        previous = previous_bytes.decode()
        saved = json.loads(previous)
        expected = '71fd439241df235482803e155a42bb2486f6786aed89f31737d71d36905eb016'
        self.assertEqual(hashlib.sha256(previous_bytes).hexdigest(), 'e85fee78faae160dcffd6725e566a006b86642d22da7891c33daa91f1c852d89')
        self.assertEqual(saved['revision'], 15)
        self.assertEqual(history.checksum_for(saved), expected)
        record = next((row for row in history.REVIEWED if row['revision'] == 15))
        self.assertEqual(record['package_sha256'], 'bc0330d23683216c504beb38fdb7e81e521c4d7085f13e9e3d1ac37fa231a8fa')
        for feature, controls in record['policy_controls'].items():
            self.assertEqual(controls['helper'], saved['files_sha256'][feature + '-policy.sh'])
            self.assertEqual(controls['recovery'], saved['files_sha256'][feature + '-recovery.sh'])
        self.assertEqual(json.loads(self.current_manifest())['revision'], install.REVISION)
        prop = PROPERTY.rsplit('=', 1)[0] + '=15'
        result, commands, adb = self.run_install(active={'ownership': prop, 'manifest': previous})
        self.assertTrue(result['installed'])
        self.assertTrue(result['reboot_required'])
        verification = next((command for command in commands if 'sha256sum -c SHA256SUMS' in command))
        stage = next((command for command in commands if 'module install' in command))
        self.assertIn(expected, verification)
        self.assertIn(expected, stage)
        self.assertLess(commands.index(verification), commands.index(stage))
        self.assertEqual(adb.call_count, 1)
        saved['files_sha256']['platform.sh'] = 'a' * 64
        self.assertIsNone(history.checksum_for(saved))
        result, commands, adb = self.run_install(active={'ownership': prop, 'manifest': json.dumps(saved)})
        self.assertEqual(result['reason'], 'unreviewed-core-controls')
        self.assertFalse(any(('module install' in command for command in commands)))
        adb.assert_not_called()

    def test_final_deployed_core16_controls_authenticate_before_verified_cache_reuse(self):
        previous_bytes = (REPO / 'tests/fixtures/native-compat-v16-final-manifest.json').read_bytes()
        saved = json.loads(previous_bytes)
        expected = '78ea6b5cb42eca9a8c22755e2edc4542be9e30a1a6a140e616195b0f7a59f85d'
        self.assertEqual(hashlib.sha256(previous_bytes).hexdigest(), '907bfe60a7814493facc12f0fa1a8dff708157d089bf21205451b7b79aff9985')
        self.assertEqual(saved['revision'], 16)
        self.assertEqual(history.checksum_for(saved), expected)
        record = next((row for row in history.REVIEWED if row['revision'] == 16))
        self.assertEqual(record['package_sha256'], '42ccf7b92c0ba41a08ee4b5e63ff806d09827adc29fdb4d4c8ae3263615f3417')
        for feature, controls in record['policy_controls'].items():
            self.assertEqual(controls['helper'], saved['files_sha256'][feature + '-policy.sh'])
            self.assertEqual(controls['recovery'], saved['files_sha256'][feature + '-recovery.sh'])
        prop = PROPERTY.rsplit('=', 1)[0] + '=16'
        result, commands, adb = self.run_install(active={'ownership': prop, 'manifest': previous_bytes.decode()})
        self.assertTrue(result['installed'])
        self.assertTrue(result['reboot_required'])
        verification = next((command for command in commands if 'sha256sum -c SHA256SUMS' in command))
        stage = next((command for command in commands if 'module install' in command))
        self.assertIn(expected, verification)
        self.assertIn(expected, stage)
        self.assertLess(commands.index(verification), commands.index(stage))
        self.assertEqual(adb.call_count, 1)
        saved['files_sha256']['runtime.sh'] = 'a' * 64
        self.assertIsNone(history.checksum_for(saved))
        result, commands, adb = self.run_install(active={'ownership': prop, 'manifest': json.dumps(saved)})
        self.assertEqual(result['reason'], 'unreviewed-core-controls')
        self.assertFalse(any(('module install' in command for command in commands)))
        adb.assert_not_called()

    def test_final_deployed_core17_controls_authenticate_before_process_map_batching(self):
        previous_bytes = (REPO / 'tests/fixtures/native-compat-v17-final-manifest.json').read_bytes()
        saved = json.loads(previous_bytes)
        expected = '31e5461352a04a5771e2dbfd2a9ecba429451be03dc5c3d53595eb28d5cd1910'
        self.assertEqual(hashlib.sha256(previous_bytes).hexdigest(), '706e655f1a2235dd2284803c68dec063c7b52831bea41c1d78ac4c601e25e687')
        self.assertEqual(saved['revision'], 17)
        self.assertEqual(history.checksum_for(saved), expected)
        record = next((row for row in history.REVIEWED if row['revision'] == 17))
        self.assertEqual(record['package_sha256'], '797ff25ee6b32c212ed6cf38eb7228cc50dd9ae33de61a31c17737bd849cc66e')
        for feature, controls in record['policy_controls'].items():
            self.assertEqual(controls['helper'], saved['files_sha256'][feature + '-policy.sh'])
            self.assertEqual(controls['recovery'], saved['files_sha256'][feature + '-recovery.sh'])
        prop = PROPERTY.rsplit('=', 1)[0] + '=17'
        result, commands, adb = self.run_install(active={'ownership': prop, 'manifest': previous_bytes.decode()})
        self.assertTrue(result['installed'])
        self.assertTrue(result['reboot_required'])
        verification = next((command for command in commands if 'sha256sum -c SHA256SUMS' in command))
        stage = next((command for command in commands if 'module install' in command))
        self.assertIn(expected, verification)
        self.assertIn(expected, stage)
        self.assertLess(commands.index(verification), commands.index(stage))
        self.assertEqual(adb.call_count, 1)
        saved['files_sha256']['runtime.sh'] = 'a' * 64
        self.assertIsNone(history.checksum_for(saved))
        result, commands, adb = self.run_install(active={'ownership': prop, 'manifest': json.dumps(saved)})
        self.assertEqual(result['reason'], 'unreviewed-core-controls')
        self.assertFalse(any(('module install' in command for command in commands)))
        adb.assert_not_called()

    def test_final_frozen_core6_migrates_only_complete_controls_to_policy_revision(self):
        previous = (REPO / 'tests/fixtures/native-compat-v6-final-manifest.json').read_text()
        saved = json.loads(previous)
        self.assertEqual(saved['revision'], 6)
        expected = '57f2b841a029072510c781fd414fa470d09da66745efd027b4c892049b43755f'
        self.assertEqual(history.checksum_for(saved), expected)
        current = json.loads(self.current_manifest())
        self.assertIn('finddevice', current['features'])
        self.assertIn('vendor-ims', current['features'])
        self.assertNotIn('finddevice', saved['features'])
        prop = PROPERTY.rsplit('=', 1)[0] + '=6'
        result, commands, adb = self.run_install(active={'ownership': prop, 'manifest': previous})
        self.assertTrue(result['installed'])
        self.assertTrue(result['reboot_required'])
        self.assertTrue(any((expected in command for command in commands if 'sha256sum -c SHA256SUMS' in command)))
        self.assertEqual(adb.call_count, 1)
        saved['files_sha256']['platform.sh'] = 'a' * 64
        self.assertIsNone(history.checksum_for(saved))

    def test_reviewed_intermediate_core6_accepts_only_the_complete_frozen_producer(self):
        previous = (REPO / 'tests/fixtures/native-compat-v6-intermediate-manifest.json').read_text()
        saved = json.loads(previous)
        expected = '03b675711f0d24633e688dd01fbeff8be5a12e16100ac766b2e4519fe477a337'
        self.assertEqual(history.checksum_for(saved), expected)
        current = json.loads(self.current_manifest())
        self.assertEqual(saved['files_sha256']['runtime.sh'], '16d3e14b34694eee15806bc007ef87b78315ec08e6ac4fa4223d7d15327d7b9e')
        self.assertNotEqual(saved['files_sha256']['runtime.sh'], current['files_sha256']['runtime.sh'])
        result, commands, adb = self.run_install(active={'ownership': PROPERTY.rsplit('=', 1)[0] + '=6', 'manifest': previous})
        self.assertTrue(result['installed'])
        self.assertTrue(result['reboot_required'])
        verify = next((command for command in commands if 'sha256sum -c SHA256SUMS' in command))
        stage = next((command for command in commands if 'module install' in command))
        self.assertIn(expected, verify)
        self.assertIn(expected, stage)
        self.assertLess(commands.index(verify), commands.index(stage))
        self.assertEqual(adb.call_count, 1)
        saved['files_sha256']['display-privacy-capability.tsv'] = 'a' * 64
        self.assertIsNone(history.checksum_for(saved))
        result, commands, adb = self.run_install(active={'ownership': PROPERTY.rsplit('=', 1)[0] + '=6', 'manifest': json.dumps(saved)})
        self.assertEqual(result['reason'], 'unreviewed-core-controls')
        adb.assert_not_called()

    def test_unknown_control_revision_never_uses_guest_receipt_as_authorization(self):
        previous = json.loads(self.previous_manifest())
        previous['files_sha256']['service.sh'] = 'b' * 64
        self.assertIsNone(history.checksum_for(previous))
        prop = PROPERTY.rsplit('=', 1)[0] + '=2'
        result, commands, adb = self.run_install(active={'ownership': prop, 'manifest': json.dumps(previous)})
        self.assertEqual(result['reason'], 'unreviewed-core-controls')
        self.assertFalse(any(('module install' in command or 'features.disabled' in command for command in commands)))
        adb.assert_not_called()

class NativeModuleShellGuardTests(unittest.TestCase):
    """Execute the emitted read/verification guards on disposable local files."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='hyperos-native-guards-')
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name)
        self.active = self.folder / 'active'
        self.pending = self.folder / 'pending'
        if shutil.which('sha256sum'):
            self.hash_command = shlex.quote(shutil.which('sha256sum'))
        elif shutil.which('shasum'):
            self.hash_command = shlex.quote(shutil.which('shasum')) + ' -a 256'
        else:
            self.skipTest('No local SHA-256 utility is available.')

    def shell(self, command):
        translated = command.replace(install.PENDING, str(self.pending)).replace(install.MODULE, str(self.active))
        translated = translated.replace('/data/adb/ksu/bin/busybox sha256sum', self.hash_command)
        result = subprocess.run(['sh', '-c', 'set -e\n' + translated], capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError('Local module guard rejected unsafe or mismatched assets.')
        return result.stdout.strip()

    def test_exact_assets_pass_but_rewritten_checksums_cannot_authenticate_tampered_script(self):
        files = package.module_files()
        self.active.mkdir()
        for name, body in files.items():
            target = self.active / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
        expected = hashlib.sha256(files['SHA256SUMS']).hexdigest()
        with patch.object(install, 'root', side_effect=lambda config, command: self.shell(command)):
            install._verify_assets({}, install.MODULE, expected)
            files['runtime.sh'] += b'\n# Changed outside the known package.\n'
            (self.active / 'runtime.sh').write_bytes(files['runtime.sh'])
            checksum = ''.join((hashlib.sha256(body).hexdigest() + '  ' + name + '\n' for name, body in sorted(files.items()) if name != 'SHA256SUMS'))
            (self.active / 'SHA256SUMS').write_text(checksum)
            with self.assertRaisesRegex(RuntimeError, 'rejected'):
                install._verify_assets({}, install.MODULE, expected)

    def test_dangling_remove_link_is_preserved_as_a_lifecycle_flag(self):
        self.active.mkdir()
        (self.active / 'module.prop').write_text(PROPERTY + '\n')
        (self.active / 'remove').symlink_to(self.folder / 'missing')
        with patch.object(install, 'root', side_effect=lambda config, command: self.shell(command)):
            self.assertEqual(install._module({}, install.MODULE)['flags'], ['remove'])

    def test_control_alias_or_late_hook_edit_is_not_replaced(self):
        files = package.module_files()
        self.active.mkdir()
        for name, body in files.items():
            target = self.active / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
        checksum = hashlib.sha256(files['SHA256SUMS']).hexdigest()
        hook = self.active / 'service.sh'
        foreign = self.folder / 'foreign-hook'
        hook.rename(foreign)
        hook.symlink_to(foreign)
        with patch.object(install, 'root', side_effect=lambda config, command: self.shell(command)), self.assertRaises(RuntimeError):
            install._verify_assets({}, install.MODULE, checksum)
        self.assertTrue(hook.is_symlink())
        self.assertEqual(foreign.read_bytes(), files['service.sh'])
        hook.unlink()
        foreign.rename(hook)
        active = {'properties': (self.active / 'module.prop').read_text().strip(), 'checksums_sha256': checksum}
        hook.write_bytes(files['service.sh'] + b'\n# Changed after authentication\n')
        with self.assertRaises(RuntimeError):
            self.shell(install._stage_guard(active))
        self.assertFalse(self.pending.exists())

    def test_module_directory_link_is_not_followed(self):
        self.pending.mkdir()
        (self.pending / 'module.prop').write_text(PROPERTY + '\n')
        self.active.symlink_to(self.pending, target_is_directory=True)
        with patch.object(install, 'root', side_effect=lambda config, command: self.shell(command)), self.assertRaisesRegex(RuntimeError, 'rejected'):
            install._module({}, install.MODULE)

    def test_preinstall_guard_rejects_a_new_pending_stage(self):
        self.pending.mkdir()
        marker = self.folder / 'should-not-install'
        with self.assertRaisesRegex(RuntimeError, 'rejected'):
            self.shell(install._stage_guard(None) + 'touch ' + shlex.quote(str(marker)))
        self.assertFalse(marker.exists())

    def test_preinstall_guard_rejects_a_late_user_disable_choice(self):
        self.active.mkdir()
        (self.active / 'module.prop').write_text(PROPERTY + '\n')
        (self.active / 'disable').touch()
        marker = self.folder / 'should-not-install'
        with self.assertRaisesRegex(RuntimeError, 'rejected'):
            self.shell(install._stage_guard({'properties': PROPERTY}) + 'touch ' + shlex.quote(str(marker)))
        self.assertFalse(marker.exists())

    def test_preinstall_guard_accepts_unchanged_owned_active_module(self):
        self.active.mkdir()
        (self.active / 'module.prop').write_text(PROPERTY + '\n')
        self.shell(install._stage_guard({'properties': PROPERTY}))

if __name__ == '__main__':
    unittest.main()
