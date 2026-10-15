"""Consolidated unit tests for OS4 launch runtime:
boot migration, optional patch outcomes, and userdata initialization.
"""
from contextlib import ExitStack
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

REPO = Path(__file__).resolve().parents[1]
ROOT = REPO
sys.path.insert(0, str(REPO / 'scripts'))

import apply_boot_service_fix as boot
import apply_native_compat as native
import launch
import os4_defaults
from patch_outcome import UnsupportedPatch
from userdata_resize import OfflineBackupRequiredError, OpaqueFilesystemError



# --- tests/test_launch_boot_migration.py ---

'Keep optional legacy module migration ordered and local during initialization.'

class LaunchBootMigrationTests(unittest.TestCase):

    def initialize(self, supported=True, failure=None):
        order = []
        config = {'name': 'Any_Renamed_AVD', 'port': 5590}

        def adb(_config, *arguments, **_kwargs):
            command = arguments[-1]
            if command == 'id':
                output = 'uid=2000(shell)'
            elif command == "su -W -c 'id'":
                output = 'uid=0(root)'
            elif 'feature set selinux_hide' in command:
                output = 'uid=0(root)\nEnforcing\n'
            elif command == 'getprop sys.boot_completed':
                output = '1\n'
            elif command == 'pm path me.weishu.kernelsu':
                output = 'package:/system/app/KernelSU.apk\n'
            else:
                output = ''
            return Mock(returncode=0, stdout=output, stderr='')

        def kernel(_config):
            order.append('kernel')
            if failure:
                raise RuntimeError(failure)
            return {'migrated': True, 'reboot_required': True}

        def uninstall(_config):
            order.append('uninstall')
            return {'migrated': False, 'unsupported': True, 'reason': 'Unknown hook is preserved.'}

        def standard(_config, platform_context=None):
            order.append('native')

        def lifecycle(_config):
            order.append('lifecycle')
            return {'migrated': False}
        with tempfile.TemporaryDirectory() as temporary, patch.object(launch, 'ROOT', Path(temporary)), patch.object(launch, 'is_os4', return_value=supported), patch.object(launch, 'adb', side_effect=adb) as transport, patch.object(os4_defaults, 'apply_sensor_defaults'), patch.object(boot, 'migrate_kernel_helper', side_effect=kernel), patch.object(boot, 'migrate_uninstall_hook', side_effect=uninstall), patch.object(boot, 'migrate_lifecycle_hooks', side_effect=lifecycle), patch.object(native, 'install', side_effect=standard), patch('core_context.load', return_value={}), patch('apply_app_compat.install_prebuilt', return_value={'installed': True}), patch('sys.stdout', new_callable=io.StringIO) as output:
            launch.initialize(config)
            record = json.loads((Path(temporary) / 'local/last-boot.json').read_text())
        return (order, output.getvalue(), transport.call_args_list, record)

    def test_os4_migrates_known_hooks_before_native_module_installation(self):
        order, output, calls, record = self.initialize()
        self.assertEqual(order, ['kernel', 'uninstall', 'lifecycle', 'native'])
        self.assertIn('current user settings are preserved', output)
        self.assertIn('Unknown hook is preserved', output)
        self.assertFalse(any(('reboot' in str(call) or 'ctl.restart' in str(call) for call in calls)))
        self.assertEqual(record['name'], 'Any_Renamed_AVD')

    def test_unknown_legacy_source_does_not_abort_native_initialization(self):
        order, output, _, _ = self.initialize(failure='Unknown owned helper checksum')
        self.assertEqual(order, ['kernel', 'uninstall', 'lifecycle', 'native'])
        self.assertIn('kernel helper is preserved: Unknown owned helper checksum', output)
        self.assertIn('HyperOS is ready', output)

    def test_other_os_does_not_invoke_os4_migrations(self):
        order, _, _, _ = self.initialize(supported=False)
        self.assertEqual(order, [])

if __name__ == '__main__':
    unittest.main()


# --- tests/test_launch_optional_patches.py ---

'Keep unknown optional workloads local without masking integrity failures.'

class OptionalPatchTests(unittest.TestCase):

    def test_only_explicit_untouched_outcome_is_skipped(self):
        outcomes = {}
        with patch('sys.stdout', new_callable=io.StringIO):
            launch.optional_patch(outcomes, 'weather', Mock(side_effect=UnsupportedPatch('Unknown APK')))
        self.assertEqual(outcomes, {'weather': {'state': 'unsupported', 'reason': 'Unknown APK'}})
        for failure in (RuntimeError('Unknown owned payload'), OSError('read failure'), subprocess.CalledProcessError(1, 'adb')):
            with self.subTest(error=failure), self.assertRaises(type(failure)):
                launch.optional_patch({}, 'weather', Mock(side_effect=failure))

    def _initialize(self, source, failure=None, mandatory_failure=None):
        order = []

        def transport(_config, *args, **_kwargs):
            command = args[-1]
            output = 'uid=2000(shell)' if command == 'id' else 'uid=0(root)' if command == "su -W -c 'id'" else 'uid=0(root)\nEnforcing' if 'feature set selinux_hide' in command else '1' if command == 'getprop sys.boot_completed' else 'package:/system/app/KernelSU.apk' if command == 'pm path me.weishu.kernelsu' else ''
            return Mock(returncode=0, stdout=output, stderr='')

        def record(name, error=None):

            def call(*_args, **_kwargs):
                order.append(name)
                if error:
                    raise error
                return {'installed': True, 'features': ['weather', 'oem-camera', 'parrot-camera']}
            return call
        imports = {'os4_defaults.apply_sensor_defaults': Mock(), 'os4_defaults.apply_runtime': record('defaults'), 'os4_pad.apply_runtime': record('defaults'), 'os4_pad.align_window': record('window'), 'apply_native_compat.install': record('native', mandatory_failure), 'core_context.load': Mock(return_value={'schema': 1, 'identity_sources': []}), 'apply_app_compat.install_prebuilt': record('apps', failure), 'apply_flutter_fix.install': Mock(side_effect=AssertionError('Legacy Flutter installer invoked')), 'apply_navigation_fix.install': Mock(side_effect=AssertionError('Legacy navigation installer invoked')), 'apply_weather_fix.install': Mock(side_effect=AssertionError('Legacy Weather installer invoked')), 'apply_assistant_fix.install': Mock(side_effect=AssertionError('Legacy XiaoAI installer invoked')), 'apply_xiaomi_camera_fix.install': Mock(side_effect=AssertionError('Legacy Phone camera invoked')), 'apply_pad_camera_fix.install': Mock(side_effect=AssertionError('Legacy Pad ANGLE invoked')), 'apply_pad_camera_native_fix.install': Mock(side_effect=AssertionError('Legacy Pad camera invoked'))}
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            root = Path(temporary)
            (root / 'local').mkdir()
            (root / 'local/build.json').write_text(json.dumps({'source': source}))
            stack.enter_context(patch.object(launch, 'ROOT', root))
            stack.enter_context(patch.object(launch, 'adb', side_effect=transport))
            stack.enter_context(patch.object(launch, 'migrate_boot_service_helpers', side_effect=record('migration')))
            stack.enter_context(patch('sys.stdout', new_callable=io.StringIO))
            for target, effect in imports.items():
                stack.enter_context(patch(target, side_effect=effect))
            launch.initialize({'name': 'Renamed_Device', 'port': 5586, 'camera_bridge': True})
            result = json.loads((root / 'local/last-boot.json').read_text())
        return (order, result)

    def test_phone_uses_two_common_owners_without_per_app_installers(self):
        order, result = self._initialize('official-hongkong-ota')
        self.assertEqual(order, ['defaults', 'migration', 'native', 'apps'])
        self.assertEqual(set(result['patch_outcomes']), {'core', 'apps'})

    def test_pad_uses_the_same_common_owners_as_phone(self):
        order, result = self._initialize('official-yingtian-ota')
        self.assertEqual(order, ['defaults', 'window', 'migration', 'native', 'apps'])
        self.assertEqual(set(result['patch_outcomes']), {'core', 'apps'})

    def test_mandatory_shared_engine_failure_stays_fatal(self):
        with self.assertRaisesRegex(RuntimeError, 'Unknown shared engine'):
            self._initialize('official-hongkong-ota', mandatory_failure=RuntimeError('Unknown shared engine'))

    def test_optional_integrity_failure_stays_fatal(self):
        with self.assertRaisesRegex(RuntimeError, 'Unrelated module'):
            self._initialize('official-yingtian-ota', failure=RuntimeError('Unrelated module'))

if __name__ == '__main__':
    unittest.main()


# --- tests/test_launch_userdata.py ---

'Guard launch-time userdata creation and offline filesystem preparation.'

class LaunchUserdataTests(unittest.TestCase):

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.name = 'Renamed_User_AVD'
        self.avd = self.root / 'avd' / (self.name + '.avd')
        self.avd.mkdir(parents=True)
        self.template = self.root / 'images/userdata.img'
        self.template.parent.mkdir()
        self.template.write_bytes(b'clean userdata template')
        self.config = {'name': self.name, 'sdk': '/unused/sdk', 'hardware': {}}
        self.sdk = Path(self.config['sdk'])
        self.patch_root = patch.object(launch, 'ROOT', self.root)
        self.patch_root.start()
        self.addCleanup(self.patch_root.stop)
        self.write_capacity('32G')

    def write_capacity(self, value):
        lines = ['hw.ramSize=6144', 'hw.cpu.ncore=4']
        if value is not None:
            lines.append('disk.dataPartition.size=' + value)
        (self.avd / 'config.ini').write_text('\n'.join(lines) + '\n')

    def existing(self):
        userdata = self.avd / 'userdata-qemu.img'
        userdata.write_bytes(b'retained userdata')
        return userdata

    def test_legacy_empty_hardware_uses_configured_capacity(self):
        userdata = self.existing()
        with patch('manage.validate_userdata') as validate, patch('manage.resize', return_value='repaired') as resize, patch('userdata_resize.check_dependencies') as dependencies, patch.object(launch.shutil, 'copyfile') as copy:
            result = launch.prepare_userdata(self.config)
        self.assertEqual(result, 'repaired')
        validate.assert_called_once_with(self.sdk, self.avd)
        resize.assert_called_once_with(self.sdk, self.avd, 32, allow_guest=True)
        dependencies.assert_not_called()
        copy.assert_not_called()
        self.assertEqual(userdata.read_bytes(), b'retained userdata')

    def test_missing_hardware_and_partial_hardware_use_configured_capacity(self):
        self.existing()
        for hardware in (None, {'hw.ramSize': '8192'}):
            with self.subTest(hardware=hardware):
                config = dict(self.config)
                if hardware is None:
                    config.pop('hardware')
                else:
                    config['hardware'] = hardware
                with patch('manage.validate_userdata'), patch('manage.resize') as resize:
                    launch.prepare_userdata(config)
                resize.assert_called_once_with(self.sdk, self.avd, 32, allow_guest=True)

    def test_runtime_capacity_overrides_configured_capacity(self):
        self.existing()
        self.config['hardware']['disk.dataPartition.size'] = '48G'
        with patch('manage.validate_userdata'), patch('manage.resize') as resize:
            launch.prepare_userdata(self.config)
        resize.assert_called_once_with(self.sdk, self.avd, 48, allow_guest=True)

    def test_valid_configured_sizes_reach_resize_as_gib(self):
        self.existing()
        for gib in (6, 32, 64, 1024):
            with self.subTest(gib=gib):
                self.write_capacity(f'{gib}G')
                with patch('manage.validate_userdata'), patch('manage.resize') as resize:
                    launch.prepare_userdata(self.config)
                resize.assert_called_once_with(self.sdk, self.avd, gib, allow_guest=True)

    def test_missing_or_invalid_capacity_refuses_before_mutation(self):
        for capacity in (None, '', '32', '32M', '-1G', '1.5G', 'G', '0G', '5G', '1025G'):
            with self.subTest(capacity=capacity):
                self.write_capacity(capacity)
                with patch('manage.validate_userdata') as validate, patch('manage.resize') as resize, patch('userdata_resize.check_dependencies') as dependencies, patch.object(launch.shutil, 'copyfile') as copy:
                    with self.assertRaisesRegex(RuntimeError, 'capacity'):
                        launch.prepare_userdata(self.config)
                dependencies.assert_not_called()
                copy.assert_not_called()
                validate.assert_not_called()
                resize.assert_not_called()

    def test_invalid_runtime_capacity_is_not_replaced_by_config_fallback(self):
        for capacity in (None, 32, False, '32M'):
            with self.subTest(capacity=capacity):
                self.config['hardware']['disk.dataPartition.size'] = capacity
                with patch('manage.validate_userdata') as validate, patch('manage.resize') as resize, patch.object(launch.shutil, 'copyfile') as copy:
                    with self.assertRaisesRegex(RuntimeError, 'capacity'):
                        launch.prepare_userdata(self.config)
                copy.assert_not_called()
                validate.assert_not_called()
                resize.assert_not_called()

    def test_missing_fresh_dependencies_refuse_before_template_copy(self):
        with patch('userdata_resize.check_dependencies', side_effect=RuntimeError('Missing e2fsprogs')) as dependencies, patch.object(launch.shutil, 'copyfile') as copy, patch('manage.validate_userdata') as validate, patch('manage.resize') as resize:
            with self.assertRaisesRegex(RuntimeError, 'e2fsprogs'):
                launch.prepare_userdata(self.config)
        dependencies.assert_called_once_with(self.sdk)
        copy.assert_not_called()
        validate.assert_not_called()
        resize.assert_not_called()
        self.assertFalse((self.avd / 'userdata-qemu.img').exists())

    def test_fresh_creation_checks_dependencies_then_validates_before_resize(self):
        order = Mock()
        with patch('userdata_resize.check_dependencies') as dependencies, patch.object(launch.shutil, 'copyfile', wraps=launch.shutil.copyfile) as copy, patch('manage.validate_userdata') as validate, patch('manage.resize', return_value='expanded') as resize:
            for name, function in (('dependencies', dependencies), ('copy', copy), ('validate', validate), ('resize', resize)):
                order.attach_mock(function, name)
            result = launch.prepare_userdata(self.config)
        self.assertEqual(result, 'expanded')
        self.assertEqual([item[0] for item in order.mock_calls], ['dependencies', 'copy', 'validate', 'resize'])
        dependencies.assert_called_once_with(self.sdk)
        copy.assert_called_once_with(self.template, self.avd / 'userdata-qemu.img')
        validate.assert_called_once_with(self.sdk, self.avd)
        resize.assert_called_once_with(self.sdk, self.avd, 32, allow_guest=True)
        self.assertEqual((self.avd / 'userdata-qemu.img').read_bytes(), self.template.read_bytes())

    def test_existing_validation_failure_prevents_resize_and_copy(self):
        userdata = self.existing()
        with patch('manage.validate_userdata', side_effect=RuntimeError('Invalid QCOW2 chain')) as validate, patch('manage.resize') as resize, patch.object(launch.shutil, 'copyfile') as copy:
            with self.assertRaisesRegex(RuntimeError, 'QCOW2'):
                launch.prepare_userdata(self.config)
        validate.assert_called_once_with(self.sdk, self.avd)
        resize.assert_not_called()
        copy.assert_not_called()
        self.assertEqual(userdata.read_bytes(), b'retained userdata')

    def test_opaque_existing_data_is_backed_up_before_owned_guest_repair(self):
        userdata = self.existing()
        self.config['port'] = 5588
        folder = self.root / 'backups' / 'saved'
        deferred = {'guest_required': True, 'userdata_capacity_token': {'nonce': 'private'}}
        order = Mock()
        with patch('manage.validate_userdata'), patch('manage.resize', return_value=deferred), patch('manage.backup', return_value=folder) as backup, patch('manage.prepare_storage', return_value={'capacity_proof': 'verified-in-guest'}) as repair:
            order.attach_mock(backup, 'backup')
            order.attach_mock(repair, 'repair')
            result = launch.prepare_userdata(self.config)
        self.assertEqual([call[0] for call in order.mock_calls], ['backup', 'repair'])
        backup.assert_called_once_with(self.root, self.name)
        repair.assert_called_once_with(self.root, self.name, 5588, self.sdk, 32, folder)
        self.assertEqual(result, {'capacity_proof': 'verified-in-guest'})
        self.assertEqual(userdata.read_bytes(), b'retained userdata')

    def test_guest_repair_backup_failure_stops_before_starting_guest(self):
        userdata = self.existing()
        self.config['port'] = 5588
        with patch('manage.validate_userdata'), patch('manage.resize', return_value={'guest_required': True}), patch('manage.backup', side_effect=OSError('backup failed')), patch('manage.prepare_storage') as repair:
            with self.assertRaisesRegex(OSError, 'backup failed'):
                launch.prepare_userdata(self.config)
        repair.assert_not_called()
        self.assertEqual(userdata.read_bytes(), b'retained userdata')

    def test_encrypted_disk_growth_creates_backup_before_managed_resize_and_guest(self):
        userdata = self.existing()
        self.config['port'] = 5596
        folder = self.root / 'backups' / 'before-encrypted-growth'
        order = Mock()
        with patch('manage.validate_userdata') as validate, patch('manage.resize', side_effect=OfflineBackupRequiredError('matching complete offline backup')) as resize, patch('manage.backup', return_value=folder) as backup, patch('manage.prepare_storage', return_value={'prepared_filesystem_bytes': 32 * 1024 ** 3}) as repair:
            for name, function in (('validate', validate), ('resize', resize), ('backup', backup), ('repair', repair)):
                order.attach_mock(function, name)
            result = launch.prepare_userdata(self.config)
        self.assertEqual([call[0] for call in order.mock_calls], ['validate', 'resize', 'backup', 'repair'])
        backup.assert_called_once_with(self.root, self.name)
        repair.assert_called_once_with(self.root, self.name, 5596, self.sdk, 32, folder)
        self.assertEqual(result['prepared_filesystem_bytes'], 32 * 1024 ** 3)
        self.assertEqual(userdata.read_bytes(), b'retained userdata')

    def test_encrypted_disk_growth_backup_failure_preserves_data_without_boot(self):
        userdata = self.existing()
        with patch('manage.validate_userdata'), patch('manage.resize', side_effect=OfflineBackupRequiredError('offline backup')), patch('manage.backup', side_effect=OSError('encrypted backup failed')), patch('manage.prepare_storage') as repair, patch.object(launch.shutil, 'copyfile') as copy:
            with self.assertRaisesRegex(OSError, 'encrypted backup failed'):
                launch.prepare_userdata(self.config)
        repair.assert_not_called()
        copy.assert_not_called()
        self.assertEqual(userdata.read_bytes(), b'retained userdata')

    def test_other_opaque_refusals_cannot_create_backup_or_boot(self):
        userdata = self.existing()
        with patch('manage.validate_userdata'), patch('manage.resize', side_effect=OpaqueFilesystemError('mismatched or unknown chain')), patch('manage.backup') as backup, patch('manage.prepare_storage') as repair:
            with self.assertRaisesRegex(OpaqueFilesystemError, 'mismatched'):
                launch.prepare_userdata(self.config)
        backup.assert_not_called()
        repair.assert_not_called()
        self.assertEqual(userdata.read_bytes(), b'retained userdata')

    def test_interrupted_activation_recovers_original_before_fresh_copy(self):
        from userdata_resize import PENDING
        original = self.avd / PENDING / 'original'
        original.mkdir(parents=True)
        retained = original / 'userdata-qemu.img'
        retained.write_bytes(b'original interrupted userdata')
        overlay = original / 'userdata-qemu.img.qcow2'
        overlay.write_bytes(b'original interrupted overlay')
        order = Mock()

        def recover(*_, **kwargs):
            retained.replace(self.avd / retained.name)
            overlay.replace(self.avd / overlay.name)
            return 'recovered and expanded'
        with patch('manage.resize', side_effect=recover) as resize, patch('manage.validate_userdata') as validate, patch('userdata_resize.check_dependencies') as dependencies, patch.object(launch.shutil, 'copyfile') as copy:
            order.attach_mock(resize, 'resize')
            order.attach_mock(validate, 'validate')
            result = launch.prepare_userdata(self.config)
        self.assertEqual(result, 'recovered and expanded')
        resize.assert_called_once_with(self.sdk, self.avd, 32, allow_guest=True)
        validate.assert_called_once_with(self.sdk, self.avd)
        self.assertEqual([item[0] for item in order.mock_calls], ['resize', 'validate'])
        copy.assert_not_called()
        dependencies.assert_not_called()
        self.assertEqual((self.avd / retained.name).read_bytes(), b'original interrupted userdata')
        self.assertEqual((self.avd / overlay.name).read_bytes(), b'original interrupted overlay')

    def test_bad_pending_transaction_refuses_before_fresh_copy(self):
        from userdata_resize import PENDING
        for kind in ('directory', 'broken_symlink'):
            with self.subTest(kind=kind):
                pending = self.avd / PENDING
                if kind == 'directory':
                    pending.mkdir()
                else:
                    pending.symlink_to(self.avd / 'missing-transaction')
                try:
                    with patch('manage.resize', side_effect=RuntimeError('Unknown pending transaction')) as resize, patch('manage.validate_userdata') as validate, patch('userdata_resize.check_dependencies') as dependencies, patch.object(launch.shutil, 'copyfile') as copy:
                        with self.assertRaisesRegex(RuntimeError, 'pending transaction'):
                            launch.prepare_userdata(self.config)
                    resize.assert_called_once_with(self.sdk, self.avd, 32, allow_guest=True)
                    copy.assert_not_called()
                    dependencies.assert_not_called()
                    validate.assert_not_called()
                    self.assertFalse((self.avd / 'userdata-qemu.img').exists())
                finally:
                    pending.rmdir() if kind == 'directory' else pending.unlink()

if __name__ == '__main__':
    unittest.main()
