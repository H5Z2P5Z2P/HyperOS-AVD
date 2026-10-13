"""Verify registered source upgrades, conservative owners and rollback dispatch."""
import copy
from contextlib import ExitStack
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import common
import manage
import setup
from phone_profile import ARCHIVES, profile
import test_manager

PHONE17 = '4.0.17.0.XFRCNXM'
PHONE18 = '4.0.18.0.XFRCNXM'
PHONE24 = '4.0.24.0.XFRCNXM'


def manifest(firmware, revision=6):
    return {'variant': 'os4-official', 'hyperos': firmware,
            'version': f'v0.2.5-a17-hyperos4-hongkong-r{revision}',
            'build': {'source': common.OS4_SOURCE, 'hyperos': firmware,
                      'archive_sha256': ARCHIVES[firmware]}}


class FirmwareUpgradeTests(unittest.TestCase):
    def test_historical_layout_rejects_extra_early_hooks_and_aliases(self):
        for case in (None, 'post-mount.sh', 'boot-completed.sh', 'sepolicy.rule', 'zygisk',
                     'system', 'initrc', 'initrc-link', 'uninstall.sh', 'service.sh.next', 'symlink', 'hardlink'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                module = Path(directory) / 'old-owner'; module.mkdir()
                for name in ('module.prop', 'manifest.json', 'post-fs-data.sh', 'service.sh'):
                    (module / name).write_text('published historical controls\n')
                if case in ('zygisk', 'system', 'initrc'):
                    (module / case).mkdir()
                elif case == 'initrc-link':
                    (module / 'initrc').symlink_to(Path(directory) / 'external')
                elif case == 'symlink':
                    (module / 'service.sh').unlink()
                    (module / 'service.sh').symlink_to(Path(directory) / 'external')
                elif case == 'hardlink':
                    os.link(module / 'service.sh', Path(directory) / 'aliased.sh')
                elif case:
                    (module / case).write_text('unreviewed startup control')
                def adb(config, *args, **kwargs):
                    script = shlex.split(args[-1])[-1]
                    if sys.platform == 'darwin':
                        script = script.replace('stat -c %h', 'stat -f %l')
                    return subprocess.run(['sh', '-c', script],
                                          check=kwargs['check'], capture_output=True, text=True)
                with patch.object(common, 'adb', side_effect=adb):
                    if case:
                        with self.assertRaisesRegex(RuntimeError, 'historical startup'):
                            manage.audit_legacy_startup({}, str(module.resolve()))
                    else:
                        manage.audit_legacy_startup({}, str(module.resolve()))

    def test_direct_historical_upgrade_guards_nav5_flutter6_without_losing_modern_input_checks(self):
        from patch_flutter import PROFILES
        from phone_profile import LEGACY_PINS
        modules = {
            'hyperos_avd_navigation': {'revision': 5, 'property': 'ro.miui.product.home',
                'value': 'com.miui.home',
                'component': 'com.miui.home/com.miui.home.recents.RecentsActivity'},
            'hyperos_avd_flutter_render': {'revision': 6, 'packages': {}, 'system': {
                'target': '/system_ext/lib64/libhyper_os_flutter.so',
                'before': LEGACY_PINS['flutter'], 'after': PROFILES[LEGACY_PINS['flutter']]['output']}},
        }
        original = '#!/system/bin/sh\nprintf original\n'
        commands = []
        def adb(config, *args, **kwargs):
            command = args[-1]; commands.append(args)
            identifier = next((name for name in modules if name in command), None)
            output = ''
            if args[0] == 'get-state':
                output = 'device'
            elif args[:3] == ('emu', 'avd', 'name'):
                output = 'Renamed_Phone\nOK'
            elif 'getenforce' in command:
                output = 'uid=0(root) gid=0(root)\nEnforcing\nOS' + PHONE17
            elif identifier and 'if [ -d ' in command:
                output = 'yes'
            elif identifier and '/module.prop' in command:
                output = 'id=' + identifier + '\nauthor=HyperOS-AVD\n'
            elif identifier and '/manifest.json' in command:
                output = json.dumps(modules[identifier])
            elif identifier and 'for flag in disable remove' in command:
                output = 'disable'
            elif args[0] == 'exec-out':
                output = original
            return subprocess.CompletedProcess(args, 0, output, '')
        with tempfile.TemporaryDirectory() as directory:
            root, old, backup = self.fixture(Path(directory))
            old.update(manifest(PHONE17, 2))
            process = Mock(); process.poll.return_value = None
            with patch.object(manage, 'idle'), patch.object(common, 'adb', side_effect=adb), \
                    patch.object(manage.subprocess, 'Popen', return_value=process), \
                    patch.object(manage, 'audit_firmware_modules', return_value=[]) as audit, \
                    patch('launch.vulkan_features', return_value=[]) as vk, \
                    patch('rear_display_config.runtime_options', return_value=[]) as rear:
                manage.prepare_firmware_upgrade(root, old, manifest(PHONE24), 'Renamed_Phone',
                                                5584, Path('/sdk'), backup)
            vk.assert_called_once_with(old['build']); rear.assert_called_once_with(old['build'])
            self.assertEqual(audit.call_args.kwargs['guarded_ids'], set(modules))
            receipt = json.loads((backup / 'module-upgrade.json').read_text())
            self.assertEqual({value['revision'] for value in receipt['guarded_modules']}, {5, 6})
            self.assertTrue(all(value['flags'] == ['disable'] for value in receipt['guarded_modules']))
            self.assertEqual((root / 'avd/Renamed_Phone.avd/userdata-qemu.img').read_bytes(),
                             b'personal data and stable serial')
            for name in modules:
                guarded = (backup / 'module-guards' / (name + '-service.sh')).read_text()
                self.assertIn('OS' + PHONE17, guarded)
                self.assertTrue(guarded.endswith(original.split('\n', 1)[1]))

    def fixture(self, directory):
        root = directory / 'instance'
        avd = root / 'avd/Renamed_Phone.avd'
        avd.mkdir(parents=True)
        (avd / 'config.ini').write_text('hw.ramSize=8192\nhw.cpu.ncore=2\n')
        (avd / 'userdata-qemu.img').write_bytes(b'personal data and stable serial')
        old = manifest(PHONE18, 5)
        old['files'] = {}
        for name in ('images/system.img', 'images/kernel-ranchu', 'images/ramdisk.img',
                     'images/encryptionkey.img', 'images/advancedFeatures.ini',
                     'tools/ksud-aarch64-linux-android'):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(name.encode())
            old['files'][name] = {'sha256': common.sha256(path)}
        backup = directory / 'backup'
        backup.mkdir()
        return root, old, backup

    def test_source_dispatch_keeps_frozen_bootstrap_and_accepts_future_revisions(self):
        for source, target, legacy in ((PHONE17, PHONE18, True), (PHONE18, PHONE24, False),
                                       (PHONE17, PHONE24, False)):
            for revision in (6, 999):
                with self.subTest(source=source, revision=revision), \
                        patch.object(manage, 'prepare_module_upgrade') as frozen, \
                        patch.object(manage, '_stage_module_upgrade') as adaptive:
                    old, new = manifest(source, 1), manifest(target, revision)
                    manage.prepare_firmware_upgrade(Path('/instance'), old, new, 'Renamed_Phone',
                                                    5990, Path('/sdk'), Path('/backup'))
                    self.assertEqual(frozen.called, legacy)
                    self.assertEqual(adaptive.called, not legacy)
                    if adaptive.called:
                        self.assertFalse(adaptive.call_args.kwargs['legacy'])
                        self.assertEqual(adaptive.call_args.args[-1], profile(source))

    def test_unknown_mismatched_downgrade_and_tampered_sources_fail_before_boot(self):
        pairs = []
        for field in ('archive_sha256', 'hyperos', 'source'):
            old, new = manifest(PHONE18), manifest(PHONE24)
            if field == 'archive_sha256':
                old['build'][field] = 'f' * 64
            elif field == 'hyperos':
                new['build'][field] = '4.0.999.0.XFRCNXM'
            else:
                new['build'][field] = 'official-yingtian-ota'
            pairs.append((old, new))
        old, new = manifest(PHONE18), manifest(PHONE24)
        new['hyperos'] = PHONE18
        pairs += [(old, new), (manifest(PHONE24), manifest(PHONE18)),
                  (manifest(PHONE18), manifest(PHONE18))]
        old, new = manifest(PHONE18), manifest(PHONE24)
        new['variant'] = 'os4-pad'
        pairs.append((old, new))
        with patch.object(manage.subprocess, 'Popen') as boot:
            for old, new in pairs:
                with self.subTest(old=old, new=new), self.assertRaises(RuntimeError):
                    manage.prepare_firmware_upgrade(Path('/instance'), old, new, 'Any_Name',
                                                    5990, Path('/sdk'), Path('/backup'))
        boot.assert_not_called()

    def test_old_image_auxiliary_files_are_authenticated_before_boot(self):
        for kind in ('tampered', 'alias', 'missing', 'path-traversal'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root, old, backup = self.fixture(Path(directory))
                path = root / 'images/advancedFeatures.ini'
                if kind == 'tampered':
                    path.write_bytes(b'custom feature override')
                elif kind == 'alias':
                    original = path.read_bytes()
                    path.unlink()
                    (root / 'external.ini').write_bytes(original)
                    path.symlink_to('../external.ini')
                elif kind == 'missing':
                    path.unlink()
                else:
                    old['files']['images/../untrusted'] = {'sha256': 'f' * 64}
                with patch.object(manage.subprocess, 'Popen') as boot, self.assertRaises(RuntimeError):
                    manage.prepare_firmware_upgrade(root, old, manifest(PHONE24), 'Renamed_Phone',
                                                    5990, Path('/sdk'), backup)
                boot.assert_not_called()

    def test_adaptive_staging_preserves_hooks_data_and_awake_choices(self):
        from os4_defaults import AWAKE_STAMP
        for fail in (False, True):
            with self.subTest(fail=fail), tempfile.TemporaryDirectory() as directory:
                root, old, backup = self.fixture(Path(directory))
                calls = []
                process = Mock()
                process.poll.return_value = None
                def adb(config, *args, **kwargs):
                    self.assertEqual((config['name'], config['port']), ('Renamed_Phone', 5990))
                    calls.append(args)
                    output = ''
                    if args[0] == 'get-state':
                        output = 'device'
                    elif args[:3] == ('emu', 'avd', 'name'):
                        output = 'Renamed_Phone\nOK'
                    elif 'getenforce' in args[-1]:
                        output = 'uid=0(root) gid=0(root)\nEnforcing\nOS' + PHONE18
                    return subprocess.CompletedProcess(args, 0, output, '')
                owners = [{'id': 'hyperos_avd_native_compat', 'flags': ['disable'],
                           'mode': 'content-adaptive'}]
                audit = Mock(side_effect=RuntimeError('unknown active owner') if fail else None,
                             return_value=owners)
                with patch.object(manage, 'idle'), patch.object(common, 'adb', side_effect=adb), \
                        patch.object(manage.subprocess, 'Popen', return_value=process) as boot, \
                        patch.object(manage, 'audit_firmware_modules', audit), \
                        patch.object(manage, 'guarded_modules') as guards, \
                        patch('launch.vulkan_features', return_value=['-feature', 'verified-vulkan']), \
                        patch('rear_display_config.runtime_options', return_value=['-no-multi-display']):
                    if fail:
                        with self.assertRaisesRegex(RuntimeError, 'unknown active owner'):
                            manage.prepare_firmware_upgrade(root, old, manifest(PHONE24),
                                                            'Renamed_Phone', 5990, Path('/sdk'), backup)
                    else:
                        manage.prepare_firmware_upgrade(root, old, manifest(PHONE24),
                                                        'Renamed_Phone', 5990, Path('/sdk'), backup)
                    guards.assert_not_called()
                    audit.assert_called_once_with({'sdk': '/sdk', 'name': 'Renamed_Phone', 'port': 5990}, old, root)
                    command = boot.call_args.args[0]
                    self.assertIn('8192', command)
                    self.assertIn('verified-vulkan', command)
                self.assertEqual((root / 'avd/Renamed_Phone.avd/userdata-qemu.img').read_bytes(),
                                 b'personal data and stable serial')
                stamps = [args for args in calls if AWAKE_STAMP in args[-1]]
                self.assertEqual(bool(stamps), not fail)
                self.assertFalse(any('settings put' in args[-1] or 'push' == args[0] for args in calls))
                process.wait.assert_called_once()
                if not fail:
                    receipt = json.loads((backup / 'module-upgrade.json').read_text())
                    self.assertEqual(receipt['retained_modules'], owners)
                    self.assertNotIn('guarded_modules', receipt)
                    self.assertEqual(receipt['preserved_defaults'], {'awake_stamp': AWAKE_STAMP})

    def test_modern_failure_uses_existing_full_transaction_rollback(self):
        helper = test_manager.ManagerTests()
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            path, original = helper.bundle(folder / 'bundle')
            target = copy.deepcopy(original)
            target.update(manifest(PHONE24))
            target['compatibility'].update(module_upgrade_preflight=manage.MODULE_UPGRADE_PREFLIGHT,
                                           upgrade_policy=manage.FORWARD_UPGRADE_POLICY)
            root = folder / 'instance'
            before = helper.legacy(root, original)
            installed = root / 'local/installed-release.json'
            old = json.loads(installed.read_text())
            old.update(manifest(PHONE18, 5))
            old['format'] = 3
            old['compatibility'] = original['compatibility']
            installed.write_text(json.dumps(old))
            def fail_stage(*args, **kwargs):
                self.assertTrue((root / 'local/upgrade-pending.json').is_file())
                (root / 'avd/Test_temp.avd/userdata-qemu.img').write_bytes(b'modified by old guest')
                raise RuntimeError('injected adaptive staging failure')
            with patch.object(setup, 'read_manifest', return_value=(target, path.as_uri())), \
                    patch.object(setup, 'install_bundle'), \
                    patch.object(manage, 'prepare_storage'), \
                    patch.object(manage, '_stage_module_upgrade', side_effect=fail_stage) as stage, \
                    patch('userdata_resize.check_dependencies', return_value={}), \
                    patch('sys.stdout', new_callable=io.StringIO):
                with self.assertRaisesRegex(RuntimeError, 'injected adaptive'):
                    helper.invoke(root, path, folder / 'registry')
            self.assertFalse(stage.call_args.kwargs['legacy'])
            self.assertEqual((root / 'images/system.img').read_bytes(), b'old firmware')
            for name, value in before.items():
                self.assertEqual((root / 'avd/Test_temp.avd' / name).read_bytes(), value)
            self.assertEqual(json.loads(installed.read_text())['hyperos'], PHONE18)
            self.assertFalse((root / 'local/upgrade-pending.json').exists())


class FirmwareOwnerAuditTests(unittest.TestCase):
    def test_only_this_transaction_guarded_historical_owners_are_excluded(self):
        old_owner = {'id': 'hyperos_avd_navigation', 'status': 'preserved',
                     'reason': 'Unreviewed navigation receipt schema.'}
        self.patches(core_legacy=[old_owner], app_legacy={'modules': [], 'preserved': [
            {'module': 'hyperos_avd_xiaomi_camera', 'reason': 'unknown-or-custom'}]})
        guarded = {'hyperos_avd_navigation', 'hyperos_avd_xiaomi_camera'}
        receipt = manage.audit_firmware_modules({}, manifest(PHONE17), Path('/instance'),
                                               guarded_ids=guarded)
        self.assertFalse(any(value['id'] in guarded for value in receipt))
        with self.assertRaisesRegex(RuntimeError, 'Unknown legacy Apps'):
            manage.audit_firmware_modules({}, manifest(PHONE17), Path('/instance'),
                                          guarded_ids={'hyperos_avd_navigation'})

    def patches(self, *, core_flags=None, app_flags=None, core_manifest=None,
                core_legacy=None, app_legacy=None, pending=False):
        import apply_native_compat as core
        import apply_app_compat as apps
        from package_native_module import module_files
        stack = ExitStack()
        self.addCleanup(stack.close)
        guest = stack.enter_context(patch('apply_flutter_fix.root', return_value='pending' if pending else ''))
        native = {'flags': list(core_flags or []), 'directory': core.MODULE}
        app = {'flags': list(app_flags or []), 'directory': '/data/adb/modules/' + apps.MODULE_ID}
        stack.enter_context(patch.object(core, '_module', return_value=native))
        current = json.loads(module_files()['manifest.json'])
        stack.enter_context(patch.object(core, '_manifest', return_value=current if core_manifest is None else core_manifest))
        verify_core = stack.enter_context(patch.object(core, '_verify_assets'))
        stack.enter_context(patch.object(apps, '_inspect', return_value=app))
        verify_apps = stack.enter_context(patch.object(apps, '_saved'))
        stack.enter_context(patch('core_legacy.inspect_legacy', return_value=core_legacy or []))
        plan = stack.enter_context(patch('app_compat_migration.plan', return_value=app_legacy or {
            'modules': [], 'preserved': []}))
        return guest, verify_core, verify_apps, plan

    def test_adaptive_owners_are_authenticated_without_writing_any_choice(self):
        guest, core, apps, plan = self.patches()
        receipt = manage.audit_firmware_modules({'name': 'Renamed'}, manifest(PHONE18), Path('/instance'))
        self.assertEqual([item['mode'] for item in receipt], ['content-adaptive', 'content-adaptive'])
        core.assert_called_once()
        apps.assert_called_once()
        self.assertEqual(plan.call_args.kwargs['workspace'], Path('/instance'))
        commands = [call.args[1] for call in guest.call_args_list]
        self.assertFalse(any('settings put' in command or 'mv ' in command or 'rm ' in command
                             or 'touch ' in command for command in commands))

    def test_disabled_and_removed_current_modules_keep_flags_and_payloads(self):
        _, core, apps, _ = self.patches(core_flags=['disable'], app_flags=['remove'])
        receipt = manage.audit_firmware_modules({}, manifest(PHONE18), Path('/instance'))
        self.assertEqual(receipt[0]['flags'], ['disable'])
        self.assertEqual(receipt[1]['flags'], ['remove'])
        core.assert_not_called()
        apps.assert_not_called()

    def test_pending_owner_blocks_switch_without_cancelling_it(self):
        guest, core, apps, _ = self.patches(pending=True)
        with self.assertRaisesRegex(RuntimeError, 'pending KernelSU'):
            manage.audit_firmware_modules({}, manifest(PHONE18), Path('/instance'))
        core.assert_not_called()
        apps.assert_not_called()
        self.assertFalse(any('rm ' in call.args[1] for call in guest.call_args_list))

    def test_unknown_active_core_or_legacy_payload_blocks_switch(self):
        for case in ('core', 'legacy-core', 'legacy-app'):
            with self.subTest(case=case):
                self.patches(core_manifest={'revision': 999} if case == 'core' else None,
                             core_legacy=[{'id': 'hyperos_avd_navigation', 'status': 'preserved',
                                           'reason': 'Unreviewed legacy file contents.'}] if case == 'legacy-core' else [],
                             app_legacy={'modules': [], 'preserved': [{'module': 'hyperos_avd_xiaomi_camera',
                                                                    'reason': 'unknown-or-custom'}]}
                             if case == 'legacy-app' else None)
                with self.assertRaisesRegex(RuntimeError, 'Unknown'):
                    manage.audit_firmware_modules({}, manifest(PHONE18), Path('/instance'))
                self.doCleanups()

    def test_added_boot_hook_is_rejected_but_feature_choices_are_retained(self):
        def guest(config, command):
            subprocess.run(['sh', '-c', command], check=True, capture_output=True)
            return ''
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder / 'service.sh').write_text('#!/bin/sh\n')
            (folder / 'features.disabled').write_text('rear-wake\n')
            expected = {'files_sha256': {'service.sh': 'a' * 64}}
            with patch('apply_flutter_fix.root', side_effect=guest):
                manage.audit_module_inventory({}, str(folder), expected)
                (folder / 'boot-completed.sh').write_text('unexpected early code\n')
                with self.assertRaises(subprocess.CalledProcessError):
                    manage.audit_module_inventory({}, str(folder), expected)
            self.assertEqual((folder / 'features.disabled').read_text(), 'rear-wake\n')

    def test_audited_core_runtime_leases_are_typed_and_foreign_content_is_preserved(self):
        cases = (None, 'empty-lock', 'guard-only', 'bad-pid', 'bad-boot', 'extra-field',
                 'nonempty-guard', 'guard-link', 'directory-link', 'pid-link',
                 'pid-hardlink', 'guard-hardlink', 'guard-directory', 'foreign-owner', 'apps-owner')
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                folder = Path(directory) / 'module'; folder.mkdir()
                lock = folder / 'service.lock'; lock.mkdir()
                (folder / 'service.sh').write_text('#!/system/bin/sh\n')
                (folder / 'features.disabled').write_text('assistant\n')
                (folder / 'service.lock.guard').write_bytes(b'')
                (lock / 'pid').write_text('3781\n')
                (lock / 'boot').write_text('1c59c65c-aea6-4ed6-a208-892fd5098f0d\n')
                expected = {'id': 'hyperos_avd_native_compat', 'files_sha256': {'service.sh': 'a' * 64}}
                if case in ('empty-lock', 'guard-only', 'directory-link'):
                    (lock / 'pid').unlink(); (lock / 'boot').unlink()
                    if case != 'empty-lock':
                        lock.rmdir()
                    if case == 'directory-link':
                        lock.symlink_to(folder / 'external')
                elif case == 'bad-pid':
                    (lock / 'pid').write_text('not-a-pid\n')
                elif case == 'bad-boot':
                    (lock / 'boot').write_text('not-a-boot-id\n')
                elif case == 'extra-field':
                    (lock / 'init.rc').write_text('unreviewed early hook\n')
                elif case == 'nonempty-guard':
                    (folder / 'service.lock.guard').write_text('custom guard\n')
                elif case in ('guard-link', 'pid-link'):
                    file = folder / 'service.lock.guard' if case == 'guard-link' else lock / 'pid'
                    file.unlink(); file.symlink_to(folder / 'external')
                elif case in ('guard-hardlink', 'pid-hardlink'):
                    file = folder / 'service.lock.guard' if case == 'guard-hardlink' else lock / 'pid'
                    os.link(file, Path(directory) / 'external')
                elif case == 'guard-directory':
                    (folder / 'service.lock.guard').unlink(); (folder / 'service.lock.guard').mkdir()
                elif case == 'apps-owner':
                    expected['id'] = 'hyperos_avd_app_compat'

                def guest(config, command):
                    # The production guest requires uid/gid 0. Local fixtures
                    # keep the current host user's ownership without sudo.
                    ownership = f'{os.geteuid()}:{os.getegid()}' if case != 'foreign-owner' else '99999:99999'
                    command = command.replace('= 0:0 ]', '= ' + ownership + ' ]')
                    if sys.platform == 'darwin':
                        for before, after in (('stat -c %h', 'stat -f %l'),
                                              ('stat -c %s', 'stat -f %z'),
                                              ('stat -c %u:%g', 'stat -f %u:%g')):
                            command = command.replace(before, after)
                    subprocess.run(['sh', '-c', command], check=True, capture_output=True, text=True)
                    return ''

                choices = (folder / 'features.disabled').read_bytes()
                with patch('apply_flutter_fix.root', side_effect=guest):
                    if case in (None, 'empty-lock', 'guard-only'):
                        manage.audit_module_inventory({}, str(folder), expected)
                    else:
                        with self.assertRaises(subprocess.CalledProcessError) as caught:
                            manage.audit_module_inventory({}, str(folder), expected)
                        self.assertIn('Unreviewed module content preserved:', caught.exception.stderr)
                        self.assertIn(str(folder), caught.exception.stderr)
                self.assertEqual((folder / 'features.disabled').read_bytes(), choices)


if __name__ == '__main__':
    unittest.main()
