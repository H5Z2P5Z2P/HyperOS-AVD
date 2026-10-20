"""Consolidated unit tests for OS4 Phone upgrade subsystem:
OTA upgrade flow, camera service upgrade, runtime migrations, and firmware owner lifecycle.
"""
from contextlib import ExitStack
import copy
import hashlib
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

REPO = Path(__file__).resolve().parents[1]
ROOT = REPO
sys.path.insert(0, str(REPO / 'scripts'))

import apply_flutter_fix as flutter
import apply_navigation_fix as navigation
import apply_xiaomi_camera_fix as camera
import common
import manage
import module_lifecycle
import os4_defaults as defaults
import package_release
from patch_flutter import PROFILES
from phone_profile import ARCHIVES, LEGACY_PINS, profile
import setup
import test_manager



# --- tests/test_phone_upgrade.py ---

'Verify pre-boot module gates and recoverable phone firmware upgrades.'

R2 = 'v0.2.1-a17-hyperos4-hongkong-r2'

R3 = 'v0.2.2-a17-hyperos4-hongkong-r3'

R4 = 'v0.2.3-a17-hyperos4-hongkong-r4'

R5 = 'v0.2.4-a17-hyperos4-hongkong-r5'

R6 = 'v0.2.5-a17-hyperos4-hongkong-r6'

OLD = 'OS4.0.17.0.XFRCNXM'

NEW = '4.0.18.0.XFRCNXM'

LATEST = '4.0.24.0.XFRCNXM'

def r3_manifest(value):
    result = copy.deepcopy(value)
    result.update(version=R3, hyperos=NEW, source=common.OS4_SOURCE, source_device='hongkong')
    result['build'].update(hyperos=NEW, archive_sha256=ARCHIVES[NEW])
    result['compatibility'].update(minimum_installer='1.2.0', runtime_in_bundle=True, upgrade_from=[R2], module_upgrade_preflight=manage.MODULE_UPGRADE_PREFLIGHT)
    return result

class PhoneUpgradeTests(unittest.TestCase):

    def test_registered_new_source_requires_the_full_forward_manifest_contract(self):
        from apply_boot_service_fix import receipt
        helper = test_manager.ManagerTests()
        with tempfile.TemporaryDirectory() as directory:
            path, original = helper.bundle(Path(directory) / 'bundle')
            previous = r3_manifest(original)
            target = copy.deepcopy(previous)
            target.update(version=R6, hyperos=LATEST)
            target['build'].update(hyperos=LATEST, archive_sha256=ARCHIVES[LATEST], boot_service_fix=receipt())
            target['compatibility'].pop('upgrade_from')
            target['compatibility'].update(minimum_installer='1.2.3', upgrade_policy=manage.FORWARD_UPGRADE_POLICY)
            path.write_text(json.dumps(target))
            parsed, _ = setup.read_manifest(str(path))
            from patch_boot_services import image_receipts
            for version in (NEW, LATEST):
                for recipe in image_receipts():
                    value = copy.deepcopy(target)
                    value.update(version=R5 if version == NEW else R6, hyperos=version)
                    value['build'].update(hyperos=version, archive_sha256=ARCHIVES[version], boot_service_fix=recipe)
                    path.write_text(json.dumps(value))
                    with self.subTest(source=version, recipe=recipe['targets']['services']['before']):
                        self.assertEqual(setup.read_manifest(str(path))[0], value)
                    if version == NEW and recipe != image_receipts()[0]:
                        value['compatibility']['minimum_installer'] = '1.2.2'
                        path.write_text(json.dumps(value))
                        with self.assertRaises(RuntimeError):
                            setup.read_manifest(str(path))
            for version in ('v0.2.0-a17-hyperos4-hongkong-r1', R2, R3, R4, R5):
                source = copy.deepcopy(original if version in ('v0.2.0-a17-hyperos4-hongkong-r1', R2) else previous)
                source['version'] = version
                with self.subTest(source=version):
                    manage.compatible(source, parsed)
            for mutate in ('old-format', 'wrong-family', 'wrong-archive', 'missing-recipe', 'bad-recipe', 'bad-recipe-type', 'partial-recipe', 'old-installer', 'previous-installer', 'missing-runtime', 'missing-preflight', 'unknown-policy', 'unregistered-source', 'invalid-tag'):
                bad = copy.deepcopy(target)
                if mutate == 'old-format':
                    bad['format'] = 2
                elif mutate == 'wrong-family':
                    bad['compatibility']['userdata_family'] = setup.PAD_FAMILY
                elif mutate == 'wrong-archive':
                    bad['build']['archive_sha256'] = ARCHIVES[NEW]
                elif mutate == 'missing-recipe':
                    del bad['build']['boot_service_fix']
                elif mutate == 'bad-recipe':
                    bad['build']['boot_service_fix']['probe_sha256'] = 'f' * 64
                elif mutate == 'bad-recipe-type':
                    bad['build']['boot_service_fix']['schema'] = True
                elif mutate == 'partial-recipe':
                    del bad['build']['boot_service_fix']['targets']['services']
                elif mutate == 'old-installer':
                    bad['compatibility']['minimum_installer'] = '1.2.1'
                elif mutate == 'previous-installer':
                    bad['compatibility']['minimum_installer'] = '1.2.2'
                elif mutate == 'missing-runtime':
                    bad['compatibility']['runtime_in_bundle'] = False
                elif mutate == 'missing-preflight':
                    del bad['compatibility']['module_upgrade_preflight']
                elif mutate == 'unknown-policy':
                    bad['compatibility']['upgrade_policy'] = 'unchecked-ota'
                elif mutate == 'unregistered-source':
                    bad['hyperos'] = bad['build']['hyperos'] = '4.0.999.0.XFRCNXM'
                else:
                    bad['version'] = 'v0.2.5-custom'
                path.write_text(json.dumps(bad))
                with self.subTest(mutate=mutate), self.assertRaises(RuntimeError):
                    setup.read_manifest(str(path))
            path.write_text(json.dumps(previous))
            self.assertEqual(setup.read_manifest(str(path))[0], previous)
            future_revision = copy.deepcopy(target)
            future_revision['version'] = 'v0.9.9-a17-hyperos4-hongkong-r999'
            path.write_text(json.dumps(future_revision))
            manage.compatible(parsed, setup.read_manifest(str(path))[0])

    def test_new_source_release_metadata_preserves_recipe_and_selects_r6_patch(self):
        from patch_boot_services import image_receipts
        recipe = image_receipts()[-1]
        build = {'source': common.OS4_SOURCE, 'hyperos': LATEST, 'android_api': 37, 'archive_sha256': ARCHIVES[LATEST], 'adb_authentication': True, 'flutter_render_fix': 6, 'native_quickstep_identity': True, 'preinstalled_apps': {'apps': ['fixture']}, 'avd_defaults': {'fixture': True}, 'boot_service_fix': recipe, 'rear_display': {'source': LATEST}, 'lockscreen_video_fix': {'audited': True}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'local').mkdir()
            file = root / 'local/build.json'
            file.write_text(json.dumps(build))
            metadata = package_release.release_metadata(root, 'os4-official')
            self.assertEqual(metadata['build']['boot_service_fix'], recipe)
            self.assertEqual(metadata['build']['rear_display'], build['rear_display'])
            self.assertEqual(metadata['build']['lockscreen_video_fix'], build['lockscreen_video_fix'])
            self.assertEqual(metadata['compatibility']['upgrade_policy'], manage.FORWARD_UPGRADE_POLICY)
            from bundle_runtime import PROTOCOL_MINIMUM
            self.assertEqual(metadata['compatibility']['minimum_installer'], PROTOCOL_MINIMUM)
            self.assertNotIn('upgrade_from', metadata['compatibility'])
            self.assertEqual(package_release.default_release_version('os4-official', metadata), R6 + '.2')
            del build['boot_service_fix']
            file.write_text(json.dumps(build))
            with self.assertRaisesRegex(RuntimeError, 'boot-service repairs'):
                package_release.release_metadata(root, 'os4-official')
            with self.assertRaisesRegex(RuntimeError, 'Unsupported official'):
                package_release.default_release_version('os4-official', {'hyperos': '4.0.999.0.XFRCNXM'})

    def test_forward_policy_accepts_supported_old_and_future_revisions(self):
        from apply_boot_service_fix import receipt
        helper = test_manager.ManagerTests()
        with tempfile.TemporaryDirectory() as directory:
            path, original = helper.bundle(Path(directory) / 'bundle')
            old = r3_manifest(original)
            new = copy.deepcopy(old)
            new['version'] = R5
            new['build']['boot_service_fix'] = receipt()
            new['compatibility'].pop('upgrade_from')
            new['compatibility'].update(minimum_installer='1.2.2', upgrade_policy=manage.FORWARD_UPGRADE_POLICY)
            path.write_text(json.dumps(new))
            parsed, _ = setup.read_manifest(str(path))
            manage.compatible(old, parsed)
            self.assertFalse(manage.firmware_change(old, parsed))
            for mutate in ('old-installer', 'unknown-policy', 'bad-receipt', 'missing-receipt'):
                bad = copy.deepcopy(new)
                if mutate == 'old-installer':
                    bad['compatibility']['minimum_installer'] = '1.2.0'
                elif mutate == 'unknown-policy':
                    bad['compatibility']['upgrade_policy'] = 'unsafe-skip-checks'
                elif mutate == 'bad-receipt':
                    bad['build']['boot_service_fix']['probe_sha256'] = 'f' * 64
                else:
                    del bad['build']['boot_service_fix']
                path.write_text(json.dumps(bad))
                with self.subTest(mutate=mutate), self.assertRaisesRegex(RuntimeError, 'r4|upgrade policy'):
                    setup.read_manifest(str(path))
            for version in ('v0.2.0-a17-hyperos4-hongkong-r1', R2, R3, R4):
                source = copy.deepcopy(original if version in ('v0.2.0-a17-hyperos4-hongkong-r1', R2) else old if version == R3 else new)
                source['version'] = version
                if version == R4:
                    source['compatibility']['minimum_installer'] = '1.2.1'
                with self.subTest(source=version):
                    manage.compatible(source, new)
                    self.assertEqual(manage.firmware_change(source, new), version in ('v0.2.0-a17-hyperos4-hongkong-r1', R2))
            future = copy.deepcopy(new)
            future['version'] = 'v0.9.9-a17-hyperos4-hongkong-r999'
            path.write_text(json.dumps(future))
            setup.read_manifest(str(path))
            manage.compatible(new, future)
            future['version'] = 'v0.2.4-a17-hyperos4-hongkong-r999'
            path.write_text(json.dumps(future))
            setup.read_manifest(str(path))
            manage.compatible(new, future)
            with self.assertRaisesRegex(RuntimeError, 'downgrades'):
                manage.compatible(future, new)
            wrong = copy.deepcopy(old)
            wrong['build']['archive_sha256'] = 'f' * 64
            with self.assertRaisesRegex(RuntimeError, 'archive'):
                manage.compatible(wrong, new)
            with self.assertRaisesRegex(RuntimeError, 'downgrades'):
                manage.compatible(new, old)

    def test_current_phone_metadata_requires_new_installer_and_retains_pinned_receipt(self):
        from apply_boot_service_fix import receipt
        build = {'source': common.OS4_SOURCE, 'hyperos': NEW, 'android_api': 37, 'archive_sha256': ARCHIVES[NEW], 'adb_authentication': True, 'flutter_render_fix': 6, 'native_quickstep_identity': True, 'preinstalled_apps': {'apps': ['test']}, 'avd_defaults': {'test': True}, 'boot_service_fix': receipt()}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'local').mkdir()
            (root / 'local/build.json').write_text(json.dumps(build))
            metadata = package_release.release_metadata(root, 'os4-official')
            self.assertEqual(metadata['build']['boot_service_fix'], receipt())
            from bundle_runtime import PROTOCOL_MINIMUM
            self.assertEqual(metadata['compatibility']['minimum_installer'], PROTOCOL_MINIMUM)
            self.assertNotIn('upgrade_from', metadata['compatibility'])
            self.assertEqual(metadata['compatibility']['upgrade_policy'], manage.FORWARD_UPGRADE_POLICY)
            self.assertEqual(package_release.default_release_version('os4-official', metadata), R5)

    def staging_fixture(self, folder):
        root = folder / 'instance'
        avd = root / 'avd/Test_temp.avd'
        avd.mkdir(parents=True)
        (avd / 'config.ini').write_text('hw.ramSize=6144\nhw.cpu.ncore=4\n')
        old = {'version': R2, 'variant': 'os4-official', 'build': {}, 'files': {}}
        for name in ('images/system.img', 'images/kernel-ranchu', 'images/ramdisk.img', 'tools/ksud-aarch64-linux-android'):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(name.encode())
            old['files'][name] = {'sha256': manage.sha256(path)}
        backup = folder / 'backup'
        backup.mkdir()
        return (root, old, backup)

    def test_staging_marks_awake_defaults_only_after_all_module_validation(self):
        from os4_defaults import AWAKE_STAMP
        for reject, touched in ((False, True), (True, False)):
            with self.subTest(reject=reject), tempfile.TemporaryDirectory() as directory:
                folder = Path(directory)
                root, old, backup = self.staging_fixture(folder)
                calls = []

                def adb(config, *args, **kwargs):
                    self.assertEqual(config['name'], 'Test_temp')
                    self.assertEqual(config['port'], 5584)
                    calls.append(args)
                    output = ''
                    if args[0] == 'get-state':
                        output = 'device'
                    elif args[:3] == ('emu', 'avd', 'name'):
                        output = 'Test_temp\nOK'
                    elif 'getenforce' in args[-1]:
                        output = 'uid=0(root) gid=0(root)\nEnforcing\n' + OLD
                    return subprocess.CompletedProcess(args, 0, output, '')

                def guards(*args):
                    self.assertEqual(args[-1], NEW)
                    calls.append(('module-validation',))
                    if reject:
                        raise RuntimeError('unsupported module')
                    return []
                process = unittest.mock.Mock()
                process.poll.return_value = None
                with patch('phone_profile.profile_from_build', return_value={'hyperos': '4.0.17.0.XFRCNXM', 'incremental': OLD}), patch.object(manage, 'idle'), patch.object(manage.subprocess, 'Popen', return_value=process), patch.object(common, 'adb', side_effect=adb), patch.object(manage, 'guarded_modules', side_effect=guards):
                    if reject:
                        with self.assertRaisesRegex(RuntimeError, 'unsupported module'):
                            manage.prepare_module_upgrade(root, old, {'version': R3, 'hyperos': NEW}, 'Test_temp', 5584, folder / 'sdk', backup)
                    else:
                        manage.prepare_module_upgrade(root, old, {'version': R3, 'hyperos': NEW}, 'Test_temp', 5584, folder / 'sdk', backup)
                stamps = [index for index, args in enumerate(calls) if AWAKE_STAMP in args[-1]]
                self.assertEqual(bool(stamps), touched)
                if touched:
                    self.assertGreater(stamps[0], calls.index(('module-validation',)))
                    self.assertNotIn('settings put', calls[stamps[0]][-1])
                    receipt = json.loads((backup / 'module-upgrade.json').read_text())
                    self.assertEqual(receipt['preserved_defaults'], {'awake_stamp': AWAKE_STAMP})

    def test_staging_guest_refuses_safe_mode_before_module_inventory(self):
        for persistent, boot, accepted in (('', '', True), ('0', '0', True), ('1', '0', False), ('0', '1', False)):
            with self.subTest(persistent=persistent, boot=boot):

                def adb(config, *args, **kwargs):
                    self.assertEqual(config['port'], 5584)
                    value = {'persist.sys.safemode': persistent, 'ro.sys.safemode': boot}.get(args[-1], 'uid=0(root) gid=0(root)\nEnforcing\n' + OLD)
                    return subprocess.CompletedProcess(args, 0, value + '\n', '')
                with patch.object(common, 'adb', side_effect=adb):
                    if accepted:
                        manage.validate_upgrade_guest({'port': 5584}, OLD)
                    else:
                        with self.assertRaisesRegex(RuntimeError, 'safe mode'):
                            manage.validate_upgrade_guest({'port': 5584}, OLD)

    def test_candidate_metadata_keeps_phone_family_and_requires_guarded_upgrade(self):
        build = {'source': common.OS4_SOURCE, 'hyperos': NEW, 'android_api': 37, 'archive_sha256': ARCHIVES[NEW], 'adb_authentication': True, 'flutter_render_fix': 6, 'native_quickstep_identity': True, 'preinstalled_apps': {'apps': ['test']}, 'avd_defaults': {'test': True}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'local').mkdir()
            source = root / 'local/build.json'
            source.write_text(json.dumps(build))
            metadata = package_release.release_metadata(root, 'os4-official')
            self.assertEqual(metadata['hyperos'], NEW)
            self.assertEqual(metadata['compatibility'], {'minimum_installer': '1.2.3', 'install_protocol': 'verified-bundle-runtime-v1', 'userdata_family': 'os4-hongkong-api37-ranchu-4k', 'upgrade_from': [R2], 'runtime_in_bundle': True, 'module_upgrade_preflight': manage.MODULE_UPGRADE_PREFLIGHT})
            source.write_text(json.dumps({**build, 'archive_sha256': 'f' * 64}))
            with self.assertRaisesRegex(RuntimeError, 'archive'):
                package_release.release_metadata(root, 'os4-official')

    def test_module_staging_preserves_serial_manifest_and_disabled_choice(self):
        navigation = {'revision': 10, 'property': 'ro.miui.product.home', 'value': 'com.miui.home', 'component': 'com.miui.home/com.miui.home.recents.RecentsActivity', 'serial_number': '69704/F5XA01467'}
        source = '#!/system/bin/sh\n# Retain exact original whitespace.\nprintf patched\n\n'
        calls = []

        def adb(config, *args, **kwargs):
            self.assertEqual(config['port'], 5584)
            calls.append(args)
            command = args[-1]
            output = ''
            if args[0] == 'push':
                self.assertIn('hyperos_avd_navigation', args[1])
            elif 'if [ -d /data/adb/modules/hyperos_avd_navigation' in command:
                output = 'yes\n'
            elif 'cat /data/adb/modules/hyperos_avd_navigation/module.prop' in command:
                output = 'id=hyperos_avd_navigation\nauthor=HyperOS-AVD\n'
            elif 'cat /data/adb/modules/hyperos_avd_navigation/manifest.json' in command:
                output = json.dumps(navigation) + '\n'
            elif 'for flag in disable remove' in command:
                output = 'disable\n'
            elif args[0] == 'exec-out':
                output = source
            return subprocess.CompletedProcess(args, 0, output, '')
        with tempfile.TemporaryDirectory() as directory, patch.object(common, 'adb', side_effect=adb):
            receipt = manage.guarded_modules({'port': 5584}, Path(directory), OLD)
            local = Path(directory) / 'hyperos_avd_navigation-post-fs-data.sh'
            self.assertTrue(local.read_text().endswith(source[len('#!/system/bin/sh\n'):]))
        self.assertEqual(receipt[0]['flags'], ['disable'])
        self.assertEqual(receipt[0]['manifest_sha256'], hashlib.sha256(json.dumps(navigation, sort_keys=True).encode()).hexdigest())
        write_commands = [args[-1] for args in calls if args[0] == 'shell' and 'cp /data/local/tmp/' in args[-1]]
        self.assertEqual(len(write_commands), 2)
        self.assertTrue(any((args[0] == 'push' for args in calls)))
        self.assertTrue(all(('/manifest.json.next' not in command and '/disable.next' not in command and ('/identity.prop.next' not in command) for command in write_commands)))

    def test_unknown_later_module_is_rejected_before_any_guest_file_push(self):
        navigation = {'revision': 10, 'property': 'ro.miui.product.home', 'value': 'com.miui.home', 'component': 'com.miui.home/com.miui.home.recents.RecentsActivity'}
        calls = []

        def adb(config, *args, **kwargs):
            calls.append(args)
            command = args[-1]
            output = ''
            if 'if [ -d ' in command:
                output = 'yes\n'
            elif '/module.prop' in command:
                module = 'hyperos_avd_flutter_render' if 'flutter_render' in command else 'hyperos_avd_navigation'
                output = 'id=' + module + '\nauthor=HyperOS-AVD\n'
            elif '/manifest.json' in command:
                output = json.dumps({'revision': 88} if 'flutter_render' in command else navigation)
            elif args[0] == 'exec-out':
                output = '#!/system/bin/sh\nexit 0\n'
            return subprocess.CompletedProcess(args, 0, output, '')
        with tempfile.TemporaryDirectory() as directory, patch.object(common, 'adb', side_effect=adb):
            with self.assertRaisesRegex(RuntimeError, 'schema'):
                manage.guarded_modules({'port': 5584}, Path(directory), OLD)
        self.assertFalse(any((args[0] == 'push' for args in calls)))

    def test_camera_revision_one_is_rejected_before_r3_guest_writes_and_revision_two_keeps_flags(self):
        module_id = 'hyperos_avd_xiaomi_camera'
        module = '/data/adb/modules/' + module_id
        saved = {'revision': 1, 'experimental': True, 'apk_sha256': LEGACY_PINS['camera_apk'], 'runtime_sha256': LEGACY_PINS['android_runtime'], 'targets': [{'target': '/vendor/bin/hw/android.hardware.camera.provider@2.7-service-google'}, {'target': '/vendor/lib64/libgooglecamerahwl_impl.so'}]}
        for revision in (1, 2):
            with self.subTest(revision=revision), tempfile.TemporaryDirectory() as directory:
                calls = []
                manifest = {**saved, 'revision': revision}

                def adb(config, *args, **kwargs):
                    calls.append(args)
                    command = args[-1]
                    output = ''
                    if 'if [ -d ' + module in command:
                        output = 'yes\n'
                    elif 'cat ' + module + '/module.prop' in command:
                        output = 'id=' + module_id + '\nauthor=HyperOS-AVD\n'
                    elif 'cat ' + module + '/manifest.json' in command:
                        output = json.dumps(manifest) + '\n'
                    elif 'for flag in disable remove' in command:
                        output = 'disable\nremove\n'
                    elif args[0] == 'exec-out':
                        output = '#!/system/bin/sh\nexit 0\n'
                    return subprocess.CompletedProcess(args, 0, output, '')
                with patch.object(common, 'adb', side_effect=adb):
                    if revision == 1:
                        with self.assertRaisesRegex(RuntimeError, 'existing r2 firmware.*revision 2'):
                            manage.guarded_modules({'port': 5584}, Path(directory), OLD, NEW)
                        self.assertFalse(any((args[0] in ('push', 'exec-out') for args in calls)))
                        self.assertFalse(list(Path(directory).iterdir()))
                    else:
                        receipt = manage.guarded_modules({'port': 5584}, Path(directory), OLD, NEW)
                        self.assertEqual(receipt[0]['revision'], 2)
                        self.assertEqual(receipt[0]['flags'], ['disable', 'remove'])
                        self.assertEqual(receipt[0]['manifest_sha256'], hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest())
                        self.assertEqual(sum((args[0] == 'push' for args in calls)), 2)
                guest_writes = [args[-1] for args in calls if args[0] == 'shell' and '.next' in args[-1]]
                self.assertTrue(all(('/manifest.json.next' not in command and '/disable.next' not in command and ('/remove.next' not in command) for command in guest_writes)))

    def test_camera_revision_one_remains_supported_outside_r3_preflight(self):
        module_id = 'hyperos_avd_xiaomi_camera'
        manage.validate_owned_module(module_id, 'id=' + module_id + '\nauthor=HyperOS-AVD\n', {'revision': 1, 'experimental': True, 'apk_sha256': LEGACY_PINS['camera_apk'], 'runtime_sha256': LEGACY_PINS['android_runtime'], 'targets': [{'target': '/vendor/bin/hw/android.hardware.camera.provider@2.7-service-google'}, {'target': '/vendor/lib64/libgooglecamerahwl_impl.so'}]})

    def test_firmware_gate_executes_only_on_original_firmware_and_is_idempotent(self):
        guarded = manage.migration_guard('#!/system/bin/sh\nprintf migrated\n', OLD)
        self.assertEqual(manage.migration_guard(guarded, OLD), guarded)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            getprop = root / 'getprop'
            getprop.write_text('#!/bin/sh\nprintf "%s" "$TEST_FIRMWARE"\n')
            getprop.chmod(493)
            script = root / 'module.sh'
            script.write_text(guarded)
            for firmware, expected in ((OLD, 'migrated'), ('OS' + NEW, '')):
                output = subprocess.check_output(['sh', str(script)], text=True, env={**os.environ, 'PATH': str(root) + os.pathsep + os.environ['PATH'], 'TEST_FIRMWARE': firmware})
                self.assertEqual(output, expected)
        for invalid in ('#!/bin/sh\nexit 0\n', '#!/system/bin/sh\n\x00'):
            with self.assertRaisesRegex(RuntimeError, 'script'):
                manage.migration_guard(invalid, OLD)

    def test_owned_module_validation_rejects_unrelated_code_and_automatic_mounts(self):
        module = 'hyperos_avd_navigation'
        prop = 'id=' + module + '\nauthor=HyperOS-AVD\n'
        manifest = {'revision': 10, 'property': 'ro.miui.product.home', 'value': 'com.miui.home', 'component': 'com.miui.home/com.miui.home.recents.RecentsActivity', 'serial_number': '69704/F5XA01467'}
        manage.validate_owned_module(module, prop, manifest, 'persist.miui.home_sf_anim=true\n')
        for kwargs in ({'has_system': True}, {'system_prop': 'ro.build.fingerprint=old\n'}):
            with self.assertRaises(RuntimeError):
                manage.validate_owned_module(module, prop, manifest, **kwargs)
        for wrong in ({**manifest, 'revision': 50}, {**manifest, 'component': 'com.android.launcher3/.Home'}):
            with self.assertRaisesRegex(RuntimeError, 'schema'):
                manage.validate_owned_module(module, prop, wrong)
        with self.assertRaisesRegex(RuntimeError, 'ownership'):
            manage.validate_owned_module(module, prop.replace('HyperOS-AVD', 'other'), manifest)
        flutter = 'hyperos_avd_flutter_render'
        manage.validate_owned_module(flutter, 'id=' + flutter + '\nauthor=HyperOS-AVD\n', {'revision': 6, 'packages': {'com.miui.home': '/product/Home.apk'}, 'system': {'target': '/system_ext/lib64/libhyper_os_flutter.so', 'before': LEGACY_PINS['flutter'], 'after': PROFILES[LEGACY_PINS['flutter']]['output']}})
        camera = 'hyperos_avd_xiaomi_camera'
        manage.validate_owned_module(camera, 'id=' + camera + '\nauthor=HyperOS-AVD\n', {'revision': 2, 'experimental': True, 'apk_sha256': LEGACY_PINS['camera_apk'], 'runtime_sha256': LEGACY_PINS['android_runtime'], 'targets': [{'target': '/vendor/bin/hw/android.hardware.camera.provider@2.7-service-google'}, {'target': '/vendor/lib64/libgooglecamerahwl_impl.so'}]})

    def test_r3_requires_a_known_upgrade_source_and_same_family_key(self):
        old = {'version': R2, 'variant': 'os4-official', 'format': 3, 'hyperos': '4.0.17.0.XFRCNXM', 'compatibility': {'userdata_family': 'os4-hongkong-api37-ranchu-4k'}, 'files': {'images/encryptionkey.img': {'sha256': 'same'}}}
        new = r3_manifest({**old, 'build': {}})
        manage.compatible(old, new)
        self.assertTrue(manage.firmware_change(old, new))
        with self.assertRaisesRegex(RuntimeError, 'validated'):
            manage.compatible({**old, 'version': 'v0.2.0-a17-hyperos4-hongkong-r1'}, new)
        with self.assertRaisesRegex(RuntimeError, 'migration'):
            manage.compatible(old, {**new, 'compatibility': {**new['compatibility'], 'module_upgrade_preflight': 'unknown'}})

    def test_failed_staging_restores_original_userdata_before_switch(self):
        helper = test_manager.ManagerTests()
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            path, original = helper.bundle(folder / 'bundle')
            new = r3_manifest(original)
            path.write_text(json.dumps(new))
            root = folder / 'instance'
            before = helper.legacy(root, original)
            old_path = root / 'local/installed-release.json'
            old = json.loads(old_path.read_text())
            old.update(format=3, version=R2, compatibility=original['compatibility'])
            old_path.write_text(json.dumps(old))

            def fail_stage(*args):
                self.assertTrue((root / 'local/upgrade-pending.json').is_file())
                (root / 'avd/Test_temp.avd/userdata-qemu.img').write_bytes(b'staging changed data')
                raise RuntimeError('injected staging failure')
            with patch('phone_profile.profile_from_build', side_effect=lambda build: profile(build['hyperos'].removeprefix('OS'))), patch('userdata_resize.check_dependencies', return_value={}), patch.object(manage, 'prepare_module_upgrade', side_effect=fail_stage) as stage:
                with self.assertRaisesRegex(RuntimeError, 'injected staging'):
                    helper.invoke(root, path, folder / 'registry')
            stage.assert_called_once()
            self.assertEqual((root / 'images/system.img').read_bytes(), b'old firmware')
            for name, value in before.items():
                self.assertEqual((root / 'avd/Test_temp.avd' / name).read_bytes(), value)
            self.assertFalse((root / 'local/upgrade-pending.json').exists())
            self.assertEqual(json.loads(old_path.read_text())['version'], R2)

    def test_direct_setup_refuses_retained_data_before_extracting_new_image(self):
        helper = test_manager.ManagerTests()
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            path, original = helper.bundle(folder / 'bundle')
            path.write_text(json.dumps(r3_manifest(original)))
            root = folder / 'instance'
            before = helper.legacy(root, original)
            with patch.object(setup, 'ROOT', root), patch('phone_profile.profile_from_build', return_value=profile(NEW)):
                with self.assertRaisesRegex(RuntimeError, 'Installer 1.2.0 Upgrade'):
                    setup.install_bundle(str(path))
            self.assertEqual((root / 'images/system.img').read_bytes(), b'old firmware')
            self.assertEqual((root / 'avd/Test_temp.avd/userdata-qemu.img').read_bytes(), before['userdata-qemu.img'])
            self.assertFalse((root / 'downloads').exists())

    def test_direct_setup_refuses_userdata_without_verified_current_build(self):
        helper = test_manager.ManagerTests()
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            path, original = helper.bundle(folder / 'bundle')
            path.write_text(json.dumps(r3_manifest(original)))
            root = folder / 'instance'
            before = helper.legacy(root, original)
            build_path = root / 'local/build.json'
            for saved in (None, {}, {'source': common.OS4_SOURCE, 'hyperos': NEW}, {'source': common.OS4_SOURCE, 'hyperos': NEW, 'archive_sha256': 'f' * 64}, {'source': 'official-yingtian-ota', 'hyperos': NEW, 'archive_sha256': ARCHIVES[NEW]}):
                with self.subTest(saved=saved):
                    if saved is None:
                        build_path.unlink(missing_ok=True)
                    else:
                        build_path.write_text(json.dumps(saved))
                    with patch.object(setup, 'ROOT', root):
                        with self.assertRaisesRegex(RuntimeError, 'Installer 1.2.0 Upgrade or Recover'):
                            setup.install_bundle(str(path))
                    self.assertEqual((root / 'images/system.img').read_bytes(), b'old firmware')
                    self.assertEqual((root / 'avd/Test_temp.avd/userdata-qemu.img').read_bytes(), before['userdata-qemu.img'])
                    self.assertFalse((root / 'downloads').exists())

    def test_direct_setup_accepts_verified_same_firmware_userdata(self):
        helper = test_manager.ManagerTests()
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            path, original = helper.bundle(folder / 'bundle')
            path.write_text(json.dumps(r3_manifest(original)))
            root = folder / 'instance'
            helper.legacy(root, original)
            (root / 'local/build.json').write_text(json.dumps({'source': common.OS4_SOURCE, 'hyperos': NEW, 'archive_sha256': ARCHIVES[NEW]}))
            with patch.object(setup, 'ROOT', root), patch.object(setup, 'validate_memory', side_effect=RuntimeError('passed userdata guard')):
                with self.assertRaisesRegex(RuntimeError, 'passed userdata guard'):
                    setup.install_bundle(str(path))

    def test_r3_manifest_rejects_missing_preflight_or_old_installer_requirement(self):
        helper = test_manager.ManagerTests()
        with tempfile.TemporaryDirectory() as directory:
            path, original = helper.bundle(Path(directory) / 'bundle')
            for field, invalid in (('minimum_installer', '1.1.0'), ('module_upgrade_preflight', None), ('upgrade_from', [])):
                value = r3_manifest(original)
                value['compatibility'][field] = invalid
                path.write_text(json.dumps(value))
                with patch('phone_profile.profile_from_build', return_value=profile(NEW)):
                    with self.assertRaisesRegex(RuntimeError, 'r3 upgrade'):
                        setup.read_manifest(str(path))

if __name__ == '__main__':
    unittest.main()


# --- tests/test_phone_camera_upgrade.py ---

'Verify source-pinned camera ABI reuse and owned factory-app migration.'

def camera_manifest(apk=camera.APK_HASH):
    return {'revision': 2, 'experimental': True, 'apk_sha256': apk, 'runtime_sha256': camera.RUNTIME_HASH, 'targets': [{'payload': payload, 'target': target, 'before': before, 'after': hashlib.sha256(payload.encode()).hexdigest()} for payload, target, before in (('provider', camera.PROVIDER, camera.PROVIDER_HASH), ('hwl.so', camera.HWL, camera.HWL_HASH))], 'yuv_sha256': hashlib.sha256(b'yuv.so').hexdigest()}

class PhoneCameraUpgradeTests(unittest.TestCase):

    def test_only_audited_apk_and_framework_pairs_are_accepted(self):
        for version, digest in camera.CAMERA_VERSIONS.items():
            selected = camera.camera_inputs(profile(digest))
            self.assertEqual(selected['apk_sha256'], version)
            self.assertEqual(selected['native_abi']['jni_sha256'], camera.YUV_HASH)
            self.assertEqual(selected['native_abi']['capture_contract_sha256'], camera.CAPTURE_ABI)
        selected = profile('4.0.18.0.XFRCNXM')
        invalid = [copy.deepcopy(selected) for _ in range(3)]
        invalid[0]['pins']['camera_apk'] = 'f' * 64
        invalid[1]['pins']['android_runtime'] = 'e' * 64
        invalid[2]['incremental'] = 'OS4.0.17.0.XFRCNXM'
        for value in invalid:
            with self.assertRaisesRegex(RuntimeError, 'ABI profile'):
                camera.camera_inputs(value)

    def test_legacy_receipt_adopts_only_metadata_after_payload_and_source_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            prebuilt = workspace / 'tools/xiaomi-camera'
            prebuilt.mkdir(parents=True)
            saved = camera_manifest()
            (prebuilt / 'manifest.json').write_text(json.dumps(saved))
            for name in ('provider', 'hwl.so', 'yuv.so'):
                (prebuilt / name).write_bytes(name.encode())
            receipt = {'sources': {name: camera.sha256(camera.REPO_ROOT / 'native' / name) for name in ('camera_hwl_roles.cpp', 'camera_yuv_planes.c')}, 'files': {name: camera.sha256(prebuilt / name) for name in ('provider', 'hwl.so', 'yuv.so', 'manifest.json')}}
            (prebuilt / 'receipt.json').write_text(json.dumps(receipt))
            selected = profile('4.0.18.0.XFRCNXM')
            with patch.object(camera, 'ROOT', workspace), patch.object(camera.subprocess, 'run') as compile:
                newer = camera.build('/no-ndk', workspace / 'normalized', selected)
            compile.assert_not_called()
            self.assertEqual(newer['apk_sha256'], camera.APK18_HASH)
            self.assertEqual(newer['runtime_sha256'], camera.RUNTIME_HASH)
            self.assertEqual(newer['targets'], saved['targets'])
            self.assertEqual(newer['yuv_sha256'], saved['yuv_sha256'])
            for name in ('provider', 'hwl.so', 'yuv.so'):
                self.assertEqual((workspace / 'normalized' / name).read_bytes(), (prebuilt / name).read_bytes())
            self.assertEqual(json.loads((prebuilt / 'manifest.json').read_text()), saved)
            (prebuilt / 'hwl.so').write_bytes(b'changed payload')
            with patch.object(camera, 'ROOT', workspace):
                with self.assertRaisesRegex(RuntimeError, 'Invalid precompiled'):
                    camera.build('/no-ndk', workspace / 'invalid', selected)
            (prebuilt / 'hwl.so').write_bytes(b'hwl.so')
            receipt['sources']['camera_yuv_planes.c'] = '0' * 64
            (prebuilt / 'receipt.json').write_text(json.dumps(receipt))
            with patch.object(camera, 'ROOT', workspace):
                with self.assertRaisesRegex(RuntimeError, 'source differs'):
                    camera.build('/no-ndk', workspace / 'invalid-source', selected)

    def test_unknown_metadata_and_native_contract_are_rejected(self):
        for field, wrong in (('revision', 99), ('experimental', False), ('apk_sha256', 'f' * 64), ('runtime_sha256', 'e' * 64), ('yuv_sha256', 'z' * 64), ('native_abi', {'jni_sha256': 'e' * 64}), ('firmware', {'source': 'official-yingtian-ota'})):
            with self.subTest(field=field):
                value = {**camera_manifest(), field: wrong}
                with self.assertRaisesRegex(RuntimeError, 'precompiled camera'):
                    camera.normalized_manifest(value, profile('4.0.18.0.XFRCNXM'))

    def test_boot_script_checks_firmware_and_every_apk_before_hal_mount(self):
        selected = profile('4.0.18.0.XFRCNXM')
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            value = camera.normalized_manifest(camera_manifest(), selected)
            camera.write_module_scripts(folder, value, selected)
            source = (folder / 'post-fs-data.sh').read_text()
            first_mount = source.index('mount -o bind')
            for guard in ('/disable', '/remove', selected['incremental'], camera.APK18_HASH, '/system/lib64/libandroid_runtime.so', '# Validate every namespace'):
                self.assertLess(source.index(guard), first_mount)
            self.assertNotIn(camera.APK_HASH, source)
            self.assertNotIn('@INCREMENTAL@', source)
            for name in ('post-fs-data.sh', 'service.sh'):
                subprocess.run(['sh', '-n', str(folder / name)], check=True)

    def test_owned_camera_migration_preserves_flags_and_copies_new_signed_factory_app(self):
        calls, pushes = ([], [])
        saved = camera_manifest()
        selected = profile('4.0.18.0.XFRCNXM')
        newer = camera.normalized_manifest(saved, selected)
        expected = {camera.MODULE + '/app/MiuiCamera.apk': saved['apk_sha256'], camera.MODULE + '/app/lib/arm64/libcamera_yuv_jni.so': saved['yuv_sha256'], **{camera.MODULE + '/' + item['payload']: item['after'] for item in saved['targets']}}

        def guest(config, command):
            self.assertEqual(config['port'], 5584)
            calls.append(command)
            if command == 'cat ' + camera.MODULE + '/module.prop':
                return 'id=hyperos_avd_xiaomi_camera\nauthor=HyperOS-AVD\n'
            if command == 'ls -A ' + camera.MODULE:
                return '\n'.join(['provider', 'hwl.so', 'app', 'manifest.json', 'module.prop', 'post-fs-data.sh', 'service.sh', 'skip_mount', 'disable', 'remove'])
            if command.startswith('sha256sum '):
                return expected[command[len('sha256sum '):]] + '  payload'
            return ''

        def push(config, *args, **kwargs):
            self.assertEqual(config['port'], 5584)
            pushes.append(args)
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            (workspace / 'local').mkdir()
            with patch.object(camera, 'ROOT', workspace), patch.object(camera, 'root', side_effect=guest), patch.object(camera, 'adb', side_effect=push):
                self.assertEqual(camera.migrate_camera_app({'port': 5584}, saved, newer, workspace, selected), newer)
            self.assertEqual(len(pushes), 8)
            transaction = next((command for command in calls if 'backup=/data/adb/' in command))
            self.assertIn('cp -a ' + camera.APP + '/.', transaction)
            self.assertIn(camera.APK18_HASH, transaction)
            self.assertIn('for flag in disable remove', transaction)
            self.assertIn('cp -p ' + camera.MODULE + '/$flag', transaction)
            self.assertIn("trap '[ -e " + camera.MODULE, transaction)
            self.assertNotIn('pm clear', transaction)
            self.assertNotIn('/data/user', transaction)
            subprocess.run(['sh', '-n'], input=transaction, text=True, check=True)

    def test_camera_migration_refuses_unknown_owned_layout_before_push(self):
        saved = camera_manifest()
        selected = profile('4.0.18.0.XFRCNXM')

        def guest(config, command):
            if '/module.prop' in command:
                return 'id=hyperos_avd_xiaomi_camera\nauthor=HyperOS-AVD\n'
            if command.startswith('ls -A'):
                return 'provider\nhwl.so\napp\nmanifest.json\nmodule.prop\nsystem\n'
            return ''
        with tempfile.TemporaryDirectory() as directory, patch.object(camera, 'root', side_effect=guest), patch.object(camera, 'adb') as push:
            with self.assertRaisesRegex(RuntimeError, 'Unknown owned camera module layout'):
                camera.migrate_camera_app({'port': 5584}, saved, camera.normalized_manifest(saved, selected), Path(directory), selected)
            push.assert_not_called()

    def test_retained_disabled_old_copy_migrates_before_disabled_fastpath(self):
        selected = profile('4.0.18.0.XFRCNXM')
        saved = camera_manifest()
        newer = camera.normalized_manifest(saved, selected)
        calls = []
        config = {'name': 'User-renamed-phone', 'port': 5584, 'sdk': '/unused-sdk'}
        values = {'ro.boot.qemu.avd_name': config['name'], 'ro.boot.hardware': 'ranchu', 'ro.mi.os.version.incremental': selected['incremental']}
        hashes = {camera.APK: camera.APK18_HASH, '/system/lib64/libandroid_runtime.so': camera.RUNTIME_HASH, '/vendor/lib64/libc++.so': camera.CPP_HASH}

        def guest(device, command):
            self.assertEqual(device, config)
            calls.append(command)
            if command.startswith('getprop '):
                return values[command[len('getprop '):]]
            if command.startswith('sha256sum '):
                return hashes[command[len('sha256sum '):]] + '  factory'
            if command == 'pm path com.android.camera':
                return 'package:' + camera.APK
            if command == 'cat ' + camera.MODULE + '/manifest.json':
                return json.dumps(saved)
            if command.startswith('if [ -d ') or '/disable' in command:
                return 'yes'
            return ''
        with patch.object(camera, 'official'), patch('phone_profile.profile_from_build', return_value=selected), patch.object(camera, 'root', side_effect=guest), patch.object(camera, 'build', return_value=newer), patch.object(camera, 'migrate_camera_app', return_value=newer) as migrate:
            self.assertEqual(camera.install(config), newer)
        migrate.assert_called_once()
        self.assertEqual(migrate.call_args.args[:3], (config, saved, newer))
        self.assertFalse(any(('/disable' in command for command in calls)))

    def test_unverified_app_store_camera_update_is_rejected_before_module_access(self):
        selected = profile('4.0.18.0.XFRCNXM')
        config = {'name': 'User-renamed-phone', 'port': 5584, 'sdk': '/unused-sdk'}
        values = {'ro.boot.qemu.avd_name': config['name'], 'ro.boot.hardware': 'ranchu', 'ro.mi.os.version.incremental': selected['incremental']}
        calls = []
        lifecycle_read = module_lifecycle.state_script(camera.MODULE)

        def guest(device, command):
            self.assertEqual(device, config)
            calls.append(command)
            if command == lifecycle_read:
                self.assertNotRegex(command, '\\b(?:touch|rm|mv|cp|mkdir|chmod|chcon|mount|resetprop)\\b')
                return ''
            if command.startswith('getprop '):
                return values[command[len('getprop '):]]
            self.assertEqual(command, 'pm path com.android.camera')
            return 'package:/data/app/unsupported/base.apk'
        with tempfile.TemporaryDirectory() as directory, patch.object(camera, 'ROOT', Path(directory)), patch.object(camera, 'official'), patch('phone_profile.profile_from_build', return_value=selected), patch.object(camera, 'root', side_effect=guest), patch.object(camera, 'build') as build, patch.object(camera, 'adb') as adb, patch.object(camera, 'migrate_camera_app') as migrate:
            with self.assertRaisesRegex(RuntimeError, 'update is unsupported'):
                camera.install(config)
            self.assertEqual(list(Path(directory).iterdir()), [])
        build.assert_not_called()
        adb.assert_not_called()
        migrate.assert_not_called()
        self.assertEqual(calls, [lifecycle_read, *('getprop ' + key for key in values), 'pm path com.android.camera'])

if __name__ == '__main__':
    unittest.main()


# --- tests/test_phone_runtime_upgrade.py ---

'Keep OTA-specific runtime overlays and user identity separate.'

class PhoneRuntimeUpgradeTests(unittest.TestCase):

    def test_deadline_diagnostics_distinguish_factory_patch_missing_libraries_and_unknown_code(self):
        libraries = {'libapp.so': navigation.AOT_BEFORE, 'libapp_launcher.so': navigation.WATCHDOG_BEFORE}
        patched = {'libapp.so': navigation.AOT_AFTER, 'libapp_launcher.so': navigation.WATCHDOG_AFTER}
        state, message = navigation.deadline_status('factory', libraries, patched, factory_hash='factory', factory=True)
        self.assertEqual(state, 'baked')
        self.assertIn('already patched in the factory image', message)
        state, message = navigation.deadline_status('updated', dict.fromkeys(libraries, flutter.EMPTY), {})
        self.assertEqual(state, 'not-applicable')
        self.assertIn('do not apply', message)
        self.assertNotIn('not supported', message)
        self.assertEqual(navigation.deadline_status('changed-apk', libraries, {})[0], 'catalog')
        unknown = dict(libraries, **{'libapp.so': 'a' * 64})
        state, message = navigation.deadline_status('updated', unknown, {})
        self.assertEqual(state, 'unknown')
        self.assertIn('other navigation setup continues', message)
        self.assertEqual(navigation.deadline_status('updated', {}, {})[0], 'unverified')

    def test_deadline_inspection_accepts_empty_native_entries_only_after_readable_apk(self):
        from unittest.mock import patch
        lines = ''.join((name + '|' + flutter.EMPTY + '  -\nnative-' + name + '|missing\n' for name in ('libapp.so', 'libapp_launcher.so')))
        with patch.object(navigation, 'root', return_value=lines) as read:
            result = navigation.inspect_deadlines({}, '/data/app/x/base.apk', 'new', {})
            self.assertEqual(result[0], 'not-applicable')
            self.assertIn('unzip -l "$APK" >/dev/null 2>&1 || exit 1', read.call_args.args[1])
        with patch.object(navigation, 'root', side_effect=RuntimeError('APK unavailable')):
            self.assertEqual(navigation.inspect_deadlines({}, '/data/app/x/base.apk', 'new', {})[0], 'unverified')

    def profile(self):
        return {'hyperos': '4.0.18.0.XFRCNXM', 'incremental': 'OS4.0.18.0.XFRCNXM', 'properties': {'ro.build.fingerprint': 'verified-new-source', 'ro.product.device': 'hongkong'}, 'display': {'width': 1120, 'height': 2436, 'density': 480}}

    def test_selected_identity_does_not_copy_the_previous_fingerprint(self):
        source = b'ro.debuggable=0\nro.hardware=ranchu\nro.build.fingerprint=old\n'
        result = defaults.production_properties(source, self.profile())
        self.assertIn(b'ro.build.fingerprint=verified-new-source\n', result)
        self.assertNotIn(b'ro.build.fingerprint=old\n', result)
        self.assertIn(b'ro.hardware=ranchu\n', result)
        self.assertEqual(defaults.production_properties(result, self.profile()), result)

    def test_current_defaults_use_capabilities_and_keep_legacy_stamps(self):
        legacy = (defaults.AOD_SCRIPT, defaults.REFRESH_SCRIPT, defaults.REFRESH_WRAPPER)
        aod, refresh = defaults.phone_scripts(self.profile())
        wrapper = defaults.refresh_wrapper(self.profile())
        for script in (aod, refresh, wrapper):
            self.assertNotIn(b'ro.mi.os.version.incremental', script)
            self.assertIn(defaults.display_capability_script(), script)
        for stamp in (defaults.AOD_STAMP, defaults.COLOR_STAMP):
            self.assertIn(stamp.encode(), aod)
        self.assertEqual(legacy, (defaults.AOD_SCRIPT, defaults.REFRESH_SCRIPT, defaults.REFRESH_WRAPPER))
        self.assertEqual(defaults.legacy_phone_scripts(), legacy[:2])
        self.assertEqual(defaults.legacy_refresh_wrapper(), legacy[2])
        self.assertIn(b'OS4.0.18.0.XFRCNXM', defaults.legacy_refresh_wrapper(self.profile()))
        self.assertEqual(defaults.display_template('hw.lcd.width=1080\nhw.lcd.height=2400\nhw.lcd.density=440\n', self.profile()), 'hw.lcd.width=1120\nhw.lcd.height=2436\nhw.lcd.density=480\n')

    def test_navigation_mismatched_firmware_exits_before_identity_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            getprop = folder / 'getprop'
            getprop.write_text('#!/bin/sh\ncase "$1" in\nro.boot.hardware) echo ranchu;;\nro.mi.os.version.incremental) echo OS4.0.17.0.XFRCNXM;;\nesac\n')
            getprop.chmod(448)
            script = folder / 'post-fs-data.sh'
            script.write_text(navigation.startup_script(navigation.EARLY_SCRIPT, self.profile()))
            (folder / 'identity.prop').write_text('ro.build.fingerprint=must-not-be-written\n')
            result = subprocess.run(['sh', str(script)], capture_output=True, env=dict(os.environ, PATH=str(folder) + ':' + os.environ['PATH']))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((folder / 'navigation.log').exists())
            self.assertEqual((folder / 'identity.prop').read_text(), 'ro.build.fingerprint=must-not-be-written\n')

    def test_flutter_reuse_requires_ota_shared_library_and_apk_content(self):
        firmware = {'source': 'official-hongkong-ota', 'incremental': 'OS4.0.18.0.XFRCNXM', 'shared_input_sha256': 'a' * 64}
        targets = {'com.miui.home': '/product/priv-app/MiuiHome/MiuiHome.apk', 'com.miui.weather2': '/data/app/weather/base.apk'}
        apks = {'com.miui.home': 'b' * 64, 'com.miui.weather2': 'c' * 64}
        script_hash = hashlib.sha256(flutter.boot_script(firmware=firmware).encode()).hexdigest()
        saved = {'revision': flutter.REVISION, 'firmware': firmware, 'packages': targets, 'apk_hashes': apks, 'startup_script_sha256': script_hash, 'system': {'target': flutter.SYSTEM_LIB, 'before': 'a' * 64, 'after': 'd' * 64}, 'apks': []}
        self.assertTrue(flutter.reusable_manifest(saved, targets, firmware, apks, 'd' * 64, script_hash))
        legacy = copy.deepcopy(saved)
        legacy['revision'] = 6
        self.assertFalse(flutter.reusable_manifest(legacy, targets, firmware, apks, 'd' * 64, script_hash))
        newer_apks = dict(apks, **{'com.miui.home': 'e' * 64})
        self.assertFalse(flutter.reusable_manifest(saved, targets, firmware, newer_apks, 'd' * 64, script_hash))
        self.assertFalse(flutter.reusable_manifest(saved, targets, firmware, apks, 'e' * 64, script_hash))
        other_firmware = dict(firmware, incremental='OS4.0.17.0.XFRCNXM')
        self.assertFalse(flutter.reusable_manifest(saved, targets, other_firmware, apks, 'd' * 64, script_hash))
        self.assertFalse(flutter.reusable_manifest(saved, targets, firmware, apks, 'd' * 64, 'e' * 64))

    def test_flutter_previous_shared_patch_is_a_literal_scoped_upgrade_input(self):
        from patch_flutter import PROFILES
        original = '7f88d7f4d9a464fdd56fb255642c9d300f28f50272ccf5fd31f082c1a52e17f4'
        item = PROFILES[original]
        firmware = {'source': 'official-hongkong-ota', 'incremental': 'OS4.0.18.0.XFRCNXM', 'shared_input_sha256': original}
        script = flutter.boot_script(firmware=firmware)
        expected = '|'.join((flutter.SYSTEM_LIB, original, item['output'], item['legacy'][0]))
        self.assertIn(expected, script)
        self.assertIn('case "$target|$before|$after|$actual"', script)
        guard = script.split('    if [ "$actual" != "$before" ]; then\n', 1)[1].split('    fi\n', 1)[0]
        shell = 'guard() { if [ "$actual" != "$before" ]; then\n' + guard + 'fi; }; log() { :; }; guard'
        for target, actual, allowed in ((flutter.SYSTEM_LIB, item['legacy'][0], True), (flutter.SYSTEM_LIB, original, True), ('/data/app/unknown/lib/arm64/libhyper_os_flutter.so', item['legacy'][0], False), (flutter.SYSTEM_LIB, 'f' * 64, False)):
            env = dict(os.environ, target=target, actual=actual, before=original, after=item['output'])
            result = subprocess.run(['sh', '-c', shell], env=env, capture_output=True)
            self.assertEqual(result.returncode == 0, allowed)
        old = {'revision': 7, 'system': {'target': flutter.SYSTEM_LIB}, 'apks': []}
        self.assertEqual(flutter.old_targets(old), [old['system']])
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'module.sh'
            path.write_text(script)
            self.assertEqual(subprocess.run(['sh', '-n', str(path)]).returncode, 0)

    def test_flutter_guard_precedes_mounts_and_weather_rescan_is_deferred(self):
        firmware = {'source': 'official-hongkong-ota', 'incremental': 'OS4.0.18.0.XFRCNXM', 'shared_input_sha256': 'a' * 64}
        script = flutter.boot_script(firmware=firmware)
        self.assertLess(script.index('OS4.0.18.0.XFRCNXM'), script.index('. "$MODDIR/targets.conf"'))
        early = script.split('if [ "${0##*/}" = post-fs-data.sh ]; then', 1)[1].split('    exit 0', 1)[0]
        self.assertIn('[ "$package" = com.miui.weather2 ] && continue', early)
        self.assertIn('"$current_sha" = "$apk_sha"', script)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'module.sh'
            path.write_text(script)
            result = subprocess.run(['sh', '-n', str(path)], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)

if __name__ == '__main__':
    unittest.main()


# --- tests/test_phone_firmware_upgrade.py ---

'Verify registered source upgrades, conservative owners and rollback dispatch.'

PHONE17 = '4.0.17.0.XFRCNXM'

PHONE18 = '4.0.18.0.XFRCNXM'

PHONE24 = '4.0.24.0.XFRCNXM'

def firmware_manifest(firmware, revision=6):
    return {'variant': 'os4-official', 'hyperos': firmware, 'version': f'v0.2.5-a17-hyperos4-hongkong-r{revision}', 'build': {'source': common.OS4_SOURCE, 'hyperos': firmware, 'archive_sha256': ARCHIVES[firmware]}}

class FirmwareUpgradeTests(unittest.TestCase):

    def test_historical_layout_rejects_extra_early_hooks_and_aliases(self):
        for case in (None, 'post-mount.sh', 'boot-completed.sh', 'sepolicy.rule', 'zygisk', 'system', 'initrc', 'initrc-link', 'uninstall.sh', 'service.sh.next', 'symlink', 'hardlink'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                module = Path(directory) / 'old-owner'
                module.mkdir()
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
                    return subprocess.run(['sh', '-c', script], check=kwargs['check'], capture_output=True, text=True)
                with patch.object(common, 'adb', side_effect=adb):
                    if case:
                        with self.assertRaisesRegex(RuntimeError, 'historical startup'):
                            manage.audit_legacy_startup({}, str(module.resolve()))
                    else:
                        manage.audit_legacy_startup({}, str(module.resolve()))

    def test_direct_historical_upgrade_guards_nav5_flutter6_without_losing_modern_input_checks(self):
        from patch_flutter import PROFILES
        from phone_profile import LEGACY_PINS
        modules = {'hyperos_avd_navigation': {'revision': 5, 'property': 'ro.miui.product.home', 'value': 'com.miui.home', 'component': 'com.miui.home/com.miui.home.recents.RecentsActivity'}, 'hyperos_avd_flutter_render': {'revision': 6, 'packages': {}, 'system': {'target': '/system_ext/lib64/libhyper_os_flutter.so', 'before': LEGACY_PINS['flutter'], 'after': PROFILES[LEGACY_PINS['flutter']]['output']}}}
        original = '#!/system/bin/sh\nprintf original\n'
        commands = []

        def adb(config, *args, **kwargs):
            command = args[-1]
            commands.append(args)
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
            old.update(firmware_manifest(PHONE17, 2))
            process = Mock()
            process.poll.return_value = None
            with patch.object(manage, 'idle'), patch.object(common, 'adb', side_effect=adb), patch.object(manage.subprocess, 'Popen', return_value=process), patch.object(manage, 'audit_firmware_modules', return_value=[]) as audit, patch('launch.vulkan_features', return_value=[]) as vk, patch('rear_display_config.runtime_options', return_value=[]) as rear:
                manage.prepare_firmware_upgrade(root, old, firmware_manifest(PHONE24), 'Renamed_Phone', 5584, Path('/sdk'), backup)
            vk.assert_called_once_with(old['build'])
            rear.assert_called_once_with(old['build'])
            self.assertEqual(audit.call_args.kwargs['guarded_ids'], set(modules))
            receipt = json.loads((backup / 'module-upgrade.json').read_text())
            self.assertEqual({value['revision'] for value in receipt['guarded_modules']}, {5, 6})
            self.assertTrue(all((value['flags'] == ['disable'] for value in receipt['guarded_modules'])))
            self.assertEqual((root / 'avd/Renamed_Phone.avd/userdata-qemu.img').read_bytes(), b'personal data and stable serial')
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
        old = firmware_manifest(PHONE18, 5)
        old['files'] = {}
        for name in ('images/system.img', 'images/kernel-ranchu', 'images/ramdisk.img', 'images/encryptionkey.img', 'images/advancedFeatures.ini', 'tools/ksud-aarch64-linux-android'):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(name.encode())
            old['files'][name] = {'sha256': common.sha256(path)}
        backup = directory / 'backup'
        backup.mkdir()
        return (root, old, backup)

    def test_source_dispatch_keeps_frozen_bootstrap_and_accepts_future_revisions(self):
        for source, target, legacy in ((PHONE17, PHONE18, True), (PHONE18, PHONE24, False), (PHONE17, PHONE24, False)):
            for revision in (6, 999):
                with self.subTest(source=source, revision=revision), patch.object(manage, 'prepare_module_upgrade') as frozen, patch.object(manage, '_stage_module_upgrade') as adaptive:
                    old, new = (firmware_manifest(source, 1), firmware_manifest(target, revision))
                    manage.prepare_firmware_upgrade(Path('/instance'), old, new, 'Renamed_Phone', 5990, Path('/sdk'), Path('/backup'))
                    self.assertEqual(frozen.called, legacy)
                    self.assertEqual(adaptive.called, not legacy)
                    if adaptive.called:
                        self.assertFalse(adaptive.call_args.kwargs['legacy'])
                        self.assertEqual(adaptive.call_args.args[-1], profile(source))

    def test_unknown_mismatched_downgrade_and_tampered_sources_fail_before_boot(self):
        pairs = []
        for field in ('archive_sha256', 'hyperos', 'source'):
            old, new = (firmware_manifest(PHONE18), firmware_manifest(PHONE24))
            if field == 'archive_sha256':
                old['build'][field] = 'f' * 64
            elif field == 'hyperos':
                new['build'][field] = '4.0.999.0.XFRCNXM'
            else:
                new['build'][field] = 'official-yingtian-ota'
            pairs.append((old, new))
        old, new = (firmware_manifest(PHONE18), firmware_manifest(PHONE24))
        new['hyperos'] = PHONE18
        pairs += [(old, new), (firmware_manifest(PHONE24), firmware_manifest(PHONE18)), (firmware_manifest(PHONE18), firmware_manifest(PHONE18))]
        old, new = (firmware_manifest(PHONE18), firmware_manifest(PHONE24))
        new['variant'] = 'os4-pad'
        pairs.append((old, new))
        with patch.object(manage.subprocess, 'Popen') as boot:
            for old, new in pairs:
                with self.subTest(old=old, new=new), self.assertRaises(RuntimeError):
                    manage.prepare_firmware_upgrade(Path('/instance'), old, new, 'Any_Name', 5990, Path('/sdk'), Path('/backup'))
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
                    manage.prepare_firmware_upgrade(root, old, firmware_manifest(PHONE24), 'Renamed_Phone', 5990, Path('/sdk'), backup)
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
                owners = [{'id': 'hyperos_avd_native_compat', 'flags': ['disable'], 'mode': 'content-adaptive'}]
                audit = Mock(side_effect=RuntimeError('unknown active owner') if fail else None, return_value=owners)
                with patch.object(manage, 'idle'), patch.object(common, 'adb', side_effect=adb), patch.object(manage.subprocess, 'Popen', return_value=process) as boot, patch.object(manage, 'audit_firmware_modules', audit), patch.object(manage, 'guarded_modules') as guards, patch('launch.vulkan_features', return_value=['-feature', 'verified-vulkan']), patch('rear_display_config.runtime_options', return_value=['-no-multi-display']):
                    if fail:
                        with self.assertRaisesRegex(RuntimeError, 'unknown active owner'):
                            manage.prepare_firmware_upgrade(root, old, firmware_manifest(PHONE24), 'Renamed_Phone', 5990, Path('/sdk'), backup)
                    else:
                        manage.prepare_firmware_upgrade(root, old, firmware_manifest(PHONE24), 'Renamed_Phone', 5990, Path('/sdk'), backup)
                    guards.assert_not_called()
                    audit.assert_called_once_with({'sdk': '/sdk', 'name': 'Renamed_Phone', 'port': 5990}, old, root)
                    command = boot.call_args.args[0]
                    self.assertIn('8192', command)
                    self.assertIn('verified-vulkan', command)
                self.assertEqual((root / 'avd/Renamed_Phone.avd/userdata-qemu.img').read_bytes(), b'personal data and stable serial')
                stamps = [args for args in calls if AWAKE_STAMP in args[-1]]
                self.assertEqual(bool(stamps), not fail)
                self.assertFalse(any(('settings put' in args[-1] or 'push' == args[0] for args in calls)))
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
            target.update(firmware_manifest(PHONE24))
            target['compatibility'].update(module_upgrade_preflight=manage.MODULE_UPGRADE_PREFLIGHT, upgrade_policy=manage.FORWARD_UPGRADE_POLICY)
            root = folder / 'instance'
            before = helper.legacy(root, original)
            installed = root / 'local/installed-release.json'
            old = json.loads(installed.read_text())
            old.update(firmware_manifest(PHONE18, 5))
            old['format'] = 3
            old['compatibility'] = original['compatibility']
            installed.write_text(json.dumps(old))

            def fail_stage(*args, **kwargs):
                self.assertTrue((root / 'local/upgrade-pending.json').is_file())
                (root / 'avd/Test_temp.avd/userdata-qemu.img').write_bytes(b'modified by old guest')
                raise RuntimeError('injected adaptive staging failure')
            with patch.object(setup, 'read_manifest', return_value=(target, path.as_uri())), patch.object(setup, 'install_bundle'), patch.object(manage, 'prepare_storage'), patch.object(manage, '_stage_module_upgrade', side_effect=fail_stage) as stage, patch('userdata_resize.check_dependencies', return_value={}), patch('sys.stdout', new_callable=io.StringIO):
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
        old_owner = {'id': 'hyperos_avd_navigation', 'status': 'preserved', 'reason': 'Unreviewed navigation receipt schema.'}
        self.patches(core_legacy=[old_owner], app_legacy={'modules': [], 'preserved': [{'module': 'hyperos_avd_xiaomi_camera', 'reason': 'unknown-or-custom'}]})
        guarded = {'hyperos_avd_navigation', 'hyperos_avd_xiaomi_camera'}
        receipt = manage.audit_firmware_modules({}, firmware_manifest(PHONE17), Path('/instance'), guarded_ids=guarded)
        self.assertFalse(any((value['id'] in guarded for value in receipt)))
        with self.assertRaisesRegex(RuntimeError, 'Unknown legacy Apps'):
            manage.audit_firmware_modules({}, firmware_manifest(PHONE17), Path('/instance'), guarded_ids={'hyperos_avd_navigation'})

    def patches(self, *, core_flags=None, app_flags=None, core_manifest=None, core_legacy=None, app_legacy=None, pending=False):
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
        plan = stack.enter_context(patch('app_compat_migration.plan', return_value=app_legacy or {'modules': [], 'preserved': []}))
        return (guest, verify_core, verify_apps, plan)

    def test_adaptive_owners_are_authenticated_without_writing_any_choice(self):
        guest, core, apps, plan = self.patches()
        receipt = manage.audit_firmware_modules({'name': 'Renamed'}, firmware_manifest(PHONE18), Path('/instance'))
        self.assertEqual([item['mode'] for item in receipt], ['content-adaptive', 'content-adaptive'])
        core.assert_called_once()
        apps.assert_called_once()
        self.assertEqual(plan.call_args.kwargs['workspace'], Path('/instance'))
        commands = [call.args[1] for call in guest.call_args_list]
        self.assertFalse(any(('settings put' in command or 'mv ' in command or 'rm ' in command or ('touch ' in command) for command in commands)))

    def test_disabled_and_removed_current_modules_keep_flags_and_payloads(self):
        _, core, apps, _ = self.patches(core_flags=['disable'], app_flags=['remove'])
        receipt = manage.audit_firmware_modules({}, firmware_manifest(PHONE18), Path('/instance'))
        self.assertEqual(receipt[0]['flags'], ['disable'])
        self.assertEqual(receipt[1]['flags'], ['remove'])
        core.assert_not_called()
        apps.assert_not_called()

    def test_pending_owner_blocks_switch_without_cancelling_it(self):
        guest, core, apps, _ = self.patches(pending=True)
        with self.assertRaisesRegex(RuntimeError, 'pending KernelSU'):
            manage.audit_firmware_modules({}, firmware_manifest(PHONE18), Path('/instance'))
        core.assert_not_called()
        apps.assert_not_called()
        self.assertFalse(any(('rm ' in call.args[1] for call in guest.call_args_list)))

    def test_unknown_active_core_or_legacy_payload_blocks_switch(self):
        for case in ('core', 'legacy-core', 'legacy-app'):
            with self.subTest(case=case):
                self.patches(core_manifest={'revision': 999} if case == 'core' else None, core_legacy=[{'id': 'hyperos_avd_navigation', 'status': 'preserved', 'reason': 'Unreviewed legacy file contents.'}] if case == 'legacy-core' else [], app_legacy={'modules': [], 'preserved': [{'module': 'hyperos_avd_xiaomi_camera', 'reason': 'unknown-or-custom'}]} if case == 'legacy-app' else None)
                with self.assertRaisesRegex(RuntimeError, 'Unknown'):
                    manage.audit_firmware_modules({}, firmware_manifest(PHONE18), Path('/instance'))
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
        cases = (None, 'empty-lock', 'guard-only', 'bad-pid', 'bad-boot', 'extra-field', 'nonempty-guard', 'guard-link', 'directory-link', 'pid-link', 'pid-hardlink', 'guard-hardlink', 'guard-directory', 'foreign-owner', 'apps-owner')
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                folder = Path(directory) / 'module'
                folder.mkdir()
                lock = folder / 'service.lock'
                lock.mkdir()
                (folder / 'service.sh').write_text('#!/system/bin/sh\n')
                (folder / 'features.disabled').write_text('assistant\n')
                (folder / 'service.lock.guard').write_bytes(b'')
                (lock / 'pid').write_text('3781\n')
                (lock / 'boot').write_text('1c59c65c-aea6-4ed6-a208-892fd5098f0d\n')
                expected = {'id': 'hyperos_avd_native_compat', 'files_sha256': {'service.sh': 'a' * 64}}
                if case in ('empty-lock', 'guard-only', 'directory-link'):
                    (lock / 'pid').unlink()
                    (lock / 'boot').unlink()
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
                    file.unlink()
                    file.symlink_to(folder / 'external')
                elif case in ('guard-hardlink', 'pid-hardlink'):
                    file = folder / 'service.lock.guard' if case == 'guard-hardlink' else lock / 'pid'
                    os.link(file, Path(directory) / 'external')
                elif case == 'guard-directory':
                    (folder / 'service.lock.guard').unlink()
                    (folder / 'service.lock.guard').mkdir()
                elif case == 'apps-owner':
                    expected['id'] = 'hyperos_avd_app_compat'

                def guest(config, command):
                    ownership = f'{os.geteuid()}:{os.getegid()}' if case != 'foreign-owner' else '99999:99999'
                    command = command.replace('= 0:0 ]', '= ' + ownership + ' ]')
                    if sys.platform == 'darwin':
                        for before, after in (('stat -c %h', 'stat -f %l'), ('stat -c %s', 'stat -f %z'), ('stat -c %u:%g', 'stat -f %u:%g')):
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
