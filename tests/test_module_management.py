"""Consolidated unit tests for module lifecycle & management:
hook preservation, state transitions, WebUI management, and parrot module validation.
"""
from contextlib import ExitStack
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

REPO = Path(__file__).resolve().parents[1]
ROOT = REPO
sys.path.insert(0, str(REPO / 'scripts'))

import apply_camera_fix as camera
import apply_flutter_fix as flutter
import apply_navigation_fix as navigation
import module_lifecycle as lifecycle
import module_webui
from patch_flutter import PROFILES
from patch_outcome import UnsupportedPatch
from phone_profile import profile



# --- tests/test_module_hook_preservation.py ---

'Verify real hook files through host installer reuse and enable paths.'

class HookPreservationTests(unittest.TestCase):

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name)
        self.workspace = self.folder / 'workspace'
        (self.workspace / 'local').mkdir(parents=True)
        self.firmware = profile('4.0.18.0.XFRCNXM')
        (self.workspace / 'local/build.json').write_text(json.dumps({'source': 'official-hongkong-ota', 'hyperos': self.firmware['hyperos'], 'archive_sha256': self.firmware['archive_sha256']}))
        self.context = flutter.firmware_context(json.loads((self.workspace / 'local/build.json').read_text()))
        self.commands = []
        self.module = self.folder / 'guest/module'
        self.module.mkdir(parents=True)
        self.pending = self.folder / 'guest/modules_update'
        self.remote = self.folder / 'guest/tmp'
        self.remote.mkdir()
        self.packages = {'com.miui.home': '/product/priv-app/MiuiHome/MiuiHome.apk', 'com.miui.weather2': '/data/app/com.miui.weather2/base.apk'}
        self.apk_hashes = {name: hashlib.sha256(name.encode()).hexdigest() for name in self.packages}
        self.module_id = None

    def root(self, config, command, **kwargs):
        self.commands.append(command)
        replies = {'id -u': '0', 'getprop sys.boot_completed': '1', 'getprop ro.mi.os.version.incremental': self.firmware['incremental'], 'getprop ' + navigation.PROPERTY: 'com.miui.home', 'cmd overlay lookup android android:string/config_recentsComponentName': navigation.COMPONENT, 'test -f /product/overlay/MiuiHomeLauncherResOverlay.apk': ''}
        if command in replies:
            return replies[command]
        if command.startswith('pm path '):
            return 'package:' + self.packages[command.removeprefix('pm path ')]
        for package, path in self.packages.items():
            if command == 'sha256sum ' + path:
                return self.apk_hashes[package] + '  ' + path
        if command == 'sha256sum ' + flutter.SYSTEM_LIB or command.startswith('if [ -f ' + flutter.SYSTEM_LIB):
            return PROFILES[self.context['shared_input_sha256']]['output'] + '  ' + flutter.SYSTEM_LIB
        if re.search('\\nsh ' + re.escape(self.module_id) + '/(service|post-fs-data)\\.sh$', command):
            return ''
        if '\ncmd overlay disable ' in command:
            return ''
        translated = command.replace('/data/adb/modules_update/' + self.module_id.rsplit('/', 1)[1], str(self.pending))
        translated = translated.replace(self.module_id, str(self.module)).replace('/data/local/tmp', str(self.remote))
        result = subprocess.run(['sh', '-c', translated], capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError('Fixture guest command failed: ' + command + '\n' + result.stderr)
        return result.stdout.strip()

    def push(self, config, action, *args, **kwargs):
        if action != 'push':
            raise AssertionError('Native payloads must not be pulled during hook migration.')
        destination = Path(args[1].replace('/data/local/tmp', str(self.remote)))
        shutil.copyfile(args[0], destination)

    def seed_flutter(self, *, receipt='legacy', hooks='legacy', revision=None):
        self.module_id = flutter.MODULE
        legacy = flutter.legacy_boot_script(firmware=self.context)
        current = flutter.boot_script(firmware=self.context)
        receipt_script = legacy if receipt == 'legacy' else current
        script = legacy if hooks == 'legacy' else current
        (self.module / 'module.prop').write_text('id=' + flutter.MODULE_ID + '\nauthor=HyperOS-AVD\n')
        self.saved = {'revision': flutter.REVISION if revision is None else revision, 'firmware': self.context, 'packages': self.packages, 'apk_hashes': self.apk_hashes, 'startup_script_sha256': hashlib.sha256(receipt_script.encode()).hexdigest(), 'system': {'target': flutter.SYSTEM_LIB, 'before': self.context['shared_input_sha256'], 'after': PROFILES[self.context['shared_input_sha256']]['output']}, 'apks': [], 'skipped_apks': {}}
        (self.module / 'manifest.json').write_text(json.dumps(self.saved, indent=2) + '\n')
        for name in ('post-fs-data.sh', 'service.sh'):
            (self.module / name).write_text(script)
            (self.module / name).chmod(493)
        for name in ('flutter.so', 'com.miui.home.apk', 'targets.conf', 'apks.conf'):
            (self.module / name).write_bytes(b'owned native payload: ' + name.encode())
        return current

    def seed_navigation(self):
        self.module_id = navigation.MODULE
        (self.module / 'module.prop').write_text('id=hyperos_avd_navigation\nauthor=HyperOS-AVD\n')
        self.saved = {'revision': navigation.REVISION, 'hyperos': '4.0.17.0.XFRCNXM', 'incremental': 'OS4.0.17.0.XFRCNXM', 'serial_number': '69704/F5XA01467'}
        (self.module / 'manifest.json').write_text(json.dumps(self.saved, indent=2) + '\n')
        previous = profile('4.0.17.0.XFRCNXM')
        for name, template in (('post-fs-data.sh', navigation.EARLY_SCRIPT), ('service.sh', navigation.BOOT_SCRIPT)):
            (self.module / name).write_text(navigation.legacy_startup_script(template, previous))
            (self.module / name).chmod(493)
        (self.module / 'owned-native.so').write_bytes(b'unchanged native payload')

    def snapshot(self):
        return {path.name: (path.lstat().st_ino, path.read_bytes() if not path.is_symlink() else path.readlink()) for path in self.module.iterdir()}

    def run_flutter(self, *, enable=False):
        with patch.object(flutter, 'ROOT', self.workspace), patch.object(flutter, 'official'), patch.object(flutter, 'root', side_effect=self.root), patch.object(flutter, 'adb') as adb, patch.object(flutter, 'detach') as detach:
            result = flutter.install({}, enable=enable)
            adb.assert_not_called()
            detach.assert_not_called()
        return result

    def run_navigation(self, *, enable=False):
        with ExitStack() as stack:
            stack.enter_context(patch.object(navigation, 'ROOT', self.workspace))
            stack.enter_context(patch.object(navigation, 'official'))
            stack.enter_context(patch.object(navigation, 'root', side_effect=self.root))
            adb = stack.enter_context(patch.object(navigation, 'adb', side_effect=self.push))
            stack.enter_context(patch('phone_profile.profile_from_build', return_value=self.firmware))
            stack.enter_context(patch.object(navigation, 'inspect_deadlines', return_value=('catalog', 'audited native code')))
            result = navigation.install({}, enable=enable)
        return (result, adb)

    def test_flutter_saved_current_sha_never_authorizes_local_hook_overwrite(self):
        for revision in (6, flutter.REVISION):
            with self.subTest(revision=revision):
                self.seed_flutter(receipt='current', hooks='current', revision=revision)
                service = self.module / 'service.sh'
                service.write_text(service.read_text() + '# local startup edit\n')
                baseline = self.snapshot()
                result = self.run_flutter()
                self.assertEqual(result, {'preserved': True, 'reason': 'unreviewed-startup-hook', 'hook': 'service.sh'})
                self.assertEqual(self.snapshot(), baseline)
                self.assertFalse((self.workspace / 'work').exists())
                self.assertFalse((self.workspace / 'local/flutter-render-fix.json').exists())

    def test_flutter_enable_keeps_disable_when_hook_is_local_or_missing(self):
        for missing in (False, True):
            with self.subTest(missing=missing):
                self.seed_flutter(receipt='current')
                service = self.module / 'service.sh'
                if missing:
                    service.unlink()
                    service.symlink_to(self.folder / 'missing-hook')
                else:
                    service.write_text(service.read_text() + '# local startup edit\n')
                (self.module / 'disable').touch()
                baseline = self.snapshot()
                result = self.run_flutter(enable=True)
                self.assertTrue(result['preserved'])
                self.assertEqual(self.snapshot(), baseline)
                self.assertTrue((self.module / 'disable').exists())
                self.assertFalse((self.workspace / 'work').exists())

    def test_flutter_prior_same_revision_migrates_only_hooks_and_receipt(self):
        current = self.seed_flutter()
        baseline = self.snapshot()
        result = self.run_flutter()
        for name in ('flutter.so', 'com.miui.home.apk', 'targets.conf', 'apks.conf', 'module.prop'):
            self.assertEqual(self.snapshot()[name], baseline[name])
        for name in ('post-fs-data.sh', 'service.sh'):
            self.assertEqual((self.module / name).read_text(), current)
            self.assertEqual((self.module / name).stat().st_mode & 511, 493)
        receipt = json.loads((self.module / 'manifest.json').read_text())
        self.assertEqual(receipt['startup_script_sha256'], hashlib.sha256(current.encode()).hexdigest())
        self.assertEqual(result, receipt)
        self.assertEqual(json.loads((self.workspace / 'local/flutter-render-fix.json').read_text()), receipt)
        self.assertFalse((self.workspace / 'work').exists())
        self.assertFalse(any(('.lifecycle.' in path.name for path in self.module.iterdir())))

    def test_flutter_current_hooks_are_not_replaced_on_reuse(self):
        self.seed_flutter(receipt='current', hooks='current')
        baseline = self.snapshot()
        self.run_flutter()
        self.assertEqual(self.snapshot(), baseline)
        self.assertFalse((self.workspace / 'work').exists())

    def test_navigation_unknown_hook_preserves_disabled_owned_module(self):
        self.seed_navigation()
        (self.module / 'service.sh').write_text('#!/system/bin/sh\n# locally maintained hook\n')
        (self.module / 'disable').touch()
        baseline = self.snapshot()
        result, adb = self.run_navigation(enable=True)
        self.assertEqual(result, {'preserved': True, 'reason': 'unreviewed-startup-hook', 'hook': 'service.sh'})
        self.assertEqual(self.snapshot(), baseline)
        adb.assert_not_called()
        self.assertFalse((self.workspace / 'work').exists())
        self.assertFalse((self.workspace / 'local/navigation-fix.json').exists())

    def test_navigation_known_previous_ota_hooks_use_atomic_refresh(self):
        self.seed_navigation()
        baseline = self.snapshot()
        result, adb = self.run_navigation()
        self.assertEqual(self.snapshot()['owned-native.so'], baseline['owned-native.so'])
        self.assertEqual(result['serial_number'], self.saved['serial_number'])
        for name, template in (('post-fs-data.sh', navigation.EARLY_SCRIPT), ('service.sh', navigation.BOOT_SCRIPT)):
            self.assertEqual((self.module / name).read_text(), navigation.startup_script(template, self.firmware))
            self.assertEqual((self.module / name).stat().st_mode & 511, 493)
            self.assertFalse(any((name + '.next' in command for command in self.commands)))
            self.assertFalse(any((call.args[2].endswith('/' + name) for call in adb.call_args_list)))
        self.assertFalse(any(('.lifecycle.' in path.name for path in self.module.iterdir())))

if __name__ == '__main__':
    unittest.main()


# --- tests/test_module_lifecycle.py ---

'Exercise actual lifecycle shell guards and installer preservation boundaries.'

class LifecycleTests(unittest.TestCase):

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name)
        self.module = self.folder / 'modules/test_module'
        self.pending = self.folder / 'modules_update/test_module'
        self.module.mkdir(parents=True)
        self.module_id = '/data/adb/modules/test_module'

    def translate(self, command):
        return command.replace('/data/adb/modules_update/test_module', str(self.pending)).replace(self.module_id, str(self.module))

    def root(self, config, command):
        result = subprocess.run(['sh', '-c', self.translate(command)], capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError('guest shell refused mutation: ' + str(result.returncode))
        return result.stdout.strip()

    def test_all_lifecycle_markers_including_dangling_aliases_win(self):
        for flag in ('disable', 'remove', 'pending'):
            marker = self.pending if flag == 'pending' else self.module / flag
            marker.parent.mkdir(parents=True, exist_ok=True)
            for alias in (False, True):
                if alias:
                    marker.symlink_to(self.folder / 'missing')
                else:
                    marker.touch()
                self.assertEqual(lifecycle.preserved(self.root, {}, self.module_id), {'preserved': True, 'lifecycle': [flag]})
                if flag != 'disable':
                    self.assertIsNotNone(lifecycle.preserved(self.root, {}, self.module_id, enable=True))
                marker.unlink()

    def test_enable_requires_owned_metadata_and_never_clears_removal(self):
        flag = self.module / 'disable'
        flag.symlink_to(self.folder / 'missing')
        prop = self.module / 'module.prop'
        prop.write_text('id=foreign_module\nauthor=SomeoneElse\n')
        with self.assertRaises(RuntimeError):
            lifecycle.enable_owned(self.root, {}, self.module_id)
        self.assertTrue(flag.is_symlink())
        prop.write_text('id=test_module\nauthor=HyperOS-AVD\n')
        (self.module / 'remove').symlink_to(self.folder / 'missing')
        with self.assertRaises(RuntimeError):
            lifecycle.enable_owned(self.root, {}, self.module_id)
        self.assertTrue(flag.is_symlink())
        (self.module / 'remove').unlink()
        lifecycle.enable_owned(self.root, {}, self.module_id)
        self.assertFalse(flag.is_symlink())

    def test_pending_or_new_flags_block_mutation_and_do_not_touch_payload(self):
        target = self.folder / 'must-not-write'
        for flag in ('disable', 'remove', 'pending'):
            marker = self.pending if flag == 'pending' else self.module / flag
            marker.parent.mkdir(parents=True, exist_ok=True)
            marker.symlink_to(self.folder / 'missing')
            with self.assertRaises(RuntimeError):
                self.root({}, lifecycle.mutation_guard(self.module_id) + 'touch ' + str(target))
            self.assertFalse(target.exists())
            self.assertTrue(marker.is_symlink())
            marker.unlink()

    def test_only_exact_legacy_hooks_are_migrated_atomically(self):
        (self.module / 'module.prop').write_text('id=test_module\nauthor=HyperOS-AVD\n')
        hook = self.module / 'service.sh'
        old, new = ('#!/bin/sh\nexit 0\n', '#!/bin/sh\n# checked lifecycle\nexit 0\n')
        hook.write_text(old)
        lifecycle.refresh_hooks(self.root, {}, self.module_id, {'service.sh': (old, new)})
        self.assertEqual(hook.read_text(), new)
        lifecycle.refresh_hooks(self.root, {}, self.module_id, {'service.sh': (old, new)})
        hook.write_text(old + '# local hook\n')
        with self.assertRaisesRegex(RuntimeError, 'Unreviewed'):
            lifecycle.refresh_hooks(self.root, {}, self.module_id, {'service.sh': (old, new)})
        self.assertEqual(hook.read_text(), old + '# local hook\n')
        self.assertFalse(any(('.lifecycle.' in p.name for p in self.module.iterdir())))

    def test_unknown_second_hook_preserves_first_legacy_hook(self):
        (self.module / 'module.prop').write_text('id=test_module\nauthor=HyperOS-AVD\n')
        old, new = ('#!/bin/sh\nexit 0\n', '#!/bin/sh\n# checked lifecycle\nexit 0\n')
        first = self.module / 'post-fs-data.sh'
        second = self.module / 'service.sh'
        first.write_text(old)
        second.write_text(old + '# custom service\n')
        with self.assertRaisesRegex(RuntimeError, 'Unreviewed'):
            lifecycle.refresh_hooks(self.root, {}, self.module_id, {'post-fs-data.sh': (old, new), 'service.sh': (old, new)})
        self.assertEqual(first.read_text(), old)
        self.assertEqual(second.read_text(), old + '# custom service\n')

    def test_reviewed_multiple_versions_can_be_verified_without_enabling(self):
        (self.module / 'module.prop').write_text('id=test_module\nauthor=HyperOS-AVD\n')
        marker = self.module / 'disable'
        marker.touch()
        old, prior, current = ('#!/bin/sh\nexit 0\n', '#!/bin/sh\nexit 1\n', '#!/bin/sh\nexit 2\n')
        service = self.module / 'service.sh'
        service.write_text(prior)
        inode = service.stat().st_ino
        observed = lifecycle.verify_hooks(self.root, {}, self.module_id, {'service.sh': ((old, prior), current)}, allow_disabled=True)
        self.assertEqual(observed['service.sh'], hashlib.sha256(prior.encode()).hexdigest())
        self.assertEqual(service.stat().st_ino, inode)
        self.assertTrue(marker.exists())
        marker.unlink()
        lifecycle.refresh_hooks(self.root, {}, self.module_id, {'service.sh': ((old, prior), current)})
        self.assertEqual(service.read_text(), current)

    def test_receipt_refresh_checks_inspected_content_and_preserves_payload(self):
        (self.module / 'module.prop').write_text('id=test_module\nauthor=HyperOS-AVD\n')
        receipt = self.module / 'manifest.json'
        payload = self.module / 'payload.so'
        old, current = ('{"hook": "old"}\n', '{"hook": "current"}\n')
        receipt.write_text(old)
        payload.write_bytes(b'unchanged payload')
        inode = payload.stat().st_ino
        with self.assertRaises(RuntimeError):
            lifecycle.refresh_receipt(self.root, {}, self.module_id, '{"hook": "unrelated"}', current)
        self.assertEqual(receipt.read_text(), old)
        lifecycle.refresh_receipt(self.root, {}, self.module_id, old.strip(), current)
        self.assertEqual(receipt.read_text(), current)
        self.assertEqual(payload.stat().st_ino, inode)
        self.assertEqual(payload.read_bytes(), b'unchanged payload')
        self.assertFalse(any(('.lifecycle.' in path.name for path in self.module.iterdir())))

    def test_removed_during_boot_wait_exits_before_effects(self):
        tools = self.folder / 'tools'
        tools.mkdir()
        flag = self.module / 'remove'
        (tools / 'getprop').write_text('#!/bin/sh\ntouch ' + str(flag) + '\necho 0\n')
        (tools / 'getprop').chmod(448)
        target = self.folder / 'must-not-write'
        original = '#!/bin/sh\nMODDIR=${0%/*}\ncount=0\nwhile [ "$(getprop sys.boot_completed)" != 1 ]; do\n    count=$((count+1)); [ "$count" -lt 2 ] || exit 1; sleep 1\ndone\nsettings put global test 1\ntouch ' + str(target) + '\n'
        (tools / 'settings').write_text('#!/bin/sh\ntouch ' + str(target) + '\n')
        (tools / 'settings').chmod(448)
        service = self.module / 'service.sh'
        service.write_text(lifecycle.guarded_hook(original))
        result = subprocess.run(['sh', str(service)], capture_output=True, text=True, env=dict(os.environ, PATH=str(tools) + ':' + os.environ['PATH']))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(flag.exists())
        self.assertFalse(target.exists())

    def test_generated_hooks_stop_on_broken_lifecycle_markers(self):
        import apply_assistant_fix as assistant
        import apply_flutter_fix as flutter
        import apply_navigation_fix as navigation
        import apply_boot_service_fix as boot
        import apply_pad_camera_native_fix as pad_camera
        import apply_xiaomi_camera_fix as phone_camera
        from phone_profile import profile
        firmware = profile('4.0.18.0.XFRCNXM')
        pad_folder = self.folder / 'pad-hooks'
        phone_folder = self.folder / 'phone-hooks'
        pad_folder.mkdir()
        phone_folder.mkdir()
        pad_camera.write_scripts(pad_folder)
        phone_camera.write_module_scripts(phone_folder, {'apk_sha256': phone_camera.APK18_HASH, 'runtime_sha256': phone_camera.RUNTIME_HASH, 'yuv_sha256': 'a' * 64, 'targets': []}, firmware)
        hooks = [assistant.boot_script(), assistant.boot_script(assistant.PAD_SOURCE), flutter.boot_script(), flutter.boot_script(flutter.PAD_SOURCE), boot.boot_script()[0], navigation.startup_script(navigation.EARLY_SCRIPT, firmware), navigation.startup_script(navigation.BOOT_SCRIPT, firmware)]
        hooks += [(folder / name).read_text() for folder in (pad_folder, phone_folder) for name in ('post-fs-data.sh', 'service.sh')]
        service = self.module / 'service.sh'
        for index, script in enumerate(hooks):
            subprocess.run(['sh', '-n'], input=script, text=True, check=True, capture_output=True)
            service.write_text(script)
            for name in ('disable', 'remove'):
                marker = self.module / name
                marker.symlink_to(self.folder / 'missing')
                baseline = {p.name for p in self.module.iterdir()}
                with self.subTest(hook=index, marker=name):
                    result = subprocess.run(['sh', str(service)], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual({p.name for p in self.module.iterdir()}, baseline)
                    self.assertTrue(marker.is_symlink())
                marker.unlink()

    def test_provider_restoration_runs_when_disabled_during_owned_restart(self):
        tools = self.folder / 'tools'
        tools.mkdir()
        marker = self.module / 'disable'
        events = self.folder / 'events'
        (tools / 'stop').write_text('#!/bin/sh\necho stop >> ' + str(events) + '\ntouch ' + str(marker) + '\n')
        (tools / 'start').write_text('#!/bin/sh\necho start >> ' + str(events) + '\n')
        for path in tools.iterdir():
            path.chmod(448)
        service = self.module / 'service.sh'
        service.write_text(lifecycle.guarded_hook('#!/bin/sh\nMODDIR=${0%/*}\nstop owned-provider\nstart owned-provider\n'))
        result = subprocess.run(['sh', str(service)], capture_output=True, text=True, env=dict(os.environ, PATH=str(tools) + ':' + os.environ['PATH']))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(events.read_text().splitlines(), ['stop', 'start'])
        self.assertTrue(marker.exists())

    def test_assigned_installers_preserve_choices_before_optional_apk_checks(self):
        for module_name in ('apply_flutter_fix', 'apply_navigation_fix', 'apply_assistant_fix', 'apply_pad_camera_native_fix', 'apply_xiaomi_camera_fix', 'apply_boot_service_fix'):
            module = importlib.import_module(module_name)
            for flag in ('disable', 'remove', 'pending'):
                with self.subTest(module=module_name, flag=flag), ExitStack() as stack:
                    stack.enter_context(patch.object(module, 'official'))
                    root = stack.enter_context(patch.object(module, 'root', return_value=flag))
                    adb = stack.enter_context(patch.object(module, 'adb'))
                    stack.enter_context(patch.object(module, 'ROOT', self.folder / 'unused'))
                    args = ({}, self.folder / 'unsupported-payload') if module_name == 'apply_boot_service_fix' else ({},)
                    self.assertEqual(module.install(*args), {'preserved': True, 'lifecycle': [flag]})
                    self.assertEqual(root.call_count, 1)
                    adb.assert_not_called()
                    self.assertFalse((self.folder / 'unused').exists())

if __name__ == '__main__':
    unittest.main()


# --- tests/test_module_webui.py ---

class ModuleWebUIShellTests(unittest.TestCase):
    """Read actual lifecycle flags from disposable Android-like directories."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='hyperos-webui-status-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.base = self.root / 'adb'
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.module = self.base / 'modules/hyperos_avd_native_compat'
        (self.module / 'state').mkdir(parents=True)
        (self.module / 'module.prop').write_text('id=hyperos_avd_native_compat\nauthor=HyperOS-AVD\n')
        (self.module / 'state/status.tsv').write_text('flutter|/system/lib.so|failed|patch-verification\n')
        self.collector = self.root / 'status.sh'
        self.collector.write_bytes(module_webui.files('core')['webui-status.sh'])
        self.busybox = self.bin / 'busybox'
        self.busybox.write_text('#!' + sys.executable + '\n' + "import os,pathlib,sys\nargs=sys.argv[1:]\nif args[:3] == ['stat','-c','%h:%u']:\n    print(str(pathlib.Path(args[3]).stat().st_nlink)+':0'); sys.exit(0)\nos.execvp(args[0],args)\n")
        self.busybox.chmod(493)
        for name, value in (('getprop', 'skiavk'), ('getenforce', 'Enforcing')):
            path = self.bin / name
            path.write_text('#!/bin/sh\necho ' + value + '\n')
            path.chmod(493)

    def collect(self):
        environment = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'], HYPEROS_STATUS_BB=str(self.busybox), HYPEROS_STATUS_BASE=str(self.base))
        return subprocess.run(['sh', str(self.collector)], env=environment, check=True, capture_output=True, text=True).stdout

    def snapshot(self):
        return {str(path.relative_to(self.base)): (path.read_bytes(), path.stat().st_ino, path.stat().st_mode) for path in self.base.rglob('*') if path.is_file() and (not path.is_symlink())}

    def test_enabled_lifecycle_does_not_claim_all_patches_are_ready_and_is_read_only(self):
        before = self.snapshot()
        output = self.collect()
        self.assertIn('state=enabled\n', output)
        self.assertIn('flutter|/system/lib.so|failed|patch-verification', output)
        self.assertEqual(before, self.snapshot())

    def test_disable_remove_and_pending_flags_have_distinct_lifecycle_states(self):
        for flag, state in (('disable', 'disabled'), ('remove', 'pending-removal')):
            for broken_alias in (False, True):
                with self.subTest(flag=flag, broken_alias=broken_alias):
                    marker = self.module / flag
                    if broken_alias:
                        marker.symlink_to(self.root / 'missing')
                    else:
                        marker.touch()
                    self.assertIn('state=' + state + '\n', self.collect())
                    if broken_alias:
                        self.assertTrue(marker.is_symlink())
                    marker.unlink()
        stage = self.base / 'modules_update/hyperos_avd_native_compat'
        stage.mkdir(parents=True)
        self.assertIn('state=pending\n', self.collect())
        (self.module / 'remove').touch()
        (self.module / 'disable').touch()
        self.assertIn('state=pending-removal\n', self.collect())

    def test_unactivated_or_aliased_state_is_not_treated_as_verified(self):
        state = self.module / 'state/status.tsv'
        state.unlink()
        self.assertIn('state=not-activated\n', self.collect())
        foreign = self.root / 'foreign-status'
        foreign.write_text('SECRET_EXTERNAL_STATE\n')
        state.symlink_to(foreign)
        output = self.collect()
        self.assertIn('state=not-activated\n', output)
        self.assertNotIn('SECRET_EXTERNAL_STATE', output)
        self.assertTrue(state.is_symlink())

class ModuleWebUITests(unittest.TestCase):

    def test_both_modules_embed_offline_assets_with_fixed_commands(self):
        for family, identity in module_webui.FAMILIES.items():
            files = module_webui.files(family)
            self.assertEqual(set(files), {'webroot/index.html', 'webroot/app.js', 'webroot/style.css', 'webui-status.sh'})
            self.assertIn(identity.encode(), files['webroot/index.html'])
            self.assertIn(('ID=' + identity).encode(), files['webui-status.sh'])
            self.assertNotIn(b'@MODULE_ID@', b''.join(files.values()))
            self.assertNotIn(b'@CORE_TITLES@', files['webroot/app.js'])
            self.assertEqual("'rear-input':'背屏触控'".encode() in files['webroot/app.js'], family == 'core')
            self.assertIn(b"connect-src 'none'", files['webroot/index.html'])
            self.assertNotIn(b'http', files['webroot/app.js'])
            self.assertNotIn(b'innerHTML', files['webroot/app.js'])
        with self.assertRaises(RuntimeError):
            module_webui.files('../../foreign')

    def test_collector_is_syntax_valid_and_bounded(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'status.sh'
            path.write_bytes(module_webui.files('core')['webui-status.sh'])
            subprocess.run(['sh', '-n', str(path)], check=True)
        data = module_webui.files('core')['webui-status.sh'].decode()
        self.assertIn('head -c 24576', data)
        self.assertIn('head -n 160', data)
        self.assertIn('tail -c 8192', data)
        self.assertIn('safe_file', data)
        for mutation in ('chmod ', 'setprop ', 'settings put ', 'mount ', 'rm ', 'cp ', 'eval '):
            self.assertNotIn(mutation, data)

    @unittest.skipUnless(shutil.which('node'), 'JavaScript runtime is optional')
    def test_status_parser_and_bridge_cleanup(self):
        source = module_webui.ROOT / 'modules/compat-webui/app.js'
        javascript = "\nconst assert=require('node:assert/strict');\nconst view=require(process.argv[1]);\nconst data=view.parse('[module]\\nstate=pending\\n[health]\\nrenderer=skiavk\\n[status]\\n'+\n  'flutter|/system/lib.so|ready|verified-bind\\nweather|com.miui.weather2|unsupported|unsupported-apk\\n'+\n  'foreign|x|unknown;rm|y\\n[log]\\n<script>unsafe</script>');\nassert.equal(data.module.state,'pending');\nassert.equal(data.patches.length,2);\nassert.equal(data.patches[1].state,'unsupported');\nassert.equal(data.logs[0],'<script>unsafe</script>');\n(async()=>{\n let callback;\n const text=await view.run('fixed-read-only-command',{exec:(command,options,name)=>{\n  assert.equal(command,'fixed-read-only-command');assert.equal(options,'{}');callback=name;\n  globalThis[name](0,'status-output','');\n }});\n assert.equal(text,'status-output');assert.equal(globalThis[callback],undefined);\n await assert.rejects(view.run('fixed',undefined),/KernelSU/);\n await assert.rejects(view.run('fixed',{exec:()=>{throw new Error('transport');}}),/transport/);\n await assert.rejects(view.run('fixed',{exec:(_,__,name)=>globalThis[name](1,'','failed')}),/failed/);\n const names=Object.keys(globalThis).filter(x=>x.startsWith('hyperos_status_'));\n assert.equal(names.length,0);\n})().catch(error=>{console.error(error);process.exitCode=1;});\n"
        subprocess.run([shutil.which('node'), '-e', javascript, str(source)], check=True, timeout=20)

    @unittest.skipUnless(shutil.which('node'), 'JavaScript runtime is optional')
    def test_render_treats_status_and_logs_as_text(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        source = Path(temporary.name) / 'app.js'
        source.write_bytes(module_webui.files('core')['webroot/app.js'])
        javascript = "\nconst assert=require('node:assert/strict');const view=require(process.argv[1]);\nconst nodes={};function node(){return {children:[],textContent:'',append(...items){this.children.push(...items);},replaceChildren(){this.children=[];}};}\nconst document={getElementById:id=>nodes[id]??=(node()),createElement:()=>node()};\nview.render({module:{state:'disabled'},health:{renderer:'skiavk',selinux:'Enforcing'},\n patches:[{feature:'weather',state:'unsupported',reason:'<script>x</script>',target:'$(touch /data/pwn)'},\n          {feature:'rear-input',state:'ready',reason:'verified-bind',target:'/system/framework/services.jar'}],\n logs:['<img src=x onerror=alert(1)>']},document);\nassert.equal(nodes['module-state'].textContent,'已停用');\nassert.equal(nodes.patches.children[0].children[1].textContent,'<script>x</script>');\nassert.equal(nodes.patches.children[0].children[2].textContent,'$(touch /data/pwn)');\nassert.equal(nodes.patches.children[1].children[0].children[0].textContent,'背屏触控');\nassert.equal(nodes.logs.textContent,'<img src=x onerror=alert(1)>');\nview.render({module:{state:'enabled'},health:{},patches:[],logs:[]},document);\nassert.equal(nodes['module-state'].textContent,'已启用');\nview.render({module:{state:'pending-removal'},health:{},patches:[],logs:[]},document);\nassert.equal(nodes['module-state'].textContent,'待卸载');\n"
        subprocess.run([shutil.which('node'), '-e', javascript, str(source)], check=True, timeout=20)

    @unittest.skipUnless(shutil.which('node'), 'JavaScript runtime is optional')
    def test_log_section_markers_are_literal_and_cannot_forge_actual_status(self):
        source = module_webui.ROOT / 'modules/compat-webui/app.js'
        javascript = "\nconst assert=require('node:assert/strict'),view=require(process.argv[1]);\nconst log='subprocess output\\n[module]\\nstate=ready\\n[health]\\nrenderer=forged\\n[status]\\nflutter|forged.so|ready|verified-bind\\n[log]\\nend';\nconst data=view.parse('[module]\\nstate=disabled\\n[health]\\nrenderer=skiavk\\n[status]\\nflutter|real.so|disabled|user-choice\\n[log]\\n'+log);\nassert.equal(data.module.state,'disabled');assert.equal(data.health.renderer,'skiavk');\nassert.equal(data.patches.length,1);assert.equal(data.patches[0].target,'real.so');\nassert.equal(data.logs.join('\\n'),log);\n"
        subprocess.run([shutil.which('node'), '-e', javascript, str(source)], check=True, timeout=20)

if __name__ == '__main__':
    unittest.main()


# --- tests/test_parrot_module.py ---

'Keep the optional allocator bridge portable, guarded and module-owned.'

class ParrotModuleTests(unittest.TestCase):

    def fixture(self, temporary):
        base = Path(temporary)
        source = base / 'native/camera_aion_cpu.c'
        source.parent.mkdir()
        source.write_bytes(b'audited source fixture')
        folder = base / 'tools/parrot-camera'
        folder.mkdir(parents=True)
        payload = folder / 'lib_aion_buffer.so'
        payload.write_bytes(b'audited allocator fixture')
        source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        payload_hash = hashlib.sha256(payload.read_bytes()).hexdigest()
        receipt = {'revision': 1, 'source_sha256': source_hash, 'files': {'lib_aion_buffer.so': payload_hash}}
        (folder / 'receipt.json').write_text(json.dumps(receipt))
        stack = ExitStack()
        stack.enter_context(patch.object(camera, 'ROOT', base))
        stack.enter_context(patch.object(camera, 'REPO_ROOT', base))
        stack.enter_context(patch.object(camera, 'BRIDGE_SOURCE_SHA256', source_hash))
        stack.enter_context(patch.object(camera, 'BRIDGE_SHA256', payload_hash))
        return (base, folder, payload, stack)

    def test_release_prebuilt_works_without_ndk_or_guest_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            base, folder, payload, stack = self.fixture(temporary)
            destination = base / 'candidate.so'
            with stack, patch.object(camera.subprocess, 'run') as compile_call:
                camera.build_payload({}, destination)
                self.assertEqual(destination.read_bytes(), payload.read_bytes())
                compile_call.assert_not_called()
                self.assertEqual(camera.prepare_prebuilt(base, 'missing SDK'), folder)
                compile_call.assert_not_called()
                self.assertFalse(list(folder.parent.glob('.parrot-prebuilt-*')))

    def test_corrupt_prebuilt_or_source_never_falls_back_to_compiler(self):
        for change in ('source', 'payload', 'receipt', 'missing', 'alias'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                base, folder, payload, stack = self.fixture(temporary)
                if change == 'source':
                    (base / 'native/camera_aion_cpu.c').write_bytes(b'future source')
                elif change == 'payload':
                    payload.write_bytes(b'unknown allocator')
                elif change == 'receipt':
                    (folder / 'receipt.json').write_text('{')
                elif change == 'missing':
                    payload.unlink()
                elif change == 'alias':
                    actual = base / 'actual.so'
                    payload.rename(actual)
                    payload.symlink_to(actual)
                with stack, patch.object(camera.subprocess, 'run') as compile_call, self.assertRaises(RuntimeError):
                    camera.build_payload({}, base / 'candidate.so')
                compile_call.assert_not_called()
                self.assertFalse((base / 'candidate.so').exists())

    def test_disabled_or_pending_choice_precedes_apk_lookup(self):
        for flag in ('disable', 'remove', 'pending'):
            transport = Mock(return_value=flag)
            fake = SimpleNamespace(install=Mock(), remove=Mock())
            with patch.object(camera, 'official'), patch.object(camera, 'root', transport), patch.dict(sys.modules, {'app_bridge_module': fake}):
                result = camera.install({'name': 'Renamed_AVD'})
            self.assertEqual(result['lifecycle'], [flag])
            self.assertEqual(transport.call_count, 1)
            fake.install.assert_not_called()

    def test_same_apk_reinstallation_does_not_pin_module_to_old_path(self):
        for suffix in ('first', 'reinstalled'):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                apk = '/data/app/~~a/com.google.android.GoogleCamera.parrot-' + suffix + '/base.apk'

                def transport(_config, command):
                    if 'for flag in disable remove' in command:
                        return ''
                    if command == 'pm path ' + camera.PACKAGE:
                        return 'package:' + apk
                    if command.startswith('sha256sum /system/'):
                        return camera.RUNTIME_SHA256 + ' runtime'
                    if command.startswith('sha256sum ') and shlex.split(command)[1].startswith('/data/'):
                        return camera.APK_SHA256 + ' apk'
                    raise AssertionError('Unexpected guest mutation: ' + command)
                payload = base / 'bridge.so'
                payload.write_bytes(b'fixture')
                fake = SimpleNamespace(install=Mock(return_value={'pending': True}), remove=Mock())
                with patch.object(camera, 'ROOT', base), patch.object(camera, 'official'), patch.object(camera, 'root', side_effect=transport), patch.object(camera, 'build_payload', return_value=payload), patch.dict(sys.modules, {'app_bridge_module': fake}):
                    self.assertEqual(camera.install({}), {'pending': True})
                options = fake.install.call_args.kwargs
                self.assertNotIn(apk, json.dumps(options['profiles']))
                self.assertEqual(options['profiles'], camera.bridge_profiles())
                self.assertEqual(json.loads((base / 'local/camera-fix.json').read_text())['revision'], 3)

    def test_unknown_apk_is_explicit_untouched_outcome(self):
        transport = Mock(side_effect=['', 'package:/data/app/com.google.android.GoogleCamera.parrot-a/base.apk', '0' * 64 + ' apk'])
        fake = SimpleNamespace(install=Mock(), remove=Mock())
        with patch.object(camera, 'official'), patch.object(camera, 'root', transport), patch.dict(sys.modules, {'app_bridge_module': fake}), self.assertRaises(UnsupportedPatch):
            camera.install({})
        fake.install.assert_not_called()

    def test_remove_after_uninstall_marks_only_module(self):
        fake = SimpleNamespace(install=Mock(), remove=Mock(return_value={'removed': True}))
        with patch.object(camera, 'official'), patch.object(camera, 'root', return_value='') as transport, patch.dict(sys.modules, {'app_bridge_module': fake}):
            self.assertEqual(camera.install({}, remove=True), {'removed': True})
        self.assertEqual(transport.call_args.args[-1], 'pm path ' + camera.PACKAGE)
        fake.remove.assert_called_once_with({}, camera.MODULE_ID, profiles=camera.bridge_profiles(), name=camera.MODULE_NAME, description=camera.MODULE_DESCRIPTION, package=camera.PACKAGE)

if __name__ == '__main__':
    unittest.main()
