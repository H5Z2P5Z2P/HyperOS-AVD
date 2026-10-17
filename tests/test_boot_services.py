"""Consolidated unit tests for OS4 boot services:
boot service patches, installer migrations, and kernel image services.
"""
from contextlib import ExitStack
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
import zipfile

REPO = Path(__file__).resolve().parents[1]
ROOT = REPO
sys.path.insert(0, str(REPO / 'scripts'))

import apply_boot_service_fix as installer
import apply_boot_service_fix as install
import image_kernel_services as helper
from os4_defaults import boot_defaults
import package_release as release
from package_release import verify_boot_services
import patch_boot_services as fixes
import patch_boot_services as services
from phone_profile import profile
import prepare_release_image as prepare

def digest(data):
    return hashlib.sha256(data).hexdigest()



# --- tests/test_boot_services.py ---

'Check scoped boot-service guards and supplied firmware artifacts.'

def archive():
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as zipped:
        zipped.writestr('classes.dex', b'original')
    return output.getvalue()

def signed_fixture(data):
    end, directory = fixes.zip_directory(data)
    payload = b'original signer metadata'
    length = len(payload) + 24
    block = struct.pack('<Q', length) + payload + struct.pack('<Q', length) + b'APK Sig Block 42'
    result = bytearray(data[:directory] + block + data[directory:])
    struct.pack_into('<I', result, end + len(block) + 16, directory + len(block))
    return bytes(result)

class BootServiceTests(unittest.TestCase):

    def test_boot_service_requires_a_narrow_init_transition(self):
        self.assertIn(b'seclabel u:r:su:s0', fixes.BOOT_INIT)
        self.assertIn(b'(allow init su (process (transition)))', fixes.BOOT_SEPOLICY)
        self.assertNotIn(b'permissive', fixes.BOOT_SEPOLICY)

    def test_unknown_input_rejected_before_tools_and_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output = (Path(directory) / 'source.apk', Path(directory) / 'output.apk')
            source.write_bytes(b'unknown')
            with patch.object(fixes.subprocess, 'run') as command:
                with self.assertRaisesRegex(RuntimeError, 'Unsupported boot service input'):
                    fixes.patch('registration', source, output)
                command.assert_not_called()
            self.assertFalse(output.exists())

    def test_modified_zip_retains_exact_original_signer_block(self):
        source = signed_fixture(archive())
        modified = io.BytesIO()
        with zipfile.ZipFile(modified, 'w') as zipped:
            zipped.writestr('classes.dex', b'new bytecode with different length')
        result = fixes.retain_system_signer(source, modified.getvalue())
        self.assertEqual(fixes.signing_block(source), fixes.signing_block(result))
        with zipfile.ZipFile(io.BytesIO(result)) as zipped:
            self.assertEqual(zipped.read('classes.dex'), b'new bytecode with different length')
            self.assertIsNone(zipped.testzip())
        with self.assertRaisesRegex(RuntimeError, 'unexpectedly contains'):
            fixes.retain_system_signer(source, result)

    def test_signer_and_zip_layout_fail_closed(self):
        for data in (b'not an APK', archive(), archive()[:-1]):
            with self.assertRaises(RuntimeError):
                fixes.signing_block(data)
        bad = bytearray(signed_fixture(archive()))
        _, directory = fixes.zip_directory(bad)
        struct.pack_into('<Q', bad, directory - 24, 2 ** 63)
        with self.assertRaises(RuntimeError):
            fixes.signing_block(bad)

    def test_round_trip_compares_targets_and_instructions(self):
        old = '.method private run()V\n.registers 2\nif-eqz v0, :alias\n:alias\n:exit\nreturn-void\n.end method'
        same = old.replace(':alias', ':cond_4').replace(':exit\n', '')
        self.assertEqual(fixes.method_code(old, 'run()V'), fixes.method_code(same, 'run()V'))
        self.assertNotEqual(fixes.method_code(old, 'run()V'), fixes.method_code(same.replace('v0', 'v1'), 'run()V'))

    def test_registered_modern_phone_sources_get_kernel_boot_policy(self):
        empty = b'on boot\n    setprop example 1\n'
        self.assertNotIn(fixes.BOOT_INIT, boot_defaults(empty, profile('4.0.17.0.XFRCNXM')))
        for version in ('4.0.18.0.XFRCNXM', '4.0.24.0.XFRCNXM'):
            with self.subTest(version=version):
                current = boot_defaults(empty, profile(version))
                self.assertEqual(current.count(fixes.BOOT_INIT), 1)
                self.assertEqual(boot_defaults(current, profile(version)), current)

    def test_capability_policy_distinguishes_supported_missing_and_denied(self):
        script = (REPO / 'config/check_kernel_services.sh').read_text()
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            events, node = (folder / 'events', folder / 'iorap_dev')
            for name, body in {'getprop': 'case "$1" in ro.boot.hardware) echo "$HARDWARE";; ro.product.device) echo "$DEVICE";; ro.mi.os.version.incremental) echo "$FIRMWARE";; ro.millet.netlink) echo 31;; esac', 'setprop': 'echo "$*" >> "$EVENTS"', 'probe': 'if [ "$1" = gnss-extension ]; then exit "$GNSS_RESULT"; fi\nexit "$PROBE_RESULT"'}.items():
                path = folder / name
                path.write_text('#!/bin/sh\n' + body + '\n')
                path.chmod(493)
            env = dict(os.environ, PATH=str(folder) + ':' + os.environ['PATH'], EVENTS=str(events), HARDWARE='ranchu', DEVICE='hongkong', FIRMWARE='OS4.0.18.0.XFRCNXM', GNSS_RESULT='0')
            command = script.replace('/dev/iorap_dev', str(node)).replace('PROBE=${1:-/system/bin/hyperos_kernel_probe}', 'PROBE=' + str(folder / 'probe'))
            for result, present in ((0, True), (2, False), (3, True)):
                with self.subTest(result=result):
                    events.unlink(missing_ok=True)
                    if present:
                        node.touch()
                    else:
                        node.unlink(missing_ok=True)
                    run = subprocess.run(['sh'], input=command, text=True, env={**env, 'PROBE_RESULT': str(result)})
                    changes = events.read_text() if events.exists() else ''
                    self.assertEqual(run.returncode, 1 if result == 3 else 0)
                    self.assertEqual('ctl.stop millet_monitor' in changes, result == 2)
                    self.assertNotIn('ctl.stop iorapd', changes)
                    self.assertNotIn('persist.sys.stability.PrereadEnable', changes)
                    if result == 0:
                        self.assertIn('sys.hyperos_avd.millet_supported 1', changes)
                    self.assertNotIn('ctl.stop loc_sys_service', changes)
            for result in (2, 3):
                events.unlink(missing_ok=True)
                node.touch()
                run = subprocess.run(['sh'], input=command, text=True, env={**env, 'PROBE_RESULT': '0', 'GNSS_RESULT': str(result)})
                changes = events.read_text()
                self.assertEqual(run.returncode, 1 if result == 3 else 0)
                self.assertEqual('ctl.stop loc_sys_service' in changes, result == 2)
                self.assertNotIn('ctl.stop vendor.gnss.ranchu', changes)
            for field, value in (('DEVICE', 'yingtian'), ('HARDWARE', 'qcom'), ('FIRMWARE', 'OS4.0.17.0.XFRCNXM')):
                events.unlink(missing_ok=True)
                subprocess.run(['sh'], input=command, text=True, env={**env, field: value, 'PROBE_RESULT': '2'}, check=True)
                self.assertFalse(events.exists())

    def test_existing_module_payload_is_verified_before_reuse(self):
        device = {'name': 'Renamed-by-user', 'port': 5584}
        import json
        calls = []

        def root(config, command):
            self.assertEqual(config, device)
            calls.append(command)
            import module_lifecycle
            if command == module_lifecycle.state_script(installer.MODULE):
                return ''
            if command.startswith('if [ -d '):
                return json.dumps(installer.receipt())
            for name, (path, _, _) in fixes.TARGETS.items():
                if command == 'pm path ' + installer.PACKAGES.get(name, '-'):
                    return 'package:' + path
                if command == 'sha256sum ' + path:
                    return fixes.AFTER[name] + '  ' + path
                if command == f'sha256sum {installer.MODULE}/payload/{name}':
                    return 'f' * 64 + '  modified-payload'
            raise AssertionError('Unexpected mutation: ' + command)

        def digest(path):
            return fixes.AFTER[Path(path).stem]
        with patch.object(installer, 'official'), patch.object(installer, 'sha256', side_effect=digest), patch.object(installer, 'root', side_effect=root), patch.object(installer, 'adb') as adb:
            with self.assertRaisesRegex(RuntimeError, 'Existing boot service payload differs'):
                installer.install(device, Path('unused-payload'))
            adb.assert_not_called()
        self.assertFalse(any(('mkdir' in call or 'mount ' in call for call in calls)))

    def test_retired_payload_entry_point_cannot_create_a_standalone_module(self):
        calls = []
        with patch.object(installer, 'official'), patch.object(installer, 'root', side_effect=lambda config, command: calls.append(command) or ''), \
                patch.object(installer, 'sha256') as checksum, patch.object(installer, 'adb') as adb:
            with self.assertRaisesRegex(RuntimeError, 'Use the shared Core module'):
                installer.install({'name': 'Any-name'}, Path('missing-payload'))
            checksum.assert_not_called()
            adb.assert_not_called()
        self.assertFalse(any('mkdir' in command or 'mount ' in command or 'getprop ro.mi.os' in command for command in calls))

    def test_release_rejects_wrong_version_and_claimed_but_missing_repair(self):
        reader = unittest.mock.Mock(return_value=b'wrong artifact')
        self.assertEqual(verify_boot_services({}, reader), 0)
        reader.assert_not_called()
        with self.assertRaisesRegex(RuntimeError, 'Unexpected boot service fix'):
            verify_boot_services({'hyperos': '4.0.17.0.XFRCNXM', 'boot_service_fix': installer.receipt()}, reader)
        with self.assertRaisesRegex(RuntimeError, 'Baked boot service checksum'):
            verify_boot_services({'hyperos': '4.0.18.0.XFRCNXM', 'archive_sha256': profile('4.0.18.0.XFRCNXM')['archive_sha256'], 'boot_service_fix': installer.receipt()}, reader)

    def test_new_registered_release_uses_recipe_bytes_and_rejects_foreign_provenance(self):
        selected = profile('4.0.24.0.XFRCNXM')
        build = {'source': 'official-hongkong-ota', 'hyperos': selected['hyperos'], 'archive_sha256': selected['archive_sha256'], 'boot_service_fix': installer.receipt()}
        reader = unittest.mock.Mock(return_value=b'missing fixed bytecode')
        with self.assertRaisesRegex(RuntimeError, 'Baked boot service checksum'):
            verify_boot_services(build, reader)
        self.assertGreater(reader.call_count, 0)
        reader.reset_mock()
        for field, value in (('hyperos', '4.0.999.0.XFRCNXM'), ('archive_sha256', 'f' * 64)):
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                verify_boot_services(dict(build, **{field: value}), reader)
            reader.assert_not_called()
        self.assertEqual(build['boot_service_fix']['firmware'], 'OS4.0.18.0.XFRCNXM')

    def test_release_reads_each_authenticated_recipe_and_rejects_wrong_service_bytes(self):
        payloads = {path: ('fixed fixture ' + name).encode() for name, (path, _, _) in fixes.TARGETS.items()}
        after = {name: hashlib.sha256(payloads[path]).hexdigest() for name, (path, _, _) in fixes.TARGETS.items()}
        variants = {before: ('fixed GNSS recipe fixture ' + before).encode() for before in fixes.SERVICE_RECIPES}
        recipes = {before: hashlib.sha256(data).hexdigest() for before, data in variants.items()}
        probe = b'audited kernel probe fixture'
        payloads.update({'/system/bin/hyperos_kernel_probe': probe, '/system_ext/etc/init/init.hyperos_avd.rc': fixes.BOOT_INIT, '/system_ext/etc/selinux/system_ext_sepolicy.cil': fixes.BOOT_SEPOLICY})
        with patch.object(fixes, 'AFTER', after), patch.object(fixes, 'SERVICE_RECIPES', recipes), patch.object(fixes, 'PROBE_SHA256', hashlib.sha256(probe).hexdigest()):
            from image_kernel_services import image_script
            payloads['/system/etc/hyperos-kernel-services.sh'] = image_script()
            for version in ('4.0.18.0.XFRCNXM', '4.0.24.0.XFRCNXM'):
                for marker in fixes.image_receipts():
                    selected = profile(version)
                    row = marker['targets']['services']
                    files = {**payloads, row['path']: variants[row['before']]}
                    build = {'hyperos': version, 'archive_sha256': selected['archive_sha256'], 'boot_service_fix': marker}
                    with self.subTest(version=version, recipe=row['before']):
                        self.assertEqual(verify_boot_services(build, files.__getitem__), 7)
                        files[row['path']] = b'wrong producer bytes'
                        with self.assertRaisesRegex(RuntimeError, 'checksum mismatch: ' + row['path']):
                            verify_boot_services(build, files.__getitem__)

    def test_real_artifacts_preserve_all_unrelated_entries_and_signers(self):
        location = os.environ.get('HYPEROS_AVD_BOOT_FIX_ARTIFACTS')
        if not location:
            self.skipTest('Pinned firmware artifacts not supplied.')
        folder = Path(location)
        for name, (_, before, dex) in fixes.TARGETS.items():
            suffix = '.apk' if name in ('qualcomm', 'registration') else '.jar'
            source, output = (folder / 'input' / (name + suffix), folder / 'output' / (name + suffix))
            self.assertEqual(fixes.sha256(source), before)
            self.assertEqual(fixes.sha256(output), fixes.AFTER[name])
            with zipfile.ZipFile(source) as old, zipfile.ZipFile(output) as new:
                self.assertEqual(old.namelist(), new.namelist())
                self.assertNotEqual(old.read(dex), new.read(dex))
                for entry in old.namelist():
                    if entry != dex:
                        self.assertEqual(old.read(entry), new.read(entry), entry)
            if suffix == '.apk':
                self.assertEqual(fixes.signing_block(source.read_bytes()), fixes.signing_block(output.read_bytes()))

if __name__ == '__main__':
    unittest.main()


# --- tests/test_boot_service_migration.py ---

'Exercise legacy helper authentication and migration on disposable files.'

LEGACY_IORAP_BLOCK = b"if [ ! -e /dev/iorap_dev ]; then\n    # Use the service's own documented opt-out; retain data and other preloaders.\n    setprop persist.sys.stability.PrereadEnable false\n    setprop ctl.stop iorapd\nfi\n"

class BootServiceMigrationTests(unittest.TestCase):

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='hyperos-boot-migration-')
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name)
        self.module, self.pending = (self.folder / 'module', self.folder / 'pending')
        self.tools = self.folder / 'tools'
        self.tools.mkdir()
        if shutil.which('sha256sum'):
            checksum = shlex.quote(shutil.which('sha256sum'))
        elif shutil.which('shasum'):
            checksum = shlex.quote(shutil.which('shasum')) + ' -a 256'
        else:
            self.skipTest('No local SHA-256 utility is available.')
        self.source = install.PERF_SCRIPT.read_bytes()
        self.legacy = self.source.replace(b'PROBE=${1:-', LEGACY_IORAP_BLOCK + b'PROBE=${1:-', 1)
        self.assertEqual(hashlib.sha256(self.legacy).hexdigest(), install.LEGACY_KERNEL_SCRIPT_SHA256)
        self.assertEqual(hashlib.sha256(self.source).hexdigest(), install.KERNEL_SCRIPT_SHA256)
        self.environment = dict(os.environ, PATH=str(self.tools) + ':' + os.environ['PATH'], HYPEROS_TEST_MODULE=str(self.module), HYPEROS_TEST_OWNER='0', HYPEROS_TEST_RACE='', HYPEROS_TEST_CHCON_FAIL='0')
        self.executable('getprop', 'case "$1" in\nro.boot.hardware) echo ranchu;;\nro.product.device) echo hongkong;;\nro.mi.os.version.incremental) echo OS4.0.18.0.XFRCNXM;;\n*) exit 1;;\nesac')
        self.executable('busybox', 'command=$1\nshift\ncase "$command" in\nstat) printf \'%s\\n\' "$HYPEROS_TEST_OWNER";;\nsha256sum) exec ' + checksum + ' "$@";;\ncp)\n    case "$HYPEROS_TEST_RACE" in\n    disable|remove) touch "$HYPEROS_TEST_MODULE/$HYPEROS_TEST_RACE";;\n    helper) printf \'changed concurrently\' > "$HYPEROS_TEST_MODULE/check-kernel-services.sh";;\n    esac\n    exec cp "$@";;\n*) exec "$command" "$@";;\nesac')
        self.executable('chcon', 'exit "$HYPEROS_TEST_CHCON_FAIL"')
        self.executable('ls', 'printf "u:object_r:system_file:s0 %s\\n" "$2"')
        self.commands = []
        self.expected = install._module_asset_hashes()
        self.fixture()

    def executable(self, name, body):
        path = self.tools / name
        path.write_text('#!/bin/sh\n' + body + '\n')
        path.chmod(493)

    def fixture(self):
        self.module.mkdir()
        (self.module / 'payload').mkdir()
        hook, targets = install.boot_script()
        files = {'module.prop': install.MODULE_PROPERTIES.encode(), 'manifest.json': (json.dumps(install.receipt(), indent=2) + '\n').encode(), 'post-fs-data.sh': hook.encode(), 'service.sh': hook.encode(), 'targets.conf': targets.encode(), 'skip_mount': b'', 'kernel-probe': b'private probe fixture', 'check-kernel-services.sh': self.legacy, 'uninstall.sh': b'#!/system/bin/sh\n# Preserve an existing user hook.\n', 'user-choice': b'keep my choice\n'}
        for name in install.AFTER:
            files['payload/' + name] = ('private fixture ' + name).encode()
        for name, content in files.items():
            path = self.module / name
            path.write_bytes(content)
            path.chmod(493 if name.endswith('.sh') or name == 'kernel-probe' else 420)
        for name in ('kernel-probe', *('payload/' + name for name in install.AFTER)):
            self.expected[name] = hashlib.sha256(files[name]).hexdigest()

    def guest(self, config, command):
        self.assertEqual(config, {'name': 'Renamed_Without_Changing_Patches', 'port': 5580})
        self.commands.append(command)
        translated = command.replace('/data/adb/ksu/bin/busybox', str(self.tools / 'busybox'))
        translated = translated.replace('/system/bin/chcon', str(self.tools / 'chcon'))
        translated = translated.replace('/system/bin/ls', str(self.tools / 'ls'))
        result = subprocess.run(['sh', '-c', 'set -e\n' + translated], text=True, capture_output=True, env=self.environment)
        if result.returncode:
            raise RuntimeError('Disposable guest guard rejected: ' + result.stderr)
        return result.stdout.strip()

    def migrate(self, operation='migrate_kernel_helper'):
        with patch.object(install, 'MODULE', str(self.module)), patch.object(install, 'PENDING', str(self.pending)), patch.object(install, '_module_asset_hashes', return_value=self.expected), patch.object(install, 'root', side_effect=self.guest), patch.object(install, 'adb') as adb:
            result = getattr(install, operation)({'name': 'Renamed_Without_Changing_Patches', 'port': 5580})
            adb.assert_not_called()
            return result

    def snapshot(self):
        return {str(path.relative_to(self.module)): (path.read_bytes(), path.stat().st_mode & 511) for path in self.module.rglob('*') if path.is_file() and (not path.is_symlink())}

    def test_only_known_helper_changes_atomically_without_executing_hooks(self):
        helper = self.module / 'check-kernel-services.sh'
        helper.chmod(488)
        before = self.snapshot()
        result = self.migrate()
        self.assertTrue(result['migrated'])
        self.assertTrue(result['reboot_required'])
        before['check-kernel-services.sh'] = (self.source, 488)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(list(self.module.glob('.kernel-helper-*')), [])
        self.assertFalse(any(('nsenter' in command or 'ctl.restart' in command or 'reboot' in command for command in self.commands)))

    def test_current_helper_is_authenticated_and_reused_without_writing(self):
        (self.module / 'check-kernel-services.sh').write_bytes(self.source)
        before = self.snapshot()
        result = self.migrate()
        self.assertTrue(result['reused'])
        self.assertFalse(result['migrated'])
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(any(('mkdir -m 700' in command for command in self.commands)))

    def test_absent_module_is_not_created(self):
        shutil.rmtree(self.module)
        self.assertEqual(self.migrate(), {'migrated': False, 'present': False})
        self.assertFalse(self.module.exists())

    def test_disabled_removed_or_pending_module_choices_are_untouched(self):
        for flag in ('disable', 'remove'):
            with self.subTest(flag=flag):
                path = self.module / flag
                path.symlink_to(self.module / 'no-such-file')
                result = self.migrate()
                self.assertEqual(result['preserved'], [flag])
                self.assertTrue(path.is_symlink())
                self.assertEqual((self.module / 'check-kernel-services.sh').read_bytes(), self.legacy)
                path.unlink()
        self.pending.mkdir()
        (self.pending / 'features.disabled').write_text('keep pending settings\n')
        self.assertTrue(self.migrate()['deferred'])
        self.assertEqual((self.pending / 'features.disabled').read_text(), 'keep pending settings\n')

    def test_unknown_owner_receipt_hooks_payload_probe_or_helper_are_rejected(self):
        for name in ('module.prop', 'manifest.json', 'targets.conf', 'post-fs-data.sh', 'service.sh', 'kernel-probe', 'payload/services', 'check-kernel-services.sh'):
            with self.subTest(name=name):
                path = self.module / name
                original = path.read_bytes()
                path.write_bytes(original + b'changed')
                before = self.snapshot()
                with self.assertRaises(RuntimeError):
                    self.migrate()
                self.assertEqual(self.snapshot(), before)
                path.write_bytes(original)
        self.environment['HYPEROS_TEST_OWNER'] = '1000'
        with self.assertRaises(RuntimeError):
            self.migrate()
        self.assertEqual((self.module / 'check-kernel-services.sh').read_bytes(), self.legacy)

    def test_newer_module_revision_and_symlinked_assets_are_preserved(self):
        prop = self.module / 'module.prop'
        original = prop.read_bytes()
        prop.write_bytes(original.replace(b'versionCode=2', b'versionCode=999'))
        with self.assertRaises(RuntimeError):
            self.migrate()
        self.assertIn(b'versionCode=999', prop.read_bytes())
        prop.write_bytes(original)
        target = self.module / 'service.sh'
        content = target.read_bytes()
        replacement = self.folder / 'elsewhere.sh'
        replacement.write_bytes(content)
        target.unlink()
        target.symlink_to(replacement)
        with self.assertRaises(RuntimeError):
            self.migrate()
        self.assertTrue(target.is_symlink())
        self.assertEqual(replacement.read_bytes(), content)

    def test_other_device_or_firmware_does_not_receive_phone_policy(self):
        for key, value in (('ro.product.device', 'yingtian'), ('ro.boot.hardware', 'qcom'), ('ro.mi.os.version.incremental', 'OS4.0.19.0.XFRCNXM')):
            with self.subTest(key=key):
                self.executable('getprop', f'case "$1" in\n{key}) echo {value};;\nro.boot.hardware) echo ranchu;;\nro.product.device) echo hongkong;;\nro.mi.os.version.incremental) echo OS4.0.18.0.XFRCNXM;;\n*) exit 1;;\nesac')
                before = self.snapshot()
                with self.assertRaises(RuntimeError):
                    self.migrate()
                self.assertEqual(self.snapshot(), before)

    def test_probe_must_remain_executable(self):
        (self.module / 'kernel-probe').chmod(420)
        before = self.snapshot()
        with self.assertRaises(RuntimeError):
            self.migrate()
        self.assertEqual(self.snapshot(), before)

    def test_late_lifecycle_or_content_change_aborts_and_cleans_its_stage(self):
        for race in ('disable', 'remove', 'helper'):
            with self.subTest(race=race):
                (self.module / 'check-kernel-services.sh').write_bytes(self.legacy)
                self.environment['HYPEROS_TEST_RACE'] = race
                with self.assertRaises(RuntimeError):
                    self.migrate()
                self.assertEqual(list(self.module.glob('.kernel-helper-*')), [])
                if race == 'helper':
                    self.assertEqual((self.module / 'check-kernel-services.sh').read_bytes(), b'changed concurrently')
                else:
                    self.assertTrue((self.module / race).exists())
                    self.assertEqual((self.module / 'check-kernel-services.sh').read_bytes(), self.legacy)
                    (self.module / race).unlink()

    def test_failed_context_preservation_does_not_replace_helper(self):
        self.environment['HYPEROS_TEST_CHCON_FAIL'] = '1'
        before = self.snapshot()
        with self.assertRaises(RuntimeError):
            self.migrate()
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(list(self.module.glob('.kernel-helper-*')), [])

    def test_helper_hash_exports_are_exact_and_current_source_stays_pinned(self):
        self.assertEqual(install.KERNEL_SCRIPT_HASHES, (install.LEGACY_KERNEL_SCRIPT_SHA256, install.KERNEL_SCRIPT_SHA256))
        self.assertEqual(hashlib.sha256(self.source).hexdigest(), install.KERNEL_SCRIPT_SHA256)
        self.assertNotIn(b'persist.sys.stability.PrereadEnable', self.source)
        self.assertNotIn(b'ctl.stop iorapd', self.source)
        self.assertIn(b'sys.hyperos_avd.millet_supported 0', self.source)
        self.assertIn(b'gnss-extension', self.source)
        with tempfile.NamedTemporaryFile() as unrelated, patch.object(install, 'PERF_SCRIPT', Path(unrelated.name)):
            unrelated.write(b'changed repository helper')
            unrelated.flush()
            with self.assertRaisesRegex(RuntimeError, 'source differs'):
                install._kernel_migration_script()

    def test_known_uninstall_hooks_migrate_without_touching_current_preferences(self):
        target = self.module / 'uninstall.sh'
        template = '#!/system/bin/sh\n[ "$(getprop persist.sys.stability.PrereadEnable)" = false ] && setprop persist.sys.stability.PrereadEnable '
        before = self.snapshot()
        digests = []
        for prior in ('', 'false', 'true', '0', '1'):
            with self.subTest(prior=prior):
                old = (template + shlex.quote(prior) + '\n').encode()
                digests.append(hashlib.sha256(old).hexdigest())
                target.write_bytes(old)
                self.assertTrue(self.migrate('migrate_uninstall_hook')['migrated'])
                self.assertEqual(target.read_bytes(), install.UNINSTALL_SCRIPT.encode())
                self.assertEqual((self.module / 'check-kernel-services.sh').read_bytes(), self.legacy)
                self.assertEqual(list(self.module.glob('.kernel-helper-*')), [])
        self.assertEqual(tuple(digests), install.LEGACY_UNINSTALL_SHA256S)
        before['uninstall.sh'] = (install.UNINSTALL_SCRIPT.encode(), 493)
        self.assertEqual(self.snapshot(), before)
        self.assertNotIn(b'persist.sys.stability.PrereadEnable', target.read_bytes())
        self.assertTrue(self.migrate('migrate_uninstall_hook')['reused'])

    def test_unknown_absent_or_disabled_uninstall_hook_is_preserved(self):
        target = self.module / 'uninstall.sh'
        original = target.read_bytes()
        result = self.migrate('migrate_uninstall_hook')
        self.assertTrue(result['unsupported'])
        self.assertEqual(target.read_bytes(), original)
        (self.module / 'disable').touch()
        self.assertEqual(self.migrate('migrate_uninstall_hook')['preserved'], ['disable'])
        self.assertEqual(target.read_bytes(), original)
        (self.module / 'disable').unlink()
        target.unlink()
        self.assertFalse(self.migrate('migrate_uninstall_hook')['hook_present'])
        self.assertFalse(target.exists())

if __name__ == '__main__':
    unittest.main()


# --- tests/test_image_kernel_services.py ---

'Exercise generated first-boot authorization and capability effects offline.'

class ImageKernelServicesTests(unittest.TestCase):

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.temporary = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.root = Path(self.temporary)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.events = self.root / 'events'
        self.payloads = {path: ('audited fixture ' + name).encode() for name, (path, _, _) in services.TARGETS.items()}
        self.probe = b'#!/bin/sh\nprintf \'probe:%s\n\' "$1" >> "$EVENTS"\nif [ "$1" = gnss-extension ]; then exit "$GNSS_RESULT"; fi\nexit "$MILLET_RESULT"\n'
        self.payloads[helper.PROBE_PATH] = self.probe
        after = {name: digest(self.payloads[path]) for name, (path, _, _) in services.TARGETS.items()}
        modern = b'audited modern GNSS fixture'
        self.modern = modern
        modern_before = next(reversed(services.SERVICE_RECIPES))
        variants = {services.TARGETS['services'][1]: after['services'], modern_before: digest(modern)}
        self.stack.enter_context(patch.object(services, 'AFTER', after))
        self.stack.enter_context(patch.object(services, 'SERVICE_RECIPES', variants))
        self.stack.enter_context(patch.object(services, 'PROBE_SHA256', digest(self.probe)))
        self.write_bin('id', '#!/bin/sh\nprintf "%s\\n" "$USER_ID"\n')
        self.write_bin('uname', '#!/bin/sh\nprintf "%s\\n" "$KERNEL_ABI"\n')
        self.write_bin('getprop', '#!/bin/sh\ncase "$1" in\n    ro.boot.hardware) printf \'%s\n\' "$HARDWARE" ;;\n    ro.product.cpu.abi) printf \'%s\n\' "$ANDROID_ABI" ;;\n    ro.millet.netlink) printf \'30\n\' ;;\n    *) printf \'deliberately-unrelated\n\' ;;\nesac\n')
        self.write_bin('setprop', '#!/bin/sh\nprintf "property:%s:%s\\n" "$1" "$2" >> "$EVENTS"\n')
        self.write_bin('sha256sum', '#!' + sys.executable + '\nimport hashlib, pathlib, sys\nprint(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest(), sys.argv[1])\n')
        self.environment = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'], EVENTS=str(self.events), USER_ID='0', HARDWARE='ranchu', ANDROID_ABI='arm64-v8a', KERNEL_ABI='aarch64', MILLET_RESULT='2', GNSS_RESULT='2')

    def write_bin(self, name, content):
        path = self.bin / name
        path.write_text(content)
        path.chmod(493)

    def run_helper(self, *, modern=False, mutate=None, environment=None):
        for path, content in self.payloads.items():
            file = self.root / path.lstrip('/')
            file.parent.mkdir(parents=True, exist_ok=True)
            file.unlink(missing_ok=True)
            file.write_bytes(self.modern if modern and path == services.TARGETS['services'][0] else content)
            file.chmod(493 if path == helper.PROBE_PATH else 420)
        if mutate is not None:
            mutate(self.root)
        script = helper.image_script()
        for path in sorted(self.payloads, key=len, reverse=True):
            script = script.replace(path.encode(), str(self.root / path.lstrip('/')).encode())
        path = self.root / 'helper.sh'
        path.write_bytes(script)
        result = subprocess.run(['sh', str(path)], env={**self.environment, **(environment or {})}, text=True, capture_output=True)
        events = self.events.read_text().splitlines() if self.events.exists() else []
        return (result, events)

    def test_full_old_and_modern_recipes_work_without_ksu_or_version_identity(self):
        for modern in (False, True):
            with self.subTest(modern=modern):
                self.events.unlink(missing_ok=True)
                result, events = self.run_helper(modern=modern)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('verified recipe', result.stderr)
                self.assertEqual(events, ['probe:30', 'property:sys.hyperos_avd.millet_supported:0', 'property:ctl.stop:millet_monitor', 'probe:gnss-extension', 'property:ctl.stop:loc_sys_service'])
        script = helper.image_script().decode()
        for value in ('/data/adb', 'OS4.0.', 'ro.product.device', 'ro.mi.os.version', 'HyperOS_4_'):
            self.assertNotIn(value, script)

    def test_supported_capabilities_keep_hardware_daemons(self):
        result, events = self.run_helper(environment={'MILLET_RESULT': '0', 'GNSS_RESULT': '0'})
        self.assertEqual(result.returncode, 0)
        self.assertEqual(events, ['probe:30', 'property:sys.hyperos_avd.millet_supported:1', 'probe:gnss-extension'])

    def test_failed_probe_reports_failure_without_treating_unknown_as_unsupported(self):
        result, events = self.run_helper(environment={'MILLET_RESULT': '1'})
        self.assertEqual(result.returncode, 1)
        self.assertIn('failed (millet-probe)', result.stderr)
        self.assertEqual(events, ['probe:30'])

    def test_foreign_hardware_or_abi_cannot_probe_or_change_properties(self):
        for environment in ({'USER_ID': '1000'}, {'HARDWARE': 'qcom'}, {'ANDROID_ABI': 'x86_64'}, {'KERNEL_ABI': 'x86_64'}):
            with self.subTest(environment=environment):
                result, events = self.run_helper(environment=environment)
                self.assertEqual(result.returncode, 0)
                self.assertIn('skip (', result.stderr)
                self.assertFalse(events)

    def test_unknown_missing_mixed_and_aliased_recipes_skip_before_effects(self):
        target = services.TARGETS['qualcomm'][0]

        def changed(root):
            (root / target.lstrip('/')).write_bytes(b'foreign service')

        def missing(root):
            (root / target.lstrip('/')).unlink()

        def alias(root):
            path = root / target.lstrip('/')
            saved = path.with_suffix('.known')
            path.rename(saved)
            path.symlink_to(saved)

        def altered_probe(root):
            (root / helper.PROBE_PATH.lstrip('/')).write_bytes(b'#!/bin/sh\nexit 2\n')
        for mutate in (changed, missing, alias, altered_probe):
            with self.subTest(mutate=mutate.__name__):
                result, events = self.run_helper(mutate=mutate)
                self.assertEqual(result.returncode, 0)
                self.assertIn('skip (', result.stderr)
                self.assertFalse(events)

    def test_known_individual_pins_cannot_authorize_a_mixed_recipe(self):
        frozen, modern = services.image_receipts()
        modern = json.loads(json.dumps(modern))
        modern['targets']['qualcomm']['after'] = digest(b'audited second Qualcomm fixture')
        with patch.object(services, 'image_receipts', return_value=(frozen, modern)):
            result, events = self.run_helper(modern=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn('unknown-mixed-or-incomplete-image-recipe', result.stderr)
        self.assertFalse(events)

    def test_generator_rejects_duplicate_incomplete_and_noncanonical_receipts(self):
        receipt = services.image_receipt()
        with patch.object(services, 'image_receipts', return_value=(receipt, receipt)):
            with self.assertRaisesRegex(RuntimeError, 'Duplicate'):
                helper.image_script()
        bad = json.loads(json.dumps(receipt))
        del bad['targets']['qualcomm']
        with patch.object(services, 'image_receipts', return_value=(bad,)):
            with self.assertRaisesRegex(RuntimeError, 'Incomplete image kernel-service recipe'):
                helper.image_script()

    def test_published_phone_helpers_stay_accepted_only_for_their_frozen_source(self):
        from apply_boot_service_fix import KERNEL_SCRIPT_SHA256, KERNEL_SCRIPT_HASHES
        from phone_profile import profile
        old = profile('4.0.18.0.XFRCNXM')
        build = {'hyperos': old['hyperos'], 'archive_sha256': old['archive_sha256'], 'boot_service_fix': services.image_receipt()}
        self.assertTrue(set(KERNEL_SCRIPT_HASHES) <= set(helper.accepted_hashes(build)))
        self.assertIn(KERNEL_SCRIPT_SHA256, helper.accepted_hashes({**build, 'boot_policy': {}}))
        modern = profile('4.0.24.0.XFRCNXM')
        new = {**build, 'hyperos': modern['hyperos'], 'archive_sha256': modern['archive_sha256']}
        self.assertEqual(helper.accepted_hashes(new), (helper.image_script_sha256(),))
        for marker in services.image_receipts()[1:]:
            self.assertEqual(helper.accepted_hashes({**build, 'boot_service_fix': marker}), (helper.image_script_sha256(),))

    def test_current_image_producer_uses_the_same_exact_generated_helper(self):
        originals = {name: ('original ' + name).encode() for name in services.TARGETS}
        selected = {name: {'before': services.TARGETS[name][1]} for name in originals}
        probe = self.root / 'probe'
        probe.write_bytes(self.probe)

        def patched(name, source, destination):
            destination.write_bytes(self.payloads[services.TARGETS[name][0]])
            return destination
        original_select = services.select_recipe
        with patch.object(services, 'select_recipe', side_effect=lambda name, data: selected[name] if isinstance(data, bytes) else original_select(name, data)), patch.object(services, 'patch', side_effect=patched), patch.object(services, 'kernel_probe', return_value=probe):
            edits, _ = services.image_replacements(originals, self.root / 'work')
        self.assertEqual(edits[helper.PATH.lstrip('/')], (helper.image_script(), 493, 'u:object_r:system_file:s0'))

    def test_release_checks_current_helper_instead_of_version_gated_old_script(self):
        from apply_boot_service_fix import PERF_SCRIPT
        from phone_profile import profile
        selected = profile('4.0.24.0.XFRCNXM')
        build = {'hyperos': selected['hyperos'], 'archive_sha256': selected['archive_sha256'], 'boot_service_fix': services.image_receipt()}
        files = {**self.payloads, helper.PATH: helper.image_script(), '/system_ext/etc/init/init.hyperos_avd.rc': services.BOOT_INIT, '/system_ext/etc/selinux/system_ext_sepolicy.cil': services.BOOT_SEPOLICY}
        self.assertEqual(release.verify_boot_services(build, files.__getitem__), 7)
        files[helper.PATH] = PERF_SCRIPT.read_bytes()
        with self.assertRaisesRegex(RuntimeError, 'checksum mismatch: ' + helper.PATH):
            release.verify_boot_services(build, files.__getitem__)

    def test_preparer_refreshes_frozen_or_current_helper_and_rejects_unknown(self):
        import os4_boot_policy as policy
        from apply_boot_service_fix import PERF_SCRIPT
        init = services.BOOT_INIT
        graph = {policy.INIT_PATH: init}
        files = {'/' + policy.INIT_PATH: init, '/' + policy.POLICY_PATH: b'enforcing fixture'}
        for previous in (PERF_SCRIPT.read_bytes(), helper.image_script(), b'unknown helper'):
            with self.subTest(previous=digest(previous)):
                edits = {helper.PATH.lstrip('/'): (previous, 493, 'u:object_r:system_file:s0')}
                with patch.object(policy, 'init_files', return_value=graph), patch.object(policy, 'image_replacements', return_value=({}, {'fixture': True})), patch.object(prepare, 'erofs', side_effect=lambda raw, path: files[path]):
                    if previous == b'unknown helper':
                        with self.assertRaisesRegex(RuntimeError, 'Unknown existing image kernel helper'):
                            prepare.shared_boot_edits(self.root / 'system.img', self.root / 'vendor.img', edits, self.root / 'prepared')
                    else:
                        prepare.shared_boot_edits(self.root / 'system.img', self.root / 'vendor.img', edits, self.root / 'prepared')
                        self.assertEqual(edits[helper.PATH.lstrip('/')][0], helper.image_script())

if __name__ == '__main__':
    unittest.main()
