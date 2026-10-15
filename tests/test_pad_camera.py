"""Consolidated unit tests for Pad and Xiaomi camera fixes:
framework orientation/angle fix, native camera hal fix, YUV shader emulation, camera scene patch, and camera service wrapper.
"""
from contextlib import ExitStack
import copy
import ctypes
import hashlib
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

REPO = Path(__file__).resolve().parents[1]
ROOT = REPO
sys.path.insert(0, str(REPO / 'scripts'))

import apply_flutter_fix
import apply_pad_camera_fix as pad_camera_fix
import apply_pad_camera_native_fix as pad_camera_native_fix
import apply_xiaomi_camera_fix as xiaomi_camera_fix
import module_lifecycle as lifecycle
import patch_camera_scene as scene



# --- tests/test_pad_camera_fix.py ---

'Exercise guarded, reversible package-scoped ANGLE settings without a guest.'

class FakeRoot:
    """Reject commands outside the installer's read guards and settings scope."""

    def __init__(self, values, fail_write=None, fail_restore=False, corrupt_verification=False):
        self.state = dict(zip(pad_camera_fix.KEYS, values))
        self.properties = dict(pad_camera_fix.PROPERTIES)
        self.hashes = dict(pad_camera_fix.HASHES)
        self.apk = 'package:' + pad_camera_fix.APK
        self.commands = []
        self.mutations = []
        self.fail_write = fail_write
        self.fail_restore = fail_restore
        self.corrupt_verification = corrupt_verification

    def __call__(self, config, command, **kwargs):
        self.commands.append((dict(config), command))
        words = shlex.split(command)
        if len(words) == 2 and words[0] == 'getprop':
            return self.properties[words[1]]
        if words == ['pm', 'path', pad_camera_fix.PACKAGE]:
            return self.apk
        if len(words) == 2 and words[0] == 'sha256sum':
            return self.hashes[words[1]] + '  ' + words[1]
        if len(words) < 4 or words[0] != 'settings' or words[2] != 'global':
            raise AssertionError('Unexpected root command: ' + command)
        operation, key = (words[1], words[3])
        if key not in pad_camera_fix.KEYS:
            raise AssertionError('Unexpected settings key: ' + key)
        if operation == 'get' and len(words) == 4:
            if self.corrupt_verification and self.mutations and (key == pad_camera_fix.KEYS[2]):
                self.corrupt_verification = False
                return 'unexpectedFeature'
            return self.state[key]
        if operation == 'put' and len(words) == 5:
            value = words[4]
        elif operation == 'delete' and len(words) == 4:
            value = 'null'
        else:
            raise AssertionError('Unexpected settings command: ' + command)
        self.mutations.append((operation, key, value))
        count = len(self.mutations)
        if self.fail_restore and count == 3:
            raise RuntimeError('Injected restore failure before its side effect.')
        self.state[key] = value
        if count == self.fail_write:
            raise RuntimeError('Injected settings failure after its side effect.')
        return ''

    def setting_reads(self):
        return [shlex.split(command)[3] for _, command in self.commands if shlex.split(command)[:3] == ['settings', 'get', 'global']]

class AngleSettingsTests(unittest.TestCase):

    def test_empty_and_absent_selections_append_only_camera(self):
        expected = (pad_camera_fix.PACKAGE, 'angle', 'exposeES32ForTesting')
        for packages in ('null', ''):
            for values in ('null', ''):
                for features in ('null', ''):
                    with self.subTest(packages=packages, values=values, features=features):
                        self.assertEqual(pad_camera_fix.angle_settings(packages, values, features), expected)

    def test_unrelated_selection_and_feature_order_survive(self):
        self.assertEqual(pad_camera_fix.angle_settings('com.example.video,com.example.reader', 'native,default', 'forceVulkanUseDefaultUniformBlock,preferSubmitAtEndOfPass'), ('com.example.video,com.example.reader,' + pad_camera_fix.PACKAGE, 'native,default,angle', 'forceVulkanUseDefaultUniformBlock,preferSubmitAtEndOfPass,exposeES32ForTesting'))

    def test_existing_camera_and_repeated_es32_feature_are_idempotent(self):
        expected = ('com.example.video,' + pad_camera_fix.PACKAGE + ',com.example.reader', 'native,angle,default', 'first,exposeES32ForTesting,last')
        actual = pad_camera_fix.angle_settings(expected[0], 'native,native,default', 'first,exposeES32ForTesting,last,exposeES32ForTesting')
        self.assertEqual(actual, expected)
        self.assertEqual(pad_camera_fix.angle_settings(*actual), expected)

    def test_malformed_lists_cannot_be_silently_repaired(self):
        cases = (('com.one,com.two', 'angle', ''), ('com.one', 'angle,native', ''), ('com.one', '', ''), ('null', 'angle', ''), ('com.one,,com.two', 'angle,native,default', ''), ('com.one,', 'angle,native', ''), (',com.one', 'native,angle', ''), ('com.one,com.two', ',angle', ''), ('com.one,com.two', 'angle,', ''), ('com.one,com.one', 'native,angle', ''), ('', '', 'first,,last'))
        for values in cases:
            with self.subTest(values=values), self.assertRaises(RuntimeError):
                pad_camera_fix.angle_settings(*values)

class PadCameraInstallTests(unittest.TestCase):

    def setUp(self):
        self.config = {'sdk': '/unused-sdk', 'name': 'Renamed_Pad_Camera', 'port': 5596}

    def install(self, fake):
        with patch.object(pad_camera_fix, 'official') as official, patch.object(pad_camera_fix, 'root', side_effect=fake):
            result = pad_camera_fix.install(self.config)
        official.assert_called_once_with(self.config, sources=(pad_camera_fix.SOURCE,))
        return result

    def test_renamed_instance_preserves_other_packages_and_writes_only_changes(self):
        before = ('com.example.video,' + pad_camera_fix.PACKAGE + ',com.example.reader', 'native,native,default', 'otherFeature,exposeES32ForTesting')
        fake = FakeRoot(before)
        self.install(fake)
        expected = (before[0], 'native,angle,default', before[2])
        self.assertEqual(tuple((fake.state[key] for key in pad_camera_fix.KEYS)), expected)
        self.assertEqual(fake.mutations, [('put', pad_camera_fix.KEYS[1], expected[1])])
        self.assertTrue(all((config == self.config for config, _ in fake.commands)))
        first_setting = next((index for index, (_, command) in enumerate(fake.commands) if shlex.split(command)[0] == 'settings'))
        guards = [shlex.split(command) for _, command in fake.commands[:first_setting]]
        self.assertEqual(guards, [*(['getprop', key] for key in pad_camera_fix.PROPERTIES), ['pm', 'path', pad_camera_fix.PACKAGE], *(['sha256sum', path] for path in pad_camera_fix.HASHES)])
        fake.commands.clear()
        fake.mutations.clear()
        self.install(fake)
        self.assertEqual(fake.mutations, [])
        self.assertEqual(fake.setting_reads(), list(pad_camera_fix.KEYS))

    def test_actual_unknown_source_is_refused_before_any_adb(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'local').mkdir()
            (root / 'local/build.json').write_text(json.dumps({'source': 'official-unverified-ota'}))
            with patch.object(apply_flutter_fix, 'ROOT', root), patch.object(apply_flutter_fix, 'adb') as adb, patch.object(pad_camera_fix, 'root') as command:
                with self.assertRaisesRegex(RuntimeError, 'firmware profile'):
                    pad_camera_fix.install(self.config)
            adb.assert_not_called()
            command.assert_not_called()

    def test_each_device_guard_refuses_before_reading_or_writing_settings(self):
        for key in pad_camera_fix.PROPERTIES:
            with self.subTest(key=key):
                fake = FakeRoot(('null', 'null', 'null'))
                fake.properties[key] = 'unsupported'
                with self.assertRaises(RuntimeError):
                    self.install(fake)
                self.assertEqual(fake.mutations, [])
                self.assertEqual(fake.setting_reads(), [])

    def test_updated_apk_path_and_each_unknown_hash_refuse_before_settings(self):
        for target in ('apk-path', *pad_camera_fix.HASHES):
            with self.subTest(target=target):
                fake = FakeRoot(('null', 'null', 'null'))
                if target == 'apk-path':
                    fake.apk = 'package:/data/app/updated-camera/base.apk'
                else:
                    fake.hashes[target] = '0' * 64
                with self.assertRaises(RuntimeError):
                    self.install(fake)
                self.assertEqual(fake.mutations, [])
                self.assertEqual(fake.setting_reads(), [])

    def test_malformed_paired_settings_produce_no_writes(self):
        for before in (('com.one,com.two', 'angle', 'otherFeature'), ('com.one,com.one', 'native,angle', ''), ('com.one,', 'native,angle', '')):
            with self.subTest(before=before):
                fake = FakeRoot(before)
                with self.assertRaises(RuntimeError):
                    self.install(fake)
                self.assertEqual(fake.mutations, [])
                self.assertEqual(tuple((fake.state[key] for key in pad_camera_fix.KEYS)), before)

    def test_second_write_failure_restores_attempted_writes_in_reverse(self):
        before = ('null', '', 'null')
        fake = FakeRoot(before, fail_write=2)
        with self.assertRaisesRegex(RuntimeError, 'original settings restored'):
            self.install(fake)
        self.assertEqual(tuple((fake.state[key] for key in pad_camera_fix.KEYS)), before)
        self.assertEqual(fake.mutations, [('put', pad_camera_fix.KEYS[0], pad_camera_fix.PACKAGE), ('put', pad_camera_fix.KEYS[1], 'angle'), ('put', pad_camera_fix.KEYS[1], ''), ('delete', pad_camera_fix.KEYS[0], 'null')])
        self.assertEqual(fake.setting_reads()[-3:], list(pad_camera_fix.KEYS))

    def test_failed_restore_continues_other_restores_and_reports_incomplete_rollback(self):
        fake = FakeRoot(('null', '', 'null'), fail_write=2, fail_restore=True)
        with self.assertRaises(RuntimeError) as error:
            self.install(fake)
        self.assertIn('rollback', str(error.exception).lower())
        self.assertRegex(str(error.exception).lower(), 'failed|incomplete')
        self.assertEqual([key for _, key, _ in fake.mutations], [pad_camera_fix.KEYS[0], pad_camera_fix.KEYS[1], pad_camera_fix.KEYS[1], pad_camera_fix.KEYS[0]])
        self.assertEqual(fake.state[pad_camera_fix.KEYS[0]], 'null')
        self.assertEqual(fake.state[pad_camera_fix.KEYS[1]], 'angle')
        self.assertEqual(fake.setting_reads()[-3:], list(pad_camera_fix.KEYS))

    def test_postwrite_verification_mismatch_restores_all_three_settings(self):
        before = ('null', '', 'otherFeature')
        fake = FakeRoot(before, corrupt_verification=True)
        with self.assertRaisesRegex(RuntimeError, 'original settings restored'):
            self.install(fake)
        self.assertEqual(tuple((fake.state[key] for key in pad_camera_fix.KEYS)), before)
        self.assertEqual([key for _, key, _ in fake.mutations], [*pad_camera_fix.KEYS, *reversed(pad_camera_fix.KEYS)])
        self.assertEqual(fake.setting_reads(), [*pad_camera_fix.KEYS, *pad_camera_fix.KEYS, *pad_camera_fix.KEYS])

if __name__ == '__main__':
    unittest.main()


# --- tests/test_pad_camera_native_fix.py ---

'Guard and script checks for the isolated Pad camera native installer.'

class PadCameraNativeTests(unittest.TestCase):

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='pad-camera-install-test-')
        self.folder = Path(self.temporary.name)
        self.calls = []
        self.properties = dict(pad_camera_native_fix.PROPERTIES)
        self.hashes = {pad_camera_native_fix.APK: pad_camera_native_fix.APK_HASH, pad_camera_native_fix.CPP: pad_camera_native_fix.CPP_HASH, pad_camera_native_fix.RUNTIME: pad_camera_native_fix.RUNTIME_HASH, pad_camera_native_fix.PROVIDER: pad_camera_native_fix.PROVIDER_BEFORE, pad_camera_native_fix.HWL: pad_camera_native_fix.HWL_BEFORE}
        self.package = 'package:' + pad_camera_native_fix.APK
        self.native = ''
        self.existing = False
        self.disabled = False
        self.saved = pad_camera_native_fix.manifest()
        self.config = {'name': 'Custom_Pad', 'port': 5582, 'sdk': '/unused-sdk'}
        self.root_patch = patch.object(pad_camera_native_fix, 'ROOT', self.folder)
        self.root_patch.start()

    def tearDown(self):
        self.root_patch.stop()
        self.temporary.cleanup()

    def fake_root(self, config, command):
        self.assertEqual(config, self.config)
        self.calls.append(command)
        if command == lifecycle.state_script(pad_camera_native_fix.MODULE):
            return 'disable' if self.disabled else ''
        command = command.removeprefix('set -e\n').removeprefix(lifecycle.mutation_guard(pad_camera_native_fix.MODULE))
        hook = next((line for line in command.splitlines() if line in ('sha256sum ' + pad_camera_native_fix.MODULE + '/service.sh', 'sha256sum ' + pad_camera_native_fix.MODULE + '/post-fs-data.sh')), None)
        if hook:
            name = hook.rsplit('/', 1)[1]
            p = self.folder / 'work/pad-camera-native/script-check' / name
            return hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + name
        if command.startswith('getprop '):
            return self.properties[command.split()[1]]
        if command == 'pm path com.android.camera':
            return self.package
        if command.startswith('if [ -e ' + pad_camera_native_fix.MODULE + ' ]'):
            return 'yes' if self.existing else ''
        if command == 'cat ' + pad_camera_native_fix.MODULE + '/manifest.json':
            return json.dumps(self.saved)
        if command.startswith('if [ -e ' + pad_camera_native_fix.MODULE + '/disable'):
            return 'yes' if self.disabled else ''
        if command.startswith('sha256sum ' + pad_camera_native_fix.MODULE + '/'):
            name = command.rsplit('/', 1)[1]
            p = self.folder / 'work/pad-camera-native/script-check' / name
            return hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + name
        if command.startswith('sh ' + pad_camera_native_fix.MODULE + '/post-fs-data.sh'):
            return ''
        if 'sha256sum' in command:
            if command.endswith(' sh ' + pad_camera_native_fix.YUV):
                return self.native
            path = command.rsplit(' ', 1)[1]
            return self.hashes[path] + '  ' + path
        raise AssertionError('Unexpected root command: ' + command)

    def install(self):
        with patch.object(pad_camera_native_fix, 'official') as ownership, patch.object(pad_camera_native_fix, 'root', self.fake_root):
            result = pad_camera_native_fix.install(self.config)
            ownership.assert_called_once_with(self.config, sources=(pad_camera_native_fix.SOURCE,))
            return result

    def assert_no_guest_write(self):
        self.assertFalse(any((command.startswith(('mkdir', 'cp ', 'mv ', 'sh ', 'am ', 'settings ')) for command in self.calls)))

    def test_unknown_framework_refused_before_mutation(self):
        self.hashes[pad_camera_native_fix.RUNTIME] = '0' * 64
        with self.assertRaisesRegex(RuntimeError, 'native input'):
            self.install()
        self.assert_no_guest_write()
        self.assertFalse((self.folder / 'work').exists())

    def test_unknown_vendor_inputs_are_refused_before_mutation(self):
        for target in (pad_camera_native_fix.CPP, pad_camera_native_fix.PROVIDER, pad_camera_native_fix.HWL, pad_camera_native_fix.APK):
            with self.subTest(target=target):
                previous = self.hashes[target]
                self.hashes[target] = '0' * 64
                with self.assertRaisesRegex(RuntimeError, 'native input'):
                    self.install()
                self.assert_no_guest_write()
                self.hashes[target] = previous

    def test_wrong_source_stops_before_any_guest_command(self):
        with patch.object(pad_camera_native_fix, 'official', side_effect=RuntimeError('wrong source')), patch.object(pad_camera_native_fix, 'root', self.fake_root):
            with self.assertRaisesRegex(RuntimeError, 'wrong source'):
                pad_camera_native_fix.install(self.config)
        self.assertEqual(self.calls, [])

    def test_unknown_update_and_private_native_are_refused(self):
        self.package += '.updated'
        with self.assertRaisesRegex(RuntimeError, 'camera update'):
            self.install()
        self.assert_no_guest_write()
        self.package = 'package:' + pad_camera_native_fix.APK
        self.native = 'f' * 64 + '  ' + pad_camera_native_fix.YUV
        with self.assertRaisesRegex(RuntimeError, 'native overlay'):
            self.install()
        self.assert_no_guest_write()

    def test_disabled_owned_module_remains_disabled(self):
        self.existing = self.disabled = True
        self.assertEqual(self.install(), {'preserved': True, 'lifecycle': ['disable']})
        self.assert_no_guest_write()
        self.assertFalse((self.folder / 'work').exists())

    def test_unknown_existing_manifest_is_never_adopted(self):
        self.existing = True
        self.saved['targets'][0]['after'] = '0' * 64
        with self.assertRaisesRegex(RuntimeError, 'Unknown Pad camera manifest'):
            self.install()
        self.assert_no_guest_write()

    def test_verified_prototype_hashes_are_accepted_for_existing_module(self):
        self.existing = True
        self.hashes[pad_camera_native_fix.HWL] = pad_camera_native_fix.HWL_AFTER
        self.hashes[pad_camera_native_fix.PROVIDER] = pad_camera_native_fix.PROVIDER_AFTER
        self.native = pad_camera_native_fix.YUV_AFTER + '  ' + pad_camera_native_fix.YUV
        self.assertEqual(self.install(), pad_camera_native_fix.manifest())
        self.assertTrue(self.calls[-1].endswith('sh ' + pad_camera_native_fix.MODULE + '/post-fs-data.sh'))

    def test_unknown_runtime_never_uses_private_offsets(self):
        with self.assertRaisesRegex(RuntimeError, 'Unsupported Pad ImageReader'):
            pad_camera_native_fix.validate_runtime(b'not an ELF')

    def test_manifest_rejects_phone_and_changes(self):
        for field in ('source', 'apk_sha256', 'runtime_sha256', 'embedded_yuv_sha256', 'yuv_sha256', 'plane_offset', 'recovery'):
            changed = copy.deepcopy(pad_camera_native_fix.manifest())
            changed[field] = 'unknown'
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                pad_camera_native_fix.validate_manifest(changed)

    def test_generated_shell_scripts_have_no_placeholders_and_parse(self):
        pad_camera_native_fix.write_scripts(self.folder)
        for name in ('post-fs-data.sh', 'service.sh'):
            subprocess.run(['sh', '-n', str(self.folder / name)], check=True)
        source = (self.folder / 'post-fs-data.sh').read_text()
        self.assertNotRegex(source, '@[A-Z_]+@')
        self.assertLess(source.index('# Preflight every'), source.index('mount -o bind'))
        self.assertIn(pad_camera_native_fix.RUNTIME_HASH, source)
        self.assertIn(pad_camera_native_fix.PROVIDER_BEFORE + '|' + pad_camera_native_fix.PROVIDER_AFTER, source)
        self.assertIn(hashlib.sha256(pad_camera_native_fix.targets_text().encode()).hexdigest(), source)
        preflight = source.split('changed=0', 1)[0]
        for name in ('provider', 'hwl.so', 'app/MiuiCamera.apk', 'app/lib/arm64/libcamera_yuv_jni.so'):
            self.assertIn('nsenter -t "$pid" -m -- "$BB" sha256sum "$MODDIR/' + name + '"', preflight)
        self.assertIn('flags=ro,suid,exec', source)
        self.assertNotIn('setenforce', source)
        self.assertNotIn('pm clear', source)

    def test_early_boot_without_zygote_still_selects_init(self):
        prefix = pad_camera_native_fix.namespace_preflight().split('# Preflight every', 1)[0]
        script = 'set -e\ngetprop() { return 0; }\npidof() { return 1; }\n' + prefix
        script += '\nprintf "%s" "$pids"\n'
        result = subprocess.run(['sh', '-c', script], text=True, check=True, capture_output=True)
        self.assertEqual(result.stdout.strip(), '1')

    def test_unknown_prebuilt_receipt_never_copies_payloads(self):
        cache = self.folder / 'tools/pad-camera-native'
        cache.mkdir(parents=True)
        (cache / 'receipt.json').write_text(json.dumps({'sources': {}, 'files': {}}))
        destination = self.folder / 'output'
        with self.assertRaisesRegex(RuntimeError, 'Unknown precompiled'):
            pad_camera_native_fix.build('/unused-sdk', destination)
        self.assertFalse(destination.exists())

    def publication_inputs(self):
        for name in ('provider', 'hwl.so', 'yuv.so', 'manifest.json', 'post-fs-data.sh', 'service.sh', 'targets.conf', 'module.prop'):
            (self.folder / name).write_text('temporary test payload\n')

    def test_publication_uses_unbound_unique_uploads_and_valid_shell(self):
        self.publication_inputs()
        commands = []

        def capture(config, command):
            commands.append(command)
            subprocess.run(['sh', '-n'], input=command, text=True, check=True)
            return ''
        with patch.object(pad_camera_native_fix, 'root', capture), patch.object(pad_camera_native_fix, 'adb') as transport:
            pad_camera_native_fix.publish(self.config, self.folder)
        uploads = [call.args[-1] for call in transport.call_args_list]
        self.assertEqual(len(uploads), 8)
        self.assertTrue(all(('/hyperos-pad-camera-install-' in path for path in uploads)))
        self.assertNotIn('/data/local/tmp/hyperos-pad-camera-provider', uploads)
        self.assertIn('mv /data/adb/hyperos-pad-camera-stage-', commands[-1])
        self.assertNotIn('rm -rf ' + pad_camera_native_fix.MODULE, '\n'.join(commands))

    def test_failed_upload_cleanup_never_removes_published_module(self):
        self.publication_inputs()
        commands = []
        with patch.object(pad_camera_native_fix, 'root', side_effect=lambda config, cmd: commands.append(cmd) or ''), patch.object(pad_camera_native_fix, 'adb', side_effect=subprocess.CalledProcessError(1, ['adb'])):
            with self.assertRaises(subprocess.CalledProcessError):
                pad_camera_native_fix.publish(self.config, self.folder)
        removals = [cmd for cmd in commands if 'rm ' in cmd]
        self.assertEqual(len(removals), 2)
        self.assertIn('rm -rf /data/adb/hyperos-pad-camera-stage-', removals[0])
        self.assertIn('rm -f /data/local/tmp/hyperos-pad-camera-install-', removals[1])
        self.assertNotIn(pad_camera_native_fix.MODULE, '\n'.join(removals))

    def test_prebuilt_bytes_must_match_all_pinned_checksums(self):
        cache = self.folder / 'tools/pad-camera-native'
        cache.mkdir(parents=True)
        expected = {**pad_camera_native_fix.PAYLOADS, 'manifest.json': hashlib.sha256((json.dumps(pad_camera_native_fix.manifest(), indent=2) + '\n').encode()).hexdigest()}
        (cache / 'receipt.json').write_text(json.dumps({'sources': pad_camera_native_fix.SOURCES, 'files': expected}))
        for name in expected:
            (cache / name).write_bytes(b'corrupt payload')
        destination = self.folder / 'output'
        with self.assertRaisesRegex(RuntimeError, 'payload changed'):
            pad_camera_native_fix.build('/unused-sdk', destination)
        self.assertFalse(destination.exists())

if __name__ == '__main__':
    unittest.main()


# --- tests/test_pad_camera_yuv.py ---

'Exercise the native byte conversion without loading or modifying an AVD.'

class PadCameraYuvTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        compiler = shutil.which('clang')
        if not compiler:
            raise unittest.SkipTest('A host clang compiler is needed for native byte tests.')
        cls.temporary = tempfile.TemporaryDirectory(prefix='pad-camera-yuv-test-')
        cls.source = Path(__file__).resolve().parents[1] / 'native/camera_pad_yuv_planes.c'
        library = Path(cls.temporary.name) / 'conversion.so'
        subprocess.run([compiler, '-DAVD_YUV_HOST_TEST', '-shared', '-fPIC', '-O2', '-Wall', '-Wextra', '-Werror', str(cls.source), '-o', str(library)], check=True, capture_output=True)
        cls.library = ctypes.CDLL(str(library))
        cls.convert = cls.library.avd_test_interleave
        pointer = ctypes.POINTER(ctypes.c_ubyte)
        cls.convert.argtypes = [pointer, ctypes.c_size_t, pointer, ctypes.c_size_t, ctypes.c_size_t, pointer, ctypes.c_size_t, ctypes.c_size_t, ctypes.c_int, ctypes.c_int]
        cls.convert.restype = ctypes.c_int

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def conversion(self, u, v, width, height, urow=None, vrow=None, capacity=None):
        capacity = width * height // 2 if capacity is None else capacity
        output = (ctypes.c_ubyte * capacity)(*[165] * capacity)
        uarray = (ctypes.c_ubyte * len(u))(*u)
        varray = (ctypes.c_ubyte * len(v))(*v)
        result = self.convert(output, capacity, uarray, len(u), width // 2 if urow is None else urow, varray, len(v), width // 2 if vrow is None else vrow, width, height)
        return (result, bytes(output))

    def test_exact_nv21_chroma_order(self):
        self.assertEqual(self.conversion([1, 2, 3, 4], [11, 12, 13, 14], 4, 4), (1, bytes([11, 1, 12, 2, 13, 3, 14, 4])))

    def test_independent_row_padding_and_short_final_row(self):
        self.assertEqual(self.conversion([1, 2, 99, 99, 3, 4], [11, 12, 99, 13, 14], 4, 4, urow=4, vrow=3), (1, bytes([11, 1, 12, 2, 13, 3, 14, 4])))

    def test_minimum_even_image(self):
        self.assertEqual(self.conversion([23], [45], 2, 2), (1, bytes([45, 23])))

    def test_invalid_bounds_leave_output_untouched(self):
        cases = [([1, 2], [11, 12], 4, 4, None, None, 8), ([1, 2, 3, 4], [11, 12, 13, 14], 4, 4, 1, 2, 8), ([1, 2, 3, 4], [11, 12, 13, 14], 4, 4, 2, 1, 8), ([1, 2, 3, 4], [11, 12, 13, 14], 4, 4, None, None, 7), ([1, 2, 3, 4], [11, 12, 13, 14], 3, 4, None, None, 8), ([1, 2, 3, 4], [11, 12, 13, 14], 4, 3, None, None, 8), ([1], [11], 4, 4, ctypes.c_size_t(-1).value, 2, 8)]
        for u, v, width, height, urow, vrow, capacity in cases:
            with self.subTest(width=width, height=height, urow=urow, vrow=vrow, capacity=capacity):
                self.assertEqual(self.conversion(u, v, width, height, urow, vrow, capacity), (0, bytes([165] * capacity)))

    def test_real_ranchu_photo_size(self):
        width, height = (1280, 960)
        samples = width * height // 4
        result, output = self.conversion([97] * samples, [153] * samples, width, height)
        self.assertEqual(result, 1)
        self.assertEqual(output, bytes([153, 97]) * samples)

if __name__ == '__main__':
    unittest.main()


# --- tests/test_camera_scene.py ---

'Reject unsupported virtual camera binaries and verify the pinned ELF edit.'

class CameraSceneTests(unittest.TestCase):

    def test_unknown_provider_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
            scene.patch(b'unknown provider')

    def test_already_patched_provider_is_unchanged(self):
        digest = Mock()
        digest.hexdigest.return_value = scene.AFTER
        with patch.object(scene.hashlib, 'sha256', return_value=digest):
            self.assertEqual(scene.patch(b'already verified'), b'already verified')

    def test_hash_cannot_bypass_the_instruction_guard(self):
        digest = Mock()
        digest.hexdigest.return_value = scene.BEFORE
        with patch.object(scene.hashlib, 'sha256', return_value=digest):
            with self.assertRaisesRegex(RuntimeError, 'instruction'):
                scene.patch(bytes(340368))

    def test_dependency_preserves_addresses_and_relro(self):
        source = bytearray(340368)
        source[216276:216280] = bytes.fromhex('40018052')
        struct.pack_into('<Q', source, 32, 64)
        struct.pack_into('<HH', source, 54, 56, 12)
        struct.pack_into('<IIQQQQQQ', source, 64 + 11 * 56, 4, 4, 760, 760, 760, 56, 56, 4)
        struct.pack_into('<IIQQQQQQ', source, 64 + 8 * 56, 1685382482, 4, 311296, 311296, 311296, 16384, 16384, 1)
        source[15896:16064] = b'R' * (16064 - 15896)
        for index, entry in enumerate(((5, 8348), (10, 7542), (21, 0))):
            struct.pack_into('<QQ', source, 314008 + index * 16, *entry)
        before, after = (Mock(), Mock())
        before.hexdigest.return_value = scene.BEFORE
        after.hexdigest.return_value = scene.AFTER
        with patch.object(scene.hashlib, 'sha256', side_effect=[before, after]):
            result = scene.patch(source)
        self.assertEqual(result[216276:216280], bytes.fromhex('00008052'))
        self.assertEqual(result[64 + 8 * 56:64 + 9 * 56], source[64 + 8 * 56:64 + 9 * 56])
        self.assertEqual(result[15896:16064], source[15896:16064])
        self.assertEqual(struct.unpack_from('<QQ', result, 314008), (5, 344064))
        self.assertEqual(struct.unpack_from('<QQ', result, 314040), (1, 7542))
        self.assertEqual(result[344064:344064 + 7542], source[8348:8348 + 7542])
        self.assertEqual(result[344064 + 7542:], scene.LIBRARY.encode() + b'\x00')

if __name__ == '__main__':
    unittest.main()


# --- tests/test_xiaomi_camera_fix.py ---

'Guard the experimental provider bridge against unsupported firmware.'

class XiaomiCameraTests(unittest.TestCase):

    def test_unrecognized_provider_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
            xiaomi_camera_fix.patch_provider(b'unsupported provider')

    def test_guarded_patch_changes_only_the_reserved_code_slot(self):
        source = b'X' * xiaomi_camera_fix.OFFSET + xiaomi_camera_fix.BEFORE + b'unrelated instructions'
        before, after = (Mock(), Mock())
        before.hexdigest.return_value = xiaomi_camera_fix.PROVIDER_HASH
        after.hexdigest.return_value = xiaomi_camera_fix.PROVIDER_AFTER
        with patch.object(xiaomi_camera_fix.hashlib, 'sha256', side_effect=[before, after]):
            result = xiaomi_camera_fix.patch_provider(source)
        self.assertEqual(len(source), len(result))
        self.assertEqual(source[:xiaomi_camera_fix.OFFSET], result[:xiaomi_camera_fix.OFFSET])
        size = len(xiaomi_camera_fix.BEFORE)
        self.assertEqual(source[xiaomi_camera_fix.OFFSET + size:], result[xiaomi_camera_fix.OFFSET + size:])
        self.assertEqual(xiaomi_camera_fix.AFTER, result[xiaomi_camera_fix.OFFSET:xiaomi_camera_fix.OFFSET + size])

    def test_correct_hash_does_not_bypass_the_instruction_guard(self):
        digest = Mock()
        digest.hexdigest.return_value = xiaomi_camera_fix.PROVIDER_HASH
        with patch.object(xiaomi_camera_fix.hashlib, 'sha256', return_value=digest):
            with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
                xiaomi_camera_fix.patch_provider(b'X' * (xiaomi_camera_fix.OFFSET + len(xiaomi_camera_fix.BEFORE)))

    def test_exact_vendor_mode_and_branch_destinations(self):
        words = [int.from_bytes(xiaomi_camera_fix.AFTER[i:i + 4], 'little') for i in range(0, len(xiaomi_camera_fix.AFTER), 4)]
        self.assertEqual(words[0], 1385300136)
        self.assertEqual(words[1], 1795686559)
        self.assertEqual(words[2], 1409286272)
        self.assertEqual(words[3], 1385169032)
        self.assertEqual(words[4], 1795686559)
        self.assertEqual(words[5], 1409286241)
        self.assertEqual(words[6], 706675684)
        for index, destination in ((7, 170648),):
            displacement = words[index] & 67108863
            if displacement & 33554432:
                displacement -= 67108864
            self.assertEqual(xiaomi_camera_fix.OFFSET + index * 4 + displacement * 4, destination)
        for index, destination in ((2, 170804), (5, 170812)):
            displacement = words[index] >> 5 & 524287
            if displacement & 262144:
                displacement -= 524288
            self.assertEqual(xiaomi_camera_fix.OFFSET + index * 4 + displacement * 4, destination)
        self.assertEqual(words[8], 284107283)

    def test_provider_upgrade_refuses_other_hal_changes(self):
        hwl = {'payload': 'hwl.so', 'target': xiaomi_camera_fix.HWL, 'before': xiaomi_camera_fix.HWL_HASH, 'after': 'a' * 64}
        old = {'payload': 'provider', 'target': xiaomi_camera_fix.PROVIDER, 'before': xiaomi_camera_fix.PROVIDER_HASH, 'after': xiaomi_camera_fix.PROVIDER_REV1}
        new = {**old, 'after': xiaomi_camera_fix.PROVIDER_AFTER}
        saved, newer = ({'targets': [old, hwl]}, {'targets': [new, hwl]})
        self.assertTrue(xiaomi_camera_fix.provider_upgrade(saved, newer))
        self.assertFalse(xiaomi_camera_fix.provider_upgrade(newer, newer))
        with self.assertRaisesRegex(RuntimeError, 'Unsupported HAL'):
            xiaomi_camera_fix.provider_upgrade(saved, {'targets': [new, {**hwl, 'after': 'b' * 64}]})
        with self.assertRaisesRegex(RuntimeError, 'Unsupported HAL'):
            xiaomi_camera_fix.provider_upgrade({'targets': [{**old, 'after': 'c' * 64}, hwl]}, newer)

if __name__ == '__main__':
    unittest.main()
