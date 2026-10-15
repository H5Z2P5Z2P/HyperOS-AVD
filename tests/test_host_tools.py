"""Consolidated unit tests for host tools: host display color correction, ADB management, and HTTPS transport."""
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import ssl
import struct
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch
import urllib.error
import urllib.request
import zipfile

REPO = Path(__file__).resolve().parents[1]
ROOT = REPO
sys.path.insert(0, str(REPO / 'scripts'))

import host_adb
import host_color
import https_transport as transport
import manage
import package_installer
import package_release
import setup



# --- tests/test_host_color.py ---

'Exercise owned-launch authorization and the compiled native AVD guard.'

def macho(name=host_color.INSTALL_NAME, duplicate=False, trailer=b''):
    value = name.encode() + b'\x00'
    length = 24 + len(value) + 7 & ~7
    command = struct.pack('<IIIIII', 13, length, 24, 0, 0, 0)
    command += value + bytes(length - 24 - len(value))
    commands = command * (2 if duplicate else 1)
    header = struct.pack('<IIIIIIII', 4277009103, 16777228, 0, 6, 2 if duplicate else 1, len(commands), 0, 0)
    return header + commands + trailer

class PortableHostColorBuildTests(unittest.TestCase):

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.tools = self.root / 'tools'
        self.tools.mkdir()
        self.library = self.tools / host_color.LIBRARY
        self.receipt = self.tools / host_color.RECEIPT
        self.source_hash = hashlib.sha256((REPO / 'native/emulator_srgb.m').read_bytes()).hexdigest()

    def seed(self, data, portable=True):
        self.library.write_bytes(data)
        value = {'source_sha256': self.source_hash, 'sha256': hashlib.sha256(data).hexdigest()}
        if portable:
            value['install_name'] = host_color.INSTALL_NAME
        self.receipt.write_text(json.dumps(value) + '\n')

    def compile(self, arguments, **kwargs):
        self.assertIn('-Wl,-install_name,@rpath/emulator_srgb.dylib', arguments)
        self.assertEqual(kwargs, {'check': True})
        Path(arguments[arguments.index('-o') + 1]).write_bytes(macho())
        return subprocess.CompletedProcess(arguments, 0)

    def test_portable_macho_and_exact_receipt_reuse_without_compiler(self):
        self.seed(macho())
        with patch.object(host_color.subprocess, 'run') as compiler:
            self.assertEqual(host_color.build(self.root), (self.library, self.receipt))
        compiler.assert_not_called()
        self.assertEqual(host_color.validate_library(self.library.read_bytes()), host_color.INSTALL_NAME)

    def test_old_absolute_install_name_is_rebuilt_before_reuse(self):
        self.seed(macho('/Users/private/build/emulator_srgb-123.dylib'), portable=False)
        with patch.object(host_color.subprocess, 'run', side_effect=self.compile) as compiler:
            host_color.build(self.root)
        compiler.assert_called_once()
        self.assertEqual(self.library.read_bytes(), macho())
        metadata = json.loads(self.receipt.read_text())
        self.assertEqual(metadata, {'source_sha256': self.source_hash, 'sha256': hashlib.sha256(macho()).hexdigest(), 'install_name': host_color.INSTALL_NAME})
        self.assertEqual(set(self.tools.iterdir()), {self.library, self.receipt})

    def test_failed_compiler_or_invalid_output_preserves_both_old_files(self):
        self.seed(macho('/Volumes/private/build/old.dylib'), portable=False)
        previous = (self.library.read_bytes(), self.receipt.read_bytes())

        def invalid(arguments, **kwargs):
            Path(arguments[arguments.index('-o') + 1]).write_bytes(macho('/Volumes/private/new.dylib'))
        for effect, error in ((subprocess.CalledProcessError(1, ['clang']), subprocess.CalledProcessError), (invalid, RuntimeError)):
            with self.subTest(error=error), patch.object(host_color.subprocess, 'run', side_effect=effect):
                with self.assertRaises(error):
                    host_color.build(self.root)
            self.assertEqual((self.library.read_bytes(), self.receipt.read_bytes()), previous)
            self.assertEqual(set(self.tools.iterdir()), {self.library, self.receipt})

    def test_symlink_attachment_is_refused_without_building(self):
        self.seed(macho())
        for path in (self.library, self.receipt):
            data = path.read_bytes()
            path.unlink()
            target = self.root / 'foreign'
            target.write_bytes(data)
            path.symlink_to(target)
            with patch.object(host_color.subprocess, 'run') as compiler:
                with self.assertRaisesRegex(RuntimeError, 'symlink'):
                    host_color.build(self.root)
            compiler.assert_not_called()
            self.assertEqual(target.read_bytes(), data)
            path.unlink()
            path.write_bytes(data)

    def test_invalid_macho_identity_and_bounds_fail_closed(self):
        misaligned = bytearray(macho())
        struct.pack_into('<I', misaligned, 36, 9)
        wrong_offset = bytearray(macho())
        struct.pack_into('<I', wrong_offset, 40, 20)
        wrong_arch = bytearray(macho())
        struct.pack_into('<I', wrong_arch, 4, 16777223)
        unterminated = struct.pack('<IIIIIIII', 4277009103, 16777228, 0, 6, 1, 48, 0, 0)
        unterminated += struct.pack('<IIIIII', 13, 48, 24, 0, 0, 0) + b'x' * 24
        for data in (b'not a dylib', macho()[:40], macho(duplicate=True), macho('emulator_srgb.dylib'), bytes(misaligned), bytes(wrong_offset), bytes(wrong_arch), unterminated, macho(trailer=b'/home/private/source.m\x00')):
            with self.subTest(size=len(data)), self.assertRaises(RuntimeError):
                host_color.validate_library(data)

class HostColorEnvironmentTests(unittest.TestCase):

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / 'local').mkdir()
        self.library = self.root / 'tools/emulator_srgb.dylib'
        self.cached = self.root / 'owned-user-state/emulator_srgb.dylib'
        inherited = {'DYLD_INSERT_LIBRARIES': '/existing/plugin.dylib', 'HYPEROS_AVD_SRGB': '1', 'HYPEROS_AVD_SRGB_AVD': 'Old_AVD', 'UNRELATED_OPTION': 'kept'}
        environment = patch.dict(os.environ, inherited, clear=True)
        environment.start()
        self.addCleanup(environment.stop)

    def manifest(self, source):
        (self.root / 'local/build.json').write_text(json.dumps({'source': source}))

    def test_owned_phone_and_pad_use_current_name_without_global_changes(self):
        for source, name in (('official-hongkong-ota', 'Renamed_Phone_API_99'), ('official-yingtian-ota', 'Renamed_Pad_API_99')):
            with self.subTest(source=source):
                self.manifest(source)
                before = dict(os.environ)
                with patch.object(host_color, 'build', return_value=(self.library, None)) as build, patch.object(host_color, 'cached_library', return_value=self.cached) as cache:
                    result = host_color.environment(self.root, name)
                build.assert_called_once_with(self.root)
                self.assertEqual(result['HYPEROS_AVD_SRGB'], '1')
                self.assertEqual(result['HYPEROS_AVD_SRGB_AVD'], name)
                self.assertEqual(result['DYLD_INSERT_LIBRARIES'], str(self.cached.resolve()) + ':/existing/plugin.dylib')
                cache.assert_called_once_with(self.library, None)
                self.assertEqual(result['UNRELATED_OPTION'], 'kept')
                self.assertEqual(dict(os.environ), before)

    def test_default_scope_requires_an_owned_source_manifest(self):
        for source in (None, 'google-apis', 'official-unverified-ota'):
            with self.subTest(source=source):
                if source is None:
                    (self.root / 'local/build.json').unlink(missing_ok=True)
                else:
                    self.manifest(source)
                with patch.object(host_color, 'build') as build:
                    result = host_color.environment(self.root, 'Pixel_9')
                build.assert_not_called()
                self.assertNotIn('HYPEROS_AVD_SRGB', result)
                self.assertNotIn('HYPEROS_AVD_SRGB_AVD', result)
                self.assertEqual(result['DYLD_INSERT_LIBRARIES'], '/existing/plugin.dylib')

    def test_opt_out_clears_inherited_authorization_without_building(self):
        self.manifest('official-yingtian-ota')
        with patch.object(host_color, 'build') as build:
            result = host_color.environment(self.root, 'Owned_Pad', enabled=False)
        build.assert_not_called()
        self.assertNotIn('HYPEROS_AVD_SRGB', result)
        self.assertNotIn('HYPEROS_AVD_SRGB_AVD', result)
        self.assertEqual(result['DYLD_INSERT_LIBRARIES'], '/existing/plugin.dylib')
        self.assertEqual(os.environ['HYPEROS_AVD_SRGB_AVD'], 'Old_AVD')

    def test_owned_launch_requires_a_nonempty_name(self):
        self.manifest('official-yingtian-ota')
        with patch.object(host_color, 'build') as build:
            for name in ('', None):
                with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, 'AVD name'):
                    host_color.environment(self.root, name)
        build.assert_not_called()

    def test_only_owned_dyld_entries_are_relocated_without_copying_foreign_plugins(self):
        self.manifest('official-yingtian-ota')
        os.environ['DYLD_INSERT_LIBRARIES'] = ':'.join(('/foreign/first.dylib', str(self.library.resolve()), '/foreign/second.dylib', str(self.cached.resolve())))
        with patch.object(host_color, 'build', return_value=(self.library, None)), patch.object(host_color, 'cached_library', return_value=self.cached) as cache:
            result = host_color.environment(self.root, 'Owned_Pad')
        self.assertEqual(result['DYLD_INSERT_LIBRARIES'], ':'.join((str(self.cached.resolve()), '/foreign/first.dylib', '/foreign/second.dylib')))
        cache.assert_called_once_with(self.library, None)

class InternalHostColorCacheTests(unittest.TestCase):

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.library = self.root / host_color.LIBRARY
        self.receipt = self.root / host_color.RECEIPT
        self.data = macho()
        self.metadata = {'source_sha256': hashlib.sha256((REPO / 'native/emulator_srgb.m').read_bytes()).hexdigest(), 'sha256': hashlib.sha256(self.data).hexdigest(), 'install_name': host_color.INSTALL_NAME}
        self.library.write_bytes(self.data)
        self.receipt.write_text(json.dumps(self.metadata))
        self.state = self.root / 'owned-user-state'
        self.state.mkdir()
        directory = patch('host_launch.job_directory', return_value=self.state / 'launchd')
        directory.start()
        self.addCleanup(directory.stop)

    def cache(self):
        return host_color.cached_library(self.library, self.receipt)

    def test_verified_hook_is_cached_privately_by_content_and_reused_without_compilation(self):
        with patch.object(host_color.subprocess, 'run') as compile:
            cached = self.cache()
            inode = cached.stat().st_ino
            modified = cached.stat().st_mtime_ns
            self.assertEqual(self.cache(), cached)
        compile.assert_not_called()
        self.assertEqual(cached, self.state / 'host-color' / self.metadata['sha256'] / host_color.LIBRARY)
        self.assertEqual(cached.read_bytes(), self.data)
        self.assertEqual(cached.stat().st_ino, inode)
        self.assertEqual(cached.stat().st_mtime_ns, modified)
        self.assertEqual(cached.stat().st_mode & 511, 384)
        self.assertEqual(cached.parent.stat().st_mode & 511, 448)
        self.assertEqual(json.loads(cached.with_name(host_color.RECEIPT).read_text()), self.metadata)

    def test_source_receipt_mismatch_does_not_create_cache(self):
        self.receipt.write_text(json.dumps(dict(self.metadata, source_sha256='0' * 64)))
        with self.assertRaisesRegex(RuntimeError, 'Unverified'):
            self.cache()
        self.assertFalse((self.state / 'host-color').exists())

    def test_modified_cached_hook_is_preserved_with_diagnostic(self):
        cached = self.cache()
        cached.write_bytes(b'unknown user content')
        with self.assertRaisesRegex(RuntimeError, 'modified.*preserved'):
            self.cache()
        self.assertEqual(cached.read_bytes(), b'unknown user content')

    def test_modified_cached_receipt_is_preserved_with_diagnostic(self):
        cached = self.cache()
        receipt = cached.with_name(host_color.RECEIPT)
        receipt.write_bytes(b'unknown user receipt')
        with self.assertRaisesRegex(RuntimeError, 'modified.*preserved'):
            self.cache()
        self.assertEqual(receipt.read_bytes(), b'unknown user receipt')
        self.assertEqual(cached.read_bytes(), self.data)

    def test_foreign_cache_alias_is_preserved_without_following_or_rewriting(self):
        cached = self.cache()
        cached.unlink()
        foreign = self.root / 'foreign'
        foreign.write_bytes(b'foreign library')
        foreign.chmod(384)
        cached.symlink_to(foreign)
        with self.assertRaisesRegex(RuntimeError, 'aliased'):
            self.cache()
        self.assertEqual(foreign.read_bytes(), b'foreign library')
        self.assertTrue(cached.is_symlink())

@unittest.skipUnless(sys.platform == 'darwin' and platform.machine() == 'arm64' and shutil.which('xcrun'), 'Native host guard needs macOS ARM64 CLT')
class NativeHostColorGuardTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.root = Path(temporary.name)
        cls.library, _ = host_color.build(cls.root)
        main = cls.root / 'probe.c'
        main.write_text('int main(void) { return 0; }\n')
        cls.probe = cls.root / 'probe'
        subprocess.run(['xcrun', 'clang', '-Wall', '-Wextra', '-Werror', '-arch', 'arm64', '-mmacosx-version-min=12.0', str(main), '-o', str(cls.probe)], check=True, capture_output=True)

    def test_actual_macho_otool_identity_is_portable(self):
        name = subprocess.check_output(['otool', '-D', str(self.library)], text=True).splitlines()[1:]
        self.assertEqual([line.strip() for line in name], [host_color.INSTALL_NAME])
        self.assertEqual(host_color.validate_library(self.library.read_bytes()), host_color.INSTALL_NAME)
        metadata = json.loads((self.root / 'tools' / host_color.RECEIPT).read_text())
        self.assertEqual(metadata['install_name'], host_color.INSTALL_NAME)
        self.assertEqual(metadata['sha256'], hashlib.sha256(self.library.read_bytes()).hexdigest())

    def run_probe(self, arguments, enabled='1', expected='Renamed_Pad_API_99'):
        environment = os.environ.copy()
        environment.pop('HYPEROS_AVD_SRGB', None)
        environment.pop('HYPEROS_AVD_SRGB_AVD', None)
        environment['DYLD_INSERT_LIBRARIES'] = str(self.library)
        if enabled is not None:
            environment['HYPEROS_AVD_SRGB'] = enabled
        if expected is not None:
            environment['HYPEROS_AVD_SRGB_AVD'] = expected
        result = subprocess.run([str(self.probe), *arguments], env=environment, text=True, capture_output=True, check=True)
        return result.stderr

    def test_compiled_hook_accepts_the_matching_renamed_instance(self):
        output = self.run_probe(['-avd', 'Renamed_Pad_API_99'])
        self.assertIn('sRGB tagging enabled for the owned OS4 AVD Renamed_Pad_API_99', output)

    def test_compiled_hook_rejects_optout_missing_name_and_other_instances(self):
        cases = ((['-avd', 'Pixel_9'], '1', 'Renamed_Pad_API_99'), (['-avd', 'Renamed_Pad_API_99'], '0', 'Renamed_Pad_API_99'), (['-avd', 'Renamed_Pad_API_99'], None, 'Renamed_Pad_API_99'), (['-avd', 'HyperOS_4_Official_API_37'], '1', None), (['-avd', 'HyperOS_4_Pad9ProMax_API_37'], '1', ''), ([], '1', 'Renamed_Pad_API_99'), (['-avd'], '1', 'Renamed_Pad_API_99'))
        for arguments, enabled, expected in cases:
            with self.subTest(arguments=arguments, enabled=enabled, expected=expected):
                self.assertNotIn('sRGB tagging enabled', self.run_probe(arguments, enabled, expected))

if __name__ == '__main__':
    unittest.main()


# --- tests/test_host_adb.py ---

'Exercise the internal SDK ADB no-op without an Android device or SDK mutation.'

class HostAdbTests(unittest.TestCase):

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.sdk = self.root / "SDK 'with space'"
        self.original = self.sdk / 'platform-tools/adb'
        self.original.parent.mkdir(parents=True)
        self.calls = self.root / 'calls.jsonl'
        self.serial = 'emulator-5588'
        self.state = self.root / 'private/launchd'
        self.state.mkdir(parents=True, mode=448)
        self.original.write_text('#!' + str(Path(sys.executable).resolve()) + '\nimport json, os, pathlib, sys\nwith pathlib.Path(' + repr(str(self.calls)) + ').open("a") as log:\n log.write(json.dumps(sys.argv[1:]) + "\\n")\nif len(sys.argv) == 8 and sys.argv[5] == "get":\n print(os.environ.get("FAKE_ADB_SETTING", "2147483647"))\n raise SystemExit(int(os.environ.get("FAKE_QUERY_EXIT", "0")))\nprint("original output")\nprint("original error", file=sys.stderr)\nraise SystemExit(int(os.environ.get("FAKE_FORWARD_EXIT", "0")))\n')
        self.original.chmod(493)
        self.addCleanup(patch.stopall)
        patch.object(host_adb, 'job_directory', return_value=self.state).start()
        patch.object(host_adb, '_publish_directory', side_effect=lambda source, destination: os.rename(source, destination)).start()

    def executable(self):
        return host_adb.adapter(self.sdk, self.serial)

    def command(self, serial=None, value='2147483647'):
        return ['-s', serial or self.serial, 'shell', 'settings', 'put', 'system', 'screen_off_timeout', value]

    def run_adapter(self, arguments, **environment):
        return subprocess.run([str(self.executable()), *arguments], env=dict(os.environ, **environment), capture_output=True, text=True, timeout=10)

    def requests(self):
        return [json.loads(line) for line in self.calls.read_text().splitlines()] if self.calls.exists() else []

    def test_exact_same_setting_is_a_real_idempotent_no_op_without_put_or_extra_grants(self):
        result = self.run_adapter(self.command(), FAKE_FORWARD_EXIT='23')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, '')
        self.assertEqual(self.requests(), [['-s', self.serial, 'shell', 'settings', 'get', 'system', 'screen_off_timeout']])

    def test_different_value_and_failed_query_transparently_forward_all_output_and_error(self):
        for options in ({'FAKE_ADB_SETTING': '60000'}, {'FAKE_QUERY_EXIT': '4'}):
            with self.subTest(options=options):
                self.calls.unlink(missing_ok=True)
                result = self.run_adapter(self.command(), FAKE_FORWARD_EXIT='23', **options)
                self.assertEqual(result.returncode, 23)
                self.assertEqual(result.stdout, 'original output\n')
                self.assertEqual(result.stderr, 'original error\n')
                self.assertEqual(self.requests()[-1], self.command())
                self.assertEqual(len(self.requests()), 2)

    def test_other_device_global_options_combined_shell_and_dynamic_values_are_exact_passthrough(self):
        variants = [self.command(serial='emulator-5590'), ['version'], ['-P', '5039', *self.command()], ['-e', *self.command()[2:]], ['-s', self.serial, 'shell', 'settings put system screen_off_timeout 2147483647'], self.command(value='2147483647; echo private'), self.command(value='$VALUE'), self.command(value='01'), self.command() + ['extra'], ['-s', self.serial, 'shell', 'settings', 'put', 'secure', 'sleep_timeout', '-1']]
        for arguments in variants:
            with self.subTest(arguments=arguments):
                self.calls.unlink(missing_ok=True)
                result = self.run_adapter(arguments, FAKE_FORWARD_EXIT='17')
                self.assertEqual(result.returncode, 17)
                self.assertEqual(self.requests(), [arguments])
                self.assertEqual(result.stdout, 'original output\n')
                self.assertEqual(result.stderr, 'original error\n')

    def test_wrapper_quoting_and_cache_reuse_preserve_sdk_and_do_not_persist_secrets(self):
        original = (self.original.read_bytes(), self.original.stat().st_ino)
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'private-token', 'GITHUB_TOKEN': 'private-key'}):
            executable = self.executable()
            entries = {path: (path.read_bytes(), path.stat().st_ino) for path in executable.parent.iterdir()}
            self.assertEqual(self.executable(), executable)
        self.assertEqual(original, (self.original.read_bytes(), self.original.stat().st_ino))
        self.assertEqual(entries, {path: (path.read_bytes(), path.stat().st_ino) for path in entries})
        for path, (data, _) in entries.items():
            self.assertNotIn(b'private-token', data)
            self.assertNotIn(b'private-key', data)
            self.assertEqual(path.stat().st_mode & 511, 448 if path.name == 'adb' else 384)
        self.assertEqual(executable.parent.stat().st_mode & 511, 448)
        self.assertEqual(self.run_adapter(['version']).returncode, 0)

    def test_valid_sdk_path_with_recipe_like_text_is_not_interpolated_again(self):
        changed = self.root / "__DIGEST__ __SERIAL__ __MAX_ADB__ SDK '{literal}'"
        self.sdk.rename(changed)
        self.sdk = changed
        self.original = changed / 'platform-tools/adb'
        result = self.run_adapter(['version'])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.requests(), [['version']])

    def test_modified_extra_or_aliased_cache_resources_are_preserved(self):
        executable = self.executable()
        runner = executable.parent / 'runner.py'
        original = runner.read_bytes()
        runner.write_bytes(b'custom code')
        with self.assertRaisesRegex(RuntimeError, 'Modified SDK ADB'):
            self.executable()
        self.assertEqual(runner.read_bytes(), b'custom code')
        runner.write_bytes(original)
        extra = executable.parent / 'extra'
        extra.write_text('user content')
        with self.assertRaisesRegex(RuntimeError, 'Unknown SDK ADB'):
            self.executable()
        self.assertEqual(extra.read_text(), 'user content')
        extra.unlink()
        target = self.root / 'foreign-runner'
        runner.rename(target)
        runner.symlink_to(target)
        with self.assertRaisesRegex(RuntimeError, 'aliased'):
            self.executable()
        self.assertEqual(target.read_bytes(), original)

    def test_runtime_sdk_change_is_diagnosed_and_a_new_preparation_does_not_rewrite_old_cache(self):
        executable = self.executable()
        old = (executable.read_bytes(), (executable.parent / 'receipt.json').read_bytes())
        self.original.write_text(self.original.read_text() + '# official SDK update\n')
        result = subprocess.run([str(executable), 'version'], capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('original SDK ADB changed', result.stderr)
        self.assertEqual(self.requests(), [])
        updated = self.executable()
        self.assertNotEqual(updated, executable)
        self.assertEqual(old, (executable.read_bytes(), (executable.parent / 'receipt.json').read_bytes()))

    def test_recursive_sdk_adapter_and_invalid_or_writable_source_are_refused(self):
        for serial in ('-e', 'emulator-1; unsafe', 'device other'):
            with self.subTest(serial=serial), self.assertRaisesRegex(RuntimeError, 'identity'):
                host_adb.adapter(self.sdk, serial)
        executable = self.executable()
        self.original.unlink()
        self.original.symlink_to(executable)
        with self.assertRaisesRegex(RuntimeError, 'recursive'):
            self.executable()
        self.original.unlink()
        self.original.write_text('writable SDK input')
        self.original.chmod(511)
        with self.assertRaisesRegex(RuntimeError, 'unsafe'):
            self.executable()

    def test_failed_private_publication_leaves_no_partial_adapter_and_next_try_recovers(self):
        real = host_adb.write_private

        def fail(path, content):
            if path.name == 'receipt.json':
                raise OSError('ENOSPC')
            return real(path, content)
        with patch.object(host_adb, 'write_private', side_effect=fail), self.assertRaisesRegex(OSError, 'ENOSPC'):
            self.executable()
        self.assertEqual(list((self.state.parent / 'host-adb').iterdir()), [])
        self.assertTrue(self.executable().is_file())

    def test_query_timeout_still_executes_original_command(self):
        executable = self.executable()
        source = (executable.parent / 'runner.py').read_text()
        with patch.object(sys, 'argv', [str(executable), *self.command()]), patch.object(subprocess, 'run', side_effect=subprocess.TimeoutExpired(['adb'], 5)), patch.object(os, 'execv') as forwarded:
            exec(compile(source, str(executable), 'exec'), {})
        forwarded.assert_called_once_with(str(self.original), [str(self.original), *self.command()])

@unittest.skipUnless(sys.platform == 'darwin', 'Native exclusive rename is a macOS API.')
class NativePublicationTests(unittest.TestCase):

    def test_exclusive_directory_publication_preserves_even_an_empty_racing_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            staged, destination = (root / 'staged', root / 'destination')
            staged.mkdir()
            destination.mkdir()
            with self.assertRaises(FileExistsError):
                host_adb._publish_directory(staged, destination)
            self.assertTrue(staged.is_dir())
            self.assertEqual(list(destination.iterdir()), [])
            destination.rmdir()
            host_adb._publish_directory(staged, destination)
            self.assertFalse(staged.exists())
            self.assertTrue(destination.is_dir())

if __name__ == '__main__':
    unittest.main()


# --- tests/test_https_transport.py ---

'Exercise verified macOS TLS fallback and installer streaming contracts.'

def certificate_error():
    return urllib.error.URLError(ssl.SSLCertVerificationError(1, 'certificate verify failed'))

class Process:

    def __init__(self, data, code=0):
        self.stdout = io.BytesIO(data)
        self.returncode = None
        self.code = code
        self.terminated = False
        self.killed = False

    def wait(self, timeout):
        self.returncode = self.code
        return self.code

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True

def reply(body=b'payload', status=200, headers=b'', code=0):
    return Process(b'HTTP/2 ' + str(status).encode() + b'\r\n' + headers + b'\r\n' + body, code)

class TransportTests(unittest.TestCase):

    def fallback(self, process):
        real_isfile = transport._tls_os.path.isfile
        return (patch.object(transport._tls_request, 'urlopen', side_effect=certificate_error()), patch.object(transport._tls_platform, 'system', return_value='Darwin'), patch.object(transport._tls_os.path, 'isfile', side_effect=lambda path: True if path == '/usr/bin/curl' else real_isfile(path)), patch.object(transport._tls_subprocess, 'Popen', return_value=process), patch.dict(transport._tls_os.environ, {}, clear=True), patch.object(transport._tls_request, 'getproxies', return_value={}), patch.object(transport._tls_request, 'proxy_bypass', return_value=False))

    def run_fallback(self, process, callback):
        from contextlib import ExitStack
        with ExitStack() as stack:
            mocks = [stack.enter_context(item) for item in self.fallback(process)]
            return callback(mocks)

    def test_default_python_transport_is_retained(self):
        expected = object()
        with patch.object(transport._tls_request, 'urlopen', return_value=expected) as opened, patch.object(transport._tls_subprocess, 'Popen') as native:
            self.assertIs(transport.secure_urlopen('https://example.test/', timeout=60), expected)
        opened.assert_called_once_with('https://example.test/', timeout=60)
        native.assert_not_called()

    def test_only_macos_https_certificate_failure_can_fallback(self):
        failures = [urllib.error.URLError('DNS failure'), TimeoutError('timeout'), ssl.SSLError('handshake failure'), urllib.error.HTTPError('https://example.test/', 403, 'Forbidden', {}, None)]
        for error in failures:
            with self.subTest(error=type(error).__name__), patch.object(transport._tls_request, 'urlopen', side_effect=error), patch.object(transport._tls_platform, 'system', return_value='Darwin'), patch.object(transport._tls_subprocess, 'Popen') as native:
                with self.assertRaises(type(error)):
                    transport.secure_urlopen('https://example.test/')
                native.assert_not_called()
                if hasattr(error, 'close'):
                    error.close()
        for platform, url in [('Linux', 'https://example.test/'), ('Darwin', 'http://example.test/'), ('Darwin', 'file:///tmp/fixture')]:
            with self.subTest(platform=platform, url=url), patch.object(transport._tls_request, 'urlopen', side_effect=certificate_error()), patch.object(transport._tls_platform, 'system', return_value=platform), patch.object(transport._tls_subprocess, 'Popen') as native:
                with self.assertRaises(urllib.error.URLError):
                    transport.secure_urlopen(url)
                native.assert_not_called()

    def test_final_headers_skip_proxy_redirect_and_information_blocks(self):
        process = Process(b'HTTP/1.1 200 Connection established\r\n\r\nHTTP/2 302\r\nLocation: https://cdn.example.test/archive\r\n\r\nHTTP/2 103\r\nLink: fixture\r\n\r\nHTTP/2 206\r\nContent-Range: bytes 2-6/7\r\n\r\nyload')
        request = urllib.request.Request('https://example.test/archive', headers={'User-Agent': 'HyperOS-test', 'Accept': 'application/json', 'Range': 'bytes=2-'})

        def check(mocks):
            with transport.secure_urlopen(request, timeout=60) as response:
                self.assertEqual(response.getcode(), 206)
                self.assertEqual(response.headers['Content-Range'], 'bytes 2-6/7')
                self.assertEqual(response.read(128 * 1024), b'yload')
            args = mocks[3].call_args.args[0]
            self.assertEqual(args[0], '/usr/bin/curl')
            self.assertEqual(args[1], '--disable')
            self.assertNotIn('--insecure', args)
            self.assertNotIn('-k', args)
            self.assertIn('--globoff', args)
            self.assertEqual(args[args.index('--proto') + 1], '=https')
            self.assertEqual(args[args.index('--proto-redir') + 1], '=https')
            self.assertNotIn('--max-time', args)
            for header in ('User-agent: HyperOS-test', 'Accept: application/json', 'Range: bytes=2-'):
                self.assertIn(header, args)
        self.run_fallback(process, check)

    def test_explicit_ca_file_and_proxy_are_preserved_without_error_disclosure(self):
        process = reply()

        def check(mocks):
            with patch.dict(transport._tls_os.environ, {'SSL_CERT_FILE': '/trusted/custom.pem'}), patch.object(transport._tls_request, 'getproxies', return_value={'https': 'http://user:secret@proxy.test:8080'}):
                with transport.secure_urlopen('https://example.test/') as response:
                    self.assertEqual(response.read(1024), b'payload')
            args = mocks[3].call_args.args[0]
            self.assertEqual(args[args.index('--cacert') + 1], '/trusted/custom.pem')
            self.assertEqual(args[args.index('--proxy') + 1], 'http://user:secret@proxy.test:8080')
        self.run_fallback(process, check)

    def test_explicit_ca_directory_refuses_native_fallback(self):
        with patch.object(transport._tls_request, 'urlopen', side_effect=certificate_error()), patch.object(transport._tls_platform, 'system', return_value='Darwin'), patch.dict(transport._tls_os.environ, {'SSL_CERT_DIR': '/custom/anchors'}), patch.object(transport._tls_subprocess, 'Popen') as native:
            with self.assertRaisesRegex(urllib.error.URLError, 'explicit SSL_CERT_DIR'):
                transport.secure_urlopen('https://example.test/')
            native.assert_not_called()

    def test_proxy_exclusions_remain_complete_across_cdn_redirect(self):
        process = Process(b'HTTP/2 302\r\nLocation: https://release-assets.githubusercontent.com/file\r\n\r\nHTTP/2 200\r\n\r\npayload')
        excluded = 'github.com,release-assets.githubusercontent.com'

        def check(mocks):
            with patch.object(transport._tls_request, 'getproxies', return_value={'https': 'http://proxy.test:8080', 'no': excluded}), patch.object(transport._tls_request, 'proxy_bypass', return_value=True):
                with transport.secure_urlopen('https://github.com/file') as response:
                    self.assertEqual(response.read(1024), b'payload')
            args = mocks[3].call_args.args[0]
            self.assertEqual(args[args.index('--noproxy') + 1], excluded)
        self.run_fallback(process, check)

    def test_macos_system_proxy_bypass_receives_request_port(self):

        def check(mocks):
            with patch.object(transport._tls_request, 'proxy_bypass', return_value=True) as bypass:
                with transport.secure_urlopen('https://example.test:8443/') as response:
                    response.read(1024)
                bypass.assert_called_once_with('example.test:8443')
            args = mocks[3].call_args.args[0]
            self.assertEqual(args[args.index('--noproxy') + 1], 'example.test')
        self.run_fallback(reply(), check)

    def test_direct_setup_bounds_remote_manifest_before_parsing(self):
        response = io.BytesIO(b' ' * (2 * 1024 ** 2 + 1))
        with patch.object(setup, 'secure_urlopen', return_value=response), patch.object(setup.json, 'loads') as decoded:
            with self.assertRaisesRegex(RuntimeError, 'Oversized remote release manifest'):
                setup.read_manifest('https://example.test/manifest.json')
            decoded.assert_not_called()

    def test_real_untrusted_peer_and_http_errors_are_not_accepted(self):
        for process in [Process(b'', 60), reply(status=403), reply(status=302)]:

            def check(_):
                with self.assertRaises(urllib.error.URLError) as caught:
                    transport.secure_urlopen('https://example.test/')
                self.assertNotIn('secret', str(caught.exception))
                self.assertTrue(process.stdout.closed)
            self.run_fallback(process, check)

    def test_truncated_transfer_and_early_close_wait_for_owned_process(self):
        process = reply(b'partial', code=18)

        def broken(_):
            with self.assertRaisesRegex(urllib.error.URLError, 'curl exit 18'):
                with transport.secure_urlopen('https://example.test/') as response:
                    response.read(128 * 1024)
            self.assertTrue(process.stdout.closed)
        self.run_fallback(process, broken)
        process = reply(b'large body not consumed')

        def prefix(_):
            with transport.secure_urlopen('https://example.test/') as response:
                self.assertEqual(response.read(5), b'large')
            self.assertTrue(process.terminated)
            self.assertIsNotNone(process.returncode)
            self.assertTrue(process.stdout.closed)
        self.run_fallback(process, prefix)

    def test_timeout_reaps_owned_process_and_redacts_command_credentials(self):

        class StalledProcess(Process):
            waits = 0

            def wait(self, timeout):
                self.waits += 1
                if self.waits <= 2:
                    raise subprocess.TimeoutExpired(['curl', '--proxy', 'http://user:secret@proxy.test'], timeout)
                return super().wait(timeout)
        process = StalledProcess(b'HTTP/2 200\r\n\r\nshort')

        def check(_):
            with self.assertRaisesRegex(urllib.error.URLError, 'transfer timed out') as caught:
                with transport.secure_urlopen('https://example.test/') as response:
                    response.read(1024)
            self.assertNotIn('secret', str(caught.exception))
            self.assertTrue(caught.exception.__suppress_context__)
            self.assertTrue(process.terminated)
            self.assertTrue(process.killed)
            self.assertIsNotNone(process.returncode)
            self.assertTrue(process.stdout.closed)
        self.run_fallback(process, check)

    def test_urlretrieve_fallback_streams_file_and_verifies_process_success(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'part'
            process = reply(b'payload')

            def check(_):
                with patch.object(transport._tls_request, 'urlretrieve', side_effect=certificate_error()):
                    returned, _ = transport.secure_urlretrieve('https://example.test/file', target)
                self.assertEqual(returned, str(target))
                self.assertEqual(target.read_bytes(), b'payload')
                self.assertEqual(process.returncode, 0)
            self.run_fallback(process, check)

    def test_bootstrap_embeds_identical_transport_before_installer_download(self):
        source = (ROOT / 'install.sh').read_text()
        embedded = source.split('# BEGIN EMBEDDED VERIFIED HTTPS TRANSPORT\n', 1)[1].split('# END EMBEDDED VERIFIED HTTPS TRANSPORT\n', 1)[0]
        self.assertEqual(embedded, (ROOT / 'scripts/https_transport.py').read_text())
        bootstrap = types.ModuleType('standalone_bootstrap')
        code = source.split("<<'PY'\n", 1)[1].rsplit('\nPY\n', 1)[0]
        exec(compile(code, str(ROOT / 'install.sh'), 'exec'), bootstrap.__dict__)

        def check(_):
            self.assertEqual(bootstrap.remote_json('https://example.test/releases'), [{'tag_name': 'installer-v1.2.1'}])
        self.run_fallback(reply(json.dumps([{'tag_name': 'installer-v1.2.1'}]).encode()), check)
        self.assertIn('scripts/https_transport.py', package_release.runtime_files())

    def test_installer_pins_helper_and_imports_it_from_packaged_scripts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            metadata = package_installer.package(root / 'release')
            helper = 'scripts/https_transport.py'
            with zipfile.ZipFile(root / 'release' / metadata['archive']['name']) as archive:
                data = archive.read('HyperOS-AVD/' + helper)
                self.assertEqual(hashlib.sha256(data).hexdigest(), metadata['files'][helper]['sha256'])
                archive.extractall(root / 'Package with spaces')
            unrelated = root / 'unrelated cwd'
            unrelated.mkdir()
            marker = unrelated / 'wrong-import'
            (unrelated / 'https_transport.py').write_text('from pathlib import Path\n' + 'Path(' + repr(str(marker)) + ').touch()\nraise RuntimeError("Wrong helper")\n')
            result = subprocess.run([sys.executable, str(root / 'Package with spaces/HyperOS-AVD/scripts/manage.py'), '--help'], cwd=unrelated, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(marker.exists())

    def test_manager_api_and_independent_checksum_share_tls_fallback(self):
        self.run_fallback(reply(b'[{"tag_name":"fixture"}]'), lambda _: self.assertEqual(manage.remote_json('https://example.test/releases'), [{'tag_name': 'fixture'}]))
        checksum = hashlib.sha256(b'manifest').hexdigest()
        release = {'tag_name': 'v0.2.3-a17-hyperos4-hongkong-r4', 'asset_map': {'manifest.json': {'browser_download_url': 'https://example.test/manifest.json', 'size': 8}, 'SHA256SUMS': {'browser_download_url': 'https://example.test/SHA256SUMS'}}}
        with tempfile.TemporaryDirectory() as directory:

            def check(mocks):
                manifest = {'version': release['tag_name'], 'parts': []}
                with patch.object(manage, 'download', return_value=Path(directory) / 'manifest.json') as download, patch.object(manage.setup, 'read_install_manifest', return_value=(manifest, Path(directory))) as reader:
                    manage.fetch_release(release, directory)
                reader.assert_called_once_with(str(Path(directory) / 'manifest.json'))
                self.assertEqual(download.call_args.args[3], checksum)
                args = mocks[3].call_args.args[0]
                self.assertEqual(args[args.index('--url') + 1], 'https://example.test/SHA256SUMS')
                self.assertIn('User-agent: HyperOS-AVD/' + manage.VERSION, args)
            self.run_fallback(reply((checksum + '  manifest.json\n').encode()), check)

    def test_installer_resumes_206_and_restarts_when_range_ignored(self):
        for status, headers, payload in [(206, b'Content-Range: bytes 2-6/7\r\n', b'yload'), (200, b'', b'payload')]:
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                target = Path(directory) / 'asset'
                target.with_name('asset.partial').write_bytes(b'pa')

                def check(mocks):
                    manage.download('https://example.test/asset', target, 7, hashlib.sha256(b'payload').hexdigest())
                    self.assertEqual(target.read_bytes(), b'payload')
                    self.assertFalse(target.with_name('asset.partial').exists())
                    self.assertIn('Range: bytes=2-', mocks[3].call_args.args[0])
                self.run_fallback(reply(payload, status, headers), check)

    def test_invalid_range_and_broken_tls_stream_never_replace_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'asset'
            target.write_bytes(b'old cache')
            partial = target.with_name('asset.partial')
            partial.write_bytes(b'pa')

            def invalid(_):
                with self.assertRaisesRegex(RuntimeError, 'partial download response'):
                    manage.download('https://example.test/asset', target, 7, hashlib.sha256(b'payload').hexdigest())
            self.run_fallback(reply(b'payload', 206, b'Content-Range: bytes 1-6/7\r\n'), invalid)
            self.assertEqual(partial.read_bytes(), b'pa')
            self.assertEqual(target.read_bytes(), b'old cache')
            processes = [reply(b'partial', 200, code=18) for _ in range(3)]

            def broken(mocks):
                mocks[3].side_effect = processes
                with self.assertRaises(urllib.error.URLError):
                    manage.download('https://example.test/asset', target, 7, hashlib.sha256(b'payload').hexdigest())
            self.run_fallback(processes[0], broken)
            self.assertEqual(target.read_bytes(), b'old cache')

if __name__ == '__main__':
    unittest.main()
