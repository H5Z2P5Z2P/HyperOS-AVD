"""Exercise owned-launch authorization and the compiled native AVD guard."""
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'scripts'))
import host_color


def macho(name=host_color.INSTALL_NAME, duplicate=False, trailer=b''):
    value = name.encode() + b'\0'
    length = (24 + len(value) + 7) & ~7
    command = struct.pack('<IIIIII', 0xd, length, 24, 0, 0, 0)
    command += value + bytes(length - 24 - len(value))
    commands = command * (2 if duplicate else 1)
    header = struct.pack('<IIIIIIII', 0xfeedfacf, 0x100000c, 0, 6,
                         2 if duplicate else 1, len(commands), 0, 0)
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
        self.assertEqual(metadata, {'source_sha256': self.source_hash,
            'sha256': hashlib.sha256(macho()).hexdigest(), 'install_name': host_color.INSTALL_NAME})
        self.assertEqual(set(self.tools.iterdir()), {self.library, self.receipt})

    def test_failed_compiler_or_invalid_output_preserves_both_old_files(self):
        self.seed(macho('/Volumes/private/build/old.dylib'), portable=False)
        previous = self.library.read_bytes(), self.receipt.read_bytes()
        def invalid(arguments, **kwargs):
            Path(arguments[arguments.index('-o') + 1]).write_bytes(macho('/Volumes/private/new.dylib'))
        for effect, error in ((subprocess.CalledProcessError(1, ['clang']), subprocess.CalledProcessError),
                               (invalid, RuntimeError)):
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
        struct.pack_into('<I', wrong_arch, 4, 0x1000007)
        unterminated = struct.pack('<IIIIIIII', 0xfeedfacf, 0x100000c, 0, 6, 1, 48, 0, 0)
        unterminated += struct.pack('<IIIIII', 0xd, 48, 24, 0, 0, 0) + b'x' * 24
        for data in (b'not a dylib', macho()[:40], macho(duplicate=True),
                     macho('emulator_srgb.dylib'), bytes(misaligned), bytes(wrong_offset),
                     bytes(wrong_arch), unterminated, macho(trailer=b'/home/private/source.m\0')):
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
        inherited = {'DYLD_INSERT_LIBRARIES': '/existing/plugin.dylib',
                     'HYPEROS_AVD_SRGB': '1', 'HYPEROS_AVD_SRGB_AVD': 'Old_AVD',
                     'UNRELATED_OPTION': 'kept'}
        environment = patch.dict(os.environ, inherited, clear=True)
        environment.start()
        self.addCleanup(environment.stop)

    def manifest(self, source):
        (self.root / 'local/build.json').write_text(json.dumps({'source': source}))

    def test_owned_phone_and_pad_use_current_name_without_global_changes(self):
        for source, name in (('official-hongkong-ota', 'Renamed_Phone_API_99'),
                             ('official-yingtian-ota', 'Renamed_Pad_API_99')):
            with self.subTest(source=source):
                self.manifest(source)
                before = dict(os.environ)
                with patch.object(host_color, 'build', return_value=(self.library, None)) as build, \
                        patch.object(host_color, 'cached_library', return_value=self.cached) as cache:
                    result = host_color.environment(self.root, name)
                build.assert_called_once_with(self.root)
                self.assertEqual(result['HYPEROS_AVD_SRGB'], '1')
                self.assertEqual(result['HYPEROS_AVD_SRGB_AVD'], name)
                self.assertEqual(result['DYLD_INSERT_LIBRARIES'],
                                 str(self.cached.resolve()) + ':/existing/plugin.dylib')
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
        os.environ['DYLD_INSERT_LIBRARIES'] = ':'.join((
            '/foreign/first.dylib', str(self.library.resolve()),
            '/foreign/second.dylib', str(self.cached.resolve())))
        with patch.object(host_color, 'build', return_value=(self.library, None)), \
                patch.object(host_color, 'cached_library', return_value=self.cached) as cache:
            result = host_color.environment(self.root, 'Owned_Pad')
        self.assertEqual(result['DYLD_INSERT_LIBRARIES'], ':'.join((
            str(self.cached.resolve()), '/foreign/first.dylib', '/foreign/second.dylib')))
        cache.assert_called_once_with(self.library, None)


class InternalHostColorCacheTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.library = self.root / host_color.LIBRARY
        self.receipt = self.root / host_color.RECEIPT
        self.data = macho()
        self.metadata = {'source_sha256': hashlib.sha256((REPO / 'native/emulator_srgb.m').read_bytes()).hexdigest(),
                         'sha256': hashlib.sha256(self.data).hexdigest(), 'install_name': host_color.INSTALL_NAME}
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
        self.assertEqual(cached.stat().st_mode & 0o777, 0o600)
        self.assertEqual(cached.parent.stat().st_mode & 0o777, 0o700)
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
        foreign.chmod(0o600)
        cached.symlink_to(foreign)
        with self.assertRaisesRegex(RuntimeError, 'aliased'):
            self.cache()
        self.assertEqual(foreign.read_bytes(), b'foreign library')
        self.assertTrue(cached.is_symlink())


@unittest.skipUnless(sys.platform == 'darwin' and platform.machine() == 'arm64'
                     and shutil.which('xcrun'), 'Native host guard needs macOS ARM64 CLT')
class NativeHostColorGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.root = Path(temporary.name)
        # Build the actual dylib with the same strict flags as a managed launch.
        cls.library, _ = host_color.build(cls.root)
        main = cls.root / 'probe.c'
        main.write_text('int main(void) { return 0; }\n')
        cls.probe = cls.root / 'probe'
        subprocess.run(['xcrun', 'clang', '-Wall', '-Wextra', '-Werror', '-arch', 'arm64',
                        '-mmacosx-version-min=12.0', str(main), '-o', str(cls.probe)],
                       check=True, capture_output=True)

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
        # This program only exercises the constructor; it creates no AVD/window.
        result = subprocess.run([str(self.probe), *arguments], env=environment,
                                text=True, capture_output=True, check=True)
        return result.stderr

    def test_compiled_hook_accepts_the_matching_renamed_instance(self):
        output = self.run_probe(['-avd', 'Renamed_Pad_API_99'])
        self.assertIn('sRGB tagging enabled for the owned OS4 AVD Renamed_Pad_API_99', output)

    def test_compiled_hook_rejects_optout_missing_name_and_other_instances(self):
        cases = ((['-avd', 'Pixel_9'], '1', 'Renamed_Pad_API_99'),
                 (['-avd', 'Renamed_Pad_API_99'], '0', 'Renamed_Pad_API_99'),
                 (['-avd', 'Renamed_Pad_API_99'], None, 'Renamed_Pad_API_99'),
                 (['-avd', 'HyperOS_4_Official_API_37'], '1', None),
                 (['-avd', 'HyperOS_4_Pad9ProMax_API_37'], '1', ''),
                 ([], '1', 'Renamed_Pad_API_99'),
                 (['-avd'], '1', 'Renamed_Pad_API_99'))
        for arguments, enabled, expected in cases:
            with self.subTest(arguments=arguments, enabled=enabled, expected=expected):
                self.assertNotIn('sRGB tagging enabled', self.run_probe(arguments, enabled, expected))


if __name__ == '__main__':
    unittest.main()
