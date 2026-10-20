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
        self.emulator = self.root / 'sdk/emulator/qemu/darwin-aarch64/qemu-system-aarch64'
        self.recipe = self.root / 'owned-user-state/recipe.json'
        prepare = patch('host_display.prepare', return_value=self.recipe)
        self.prepare = prepare.start()
        self.addCleanup(prepare.stop)
        inherited = {'DYLD_INSERT_LIBRARIES': '/existing/plugin.dylib', 'HYPEROS_AVD_SRGB': '1', 'HYPEROS_AVD_SRGB_AVD': 'Old_AVD', 'HYPEROS_AVD_MULTI_DISPLAY': '1', 'HYPEROS_AVD_DISPLAY_RECIPE': '/old/recipe.json', 'HYPEROS_AVD_TRACKPAD': '1', 'UNRELATED_OPTION': 'kept'}
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
                build.assert_called_once_with(self.root, use_runtime_prebuilt=True)
                self.assertEqual(result['HYPEROS_AVD_SRGB'], '1')
                self.assertEqual(result['HYPEROS_AVD_SRGB_AVD'], name)
                self.assertNotIn('HYPEROS_AVD_MULTI_DISPLAY', result)
                self.assertNotIn('HYPEROS_AVD_DISPLAY_RECIPE', result)
                self.assertEqual(result['DYLD_INSERT_LIBRARIES'], str(self.cached.resolve()) + ':/existing/plugin.dylib')
                cache.assert_called_once_with(self.library, None)
                self.assertEqual(result['UNRELATED_OPTION'], 'kept')
                self.assertEqual(dict(os.environ), before)

    def test_color_scope_does_not_limit_runtime_display_discovery(self):
        for source in (None, 'google-apis', 'custom', 'official-unverified-ota'):
            if source is None:
                (self.root / 'local/build.json').unlink(missing_ok=True)
            else:
                self.manifest(source)
            for multi_display in (False, True):
                with self.subTest(source=source, multi_display=multi_display), \
                        patch.object(host_color, 'build', return_value=(self.library, None)) as build, \
                        patch.object(host_color, 'cached_library', return_value=self.cached):
                    result = host_color.environment(self.root, 'Arbitrary_Owned_Device',
                                                    multi_display=multi_display, emulator=self.emulator)
                self.assertNotIn('HYPEROS_AVD_SRGB', result)
                if multi_display:
                    build.assert_called_once_with(self.root, use_runtime_prebuilt=True)
                    self.assertEqual(result['HYPEROS_AVD_SRGB_AVD'], 'Arbitrary_Owned_Device')
                    self.assertEqual(result['HYPEROS_AVD_MULTI_DISPLAY'], '1')
                    self.assertEqual(result['HYPEROS_AVD_DISPLAY_RECIPE'], str(self.recipe))
                    self.assertEqual(result['DYLD_INSERT_LIBRARIES'], str(self.cached.resolve()) + ':/existing/plugin.dylib')
                else:
                    build.assert_not_called()
                    self.assertNotIn('HYPEROS_AVD_SRGB_AVD', result)
                    self.assertNotIn('HYPEROS_AVD_MULTI_DISPLAY', result)
                    self.assertNotIn('HYPEROS_AVD_DISPLAY_RECIPE', result)
                    self.assertEqual(result['DYLD_INSERT_LIBRARIES'], '/existing/plugin.dylib')

    def test_color_and_multi_display_opt_ins_are_independent(self):
        self.manifest('official-hongkong-ota')
        for color, multi_display in ((True, True), (False, True), (True, False)):
            self.prepare.reset_mock()
            with self.subTest(color=color, multi_display=multi_display), \
                    patch.object(host_color, 'build', return_value=(self.library, None)) as build, \
                    patch.object(host_color, 'cached_library', return_value=self.cached):
                result = host_color.environment(self.root, 'Renamed_Phone',
                                                enabled=color, multi_display=multi_display,
                                                emulator=self.emulator)
            build.assert_called_once_with(self.root, use_runtime_prebuilt=True)
            self.assertEqual(result.get('HYPEROS_AVD_SRGB'), '1' if color else None)
            self.assertEqual(result.get('HYPEROS_AVD_MULTI_DISPLAY'), '1' if multi_display else None)
            self.assertEqual(result.get('HYPEROS_AVD_DISPLAY_RECIPE'), str(self.recipe) if multi_display else None)
            if multi_display:
                self.prepare.assert_called_once_with(self.emulator)
            else:
                self.prepare.assert_not_called()
            self.assertEqual(result['HYPEROS_AVD_SRGB_AVD'], 'Renamed_Phone')
            self.assertEqual(result['DYLD_INSERT_LIBRARIES'], str(self.cached.resolve()) + ':/existing/plugin.dylib')

    def test_opt_out_clears_inherited_authorization_without_building(self):
        self.manifest('official-yingtian-ota')
        with patch.object(host_color, 'build') as build:
            result = host_color.environment(self.root, 'Owned_Pad', enabled=False, emulator=self.emulator)
        build.assert_not_called()
        self.prepare.assert_not_called()
        self.assertNotIn('HYPEROS_AVD_SRGB', result)
        self.assertNotIn('HYPEROS_AVD_SRGB_AVD', result)
        self.assertNotIn('HYPEROS_AVD_MULTI_DISPLAY', result)
        self.assertNotIn('HYPEROS_AVD_DISPLAY_RECIPE', result)
        self.assertNotIn('HYPEROS_AVD_TRACKPAD', result)
        self.assertEqual(result['DYLD_INSERT_LIBRARIES'], '/existing/plugin.dylib')
        self.assertEqual(os.environ['HYPEROS_AVD_SRGB_AVD'], 'Old_AVD')

    def test_trackpad_is_independent_of_color_manifest_and_display_abi(self):
        self.prepare.return_value = None
        for source in ('official-hongkong-ota', 'official-yingtian-ota', 'custom'):
            self.manifest(source)
            with self.subTest(source=source), \
                    patch.object(host_color, 'build', return_value=(self.library, None)) as build, \
                    patch.object(host_color, 'cached_library', return_value=self.cached):
                result = host_color.environment(self.root, 'Renamed_Device', enabled=False,
                                                multi_display=True, emulator=self.emulator,
                                                trackpad=True)
            build.assert_called_once_with(self.root, use_runtime_prebuilt=True)
            self.assertEqual(result['HYPEROS_AVD_TRACKPAD'], '1')
            self.assertEqual(result['HYPEROS_AVD_SRGB_AVD'], 'Renamed_Device')
            self.assertNotIn('HYPEROS_AVD_SRGB', result)
            self.assertNotIn('HYPEROS_AVD_MULTI_DISPLAY', result)
            self.assertEqual(result['DYLD_INSERT_LIBRARIES'], str(self.cached.resolve()) + ':/existing/plugin.dylib')
        with self.assertRaisesRegex(RuntimeError, 'AVD name'):
            host_color.environment(self.root, '', enabled=False, trackpad=True)

    def test_owned_launch_requires_a_nonempty_name(self):
        self.manifest('official-yingtian-ota')
        with patch.object(host_color, 'build') as build:
            for name, color, multi_display in (('', True, False), (None, True, False),
                                               ('', False, True), (None, False, True)):
                with self.subTest(name=name, multi_display=multi_display), self.assertRaisesRegex(RuntimeError, 'AVD name'):
                    host_color.environment(self.root, name, enabled=color,
                                           multi_display=multi_display, emulator=self.emulator)
        build.assert_not_called()
        self.prepare.assert_not_called()

    def test_unsupported_host_capabilities_skip_only_display_and_need_no_compiler(self):
        self.prepare.return_value = None
        for source, color in (('custom', False), ('official-hongkong-ota', True)):
            self.manifest(source)
            with self.subTest(source=source), \
                    patch.object(host_color, 'build', return_value=(self.library, None)) as build, \
                    patch.object(host_color, 'cached_library', return_value=self.cached):
                result = host_color.environment(self.root, 'Owned_Device',
                                                multi_display=True, emulator=self.emulator)
            self.assertNotIn('HYPEROS_AVD_MULTI_DISPLAY', result)
            self.assertNotIn('HYPEROS_AVD_DISPLAY_RECIPE', result)
            self.assertEqual(result.get('HYPEROS_AVD_SRGB'), '1' if color else None)
            self.assertEqual(result.get('HYPEROS_AVD_SRGB_AVD'), 'Owned_Device' if color else None)
            if color:
                build.assert_called_once_with(self.root, use_runtime_prebuilt=True)
            else:
                build.assert_not_called()
        self.prepare.reset_mock()
        with patch.object(host_color, 'build') as build:
            result = host_color.environment(self.root, 'Owned_Device', enabled=False,
                                            multi_display=True)
        self.prepare.assert_not_called()
        build.assert_not_called()
        self.assertNotIn('HYPEROS_AVD_MULTI_DISPLAY', result)
        self.assertNotIn('HYPEROS_AVD_DISPLAY_RECIPE', result)

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

    def test_runtime_prebuilt_works_offline_without_changing_old_instance_tools(self):
        runtime = self.root / 'runtime-prebuilt'
        (runtime / 'native').mkdir(parents=True)
        (runtime / 'native/emulator_srgb.m').write_bytes((REPO / 'native/emulator_srgb.m').read_bytes())
        (runtime / 'tools').mkdir()
        for name in (host_color.LIBRARY, host_color.RECEIPT):
            shutil.copy2(self.root / 'tools' / name, runtime / 'tools' / name)
        instance = self.root / 'older-instance'
        (instance / 'tools').mkdir(parents=True)
        old = instance / 'tools' / host_color.LIBRARY
        old.write_bytes(b'old attachment')
        with patch.object(host_color, 'REPO_ROOT', runtime), \
                patch.object(host_color.subprocess, 'run') as compiler:
            self.assertEqual(host_color.build(instance, use_runtime_prebuilt=True),
                             (runtime / 'tools' / host_color.LIBRARY, runtime / 'tools' / host_color.RECEIPT))
            compiler.assert_not_called()
            self.assertEqual(old.read_bytes(), b'old attachment')
            (runtime / 'native/emulator_srgb.m').write_bytes(b'changed source')
            compiler.side_effect = RuntimeError('Compiler unavailable')
            with self.assertRaisesRegex(RuntimeError, 'Compiler unavailable'):
                host_color.build(instance, use_runtime_prebuilt=True)
            compiler.assert_called_once()
            self.assertEqual(old.read_bytes(), b'old attachment')

    def run_probe(self, arguments, enabled='1', expected='Renamed_Pad_API_99', multi_display=None):
        environment = os.environ.copy()
        environment.pop('HYPEROS_AVD_SRGB', None)
        environment.pop('HYPEROS_AVD_SRGB_AVD', None)
        environment.pop('HYPEROS_AVD_MULTI_DISPLAY', None)
        environment['DYLD_INSERT_LIBRARIES'] = str(self.library)
        if enabled is not None:
            environment['HYPEROS_AVD_SRGB'] = enabled
        if expected is not None:
            environment['HYPEROS_AVD_SRGB_AVD'] = expected
        if multi_display is not None:
            environment['HYPEROS_AVD_MULTI_DISPLAY'] = multi_display
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

    def test_native_trackpad_streams_preserve_axes_scope_and_touch_lifecycle(self):
        harness = self.root / 'trackpad.m'
        harness.write_text('#include ' + json.dumps(str(REPO / 'native/emulator_srgb.m')) + '\n' + r'''
#include <assert.h>
static NSMutableArray<NSEvent *> *mouseEvents;
@interface EmuGLView : NSView @end
@implementation EmuGLView
- (void)mouseDown:(NSEvent *)event { [mouseEvents addObject:event]; }
- (void)mouseDragged:(NSEvent *)event { [mouseEvents addObject:event]; }
- (void)mouseUp:(NSEvent *)event { [mouseEvents addObject:event]; }
@end
@interface ScrollProbe : NSEvent
@property NSWindow *target;
@property NSPoint point;
@property NSEventPhase finger, momentum;
@property CGFloat dx, dy;
@property BOOL precise;
@property NSEventModifierFlags flags;
@end
@implementation ScrollProbe
- (NSEventType)type { return NSEventTypeScrollWheel; }
- (NSWindow *)window { return self.target; }
- (NSPoint)locationInWindow { return self.point; }
- (NSEventPhase)phase { return self.finger; }
- (NSEventPhase)momentumPhase { return self.momentum; }
- (CGFloat)scrollingDeltaX { return self.dx; }
- (CGFloat)scrollingDeltaY { return self.dy; }
- (BOOL)hasPreciseScrollingDeltas { return self.precise; }
- (NSEventModifierFlags)modifierFlags { return self.flags; }
- (NSTimeInterval)timestamp { return NSProcessInfo.processInfo.systemUptime; }
@end
int main(void) { @autoreleasepool {
    [NSApplication sharedApplication];
    mouseEvents = [NSMutableArray array];
    NSWindow *window = [[NSWindow alloc] initWithContentRect:NSMakeRect(0,0,400,600)
        styleMask:NSWindowStyleMaskBorderless backing:NSBackingStoreBuffered defer:NO];
    EmuGLView *guest = [[EmuGLView alloc] initWithFrame:NSMakeRect(20,30,300,500)];
    [window.contentView addSubview:guest];
    [window orderFront:nil];
    ScrollProbe *event = [ScrollProbe new];
    event.target = window; event.point = NSMakePoint(100,300); event.precise = YES;
    event.finger = NSEventPhaseBegan;
    assert(trackpadScrollEvent(event) == nil && mouseEvents.count == 0);
    event.finger = NSEventPhaseChanged; event.dx = 12; event.dy = 20;
    assert(trackpadScrollEvent(event) == nil && mouseEvents.count == 2);
    assert(mouseEvents[0].type == NSEventTypeLeftMouseDown);
    assert(NSEqualPoints(mouseEvents[0].locationInWindow, event.point));
    assert(NSEqualPoints(mouseEvents[1].locationInWindow, NSMakePoint(112,280)));
    event.dx = -8; event.dy = -9;
    assert(trackpadScrollEvent(event) == nil && mouseEvents.count == 3);
    assert(NSEqualPoints(mouseEvents[2].locationInWindow, NSMakePoint(104,289)));
    event.finger = NSEventPhaseEnded; event.dx = event.dy = 0;
    assert(trackpadScrollEvent(event) == nil && mouseEvents.count == 4);
    assert(mouseEvents.lastObject.type == NSEventTypeLeftMouseUp && !trackpadDown);
    event.finger = NSEventPhaseNone; event.momentum = NSEventPhaseBegan; event.dy = 500;
    assert(trackpadScrollEvent(event) == nil && mouseEvents.count == 4);
    event.momentum = NSEventPhaseEnded;
    assert(trackpadScrollEvent(event) == nil && trackpadMomentumWindow == nil);
    // An unrelated momentum stream and ordinary mouse wheel stay native.
    event.momentum = NSEventPhaseChanged;
    assert(trackpadScrollEvent(event) == event);
    event.momentum = NSEventPhaseNone;
    assert(trackpadScrollEvent(event) == event);
    // No touch is generated for an empty or cancelled candidate.
    event.finger = NSEventPhaseBegan; event.dy = 0;
    assert(trackpadScrollEvent(event) == nil);
    event.finger = NSEventPhaseCancelled; event.dy = 100;
    assert(trackpadScrollEvent(event) == nil && mouseEvents.count == 4);
    event.finger = NSEventPhaseBegan; event.dy = 0;
    assert(trackpadScrollEvent(event) == nil);
    event.finger = NSEventPhaseEnded;
    assert(trackpadScrollEvent(event) == nil && mouseEvents.count == 4);
    // Precise but unphased, modified, discrete, and outside-screen input passes through.
    event.finger = NSEventPhaseBegan; event.flags = NSEventModifierFlagControl;
    assert(trackpadScrollEvent(event) == event);
    event.flags = 0; event.precise = NO;
    assert(trackpadScrollEvent(event) == event);
    event.precise = YES; event.point = NSMakePoint(390,590);
    assert(trackpadScrollEvent(event) == event);
    event.point = NSMakePoint(100,300); event.dx = 10000; event.dy = -10000;
    assert(trackpadScrollEvent(event) == nil && trackpadDown);
    NSRect guestRect = [guest convertRect:guest.bounds toView:nil];
    if (!NSPointInRect(trackpadPoint, guestRect))
        fprintf(stderr, "point=%s bounds=%s guest=%s\n", NSStringFromPoint(trackpadPoint).UTF8String,
            NSStringFromRect(trackpadBounds).UTF8String, NSStringFromRect(guestRect).UTF8String);
    assert(NSPointInRect(trackpadPoint, guestRect));
    // Resizing, focus loss and a new physical click each release the contact once.
    for (int reason = 0; reason < 3; ++reason) {
        if (reason) { event.finger = NSEventPhaseBegan; event.dx = 10; event.dy = 0;
            assert(trackpadScrollEvent(event) == nil && trackpadDown); }
        NSUInteger count = mouseEvents.count;
        if (reason == 0) {
            guest.frame = NSMakeRect(20,30,300,400); event.finger = NSEventPhaseChanged;
            assert(trackpadScrollEvent(event) == nil);
        } else if (reason == 1) {
            trackpadWindowChanged([NSNotification notificationWithName:NSApplicationDidResignActiveNotification object:NSApp]);
        } else {
            NSEvent *click = [NSEvent mouseEventWithType:NSEventTypeLeftMouseDown
                location:event.point modifierFlags:0 timestamp:event.timestamp
                windowNumber:window.windowNumber context:nil eventNumber:0 clickCount:1 pressure:1];
            assert(trackpadLocalEvent(click) == click);
        }
        assert(!trackpadTracking && !trackpadDown && mouseEvents.count == count + 1);
        assert(mouseEvents.lastObject.type == NSEventTypeLeftMouseUp);
        trackpadRelease(event.timestamp, true);
        assert(mouseEvents.count == count + 1);
    }
    return 0;
} }
''')
        executable = self.root / 'trackpad'
        result = subprocess.run(['xcrun', 'clang', '-fobjc-arc', '-Wall', '-Wextra', '-Werror',
                                 '-arch', 'arm64', '-mmacosx-version-min=12.0',
                                 '-framework', 'AppKit', '-framework', 'QuartzCore',
                                 str(harness), '-o', str(executable)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith('HYPEROS_AVD_') and key != 'DYLD_INSERT_LIBRARIES'}
        result = subprocess.run([str(executable)], env=environment, capture_output=True,
                                text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_primary_rotation_uses_only_each_reviewed_independent_window_pose(self):
        harness = self.root / 'rotation.m'
        harness.write_text('#include ' + json.dumps(str(REPO / 'native/emulator_srgb.m')) + '\n' + r'''
#include <assert.h>
static bool independent = true;
static int poseStatus = 0;
static uint32_t poseWidth = 1120, poseHeight = 2436;
static unsigned int poseCalls = 0;
static unsigned int rotation = 0, eventCount = 0, nextCalls = 0;
static bool repeatDisplayId = false;
static struct { uint32_t type, id, width, height; } events[8];
static const struct {
    uint32_t id, width, height, buffer;
    bool enabled;
} panels[] = {
    {0, 1120, 2436, 1, true}, {2, 912, 596, 10, true},
    {4, 320, 240, 0, true}, {7, 640, 480, 11, true},
    {8, 111, 222, 12, false}, {9, 0, 240, 13, true}
};
static bool independentWindows(void) { return independent; }
static int currentPose(uint32_t display, int32_t *x, int32_t *y, uint32_t *w, uint32_t *h) {
    assert(display == 0);
    ++poseCalls;
    *x = 17; *y = 19; *w = poseWidth; *h = poseHeight;
    return poseStatus;
}
static bool enumerateDisplay(int32_t previous, uint32_t *id, int32_t *x, int32_t *y,
                             uint32_t *w, uint32_t *h, uint32_t *dpi,
                             uint32_t *flags, uint32_t *buffer) {
    ++nextCalls;
    if (repeatDisplayId) { *id = previous < 0 ? 0 : (uint32_t)previous; return true; }
    for (size_t i = 0; i < sizeof(panels) / sizeof(panels[0]); ++i) {
        if (previous >= 0 && panels[i].id <= (uint32_t)previous) continue;
        *id = panels[i].id; *x = 20; *y = 30; *dpi = 450; *flags = 0;
        *w = rotation ? panels[i].height : panels[i].width;
        *h = rotation ? panels[i].width : panels[i].height;
        *buffer = panels[i].buffer;
        return true;
    }
    return false;
}
static bool naturalDisplay(uint32_t id, int32_t *x, int32_t *y, uint32_t *w,
                           uint32_t *h, uint32_t *dpi, uint32_t *flags, bool *enabled) {
    for (size_t i = 0; i < sizeof(panels) / sizeof(panels[0]); ++i) {
        if (id != panels[i].id) continue;
        *x = 20; *y = 30; *dpi = 450; *flags = 0;
        *w = panels[i].width; *h = panels[i].height; *enabled = panels[i].enabled;
        return true;
    }
    return false;
}
static void recordEvent(const void *event) {
    assert(eventCount < sizeof(events) / sizeof(events[0]));
    const unsigned char *bytes = event;
    memcpy(&events[eventCount].type, bytes + skinEventTypeOffset, 4);
    memcpy(&events[eventCount].id, bytes + skinEventIdOffset, 4);
    memcpy(&events[eventCount].width, bytes + skinEventWidthOffset, 4);
    memcpy(&events[eventCount].height, bytes + skinEventHeightOffset, 4);
    ++eventCount;
}
static void expectSize(uintptr_t caller, bool handled) {
    uint32_t w = 123, h = 456;
    eventCount = nextCalls = 0;
    assert(primaryRotationSize(caller, &w, &h) == handled);
    assert(w == (handled ? poseWidth : 123));
    assert(h == (handled ? poseHeight : 456));
    if (!handled) assert(eventCount == 0 && nextCalls == 0);
}
int main(void) {
    primaryDisplayPose = currentPose;
    separateDisplayWindows = independentWindows;
    nextDisplay = enumerateDisplay;
    displayInfo = naturalDisplay;
    queueSkinEvent = recordEvent;
    skinEventSize = 64; skinEventTypeOffset = 56;
    skinEventIdOffset = 8; skinEventWidthOffset = 12; skinEventHeightOffset = 16;
    skinEventAdd = 71; skinEventRemove = 72;
    rotationSizeCallers[0] = 0x1111;
    rotationSizeCallers[1] = 0x2222;
    const unsigned int rotations[] = {0, 1, 3};
    for (size_t r = 0; r < sizeof(rotations) / sizeof(rotations[0]); ++r) {
        rotation = rotations[r];
        poseWidth = rotation ? 2436 : 1120; poseHeight = rotation ? 1120 : 2436;
        expectSize(rotationSizeCallers[0], true);
        assert(eventCount == 0 && nextCalls == 0);
        expectSize(rotationSizeCallers[1], true);
        assert(eventCount == 4);
        const uint32_t ids[] = {2, 7}, widths[] = {912, 640}, heights[] = {596, 480};
        for (unsigned int i = 0; i < eventCount; ++i) {
            assert(events[i].type == (i % 2 ? skinEventAdd : skinEventRemove));
            assert(events[i].id == ids[i / 2]);
            if (i % 2) {
                assert(events[i].width == widths[i / 2]);
                assert(events[i].height == heights[i / 2]);
            }
        }
    }
    expectSize(0x3333, false);
    independent = false;
    expectSize(rotationSizeCallers[1], false);
    assert(poseCalls == 6);
    independent = true; poseStatus = -1;
    expectSize(rotationSizeCallers[1], false);
    poseStatus = 0; poseWidth = 0;
    expectSize(rotationSizeCallers[1], false);
    poseWidth = 2436; poseHeight = 0;
    expectSize(rotationSizeCallers[1], false);
    poseHeight = 1120; repeatDisplayId = true;
    expectSize(rotationSizeCallers[1], true);
    assert(nextCalls == 2 && eventCount == 0);
    return 0;
}
''')
        executable = self.root / 'rotation'
        result = subprocess.run(['xcrun', 'clang', '-fobjc-arc', '-Wall', '-Wextra', '-Werror',
                                 '-arch', 'arm64', '-mmacosx-version-min=12.0',
                                 '-framework', 'AppKit', '-framework', 'QuartzCore',
                                 str(harness), '-o', str(executable)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        environment = {key: value for key, value in os.environ.items()
                       if key not in ('HYPEROS_AVD_SRGB', 'HYPEROS_AVD_SRGB_AVD',
                                      'HYPEROS_AVD_MULTI_DISPLAY', 'DYLD_INSERT_LIBRARIES')}
        result = subprocess.run([str(executable)], env=environment, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        output = self.run_probe(['-avd', 'Renamed_Phone'], enabled=None,
                                expected='Renamed_Phone', multi_display='1')
        self.assertNotIn('independent primary-window rotation enabled', output)
        self.assertNotIn('sRGB tagging enabled', output)

class HostDisplayRecipeTests(unittest.TestCase):
    """Exercise byte-level discovery without an SDK, disassembler, or compiler."""

    @staticmethod
    def fixture(slots=21, base=0x100000000, code_offset=0x1000, data_gap=0,
                uuid=b'fixture UUID one', version='37.1.11', missing=None,
                extra_caller=False, bad_stack=False, type_offset=48,
                event_size=56, add_type=33, remove_type=34, chained=False,
                copy_move=False, copy_clobber=None, wrong_event_object=False,
                height_padding=0, payload_offset=0):
        import host_display as display

        def mov(destination, source):
            return 0xAA0003E0 | source << 16 | destination

        def imm(register, value):
            return 0x52800000 | value << 5 | register

        def add(destination, source, value):
            return 0x91000000 | value << 10 | source << 5 | destination

        def load(register, source, offset, width=8):
            return (0xF9400000 if width == 8 else 0xB9400000) | (offset // width) << 10 | source << 5 | register

        def store(register, source, offset, width=8):
            return (0xF9000000 if width == 8 else 0xB9000000) | (offset // width) << 10 | source << 5 | register

        def pair(first, second, source, offset, width=8):
            return (0xA9000000 if width == 8 else 0x29000000) | ((offset // width) & 127) << 15 | second << 10 | source << 5 | first

        def call(name, link=True):
            return ('branch', name, link)

        slot_map = dict(display_info=2, next_display=3, combined=5, pose=12,
                        separate_windows=18 if slots == 21 else 16,
                        perform_rotation=19 if slots == 21 else 17)
        bodies = {}
        for role in display.FUNCTIONS:
            bodies[role] = [0xD65F03C0]
        names = dict(display.FUNCTIONS)
        names['unused'] = '_ZN8Fixture06unusedEv'
        bodies['unused'] = [0xD65F03C0]
        for number, role in enumerate(display.AGENT_SIGNATURES):
            name = 'wrapper_' + role
            names[name] = '_ZN3$_' + str(number) + display.AGENT_SIGNATURES[role]
            count = dict(combined=2, pose=5, separate_windows=0, next_display=9,
                         display_info=8, perform_rotation=1)[role]
            body = [0xD10203FF]
            body += [mov(19 + index, index) for index in range(min(count, 8))]
            body += [call('instance'), 0xB4000040]
            if role == 'display_info':
                body += [pair(19 if bad_stack else 31, 26, 31, 0)]
            if role == 'next_display':
                body += [load(27, 31, 128), pair(26, 27, 31, 0)]
            body += [mov(index + 1, 19 + index) for index in range(min(count, 7))]
            body += [call(role, role in ('display_info', 'next_display')), 0xD65F03C0]
            bodies[name] = body

        def agent_call(role):
            return [load(8, 21, 0), load(8, 8, 120), load(8, 8, slot_map[role] * 8)]

        def size_call(number):
            return (agent_call('combined') + [add(0, 31, 0), add(1, 31, 4), 0xD63F0100,
                    load(3, 31, 0, 4), load(4, 31, 4, 4), mov(0, 19), imm(1, 0),
                    imm(2, 0), imm(5, number), call('resize')])

        bodies['rotate'] = ([0xD10203FF, mov(19, 0), mov(20, 1), ('adrp', 21, 'ui'), ('add_address', 21, 'ui')]
                            + size_call(0) + agent_call('perform_rotation') + [mov(0, 20), 0xD63F0100]
                            + size_call(1))
        if extra_caller:
            bodies['rotate'] += agent_call('combined') + [add(0, 31, 0), add(1, 31, 4), 0xD63F0100]
        bodies['rotate'] += [0xD65F03C0]
        event = [0xD10203FF, mov(19, 0), call('instance'),
                 0xAD400660, 0xAD0007E0]
        for offset in range(32, event_size - 8, 16):
            event += [0x3DC00000 | (offset // 16) << 10 | 19 << 5]
            if copy_clobber == 'simd':
                event += [0x6F00E400]
            event += [0x3D800000 | (offset // 16) << 10 | 31 << 5]
        event += [load(8, 19, event_size - 8)]
        if copy_move:
            event += [mov(9, 8)]
        if copy_clobber == 'gpr':
            event += [imm(8, 0)]
        if copy_clobber == 'call':
            event += [call('instance')]
        if copy_clobber == 'narrow':
            event += [0x2A0803E9]
        event += [store(9 if copy_move or copy_clobber == 'narrow' else 8, 31, event_size - 8),
                  add(1, 31, 0), call('queue_event'), 0xD65F03C0]
        bodies['event'] = event
        bodies['create_event'] = [store(0, 8, type_offset, 4), 0xD65F03C0]
        bodies['add_window'] = [0xD10203FF, mov(20, 1), ('cbz', 2, 'remove'),
                                mov(21, 3), mov(22, 4), add(8, 31, 64 if wrong_event_object else 16), imm(0, add_type),
                                call('create_event'), ('jump', 'payload'), ('label', 'remove'),
                                add(8, 31, 64 if wrong_event_object else 16), imm(0, remove_type), call('create_event'),
                                ('label', 'payload'), pair(20, 21, 31, 16 + payload_offset, 4),
                                store(22, 31, 24 + payload_offset + height_padding, 4),
                                add(1, 31, 16), mov(0, 19), call('queue_event'), 0xD65F03C0]
        addresses, cursor = {}, base + code_offset
        for name, body in bodies.items():
            addresses[name] = cursor
            cursor += 4 * sum(not (isinstance(item, tuple) and item[0] == 'label') for item in body)
        code_size = cursor - base - code_offset
        data_file = (code_offset + code_size + 4095) & ~4095
        data_address = base + data_file + data_gap
        addresses.update(table=data_address, exported=data_address + slots * 8,
                         ui=data_address + slots * 8 + 8)
        code = bytearray()
        for name, body in bodies.items():
            labels, position = {}, addresses[name]
            for item in body:
                if isinstance(item, tuple) and item[0] == 'label':
                    labels[item[1]] = position
                else:
                    position += 4
            position = addresses[name]
            for item in body:
                if isinstance(item, tuple):
                    kind = item[0]
                    if kind == 'label':
                        continue
                    if kind == 'branch':
                        word = (0x94000000 if item[2] else 0x14000000) | (((addresses[item[1]] - position) // 4) & 0x3FFFFFF)
                    elif kind == 'adrp':
                        immediate = ((addresses[item[2]] & ~4095) - (position & ~4095)) // 4096
                        word = 0x90000000 | (immediate & 3) << 29 | ((immediate >> 2) & 0x7FFFF) << 5 | item[1]
                    elif kind == 'add_address':
                        word = add(item[1], item[1], addresses[item[2]] & 4095)
                    elif kind == 'cbz':
                        word = 0x34000000 | (((labels[item[2]] - position) // 4) & 0x7FFFF) << 5 | item[1]
                    elif kind == 'jump':
                        word = 0x14000000 | (((labels[item[1]] - position) // 4) & 0x3FFFFFF)
                    else:
                        raise AssertionError(kind)
                else:
                    word = item
                code += struct.pack('<I', word)
                position += 4
        table = [addresses['unused']] * slots
        for role, index in slot_map.items():
            table[index] = addresses['wrapper_' + role]
        const = struct.pack('<' + 'Q' * (slots + 2), *table, addresses['table'], 0)
        strings = bytearray(b'\0')
        symbols = bytearray()
        for name in bodies:
            if name == missing:
                continue
            text = ('_' + names[name]).encode() + b'\0'
            symbols += struct.pack('<IBBHQ', len(strings), 0x0E if name.startswith('wrapper_') else 0x0F,
                                   1, 0, addresses[name])
            strings += text
        for name, symbol_name, external in (('table', 'arbitraryLocalAgentTable', False),
                                             ('exported', display.AGENT_GLOBAL, True),
                                             ('ui', display.UI_AGENT_GLOBAL, True)):
            symbols += struct.pack('<IBBHQ', len(strings), 0x0F if external else 0x0E, 2, 0, addresses[name])
            strings += ('_' + symbol_name).encode() + b'\0'
        strings += version.encode() + b'\0'
        sym_offset = (data_file + len(const) + 7) & ~7
        strings_offset = sym_offset + len(symbols)
        link_size = len(symbols) + len(strings)

        def segment(name, address, offset, file_size, protection, section=None):
            command = struct.pack('<II16sQQQQiiII', 0x19, 152 if section else 72,
                                  name.ljust(16, b'\0'), address, file_size, offset,
                                  file_size, protection, protection, int(section is not None), 0)
            if section:
                section_name, section_address, section_size, section_offset = section
                command += struct.pack('<16s16sQQIIIIIIII', section_name.ljust(16, b'\0'),
                                       name.ljust(16, b'\0'), section_address, section_size,
                                       section_offset, 2, 0, 0, 0, 0, 0, 0)
            return command

        commands = (segment(b'__TEXT', base, 0, data_file, 5,
                            (b'__text', base + code_offset, code_size, code_offset))
                    + segment(b'__DATA_CONST', data_address, data_file, len(const), 1,
                              (b'__const', data_address, len(const), data_file))
                    + segment(b'__LINKEDIT', base + sym_offset + data_gap, sym_offset, link_size, 1)
                    + struct.pack('<IIIIII', 2, 24, sym_offset, len(symbols) // 16, strings_offset, len(strings))
                    + struct.pack('<II16s', 0x1B, 24, uuid.ljust(16, b'\0')[:16]))
        if chained:
            commands += struct.pack('<IIII', 0x80000034, 16, sym_offset, 0)
        result = bytearray(strings_offset + len(strings))
        header = struct.pack('<8I', 0xFEEDFACF, 0x0100000C, 0, 2, 6 if chained else 5, len(commands), 0, 0)
        result[:32 + len(commands)] = header + commands
        result[code_offset:code_offset + len(code)] = code
        result[data_file:data_file + len(const)] = const
        result[sym_offset:sym_offset + len(symbols)] = symbols
        result[strings_offset:] = strings
        return bytes(result)

    def test_discovers_full_19_and_21_slot_tables_and_real_member_abi(self):
        import host_display as display
        for slots in (19, 21):
            with self.subTest(slots=slots):
                data = self.fixture(slots=slots)
                recipe = display.analyze(data)
                self.assertEqual(recipe['binary_sha256'], hashlib.sha256(data).hexdigest())
                self.assertEqual(recipe['agent']['table_size'], slots * 8)
                self.assertEqual(recipe['agent']['slots']['combined'], 5)
                self.assertEqual(recipe['agent']['slots']['separate_windows'], slots - 3)
                self.assertEqual(len(recipe['rotation_callers']), 2)
                self.assertEqual(set(recipe['agent']['entries']), set(display.AGENT_SIGNATURES))
                self.assertEqual(recipe['event'], dict(size=56, type_offset=48, add_type=33,
                                 remove_type=34, id_offset=0, width_offset=4, height_offset=8))

    def test_code_data_base_uuid_and_version_are_not_identity_pins(self):
        import host_display as display
        first = display.analyze(self.fixture())
        moved = display.analyze(self.fixture(base=0x200000000, code_offset=0x3000, data_gap=0x4000,
                                             uuid=b'different UUID!!', version='future SDK'))
        self.assertEqual(first['bindings'], moved['bindings'])
        self.assertEqual(first['rotation_callers'], moved['rotation_callers'])
        self.assertEqual(first['agent']['slots'], moved['agent']['slots'])
        self.assertEqual(first['event'], moved['event'])
        self.assertNotEqual(first['image_preferred_base'], moved['image_preferred_base'])
        self.assertNotEqual(first['agent']['table_offset'], moved['agent']['table_offset'])

    def test_derives_event_size_and_discriminator_values(self):
        import host_display as display
        event = display.analyze(self.fixture(event_size=72, type_offset=64,
                                             add_type=71, remove_type=9, height_padding=4,
                                             payload_offset=8))['event']
        self.assertEqual((event['size'], event['type_offset'], event['add_type'], event['remove_type']),
                         (72, 64, 71, 9))
        self.assertEqual((event['id_offset'], event['width_offset'], event['height_offset']), (8, 12, 20))

    def test_copy_provenance_supports_register_moves_and_rejects_clobbers(self):
        import host_display as display
        self.assertEqual(display.analyze(self.fixture(copy_move=True))['event']['size'], 56)
        for clobber in ('gpr', 'simd', 'call', 'narrow'):
            with self.subTest(clobber=clobber), self.assertRaises(ValueError):
                display.analyze(self.fixture(copy_clobber=clobber))
        with self.assertRaisesRegex(ValueError, 'queued event object'):
            display.analyze(self.fixture(wrong_event_object=True))

    def test_missing_symbols_ambiguous_calls_and_unknown_abi_fail_closed(self):
        import host_display as display
        cases = (dict(missing='pose'), dict(extra_caller=True), dict(bad_stack=True),
                 dict(type_offset=8), dict(type_offset=64), dict(chained=True))
        for options in cases:
            with self.subTest(options=options), self.assertRaises(ValueError):
                display.analyze(self.fixture(**options))
        for data in (b'', b'not a Mach-O', self.fixture()[:64]):
            with self.subTest(length=len(data)), self.assertRaises(ValueError):
                display.analyze(data)

    def test_prepare_reuses_private_content_cache_and_preserves_unknown_entries(self):
        import host_display as display
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            state = root / 'state'
            state.mkdir()
            executable = root / 'qemu'
            data = self.fixture()
            executable.write_bytes(data)
            with patch('host_launch.job_directory', return_value=state / 'launchd'), \
                    patch('sys.stderr', new_callable=io.StringIO) as diagnostic:
                target = display.prepare(executable)
                self.assertEqual(target, state / 'host-display' / hashlib.sha256(data).hexdigest() / 'recipe.json')
                self.assertEqual(target.stat().st_mode & 0o777, 0o600)
                self.assertEqual(target.parent.stat().st_mode & 0o777, 0o700)
                before = (target.read_bytes(), target.stat().st_ino, target.stat().st_mtime_ns)
                self.assertEqual(json.loads(before[0]), display.analyze(data))
                self.assertEqual(display.prepare(executable), target)
                self.assertEqual((target.read_bytes(), target.stat().st_ino, target.stat().st_mtime_ns), before)
                target.write_bytes(b'unknown cache contents')
                self.assertIsNone(display.prepare(executable))
                self.assertEqual(target.read_bytes(), b'unknown cache contents')
                self.assertIn('modified', diagnostic.getvalue())
                target.unlink()
                foreign = root / 'foreign.json'
                foreign.write_bytes(b'foreign contents')
                target.symlink_to(foreign)
                self.assertIsNone(display.prepare(executable))
                self.assertTrue(target.is_symlink())
                self.assertEqual(foreign.read_bytes(), b'foreign contents')
            executable.write_bytes(b'unsupported executable')
            with patch('host_launch.job_directory', return_value=root / 'unknown/launchd'), \
                    patch('sys.stderr', new_callable=io.StringIO):
                self.assertIsNone(display.prepare(executable))
            self.assertFalse((root / 'unknown').exists())


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
            library, receipt = root / host_color.LIBRARY, root / host_color.RECEIPT
            library.write_bytes(macho())
            receipt.write_text(json.dumps({'source_sha256': hashlib.sha256((REPO / 'native/emulator_srgb.m').read_bytes()).hexdigest(),
                                          'sha256': hashlib.sha256(macho()).hexdigest(),
                                          'install_name': host_color.INSTALL_NAME}))
            with patch.object(host_color, 'build', return_value=(library, receipt)) as build:
                metadata = package_installer.package(root / 'release')
            build.assert_called_once_with(REPO)
            helper = 'scripts/https_transport.py'
            with zipfile.ZipFile(root / 'release' / metadata['archive']['name']) as archive:
                self.assertEqual(archive.read('HyperOS-AVD/tools/' + host_color.LIBRARY), library.read_bytes())
                self.assertEqual(archive.read('HyperOS-AVD/tools/' + host_color.RECEIPT), receipt.read_bytes())
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
