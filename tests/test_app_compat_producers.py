"""Verify the universal producer union and its owned, compiler-free inputs."""
from contextlib import ExitStack
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import subprocess

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import app_compat_producers as producer
import apply_pad_camera_native_fix as camera_b
import apply_xiaomi_camera_fix as camera_a
from phone_profile import profile


def digest(data):
    return hashlib.sha256(data).hexdigest()


def signed_fixture(name):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as archive:
        archive.writestr('lib/arm64-v8a/libmgl.so', name.encode())
    return output.getvalue()


class AppCompatRecipeTests(unittest.TestCase):
    def test_complete_union_selects_content_and_preserves_defaults(self):
        values = producer.recipes()
        self.assertEqual(len(values), 6)
        self.assertEqual(values, sorted(values, key=lambda row: row['id']))
        self.assertEqual(len({row['id'] for row in values}), 6)
        self.assertEqual({row['feature'] for row in values}, {'weather', 'oem-camera', 'parrot-camera'})
        cameras = [row for row in values if row['feature'] == 'oem-camera']
        self.assertEqual({row['apk_sha256'] for row in cameras},
                         {*camera_a.CAMERA_VERSIONS, camera_b.APK_HASH})
        self.assertEqual({row['apk_libraries'][producer.CAMERA_ENTRY] for row in cameras},
                         {camera_a.YUV_HASH, camera_b.YUV_BEFORE})
        self.assertEqual(len({json.dumps(row['system_targets'], sort_keys=True) for row in cameras}), 1)
        self.assertEqual([row['default_enabled'] for row in cameras].count(True), 1)
        self.assertEqual(next(row for row in cameras if row['default_enabled'])['apk_sha256'], camera_b.APK_HASH)
        for row in values:
            self.assertFalse({'source', 'device', 'firmware', 'incremental', 'avd', 'version'} & set(row))
            if row['feature'] == 'weather':
                self.assertTrue(row['default_enabled'])
            elif row['feature'] == 'parrot-camera':
                self.assertFalse(row['default_enabled'])
        with patch.object(camera_a, 'CAMERA_VERSIONS', dict(reversed(list(camera_a.CAMERA_VERSIONS.items())))):
            self.assertEqual(producer.recipes(), values)

    def test_publish_and_owned_alias_guards(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / 'output'
            output.mkdir()
            data = b'verified payload'
            checksum = digest(data)
            path = producer._publish(output, checksum, data)
            self.assertEqual(producer._publish(output, checksum, data), path)
            path.write_bytes(b'changed')
            with self.assertRaisesRegex(RuntimeError, 'cache changed'):
                producer._publish(output, checksum, data)
            path.unlink()
            target = root / 'foreign'
            target.write_bytes(data)
            path.symlink_to(target)
            with self.assertRaisesRegex(RuntimeError, 'Invalid'):
                producer._publish(output, checksum, data)
            path.unlink()
            os.link(target, path)
            with self.assertRaisesRegex(RuntimeError, 'Invalid'):
                producer._publish(output, checksum, data)
            version = root / 'versions/custom/tools'
            version.mkdir(parents=True)
            (root / 'tools').symlink_to(version)
            self.assertEqual(producer._cache_directory(root, 'camera'), version.resolve() / 'camera')
            (root / 'tools').unlink()
            (root / 'tools').symlink_to(root.parent)
            with self.assertRaisesRegex(RuntimeError, 'Invalid'):
                producer._cache_directory(root, 'camera')

    def test_factory_passthrough_is_content_pinned_and_does_not_add_payloads(self):
        values = producer.recipes()
        cameras = [row for row in values if row['feature'] == 'oem-camera']
        self.assertEqual(set(producer.CAMERA_FACTORY_PASSTHROUGH),
                         {*camera_a.CAMERA_VERSIONS, camera_b.APK_HASH})
        expected_paths = {'oat/arm64/MiuiCamera.odex', 'oat/arm64/MiuiCamera.vdex'}
        for row in cameras:
            self.assertTrue(row['factory_overlay'])
            self.assertEqual(row['factory_passthrough'],
                             producer.CAMERA_FACTORY_PASSTHROUGH[row['apk_sha256']])
            self.assertEqual(set(row['factory_passthrough']), expected_paths)
            for checksum in row['factory_passthrough'].values():
                self.assertRegex(checksum, r'^[0-9a-f]{64}$')
        self.assertTrue(all('factory_passthrough' not in row for row in values
                            if row['feature'] != 'oem-camera'))
        outputs = {target['after'] for row in values
                   for target in [*row['libraries'], *row['system_targets']]}
        self.assertEqual(len(outputs), 11)
        self.assertFalse(outputs & {value for row in cameras for value in row['factory_passthrough'].values()})
        cameras[0]['factory_passthrough']['oat/arm64/MiuiCamera.odex'] = '0' * 64
        self.assertNotEqual(producer.recipes()[0]['factory_passthrough']['oat/arm64/MiuiCamera.odex'], '0' * 64)
        with self.assertRaisesRegex(RuntimeError, 'No audited OEM factory directory'):
            producer._camera_recipe('unknown', '0' * 64, camera_a.RUNTIME_HASH,
                                    camera_a.YUV_HASH, camera_a.PAYLOADS['yuv.so'], False)

    def test_packed_reader_supports_folded_product_and_rejects_split_extents(self):
        root = Path('/audited/renamed-workspace')
        part = {'name': 'system', 'size': 1024, 'extents': [(2, 0, 8, 0)]}
        with patch('packed_source.source_info', return_value=({}, root / 'images/system.img', '0' * 64, {})), \
                patch('lp_image.read_lp', return_value=(4096, [part])), \
                patch.object(producer, 'tool', return_value='/local/dump.erofs'), \
                patch.object(producer.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'input')) as run:
            self.assertEqual(producer.PackedFiles().read(root, 'product', '/app/a/lib.so'), b'input')
            run.assert_called_once_with(['/local/dump.erofs', '--cat', '--offset=8192',
                                          '--path=/product/app/a/lib.so', str(root / 'images/system.img')],
                                         check=False, capture_output=True)
            part['extents'] = [(1, 0, 8, 0), (1, 0, 16, 0)]
            with self.assertRaisesRegex(RuntimeError, 'one verified linear'):
                producer.PackedFiles().read(root, 'product', '/app/a/lib.so')


class UniversalCameraReceiptTests(unittest.TestCase):
    def make_camera_a(self, folder):
        payloads = {name: digest(name.encode()) for name in ('provider', 'hwl.so', 'yuv.so')}
        inputs = camera_a.camera_inputs(profile('4.0.18.0.XFRCNXM'))
        manifest = {'revision': 2, 'experimental': True, **inputs,
                    'targets': [{'payload': name, 'target': target, 'before': before,
                                 'after': payloads[name]}
                                for name, target, before in (
                                    ('provider', camera_a.PROVIDER, camera_a.PROVIDER_HASH),
                                    ('hwl.so', camera_a.HWL, camera_a.HWL_HASH))],
                    'yuv_sha256': payloads['yuv.so']}
        folder.mkdir()
        for name in payloads:
            (folder / name).write_bytes(name.encode())
        (folder / 'manifest.json').write_text(json.dumps(manifest))
        receipt = {'sources': {}, 'files': {**payloads, 'manifest.json': digest((folder / 'manifest.json').read_bytes())}}
        (folder / 'receipt.json').write_text(json.dumps(receipt))
        return payloads

    def test_camera_a_receipt_authenticates_all_outputs_and_rejects_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory) / 'bundle'
            payloads = self.make_camera_a(folder)
            with patch.object(camera_a, 'SOURCES', {}), patch.object(camera_a, 'PAYLOADS', payloads):
                camera_a.verify_universal_prebuilt(folder)
                original = (folder / 'hwl.so').read_bytes()
                (folder / 'hwl.so').write_bytes(b'changed')
                with self.assertRaisesRegex(RuntimeError, 'payload changed'):
                    camera_a.verify_universal_prebuilt(folder)
                (folder / 'hwl.so').write_bytes(original)
                (folder / 'provider').rename(folder / 'external')
                (folder / 'provider').symlink_to(folder / 'external')
                with self.assertRaisesRegex(RuntimeError, 'Invalid precompiled'):
                    camera_a.verify_universal_prebuilt(folder)

    def test_camera_b_receipt_authenticates_its_distinct_jni_recipe(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            payloads = {name: digest(name.encode()) for name in ('provider', 'hwl.so', 'yuv.so')}
            with patch.object(camera_b, 'SOURCES', {}), patch.object(camera_b, 'PAYLOADS', payloads), \
                    patch.object(camera_b, 'PROVIDER_AFTER', payloads['provider']), \
                    patch.object(camera_b, 'HWL_AFTER', payloads['hwl.so']), \
                    patch.object(camera_b, 'YUV_AFTER', payloads['yuv.so']):
                for name in payloads:
                    (folder / name).write_bytes(name.encode())
                (folder / 'manifest.json').write_text(json.dumps(camera_b.manifest(), indent=2) + '\n')
                receipt = {'sources': {}, 'files': {**payloads, 'manifest.json': digest((folder / 'manifest.json').read_bytes())}}
                (folder / 'receipt.json').write_text(json.dumps(receipt))
                camera_b.verify_universal_prebuilt(folder)
                receipt['files']['yuv.so'] = '0' * 64
                (folder / 'receipt.json').write_text(json.dumps(receipt))
                with self.assertRaisesRegex(RuntimeError, 'Unknown'):
                    camera_b.verify_universal_prebuilt(folder)


class AppCompatCollectorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.a, self.b = self.base / 'renamed-a', self.base / 'unrelated-z'
        self.stack = ExitStack()
        self.data = {digest(data): data for data in (
            b'provider', b'hwl', b'jni-a', b'jni-b', b'allocator', b'bridge',
            b'egl', b'gles', b'weather-a-patched', b'weather-b-patched')}
        self.a_payloads = {name: digest(data) for name, data in (
            ('provider', b'provider'), ('hwl.so', b'hwl'), ('yuv.so', b'jni-a'))}
        self.b_payloads = {**self.a_payloads, 'yuv.so': digest(b'jni-b')}
        for root, name, payloads in ((self.a, 'xiaomi-camera', self.a_payloads),
                                    (self.b, 'pad-camera-native', self.b_payloads)):
            folder = root / 'tools' / name
            folder.mkdir(parents=True)
            for filename, checksum in payloads.items():
                (folder / filename).write_bytes(self.data[checksum])
        folder = self.a / 'tools/parrot-camera'
        folder.mkdir()
        (folder / 'receipt.json').write_text('{}')
        (folder / 'lib_aion_buffer.so').write_bytes(b'allocator')
        folder = self.b / 'tools/weather-angle'
        folder.mkdir()
        for name, data in (('libEGL_angle.so', b'egl'), ('libGLESv2_angle.so', b'gles')):
            (folder / name).write_bytes(data)
        folder = self.a / 'work/weather-angle-fix'
        folder.mkdir(parents=True)
        (folder / 'libhgl.so').write_bytes(b'bridge')
        self.apks = [signed_fixture('weather-a'), signed_fixture('weather-b')]
        for root, data in zip((self.a, self.b), self.apks):
            folder = root / 'work/flutter-render-fix'
            folder.mkdir(parents=True)
            (folder / 'com.miui.weather2-current.apk').write_bytes(data)
        for module, name, value in (
                (producer, '_source_pins', lambda: None),
                (camera_a, 'PAYLOADS', self.a_payloads), (camera_b, 'PAYLOADS', self.b_payloads),
                (camera_a, 'verify_universal_prebuilt', lambda folder: {}),
                (camera_b, 'verify_universal_prebuilt', lambda folder: {}),
                (producer.parrot, 'prebuilt_receipt', lambda: {}),
                (producer.parrot, 'BRIDGE_SHA256', digest(b'allocator')),
                (producer.weather, 'BRIDGE_SHA256', digest(b'bridge')),
                (producer.weather, 'ANGLE', {'libEGL_angle.so': digest(b'egl'), 'libGLESv2_angle.so': digest(b'gles')}),
                (producer.weather, 'APK_SHA256', digest(self.apks[0])),
                (producer.weather, 'PAD_APK_SHA256', digest(self.apks[1])),
                (producer.weather, 'LIBRARIES', {'libmgl.so': (digest(b'weather-a'), digest(b'weather-a-patched'))}),
                (producer.weather, 'PAD_LIBRARIES', {'libmgl.so': (digest(b'weather-b'), digest(b'weather-b-patched'))}),
                (producer.weather, 'patch', lambda name, data, libraries: data + b'-patched'),
                (producer, 'recipes', lambda: [{'libraries': [{'after': key} for key in self.data], 'system_targets': []}])):
            self.stack.enter_context(patch.object(module, name, value))
        self.run = self.stack.enter_context(patch.object(producer.subprocess, 'run', side_effect=AssertionError('Unexpected external tool')))

    def tearDown(self):
        self.stack.close()
        self.temporary.cleanup()

    def collect(self, roots=None, output=None):
        return producer.collect_payloads(roots or [self.a, self.b], sdk='/no-ndk', output=output or self.base / 'output')

    def test_union_is_complete_deterministic_and_compiler_free(self):
        first = self.collect()
        second = self.collect([self.b, self.a], self.base / 'second')
        self.assertEqual(set(first), set(self.data))
        self.assertEqual(list(first), list(second))
        self.assertEqual({key: path.read_bytes() for key, path in first.items()}, self.data)
        self.assertEqual({key: path.read_bytes() for key, path in second.items()}, self.data)
        self.run.assert_not_called()

    def test_corrupt_present_asset_fails_closed_without_fallback(self):
        path = self.b / 'tools/weather-angle/libEGL_angle.so'
        path.write_bytes(b'foreign')
        with self.assertRaisesRegex(RuntimeError, 'audited recipe'):
            self.collect()
        self.assertEqual(path.read_bytes(), b'foreign')
        self.run.assert_not_called()

    def test_missing_camera_bundle_is_actionable_and_never_compiles(self):
        with self.assertRaisesRegex(RuntimeError, 'Missing audited producer bundle'):
            self.collect([self.a])
        self.run.assert_not_called()

    def test_unknown_signed_cache_falls_back_only_to_pinned_packed_factory(self):
        path = self.a / 'work/flutter-render-fix/com.miui.weather2-current.apk'
        path.write_bytes(b'unknown APK')
        image = self.a / 'images/system.img'
        image.parent.mkdir()
        image.touch()
        with patch.object(producer.PackedFiles, 'read', return_value=self.apks[0]) as read:
            self.collect()
        read.assert_called_once_with(self.a.resolve(), 'product', '/app/MIUIWeather/MIUIWeather.apk')
        self.assertEqual(path.read_bytes(), b'unknown APK')
        self.run.assert_not_called()

    def test_output_alias_is_rejected_before_publication(self):
        target = self.base / 'foreign'
        target.mkdir()
        output = self.base / 'output'
        output.symlink_to(target)
        with self.assertRaisesRegex(RuntimeError, 'output directory'):
            self.collect()
        self.assertEqual(list(target.iterdir()), [])


class PrebuiltPreparationTests(unittest.TestCase):
    def setUp(self):
        import app_compat_catalog as catalog
        import apply_app_compat as consumer
        self.catalog, self.consumer = catalog, consumer
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        payload = self.root / 'payload.so'; payload.write_bytes(b'complete audited output')
        self.payloads = {digest(payload.read_bytes()): payload}
        first = {'id': 'first', 'feature': 'weather', 'package': 'com.fixture.app',
                 'default_enabled': True, 'apk_sha256': digest(b'original signed APK'),
                 'libraries': [{'name': 'libtest.so', 'before': digest(b'input'),
                                'after': digest(payload.read_bytes())}]}
        self.previous = [first]
        self.current = [first, {**first, 'id': 'second', 'apk_sha256': digest(b'another signed APK')}]
        self.cache = self.root / 'verified-cache'
        self.cached = self.write_prebuilt(self.cache, self.current)
        self.workspace = self.root / 'release'
        self.destination = self.write_prebuilt(self.workspace, self.previous)
        with zipfile.ZipFile(self.destination / 'app-compat.zip') as archive:
            old = json.loads(archive.read('manifest.json'))
        mocked = patch.object(catalog, 'PREVIOUS_MANIFESTS', {digest(catalog.canonical(old)): old})
        mocked.start(); self.addCleanup(mocked.stop)
        mocked = patch.object(consumer, 'recipes', return_value=self.current)
        mocked.start(); self.addCleanup(mocked.stop)
        self.collect = patch.object(producer, 'collect_payloads', return_value=self.payloads)
        self.collect_mock = self.collect.start(); self.addCleanup(self.collect.stop)

    def write_prebuilt(self, workspace, recipes):
        folder = workspace / 'tools/os4-app-compat'; folder.mkdir(parents=True)
        receipt = self.catalog.package_catalog(folder / 'app-compat.zip', recipes, self.payloads)
        (folder / 'receipt.json').write_bytes(self.catalog.canonical(receipt))
        return folder

    def contents(self, folder):
        return {name: (folder / name).read_bytes() for name in ('app-compat.zip', 'receipt.json')}

    def test_complete_explicit_prebuilt_replaces_reviewed_previous_without_native_caches(self):
        original = self.contents(self.cached)
        self.assertEqual(self.consumer.prepare_prebuilt(self.workspace, sdk='/no-ndk',
            cache_roots=[self.workspace, self.cache]), self.destination)
        self.assertEqual(self.contents(self.destination), original)
        self.assertEqual(self.contents(self.cached), original)
        self.catalog.verify_prebuilt(self.destination, self.current)
        self.collect_mock.assert_not_called()
        self.assertEqual(list(self.destination.parent.glob('.app-compat-*')), [])

    def test_absent_destination_reuses_complete_explicit_prebuilt(self):
        workspace = self.root / 'new-release'
        result = self.consumer.prepare_prebuilt(workspace, cache_roots=[self.cache])
        self.assertEqual(self.contents(result), self.contents(self.cached))
        self.collect_mock.assert_not_called()

    def test_absent_current_cache_keeps_the_existing_complete_native_producer_path(self):
        result = self.consumer.prepare_prebuilt(self.workspace, sdk='/no-ndk',
                                                cache_roots=[self.workspace])
        self.catalog.verify_prebuilt(result, self.current)
        self.collect_mock.assert_called_once_with([self.workspace], sdk='/no-ndk')

    def test_unknown_destination_is_preserved_before_cache_copy_or_native_collection(self):
        (self.destination / 'receipt.json').write_bytes(b'custom receipt')
        before = self.contents(self.destination)
        with self.assertRaises((RuntimeError, ValueError)):
            self.consumer.prepare_prebuilt(self.workspace, cache_roots=[self.cache])
        self.assertEqual(self.contents(self.destination), before)
        self.collect_mock.assert_not_called()

    def test_reviewed_previous_with_custom_extra_is_preserved_before_staging(self):
        extra = self.destination / 'custom-notes.txt'
        extra.write_bytes(b'user-owned extra content')
        before = self.contents(self.destination)
        with patch.object(self.consumer.shutil, 'copyfileobj') as copy, \
                self.assertRaisesRegex(RuntimeError, 'Unknown files.*preserved'):
            self.consumer.prepare_prebuilt(self.workspace, cache_roots=[self.cache])
        self.assertEqual(extra.read_bytes(), b'user-owned extra content')
        self.assertEqual(self.contents(self.destination), before)
        copy.assert_not_called()
        self.collect_mock.assert_not_called()

    def test_extra_appearing_during_staging_blocks_previous_directory_replacement(self):
        import shutil
        original_copy, before = shutil.copyfileobj, self.contents(self.destination)
        extra = self.destination / 'new-custom-directory'
        copied = []
        def copy(source, output):
            original_copy(source, output)
            copied.append(source.name)
            if len(copied) == 2:
                extra.mkdir()
                (extra / 'notes.txt').write_bytes(b'concurrent user content')
        with patch.object(self.consumer.shutil, 'copyfileobj', side_effect=copy), \
                self.assertRaisesRegex(RuntimeError, 'Unknown files.*preserved'):
            self.consumer.prepare_prebuilt(self.workspace, cache_roots=[self.cache])
        self.assertEqual((extra / 'notes.txt').read_bytes(), b'concurrent user content')
        self.assertEqual(self.contents(self.destination), before)
        self.collect_mock.assert_not_called()
        self.assertEqual(list(self.destination.parent.glob('.app-compat-*')), [])

    def test_current_destination_extra_is_retained_without_any_replacement(self):
        extra = self.cached / 'custom-notes.txt'
        extra.write_bytes(b'current archive user notes')
        before = self.contents(self.cached)
        self.assertEqual(self.consumer.prepare_prebuilt(self.cache, cache_roots=[self.workspace]), self.cached)
        self.assertEqual(extra.read_bytes(), b'current archive user notes')
        self.assertEqual(self.contents(self.cached), before)
        self.collect_mock.assert_not_called()

    def test_unknown_explicit_cache_is_preserved_and_never_rebuilt_silently(self):
        (self.cached / 'app-compat.zip').write_bytes(b'unknown cache bytes')
        source, before = self.contents(self.cached), self.contents(self.destination)
        with self.assertRaises(RuntimeError):
            self.consumer.prepare_prebuilt(self.workspace, cache_roots=[self.cache])
        self.assertEqual(self.contents(self.cached), source)
        self.assertEqual(self.contents(self.destination), before)
        self.collect_mock.assert_not_called()

    def test_valid_source_change_after_copy_aborts_before_replacement(self):
        import shutil
        original_copy, before = shutil.copyfileobj, self.contents(self.destination)
        copied = []
        def copy(source, output):
            original_copy(source, output)
            copied.append(source.name)
            if len(copied) == 2:
                archive = self.cached / 'app-compat.zip'
                with zipfile.ZipFile(archive, 'a') as packed:
                    packed.comment = b'concurrently changed valid canonical archive'
                receipt = self.catalog.receipt(archive, self.current)
                (self.cached / 'receipt.json').write_bytes(self.catalog.canonical(receipt))
                self.catalog.verify_prebuilt(self.cached, self.current)
        with patch.object(self.consumer.shutil, 'copyfileobj', side_effect=copy), \
                self.assertRaisesRegex(RuntimeError, 'changed during staging'):
            self.consumer.prepare_prebuilt(self.workspace, cache_roots=[self.cache])
        self.assertEqual(self.contents(self.destination), before)
        self.collect_mock.assert_not_called()
        self.assertEqual(list(self.destination.parent.glob('.app-compat-*')), [])

    def test_stage_corruption_and_publication_failure_preserve_previous_archive(self):
        import shutil
        original_copy, original_rename = shutil.copyfileobj, Path.rename
        before = self.contents(self.destination)
        def corrupt(source, output):
            original_copy(source, output)
            if source.name.endswith('app-compat.zip'):
                output.write(b'corrupt staged archive')
        with patch.object(self.consumer.shutil, 'copyfileobj', side_effect=corrupt), \
                self.assertRaises(RuntimeError):
            self.consumer.prepare_prebuilt(self.workspace, cache_roots=[self.cache])
        self.assertEqual(self.contents(self.destination), before)
        def rename(path, target):
            if path.name.startswith('.app-compat-') and not path.name.endswith('.previous'):
                raise OSError('Publication failed')
            return original_rename(path, target)
        with patch.object(Path, 'rename', rename), self.assertRaisesRegex(OSError, 'Publication failed'):
            self.consumer.prepare_prebuilt(self.workspace, cache_roots=[self.cache])
        self.assertEqual(self.contents(self.destination), before)
        self.collect_mock.assert_not_called()
        self.assertEqual(list(self.destination.parent.glob('.app-compat-*')), [])


if __name__ == '__main__':
    unittest.main()
