"""Prepare phone releases from accepted packed images without source caches."""
from contextlib import ExitStack
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sys
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'scripts'))
import patch_flutter
import patch_boot_services
import phone_profile
import prepare_release_image as prepare
import incremental


def digest(data):
    return hashlib.sha256(data).hexdigest()


class ReleasePreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source, self.output = self.root / 'source', self.root / 'output'
        self.selected = phone_profile.profile('4.0.18.0.XFRCNXM')
        for directory in ('images', 'tools', 'config', 'local', 'avd'):
            (self.source / directory).mkdir(parents=True)
        (self.source / 'images/system.img').write_bytes(b'accepted packed image')
        (self.source / 'images/ramdisk.img').write_bytes(b'accepted boot image')
        (self.source / 'images/vendor-qemu.img').write_bytes(b'unrelated hardware image')
        (self.source / 'tools/verified-helper').write_bytes(b'accepted helper')
        (self.source / 'config/avd.ini').write_text('hw.ramSize=6144\n')
        (self.source / 'avd/userdata-qemu.img.qcow2').write_bytes(b'private userdata')
        self.info = {
            'source': 'official-hongkong-ota', 'hyperos': self.selected['hyperos'],
            'archive_sha256': self.selected['archive_sha256'],
            'system_sha256': digest(b'accepted packed image'),
            'flutter_render_fix': 6, 'rear_display': {'accepted': True},
            'boot_service_fix': {'accepted': 'r4'},
            'identity_source_sha256': {'system.build.prop': 'accepted source pin'},
        }
        self.write_info()
        self.engine, self.latest = b'previous verified engine', b'latest verified engine'
        self.input_engine_pin = self.selected['pins']['flutter']
        self.entries = {
            '/' + prepare.SHARED_FLUTTER: self.engine,
            '/product/overlay/HyperOSAVDSettingsDefaults/SettingsDefaults.apk': b'signed accepted RRO',
            '/system/build.prop': b'accepted OTA properties\n',
            '/system_ext/etc/init/init.hyperos_avd.rc': b'accepted OTA boot services\n',
            prepare.APK: b'accepted signed assistant APK',
        }
        self.partitions = {
            'system': b'accepted raw system', 'vendor': b'accepted vendor',
            'system_dlkm': b'accepted kernel modules', 'vendor_dlkm': b'unrelated logical partition',
        }
        self.cloned, self.builds, self.packs = [], [], []
        self.boot_receipt = {'schema': 1, 'targets': {'accepted-init': {'after': 'fixture'}}}
        self.codec_receipt = {'schema': 1, 'integration': 'shared-dolby-codecs'}
        import kernelsu_release
        from patch_kernelsu import receipt
        self.ksu_receipt = receipt(kernelsu_release.ASSETS[kernelsu_release.LKM])

    def write_info(self):
        (self.source / 'local/build.json').write_text(json.dumps(self.info))

    def use_pad_profile(self):
        import os4_pad
        value = os4_pad.PROFILE
        self.info.update(source=os4_pad.SOURCE, device=value['device'], hyperos=value['hyperos'],
                         archive_sha256=value['source_archive_sha256'], display=value['display'],
                         model_xml_sha256=value['model_xml_sha256'], identity_source_sha256=value['source_sha256'])
        self.write_info()

    def source_files(self):
        return {str(path.relative_to(self.source)): path.read_bytes()
                for path in self.source.rglob('*') if path.is_file()}

    def mocked_pipeline(self, *, boot_kind='defaults'):
        stack = ExitStack()
        self.addCleanup(stack.close)

        def clone(source, target):
            source, target = Path(source), Path(target)
            if boot_kind != 'pad':
                self.assertFalse(self.source / 'work' in source.parents)
            self.cloned.append((source, target))
            target.parent.mkdir(parents=True, exist_ok=True)
            return shutil.copy2(source, target)

        def unpack(source, target):
            self.assertEqual(source, self.source / 'images/system.img')
            self.assertEqual(target, self.output / 'work/accepted')
            target.mkdir(parents=True)
            for name, content in self.partitions.items():
                (target / (name + '.img')).write_bytes(content)

        def read(image, path):
            if image == self.output / 'work/accepted/system.img':
                return self.entries[path]
            self.assertEqual(image, self.output / 'work/hyperos-system.img')
            return self.builds[-1]['edits'][path.lstrip('/')][0]

        def build(target, sources, tree, edits):
            self.assertEqual(sources, [('', self.output / 'work/accepted/system.img')])
            self.builds.append({'edits': edits.copy(), 'sources': sources})
            target.write_bytes(b'updated accepted raw system')

        def pack(source, target, partitions):
            self.assertEqual(source, self.source / 'images/system.img')
            self.packs.append([(name, path.read_bytes()) for name, path in partitions])
            target.write_bytes(b'updated accepted packed image')

        def boot_edits(raw, vendor, edits, work):
            self.assertEqual(raw, self.output / 'work/accepted/system.img')
            self.assertEqual(vendor, self.output / 'work/accepted/vendor.img')
            self.assertEqual(work, self.output / 'work/boot-policy')
            if boot_kind == 'defaults':
                self.assertEqual(edits[prepare.SHARED_FLUTTER][0], self.latest)
                self.assertTrue(edits['system_ext/etc/init/init.hyperos_avd.rc'][0].endswith(b'latest defaults\n'))
            elif boot_kind == 'services':
                for _, (path, _, _) in patch_boot_services.TARGETS.items():
                    self.assertIn(path.lstrip('/'), edits)
                self.assertTrue(edits['system_ext/etc/init/init.hyperos_avd.rc'][0].endswith(
                    patch_boot_services.BOOT_INIT))
            else:
                self.assertIn(b'ro.adb.secure=1', edits['system/build.prop'][0])
            edits['system/etc/hyperos-init-capabilities.sh'] = (b'bounded boot helper', 0o755,
                                                               'u:object_r:system_file:s0')
            return self.boot_receipt

        def kernelsu(output):
            self.assertEqual(output, self.output)
            self.assertEqual(len(self.packs), 1)
            self.assertTrue((output / 'work').is_dir())
            (output / 'images/ramdisk.img').write_bytes(b'current quiet KernelSU boot image')
            return self.ksu_receipt

        def codec_vendor(source, target, work):
            self.assertEqual(source, self.output / 'work/accepted/vendor.img')
            self.assertEqual(target, self.output / 'work/vendor.img')
            self.assertEqual(work, self.output / 'work/vendor-codecs')
            target.write_bytes(source.read_bytes() + b' with shared Dolby codecs')
            return self.codec_receipt

        stack.enter_context(patch.object(prepare, 'clone', side_effect=clone))
        stack.enter_context(patch.object(prepare, 'unpack', side_effect=unpack))
        stack.enter_context(patch.object(prepare, 'erofs', side_effect=read))
        stack.enter_context(patch.object(prepare, 'build', side_effect=build))
        stack.enter_context(patch.object(prepare, 'pack', side_effect=pack))
        self.boot_mock = stack.enter_context(patch.object(prepare, 'shared_boot_edits', side_effect=boot_edits))
        stack.enter_context(patch.object(prepare, 'sdk_path', return_value=self.root / 'sdk'))
        self.defaults_mock = stack.enter_context(patch.object(prepare, 'image_replacements', return_value=(
            {'product/etc/accepted-new-default': (b'new default', 0o644, 'u:object_r:system_file:s0')},
            {'accepted_setting': True})))
        stack.enter_context(patch.object(prepare, 'production_properties',
                                         side_effect=lambda data, **_: data + b'secure ADB\n'))
        stack.enter_context(patch.object(prepare, 'boot_defaults',
                                         side_effect=lambda data, **_: data + b'latest defaults\n'))
        stack.enter_context(patch.object(prepare, 'assistant_replacements', return_value=(
            {'product/lib64/accepted-assistant.so': (b'fixed assistant', 0o644,
                                                     'u:object_r:system_lib_file:s0')},
            {'accepted': True})))
        self.profile_mock = stack.enter_context(patch.object(patch_flutter, 'profile',
            return_value=(self.input_engine_pin, {'output': digest(self.latest)})))
        self.patch_mock = stack.enter_context(patch.object(patch_flutter, 'patch', return_value=self.latest))
        self.ksu_mock = stack.enter_context(patch.object(prepare, 'prepare_release_kernelsu', side_effect=kernelsu))
        self.codec_mock = stack.enter_context(patch('dolby_codecs.build_vendor', side_effect=codec_vendor))
        return stack

    def test_canonical_input_without_work_cache_preserves_source_ota_and_partitions(self):
        context = self.source / 'tools/os4-core'
        context.mkdir()
        (context / 'receipt.json').write_bytes(b'old packed image receipt')
        (context / 'context.json').write_bytes(b'old platform context')
        original = self.source_files()
        self.assertFalse((self.source / 'work').exists())
        self.mocked_pipeline()
        prepare.prepare(self.source, self.output)
        self.assertEqual(self.source_files(), original)
        self.assertFalse((self.source / 'work').exists())
        self.assertEqual((self.output / 'images/vendor-qemu.img').read_bytes(), b'unrelated hardware image')
        self.assertFalse((self.output / 'avd').exists())
        self.assertFalse((self.output / 'tools/os4-core').exists())
        inputs = dict(self.packs[0])
        self.assertEqual(inputs['system'], b'updated accepted raw system')
        self.assertEqual(inputs['vendor'], b'accepted vendor with shared Dolby codecs')
        self.assertEqual({name: inputs[name] for name in self.partitions if name not in ('system', 'vendor')},
                         {name: content for name, content in self.partitions.items()
                          if name not in ('system', 'vendor')})
        edits = self.builds[0]['edits']
        self.assertEqual(edits[prepare.SHARED_FLUTTER],
                         (self.latest, 0o644, 'u:object_r:system_lib_file:s0'))
        self.assertEqual(edits['product/overlay/HyperOSAVDSettingsDefaults/SettingsDefaults.apk'][0],
                         b'signed accepted RRO')
        self.assertTrue(edits['system/build.prop'][0].startswith(b'accepted OTA properties\n'))
        self.assertTrue(edits['system_ext/etc/init/init.hyperos_avd.rc'][0].startswith(
            b'accepted OTA boot services\n'))
        self.profile_mock.assert_called_once_with(self.engine)
        self.patch_mock.assert_called_once_with(self.engine)
        self.boot_mock.assert_called_once()
        self.assertEqual(edits['system/etc/hyperos-init-capabilities.sh'],
                         (b'bounded boot helper', 0o755, 'u:object_r:system_file:s0'))
        info = json.loads((self.output / 'local/build.json').read_text())
        for key in ('hyperos', 'archive_sha256', 'source', 'identity_source_sha256',
                    'rear_display', 'boot_service_fix', 'flutter_render_fix'):
            self.assertEqual(info[key], self.info[key])
        self.assertEqual(info['flutter_engine'],
                         {'before': self.selected['pins']['flutter'], 'after': digest(self.latest)})
        self.assertEqual(info['system_sha256'], digest(b'updated accepted packed image'))
        self.assertEqual(info['raw_sha256'], digest(b'updated accepted raw system'))
        self.assertEqual(info['boot_policy'], self.boot_receipt)
        self.assertEqual(info['kernelsu_marker_fix'], self.ksu_receipt)
        self.assertEqual(info['audio_codecs'], self.codec_receipt)
        self.codec_mock.assert_called_once()
        self.assertEqual((self.output / 'images/ramdisk.img').read_bytes(), b'current quiet KernelSU boot image')
        self.ksu_mock.assert_called_once_with(self.output)

    def test_stale_cache_cannot_replace_the_accepted_system_or_vendor(self):
        (self.source / 'work/base').mkdir(parents=True)
        for path in ('hyperos-system.img', 'vendor.img', 'base/system_dlkm.img'):
            (self.source / 'work' / path).write_bytes(b'stale rejected cache')
        original = self.source_files()
        self.mocked_pipeline()
        prepare.prepare(self.source, self.output)
        self.assertEqual(self.source_files(), original)
        self.assertNotIn(b'stale rejected cache', dict(self.packs[0]).values())

    def test_new_registered_source_retains_baked_repairs_and_private_userdata(self):
        from patch_boot_services import image_receipts
        self.selected = phone_profile.profile('4.0.24.0.XFRCNXM')
        self.info.update(hyperos=self.selected['hyperos'],
                         archive_sha256=self.selected['archive_sha256'],
                         boot_service_fix=image_receipts()[-1],
                         rear_display={'hyperos': self.selected['hyperos'],
                                       'archive_sha256': self.selected['archive_sha256']})
        self.write_info()
        original = self.source_files()
        self.mocked_pipeline()
        prepare.prepare(self.source, self.output)
        self.assertEqual(self.source_files(), original)
        self.assertFalse((self.output / 'avd').exists())
        saved = json.loads((self.output / 'local/build.json').read_text())
        for key in ('hyperos', 'archive_sha256', 'boot_service_fix', 'rear_display'):
            self.assertEqual(saved[key], self.info[key])
        self.assertEqual(saved['flutter_engine']['before'], self.selected['pins']['flutter'])
        self.assertEqual(set(dict(self.packs[0])), set(self.partitions))

    def test_unknown_or_tampered_phone_source_refuses_before_output(self):
        original_info = self.info.copy()
        self.mocked_pipeline()
        for key, value in (('hyperos', '4.0.999.0.XFRCNXM'), ('archive_sha256', 'f' * 64)):
            with self.subTest(key=key):
                self.info = dict(original_info, **{key: value})
                self.write_info()
                original = self.source_files()
                with self.assertRaises(RuntimeError):
                    prepare.prepare(self.source, self.output)
                self.assertEqual(self.source_files(), original)
                self.assertFalse(self.output.exists())
        self.assertEqual(self.builds, [])
        self.assertEqual(self.packs, [])
        self.ksu_mock.assert_not_called()

    def test_packed_receipt_mismatch_rejects_before_output_or_build(self):
        self.info['system_sha256'] = digest(b'another accepted image')
        self.write_info()
        self.mocked_pipeline()
        with self.assertRaisesRegex(RuntimeError, 'accepted release receipt'):
            prepare.prepare(self.source, self.output)
        self.assertFalse(self.output.exists())
        self.assertEqual(self.builds, [])
        self.assertEqual(self.packs, [])

    def test_missing_packed_receipt_rejects_before_output_or_build(self):
        del self.info['system_sha256']
        self.write_info()
        self.mocked_pipeline()
        with self.assertRaisesRegex(RuntimeError, 'accepted release receipt'):
            prepare.prepare(self.source, self.output)
        self.assertFalse(self.output.exists())
        self.assertEqual(self.builds, [])

    def test_engine_from_another_known_ota_rejects_before_patching_or_build(self):
        self.input_engine_pin = phone_profile.profile()['pins']['flutter']
        original = self.source_files()
        self.mocked_pipeline()
        with self.assertRaisesRegex(RuntimeError, 'original OTA profile'):
            prepare.prepare(self.source, self.output)
        self.assertEqual(self.source_files(), original)
        self.patch_mock.assert_not_called()
        self.defaults_mock.assert_not_called()
        self.assertEqual(self.builds, [])
        self.assertEqual(self.packs, [])

    def test_already_current_engine_is_idempotent(self):
        self.latest = self.engine
        self.mocked_pipeline()
        prepare.prepare(self.source, self.output)
        self.assertEqual(self.builds[0]['edits'][prepare.SHARED_FLUTTER][0], self.engine)
        info = json.loads((self.output / 'local/build.json').read_text())
        self.assertEqual(info['flutter_engine']['after'], digest(self.engine))

    def test_r4_service_preparation_keeps_shared_boot_policy_and_extra_logical_partitions(self):
        import package_release
        self.info.pop('boot_service_fix')
        self.write_info()
        self.entries['/system_ext/etc/selinux/system_ext_sepolicy.cil'] = b'accepted policy\n'
        extra = {}
        for name, (path, _, _) in patch_boot_services.TARGETS.items():
            self.entries[path] = ('original ' + name).encode()
            extra[path.lstrip('/')] = (('fixed ' + name).encode(), 0o644, 'u:object_r:system_file:s0')
        receipt = {'targets': {name: {'after': 'fixture'} for name in patch_boot_services.TARGETS}}
        original = self.source_files()
        self.mocked_pipeline(boot_kind='services')
        with patch.object(patch_boot_services, 'image_replacements', return_value=(extra, receipt)), \
                patch.object(package_release, 'release_metadata', return_value={'verified': True}), \
                patch.object(package_release, 'verify_os4_image') as verify:
            prepare.prepare_boot_services(self.source, self.output)
        self.assertEqual(verify.call_count, 2)
        self.assertEqual(self.source_files(), original)
        self.assertFalse((self.output / 'avd').exists())
        packed = dict(self.packs[0])
        for name, value in self.partitions.items():
            if name != 'system':
                self.assertEqual(packed[name], value)
        for path, edit in extra.items():
            self.assertEqual(self.builds[0]['edits'][path], edit)
        self.boot_mock.assert_called_once()
        info = json.loads((self.output / 'local/build.json').read_text())
        self.assertEqual(info['boot_service_fix'], receipt)
        self.assertEqual(info['boot_policy'], self.boot_receipt)

    def test_pad_preparation_keeps_shared_boot_policy_and_extra_logical_partitions(self):
        import apply_app_compat
        from os4_pad import current_refresh_script
        self.use_pad_profile()
        self.entries['/system/build.prop'] = b'ro.adb.secure=0\nro.debuggable=0\nro.product.device=yingtian\n'
        self.assertFalse((self.source / 'work').exists())
        context = self.source / 'tools/os4-core'
        context.mkdir()
        (context / 'receipt.json').write_bytes(b'old Pad image receipt')
        original = self.source_files()
        self.mocked_pipeline(boot_kind='pad')
        with patch.object(apply_app_compat, 'prepare_prebuilt') as apps:
            prepare.prepare(self.source, self.output, 'os4-pad')
        apps.assert_called_once_with(self.output, cache_roots=[self.output, self.source])
        self.assertEqual(self.source_files(), original)
        self.assertFalse((self.source / 'work').exists())
        self.assertFalse((self.output / 'avd').exists())
        self.assertFalse((self.output / 'tools/os4-core').exists())
        packed = dict(self.packs[0])
        for name, data in self.partitions.items():
            if name != 'system':
                self.assertEqual(packed[name], data)
        self.boot_mock.assert_called_once()
        self.assertIn('system/etc/hyperos-init-capabilities.sh', self.builds[0]['edits'])
        self.assertEqual(self.builds[0]['edits']['product/etc/init/lock_fps.sh'],
                         (current_refresh_script(), 0o755, 'u:object_r:system_file:s0'))
        self.assertEqual(json.loads((self.output / 'local/build.json').read_text())['boot_policy'], self.boot_receipt)
        self.assertEqual(json.loads((self.output / 'local/build.json').read_text())['kernelsu_marker_fix'],
                         self.ksu_receipt)
        self.assertEqual((self.output / 'images/ramdisk.img').read_bytes(), b'current quiet KernelSU boot image')
        self.ksu_mock.assert_called_once_with(self.output)
        self.patch_mock.assert_not_called()

    def test_pad_present_packed_hash_or_unknown_profile_refuses_before_copying_output(self):
        self.use_pad_profile()
        known = self.info.copy()
        self.mocked_pipeline(boot_kind='pad')
        for key, value in (('system_sha256', digest(b'foreign packed firmware')),
                           ('hyperos', 'OS4.999.0.0.UNKNOWN')):
            with self.subTest(key=key):
                self.info = dict(known, **{key: value})
                self.write_info()
                original = self.source_files()
                with self.assertRaises(RuntimeError):
                    prepare.prepare(self.source, self.output, 'os4-pad')
                self.assertEqual(self.source_files(), original)
                self.assertFalse(self.output.exists())
        self.assertEqual(self.cloned, [])
        self.assertEqual(self.builds, [])
        self.assertEqual(self.packs, [])

    def test_kernelsu_failure_cannot_publish_a_successful_release_receipt(self):
        original = self.source_files()
        self.mocked_pipeline()
        self.ksu_mock.side_effect = RuntimeError('Unverified KernelSU producer output')
        with self.assertRaisesRegex(RuntimeError, 'KernelSU producer output'):
            prepare.prepare(self.source, self.output)
        self.assertEqual(self.source_files(), original)
        self.assertFalse((self.output / 'local/build.json').exists())

    def test_pad_kernelsu_failure_cannot_publish_a_successful_release_receipt(self):
        import apply_app_compat
        self.use_pad_profile()
        self.entries['/system/build.prop'] = b'ro.adb.secure=0\nro.debuggable=0\nro.product.device=yingtian\n'
        original = self.source_files()
        self.mocked_pipeline(boot_kind='pad')
        self.ksu_mock.side_effect = RuntimeError('Unverified KernelSU producer output')
        with patch.object(apply_app_compat, 'prepare_prebuilt'), \
                self.assertRaisesRegex(RuntimeError, 'KernelSU producer output'):
            prepare.prepare(self.source, self.output, 'os4-pad')
        self.assertEqual(self.source_files(), original)
        self.assertFalse((self.output / 'local/build.json').exists())


class ReleaseKernelSUPreparationTests(unittest.TestCase):
    def setUp(self):
        import kernelsu_release as release
        from patch_kernelsu import receipt
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo, self.output = self.root / 'repo', self.root / 'output'
        self.directory = self.repo / 'tools' / release.DIRECTORY
        self.directory.mkdir(parents=True)
        self.contents = {name: ('official fixture: ' + name).encode() for name in release.ASSETS}
        for name, content in self.contents.items():
            (self.directory / name).write_bytes(content)
        self.pins = {name: digest(content) for name, content in self.contents.items()}
        self.receipt = receipt(release.ASSETS[release.LKM])
        self.stack = {'receipt': self.receipt, 'host': self.directory / 'ksud-aarch64-apple-darwin',
                      'lkm': self.output / 'work/quiet.ko'}
        for name in ('tools', 'work', 'images'):
            (self.output / name).mkdir(parents=True, exist_ok=True)
        (self.output / 'images/ramdisk.img').write_bytes(b'old boot')
        def mock(target):
            self.addCleanup(target.stop)
            return target.start()

        mock(patch.object(prepare, 'REPO_ROOT', self.repo))
        mock(patch.object(release, 'ASSETS', self.pins))
        self.producer = mock(patch('build_os4_official.prepare_kernelsu', return_value=self.stack))

        def patch_boot(output, stack):
            self.assertEqual(output, self.output)
            self.assertEqual(stack, self.stack)
            self.assertTrue((output / 'logs').is_dir())
            self.producer.assert_called_once_with(self.repo, self.output)
            (output / 'images/ramdisk.img').write_bytes(b'verified current quiet boot')

        self.boot = mock(patch('build_os4_official.patch_kernelsu_ramdisk', side_effect=patch_boot))

    def test_complete_offline_stack_drives_both_standard_producers(self):
        before = {path.name: path.read_bytes() for path in self.directory.iterdir()}
        self.assertEqual(prepare.prepare_release_kernelsu(self.output), self.receipt)
        self.assertEqual((self.output / 'images/ramdisk.img').read_bytes(), b'verified current quiet boot')
        self.assertEqual({path.name: path.read_bytes() for path in self.directory.iterdir()}, before)
        self.producer.assert_called_once_with(self.repo, self.output)
        self.boot.assert_called_once_with(self.output, self.stack)

    def test_missing_or_modified_offline_asset_refuses_before_producer(self):
        import kernelsu_release as release
        for kind in ('missing', 'modified', 'symlink', 'hardlink'):
            with self.subTest(kind=kind):
                path = self.directory / release.MANAGER
                if kind == 'missing':
                    path.unlink()
                elif kind == 'modified':
                    path.write_bytes(b'unknown')
                elif kind == 'symlink':
                    path.unlink()
                    path.symlink_to(self.directory / release.LKM)
                else:
                    os.link(path, self.root / 'aliased-apk')
                with self.assertRaises((RuntimeError, OSError)):
                    prepare.prepare_release_kernelsu(self.output)
                self.producer.assert_not_called()
                self.boot.assert_not_called()
                self.assertFalse((self.output / 'logs').exists())
                if kind == 'hardlink':
                    (self.root / 'aliased-apk').unlink()
                if path.exists() or path.is_symlink():
                    path.unlink()
                path.write_bytes(self.contents[release.MANAGER])

    def test_partial_or_unknown_copied_stack_refuses_before_producer(self):
        import kernelsu_release as release
        directory = self.output / 'tools' / release.DIRECTORY
        directory.mkdir()
        for name, content in self.contents.items():
            (directory / name).write_bytes(content)
        manager = directory / release.MANAGER
        manager.unlink()
        with self.assertRaises(OSError):
            prepare.prepare_release_kernelsu(self.output)
        manager.write_bytes(self.contents[release.MANAGER])
        host = directory / 'ksud-aarch64-apple-darwin'
        host.write_bytes(b'unknown host producer')
        with self.assertRaisesRegex(RuntimeError, 'official pin'):
            prepare.prepare_release_kernelsu(self.output)
        self.assertEqual(host.read_bytes(), b'unknown host producer')
        self.producer.assert_not_called()
        self.boot.assert_not_called()

    def test_complete_copied_stack_is_authenticated_before_producers(self):
        import kernelsu_release as release
        directory = self.output / 'tools' / release.DIRECTORY
        directory.mkdir()
        for name, content in self.contents.items():
            (directory / name).write_bytes(content)
        self.assertEqual(prepare.prepare_release_kernelsu(self.output), self.receipt)
        self.boot.assert_called_once_with(self.output, self.stack)

    def test_valid_consumer_stack_allows_standard_producer_to_add_host_asset(self):
        import kernelsu_release as release
        directory = self.output / 'tools' / release.DIRECTORY
        directory.mkdir()
        for name in release.RUNTIME_ASSETS:
            (directory / name).write_bytes(self.contents[name])
        self.assertFalse((directory / 'ksud-aarch64-apple-darwin').exists())
        self.assertEqual(prepare.prepare_release_kernelsu(self.output), self.receipt)
        self.producer.assert_called_once_with(self.repo, self.output)
        self.boot.assert_called_once_with(self.output, self.stack)

    def test_unknown_existing_logs_leaf_is_preserved_before_producers(self):
        (self.output / 'logs').write_bytes(b'custom log leaf')
        with self.assertRaisesRegex(RuntimeError, 'unknown release KernelSU log'):
            prepare.prepare_release_kernelsu(self.output)
        self.assertEqual((self.output / 'logs').read_bytes(), b'custom log leaf')
        self.producer.assert_not_called()
        self.boot.assert_not_called()

    def test_aliased_logs_directory_is_preserved_before_producers(self):
        elsewhere = self.root / 'other-logs'
        elsewhere.mkdir()
        (self.output / 'logs').symlink_to(elsewhere, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, 'unknown release KernelSU log'):
            prepare.prepare_release_kernelsu(self.output)
        self.assertEqual(list(elsewhere.iterdir()), [])
        self.assertTrue((self.output / 'logs').is_symlink())
        self.producer.assert_not_called()
        self.boot.assert_not_called()


class IncrementalReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def bundle(self, root, version, system):
        import bundle_runtime
        payloads = {name: name.encode() for name in (
            'config/avd.ini', 'images/encryptionkey.img', bundle_runtime.ENTRYPOINT,
            'runtime/scripts/manage.py', 'runtime/scripts/setup.py', 'runtime/scripts/common.py',
            'tools/os4-core/context.json', 'tools/os4-core/receipt.json',
            'tools/os4-app-compat/app-compat.zip', 'tools/os4-app-compat/receipt.json')}
        payloads['images/system.img'] = system
        paths = {}
        for name, data in payloads.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            paths[name] = path
        manifest = {'project': 'HyperOS-AVD', 'format': 3, 'platform': 'macos-arm64',
            'version': version, 'variant': 'os4-official', 'source': 'official-hongkong-ota',
            'source_device': 'hongkong', 'android_api': 37, 'hyperos': '4.0.24.0.XFRCNXM',
            'build': {'source': 'official-hongkong-ota', 'android_api': 37,
                'hyperos': '4.0.24.0.XFRCNXM', 'adb_authentication': True,
                'archive_sha256': 'a' * 64, 'kernel_page_size': 4096,
                'hardware_base_api': 36, 'kernel_kmi': 'android15-6.6'},
            'compatibility': {'install_protocol': bundle_runtime.INSTALL_PROTOCOL,
                'minimum_installer': bundle_runtime.PROTOCOL_MINIMUM,
                'userdata_family': 'os4-hongkong-api37-ranchu-4k', 'runtime_in_bundle': True},
            'files': {name: {'size': len(data), 'sha256': digest(data)}
                      for name, data in payloads.items()},
            'parts': [{'name': 'full.tar.gz.part001', 'size': 2 * 1024**2, 'sha256': 'b' * 64}]}
        (root / 'manifest.json').write_text(json.dumps(manifest))
        return manifest, paths

    def test_block_codec_reuses_moved_ranges_and_handles_file_sizes(self):
        block = incremental.BLOCK
        original = os.urandom(block * 4)
        source, target = self.root / 'source', self.root / 'target'
        source.write_bytes(original)
        cases = [(source, b'new-prefix'.ljust(block, b'!') + original + b'new tail'),
                 (source, original[:block]), (source, b''), (None, b'new file'),
                 (None, b'')]
        for previous, content in cases:
            with self.subTest(size=len(content), source=previous is not None):
                target.write_bytes(content)
                patch_data = io.BytesIO()
                incremental.write_patch(previous, target, patch_data)
                self.assertLessEqual(len(patch_data.getvalue()), incremental.patch_limit(len(content)))
                restored = io.BytesIO()
                incremental.apply_patch(previous, io.BytesIO(patch_data.getvalue()), restored,
                    len(original) if previous else 0, len(content))
                self.assertEqual(restored.getvalue(), content)
                if len(content) > len(original):
                    self.assertLess(len(patch_data.getvalue()), block + 256)
                    self.assertIn(b'C' + struct.pack('<QQ', 0, len(original)), patch_data.getvalue())
        # Model a large image's sparse source index while shifting EROFS data by
        # one 4 KiB page. The first indexed source anchor is absent from target.
        original = os.urandom(1024**2)
        source.write_bytes(original)
        content = b'new-prefix'.ljust(8192, b'!') + original[4096:]
        target.write_bytes(content)
        patch_data = io.BytesIO()
        with patch.object(incremental, 'MAX_INDEX_BLOCKS', 16):
            incremental.write_patch(source, target, patch_data)
        self.assertLess(len(patch_data.getvalue()), 128 * 1024)
        self.assertIn(b'C' + struct.pack('<QQ', 65536, len(original) - 65536), patch_data.getvalue())
        restored = io.BytesIO()
        incremental.apply_patch(source, io.BytesIO(patch_data.getvalue()), restored,
                                len(original), len(content))
        self.assertEqual(restored.getvalue(), content)

    def test_patch_parser_rejects_corruption_expansion_and_aliases(self):
        source = self.root / 'source'
        source.write_bytes(b'abcd')
        header = incremental.MAGIC + struct.pack('<QQ', 4, 4)
        invalid = [b'', header[:-1], b'wrong' + header, header + b'X', header + b'E',
            header + b'C' + struct.pack('<QQ', 1, 4) + b'E',
            header + b'C' + struct.pack('<QQ', 0, 0) + b'E',
            header + b'D' + struct.pack('<Q', 5) + b'abcdeE',
            header + b'D' + struct.pack('<Q', 4) + b'ab',
            header + b'D' + struct.pack('<Q', 4) + b'abcdEtrailing']
        for data in invalid:
            with self.subTest(data=data), self.assertRaises(RuntimeError):
                incremental.apply_patch(source, io.BytesIO(data), io.BytesIO(), 4, 4)
        for alias in ('symlink', 'hardlink'):
            path = self.root / alias
            if alias == 'symlink':
                path.symlink_to(source)
            else:
                os.link(source, path)
            with self.subTest(alias=alias), self.assertRaises(RuntimeError):
                incremental.apply_patch(path, io.BytesIO(header + b'E'), io.BytesIO(), 4, 4)
            path.unlink()

    def test_same_base_validation_rejects_provenance_and_version_changes(self):
        old, _ = self.bundle(self.root / 'old', 'v1.0.0-a17-hyperos4-hongkong-r1', b'old')
        new, _ = self.bundle(self.root / 'new', 'v1.0.1-a17-hyperos4-hongkong-r2', b'new')
        incremental.validate_sources(old, new)
        revised = copy.deepcopy(old)
        revised['version'] = 'v1.0.0-a17-hyperos4-hongkong-r1.1'
        incremental.validate_sources(old, revised)
        following = copy.deepcopy(revised)
        following['version'] = 'v1.0.0-a17-hyperos4-hongkong-r1.2'
        incremental.validate_sources(revised, following)
        equivalent = copy.deepcopy(revised)
        equivalent['version'] = 'v1.0.0-a17-hyperos4-hongkong-r1.1.0'
        with self.assertRaisesRegex(RuntimeError, 'newer release'):
            incremental.validate_sources(revised, equivalent)
        with self.assertRaisesRegex(RuntimeError, 'newer release'):
            incremental.validate_sources(revised, old)
        changes = [('build', 'archive_sha256', 'c' * 64), ('build', 'archive_sha256', ''),
            ('build', 'kernel_page_size', 16384), ('build', 'kernel_kmi', 'different'),
            ('build', 'hardware_base_api', 37), ('compatibility', 'userdata_family', 'different'),
            (None, 'hyperos', '4.0.25.0.XFRCNXM'),
            (None, 'version', old['version']),
            (None, 'version', 'v0.9.9-a17-hyperos4-hongkong-r2')]
        for section, name, value in changes:
            invalid = copy.deepcopy(new)
            (invalid[section] if section else invalid)[name] = value
            with self.subTest(section=section, name=name), self.assertRaises(RuntimeError):
                incremental.validate_sources(old, invalid)
        new['files']['images/encryptionkey.img']['sha256'] = 'd' * 64
        with self.assertRaisesRegex(RuntimeError, 'encryption template'):
            incremental.validate_sources(old, new)

    def test_delta_archive_roundtrip_and_source_manifest_locations(self):
        import bundle_runtime
        old, _ = self.bundle(self.root / 'old', 'v1.0.0-a17-hyperos4-hongkong-r1', b'a' * incremental.BLOCK)
        new, paths = self.bundle(self.root / 'new', 'v1.0.1-a17-hyperos4-hongkong-r2',
                                 b'b' * incremental.BLOCK + b'a' * incremental.BLOCK)
        name = 'runtime/scripts/new_module.py'
        paths[name] = self.root / 'new' / name
        paths[name].write_bytes(b'# new module\n')
        new['files'][name] = {'size': paths[name].stat().st_size, 'sha256': digest(paths[name].read_bytes())}
        original_manifest = copy.deepcopy(new)
        for location in ('manifest.json', 'local/installed-release.json'):
            source_manifest = self.root / 'old' / location
            source_manifest.parent.mkdir(exist_ok=True)
            source_manifest.write_text(json.dumps(old))
            output = self.root / ('output-' + source_manifest.name)
            output.mkdir()
            descriptor = incremental.write_delta(output, new, paths, source_manifest, part_mib=1)
            self.assertEqual(set(descriptor), {'protocol', 'from_version', 'from_manifest_sha256', 'parts'})
            self.assertEqual(descriptor['from_manifest_sha256'], bundle_runtime.manifest_digest(old))
            archive = b''.join((output / item['name']).read_bytes() for item in descriptor['parts'])
            with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as packed:
                self.assertEqual(set(packed.getnames()), {'images/system.img', name})
                for member in packed:
                    old_info = old['files'].get(member.name)
                    source = self.root / 'old' / member.name if old_info else None
                    result = io.BytesIO()
                    incremental.apply_patch(source, packed.extractfile(member), result,
                        old_info['size'] if old_info else 0, new['files'][member.name]['size'])
                    self.assertEqual(result.getvalue(), paths[member.name].read_bytes())
            self.assertEqual(new, original_manifest)

    def test_delta_headers_support_large_images_and_ustar_path_prefixes(self):
        import delta_install
        names = ('images/system.img', 'runtime/' + 'a' * 90 + '/' + 'module.py')
        for name in names:
            for size in (8**11 - 1, 8**11, 8745123840):
                with self.subTest(name=name, size=size):
                    entry = incremental._PatchMember(name)
                    entry.size = size
                    header = entry.tobuf()
                    self.assertEqual(len(header), tarfile.BLOCKSIZE)
                    with tarfile.open(fileobj=io.BytesIO(header), mode='r|',
                                      tarinfo=delta_install._RegularMember) as archive:
                        member = next(iter(archive))
                        self.assertEqual((member.name, member.size), (name, size))
                        self.assertTrue(member.isfile())

    def test_full_bundle_includes_delta_and_all_archive_checksums(self):
        import bundle_runtime
        import package_release
        content = os.urandom(incremental.BLOCK * 4)
        old, _ = self.bundle(self.root / 'old', 'v1.0.0-a17-hyperos4-hongkong-r1', content)
        new, paths = self.bundle(self.root / 'new', 'v1.0.1-a17-hyperos4-hongkong-r2',
                                 b'changed'.ljust(incremental.BLOCK, b'!') + content[incremental.BLOCK:])
        output = self.root / 'release'
        manifest = package_release.write_bundle(output, new['version'], new, paths,
            part_mib=1, delta_from=[self.root / 'old/manifest.json'])
        descriptor, = manifest['deltas']
        self.assertEqual(descriptor['from_manifest_sha256'], bundle_runtime.manifest_digest(old))
        self.assertEqual(manifest['compatibility']['minimum_installer'], '1.2.3')
        checksums = dict(line.split('  ', 1)[::-1]
                         for line in (output / 'SHA256SUMS').read_text().splitlines())
        assets = [*manifest['parts'], *descriptor['parts']]
        self.assertEqual(set(checksums), {part['name'] for part in assets} | {'manifest.json'})
        for part in assets:
            self.assertEqual(checksums[part['name']], part['sha256'])
            self.assertEqual(digest((output / part['name']).read_bytes()), part['sha256'])
        self.assertEqual(checksums['manifest.json'], digest((output / 'manifest.json').read_bytes()))
        self.assertEqual(json.loads((output / 'manifest.json').read_text()), manifest)

    def test_delta_only_bundle_embeds_full_base_without_creating_full_archive(self):
        import bundle_runtime
        import package_release
        old, paths = self.bundle(self.root / 'old', 'v1.0.0-a17-hyperos4-hongkong-r6', b'unchanged image')
        metadata = copy.deepcopy(old)
        version = 'v1.0.0-a17-hyperos4-hongkong-r6.1'
        replacement = self.root / 'fixed-manage.py'
        replacement.write_bytes(b'# fixed installer runtime\n')
        paths['runtime/scripts/manage.py'] = replacement
        output = self.root / 'release'
        original = copy.deepcopy(metadata)
        with patch.object(package_release, 'sha256', wraps=package_release.sha256) as hashes:
            manifest = package_release.write_bundle(output, version, metadata, paths,
                part_mib=1, delta_from=[self.root / 'old/manifest.json'], delta_only=True)
        self.assertEqual(metadata, original)
        self.assertEqual(manifest['parts'], [])
        self.assertEqual(manifest['distribution'], bundle_runtime.DELTA_DISTRIBUTION)
        self.assertEqual(manifest['compatibility']['minimum_installer'], bundle_runtime.DELTA_MINIMUM)
        self.assertEqual(manifest['base_release'], {
            'manifest': old, 'manifest_sha256': bundle_runtime.manifest_digest(old)})
        self.assertNotIn(self.root / 'old/images/system.img', [call.args[0] for call in hashes.call_args_list])
        descriptor, = manifest['deltas']
        assets = {part['name'] for part in descriptor['parts']}
        self.assertEqual({path.name for path in output.iterdir()}, assets | {'manifest.json', 'SHA256SUMS'})
        self.assertTrue(all('-from-' in name and '-delta.tar.gz.part' in name for name in assets))
        archive = b''.join((output / part['name']).read_bytes() for part in descriptor['parts'])
        with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as packed:
            self.assertEqual(packed.getnames(), ['runtime/scripts/manage.py'])
            result = io.BytesIO()
            info = old['files']['runtime/scripts/manage.py']
            incremental.apply_patch(self.root / 'old/runtime/scripts/manage.py',
                packed.extractfile('runtime/scripts/manage.py'), result,
                info['size'], len(replacement.read_bytes()))
            self.assertEqual(result.getvalue(), replacement.read_bytes())
        checksums = dict(line.split('  ', 1)[::-1]
                         for line in (output / 'SHA256SUMS').read_text().splitlines())
        self.assertEqual(set(checksums), assets | {'manifest.json'})
        bundle_runtime.validate_envelope(manifest)
        # The delta may exceed a tiny full archive. Delta-only distributions
        # have no target full archive to fall back to or compare against.
        self.assertGreater(sum(part['size'] for part in descriptor['parts']), 1)

    def test_delta_only_requires_one_full_base_and_authenticates_reused_images(self):
        import package_release
        old, paths = self.bundle(self.root / 'old', 'v1.0.0-a17-hyperos4-hongkong-r6', b'accepted image')
        version = 'v1.0.0-a17-hyperos4-hongkong-r6.1'
        previous = self.root / 'old/manifest.json'
        for sources in ([], [previous, previous]):
            output = self.root / 'invalid-count'
            with self.subTest(sources=sources), self.assertRaisesRegex(RuntimeError, 'exactly one'):
                package_release.write_bundle(output, version, old, paths,
                    delta_from=sources, delta_only=True)
            self.assertFalse(output.exists())
        released = self.root / 'first-release'
        derived = package_release.write_bundle(released, version, old, paths,
            delta_from=[previous], delta_only=True)
        chained = self.root / 'chained-release'
        with self.assertRaisesRegex(RuntimeError, 'full base release'):
            package_release.write_bundle(chained, 'v1.0.0-a17-hyperos4-hongkong-r6.2',
                derived, paths, delta_from=[released / 'manifest.json'], delta_only=True)
        self.assertFalse(chained.exists())
        # Even when inventory construction reuses an authenticated source entry,
        # real archive generation checks all source bytes again.
        paths['images/system.img'].write_bytes(b'tampered image')
        output = self.root / 'tampered-release'
        with self.assertRaisesRegex(RuntimeError, 'differs from its manifest'):
            package_release.write_bundle(output, version, old, paths,
                delta_from=[previous], delta_only=True)
        self.assertFalse((output / 'manifest.json').exists())
        self.assertEqual(list(output.iterdir()), [])

    def test_unhelpful_or_invalid_delta_cleans_only_created_assets(self):
        old, _ = self.bundle(self.root / 'old', 'v1.0.0-a17-hyperos4-hongkong-r1', b'old')
        new, paths = self.bundle(self.root / 'new', 'v1.0.1-a17-hyperos4-hongkong-r2', b'new')
        output = self.root / 'output'
        output.mkdir()
        sentinel = output / 'existing.part001'
        sentinel.write_bytes(b'preserve')
        new['parts'][0]['size'] = 1
        self.assertIsNone(incremental.write_delta(output, new, paths, self.root / 'old/manifest.json'))
        self.assertEqual(list(output.iterdir()), [sentinel])
        new['parts'][0]['size'] = 2 * 1024**2
        (self.root / 'old/images/system.img').write_bytes(b'tampered source')
        with self.assertRaisesRegex(RuntimeError, 'differs from its manifest'):
            incremental.write_delta(output, new, paths, self.root / 'old/manifest.json')
        self.assertEqual(list(output.iterdir()), [sentinel])
        self.assertEqual(sentinel.read_bytes(), b'preserve')


class SharedFlutterPreparationTests(unittest.TestCase):
    def test_real_previous_engine_migrates_to_the_current_verified_output(self):
        original_pin = phone_profile.profile('4.0.18.0.XFRCNXM')['pins']['flutter']
        profile = patch_flutter.PROFILES[original_pin]
        path = Path(os.environ.get('HYPEROS_AVD_FLUTTER18_ARTIFACT', str(
            REPO / 'work/os4-r3-build/input/hongkong-4.0.18/flutter.bin')))
        if not path.is_file():
            self.skipTest('Original proprietary OTA engine is not distributed in Git.')
        original = path.read_bytes()
        self.assertEqual(digest(original), original_pin)
        current = patch_flutter.patch(original)
        previous = bytearray(current)
        offset = profile['glyph_raster_site']
        previous[offset:offset + 4] = original[offset:offset + 4]
        self.assertIn(digest(previous), profile['legacy'])
        fixed, receipt = prepare.refresh_shared_flutter(bytes(previous),
            phone_profile.profile('4.0.18.0.XFRCNXM'))
        self.assertEqual(fixed, current)
        self.assertEqual(receipt, {'before': original_pin, 'after': profile['output']})
        self.assertEqual(prepare.refresh_shared_flutter(fixed,
            phone_profile.profile('4.0.18.0.XFRCNXM')), (fixed, receipt))

    def test_unknown_shared_engine_retains_the_existing_patcher_guard(self):
        with self.assertRaisesRegex(RuntimeError, 'Unsupported Flutter engine'):
            prepare.refresh_shared_flutter(b'unverified engine', phone_profile.profile())


if __name__ == '__main__':
    unittest.main()
