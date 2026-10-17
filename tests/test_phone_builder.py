"""Consolidated unit tests for OS4 Phone build subsystem:
builder hardware isolation, profile identity & pins, and Vulkan / HWUI native support.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
ROOT = REPO
sys.path.insert(0, str(REPO / 'scripts'))

import build_os4_official as builder
from build_os4_official import (archive_digest, avd_template, candidate_defaults,
                                native_hwui, phone_renderer, renderer_init,
                                renderer_properties, validate_candidate,
                                validate_workspace_firmware)
from launch import vulkan_features
from os4_defaults import apply_gradient_blur_runtime
from patch_pad_hwui import (AFTER, BEFORE, PHONE_AFTER, PHONE_BEFORE, PHONE_PROFILE,
                            PROFILES, patch as patch_hwui, preload_symbol)
from phone_profile import (ARCHIVES, LEGACY_PINS, PIN_PATHS, PROP_PATHS, identity_values,
                           modern_runtime, profile, profile_for_archive,
                           profile_from_build, verify_source)

# --- tests/test_phone_builder.py ---

'Verify phone OTA build isolation and the published hardware contract.'

class PhoneBuilderIsolationTests(unittest.TestCase):

    def test_new_source_defaults_do_not_reuse_the_existing_phone_workspace(self):
        old = candidate_defaults({'hyperos': '4.0.17.0.XFRCNXM'}, REPO)
        new = candidate_defaults({'hyperos': '4.0.18.0.XFRCNXM'}, REPO)
        self.assertEqual(old, (REPO / 'work/os4-official', 'HyperOS_4_Official_API_37', 5574))
        self.assertEqual(new, (REPO / 'work/os4-r3-build', 'HyperOS_4_R3_API_37', 5584))
        latest = candidate_defaults({'hyperos': '4.0.24.0.XFRCNXM'}, REPO)
        self.assertEqual(latest, (REPO / 'work/os4-r6-build', 'HyperOS_4_R6_API_37', 5584))
        self.assertNotEqual(latest[0], old[0])
        self.assertNotEqual(latest[0], new[0])
        self.assertTrue(all((previous != candidate for previous, candidate in zip(old, new))))
        with self.assertRaisesRegex(RuntimeError, 'No isolated build defaults'):
            candidate_defaults({'hyperos': 'unverified'}, REPO)

    def test_foreign_registration_is_refused_and_its_bytes_are_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            home, workspace = (folder / 'registry', folder / 'new-workspace')
            home.mkdir()
            registry = home / 'Existing_Pixel.ini'
            original = ('avd.ini.encoding=UTF-8\npath=' + str(folder / 'another-workspace/Pixel.avd') + '\ntarget=android-36\n').encode()
            registry.write_bytes(original)
            with self.assertRaisesRegex(RuntimeError, 'belongs to another workspace'):
                validate_candidate('Existing_Pixel', 5584, workspace, home)
            self.assertEqual(registry.read_bytes(), original)
            self.assertFalse(workspace.exists())

    def test_owned_or_new_registration_is_only_inspected(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            home, workspace = (folder / 'registry', folder / 'new-workspace')
            home.mkdir()
            registry = home / 'My_Renamed_AVD.ini'
            original = ('path=' + str(workspace / 'avd/My_Renamed_AVD.avd') + '\n').encode()
            registry.write_bytes(original)
            validate_candidate('My_Renamed_AVD', 5584, workspace, home)
            validate_candidate('Another_Renamed_AVD', 5586, workspace, home)
            self.assertEqual(registry.read_bytes(), original)
            self.assertFalse((home / 'Another_Renamed_AVD.ini').exists())
            self.assertFalse(workspace.exists())

    def test_invalid_names_and_ports_cannot_escape_the_candidate(self):
        for name in ('../Pixel', 'AVD/Pixel', '', '-AVD', 'two words', 'a' * 65, None):
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, 'ASCII AVD name'):
                validate_candidate(name, 5584, REPO / 'work/test')
        for port in (5554, 5557, 5684, True, '5584', None):
            with self.subTest(port=port), self.assertRaisesRegex(RuntimeError, 'even emulator console port'):
                validate_candidate('Renamed_AVD', port, REPO / 'work/test')

    def test_archive_digest_uses_the_exact_original_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'source.zip'
            data = bytes(range(256)) * 40000
            path.write_bytes(data)
            self.assertEqual(archive_digest(path), hashlib.sha256(data).hexdigest())
            path.write_bytes(data + b'changed')
            self.assertNotEqual(archive_digest(path), hashlib.sha256(data).hexdigest())

    def test_help_exposes_safe_controls_without_importing_a_source_profile(self):
        result = subprocess.run([sys.executable, str(REPO / 'scripts/build_os4_official.py'), '--help'], check=True, capture_output=True, text=True, timeout=10)
        for option in ('--name', '--port', '--no-configure', '--workspace', '--partitions'):
            self.assertIn(option, result.stdout)

    def test_r3_build_refuses_retained_userdata_without_verified_matching_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / 'existing'
            avd = workspace / 'avd/User_Renamed.avd'
            avd.mkdir(parents=True)
            (avd / 'userdata-qemu.img.qcow2').write_bytes(b'retained encrypted userdata overlay')
            (workspace / 'local').mkdir()
            saved_path = workspace / 'local/build.json'
            current = {'source': 'official-hongkong-ota', 'hyperos': '4.0.18.0.XFRCNXM', 'archive_sha256': ARCHIVES['4.0.18.0.XFRCNXM']}
            invalid = (None, '{invalid', [], {}, {**current, 'hyperos': '4.0.17.0.XFRCNXM', 'archive_sha256': ARCHIVES['4.0.17.0.XFRCNXM']}, {**current, 'source': 'official-yingtian-ota'}, {**current, 'archive_sha256': 'f' * 64}, {key: value for key, value in current.items() if key != 'source'})
            for saved in invalid:
                with self.subTest(saved=saved):
                    if saved is None:
                        saved_path.unlink(missing_ok=True)
                    else:
                        saved_path.write_text(saved if isinstance(saved, str) else json.dumps(saved))
                    before = {path.relative_to(workspace): path.read_bytes() for path in workspace.rglob('*') if path.is_file()}
                    with self.assertRaisesRegex(RuntimeError, 'Installer 1.2.0 Upgrade or Recover'):
                        validate_workspace_firmware(profile('4.0.18.0.XFRCNXM'), workspace)
                    self.assertEqual({path.relative_to(workspace): path.read_bytes() for path in workspace.rglob('*') if path.is_file()}, before)

    def test_same_r3_rebuild_and_fresh_workspace_remain_supported_without_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / 'existing'
            validate_workspace_firmware(profile('4.0.18.0.XFRCNXM'), workspace)
            self.assertFalse(workspace.exists())
            avd = workspace / 'avd/User_Renamed.avd'
            avd.mkdir(parents=True)
            data = avd / 'userdata-qemu.img'
            data.write_bytes(b'retained encrypted userdata')
            (workspace / 'local').mkdir()
            saved_path = workspace / 'local/build.json'
            saved_path.write_text(json.dumps({'source': 'official-hongkong-ota', 'hyperos': '4.0.18.0.XFRCNXM', 'archive_sha256': ARCHIVES['4.0.18.0.XFRCNXM']}))
            before = {path.relative_to(workspace): path.read_bytes() for path in workspace.rglob('*') if path.is_file()}
            validate_workspace_firmware(profile('4.0.18.0.XFRCNXM'), workspace)
            self.assertEqual({path.relative_to(workspace): path.read_bytes() for path in workspace.rglob('*') if path.is_file()}, before)

    def test_r2_rebuild_requires_matching_identity_and_refuses_downgrade(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / 'renamed-phone'
            avd = workspace / 'avd/Renamed.avd'
            avd.mkdir(parents=True)
            (avd / 'userdata-qemu.img').write_bytes(b'user data')
            (workspace / 'local').mkdir()
            receipt = workspace / 'local/build.json'
            for version in ('4.0.18.0.XFRCNXM', '4.0.17.0.XFRCNXM'):
                receipt.write_text(json.dumps({'source': 'official-hongkong-ota', 'hyperos': version, 'archive_sha256': ARCHIVES[version]}))
                before = {path.relative_to(workspace): path.read_bytes() for path in workspace.rglob('*') if path.is_file()}
                if version == '4.0.18.0.XFRCNXM':
                    with self.assertRaisesRegex(RuntimeError, 'verified matching'):
                        validate_workspace_firmware(profile('4.0.17.0.XFRCNXM'), workspace)
                else:
                    validate_workspace_firmware(profile(version), workspace)
                self.assertEqual({path.relative_to(workspace): path.read_bytes() for path in workspace.rglob('*') if path.is_file()}, before)

    def test_no_configure_cannot_bypass_guard_before_archive_extract_or_environment_change(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / 'existing-r2'
            avd = workspace / 'avd/User_Renamed.avd'
            avd.mkdir(parents=True)
            data = avd / 'userdata-qemu.img'
            data.write_bytes(b'retained encrypted userdata')
            (workspace / 'local').mkdir()
            saved_path = workspace / 'local/build.json'
            saved_path.write_text(json.dumps({'source': 'official-hongkong-ota', 'hyperos': '4.0.17.0.XFRCNXM', 'archive_sha256': ARCHIVES['4.0.17.0.XFRCNXM']}))
            before = {path.relative_to(workspace): path.read_bytes() for path in workspace.rglob('*') if path.is_file()}
            previous = os.environ.get('HYPEROS_AVD_WORKSPACE')
            with patch.object(sys, 'argv', ['build_os4_official.py', '--zip', str(Path(temporary) / 'r3.zip'), '--workspace', str(workspace), '--no-configure']), patch.object(builder, 'archive_digest', return_value=ARCHIVES['4.0.18.0.XFRCNXM']), patch.object(builder.zipfile, 'ZipFile') as archive, patch.object(builder.subprocess, 'run') as extract:
                with self.assertRaisesRegex(RuntimeError, '--no-configure'):
                    builder.main()
            archive.assert_not_called()
            extract.assert_not_called()
            self.assertEqual(os.environ.get('HYPEROS_AVD_WORKSPACE'), previous)
            self.assertEqual({path.relative_to(workspace): path.read_bytes() for path in workspace.rglob('*') if path.is_file()}, before)

class PhoneBuilderHardwareTests(unittest.TestCase):

    def test_vulkan_is_selected_only_for_r3_and_legacy_r2_stays_reproducible(self):
        previous = profile('4.0.17.0.XFRCNXM')
        candidate = profile('4.0.18.0.XFRCNXM')
        self.assertEqual(phone_renderer(previous), 'skiagl')
        self.assertEqual(renderer_properties(previous), b'ro.mediaserver.64b.enable=true\ndebug.hwui.renderer=skiagl\ndebug.renderengine.backend=skiavkthreaded\n')
        self.assertEqual(renderer_init(previous), b'    setprop debug.renderengine.backend skiavkthreaded\n')
        self.assertEqual(phone_renderer(candidate), 'skiavk')
        self.assertIn(b'debug.hwui.renderer=skiavk\n', renderer_properties(candidate))
        self.assertEqual(renderer_init(candidate), b'    setprop debug.hwui.renderer skiavk\n    setprop debug.renderengine.backend skiavkthreaded\n')
        latest = profile('4.0.24.0.XFRCNXM')
        self.assertEqual(renderer_properties(latest), renderer_properties(candidate))
        self.assertEqual(renderer_init(latest), renderer_init(candidate))
        with self.assertRaisesRegex(RuntimeError, 'No verified phone renderer'):
            phone_renderer({'hyperos': 'unknown'})

    def test_native_replacement_refuses_an_unpinned_source_before_patching(self):
        from phone_profile import profile
        for version in ARCHIVES:
            with self.subTest(version=version), self.assertRaisesRegex(RuntimeError, 'HWUI source'):
                native_hwui(profile(version), b'unknown firmware native library')

    def test_both_firmware_versions_use_the_same_r2_hardware(self):
        original = (REPO / 'config/avd.ini').read_text()
        expected = {'target': 'android-37.0', 'hw.cpu.arch': 'arm64', 'hw.cpu.ncore': '4', 'hw.ramSize': '6144', 'disk.dataPartition.size': '32G', 'hw.lcd.width': '1120', 'hw.lcd.height': '2436', 'hw.lcd.density': '480', 'hw.camera.back': 'virtualscene', 'hw.camera.front': 'emulated', 'hw.audioOutput': 'yes', 'kernel.parameters': 'androidboot.selinux=enforcing'}
        for version in ARCHIVES:
            with self.subTest(version=version):
                selected = profile(version)
                template = avd_template(original, selected)
                values = dict((line.split('=', 1) for line in template.splitlines() if '=' in line))
                self.assertEqual({key: values[key] for key in expected}, expected)
                self.assertTrue(all((key not in values for key in ('path', 'path.rel', 'image.sysdir.1'))))
        self.assertEqual((REPO / 'config/avd.ini').read_text(), original)

if __name__ == '__main__':
    unittest.main()


# --- tests/test_phone_profile.py ---

'Reject mixed OTA identities and preserve partition-specific public values.'

class PhoneProfileTests(unittest.TestCase):

    def fixture_partitions(self, directory, version='4.0.18.0.XFRCNXM'):
        value = profile(version)
        value['source_partition_sha256'] = {}
        for part in set(PROP_PATHS) | {'mi_product'}:
            body = part.encode()
            (Path(directory) / (part + '.img')).write_bytes(body)
            value['source_partition_sha256'][part] = hashlib.sha256(body).hexdigest()
        return value

    def test_stale_mi_product_and_incomplete_partition_map_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            value = self.fixture_partitions(directory)
            (Path(directory) / 'mi_product.img').write_bytes(b'stale previous firmware')
            with patch('build_image.erofs') as read:
                with self.assertRaisesRegex(RuntimeError, 'partition: mi_product'):
                    verify_source(value, directory, b'')
                read.assert_not_called()
            del value['source_partition_sha256']['mi_product']
            with self.assertRaisesRegex(RuntimeError, 'partition pins'):
                verify_source(value, directory, b'')

    def test_empty_or_partial_native_pins_are_refused_before_reading_files(self):
        with tempfile.TemporaryDirectory() as directory:
            value = self.fixture_partitions(directory)
            for pins in ({}, {'hwui': value['pins']['hwui']}):
                with self.subTest(pins=pins), patch('build_image.erofs') as read:
                    value['pins'] = pins
                    with self.assertRaisesRegex(RuntimeError, 'source pins'):
                        verify_source(value, directory, b'')
                    read.assert_not_called()

    def test_new_build_cannot_omit_archive_identity(self):
        for version in ('4.0.18.0.XFRCNXM', '4.0.24.0.XFRCNXM'):
            with self.subTest(version=version), self.assertRaisesRegex(RuntimeError, 'archive identity'):
                profile_from_build({'source': 'official-hongkong-ota', 'hyperos': version})

    def test_registered_sources_have_complete_pins_and_preserve_legacy_contract(self):
        for version, digest in ARCHIVES.items():
            with self.subTest(version=version):
                value = profile_for_archive(digest)
                self.assertEqual(value, profile(version))
                self.assertEqual(value['hyperos'], version)
                self.assertEqual(value['archive_sha256'], digest)
                self.assertEqual(value['source'], 'OS' + version + ' official OTA')
                legacy = version == '4.0.17.0.XFRCNXM'
                self.assertEqual(set(value['pins']), set(LEGACY_PINS if legacy else PIN_PATHS))
                self.assertEqual(set(value['source_partition_sha256']), {'mi_product'} if legacy else set(PROP_PATHS) | {'mi_product'})
                self.assertEqual(set(value['source_sha256']), {part + '.build.prop' for part in PROP_PATHS} | {'ota.metadata'})
                for checksum in (digest, value['model_xml_sha256'], *value['pins'].values(), *value['source_sha256'].values(), *value['source_partition_sha256'].values()):
                    self.assertRegex(checksum, '^[0-9a-f]{64}$')
                self.assertEqual(hashlib.sha256(Path(value['model_xml']).read_bytes()).hexdigest(), value['model_xml_sha256'])
                self.assertEqual(value['display'], {'width': 1120, 'height': 2436, 'density': 480})
                self.assertFalse({'ro.boot.hardware', 'ro.hardware', 'ro.hardware.egl'} & value['properties'].keys())
                self.assertEqual(profile_from_build({'source': 'official-hongkong-ota', 'hyperos': version, 'archive_sha256': digest}), value)
        legacy = profile()
        self.assertEqual(legacy['pins'], LEGACY_PINS)
        self.assertEqual(profile_from_build({'source': 'official-hongkong-ota'}), legacy)

    def test_new_firmware_cannot_reuse_legacy_partial_partition_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            value = self.fixture_partitions(directory, '4.0.24.0.XFRCNXM')
            value['source_partition_sha256'] = {'mi_product': value['source_partition_sha256']['mi_product']}
            with patch('build_image.erofs') as read:
                with self.assertRaisesRegex(RuntimeError, 'partition pins'):
                    verify_source(value, directory, b'')
                read.assert_not_called()

    def test_new_firmware_must_match_its_own_archive(self):
        with self.assertRaisesRegex(RuntimeError, 'archive identity'):
            profile_from_build({'source': 'official-hongkong-ota', 'hyperos': '4.0.24.0.XFRCNXM', 'archive_sha256': ARCHIVES['4.0.18.0.XFRCNXM']})

    def test_runtime_policy_requires_exact_registered_archive_and_native_pins(self):
        for version in ARCHIVES:
            with self.subTest(version=version):
                selected = profile(version)
                self.assertEqual(modern_runtime(selected), version != '4.0.17.0.XFRCNXM')
                for changed in ({**selected, 'archive_sha256': '0' * 64}, {**selected, 'pins': {}}, {**selected, 'pins': {**selected['pins'], 'hwui': '0' * 64}}, {**selected, 'hyperos': '4.0.99.0.XFRCNXM'}):
                    with self.assertRaisesRegex(RuntimeError, 'Unsupported modern runtime'):
                        modern_runtime(changed)
        for incomplete in (None, {}, {'hyperos': '4.0.24.0.XFRCNXM'}):
            with self.subTest(incomplete=incomplete), self.assertRaisesRegex(RuntimeError, 'Unsupported modern runtime'):
                modern_runtime(incomplete)

    def test_unknown_firmware_and_cross_version_archive_are_refused(self):
        with self.assertRaises(RuntimeError):
            profile_for_archive('0' * 64)
        with self.assertRaises(RuntimeError):
            profile('4.0.19.0.XFRCNXM')
        with self.assertRaisesRegex(RuntimeError, 'archive identity'):
            profile_from_build({'source': 'official-hongkong-ota', 'hyperos': '4.0.17.0.XFRCNXM', 'archive_sha256': '0' * 64})
        with self.assertRaisesRegex(RuntimeError, 'different firmware'):
            profile_from_build({'source': 'official-yingtian-ota'})

    def test_partition_identity_cannot_be_overwritten_by_later_partition(self):
        for version in ARCHIVES:
            with self.subTest(version=version):
                expected = profile(version)['properties']
                sources = {part: dict(expected) for part in PROP_PATHS}
                sources['odm']['ro.vendor.build.fingerprint'] = 'wrong-vendor'
                sources['system_dlkm']['ro.product.model'] = 'wrong-global'
                sources['vendor']['ro.product.model'] = 'wrong-vendor-global'
                encoded = {part: ''.join((k + '=' + v + '\n' for k, v in values.items())).encode() for part, values in sources.items()}
                metadata = ('post-build=' + expected['ro.build.fingerprint'] + '\n').encode()
                self.assertEqual(identity_values(encoded, metadata, expected), expected)
                changed = copy.deepcopy(encoded)
                changed['vendor'] += b'ro.vendor.build.fingerprint=updated-vendor\n'
                self.assertEqual(identity_values(changed, metadata, expected)['ro.vendor.build.fingerprint'], 'updated-vendor')

    def test_profile_cannot_add_hal_selectors_or_drop_required_identity(self):
        expected = profile()['properties']
        sources = {part: ''.join((k + '=' + v + '\n' for k, v in expected.items())).encode() for part in PROP_PATHS}
        metadata = ('post-build=' + expected['ro.build.fingerprint'] + '\n').encode()
        forged = {**expected, 'ro.boot.hardware': 'qualcomm'}
        with self.assertRaisesRegex(RuntimeError, 'property set'):
            identity_values(sources, metadata, forged)
        with self.assertRaisesRegex(RuntimeError, 'property set'):
            identity_values(sources, metadata, set(expected) - {'ro.product.model'})

if __name__ == '__main__':
    unittest.main()


# --- tests/test_phone_vulkan.py ---

'Verify r3 HWUI preload scope, renderer selection and runtime compatibility.'

def build_info(version='4.0.18.0.XFRCNXM'):
    value = profile(version)
    return {'source': 'official-hongkong-ota', 'hyperos': value['hyperos'], 'archive_sha256': value['archive_sha256'], 'hwui_renderer': 'skiavk', 'hwui': {'before': PHONE_BEFORE, 'after': PHONE_AFTER, 'profile': PHONE_PROFILE}}

class PhoneVulkanNativeTests(unittest.TestCase):

    def binary(self):
        path = REPO / 'work/os4-r3-build/input/hongkong-4.0.18/hwui.bin'
        if not path.is_file():
            self.skipTest('Original proprietary OTA library is not distributed in Git.')
        data = path.read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), PHONE_BEFORE)
        return data

    def test_exact_function_branch_and_oem_shader_calls_are_preserved(self):
        data = self.binary()
        self.assertEqual(preload_symbol(data), (10407016, 80, 10407016))
        fixed = patch_hwui(data)
        self.assertEqual(hashlib.sha256(fixed).hexdigest(), PHONE_AFTER)
        self.assertEqual(patch_hwui(fixed), fixed)
        expected = bytearray(data)
        expected[10407032:10407036] = bytes.fromhex('09000014')
        self.assertEqual(fixed, expected)
        instruction = struct.unpack_from('<I', fixed, 10407032)[0]
        self.assertEqual(instruction & 4227858432, 335544320)
        self.assertEqual(10407032 + (instruction & 67108863) * 4, 10407068)
        for site, target in ((10407068, 10387952), (10407072, 4518376), (10407076, 10791844)):
            call = struct.unpack_from('<I', fixed, site)[0]
            self.assertEqual(call & 4227858432, 2483027968)
            immediate = call & 67108863
            if immediate & 33554432:
                immediate -= 67108864
            self.assertEqual(site + immediate * 4, target)

    def test_builder_binds_native_patch_to_r3_and_retains_r2_bytes(self):
        data = self.binary()
        self.assertEqual(native_hwui(profile(), data), (data, None))
        fixed, receipt = native_hwui(profile('4.0.18.0.XFRCNXM'), data)
        self.assertEqual(receipt, build_info()['hwui'])
        self.assertEqual(hashlib.sha256(fixed).hexdigest(), PHONE_AFTER)
        corrupted = bytearray(data)
        corrupted[10407068] ^= 1
        with self.assertRaisesRegex(RuntimeError, 'Unsupported Xiaomi HWUI'):
            patch_hwui(corrupted)

    def test_pad_profile_and_output_are_unchanged(self):
        self.assertEqual(PROFILES[BEFORE]['after'], AFTER)
        self.assertEqual(PROFILES[BEFORE]['site'], 9743852)
        self.assertEqual(PROFILES[BEFORE]['target'], 9743888)
        path = REPO / 'work/os4-pad/work/source-audit/libhwui-original.so'
        if path.is_file():
            data = path.read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), BEFORE)
            self.assertEqual(hashlib.sha256(patch_hwui(data)).hexdigest(), AFTER)

class PhoneVulkanRuntimeTests(unittest.TestCase):

    def test_hwui_content_and_renderer_select_workarounds_without_firmware_labels(self):
        expected = vulkan_features(build_info())
        current = build_info('4.0.24.0.XFRCNXM')
        self.assertEqual(vulkan_features(current), expected)
        for labels in ({'name': 'Any_Renamed_AVD', 'port': 5660, 'avd_path': '/custom/phone.avd'},
                       {'source': 'custom', 'hyperos': '5.9.99.0.FUTURE', 'archive_sha256': 'a' * 64},
                       {'source': 'official-yingtian-ota', 'hyperos': None, 'archive_sha256': None}):
            self.assertEqual(vulkan_features({**current, **labels}), expected)
        for key, value in (('before', '0' * 64), ('after', '0' * 64), ('profile', 'unknown')):
            with self.subTest(key=key):
                self.assertEqual(vulkan_features({**current, 'hwui': {**current['hwui'], key: value}}), [])
        for value in ({}, {'source': 'official-yingtian-ota'}, {**current, 'hwui_renderer': None},
                      {**current, 'hwui_renderer': 'skiagl'}, {**current, 'hwui': None},
                      {**current, 'hwui': {'after': PHONE_AFTER}}):
            with self.subTest(value=value):
                self.assertEqual(vulkan_features(value), [])

    def test_submission_workaround_requires_the_complete_physical_rear_contract(self):
        current = build_info()
        for value in (current, {**current, 'hwui': {'before': BEFORE, 'after': AFTER}}):
            with patch('rear_display_config.runtime_options', return_value=['-verified-rear-panel']) as rear:
                flags = vulkan_features(value)[1].split(',')
            rear.assert_called_once_with(value)
            self.assertEqual(flags.count('-VulkanQueueSubmitWithCommands'), 1)
            self.assertIn('-GLAsyncSwap', flags)
            self.assertNotIn('VulkanQueueSubmitWithCommands', flags)
        self.assertEqual(vulkan_features(current), ['-feature', 'VulkanBatchedDescriptorSetUpdate'])
        with self.assertRaisesRegex(RuntimeError, 'rear-display'):
            vulkan_features({**current, 'rear_display': {'schema': 1}})

    def test_delivered_pad_receipt_is_the_only_missing_renderer_compatibility_case(self):
        receipt = {'before': BEFORE, 'after': AFTER}
        for source in ('custom', 'official-hongkong-ota', 'official-yingtian-ota'):
            for renderer in (None, 'skiavk', 'skiagl'):
                value = {'source': source, 'hwui': receipt}
                if renderer is not None:
                    value['hwui_renderer'] = renderer
                expected = [] if renderer == 'skiagl' else ['-feature', 'VulkanBatchedDescriptorSetUpdate']
                with self.subTest(source=source, renderer=renderer):
                    self.assertEqual(vulkan_features(value), expected)
        self.assertEqual(vulkan_features({'hwui': {**receipt, 'extra': True}}), [])
        self.assertEqual(vulkan_features({'hwui': receipt, 'hwui_renderer': None}), [])

    def test_gradient_override_accepts_patched_r3_but_rejects_it_for_legacy_r2(self):
        config = {'name': 'Any_Renamed_Phone_AVD', 'port': 5584}
        for version in ('4.0.17.0.XFRCNXM', '4.0.18.0.XFRCNXM', '4.0.24.0.XFRCNXM'):
            with self.subTest(version=version), patch('apply_flutter_fix.official'), patch('phone_profile.profile_from_build', return_value=profile(version)), patch('apply_flutter_fix.root', side_effect=['ranchu', config['name'], PHONE_AFTER + ' /system/lib64/libhwui.so', 'false']) as root:
                if '4.0.17.' in version:
                    with self.assertRaisesRegex(RuntimeError, 'Unsupported HWUI'):
                        apply_gradient_blur_runtime(config)
                else:
                    apply_gradient_blur_runtime(config)
                    self.assertEqual(root.call_count, 4)
                self.assertTrue(all((not call.args[1].startswith('setprop ') for call in root.call_args_list)))

if __name__ == '__main__':
    unittest.main()
