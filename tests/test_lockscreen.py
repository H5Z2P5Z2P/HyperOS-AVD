"""Consolidated unit tests for OS4 lockscreen video patch & builder integration."""
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
import zipfile

REPO = Path(__file__).resolve().parents[1]
ROOT = REPO
sys.path.insert(0, str(REPO / 'scripts'))

from build_os4_official import lockscreen_video_replacements
import package_release
import patch_lockscreen_video as video
from phone_profile import profile



# --- tests/test_lockscreen_video.py ---

'Verify the exact signed-source RGBA video patch and preserved native layout.'

FIXTURES = REPO / 'work/os4-r3-build/work/fastplayer-analysis'

def checksum(data):
    return hashlib.sha256(data).hexdigest()

class LockscreenVideoPatchTests(unittest.TestCase):

    def native(self):
        path = FIXTURES / 'libfastplayer.so'
        if not path.is_file():
            self.skipTest('Original proprietary MIUIAod library is not distributed in Git.')
        data = path.read_bytes()
        self.assertEqual(checksum(data), video.BEFORE)
        return data

    def apk(self):
        path = FIXTURES / 'MIUIAod.apk'
        if not path.is_file():
            self.skipTest('Original proprietary signed MIUIAod APK is not distributed in Git.')
        data = path.read_bytes()
        self.assertEqual(checksum(data), video.APK_SHA256)
        return data

    def test_public_identity_selects_original_signed_apk_and_external_native_path(self):
        self.assertEqual(video.PACKAGE, 'com.miui.aod')
        self.assertEqual(video.APK, '/product/priv-app/MIUIAod/MIUIAod.apk')
        self.assertEqual(video.ENTRY, 'lib/arm64-v8a/libfastplayer.so')
        self.assertEqual(video.NATIVE, '/product/priv-app/MIUIAod/lib/arm64/libfastplayer.so')
        self.assertEqual(video.MANIFEST['apk_sha256'], video.APK_SHA256)
        self.assertEqual(video.MANIFEST['native_sha256'], video.AFTER)

    def test_exact_verified_output_is_idempotent(self):
        source = self.native()
        result = video.patch(source)
        self.assertEqual(len(result), 658544)
        self.assertEqual(checksum(result), video.AFTER)
        self.assertEqual(video.patch(result), result)

    def test_only_nine_source_instructions_change(self):
        source = self.native()
        expected = bytearray(source)
        substitutions = ((228172, '1f7500b9', '4a038052'), (228176, '2afd60d3', '0a7500b9'), (228180, '09290d29', '093500f9'), (299140, '23cb8a72', '23008052'), (299300, '176d1c12', '770a40b9'), (299312, 'fa7e4093', 'fa7e7e93'), (299332, '2a7f4093', '42f47ed3'), (299340, '21210a9b', '2121199b'), (299368, '1f090071', '32000014'))
        for address, before, after in substitutions:
            self.assertEqual(source[address:address + 4], bytes.fromhex(before))
            expected[address:address + 4] = bytes.fromhex(after)
        result = video.patch(source)
        self.assertEqual(result, bytes(expected))
        self.assertEqual(sum((a != b for a, b in zip(source, result))), 27)
        self.assertEqual(result[230352:233152], source[230352:233152])

    def test_elf_tables_and_native_function_layout_are_preserved(self):
        source = self.native()
        result = video.patch(source)
        header = struct.unpack_from('<16sHHIQQQIHHHHHH', source)
        self.assertEqual(result[:64], source[:64])
        for offset, size, count in ((header[5], header[9], header[10]), (header[6], header[11], header[12])):
            self.assertEqual(result[offset:offset + size * count], source[offset:offset + size * count])
        sections = [struct.unpack_from('<IIQQQQIIQQ', source, header[6] + i * header[11]) for i in range(header[12])]
        for section in sections:
            if section[1] in (3, 11):
                offset, size = section[4:6]
                self.assertEqual(result[offset:offset + size], source[offset:offset + size])
        self.assertEqual(video._layout(source), video._layout(result))

    def test_packed_row_arithmetic_and_post_branch(self):
        result = video.patch(self.native())
        instruction = lambda address: struct.unpack_from('<I', result, address)[0]
        stride = instruction(299312)
        self.assertEqual((stride & 31, stride >> 5 & 31), (26, 23))
        self.assertEqual((stride >> 16 & 63, stride >> 10 & 63), (62, 31))
        self.assertEqual(instruction(299332), 3548312642)
        self.assertEqual(instruction(299340) >> 16 & 31, 25)
        branch = instruction(299368)
        self.assertEqual(branch & 4227858432, 335544320)
        self.assertEqual(299368 + (branch & 67108863) * 4, 299568)
        self.assertEqual(result[299568:299604], self.native()[299568:299604])

    def test_native_extraction_leaves_signed_apk_unchanged(self):
        data = self.apk()
        snapshot = bytes(data)
        with zipfile.ZipFile(FIXTURES / 'MIUIAod.apk') as archive:
            original_native = archive.read(video.ENTRY)
        result = video.native_from_apk(data)
        self.assertEqual(checksum(original_native), video.BEFORE)
        self.assertEqual(result, video.patch(original_native))
        self.assertEqual(data, snapshot)
        self.assertEqual(checksum((FIXTURES / 'MIUIAod.apk').read_bytes()), video.APK_SHA256)

    def test_unknown_native_and_apk_are_rejected(self):
        for data in (b'', b'not an ELF', b'\x7fELF' + bytes(658540)):
            with self.subTest(kind='native', size=len(data)), self.assertRaisesRegex(RuntimeError, 'Unsupported MIUIAod fastplayer SHA-256'):
                video.patch(data)
        for data in (b'', b'not an APK', b'PK\x03\x04' + bytes(32)):
            with self.subTest(kind='apk', size=len(data)), self.assertRaisesRegex(RuntimeError, 'Unsupported MIUIAod APK'):
                video.native_from_apk(data)

    def test_partial_patch_and_extra_native_edits_are_rejected(self):
        source = self.native()
        partial = bytearray(source)
        partial[228172:228176] = bytes.fromhex('4a038052')
        extra = bytearray(video.patch(source))
        extra[299572] ^= 1
        for data in (bytes(partial), bytes(extra)):
            with self.subTest(checksum=checksum(data)), self.assertRaisesRegex(RuntimeError, 'Unsupported MIUIAod fastplayer SHA-256'):
                video.patch(data)

    def test_function_guards_reject_changed_code_even_if_source_pin_is_replaced(self):
        changed = bytearray(self.native())
        changed[228112] ^= 1
        data = bytes(changed)
        with patch.object(video, 'BEFORE', checksum(data)), self.assertRaisesRegex(RuntimeError, 'function byte guard failed'):
            video.patch(data)

    def test_function_guards_also_validate_idempotent_output(self):
        changed = bytearray(video.patch(self.native()))
        changed[299344] ^= 1
        data = bytes(changed)
        with patch.object(video, 'AFTER', checksum(data)), self.assertRaisesRegex(RuntimeError, 'function byte guard failed'):
            video.patch(data)

    def test_changed_replacement_is_rejected_by_verified_output_pin(self):
        sites = list(video.SITES)
        address, before, after = sites[-1]
        sites[-1] = (address, before, bytes.fromhex('33000014'))
        with patch.object(video, 'SITES', tuple(sites)), self.assertRaisesRegex(RuntimeError, 'patch output checksum mismatch'):
            video.patch(self.native())

    def test_modified_signed_apk_is_rejected(self):
        data = bytearray(self.apk())
        data[-1] ^= 1
        with self.assertRaisesRegex(RuntimeError, 'Unsupported MIUIAod APK'):
            video.native_from_apk(bytes(data))

    def test_apk_cli_rejects_same_path_and_hardlink_before_any_write(self):
        source = REPO / 'MIUIAod.apk'
        for output in (source, REPO / 'MIUIAod-native.so'):
            with self.subTest(output=output), patch.object(sys, 'argv', ['patch_lockscreen_video.py', '--apk', str(source), str(output)]), patch.object(Path, 'exists', return_value=True), patch.object(Path, 'samefile', return_value=True), patch.object(Path, 'read_bytes') as read, patch.object(Path, 'write_bytes') as write, self.assertRaisesRegex(RuntimeError, 'APK input must not be overwritten'):
                video.main()
            read.assert_not_called()
            write.assert_not_called()

if __name__ == '__main__':
    unittest.main()


# --- tests/test_lockscreen_builder.py ---

'Check phone r3 native video baking and release preflight source guards.'

FIXTURES = REPO / 'work/os4-r3-build/work/fastplayer-analysis'

OLD = '4.0.17.0.XFRCNXM'

NEW = '4.0.18.0.XFRCNXM'

class LockscreenBuilderTests(unittest.TestCase):

    def apk(self):
        path = FIXTURES / 'MIUIAod.apk'
        if not path.is_file():
            self.skipTest('Original proprietary signed MIUIAod APK is not distributed in Git.')
        data = path.read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), video.APK_SHA256)
        return data

    def test_r3_adds_only_the_external_native_library_and_preserves_signed_apk(self):
        apk = self.apk()
        before = hashlib.sha256(apk).hexdigest()
        replacements, manifest = lockscreen_video_replacements(profile(NEW), apk)
        self.assertEqual(set(replacements), {video.NATIVE.lstrip('/')})
        native, mode, label = replacements[video.NATIVE.lstrip('/')]
        self.assertEqual(hashlib.sha256(native).hexdigest(), video.AFTER)
        self.assertEqual((mode, label), (420, 'u:object_r:system_lib_file:s0'))
        self.assertEqual(manifest, video.MANIFEST)
        self.assertIsNot(manifest, video.MANIFEST)
        self.assertEqual(hashlib.sha256(apk).hexdigest(), before)
        self.assertNotIn(video.APK.lstrip('/'), replacements)

    def test_legacy_phone_has_no_new_replacements_or_receipt(self):
        with patch.object(video, 'native_from_apk') as extract:
            self.assertEqual(lockscreen_video_replacements(profile(OLD), b'unused'), ({}, None))
        extract.assert_not_called()

    def test_foreign_firmware_and_unpinned_r3_sources_are_refused_before_extraction(self):
        selected = profile(NEW)
        cases = (({'hyperos': '4.0.18.0.XOCCNXM'}, 'profile'), ({**selected, 'pins': {}}, 'modern runtime archive'), ({**selected, 'pins': {**selected['pins'], 'aod_apk': 'unverified'}}, 'modern runtime archive'))
        for value, message in cases:
            with self.subTest(profile=value['hyperos']), patch.object(video, 'native_from_apk') as extract:
                with self.assertRaisesRegex(RuntimeError, message):
                    lockscreen_video_replacements(value, b'unknown APK')
                extract.assert_not_called()
        with self.assertRaisesRegex(RuntimeError, 'Unsupported MIUIAod APK'):
            lockscreen_video_replacements(selected, b'unknown APK')

    def test_preflight_reads_and_accepts_exact_signed_apk_and_patched_native(self):
        apk = self.apk()
        native = video.native_from_apk(apk)
        read = Mock(side_effect={video.APK: apk, video.NATIVE: native}.__getitem__)
        self.assertEqual(package_release.verify_lockscreen_video(profile(NEW), {'lockscreen_video_fix': dict(video.MANIFEST)}, read), 2)
        self.assertEqual([call.args[0] for call in read.call_args_list], [video.APK, video.NATIVE])

    def test_preflight_requires_exact_receipt_and_source_pin_before_image_reads(self):
        selected = profile(NEW)
        receipts = [None, {}, {**video.MANIFEST, 'revision': 0}, *[{**video.MANIFEST, key: 'unverified'} for key in video.MANIFEST if key != 'revision']]
        for receipt in receipts:
            read = Mock()
            with self.subTest(receipt=receipt), self.assertRaisesRegex(RuntimeError, 'metadata or source pin'):
                package_release.verify_lockscreen_video(selected, {'lockscreen_video_fix': receipt}, read)
            read.assert_not_called()
        read = Mock()
        with self.assertRaisesRegex(RuntimeError, 'metadata or source pin'):
            package_release.verify_lockscreen_video({**selected, 'pins': {}}, {'lockscreen_video_fix': video.MANIFEST}, read)
        read.assert_not_called()

    def test_preflight_refuses_apk_changes_and_original_or_corrupt_external_native(self):
        apk = self.apk()
        native = video.native_from_apk(apk)
        original = (FIXTURES / 'libfastplayer.so').read_bytes()
        for path, files in ((video.APK, {video.APK: apk + b'changed', video.NATIVE: native}), (video.NATIVE, {video.APK: apk, video.NATIVE: original}), (video.NATIVE, {video.APK: apk, video.NATIVE: native + b'changed'})):
            with self.subTest(path=path), self.assertRaisesRegex(RuntimeError, 'checksum mismatch: ' + path):
                package_release.verify_lockscreen_video(profile(NEW), {'lockscreen_video_fix': video.MANIFEST}, files.__getitem__)

    def test_preflight_leaves_legacy_phone_and_pad_requirements_unchanged(self):
        for version in (OLD, '4.0.6.0.XOCCNXM'):
            read = Mock()
            self.assertEqual(package_release.verify_lockscreen_video({'hyperos': version}, {}, read), 0)
            read.assert_not_called()

    def test_release_metadata_keeps_receipt_only_for_phone_r3(self):
        for version in (OLD, NEW):
            selected = profile(version)
            build = {'source': 'official-hongkong-ota', 'hyperos': version, 'archive_sha256': selected['archive_sha256'], 'android_api': 37, 'adb_authentication': True, 'flutter_render_fix': 6, 'native_quickstep_identity': True, 'preinstalled_apps': {'apps': ['test']}, 'avd_defaults': {'test': True}, 'lockscreen_video_fix': dict(video.MANIFEST)}
            with self.subTest(version=version), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'local').mkdir()
                (root / 'local/build.json').write_text(json.dumps(build))
                metadata = package_release.release_metadata(root, 'os4-official')
                if version == NEW:
                    self.assertEqual(metadata['build']['lockscreen_video_fix'], video.MANIFEST)
                else:
                    self.assertNotIn('lockscreen_video_fix', metadata['build'])

if __name__ == '__main__':
    unittest.main()
