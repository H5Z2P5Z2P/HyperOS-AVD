"""Reject mixed OTA identities and preserve partition-specific public values."""
import copy
import hashlib
from pathlib import Path
import sys
import unittest
import tempfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from phone_profile import (ARCHIVES, LEGACY_PINS, PIN_PATHS, PROP_PATHS, identity_values, modern_runtime, profile,
                           profile_for_archive, profile_from_build, verify_source)


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
                self.assertEqual(set(value['source_partition_sha256']),
                                 {'mi_product'} if legacy else set(PROP_PATHS) | {'mi_product'})
                self.assertEqual(set(value['source_sha256']),
                                 {part + '.build.prop' for part in PROP_PATHS} | {'ota.metadata'})
                for checksum in (digest, value['model_xml_sha256'],
                                 *value['pins'].values(), *value['source_sha256'].values(),
                                 *value['source_partition_sha256'].values()):
                    self.assertRegex(checksum, r'^[0-9a-f]{64}$')
                self.assertEqual(hashlib.sha256(Path(value['model_xml']).read_bytes()).hexdigest(),
                                 value['model_xml_sha256'])
                self.assertEqual(value['display'], {'width': 1120, 'height': 2436, 'density': 480})
                self.assertFalse({'ro.boot.hardware', 'ro.hardware', 'ro.hardware.egl'} & value['properties'].keys())
                self.assertEqual(profile_from_build({'source': 'official-hongkong-ota',
                    'hyperos': version, 'archive_sha256': digest}), value)
        legacy = profile()
        self.assertEqual(legacy['pins'], LEGACY_PINS)
        self.assertEqual(profile_from_build({'source': 'official-hongkong-ota'}), legacy)

    def test_new_firmware_cannot_reuse_legacy_partial_partition_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            value = self.fixture_partitions(directory, '4.0.24.0.XFRCNXM')
            value['source_partition_sha256'] = {
                'mi_product': value['source_partition_sha256']['mi_product']}
            with patch('build_image.erofs') as read:
                with self.assertRaisesRegex(RuntimeError, 'partition pins'):
                    verify_source(value, directory, b'')
                read.assert_not_called()

    def test_new_firmware_must_match_its_own_archive(self):
        with self.assertRaisesRegex(RuntimeError, 'archive identity'):
            profile_from_build({'source': 'official-hongkong-ota',
                'hyperos': '4.0.24.0.XFRCNXM',
                'archive_sha256': ARCHIVES['4.0.18.0.XFRCNXM']})

    def test_runtime_policy_requires_exact_registered_archive_and_native_pins(self):
        for version in ARCHIVES:
            with self.subTest(version=version):
                selected = profile(version)
                self.assertEqual(modern_runtime(selected), version != '4.0.17.0.XFRCNXM')
                for changed in ({**selected, 'archive_sha256': '0' * 64},
                                {**selected, 'pins': {}},
                                {**selected, 'pins': {**selected['pins'], 'hwui': '0' * 64}},
                                {**selected, 'hyperos': '4.0.99.0.XFRCNXM'}):
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
            profile_from_build({'source': 'official-hongkong-ota',
                                'hyperos': '4.0.17.0.XFRCNXM',
                                'archive_sha256': '0' * 64})
        with self.assertRaisesRegex(RuntimeError, 'different firmware'):
            profile_from_build({'source': 'official-yingtian-ota'})

    def test_partition_identity_cannot_be_overwritten_by_later_partition(self):
        for version in ARCHIVES:
            with self.subTest(version=version):
                expected = profile(version)['properties']
                # Give every source a copy, with deliberate conflicts in non-owners.
                sources = {part: dict(expected) for part in PROP_PATHS}
                sources['odm']['ro.vendor.build.fingerprint'] = 'wrong-vendor'
                sources['system_dlkm']['ro.product.model'] = 'wrong-global'
                sources['vendor']['ro.product.model'] = 'wrong-vendor-global'
                encoded = {part: ''.join(k + '=' + v + '\n' for k, v in values.items()).encode()
                           for part, values in sources.items()}
                metadata = ('post-build=' + expected['ro.build.fingerprint'] + '\n').encode()
                self.assertEqual(identity_values(encoded, metadata, expected), expected)
                changed = copy.deepcopy(encoded)
                changed['vendor'] += b'ro.vendor.build.fingerprint=updated-vendor\n'
                self.assertEqual(identity_values(changed, metadata, expected)['ro.vendor.build.fingerprint'],
                                 'updated-vendor')

    def test_profile_cannot_add_hal_selectors_or_drop_required_identity(self):
        expected = profile()['properties']
        sources = {part: ''.join(k + '=' + v + '\n' for k, v in expected.items()).encode()
                   for part in PROP_PATHS}
        metadata = ('post-build=' + expected['ro.build.fingerprint'] + '\n').encode()
        forged = {**expected, 'ro.boot.hardware': 'qualcomm'}
        with self.assertRaisesRegex(RuntimeError, 'property set'):
            identity_values(sources, metadata, forged)
        with self.assertRaisesRegex(RuntimeError, 'property set'):
            identity_values(sources, metadata, set(expected) - {'ro.product.model'})


if __name__ == '__main__':
    unittest.main()
