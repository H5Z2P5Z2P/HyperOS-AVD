"""Consolidated unit tests for OS4 rear display subsystem:
hardware composer patch, display config, installation, wake service, input policy, and release packaging.
"""
from contextlib import ExitStack
import copy
import hashlib
import io
import itertools
import json
import os
from pathlib import Path
import shlex
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import xml.etree.ElementTree as ET
import zipfile
import zlib

REPO = Path(__file__).resolve().parents[1]
ROOT = REPO
sys.path.insert(0, str(REPO / 'scripts'))

import apply_rear_display_fix as rear_fix
import module_lifecycle as lifecycle
import package_release
import patch_composer
import patch_goldfish_sync as goldfish_sync
from patch_goldfish_sync import MANIFEST as SYNC
from patch_gnss import java
import patch_rear_display as rear_composer
from patch_rear_display import MANIFEST as COMPOSER
import patch_rear_input_policy as rear_input_policy
import rear_display_config as rear_config
import rear_display_wake as rear_wake
from phone_profile import profile

rear = rear_config
composer = rear_composer
sync = goldfish_sync
wake = rear_wake
rear_install = rear_fix
fix = rear_fix



# --- tests/test_rear_display.py ---

"""Guard the secondary timing patch and its chain after the alpha fix."""

SOURCE = REPO / 'work/os4-r3-build/work/rear-display-audit/composer3-ranchu.bin'

REAL_SHA256 = hashlib.sha256

def pretend_pinned_digest(data):
    """Bypass only the whole-file hash to exercise secondary guard layers."""
    if len(data) == rear_composer.SIZE:
        return SimpleNamespace(hexdigest=lambda: rear_composer.BEFORE)
    return REAL_SHA256(data)

class RearDisplayGuardTest(unittest.TestCase):
    def test_unknown_composer_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'Unsupported rear-display ranchu composer'):
            rear_composer.patch(b'unknown vendor update')

    def test_patch_chain_and_manifest_are_pinned(self):
        self.assertEqual(rear_composer.ORIGINAL, patch_composer.BEFORE)
        self.assertEqual(rear_composer.BEFORE, patch_composer.AFTER)
        self.assertEqual((rear_composer.MANIFEST['native'], rear_composer.MANIFEST['native_sha256']),
                         (patch_composer.NATIVE, rear_composer.AFTER))
        self.assertEqual(rear_composer.MANIFEST['input_native_sha256'], patch_composer.AFTER)
        self.assertEqual(rear_composer.MANIFEST['secondary_refresh_hz'], 60)
        self.assertEqual(rear_composer.MANIFEST['secondary_vsync_period_ns'], 1000000000 // 60)
        self.assertTrue(rear_composer.MANIFEST['primary_vsync_unchanged'])
        self.assertTrue(rear_composer.MANIFEST['plane_alpha_fix_retained'])

    def test_instruction_encodings_keep_the_destination_register(self):
        # Decode the AArch64 move-wide fields independently of patch().
        expected = ((0x2c648, 0x52800000, 0, 0x5e10, 0x502a),
                    (0x2c654, 0x72800000, 1, 0x005f, 0x00fe))
        self.assertEqual(len(rear_composer.SITES), 2)
        periods = [0, 0]
        for (address, before, after), (site, opcode, shift, old, new) in zip(rear_composer.SITES, expected):
            self.assertEqual(address, site)
            for index, (encoded, immediate) in enumerate(((before, old), (after, new))):
                instruction, = struct.unpack('<I', encoded)
                self.assertEqual(instruction & 0xff800000, opcode)
                self.assertEqual((instruction >> 21) & 3, shift)
                self.assertEqual(instruction & 31, 26)
                self.assertEqual((instruction >> 5) & 0xffff, immediate)
                periods[index] |= immediate << (16 * shift)
        self.assertEqual(periods, [6250000, 1000000000 // 60])

@unittest.skipUnless(SOURCE.is_file(), 'Verified vendor ELF is not bundled')
class PinnedRearDisplayTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = SOURCE.read_bytes()
        cls.alpha = patch_composer.patch(cls.original)

    def test_original_elf_requires_the_existing_alpha_fix(self):
        self.assertEqual(REAL_SHA256(self.original).hexdigest(), rear_composer.ORIGINAL)
        with self.assertRaisesRegex(RuntimeError, 'Unsupported rear-display ranchu composer'):
            rear_composer.patch(self.original)

    def test_embedded_symbol_resolves_the_function_file_extent(self):
        self.assertEqual(rear_composer.find_displays_symbol(self.alpha), (0x2b8a0, 0xf24, 0x2b8a0))
        for address in (0x2c648, 0x2c654, 0x2c6a4):
            self.assertGreaterEqual(address, 0x2b8a0)
            self.assertLess(address + 4, 0x2c7c4)

    def test_only_secondary_constant_changes_and_patch_is_idempotent(self):
        result = rear_composer.patch(self.alpha)
        self.assertEqual(REAL_SHA256(result).hexdigest(),
                         '2aafbaa3fd7f919214be29c8a0e38f8f7e1555ccec61cfd0f7b4fb1113e0f74d')
        self.assertEqual(len(result), len(self.alpha))
        self.assertEqual([i for i, (a, b) in enumerate(zip(self.alpha, result)) if a != b],
                         [0x2c648, 0x2c649, 0x2c64a, 0x2c654, 0x2c655])
        self.assertEqual(result[:0x2c648], self.alpha[:0x2c648])
        self.assertEqual(result[0x2c64c:0x2c654], self.alpha[0x2c64c:0x2c654])
        self.assertEqual(result[0x2c658:], self.alpha[0x2c658:])
        self.assertEqual(result[0x2c6a4:0x2c6a8], bytes.fromhex('1a1400b9'))
        self.assertEqual(result[0x3a178:0x3a17c], bytes.fromhex('0028201e'))
        self.assertEqual(rear_composer.patch(result), result)
        self.assertEqual(rear_composer.find_displays_symbol(result), (0x2b8a0, 0xf24, 0x2b8a0))

    def test_unrelated_update_is_rejected_without_mutating_input(self):
        tampered = bytearray(self.alpha)
        tampered[-1] ^= 1
        unchanged = bytes(tampered)
        with self.assertRaisesRegex(RuntimeError, 'Unsupported rear-display ranchu composer'):
            rear_composer.patch(tampered)
        self.assertEqual(bytes(tampered), unchanged)

    def test_instruction_guard_rejects_a_different_register(self):
        tampered = bytearray(self.alpha)
        tampered[0x2c648] ^= 1  # Change w26 to w27 without changing its immediate.
        with patch.object(rear_composer.hashlib, 'sha256', side_effect=pretend_pinned_digest):
            with self.assertRaisesRegex(RuntimeError, 'secondary vsync instruction'):
                rear_composer.patch(tampered)

    def test_field_store_guard_rejects_a_different_field(self):
        tampered = bytearray(self.alpha)
        tampered[0x2c6a5] ^= 4
        with patch.object(rear_composer.hashlib, 'sha256', side_effect=pretend_pinned_digest):
            with self.assertRaisesRegex(RuntimeError, 'secondary vsync field store'):
                rear_composer.patch(tampered)

    def test_function_guard_covers_unmodified_primary_code(self):
        tampered = bytearray(self.alpha)
        tampered[0x2bfc4] ^= 1  # Primary DisplayConfig field store remains guarded.
        with patch.object(rear_composer.hashlib, 'sha256', side_effect=pretend_pinned_digest):
            with self.assertRaisesRegex(RuntimeError, 'findDisplays function body'):
                rear_composer.patch(tampered)

    def test_elf_mapping_guard_rejects_an_offset_change(self):
        tampered = bytearray(self.alpha)
        # The RX PT_LOAD must map the symbol VA to its verified file offset.
        struct.pack_into('<Q', tampered, 64 + 3 * 56 + 8, 0x14004)
        with patch.object(rear_composer.hashlib, 'sha256', side_effect=pretend_pinned_digest):
            with self.assertRaisesRegex(RuntimeError, 'findDisplays executable mapping'):
                rear_composer.patch(tampered)

if __name__ == '__main__':
    unittest.main()


# --- tests/test_rear_display_config.py ---

"""Guard source-only physical-display aliases and the minimal rear-display RRO."""

AUDIT = REPO / 'work/os4-r3-build/work/rear-display-audit'

SDK = Path.home() / 'Library/Android/sdk'

FIXTURE_PATHS = {path: AUDIT / Path(path).name for path in rear_config.SOURCE_SHA256}

def reference_tables():
    """Aapt2's textual format with the audited source reference ordering."""
    pairs = {
        'config_displayCutoutPathArray':
            ('@string/config_mainBuiltInDisplayCutout', '@string/config_secondaryBuiltInDisplayCutout'),
        'config_displayCutoutApproximationRectArray':
            ('@string/config_mainBuiltInDisplayCutoutRectApproximation',
             '@string/config_secondaryBuiltInDisplayCutoutRectApproximation'),
        'config_roundedCornerRadiusArray':
            ('@dimen/rounded_corner_radius', '@dimen/secondary_rounded_corner_radius'),
        'config_roundedCornerTopRadiusArray':
            ('@dimen/rounded_corner_radius_top', '@dimen/secondary_rounded_corner_radius_top'),
        'config_roundedCornerBottomRadiusArray':
            ('@dimen/rounded_corner_radius_bottom', '@dimen/secondary_rounded_corner_radius_bottom'),
    }
    framework = ''.join(f'    resource 0x01070001 array/{name}\n'
                        f'      () (array) size=2\n        [{items[0]}, {items[1]}]\n'
                        for name, items in pairs.items())
    aosp = ('    resource 0x7f010008 array/config_displayUniqueIdArray\n'
            '      () (array) size=2\n'
            '        ["local:4630947121878579347", "local:4630947121878579348"]\n')
    devices = ('    resource 0x7f070001 string/config_mainBuiltInDisplayCutout\n'
               '      () "M 0,0 H -34 V 140 H 34 V 0 H 0 Z"\n'
               '    resource 0x7f070003 string/config_secondaryBuiltInDisplayCutout\n'
               '      () "M -456,0 L -456,596 L -160,596 L -160,0 Z @bind_left_cutout"\n')
    for name, value in (('rounded_corner_radius', 180), ('rounded_corner_radius_top', 180),
                        ('rounded_corner_radius_bottom', 180),
                        ('secondary_rounded_corner_radius_top', 106),
                        ('secondary_rounded_corner_radius_bottom', 106)):
        devices += (f'    resource 0x7f040002 dimen/{name}\n'
                    f'      () {value}.000000px\n      (anydpi) {value}.000000px\n')
    return framework, aosp, devices

class RearResourceGuardTests(unittest.TestCase):
    def test_image_recipe_keeps_resources_and_binds_new_marker_to_its_source(self):
        sources = {path: ('signed source fixture: ' + path).encode()
                   for path in rear_config.SOURCE_SHA256}
        for identifier, geometry in zip(rear_config.SOURCE_IDS, ((1120, 2436, 480), (912, 596, 450))):
            width, height, density = geometry
            sources[f'product/etc/displayconfig/display_id_{identifier}.xml'] = (
                '<displayConfiguration><densityMapping><density>'
                f'<width>{width}</width><height>{height}</height><density>{density}</density>'
                '</density></densityMapping></displayConfiguration>').encode()
        hashes = {path: hashlib.sha256(data).hexdigest() for path, data in sources.items()}

        def read(image, path):
            part = Path(image).stem
            relative = path.removeprefix('/system/') if part == 'system' else path.removeprefix('/')
            return sources[part + '/' + relative]

        results = []
        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(rear, 'SOURCE_SHA256', hashes), \
                patch('build_image.erofs', side_effect=read), \
                patch.object(rear, 'build_overlay', return_value=b'ID-only overlay') as compile:
            for version in ('4.0.18.0.XFRCNXM', '4.0.24.0.XFRCNXM'):
                selected = profile(version)
                edits, marker = rear_config.image_replacements(selected, temporary, SDK, temporary)
                results.append(edits)
                self.assertEqual(marker['hyperos'], selected['hyperos'])
                self.assertEqual(marker['archive_sha256'], selected['archive_sha256'])
                self.assertEqual(marker['source_sha256'], hashes)
                self.assertEqual(json.loads(edits[rear_config.MARKER_PATH][0]), marker)
                self.assertFalse(set(edits) & set(sources))
                self.assertEqual([entry['density'] for entry in marker['displays']], [480, 450])
            self.assertEqual({key: value for key, value in results[0].items() if key != rear_config.MARKER_PATH},
                             {key: value for key, value in results[1].items() if key != rear_config.MARKER_PATH})
            self.assertEqual(compile.call_count, 2)
            for path in sources:
                original = sources[path]
                sources[path] += b'tamper'
                compile.reset_mock()
                output = Path(temporary) / 'unexpected-output'
                with self.subTest(source=path), self.assertRaisesRegex(RuntimeError, 'Unexpected original'):
                    rear_config.image_replacements(profile('4.0.24.0.XFRCNXM'), temporary, SDK, output)
                compile.assert_not_called()
                self.assertFalse(output.exists())
                sources[path] = original

    def test_registered_new_source_reuses_geometry_with_current_provenance(self):
        current = profile('4.0.24.0.XFRCNXM')
        self.assertEqual(rear_config.validate_profile(current), current)
        old = profile('4.0.18.0.XFRCNXM')
        original = b'ro.test.keep=true\npersist.sys.rear_user_preference=false\n'
        self.assertEqual(rear_config.properties(original, current), rear_config.properties(original, old))
        self.assertEqual(rear_config.boot_init(current), rear_config.boot_init(old))
        build = build_fixture(rear_fix.EXPECTED_WAKE_MANIFEST, current['hyperos'])
        marker = build['rear_display']
        expected = ['-append-userspace-opt', rear_config.BOOT_PROPERTY]
        self.assertEqual(rear_config.runtime_options(build), expected)
        future = {**build, 'source': 'custom', 'hyperos': 'custom-future-build', 'archive_sha256': 'a' * 64,
                  'rear_display': {**marker, 'hyperos': 'custom-future-build', 'archive_sha256': 'a' * 64}}
        self.assertEqual(rear_config.runtime_options(future), expected)
        mutations = ({'hyperos': old['hyperos'], 'archive_sha256': old['archive_sha256']},
                     {'hyperos': old['hyperos']}, {'archive_sha256': old['archive_sha256']},
                     {'schema': True}, {'schema': 1.0}, {'source_sha256': {}},
                     {'mapping_sha256': '0' * 64}, {'overlay_priority': 1001.0})
        for fields in mutations:
            with self.subTest(marker=fields), self.assertRaises(RuntimeError):
                rear_config.runtime_options({**build, 'rear_display': {**marker, **fields}})
        for key in ('rear_display_composer_fix', 'goldfish_sync_fix'):
            with self.subTest(receipt=key), self.assertRaises(RuntimeError):
                rear_config.runtime_options({**build, key: {**build[key], 'revision': True}})
        with self.assertRaises(RuntimeError):
            rear_config.runtime_options({**build, 'archive_sha256': old['archive_sha256']})

    def test_new_source_native_pins_and_partition_identity_fail_closed(self):
        current = profile('4.0.24.0.XFRCNXM')
        variants = [None, {**current, 'hyperos': '4.0.999.0.XFRCNXM'},
                    {**current, 'pins': {**current['pins'], 'hwui': '0' * 64}},
                    {**current, 'pins': {**current['pins'], 'aod_apk': '0' * 64}},
                    {**current, 'archive_sha256': profile('4.0.18.0.XFRCNXM')['archive_sha256']},
                    {**current, 'source_partition_sha256': {
                        **current['source_partition_sha256'], 'product': '0' * 64}},
                    {**current, 'model_xml_sha256': '0' * 64},
                    {**current, 'display': {**current['display'], 'density': 480.0}}]
        for selected in variants:
            with self.subTest(profile=selected), tempfile.TemporaryDirectory() as temporary, \
                    patch('build_image.erofs') as read:
                output = Path(temporary) / 'output'
                with self.assertRaisesRegex(RuntimeError, 'Unsupported official hongkong'):
                    rear_config.image_replacements(selected, temporary, SDK, output)
                read.assert_not_called()
                self.assertFalse(output.exists())

    def test_hardware_properties_are_idempotent_and_keep_user_preferences(self):
        selected = profile('4.0.18.0.XFRCNXM')
        original = (b'ro.test.keep=value\npersist.sys.multi_display_type=0\n'
                    b'persist.sys.rear_user_preference=false\n')
        fixed = rear_config.properties(original, selected)
        self.assertEqual(rear_config.properties(fixed, selected), fixed)
        self.assertIn(b'ro.test.keep=value\n', fixed)
        self.assertIn(b'persist.sys.rear_user_preference=false\n', fixed)
        for key, value in rear_config.PROPERTIES.items():
            self.assertEqual(fixed.count((key + '=' + value + '\n').encode()), 1)
        with self.assertRaisesRegex(RuntimeError, 'Duplicate'):
            rear_config.properties(original + b'persist.sys.multi_display_type=6\n', selected)
        with self.assertRaisesRegex(RuntimeError, 'Unsupported official'):
            rear_config.properties(original, profile('4.0.17.0.XFRCNXM'))

    def test_boot_capabilities_are_restored_after_persistent_property_loading(self):
        init = rear_config.boot_init(profile('4.0.18.0.XFRCNXM')).decode()
        self.assertIn('on post-fs-data\n', init)
        self.assertIn('on property:ro.persistent_properties.ready=true\n', init)
        for key, value in rear_config.PROPERTIES.items():
            self.assertEqual(init.count(f'    setprop {key} {value}\n'), 2)

    def test_static_physical_boot_requires_verified_resources_and_both_native_fixes(self):
        selected = profile('4.0.18.0.XFRCNXM')
        build = build_fixture(rear_fix.EXPECTED_WAKE_MANIFEST, selected['hyperos'])
        expected = ['-append-userspace-opt', rear_config.BOOT_PROPERTY]
        for name in ('Any_Renamed_AVD', 'HyperOS_4_R3_API_37'):
            self.assertEqual(rear_config.runtime_options({**build, 'name': name}), expected)
        for key in ('rear_display_composer_fix', 'goldfish_sync_fix'):
            with self.subTest(key=key), self.assertRaisesRegex(RuntimeError, 'Unverified'):
                rear_config.runtime_options({**build, key: {}})
        for field in ('schema', 'source_sha256', 'mapping_sha256', 'overlay_priority'):
            altered = {**build, 'rear_display': {**build['rear_display'], field: 'unknown'}}
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, 'Unverified'):
                rear_config.runtime_options(altered)
        for old in ({}, {'source': 'gsi'}, {'source': 'official-yingtian-ota'},
                    {'hyperos': '4.0.17.0.XFRCNXM'}):
            self.assertEqual(rear_config.runtime_options(old), [])

    def test_unknown_profile_fails_before_source_reads_or_output_creation(self):
        selected = profile('4.0.18.0.XFRCNXM')
        for field, value in (('hyperos', '4.0.17.0.XFRCNXM'), ('device', 'yingtian'),
                             ('archive_sha256', 'f' * 64), ('incremental', 'unverified'),
                             ('display', {'width': 912, 'height': 596, 'density': 450}),
                             ('source_partition_sha256', {'product': 'f' * 64})):
            altered = copy.deepcopy(selected)
            altered[field] = value
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary, \
                    patch('build_image.erofs') as read:
                output = Path(temporary) / 'output'
                with self.assertRaisesRegex(RuntimeError, 'Unsupported official hongkong'):
                    rear_config.image_replacements(altered, Path(temporary), SDK, output)
                read.assert_not_called()
                self.assertFalse(output.exists())

    def test_overlay_xml_contains_only_fixed_primary_and_rear_id_mapping(self):
        resources = ET.fromstring(rear_config.RESOURCE_XML)
        self.assertEqual(resources.tag, 'resources')
        self.assertEqual(len(resources), 1)
        array = resources[0]
        self.assertEqual((array.tag, array.attrib['name']),
                         ('string-array', 'config_displayUniqueIdArray'))
        self.assertEqual([item.text for item in array],
                         ['local:4619827259835644672', 'local:4619827551948147201'])
        self.assertEqual(rear_config.MAPPING_SHA256, hashlib.sha256(rear_config.RESOURCE_XML).hexdigest())
        self.assertGreater(rear_config.PRIORITY, 1000)

    def test_incomplete_or_unverified_source_bytes_are_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'Incomplete'):
            rear_config.validate_sources({})
        with self.assertRaisesRegex(RuntimeError, 'Unexpected original'):
            rear_config.validate_sources({path: b'unverified' for path in rear_config.SOURCE_SHA256})

    def test_source_array_order_and_original_geometry_are_required(self):
        framework, aosp, devices = reference_tables()
        rear_config.validate_resource_tables(framework, aosp, devices)
        mutations = (
            (framework.replace('@string/config_secondaryBuiltInDisplayCutout]',
                               '@string/config_mainBuiltInDisplayCutout]'), aosp, devices),
            (framework, aosp.replace('4630947121878579348', '4619827551948147201'), devices),
            (framework, aosp, devices.replace('L -160,596', 'L -159,596')),
            (framework, aosp, devices.replace('106.000000px', '180.000000px')),
            (framework.replace('array/config_roundedCornerTopRadiusArray',
                               'array/missing'), aosp, devices),
        )
        for tables in mutations:
            with self.subTest(tables=tables), self.assertRaises(RuntimeError):
                rear_config.validate_resource_tables(*tables)

@unittest.skipUnless(all(path.is_file() for path in FIXTURE_PATHS.values()),
                     'Pinned original Xiaomi source files are not bundled')
class PinnedRearResourcesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources = {name: path.read_bytes() for name, path in FIXTURE_PATHS.items()}
        cls.selected = profile('4.0.18.0.XFRCNXM')

    def test_exact_original_fixture_density_mapping_is_preserved(self):
        rear_config.validate_profile(self.selected)
        rear_config.validate_sources(self.sources)
        xml = ET.fromstring(self.sources['product/etc/displayconfig/display_id_4630947121878579348.xml'])
        self.assertEqual([node.text for node in xml.findall('densityMapping/density/*')],
                         ['596', '912', '450'])
        self.assertEqual(xml.findtext('lightSensor/type'), 'xiaomi.sensor.back_lux')

    def test_each_original_xml_and_signed_resource_package_rejects_byte_tampering(self):
        for path in self.sources:
            with self.subTest(path=path):
                sources = dict(self.sources)
                sources[path] += b'changed'
                with self.assertRaisesRegex(RuntimeError, 'Unexpected original rear-display source'):
                    rear_config.validate_sources(sources)

    def test_image_edits_add_aliases_without_replacing_official_files(self):
        def read(image, path):
            part = Path(image).stem
            key = part + '/' + (path.removeprefix('/system/') if part == 'system'
                                else path.removeprefix('/'))
            return self.sources[key]
        with tempfile.TemporaryDirectory() as temporary, \
                patch('build_image.erofs', side_effect=read), \
                patch.object(rear, 'build_overlay', return_value=b'new standalone signed RRO'):
            edits, marker = rear_config.image_replacements(self.selected, Path(temporary), SDK, temporary)
        self.assertEqual(set(edits), {
            'product/etc/displayconfig/display_id_4619827259835644672.xml',
            'product/etc/displayconfig/display_id_4619827551948147201.xml',
            rear_config.OVERLAY_PATH, rear_config.MARKER_PATH})
        self.assertFalse(set(edits) & set(self.sources))
        for source, target in zip(rear_config.SOURCE_IDS, rear_config.PHYSICAL_IDS):
            self.assertEqual(edits[f'product/etc/displayconfig/display_id_{target}.xml'][0],
                             self.sources[f'product/etc/displayconfig/display_id_{source}.xml'])
        self.assertTrue(all(mode == 0o644 and label == 'u:object_r:system_file:s0'
                            for _, mode, label in edits.values()))
        self.assertEqual(json.loads(edits[rear_config.MARKER_PATH][0]), marker)
        self.assertEqual(marker['source_sha256'], rear_config.SOURCE_SHA256)
        self.assertEqual(marker['mapping_sha256'], rear_config.MAPPING_SHA256)
        self.assertEqual(marker['overridden_resources'], ['config_displayUniqueIdArray'])
        self.assertEqual([entry['density'] for entry in marker['displays']], [480, 450])
        self.assertTrue(marker['requires_runtime_resource_verification'])

    def test_tampered_source_fails_before_overlay_build(self):
        def read(image, path):
            part = Path(image).stem
            key = part + '/' + (path.removeprefix('/system/') if part == 'system'
                                else path.removeprefix('/'))
            return self.sources[key] + b'tamper'
        with tempfile.TemporaryDirectory() as temporary, \
                patch('build_image.erofs', side_effect=read), \
                patch.object(rear, 'build_overlay') as compile:
            with self.assertRaisesRegex(RuntimeError, 'Unexpected original'):
                rear_config.image_replacements(self.selected, temporary, SDK, Path(temporary) / 'output')
            compile.assert_not_called()
            self.assertFalse((Path(temporary) / 'output').exists())

    @unittest.skipUnless((SDK / 'build-tools/37.0.0/aapt2').is_file() and
                         (SDK / 'platforms/android-36/android.jar').is_file(),
                         'Pinned official Android build tools are unavailable')
    def test_real_aapt_compilation_has_one_resource_and_a_code_free_static_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            signed = rear_config.build_overlay(SDK, output, self.sources)
            self.assertTrue(signed.startswith(b'PK'))
            dump = subprocess.run([str(SDK / 'build-tools/37.0.0/aapt2'), 'dump', 'xmltree',
                                   str(output / 'RearDisplay.apk'), '--file', 'AndroidManifest.xml'],
                                  check=True, capture_output=True, text=True).stdout
            self.assertIn('android:priority(0x0101001c)=1001', dump)
            self.assertIn('android:targetPackage(0x01010021)="android"', dump)
            self.assertIn('android:isStatic(0x0101055a)=true', dump)
            self.assertIn('android:hasCode(0x0101000c)=false', dump)
            self.assertIn('android:targetSdkVersion(0x01010270)=28', dump)
            for path in rear_config.SOURCE_SHA256:
                if path.endswith('.apk'):
                    self.assertEqual((output / ('original-' + Path(path).name)).read_bytes(),
                                     self.sources[path])

if __name__ == '__main__':
    unittest.main()


# --- tests/test_rear_display_install.py ---

"""Verify rear wake installation and startup without operating an emulator."""

DISPLAY = ('DisplayInfo{"Rear", displayId 1, displayGroupId 1, '
           'uniqueId "local:4619827551948147201", state OFF}')

JAR = b'reviewed DEX fixture for installation guards'

def build_fixture(wake, version=rear_config.VERSION):
    selected = profile(version)
    displays = []
    for original, physical, geometry in zip(rear_config.SOURCE_IDS, rear_config.PHYSICAL_IDS,
                                            ((1120, 2436, 480), (912, 596, 450))):
        source = f'product/etc/displayconfig/display_id_{original}.xml'
        displays.append({'source_physical_id': original, 'physical_id': physical,
                         'unique_id': 'local:' + str(physical),
                         'config': f'/product/etc/displayconfig/display_id_{physical}.xml',
                         'config_sha256': rear_config.SOURCE_SHA256[source],
                         'width': geometry[0], 'height': geometry[1], 'density': geometry[2]})
    marker = {'schema': 1, 'hyperos': selected['hyperos'],
              'archive_sha256': selected['archive_sha256'],
              'source_sha256': dict(rear_config.SOURCE_SHA256), 'mapping_sha256': rear_config.MAPPING_SHA256,
              'overlay': rear_config.OVERLAY, 'overlay_path': '/' + rear_config.OVERLAY_PATH,
              'overlay_sha256': hashlib.sha256(b'ID-only RRO fixture').hexdigest(),
              'overlay_priority': 1001, 'source_overlay_priority': 1000,
              'requires_runtime_resource_verification': True,
              'overridden_resources': ['config_displayUniqueIdArray'], 'displays': displays,
              'rear_safe_inset_left': 296, 'rear_corner_radius': 106}
    return {'source': 'official-hongkong-ota', 'hyperos': selected['hyperos'],
            'archive_sha256': selected['archive_sha256'], 'rear_display': marker,
            'rear_display_composer_fix': dict(COMPOSER), 'goldfish_sync_fix': dict(SYNC),
            'rear_display_wake_fix': copy.deepcopy(wake)}

def module_manifest(build):
    return {'schema': 1, 'revision': 2, 'module_id': rear_fix.MODULE_ID,
            'firmware': {'source': build['source'], 'hyperos': build['hyperos'],
                         'incremental': 'OS' + build['hyperos'], 'archive_sha256': build['archive_sha256'],
                         'hardware': 'ranchu', 'device': 'hongkong'},
            'marker': {'path': '/' + rear_config.MARKER_PATH,
                       'sha256': rear_fix.digest(rear_fix.encode(build['rear_display']))},
            'wake': copy.deepcopy(build['rear_display_wake_fix'])}

class Guest:
    """Small read/write command mock; unsupported commands fail the test."""
    def __init__(self, build, name):
        wake = build['rear_display_wake_fix']
        self.files = {'/' + rear_config.MARKER_PATH: rear_fix.encode(build['rear_display']),
                      wake['jar_path']: JAR, wake['script_path']: rear_fix.LAUNCHER}
        self.properties = ['ranchu', 'hongkong', 'OS' + build['hyperos'], name]
        self.display = DISPLAY
        self.module = ''
        self.flags = []
        self.occupied = False
        self.commands = []
        self.mutations = []
        self.pushes = []
        self.starts = 0
        self.ready = True
        self.confirmations = 0

    def existing(self, manifest):
        self.module = 'directory'
        self.files.update({rear_fix.MODULE + '/manifest.json': rear_fix.encode(manifest),
                           rear_fix.MODULE + '/module.prop': rear_fix.MODULE_PROP.encode(),
                           rear_fix.MODULE + '/service.sh': rear_fix.boot_script(manifest).encode(),
                           rear_fix.MODULE + '/skip_mount': b''})

    def root(self, config, command):
        self.commands.append(command)
        if command == lifecycle.state_script(rear_fix.MODULE):
            return '\n'.join(self.flags)
        code = command.removeprefix('set -e\n').removeprefix(lifecycle.mutation_guard(rear_fix.MODULE))
        if 'sha256sum ' + rear_fix.MODULE + '/service.sh' in code.splitlines():
            return rear_fix.digest(self.files[rear_fix.MODULE + '/service.sh']) + '  service.sh'
        lines = code.splitlines()
        if code.startswith('getprop '):
            return '\n'.join(self.properties)
        if code.startswith('sha256sum '):
            return '\n'.join(f'{rear_fix.digest(self.files[path])}  {path}'
                             for path in shlex.split(code)[1:])
        if code == 'dumpsys display':
            return self.display
        if code.startswith('if [ -L ' + rear_fix.MODULE + ' ];'):
            return self.module
        if code.startswith('cat '):
            return self.files[shlex.split(code)[1]].decode().strip()
        if code.startswith('for flag in disable remove;'):
            return '\n'.join(self.flags)
        if code.startswith('if [ -e ' + rear_fix.MODULE + '/disable ]'):
            if not self.flags:
                self.starts += 1
            return ''
        if code.startswith('MODDIR='):
            self.confirmations += 1
            if not self.ready:
                raise RuntimeError('mock readiness failure')
            return 'ready'
        if code.startswith('if [ -e /data/adb/hyperos-rear-display-stage-'):
            return 'occupied' if self.occupied else ''
        if code.startswith('mkdir -p /data/adb/modules\nmkdir '):
            self.mutations.append(command)
            return ''
        if code.startswith('test "$(sha256sum '):
            self.mutations.append(command)
            source = lines[0].split('sha256sum ', 1)[1].split(' |', 1)[0]
            expected = lines[0].rsplit(' = ', 1)[1]
            if rear_fix.digest(self.files[source]) != expected:
                raise RuntimeError('mock push checksum failure')
            _, source, target = shlex.split(lines[1])
            self.files[target] = self.files[source]
            del self.files[shlex.split(lines[3])[1]]
            return ''
        if code.startswith('if [ -e ' + rear_fix.MODULE + ' ]'):
            self.mutations.append(command)
            if self.module:
                raise RuntimeError('mock activation race')
            _, stage, target = shlex.split(lines[1])
            self.files.update({target + path[len(stage):]: data
                               for path, data in list(self.files.items())
                               if path.startswith(stage + '/')})
            self.module = 'directory'
            return ''
        raise AssertionError('Unexpected root command: ' + command)

    def adb(self, config, operation, local, remote, **kwargs):
        assert operation == 'push'
        self.files[remote] = Path(local).read_bytes()
        self.pushes.append((local, remote))
        return subprocess.CompletedProcess([], 0)

class RearInstallTests(unittest.TestCase):
    def setUp(self):
        context = ExitStack()
        self.addCleanup(context.close)
        self.folder = Path(context.enter_context(tempfile.TemporaryDirectory()))
        self.wake = {**rear_fix.EXPECTED_WAKE_MANIFEST, 'jar_sha256': rear_fix.digest(JAR)}
        context.enter_context(patch.object(fix, 'EXPECTED_WAKE_MANIFEST', self.wake))
        context.enter_context(patch.object(fix, 'ROOT', self.folder))
        self.config = {'name': 'A_Renamed_Owned_AVD', 'port': 5584}
        self.build = build_fixture(self.wake)
        self.manifest = module_manifest(self.build)
        self.guest = Guest(self.build, self.config['name'])
        self.official = context.enter_context(patch.object(fix, 'official'))
        self.root = context.enter_context(patch.object(fix, 'root', side_effect=self.guest.root))
        self.adb = context.enter_context(patch.object(fix, 'adb', side_effect=self.guest.adb))

    def unchanged(self):
        self.assertEqual(self.guest.mutations, [])
        self.assertEqual(self.guest.pushes, [])
        self.assertEqual(self.guest.starts, 0)
        self.assertFalse((self.folder / 'work').exists())

    def test_new_baked_context_validates_without_widening_legacy_installer(self):
        current = build_fixture(self.wake, '4.0.24.0.XFRCNXM')
        self.assertEqual(rear_fix.validate_build(current), current['rear_display'])
        future = {**current, 'source': 'custom', 'hyperos': '5.9.99.0.FUTURE', 'archive_sha256': 'a' * 64,
                  'rear_display': {**current['rear_display'], 'hyperos': '5.9.99.0.FUTURE', 'archive_sha256': 'a' * 64}}
        self.assertEqual(rear_fix.validate_build(future), future['rear_display'])
        with self.assertRaisesRegex(RuntimeError, 'legacy rear installer'):
            rear_fix.install(self.config, current)
        self.official.assert_not_called()
        self.root.assert_not_called()
        self.unchanged()

    def test_new_baked_context_rejects_old_or_tampered_provenance(self):
        current = build_fixture(self.wake, '4.0.24.0.XFRCNXM')
        variants = [{**current, 'archive_sha256': self.build['archive_sha256']},
                    {**current, 'rear_display': copy.deepcopy(self.build['rear_display'])},
                    {**current, 'hyperos': '4.0.999.0.XFRCNXM'}]
        for field, value in (('source_sha256', {}), ('schema', True),
                             ('rear_corner_radius', 106.0), ('overlay_sha256', 'unverified')):
            variants.append({**current, 'rear_display': {**current['rear_display'], field: value}})
        for build in variants:
            with self.subTest(build=build), self.assertRaises(RuntimeError):
                rear_fix.validate_build(build)
        self.official.assert_not_called()
        self.root.assert_not_called()
        self.unchanged()

    def test_bad_source_profile_receipts_and_types_fail_before_guest_reads(self):
        variants = [{**self.build, key: value} for key, value in (
            ('source', 'official-yingtian-ota'), ('hyperos', '4.0.17.0.XFRCNXM'),
            ('archive_sha256', '0' * 64), ('rear_display', None),
            ('rear_display_composer_fix', {}), ('goldfish_sync_fix', {}),
            ('rear_display_wake_fix', {}))]
        for key, value in (('revision', 2.0), ('schema', True),
                           ('require_down_after_observed_sleep', 1),
                           ('source_sha256', '0' * 64), ('jar_sha256', '0' * 64),
                           ('script_sha256', '0' * 64), ('display_unique_id', 'wrong')):
            variants.append({**self.build, 'rear_display_wake_fix': {**self.wake, key: value}})
        altered = copy.deepcopy(self.build)
        altered['rear_display']['displays'][1]['unique_id'] = 'local:another'
        variants.append(altered)
        for build in variants:
            with self.subTest(build=build), self.assertRaises(RuntimeError):
                rear_fix.install(self.config, build)
        self.official.assert_not_called()
        self.root.assert_not_called()
        self.unchanged()

    def test_changed_host_source_or_launcher_fails_before_guest_reads(self):
        for key, value in (('JAVA_SOURCE', rear_fix.JAVA_SOURCE + '\n// changed\n'),
                           ('LAUNCHER', rear_fix.LAUNCHER + b'# changed\n')):
            with self.subTest(key=key), patch.object(fix, key, value), self.assertRaises(RuntimeError):
                rear_fix.install(self.config, self.build)
        self.root.assert_not_called()
        self.unchanged()

    def test_invalid_name_or_unowned_registered_instance_is_refused(self):
        for name in ('', None, 'name\nother', 'name\0other'):
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                rear_fix.install({**self.config, 'name': name}, self.build)
        self.official.assert_not_called()
        self.official.side_effect = RuntimeError('not the registered owned instance')
        with self.assertRaisesRegex(RuntimeError, 'registered owned'):
            rear_fix.install(self.config, self.build)
        self.root.assert_not_called()
        self.unchanged()

    def test_wrong_live_hardware_product_incremental_or_name_never_writes(self):
        original = list(self.guest.properties)
        for index, value in enumerate(('physical', 'yingtian', 'OS4.0.17.0.XFRCNXM', 'Other_AVD')):
            self.guest.properties = original.copy()
            self.guest.properties[index] = value
            with self.subTest(index=index), self.assertRaisesRegex(RuntimeError, 'guest identity'):
                rear_fix.install(self.config, self.build)
        self.unchanged()

    def test_wrong_baked_marker_jar_or_launcher_hash_never_writes(self):
        original = dict(self.guest.files)
        for path in original:
            self.guest.files = {**original, path: original[path] + b'changed'}
            with self.subTest(path=path), self.assertRaisesRegex(RuntimeError, 'checksum mismatch'):
                rear_fix.install(self.config, self.build)
        self.unchanged()

    def test_display_identifiers_must_match_together_before_writes(self):
        for display in (DISPLAY.replace('displayId 1', 'displayId 10'),
                        DISPLAY.replace('displayGroupId 1', 'displayGroupId 0'),
                        DISPLAY.replace('4619827551948147201', '4619827259835644672'),
                        'DisplayInfo{displayId 1}\nDisplayInfo{displayGroupId 1, '
                        'uniqueId "local:4619827551948147201"}'):
            self.guest.display = display
            with self.subTest(display=display), self.assertRaisesRegex(RuntimeError, 'not ready'):
                rear_fix.install(self.config, self.build)
        self.unchanged()

    def test_fresh_module_has_only_service_assets_no_host_compilation(self):
        self.assertEqual(rear_fix.install(self.config, self.build), self.manifest)
        self.official.assert_called_once_with(self.config)
        self.assertEqual(len(self.guest.pushes), 4)
        self.assertEqual(self.guest.starts, 1)
        self.assertEqual(self.guest.confirmations, 1)
        self.assertEqual(set((self.folder / 'work/rear-display-fix').iterdir()),
                         {self.folder / 'work/rear-display-fix' / name for name in
                          ('manifest.json', 'module.prop', 'service.sh', 'skip_mount')})
        for command in self.guest.mutations:
            self.assertTrue(command.startswith('set -e\n'), command)
        self.assertIn('then exit 1; fi\nmv ', self.guest.mutations[-1])
        self.assertTrue(self.guest.mutations[-1].endswith('\nsync'))
        self.assertEqual(self.guest.files[rear_fix.MODULE + '/skip_mount'], b'')
        self.assertEqual(self.guest.files[self.wake['jar_path']], JAR)

    def test_actual_shell_stops_bad_push_and_refuses_activation_race(self):
        rear_fix.install(self.config, self.build)
        copy_script = next(code for code in self.guest.mutations
                           if code.startswith('set -e\ntest "$(sha256sum '))
        source = copy_script.split('sha256sum ', 1)[1].split(' |', 1)[0]
        target = shlex.split(copy_script.splitlines()[2])[2]
        temporary_source = self.folder / 'bad-upload'
        temporary_target = self.folder / 'must-not-copy'
        temporary_source.write_bytes(b'corrupt upload')
        hash_program = self.folder / 'sha256sum'
        hash_program.write_text('#!' + sys.executable + '\n'
            'import hashlib, pathlib, sys\n'
            'print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())\n')
        hash_program.chmod(0o700)
        code = copy_script.replace(source, str(temporary_source)).replace(target, str(temporary_target))
        result = subprocess.run(['sh', '-c', code], capture_output=True,
            env=dict(os.environ, PATH=str(self.folder) + ':' + os.environ['PATH']))
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(temporary_source.exists())
        self.assertFalse(temporary_target.exists())

        activation = self.guest.mutations[-1]
        stripped = activation.removeprefix('set -e\n').removeprefix(lifecycle.mutation_guard(rear_fix.MODULE))
        stage = shlex.split(stripped.splitlines()[1])[1]
        staged = self.folder / 'stage'
        foreign = self.folder / 'foreign-module'
        staged.mkdir()
        foreign.mkdir()
        (staged / 'service.sh').write_text('owned staged file')
        (foreign / 'keep').write_text('foreign module must remain')
        code = activation.replace(stage, str(staged)).replace(rear_fix.MODULE, str(foreign))
        result = subprocess.run(['sh', '-c', code], capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((foreign / 'keep').read_text(), 'foreign module must remain')
        self.assertEqual(set(foreign.iterdir()), {foreign / 'keep'})
        self.assertTrue((staged / 'service.sh').exists())

    def test_exact_module_reuse_survives_avd_rename_without_rewriting(self):
        self.guest.existing(self.manifest)
        original = dict(self.guest.files)
        for name in (self.config['name'], 'Another_Name_After_Install'):
            config = {**self.config, 'name': name}
            self.guest.properties[-1] = name
            self.assertEqual(rear_fix.install(config, self.build), self.manifest)
        self.assertNotIn('avd_name', self.manifest)
        script = self.guest.files[rear_fix.MODULE + '/service.sh'].decode()
        self.assertNotIn('ro.boot.qemu.avd_name', script)
        self.assertNotIn(self.config['name'], script)
        self.assertEqual(self.guest.files, original)
        self.assertEqual(self.guest.starts, 2)
        self.assertEqual(self.guest.confirmations, 2)
        self.assertEqual(self.guest.pushes, [])
        self.assertFalse((self.folder / 'work').exists())

    def test_disabled_and_removed_existing_modules_are_preserved(self):
        self.guest.existing(self.manifest)
        original = dict(self.guest.files)
        for flags in (['disable'], ['remove'], ['disable', 'remove']):
            self.guest.flags = flags
            self.assertEqual(rear_fix.install(self.config, self.build),
                             {'preserved': True, 'lifecycle': flags})
        self.assertEqual(self.guest.files, original)
        self.assertEqual(self.guest.confirmations, 0)
        self.unchanged()

    def test_install_never_reports_success_when_started_daemon_is_unready(self):
        self.guest.existing(self.manifest)
        self.guest.ready = False
        with self.assertRaisesRegex(RuntimeError, '10-second readiness check'):
            rear_fix.install(self.config, self.build)
        self.assertEqual(self.guest.starts, 1)
        self.assertEqual(self.guest.confirmations, 1)
        self.assertEqual(self.guest.pushes, [])

    def test_foreign_module_manifest_property_service_and_stage_are_refused(self):
        for kind in ('foreign', 'manifest', 'property', 'service', 'skip_mount'):
            self.guest.existing(self.manifest)
            if kind == 'foreign':
                self.guest.module = 'foreign'
            else:
                key = {'manifest': 'manifest.json', 'property': 'module.prop',
                       'service': 'service.sh', 'skip_mount': 'skip_mount'}[kind]
                self.guest.files[rear_fix.MODULE + '/' + key] += b'foreign'
            with self.subTest(kind=kind), self.assertRaises(RuntimeError):
                rear_fix.install(self.config, self.build)
        self.guest.module = ''
        self.guest.occupied = True
        with self.assertRaisesRegex(RuntimeError, 'staging path'):
            rear_fix.install(self.config, self.build)
        self.unchanged()

    def test_default_build_path_and_explicit_build_hook(self):
        folder = self.folder / 'local'
        folder.mkdir()
        (folder / 'build.json').write_text(json.dumps(self.build))
        self.guest.existing(self.manifest)
        self.assertEqual(rear_fix.install(self.config), self.manifest)
        (folder / 'build.json').unlink()
        self.assertEqual(rear_fix.install(self.config, self.build), self.manifest)

class StartupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name)
        self.module = self.folder / 'module'
        self.module.mkdir()
        self.proc = self.folder / 'proc'
        (self.proc / 'sys/kernel/random').mkdir(parents=True)
        (self.proc / 'sys/kernel/random/boot_id').write_text('fixture-boot\n')
        self.jar = self.folder / 'bridge.jar'
        self.jar.write_bytes(JAR)
        self.launcher = self.folder / 'bridge'
        self.launcher.write_bytes(rear_fix.LAUNCHER)
        self.marker = self.folder / 'marker.json'
        self.marker.write_bytes(b'reviewed marker bytes')
        self.manifest = {'wake': {**rear_fix.EXPECTED_WAKE_MANIFEST,
                                 'jar_path': str(self.jar), 'jar_sha256': rear_fix.digest(JAR),
                                 'script_path': str(self.launcher)},
                         'marker': {'path': str(self.marker),
                                    'sha256': rear_fix.digest(self.marker.read_bytes())}}
        (self.module / 'manifest.json').write_bytes(rear_fix.encode(self.manifest))
        (self.module / 'module.prop').write_text(rear_fix.MODULE_PROP)
        (self.module / 'skip_mount').touch()
        self.tools = self.folder / 'tools'
        self.tools.mkdir()
        self.busybox = self.tools / 'busybox'
        self.busybox.write_text('#!' + sys.executable + '\n'
            'import fcntl, hashlib, os, pathlib, sys\n'
            'if sys.argv[1] == "sha256sum":\n'
            '    p=sys.argv[2]; print(hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()+"  "+p)\n'
            'elif sys.argv[1] == "stat":\n'
            '    value=os.stat(sys.argv[-1]); print(0 if sys.argv[3] == "%u" else value.st_nlink)\n'
            'elif sys.argv[1] == "flock":\n'
            '    try: fcntl.flock(int(sys.argv[-1]), fcntl.LOCK_EX | fcntl.LOCK_NB)\n'
            '    except BlockingIOError: raise SystemExit(1)\n'
            'elif sys.argv[1] == "nohup":\n'
            '    raise SystemExit("unexpected daemon launch")\n'
            'else:\n'
            '    os.execvp(sys.argv[1],sys.argv[1:])\n')
        self.busybox.chmod(0o700)
        self.properties = {'sys.boot_completed': '1', 'ro.boot.hardware': 'ranchu',
                           'ro.product.device': 'hongkong',
                           'ro.mi.os.version.incremental': 'OS' + rear_config.VERSION}
        self.getprop = self.tools / 'getprop'
        self.write_properties()
        (self.tools / 'id').write_text('#!/bin/sh\necho 0\n')
        (self.tools / 'id').chmod(0o700)
        self.environment = dict(os.environ, PATH=str(self.tools) + ':' + os.environ['PATH'])
        self.script = rear_fix.boot_script(self.manifest).replace(
            'BB=/data/adb/ksu/bin/busybox', 'BB=' + shlex.quote(str(self.busybox))).replace(
            'PROC=/proc', 'PROC=' + shlex.quote(str(self.proc)))
        self.service = self.module / 'service.sh'
        self.service.write_text(self.script)

    def write_properties(self):
        self.getprop.write_text('#!/bin/sh\ncase "$1" in\n' +
            ''.join(key + ') echo ' + shlex.quote(value) + ';;\n'
                    for key, value in self.properties.items()) + 'esac\n')
        self.getprop.chmod(0o700)

    def process(self, pid=123, class_name=rear_fix.CLASS, classpath=None, uid=0):
        directory = self.proc / str(pid)
        directory.mkdir(exist_ok=True)
        (directory / 'cmdline').write_bytes(b'app_process\0/system/bin\0' + class_name.encode() + b'\0')
        (directory / 'environ').write_bytes(('CLASSPATH=' + str(classpath or self.jar)).encode() + b'\0')
        (directory / 'status').write_text(f'Name:\tapp_process\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n')

    def run_service(self):
        return subprocess.run(['sh', str(self.service)], env=self.environment,
                              capture_output=True, text=True, timeout=15)

    def test_shell_syntax_and_repeated_owned_startup_never_launch_again(self):
        result = subprocess.run(['sh', '-n', str(self.service)], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.process()
        for _ in range(2):
            result = self.run_service()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((self.module / 'daemon.pid').read_text(), '123\n')
            self.assertFalse((self.module / 'startup.lock').exists())
        self.assertFalse((self.module / 'wake.log').exists())

    def test_shell_hash_alias_cannot_intercept_guard_checks(self):
        # Insert the alias after the function declaration: POSIX shells differ
        # in whether defining a function clears an existing alias. Android
        # mksh's preset hash alias was observed intercepting the old calls.
        collision = self.script.replace('guard() {', 'alias hash=false\nguard() {')
        self.process()
        self.service.write_text(collision)
        result = self.run_service()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.module / 'daemon.pid').read_text(), '123\n')
        # Negative control proves this shell actually expands the alias and
        # would fail the former production helper's checksum guards.
        self.service.write_text(collision.replace('hyperos_file_sha', 'hash'))
        result = self.run_service()
        self.assertNotEqual(result.returncode, 0)

    def test_readiness_receipt_requires_live_owned_process_and_is_bounded(self):
        probe = rear_fix.readiness_script().replace(rear_fix.MODULE, str(self.module)).replace(
            rear_fix.EXPECTED_WAKE_MANIFEST['jar_path'], str(self.jar)).replace(
            'BB=/data/adb/ksu/bin/busybox', 'BB=' + shlex.quote(str(self.busybox))).replace(
            'PROC=/proc', 'PROC=' + shlex.quote(str(self.proc)))
        path = self.folder / 'readiness.sh'
        path.write_text(probe)
        # Remove real delays while executing the production bounded loop.
        sleeps = self.folder / 'sleeps'
        (self.tools / 'sleep').write_text('#!/bin/sh\necho wait >> ' + shlex.quote(str(sleeps)) + '\n')
        (self.tools / 'sleep').chmod(0o700)
        self.process()
        (self.module / 'daemon.pid').write_text('123\n')
        result = subprocess.run(['sh', str(path)], env=self.environment,
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'ready')
        self.assertFalse(sleeps.exists())
        for pid, uid in (('999', 0), ('123', 2000)):
            (self.module / 'daemon.pid').write_text(pid + '\n')
            self.process(uid=uid)
            result = subprocess.run(['sh', str(path)], env=self.environment,
                                    capture_output=True, text=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('not ready after 10 seconds', result.stderr)
            self.assertEqual(len(sleeps.read_text().splitlines()), 10)
            sleeps.unlink()
        flag = self.module / 'disable'
        flag.symlink_to(self.folder / 'missing')
        result = subprocess.run(['sh', str(path)], env=self.environment,
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertFalse(sleeps.exists())

    def test_ownership_requires_exact_class_classpath_and_root_uid(self):
        definitions = self.script.split('owned() {', 1)[1].split('LOCK=', 1)[0]
        probe = ('PROC=' + shlex.quote(str(self.proc)) + '\nBB=' + shlex.quote(str(self.busybox)) +
                 '\nCLASS=' + shlex.quote(rear_fix.CLASS) + '\nJAR=' + shlex.quote(str(self.jar)) +
                 '\nowned() {' + definitions + '\nowned "$1"\n')
        path = self.folder / 'owned.sh'
        path.write_text(probe)
        for class_name, classpath, uid, accepted in (
                (rear_fix.CLASS, self.jar, 0, True), (rear_fix.CLASS + 'Foreign', self.jar, 0, False),
                (rear_fix.CLASS, self.folder / 'foreign.jar', 0, False),
                (rear_fix.CLASS, self.jar, 2000, False)):
            self.process(class_name=class_name, classpath=classpath, uid=uid)
            result = subprocess.run(['sh', str(path), '123'], env=self.environment,
                                    capture_output=True, timeout=5)
            self.assertEqual(result.returncode == 0, accepted)

    def test_boot_guard_rejects_hashes_and_foreign_firmware_before_writes(self):
        baseline = set(self.module.iterdir())
        original = dict(self.properties)
        for key, value in (('ro.boot.hardware', 'physical'), ('ro.product.device', 'yingtian'),
                           ('ro.mi.os.version.incremental', 'OS4.0.17.0.XFRCNXM')):
            self.properties = {**original, key: value}
            self.write_properties()
            result = self.run_service()
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(set(self.module.iterdir()), baseline)
        self.properties = original
        self.write_properties()
        for path in (self.jar, self.launcher, self.marker, self.module / 'manifest.json',
                     self.module / 'module.prop'):
            data = path.read_bytes()
            path.write_bytes(data + b'changed')
            result = self.run_service()
            path.write_bytes(data)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(set(self.module.iterdir()), baseline)

    def test_disabled_or_removed_service_exits_without_writes(self):
        for name in ('disable', 'remove'):
            flag = self.module / name
            flag.symlink_to(self.folder / 'nonexistent')
            baseline = set(self.module.iterdir())
            self.jar.write_bytes(b'foreign')
            result = self.run_service()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(set(self.module.iterdir()), baseline)
            self.assertTrue(flag.is_symlink())
            flag.unlink()

    def test_legacy_empty_missing_and_dead_boot_records_recover(self):
        self.process()
        lock = self.module / 'startup.lock'
        for files in ({}, {'pid': ''}, {'boot': ''}, {'pid': '999\n'},
                      {'pid': '999\n', 'boot': 'previous-boot\n'}):
            with self.subTest(files=files):
                lock.mkdir()
                for name, value in files.items():
                    (lock / name).write_text(value)
                result = self.run_service()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(lock.exists())
                self.assertEqual((self.module / 'daemon.pid').read_text(), '123\n')
                self.assertTrue((self.module / 'startup.guard').is_file())

    def test_legacy_live_owner_even_without_receipts_preserves_lock(self):
        self.process()
        self.process(pid=456)
        (self.proc / '456/cmdline').write_bytes(b'sh\0' + str(self.service).encode() + b'\0')
        lock = self.module / 'startup.lock'
        for records in ({}, {'pid': '456\n', 'boot': 'fixture-boot\n'}):
            lock.mkdir()
            for name, content in records.items():
                (lock / name).write_text(content)
            result = self.run_service()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(lock.is_dir())
            self.assertEqual({p.name: p.read_text() for p in lock.iterdir()}, records)
            self.assertFalse((self.module / 'daemon.pid').exists())
            for entry in lock.iterdir():
                entry.unlink()
            lock.rmdir()

    def test_legacy_alias_foreign_content_and_malformed_records_are_preserved(self):
        self.process()
        lock = self.module / 'startup.lock'
        for name, content in (('foreign', 'keep'), ('pid', 'not-a-pid'), ('boot', 'invalid/boot')):
            lock.mkdir()
            (lock / name).write_text(content)
            result = self.run_service()
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((lock / name).read_text(), content)
            (lock / name).unlink()
            lock.rmdir()
        foreign = self.folder / 'foreign-lock'
        foreign.mkdir()
        (foreign / 'pid').write_text('999\n')
        lock.symlink_to(foreign, target_is_directory=True)
        result = self.run_service()
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(lock.is_symlink())
        self.assertEqual((foreign / 'pid').read_text(), '999\n')

    def test_kernel_lease_serializes_concurrency_and_recovers_after_crash(self):
        self.process()
        guard = self.module / 'startup.guard'
        code = ('import fcntl, sys, time; '
                'f=open(sys.argv[1], "a"); fcntl.flock(f, fcntl.LOCK_EX); '
                'print("locked", flush=True); time.sleep(60)')
        owner = subprocess.Popen([sys.executable, '-c', code, str(guard)],
                                 stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(owner.stdout.readline().strip(), 'locked')
            result = self.run_service()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((self.module / 'daemon.pid').exists())
            owner.kill()
            owner.wait(timeout=5)
            result = self.run_service()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((self.module / 'daemon.pid').read_text(), '123\n')
        finally:
            if owner.poll() is None:
                owner.kill()
                owner.wait(timeout=5)
            owner.stdout.close()

    def test_guard_foreign_content_and_hardlink_are_preserved(self):
        self.process()
        guard = self.module / 'startup.guard'
        guard.write_text('foreign lease content')
        result = self.run_service()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(guard.read_text(), 'foreign lease content')
        guard.unlink()
        foreign = self.folder / 'foreign-empty-file'
        foreign.touch()
        guard.hardlink_to(foreign)
        original_mode = foreign.stat().st_mode
        result = self.run_service()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(foreign.stat().st_mode, original_mode)
        self.assertTrue(guard.exists())

    def test_guard_alias_is_never_opened_or_replaced(self):
        self.process()
        target = self.folder / 'foreign-guard'
        target.write_text('keep')
        guard = self.module / 'startup.guard'
        guard.symlink_to(target)
        result = self.run_service()
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(guard.is_symlink())
        self.assertEqual(target.read_text(), 'keep')

if __name__ == '__main__':
    unittest.main()


# --- tests/test_rear_display_wake.py ---

"""Execute the shipped Java protocol parser and double-tap state machine."""

SDK = Path.home() / 'Library/Android/sdk'

IDC = (REPO / 'work/os4-r3-build/work/vendor-rear-tree/'
       'extract-system-8eb9f9313bfb9951/usr/idc/virtio_input_multi_touch_7.idc')

HARNESS = r'''package io.github.hyperosavd;
import java.io.BufferedReader;
import java.io.InputStreamReader;

public class WakeHarness {
    static final class History implements RearDisplayWake.DisplayState {
        final int[] queries;
        RearDisplayWake.Snapshot observed;
        int state = 1;
        long uptime;
        History(int[] queries) { this.queries = queries; }
        void sample(int state, long uptime, boolean poll) {
            this.state = state; this.uptime = uptime;
            if (poll) observe();
        }
        RearDisplayWake.Snapshot observe() {
            observed = RearDisplayWake.DisplayBinder.observe(observed,
                    new RearDisplayWake.Snapshot(RearDisplayWake.UNIQUE_ID, 1, 1, state), uptime);
            return observed;
        }
        public RearDisplayWake.Snapshot snapshot() { queries[0]++; return observe(); }
    }
    public static void main(String[] args) throws Exception {
        BufferedReader input = new BufferedReader(new InputStreamReader(System.in, "UTF-8"));
        if (args[0].equals("idc")) {
            StringBuilder text = new StringBuilder(); String line;
            while ((line = input.readLine()) != null) text.append(line).append('\n');
            RearDisplayWake.validateIdc(text.toString()); return;
        }
        if (args[0].equals("identity")) {
            new RearDisplayWake.Snapshot(args[1], Integer.parseInt(args[2]),
                    Integer.parseInt(args[3]), 1); return;
        }
        final String[] states = args[0].split(",");
        final int[] queries = {0}, wakes = {0};
        final History history = new History(queries);
        RearDisplayWake.DisplayState display = args[0].equals("history") ? history
                : new RearDisplayWake.DisplayState() {
                    public RearDisplayWake.Snapshot snapshot() {
                        int state = Integer.parseInt(states[Math.min(queries[0]++, states.length - 1)]);
                        return new RearDisplayWake.Snapshot(RearDisplayWake.UNIQUE_ID, 1, 1, state);
                    }
                };
        RearDisplayWake.Detector detector = new RearDisplayWake.Detector(display,
                new RearDisplayWake.Wake() { public void run() { wakes[0]++; } });
        RearDisplayWake.EventReader events = new RearDisplayWake.EventReader(detector, "/dev/input/event7");
        String line;
        while ((line = input.readLine()) != null) {
            if (args[0].equals("history") && (line.startsWith("STATE ") || line.startsWith("CURRENT "))) {
                String[] value = line.split(" ");
                history.sample(Integer.parseInt(value[1]), Long.parseLong(value[2]), value[0].equals("STATE"));
            } else events.feed(line);
        }
        System.out.println("WAKES=" + wakes[0] + " QUERIES=" + queries[0]);
    }
}
'''

def event(time, code, value=0, device=False):
    kind = 'EV_SYN' if code.startswith('SYN_') else 'EV_ABS'
    prefix = '/dev/input/event7: ' if device else ''
    return f'[{time // 1000:8d}.{time % 1000:03d}000] {prefix}{kind:8s} {code:20s} {value & 0xffffffff:08x}\n'

def tap(time, duration=80, x=16000, y=12000, slot=0, coordinates=True):
    data = event(time, 'ABS_MT_SLOT', slot) + event(time, 'ABS_MT_TRACKING_ID', 17)
    if coordinates:
        data += event(time, 'ABS_MT_POSITION_X', x) + event(time, 'ABS_MT_POSITION_Y', y)
    return (data + event(time, 'SYN_REPORT')
            + event(time + duration, 'ABS_MT_TRACKING_ID', -1)
            + event(time + duration, 'SYN_REPORT'))

class RearDisplayWakeJavaTest(unittest.TestCase):
    JAVA_SOURCE = rear_wake.JAVA_SOURCE
    HARNESS = HARNESS

    @classmethod
    def setUpClass(cls):
        try:
            cls.java = Path(java())
        except RuntimeError as error:
            raise unittest.SkipTest(str(error))
        javac = cls.java.with_name('javac')
        if not javac.is_file():
            raise unittest.SkipTest('Host JDK javac is unavailable')
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.folder = Path(cls.temp.name)
        package = cls.folder / 'src/io/github/hyperosavd'
        package.mkdir(parents=True)
        source, harness = package / 'RearDisplayWake.java', package / 'WakeHarness.java'
        source.write_text(cls.JAVA_SOURCE)
        harness.write_text(cls.HARNESS)
        subprocess.run([str(javac), '-source', '8', '-target', '8', '-d', str(cls.folder),
                        str(source), str(harness)], check=True, capture_output=True)

    def execute(self, text, states='1', args=None, check=True):
        return subprocess.run([str(self.java), '-cp', str(self.folder),
                               'io.github.hyperosavd.WakeHarness', *(args or [states])],
                              input=text, text=True, capture_output=True, check=check)

    def test_only_two_short_stationary_taps_wake(self):
        for state in (1, 3, 4):
            with self.subTest(state=state):
                result = self.execute(tap(1000) + tap(1250, x=16200, y=12200), str(state))
                self.assertEqual(result.stdout.strip(), 'WAKES=1 QUERIES=3')

    def test_single_tap_hold_drag_and_distant_or_late_taps_do_not_wake(self):
        drag = (event(1000, 'ABS_MT_TRACKING_ID', 4)
                + event(1000, 'ABS_MT_POSITION_X', 16000)
                + event(1000, 'ABS_MT_POSITION_Y', 12000) + event(1000, 'SYN_REPORT')
                + event(1050, 'ABS_MT_POSITION_X', 24000) + event(1050, 'SYN_REPORT')
                + event(1080, 'ABS_MT_TRACKING_ID', -1) + event(1080, 'SYN_REPORT'))
        for trace in (tap(1000), tap(1000, duration=400) + tap(1550), drag + tap(1250),
                      tap(1000) + tap(1250, x=26000), tap(1000) + tap(1600)):
            with self.subTest(trace=trace):
                self.assertIn('WAKES=0', self.execute(trace).stdout)

    def test_original_time_and_panel_pixel_distance_boundaries(self):
        self.assertIn('WAKES=1', self.execute(tap(1000) + tap(1480)).stdout)
        self.assertIn('WAKES=0', self.execute(tap(1000) + tap(1481)).stdout)
        # 3592 raw X units map to 99.976 pixels; 3593 exceed 100 pixels.
        self.assertIn('WAKES=1', self.execute(tap(1000) + tap(1250, x=19592)).stdout)
        self.assertIn('WAKES=0', self.execute(tap(1000) + tap(1250, x=19593)).stdout)

    def test_awake_first_down_cannot_rewake_original_doubletap_sleep(self):
        trace = tap(1000) + tap(1250)
        for states in ('2', '2,1', '2,2,1', '5', '6', '0'):
            with self.subTest(states=states):
                self.assertIn('WAKES=0', self.execute(trace, states).stdout)
        # First/second taps arm asleep, but another route wakes before second UP.
        self.assertEqual(self.execute(trace, '1,1,2').stdout.strip(), 'WAKES=0 QUERIES=3')

    def test_delayed_awake_trace_is_rejected_by_observed_sleep_history(self):
        old_trace = 'STATE 2 900\nSTATE 1 1400\n' + tap(1000) + tap(1250)
        self.assertEqual(self.execute(old_trace, 'history').stdout.strip(), 'WAKES=0 QUERIES=2')
        # A query on DOWN must record a new sleep transition even if the poll
        # has not observed it yet. CURRENT changes only the fake Binder result.
        late_poll = 'STATE 2 900\nCURRENT 1 1400\n' + tap(1000) + tap(1250)
        self.assertIn('WAKES=0', self.execute(late_poll, 'history').stdout)
        new_trace = 'STATE 2 900\nSTATE 1 1400\n' + tap(1500) + tap(1750)
        self.assertEqual(self.execute(new_trace, 'history').stdout.strip(), 'WAKES=1 QUERIES=3')
        # Repeated observations retain the original transition time.
        repeated = ('STATE 1 900\n' + tap(1000) + 'STATE 1 1200\n' + tap(1250))
        self.assertIn('WAKES=1', self.execute(repeated, 'history').stdout)

    def test_taps_cannot_span_an_observed_wake_and_sleep_cycle(self):
        trace = ('STATE 1 900\n' + tap(1000) + 'STATE 2 1100\nSTATE 1 1200\n' + tap(1250))
        self.assertIn('WAKES=0', self.execute(trace, 'history').stdout)
        second = tap(1250)
        up = second.index(event(1330, 'ABS_MT_TRACKING_ID', -1))
        trace = ('STATE 1 900\n' + tap(1000) + second[:up]
                 + 'STATE 2 1300\nSTATE 1 1350\n' + second[up:])
        self.assertIn('WAKES=0', self.execute(trace, 'history').stdout)

    def test_unchanged_type_b_axes_and_nonzero_slot_are_retained(self):
        trace = tap(1000, slot=3) + tap(1250, slot=3, coordinates=False)
        self.assertEqual(self.execute(trace).stdout.strip(), 'WAKES=1 QUERIES=3')
        trace = trace.replace('EV_ABS', '/dev/input/event7: EV_ABS')
        self.assertIn('WAKES=1', self.execute(trace).stdout)
        axes_first = (event(1000, 'ABS_MT_POSITION_X', 16000)
                      + event(1000, 'ABS_MT_POSITION_Y', 12000)
                      + tap(1000, coordinates=False) + tap(1250, coordinates=False))
        self.assertIn('WAKES=1', self.execute(axes_first).stdout)

    def test_multitouch_and_axis_out_of_range_do_not_wake(self):
        multi = (event(1000, 'ABS_MT_TRACKING_ID', 1)
                 + event(1000, 'ABS_MT_POSITION_X', 16000)
                 + event(1000, 'ABS_MT_POSITION_Y', 12000) + event(1000, 'SYN_REPORT')
                 + event(1040, 'ABS_MT_SLOT', 1) + event(1040, 'ABS_MT_TRACKING_ID', 2)
                 + event(1040, 'ABS_MT_POSITION_X', 16100)
                 + event(1040, 'ABS_MT_POSITION_Y', 12100) + event(1040, 'SYN_REPORT')
                 + event(1080, 'ABS_MT_TRACKING_ID', -1) + event(1080, 'ABS_MT_SLOT', 0)
                 + event(1080, 'ABS_MT_TRACKING_ID', -1) + event(1080, 'SYN_REPORT'))
        self.assertIn('WAKES=0', self.execute(multi + tap(1250)).stdout)
        self.assertIn('WAKES=0', self.execute(tap(1000, x=40000) + tap(1250)).stdout)

    def test_event_device_and_dropped_events_fail_closed(self):
        wrong_device = tap(1000).replace('EV_ABS', '/dev/input/event2: EV_ABS')
        for trace in (wrong_device, event(1000, 'SYN_DROPPED'), event(1000, 'ABS_MT_SLOT', 11)):
            result = self.execute(trace, check=False)
            self.assertNotEqual(result.returncode, 0)

    def test_display_identity_and_group_fail_fast(self):
        for unique, display_id, group in ((rear_wake.UNIQUE_ID, 1, 0), (rear_wake.UNIQUE_ID, 0, 1),
                                          ('local:wrong', 1, 1)):
            result = self.execute('', args=['identity', unique, str(display_id), str(group)], check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('identity/group changed', result.stderr)

    def test_idc_requires_exact_association_and_no_single_touch_wake(self):
        valid = 'touch.displayId = ' + rear_wake.UNIQUE_ID + '\n'
        self.execute(valid, args=['idc'])
        for text in ('', valid * 2, valid + 'touch.wake = true\n', valid.replace(rear_wake.UNIQUE_ID, '1')):
            self.assertNotEqual(self.execute(text, args=['idc'], check=False).returncode, 0)
        if IDC.is_file():
            self.execute(IDC.read_text(), args=['idc'])

    @unittest.skipUnless((SDK / 'build-tools/37.0.0/d8').is_file(), 'Android D8 is unavailable')
    def test_assets_compile_and_manifest_hashes_match(self):
        edits, manifest = rear_wake.image_replacements(SDK, self.folder / 'assets')
        self.assertEqual(set(edits), {rear_wake.JAR_PATH, rear_wake.SCRIPT_PATH})
        jar, mode, label = edits[rear_wake.JAR_PATH]
        self.assertEqual((mode, label), (0o644, rear_wake.LABEL))
        with zipfile.ZipFile(io.BytesIO(jar)) as archive:
            self.assertEqual(archive.namelist(), ['classes.dex'])
            self.assertTrue(archive.read('classes.dex').startswith(b'dex\n'))
        self.assertEqual(manifest['jar_sha256'], hashlib.sha256(jar).hexdigest())
        self.assertEqual(manifest['script_sha256'], hashlib.sha256(rear_wake.LAUNCHER).hexdigest())
        self.assertEqual(manifest['state_poll_ms'], 20)
        self.assertTrue(manifest['require_down_after_observed_sleep'])
        self.assertEqual(edits[rear_wake.SCRIPT_PATH], (rear_wake.LAUNCHER, 0o755, rear_wake.LABEL))
        self.assertNotIn('touch.wake', rear_wake.LAUNCHER.decode())
        self.assertIn('"-d", "1", "keyevent", "224"', rear_wake.JAVA_SOURCE)
        self.assertEqual(rear_wake.compile_assets(SDK, self.folder / 'second-assets'), jar)

class CoreRearDisplayWakeJavaTest(RearDisplayWakeJavaTest):
    from rear_display_wake_runtime import JAVA_SOURCE
    HARNESS = HARNESS.replace('int state = 1;', 'int state = 1; Boolean interactive;').replace(
        'new RearDisplayWake.Snapshot(RearDisplayWake.UNIQUE_ID, 1, 1, state), uptime);',
        'new RearDisplayWake.Snapshot(RearDisplayWake.UNIQUE_ID, 1, 1, state, '
        'interactive != null ? interactive.booleanValue() : !(state == 1 || state == 3 || state == 4), '
        'Long.MIN_VALUE), uptime);').replace(
        'if (args[0].equals("history") && (line.startsWith("STATE ")',
        'if (args[0].equals("history") && line.startsWith("INTERACTIVE ")) {\n'
        '                String[] value = line.split(" ");\n'
        '                history.interactive = Boolean.valueOf(value[1]);\n'
        '                history.sample(history.state, Long.parseLong(value[2]), true);\n'
        '            } else if (args[0].equals("history") && (line.startsWith("STATE ")')

    def test_cold_stationary_mouse_omits_initial_axes_and_reuses_id_zero(self):
        for slot in (0, 3):
            trace = (tap(1000, slot=slot, coordinates=False) + tap(1250, slot=slot, coordinates=False))
            trace = trace.replace('00000011', '00000000')
            self.assertIn('WAKES=1', self.execute(trace).stdout)
        # A single unknown axis is stationary; the known axis still has bounds.
        first = tap(1000).replace(event(1000, 'ABS_MT_POSITION_Y', 12000), '')
        second = tap(1250).replace(event(1250, 'ABS_MT_POSITION_Y', 12000), '')
        self.assertIn('WAKES=1', self.execute(first + second).stdout)
        far = second.replace(event(1250, 'ABS_MT_POSITION_X', 16000),
                             event(1250, 'ABS_MT_POSITION_X', 24000))
        self.assertIn('WAKES=0', self.execute(first + far).stdout)

    def test_unknown_axes_cannot_cross_slots_or_become_numeric_mid_gesture(self):
        self.assertIn('WAKES=0', self.execute(tap(1000, coordinates=False)
                                             + tap(1250, slot=1, coordinates=False)).stdout)
        unknown_then_known = tap(1000, coordinates=False) + tap(1250)
        self.assertIn('WAKES=0', self.execute(unknown_then_known).stdout)

    def test_unreported_initial_slot_cannot_alias_explicit_slot_zero(self):
        implicit = ''.join(line for line in tap(1000, coordinates=False).splitlines(True)
                           if 'ABS_MT_SLOT' not in line)
        second_implicit = ''.join(line for line in tap(1250, coordinates=False).splitlines(True)
                                  if 'ABS_MT_SLOT' not in line)
        self.assertIn('WAKES=1', self.execute(implicit + second_implicit).stdout)
        self.assertIn('WAKES=0', self.execute(implicit + tap(1250, coordinates=False)).stdout)
        invalid = event(1000, 'ABS_MT_SLOT', 11)
        self.assertNotEqual(self.execute(invalid, check=False).returncode, 0)
        # Both endpoints of a candidate must share their own immutable baseline.
        first = tap(1000, coordinates=False).replace(event(1080, 'ABS_MT_TRACKING_ID', -1),
                event(1080, 'ABS_MT_POSITION_X', 16000) + event(1080, 'ABS_MT_TRACKING_ID', -1))
        self.assertIn('WAKES=0', self.execute(first + tap(1250, coordinates=False)).stdout)
        self.assertIn('WAKES=1', self.execute(first + tap(1250, coordinates=False)
                                             + tap(1500, coordinates=False)).stdout)
        # A reported invalid axis is not the sentinel for an unobserved axis.
        bad = tap(1000, x=-1) + tap(1250, coordinates=False)
        self.assertIn('WAKES=0', self.execute(bad).stdout)

    def test_initial_implicit_contact_released_by_explicit_slot_does_not_stick(self):
        # The initial contact belongs to physical slot 3, which was selected
        # before this reader opened. A second contact explicitly selects slot 0.
        trace = (event(1000, 'ABS_MT_TRACKING_ID', 0) + event(1000, 'SYN_REPORT')
                 + event(1030, 'ABS_MT_SLOT', 0) + event(1030, 'ABS_MT_TRACKING_ID', 1)
                 + event(1030, 'SYN_REPORT') + event(1060, 'ABS_MT_TRACKING_ID', -1)
                 + event(1060, 'SYN_REPORT') + event(1080, 'ABS_MT_SLOT', 3)
                 + event(1080, 'ABS_MT_TRACKING_ID', -1) + event(1080, 'SYN_REPORT'))
        self.assertIn('WAKES=0', self.execute(trace).stdout)
        self.assertIn('WAKES=1', self.execute(trace + tap(2000) + tap(2250)).stdout)
        # The same recovery applies when no second contact was introduced.
        single = (event(1000, 'ABS_MT_TRACKING_ID', 0) + event(1000, 'SYN_REPORT')
                  + event(1080, 'ABS_MT_SLOT', 3) + event(1080, 'ABS_MT_TRACKING_ID', -1)
                  + event(1080, 'SYN_REPORT'))
        self.assertIn('WAKES=0', self.execute(single).stdout)
        self.assertIn('WAKES=1', self.execute(single + tap(2000) + tap(2250)).stdout)

    def test_logical_sleep_arms_before_physical_fade_and_rejects_stale_sleep_taps(self):
        fade = ('STATE 2 900\nINTERACTIVE false 1000\n' + tap(1100) + tap(1350))
        self.assertIn('WAKES=1', self.execute(fade, 'history').stdout)
        physical = ('STATE 2 900\nINTERACTIVE false 1000\n' + tap(1100)
                    + 'STATE 4 1250\n' + tap(1350))
        self.assertIn('WAKES=1', self.execute(physical, 'history').stdout)
        awake = ('STATE 4 900\nINTERACTIVE true 1000\n' + tap(1100) + tap(1350))
        self.assertIn('WAKES=0', self.execute(awake, 'history').stdout)
        # A queued original sleep gesture cannot become a wake gesture.
        stale = 'STATE 2 900\nINTERACTIVE false 1400\n' + tap(1000) + tap(1250)
        self.assertIn('WAKES=0', self.execute(stale, 'history').stdout)
        original = ('STATE 2 900\n' + tap(1000) + 'INTERACTIVE false 1200\n' + tap(1250))
        self.assertIn('WAKES=0', self.execute(original, 'history').stdout)

    def test_original_time_and_panel_pixel_distance_boundaries(self):
        # Both DOWN->DOWN and UP->UP must match the OEM's strict 400 ms.
        self.assertIn('WAKES=1', self.execute(tap(1000) + tap(1399)).stdout)
        self.assertIn('WAKES=0', self.execute(tap(1000) + tap(1400)).stdout)
        self.assertIn('WAKES=0', self.execute(tap(1000) + tap(1250, duration=230)).stdout)
        # OEM distance uses a rectangle, including its diagonal corners.
        self.assertIn('WAKES=1', self.execute(tap(1000) + tap(1250, x=19592, y=17496)).stdout)
        self.assertIn('WAKES=0', self.execute(tap(1000) + tap(1250, x=19593)).stdout)

    def test_oem_press_duration_and_mouse_drift_are_accepted(self):
        self.assertIn('WAKES=1', self.execute(tap(1000, duration=300) + tap(1350)).stdout)
        first = (event(1000, 'ABS_MT_TRACKING_ID', 1)
                 + event(1000, 'ABS_MT_POSITION_X', 16000)
                 + event(1000, 'ABS_MT_POSITION_Y', 12000) + event(1000, 'SYN_REPORT')
                 + event(1050, 'ABS_MT_POSITION_X', 17600) + event(1050, 'SYN_REPORT')
                 + event(1080, 'ABS_MT_TRACKING_ID', -1) + event(1080, 'SYN_REPORT'))
        # 44.5 physical pixels of mouse drift exceed the old 24-pixel guard.
        self.assertIn('WAKES=1', self.execute(first + tap(1250, x=17600)).stdout)
        # Moving outside the rectangle and returning before UP matches stock.
        excursion = first.replace(event(1050, 'ABS_MT_POSITION_X', 17600),
                                  event(1040, 'ABS_MT_POSITION_X', 26000) + event(1040, 'SYN_REPORT')
                                  + event(1050, 'ABS_MT_POSITION_X', 17600))
        self.assertIn('WAKES=1', self.execute(excursion + tap(1250, x=17600)).stdout)

    def test_final_up_axes_and_each_endpoint_match_first_down(self):
        first = tap(1000)
        second = tap(1250, x=12408).replace(event(1330, 'ABS_MT_TRACKING_ID', -1),
                event(1330, 'ABS_MT_POSITION_X', 19592) + event(1330, 'ABS_MT_TRACKING_ID', -1))
        # Opposite rectangle corners are both within the first DOWN tolerance.
        self.assertIn('WAKES=1', self.execute(first + second).stdout)
        outside = second.replace(event(1330, 'ABS_MT_POSITION_X', 19592),
                                 event(1330, 'ABS_MT_POSITION_X', 24000))
        self.assertIn('WAKES=0', self.execute(first + outside).stdout)

    def test_equivalent_sleep_states_keep_one_epoch(self):
        for before, after in ((1, 3), (3, 4), (4, 1)):
            trace = f'STATE {before} 900\n' + tap(1000) + f'STATE {after} 1200\n' + tap(1250)
            self.assertIn('WAKES=1', self.execute(trace, 'history').stdout)

    def test_failed_second_up_cannot_seed_a_third_tap(self):
        dragged = tap(1200, x=17000).replace(event(1280, 'ABS_MT_TRACKING_ID', -1),
                event(1280, 'ABS_MT_POSITION_X', 26000) + event(1280, 'ABS_MT_TRACKING_ID', -1))
        self.assertIn('WAKES=0', self.execute(tap(1000) + dragged + tap(1400, x=17000)).stdout)

    @unittest.skipUnless((SDK / 'build-tools/37.0.0/d8').is_file(), 'Android D8 is unavailable')
    def test_assets_compile_and_manifest_hashes_match(self):
        from unittest.mock import patch
        import rear_display_wake_runtime as current
        assets = current.files()
        self.assertEqual(rear_wake.compile_assets(SDK, self.folder / 'current-assets', self.JAVA_SOURCE),
                         assets['rear-wake.jar'])
        self.assertEqual(hashlib.sha256(self.JAVA_SOURCE.encode()).hexdigest(),
                         current.COMPILED_SOURCE_SHA256)
        with patch.object(current, 'compile_assets', side_effect=AssertionError('Offline consumer')):
            self.assertEqual(current.files(), assets)
        with patch.object(current, 'JAVA_SOURCE', self.JAVA_SOURCE + '// changed'):
            with self.assertRaisesRegex(RuntimeError, 'rebuild'):
                current.files()
        with patch.object(current, 'JAR_HEX', '00'):
            with self.assertRaisesRegex(RuntimeError, 'asset changed'):
                current.files()
        self.assertIn('wakeUpWithDisplayId', self.JAVA_SOURCE)
        self.assertNotIn('"/system/bin/input"', self.JAVA_SOURCE)
        self.assertEqual(len(assets['rear-wake.tsv'].decode().splitlines()), 5)

if __name__ == '__main__':
    unittest.main()


# --- tests/test_rear_input_policy.py ---

"""Audit the rear-only noninteractive motion gate without repacking framework code."""

def motion(body, display, flags, wake, dispatch, action, sleeping):
    """Execute the audited method's finite DEX subset, recording policy calls."""
    units = struct.unpack('<' + 'H' * (len(body) // 2), body)
    registers = {10: 'this', 11: display, 12: 0x1002, 13: action,
                 14: 4000000000, 15: 0, 16: flags}
    pc, last, calls = 0, None, []
    for _ in range(100):
        unit = units[pc]
        opcode, high = unit & 0xff, unit >> 8
        if opcode == 0xdd:  # and-int/lit8
            operand = units[pc + 1]
            registers[high] = registers[operand & 0xff] & (operand >> 8)
            pc += 2
        elif opcode == 0x12:  # const/4
            value = high >> 4
            registers[high & 15] = value if value < 8 else value - 16
            pc += 1
        elif opcode in (0x38, 0x39, 0x33):  # if-eqz, if-nez, if-ne
            delta = units[pc + 1]
            delta = delta if delta < 32768 else delta - 65536
            if opcode == 0x33:
                take = registers[high & 15] != registers[high >> 4]
            else:
                take = (registers[high] == 0) == (opcode == 0x38)
            pc += delta if take else 2
        elif opcode == 0x0f:
            return registers[high], calls
        elif opcode == 0x54:  # iget-object mWindowWakeUpPolicy
            registers[high & 15] = 'wake-policy'
            pc += 2
        elif opcode == 0x17:  # const-wide/32
            registers[high] = units[pc + 1] | units[pc + 2] << 16
            pc += 3
        elif opcode == 0x9e:  # div-long
            operand = units[pc + 1]
            registers[high] = registers[operand & 0xff] // registers[operand >> 8]
            pc += 2
        elif opcode == 0x01:  # move
            registers[high & 15] = registers[high >> 4]
            pc += 1
        elif opcode == 0x28:  # goto
            pc += high if high < 128 else high - 256
        elif opcode == 0x55:  # iget-boolean mDeviceGoingToSleep
            registers[high & 15] = sleeping
            pc += 2
        elif opcode == 0x74:  # invoke-virtual/range wakeUpFromMotion
            assert high == 7
            start = units[pc + 2]
            calls.append(('wake', registers[start + 1], registers[start + 2],
                          registers[start + 4], registers[start + 5], registers[start + 6]))
            last = int(wake)
            pc += 3
        elif opcode == 0x70:  # invoke-direct shouldDispatchInputWhenNonInteractive
            assert high == 0x30 and units[pc + 1] == 35465
            operands = units[pc + 2]
            calls.append(('dispatch', registers[(operands >> 4) & 15],
                          registers[(operands >> 8) & 15]))
            last = int(dispatch)
            pc += 3
        elif opcode == 0x0a:  # move-result
            registers[high] = last
            pc += 1
        else:
            raise AssertionError('Unexpected audited opcode: ' + hex(opcode))
    raise AssertionError('Audited motion method did not terminate.')

class RearInputRecipeTests(unittest.TestCase):
    def test_gate_precedes_every_wake_and_dispatch_path_and_preserves_other_displays(self):
        cases = itertools.product((-1, 0, 1, 2, 3, 999), (0, 1, 3, 254),
                                  (False, True), (False, True), (0, 1, 2), (False, True))
        for values in cases:
            display, flags, wake, dispatch, action, sleeping = values
            before = motion(rear_input_policy.BODY_BEFORE, *values)
            after = motion(rear_input_policy.BODY_AFTER, *values)
            if display == rear_input_policy.DISPLAY_ID:
                self.assertEqual(after, (0, []), values)
            else:
                self.assertEqual(after, before, values)

    def test_recipe_is_one_canonical_early_unsigned_framework_edge(self):
        from native_patch_catalog import catalog
        recipe = rear_input_policy.recipe_receipt()
        self.assertEqual(rear_input_policy.catalog_recipes(), (recipe,))
        self.assertEqual(recipe['display_id'], 1)
        self.assertEqual(recipe['methods'], [rear_input_policy.METHOD])
        self.assertEqual(recipe['format'], 'framework-jar')
        profile = next(row for row in catalog()['profiles'] if row['feature'] == 'rear-input')
        self.assertEqual(profile['before'], recipe['before'])
        self.assertEqual(profile['after'], recipe['after'])
        self.assertEqual(profile['sites'], [list(site) for site in rear_input_policy.SITES])
        target = next(row for row in catalog()['targets'] if row['feature'] == 'rear-input')
        self.assertEqual((target['path'], target['phase'], target['kind']), (rear_input_policy.PATH, 'early', 'system'))
        recipe['sites'].clear()
        self.assertEqual(len(rear_input_policy.recipe_receipt()['sites']), 4)

    def test_unknown_content_never_creates_output_or_guesses_a_site(self):
        for data in (b'', b'PK\x03\x04', b'unknown signed framework'):
            with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
                rear_input_policy.patch_bytes(data)
        with self.assertRaises(RuntimeError):
            rear_input_policy.recipe_receipt(rear_input_policy.AFTER)
        with tempfile.TemporaryDirectory() as temporary:
            source, output = Path(temporary) / 'custom.jar', Path(temporary) / 'new/derivative.jar'
            source.write_bytes(b'customized firmware')
            with self.assertRaises(RuntimeError):
                rear_input_policy.patch(source, output)
            self.assertFalse(output.parent.exists())
            self.assertEqual(source.read_bytes(), b'customized firmware')

class RearInputAuditedArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        default = ROOT / ('work/feedback-investigation-20261013/rear-state-sync/'
                         'phone-services-' + rear_input_policy.BEFORE + '.jar')
        cls.path = Path(os.environ.get('HYPEROS_AVD_REAR_INPUT_ARTIFACT', str(default)))
        if not cls.path.is_file():
            raise unittest.SkipTest('Private audited services JAR unavailable; no download attempted.')
        cls.original = cls.path.read_bytes()
        cls.output = rear_input_policy.patch_bytes(cls.original)

    def test_full_content_selection_idempotence_and_generic_catalog_application_agree(self):
        self.assertFalse(rear_input_policy.audit(self.original))
        self.assertTrue(rear_input_policy.audit(self.output))
        self.assertEqual(rear_input_policy.patch_bytes(self.output), self.output)
        self.assertEqual(rear_input_policy.receipt(self.original), rear_input_policy.recipe_receipt())
        self.assertEqual(rear_input_policy.receipt(self.output), rear_input_policy.recipe_receipt())
        replay = bytearray(self.original)
        for offset, before, after in rear_input_policy.SITES:
            self.assertEqual(replay[offset:offset + len(bytes.fromhex(before))].hex(), before)
            replay[offset:offset + len(bytes.fromhex(after))] = bytes.fromhex(after)
        self.assertEqual(bytes(replay), self.output)
        self.assertEqual(hashlib.sha256(self.output).hexdigest(), rear_input_policy.AFTER)

    def test_only_four_exact_sites_change_and_other_dex_members_keep_their_bytes(self):
        self.assertEqual(len(self.original), len(self.output))
        cursor = 0
        for offset, before, after in rear_input_policy.SITES:
            self.assertEqual(self.original[cursor:offset], self.output[cursor:offset])
            self.assertEqual(self.original[offset:offset + len(bytes.fromhex(before))].hex(), before)
            self.assertEqual(self.output[offset:offset + len(bytes.fromhex(after))].hex(), after)
            cursor = offset + len(bytes.fromhex(before))
        self.assertEqual(self.original[cursor:], self.output[cursor:])
        with zipfile.ZipFile(io.BytesIO(self.original)) as original, zipfile.ZipFile(io.BytesIO(self.output)) as output:
            self.assertIsNone(output.testzip())
            self.assertEqual(original.namelist(), output.namelist())
            for first, second in zip(original.infolist(), output.infolist()):
                for field in ('filename', 'compress_type', 'header_offset', 'file_size', 'compress_size',
                              'flag_bits', 'date_time', 'extra', 'comment', 'external_attr', 'internal_attr'):
                    self.assertEqual(getattr(first, field), getattr(second, field))
                if first.filename != rear_input_policy.MEMBER:
                    self.assertEqual(original.read(first.filename), output.read(first.filename))

    def test_method_header_tables_try_debug_and_helper_are_retained_with_valid_checksums(self):
        old = self.original[rear_input_policy.DEX_OFFSET:rear_input_policy.DEX_OFFSET + rear_input_policy.DEX_SIZE]
        new = self.output[rear_input_policy.DEX_OFFSET:rear_input_policy.DEX_OFFSET + rear_input_policy.DEX_SIZE]
        start = rear_input_policy.CODE_OFFSET + 16
        self.assertEqual(old[32:start], new[32:start])
        self.assertEqual(old[start + 74:], new[start + 74:])
        self.assertEqual(rear_input_policy._methods(old), rear_input_policy._methods(new))
        self.assertEqual(struct.unpack_from('<4H2I', new, rear_input_policy.CODE_OFFSET), rear_input_policy.CODE_HEADER)
        self.assertEqual(new[12:32], hashlib.sha1(new[32:]).digest())
        self.assertEqual(struct.unpack_from('<I', new, 8)[0], zlib.adler32(new[12:]) & 0xffffffff)
        self.assertEqual(hashlib.sha256(new).hexdigest(), rear_input_policy.DEX_AFTER)

    def test_unknown_tampered_partial_or_signed_framework_is_preserved(self):
        for offset in (0, rear_input_policy.SITES[0][0], rear_input_policy.DEX_OFFSET + 8,
                       rear_input_policy.DEX_OFFSET + rear_input_policy.CODE_OFFSET + 16, len(self.original) - 1):
            changed = bytearray(self.original)
            changed[offset] ^= 1
            with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
                rear_input_policy.patch_bytes(changed)
        partial = bytearray(self.original)
        offset, _, replacement = rear_input_policy.SITES[2]
        partial[offset:offset + 74] = bytes.fromhex(replacement)
        with self.assertRaises(RuntimeError):
            rear_input_policy.patch_bytes(partial)
        with self.assertRaises(RuntimeError):
            rear_input_policy.patch_bytes(self.original + b'APK Sig Block 42')

    def test_atomic_outputs_keep_existing_inodes_unknown_files_and_aliases(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'derivative.jar'
            rear_input_policy.patch(self.path, output)
            inode = output.stat().st_ino
            rear_input_policy.patch(self.path, output)
            self.assertEqual(output.stat().st_ino, inode)
            alias = Path(temporary) / 'alias.jar'
            alias.symlink_to(output)
            with self.assertRaises(RuntimeError):
                rear_input_policy.patch(self.path, alias)
            output.write_bytes(b'custom user derivative')
            with self.assertRaises(RuntimeError):
                rear_input_policy.patch(self.path, output)
            self.assertEqual(output.read_bytes(), b'custom user derivative')
            self.assertFalse(list(Path(temporary).glob('.rear-input-*')))

    def test_racing_output_is_preserved_and_temporary_file_is_removed(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'derivative.jar'

            def occupied(*_):
                output.write_bytes(b'racing user output')
                raise FileExistsError()

            with patch.object(rear_input_policy.os, 'link', side_effect=occupied), self.assertRaises(RuntimeError):
                rear_input_policy.patch(self.path, output)
            self.assertEqual(output.read_bytes(), b'racing user output')
            self.assertFalse(list(Path(temporary).glob('.rear-input-*')))

if __name__ == '__main__':
    unittest.main()


# --- tests/test_rear_release.py ---

"""Verify r3 release receipts against actual reader bytes without making images."""

OLD = '4.0.17.0.XFRCNXM'

NEW = '4.0.18.0.XFRCNXM'

CURRENT = '4.0.24.0.XFRCNXM'

def density_xml(width, height, density):
    return (f'<displayConfiguration><densityMapping><density><width>{width}</width>'
            f'<height>{height}</height><density>{density}</density></density>'
            '</densityMapping></displayConfiguration>').encode()

class RearReleaseTests(unittest.TestCase):
    def setUp(self):
        # Use small deterministic byte fixtures; only artifact pins are replaced.
        # The verifier still computes actual hashes and parses the XML/JSON/init.
        self.selected = profile(NEW)
        self.sources = {
            f'product/etc/displayconfig/display_id_{rear_config.SOURCE_IDS[0]}.xml': density_xml(1120, 2436, 480),
            f'product/etc/displayconfig/display_id_{rear_config.SOURCE_IDS[1]}.xml': density_xml(912, 596, 450),
            'product/overlay/AospFrameworkResOverlay.apk': b'original AOSP signed RRO',
            'product/overlay/DevicesAndroidOverlay.apk': b'original Xiaomi signed RRO',
            'system/framework/framework-res.apk': b'original signed framework resources',
        }
        pins = {path: hashlib.sha256(data).hexdigest() for path, data in self.sources.items()}
        self.vendor = {rear_composer.NATIVE: b'composer with alpha and secondary 60 Hz fixes',
                       goldfish_sync.NATIVE: b'goldfish sync with bounded threaded IRQ draining'}
        self.composer = {**rear_composer.MANIFEST,
                         'native_sha256': hashlib.sha256(self.vendor[rear_composer.NATIVE]).hexdigest()}
        self.sync = {**goldfish_sync.MANIFEST, 'native_sha256': hashlib.sha256(self.vendor[goldfish_sync.NATIVE]).hexdigest()}
        self.wake_jar = b'reviewed rear-display double-tap wake JAR fixture'
        self.wake = {**rear_fix.EXPECTED_WAKE_MANIFEST,
                     'jar_sha256': hashlib.sha256(self.wake_jar).hexdigest()}
        context = ExitStack()
        self.addCleanup(context.close)
        context.enter_context(patch.object(rear, 'SOURCE_SHA256', pins))
        context.enter_context(patch.object(composer, 'MANIFEST', self.composer))
        context.enter_context(patch.object(sync, 'MANIFEST', self.sync))
        context.enter_context(patch.object(rear_install, 'EXPECTED_WAKE_MANIFEST', self.wake))
        self.compile_wake = context.enter_context(patch.object(wake, 'compile_assets',
            side_effect=AssertionError('Release verification must not compile wake assets')))
        overlay = b'locally signed ID-only rear display overlay'
        displays = []
        for original, physical, geometry in zip(rear_config.SOURCE_IDS, rear_config.PHYSICAL_IDS,
                                                ((1120, 2436, 480), (912, 596, 450))):
            source = f'product/etc/displayconfig/display_id_{original}.xml'
            displays.append({'source_physical_id': original, 'physical_id': physical,
                             'unique_id': 'local:' + str(physical),
                             'config': f'/product/etc/displayconfig/display_id_{physical}.xml',
                             'config_sha256': pins[source], 'width': geometry[0],
                             'height': geometry[1], 'density': geometry[2]})
        self.marker = {'schema': 1, 'hyperos': NEW, 'archive_sha256': rear_config.ARCHIVE_SHA256,
                       'source_sha256': dict(pins), 'mapping_sha256': rear_config.MAPPING_SHA256,
                       'overlay': rear_config.OVERLAY, 'overlay_path': '/' + rear_config.OVERLAY_PATH,
                       'overlay_sha256': hashlib.sha256(overlay).hexdigest(),
                       'overlay_priority': 1001, 'source_overlay_priority': 1000,
                       'requires_runtime_resource_verification': True,
                       'overridden_resources': ['config_displayUniqueIdArray'],
                       'displays': displays, 'rear_safe_inset_left': 296, 'rear_corner_radius': 106}
        self.build = {'source': 'official-hongkong-ota', 'hyperos': NEW,
                      'archive_sha256': self.selected['archive_sha256'],
                      'rear_display': copy.deepcopy(self.marker),
                      'rear_display_composer_fix': dict(self.composer),
                      'composer_alpha_fix': {**patch_composer.MANIFEST,
                                             'native_sha256': self.composer['native_sha256']},
                      'goldfish_sync_fix': dict(self.sync),
                      'rear_display_wake_fix': copy.deepcopy(self.wake)}
        self.system = {'/' + path: data for path, data in self.sources.items()}
        self.system.update({'/' + rear_config.MARKER_PATH: json.dumps(self.marker).encode(),
                            '/' + rear_config.OVERLAY_PATH: overlay,
                            self.wake['jar_path']: self.wake_jar,
                            self.wake['script_path']: rear_wake.LAUNCHER,
                            '/system/build.prop': rear_config.properties(b'ro.adb.secure=1\n', self.selected),
                            '/system_ext/etc/init/init.hyperos_avd.rc':
                                b'on boot\n    setprop unrelated.value preserved\n' + rear_config.boot_init(self.selected)})
        for display, source in zip(displays, rear_config.SOURCE_IDS):
            self.system[display['config']] = self.sources[f'product/etc/displayconfig/display_id_{source}.xml']
        self.template = {'hw.multi_display_window': 'yes'}

    def readers(self, system=None, vendor=None):
        return (Mock(side_effect=(self.system if system is None else system).__getitem__),
                Mock(side_effect=(self.vendor if vendor is None else vendor).__getitem__))

    def verify(self, build=None, system=None, vendor=None, template=None):
        read, read_vendor = self.readers(system, vendor)
        return package_release.verify_rear_display(self.selected, self.build if build is None else build,
            read, read_vendor, self.template if template is None else template)

    def test_core_context_reuses_content_across_labels_and_pins_all_original_resources(self):
        import core_context
        import core_platform
        for version, archive, source in ((NEW, self.build['archive_sha256'], self.build['source']),
                                          ('5.9.99.0.FUTURE', 'a' * 64, 'custom')):
            marker = {**self.marker, 'hyperos': version, 'archive_sha256': archive}
            build = {**self.build, 'hyperos': version, 'archive_sha256': archive,
                     'source': source, 'rear_display': marker}
            system = {**self.system, '/product/etc/build.prop': b'current product identity',
                      '/' + rear_config.MARKER_PATH: rear_fix.encode(marker)}
            context = core_context.context_from_image(build, system.__getitem__)
            pins = {row['path']: row['sha256'] for row in context['rear']['files']}
            for path, data in self.sources.items():
                self.assertEqual(pins['/' + path], hashlib.sha256(data).hexdigest())
            self.assertIn('rear.record', core_platform.context_files(context))
            legacy = copy.deepcopy(context)
            legacy['rear']['files'] = [row for row in legacy['rear']['files']
                                       if row['path'].removeprefix('/') not in self.sources]
            self.assertIn('rear.record', core_platform.context_files(legacy))
            partial = copy.deepcopy(context)
            partial['rear']['files'].pop()
            with self.assertRaisesRegex(RuntimeError, 'resource prerequisites'):
                core_platform.context_files(partial)
            for path in self.sources:
                changed = {**system, '/' + path: system['/' + path] + b'tamper'}
                with self.subTest(version=version, path=path), self.assertRaisesRegex(RuntimeError, 'prerequisite differs'):
                    core_context.context_from_image(build, changed.__getitem__)

    def assert_metadata_rejected_before_reads(self, build, message):
        read, read_vendor = self.readers()
        with self.assertRaisesRegex(RuntimeError, message):
            package_release.verify_rear_display(self.selected, build, read, read_vendor, self.template)
        read.assert_not_called()
        read_vendor.assert_not_called()

    def test_exact_artifacts_receipts_geometry_properties_and_init_are_accepted(self):
        read, read_vendor = self.readers()
        self.assertEqual(package_release.verify_rear_display(
            self.selected, self.build, read, read_vendor, self.template), 12)
        self.assertEqual([call.args[0] for call in read_vendor.call_args_list], [rear_composer.NATIVE, goldfish_sync.NATIVE])
        self.assertEqual(set(call.args[0] for call in read.call_args_list), set(self.system))
        self.compile_wake.assert_not_called()

    def test_current_firmware_requires_its_own_baked_and_release_provenance(self):
        selected = profile(CURRENT)
        marker = {**self.marker, 'hyperos': selected['hyperos'],
                  'archive_sha256': selected['archive_sha256']}
        build = {**self.build, 'hyperos': selected['hyperos'],
                 'archive_sha256': selected['archive_sha256'], 'rear_display': marker}
        system = {**self.system, '/' + rear_config.MARKER_PATH: json.dumps(marker).encode()}
        read, read_vendor = self.readers(system)
        self.assertEqual(package_release.verify_rear_display(
            selected, build, read, read_vendor, self.template), 12)
        self.compile_wake.assert_not_called()
        for changed in (self.marker, {**marker, 'hyperos': NEW},
                        {**marker, 'archive_sha256': self.selected['archive_sha256']},
                        {**marker, 'schema': True}):
            read, read_vendor = self.readers(system)
            with self.subTest(marker=changed), self.assertRaisesRegex(RuntimeError, 'rear-display resource metadata'):
                package_release.verify_rear_display(selected, {**build, 'rear_display': changed},
                                                    read, read_vendor, self.template)
            read.assert_not_called()
            read_vendor.assert_not_called()
        read, read_vendor = self.readers()
        with self.assertRaisesRegex(RuntimeError, 'resource metadata differs'):
            package_release.verify_rear_display(selected, build, read, read_vendor, self.template)

    def test_current_firmware_rejects_unknown_or_unpinned_profile_before_image_reads(self):
        selected = profile(CURRENT)
        for changed in ({'hyperos': '4.0.999.0.XFRCNXM'},
                        {'archive_sha256': self.selected['archive_sha256']},
                        {'pins': {**selected['pins'], 'hwui': '0' * 64}},
                        {'pins': {**selected['pins'], 'camera_apk': '0' * 64}},
                        {'source_partition_sha256': {}},
                        {'display': {**selected['display'], 'density': 480.0}}):
            read, read_vendor = Mock(), Mock()
            with self.subTest(profile=changed), self.assertRaises(RuntimeError):
                package_release.verify_rear_display({**selected, **changed}, self.build,
                                                    read, read_vendor, self.template)
            read.assert_not_called()
            read_vendor.assert_not_called()

    def test_wake_receipt_requires_exact_reviewed_revision_source_and_schema(self):
        for marker in (None, {}, {**self.wake, 'revision': 1},
                       {**self.wake, 'schema': True}, {**self.wake, 'revision': 2.0},
                       {**self.wake, 'require_down_after_observed_sleep': 1},
                       {**self.wake, 'source_sha256': '0' * 64},
                       {**self.wake, 'jar_sha256': '0' * 64},
                       {**self.wake, 'script_sha256': '0' * 64},
                       {**self.wake, 'extra': True}):
            with self.subTest(receipt=marker):
                self.assert_metadata_rejected_before_reads(
                    {**self.build, 'rear_display_wake_fix': marker}, 'rear-display wake metadata')
        for key in self.wake:
            marker = copy.deepcopy(self.wake)
            del marker[key]
            with self.subTest(missing=key):
                self.assert_metadata_rejected_before_reads(
                    {**self.build, 'rear_display_wake_fix': marker}, 'rear-display wake metadata')
        build = copy.deepcopy(self.build)
        del build['rear_display_wake_fix']
        self.assert_metadata_rejected_before_reads(build, 'rear-display wake metadata')

    def test_changed_wake_source_or_launcher_is_refused_before_image_reads(self):
        for attribute, replacement in (('JAVA_SOURCE', rear_wake.JAVA_SOURCE + '\n// changed\n'),
                                       ('LAUNCHER', rear_wake.LAUNCHER + b'# changed\n')):
            with self.subTest(source=attribute), patch.object(wake, attribute, replacement):
                self.assert_metadata_rejected_before_reads(self.build, 'wake source or launcher')

    def test_baked_wake_jar_and_launcher_must_match_reviewed_actual_bytes(self):
        for path in (self.wake['jar_path'], self.wake['script_path']):
            for data in (b'old revision 1 wake artifact', self.system[path] + b'changed'):
                with self.subTest(path=path, bytes=data[:32]):
                    with self.assertRaisesRegex(RuntimeError, 'wake checksum mismatch: ' + path):
                        self.verify(system={**self.system, path: data})

    def test_missing_or_stale_native_receipts_never_fall_back_to_alpha_only(self):
        for key in ('rear_display_composer_fix', 'composer_alpha_fix', 'goldfish_sync_fix'):
            for replacement in (None, {}, {**self.build[key], 'revision': 0},
                                {**self.build[key], 'native_sha256': patch_composer.AFTER},
                                {**self.build[key], 'extra': True}):
                with self.subTest(key=key, receipt=replacement):
                    build = {**self.build, key: replacement}
                    self.assert_metadata_rejected_before_reads(build, 'composer or goldfish sync metadata')
        build = copy.deepcopy(self.build)
        build['goldfish_sync_fix']['kernel_vermagic'] = 'another kernel'
        self.assert_metadata_rejected_before_reads(build, 'composer or goldfish sync metadata')

    def test_missing_or_incomplete_resource_receipts_are_rejected_before_reads(self):
        for marker in (None, {}, {**self.marker, 'overlay_sha256': 'unverified'}):
            with self.subTest(marker=marker):
                self.assert_metadata_rejected_before_reads({**self.build, 'rear_display': marker},
                                                           'rear-display resource metadata')
        for key in self.marker:
            marker = copy.deepcopy(self.marker)
            del marker[key]
            with self.subTest(missing=key):
                self.assert_metadata_rejected_before_reads({**self.build, 'rear_display': marker},
                                                           'rear-display resource metadata')

    def test_every_static_marker_field_and_display_order_are_guarded(self):
        for key in self.marker.keys() - {'overlay_sha256'}:
            marker = copy.deepcopy(self.marker)
            marker[key] = 'stale metadata'
            with self.subTest(field=key):
                self.assert_metadata_rejected_before_reads({**self.build, 'rear_display': marker},
                                                           'rear-display resource metadata')
        cases = [{'extra': True}, {'schema': True}, {'overlay_priority': 1001.0},
                 {'displays': list(reversed(self.marker['displays']))}]
        for values in cases:
            with self.subTest(values=values):
                self.assert_metadata_rejected_before_reads(
                    {**self.build, 'rear_display': {**self.marker, **values}}, 'rear-display resource metadata')
        for key in self.marker['displays'][1]:
            marker = copy.deepcopy(self.marker)
            marker['displays'][1][key] = 'stale alias'
            with self.subTest(alias=key):
                self.assert_metadata_rejected_before_reads({**self.build, 'rear_display': marker},
                                                           'rear-display resource metadata')

    def test_original_alpha_only_or_corrupt_vendor_artifacts_are_rejected(self):
        for path in (rear_composer.NATIVE, goldfish_sync.NATIVE):
            for replacement in (b'original unpatched artifact', b'alpha-only composer', self.vendor[path] + b'changed'):
                with self.subTest(path=path, replacement=replacement):
                    with self.assertRaisesRegex(RuntimeError, 'vendor checksum mismatch: ' + path):
                        self.verify(vendor={**self.vendor, path: replacement})

    def test_baked_marker_and_signed_overlay_must_match_release_receipt(self):
        for data in (b'not json', json.dumps({**self.marker, 'rear_corner_radius': 180}).encode(),
                     json.dumps({**self.marker, 'schema': True}).encode()):
            with self.subTest(marker=data[:32]), self.assertRaisesRegex(RuntimeError, 'rear-display resource metadata'):
                self.verify(system={**self.system, '/' + rear_config.MARKER_PATH: data})
        with self.assertRaisesRegex(RuntimeError, 'overlay checksum mismatch'):
            self.verify(system={**self.system, '/' + rear_config.OVERLAY_PATH: self.system['/' + rear_config.OVERLAY_PATH] + b'changed'})

    def test_every_preserved_source_and_both_display_xml_aliases_are_checked(self):
        for path in self.sources:
            with self.subTest(source=path), self.assertRaisesRegex(RuntimeError, 'original rear-display source'):
                self.verify(system={**self.system, '/' + path: self.system['/' + path] + b'changed'})
        for display in self.marker['displays']:
            path = display['config']
            for replacement in (density_xml(912, 596, 480), b'other display XML'):
                with self.subTest(alias=path), self.assertRaisesRegex(RuntimeError, 'XML alias checksum mismatch'):
                    self.verify(system={**self.system, path: replacement})

    def test_missing_conflicting_or_duplicate_hardware_properties_are_rejected(self):
        path = '/system/build.prop'
        for key, value in rear_config.PROPERTIES.items():
            line = f'{key}={value}\n'.encode()
            for replacement in (self.system[path].replace(line, b''),
                                self.system[path] + line,
                                self.system[path] + f'{key}=old\n'.encode()):
                with self.subTest(key=key), self.assertRaisesRegex(RuntimeError, 'hardware property: ' + key):
                    self.verify(system={**self.system, path: replacement})

    def test_both_init_phases_are_required_without_conflicting_overrides(self):
        path = '/system_ext/etc/init/init.hyperos_avd.rc'
        block = rear_config.boot_init(self.selected)
        for replacement in (b'on boot\n', self.system[path] + block,
                            block.split(b'\non property:', 1)[0],
                            self.system[path].replace(b'ro.persistent_properties.ready=true', b'sys.boot_completed=1')):
            with self.subTest(init=replacement[:32]), self.assertRaisesRegex(RuntimeError, 'hardware initialization'):
                self.verify(system={**self.system, path: replacement})
        key = next(iter(rear_config.PROPERTIES))
        with self.assertRaisesRegex(RuntimeError, 'init property override: ' + key):
            self.verify(system={**self.system, path: self.system[path] + f'\non boot\n    setprop\t{key} old\n'.encode()})

    def test_bootconfig_interface_and_separate_window_are_required(self):
        for template in ({}, {'hw.multi_display_window': 'no'}):
            read, read_vendor = self.readers()
            with self.subTest(template=template), self.assertRaisesRegex(RuntimeError, 'boot/window configuration'):
                package_release.verify_rear_display(self.selected, self.build, read, read_vendor, template)
            read.assert_not_called()
            read_vendor.assert_not_called()
        with patch.object(rear, 'runtime_options', return_value=[]):
            with self.assertRaisesRegex(RuntimeError, 'boot/window configuration'):
                self.verify()

    def test_non_r3_phone_pad_and_os3_do_not_read_or_require_new_artifacts(self):
        for version in (OLD, '4.0.6.0.XOCCNXM', '3.0.2.0.WMCCNXM'):
            read, read_vendor = Mock(), Mock()
            with self.subTest(version=version):
                self.assertEqual(package_release.verify_rear_display(
                    {'hyperos': version}, {}, read, read_vendor, {}), 0)
            read.assert_not_called()
            read_vendor.assert_not_called()

    def test_foreign_or_unpinned_r3_profile_is_refused_before_image_reads(self):
        for changes in ({'device': 'yingtian'}, {'archive_sha256': 'unverified'},
                        {'source_partition_sha256': {}}, {'display': {'width': 912, 'height': 596, 'density': 450}}):
            read, read_vendor = Mock(), Mock()
            with self.subTest(profile=changes), self.assertRaisesRegex(RuntimeError, 'rear-display profile'):
                package_release.verify_rear_display({**self.selected, **changes}, self.build, read, read_vendor, self.template)
            read.assert_not_called()
            read_vendor.assert_not_called()

    def test_release_metadata_preserves_rear_receipts_for_registered_modern_images(self):
        keys = ('rear_display', 'rear_display_composer_fix', 'goldfish_sync_fix',
                'rear_display_wake_fix')
        for version in (OLD, NEW, CURRENT):
            selected = profile(version)
            build = {**self.build, 'hyperos': version, 'archive_sha256': selected['archive_sha256'],
                     'android_api': 37, 'adb_authentication': True, 'flutter_render_fix': 6,
                     'native_quickstep_identity': True, 'preinstalled_apps': {'apps': ['fixture']},
                     'avd_defaults': {'fixture': True}}
            build['rear_display'] = {**build['rear_display'], 'hyperos': version,
                                     'archive_sha256': selected['archive_sha256']}
            if version == CURRENT:
                from patch_boot_services import image_receipts
                build['boot_service_fix'] = image_receipts()[-1]
            with self.subTest(version=version), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'local').mkdir()
                (root / 'local/build.json').write_text(json.dumps(build))
                metadata = package_release.release_metadata(root, 'os4-official')
                for key in keys:
                    if version != OLD:
                        self.assertEqual(metadata['build'][key], build[key])
                    else:
                        self.assertNotIn(key, metadata['build'])

if __name__ == '__main__':
    unittest.main()
