"""Keep generic native delivery equivalent to the audited original patchers."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'scripts'))
import native_patch_catalog as native
import patch_flutter


def generic_patch(data, profile):
    """Model the equal-size content-guarded runtime; never guess an offset."""
    checksum = hashlib.sha256(data).hexdigest()
    if checksum == profile['after']:
        return data
    if checksum not in (profile['before'], *profile['legacy']):
        raise RuntimeError('Unsupported input content.')
    result = bytearray(data)
    for offset, before, after in profile['sites']:
        original, replacement = bytes.fromhex(before), bytes.fromhex(after)
        current = result[offset:offset + len(original)]
        if current == replacement:
            continue
        if current != original:
            raise RuntimeError('Unexpected native patch instruction.')
        result[offset:offset + len(original)] = replacement
    if len(result) != len(data) or hashlib.sha256(result).hexdigest() != profile['after']:
        raise RuntimeError('Unexpected output content.')
    return bytes(result)


def audited_wifi_inputs():
    """Optional private fixtures; identities are selected only by full content."""
    import patch_wifi_capabilities as wifi
    defaults = ('work/feedback-investigation-20261013/phone-wifi-service.jar',
                'work/feedback-investigation-20261013/pad-producer-audit/miui-wifi-service.jar')
    paths = [Path(value) for value in os.environ.get('HYPEROS_AVD_WIFI_FRAMEWORK_ARTIFACTS', '').split(os.pathsep)
             if value] or [REPO / value for value in defaults]
    found = {}
    for path in paths:
        if path.is_file():
            data = path.read_bytes()
            identity = hashlib.sha256(data).hexdigest()
            if identity in wifi.RECIPES:
                found[identity] = data
    return found


class NativePatchCatalogTests(unittest.TestCase):
    def setUp(self):
        self.value = native.catalog()

    def reject(self, edit, message=''):
        value = copy.deepcopy(self.value)
        edit(value)
        with self.assertRaisesRegex(RuntimeError, message):
            native.validate_catalog(value)

    def test_catalog_is_json_and_deterministic(self):
        data = native.dump_catalog()
        self.assertEqual(data, native.dump_catalog())
        self.assertEqual(json.loads(data), self.value)
        self.assertEqual(native.validate_catalog(self.value), self.value)
        self.assertEqual(len(self.value['profiles']), 27)
        self.assertEqual(len(self.value['targets']), 20)
        self.assertEqual(set(row['feature'] for row in self.value['profiles']), native.FEATURES)
        self.assertEqual([row['id'] for row in self.value['profiles']],
                         sorted(row['id'] for row in self.value['profiles']))
        self.assertNotIn('avd_name', data)
        self.assertNotIn('incremental', data)

    def test_all_flutter_profiles_have_exact_imported_sites_and_legacy_inputs(self):
        rows = {row['before']: row for row in self.value['profiles'] if row['feature'] == 'flutter'}
        self.assertEqual(set(rows), set(patch_flutter.PROFILES))
        for before, source in patch_flutter.PROFILES.items():
            row = rows[before]
            self.assertEqual(row['after'], source['output'])
            self.assertEqual(row['legacy'], list(source.get('legacy', ())))
            self.assertEqual(row['sites'], [list(site) for site in sorted(source['sites'])])

    def test_hwui_and_remaining_sites_use_the_original_patchers(self):
        import apply_navigation_fix as navigation
        import patch_assistant as assistant
        import patch_composer as composer
        import patch_display_privacy as privacy
        import patch_lockscreen_video as lockscreen
        import patch_pad_hwui as hwui
        import patch_rear_display as rear
        rows = {row['before']: row for row in self.value['profiles']}
        for before, source in hwui.PROFILES.items():
            self.assertEqual(rows[before]['after'], source['after'])
            self.assertEqual(rows[before]['sites'], [[source['site'], source['original'].hex(),
                                                    hwui.REPLACEMENT.hex()]])
        for before, after, sites in ((assistant.BEFORE, assistant.AFTER, assistant.SITES),
                                     (composer.BEFORE, composer.AFTER, composer.SITES),
                                     (privacy.BEFORE, privacy.AFTER, privacy.SITES),
                                     (rear.BEFORE, rear.AFTER, rear.SITES),
                                     (lockscreen.BEFORE, lockscreen.AFTER, lockscreen.SITES),
                                     (navigation.AOT_BEFORE, navigation.AOT_AFTER, navigation.AOT_SITES),
                                     (navigation.WATCHDOG_BEFORE, navigation.WATCHDOG_AFTER,
                                      navigation.WATCHDOG_SITES)):
            self.assertEqual(rows[before]['after'], after)
            self.assertEqual(rows[before]['sites'], [[offset, left.hex(), right.hex()]
                                                    for offset, left, right in sorted(sites)])

    def test_composer_alpha_and_rear_timing_form_one_audited_chain(self):
        rows = {row['feature']: row for row in self.value['profiles']
                if row['feature'] in ('composer', 'rear-display')}
        self.assertEqual(rows['composer']['after'], rows['rear-display']['before'])
        targets = {row['feature']: row for row in self.value['targets']
                   if row['feature'] in rows}
        self.assertEqual(targets['composer']['path'], targets['rear-display']['path'])
        self.assertEqual(targets['composer']['phase'], 'early')
        self.assertEqual(targets['rear-display']['phase'], 'early')
        self.reject(lambda value: next(row for row in value['targets']
                                        if row['feature'] == 'rear-display').update(phase='late'),
                    'shared target and boot phase')

    def test_system_and_app_targets_are_explicit_and_scoped(self):
        system = {row['feature']: row for row in self.value['targets'] if row['kind'] == 'system'}
        self.assertEqual(set(system), {'flutter', 'hwui', 'composer', 'rear-display', 'display-privacy', 'display-metadata', 'wifi-capabilities', 'xqos', 'vendor-ims', 'perf-hardware'})
        self.assertTrue(all(row['phase'] == 'early' and not row['package'] for row in system.values()))
        self.assertEqual(system['flutter']['path'], '/system_ext/lib64/libhyper_os_flutter.so')
        self.assertEqual(system['hwui']['path'], '/system/lib64/libhwui.so')
        apps = [row for row in self.value['targets'] if row['kind'] == 'app']
        self.assertEqual(set(row['package'] for row in apps), native.APP_PACKAGES)
        self.assertTrue(all(row['phase'] == 'late' and row['path'] == '' for row in apps))
        self.assertEqual({row['library'] for row in apps if row['feature'] == 'navigation'},
                         {'libapp.so', 'libapp_launcher.so'})
        self.assertEqual([row['library'] for row in apps if row['feature'] == 'lockscreen-video'],
                         ['libfastplayer.so'])

    def test_rejects_schema_unknown_keys_and_unsafe_identifiers(self):
        self.reject(lambda value: value.update(schema=True), 'schema')
        self.reject(lambda value: value.update(extra=True), 'schema')
        self.reject(lambda value: value['profiles'][0].update(extra=True), 'profile')
        self.reject(lambda value: value['profiles'][0].update(id='../unsafe'), 'profile')
        self.reject(lambda value: value['profiles'][0].update(feature=[]), 'profile')

    def test_rejects_bad_hashes_and_duplicate_hash_ownership(self):
        self.reject(lambda value: value['profiles'][0].update(before='A' * 64), 'hash')
        self.reject(lambda value: value['profiles'][0].update(legacy=[None]), 'hash')
        self.reject(lambda value: value['profiles'][0].update(legacy=[value['profiles'][0]['before']]), 'hash')
        self.reject(lambda value: value['profiles'][1].update(before=value['profiles'][0]['before']),
                    'input hash')
        self.reject(lambda value: value['profiles'][1].update(legacy=[value['profiles'][0]['before']]),
                    'input hash')
        self.reject(lambda value: value['profiles'][1].update(after=value['profiles'][0]['after']),
                    'output hash')
        self.reject(lambda value: value['profiles'][1].update(before=value['profiles'][0]['after']),
                    'hash chain')

    def test_rejects_invalid_hex_length_offsets_and_overlap(self):
        for site in ((0, '0g', '00'), (0, '0', '00'), (0, '00', '0000'),
                     (0, '00', '00'), (-1, '00', '01'), (True, '00', '01'),
                     (0x100000000, '00', '01'), (0xffffffff, '0000', '0101')):
            with self.subTest(site=site):
                self.reject(lambda value: value['profiles'][0].update(sites=[list(site)]))
        self.reject(lambda value: value['profiles'][0].update(
            sites=[[10, '0000', '0101'], [11, '00', '01']]), 'Overlapping')

    def test_rejects_unsafe_paths_unknown_apps_and_unmatched_libraries(self):
        def system(value):
            return next(row for row in value['targets'] if row['kind'] == 'system')
        def app(value):
            return next(row for row in value['targets'] if row['kind'] == 'app')
        for path in ('/data/local/tmp/lib.so', '/system/../lib.so', '/system//lib.so',
                     '/system/lib.so\n', 'system/lib.so'):
            self.reject(lambda value: system(value).update(path=path), 'Unsafe system')
        self.reject(lambda value: system(value).update(library='libunrelated.so'), 'Unsafe system')
        self.reject(lambda value: app(value).update(library='../lib.so'), 'target')
        self.reject(lambda value: app(value).update(package='com.unknown.app'), 'Unsafe app')
        self.reject(lambda value: app(value).update(path='/data/app/base.apk'), 'Unsafe app')
        self.reject(lambda value: value['targets'].append(value['targets'][0]), 'Duplicate')

    def test_real_flutter_fixture_and_previous_patch_match_generic_sites(self):
        path = Path(os.environ.get('HYPEROS_AVD_FLUTTER18_ARTIFACT', str(
            REPO / 'work/os4-r3-build/input/hongkong-4.0.18/flutter.bin')))
        if not path.is_file():
            self.skipTest('Original proprietary Flutter artifact is not distributed in Git.')
        data = path.read_bytes()
        checksum = hashlib.sha256(data).hexdigest()
        self.assertIn(checksum, patch_flutter.PROFILES)
        row = next(row for row in self.value['profiles'] if row['before'] == checksum)
        result = generic_patch(data, row)
        self.assertEqual(result, patch_flutter.patch(data))
        self.assertEqual(generic_patch(result, row), result)
        source = patch_flutter.PROFILES[checksum]
        if source.get('glyph_raster_site'):
            offset = source['glyph_raster_site']
            previous = bytearray(result)
            previous[offset:offset + 4] = data[offset:offset + 4]
            self.assertIn(hashlib.sha256(previous).hexdigest(), row['legacy'])
            self.assertEqual(generic_patch(previous, row), patch_flutter.patch(previous))
        changed = bytearray(data)
        changed[-1] ^= 1
        with self.assertRaisesRegex(RuntimeError, 'Unsupported input content'):
            generic_patch(changed, row)

    def test_wifi_profiles_reuse_all_six_canonical_offline_sites(self):
        import patch_wifi_capabilities as wifi
        rows = {row['before']: row for row in self.value['profiles']
                if row['feature'] == 'wifi-capabilities'}
        self.assertEqual(set(rows), set(wifi.RECIPES))
        for source in wifi.catalog_recipes():
            row = rows[source['before']]
            self.assertEqual(row['after'], source['after'])
            self.assertEqual(row['legacy'], [])
            self.assertEqual(row['sites'], [[site['offset'], site['before'], site['after']]
                                            for site in source['sites']])
            self.assertEqual(len(row['sites']), 6)
        targets = [row for row in self.value['targets'] if row['feature'] == 'wifi-capabilities']
        self.assertEqual(targets, [{'feature': 'wifi-capabilities', 'phase': 'early',
                                  'kind': 'system', 'path': wifi.PATH,
                                  'package': '', 'library': Path(wifi.PATH).name}])

    def test_wifi_recipe_cannot_be_redirected_to_apk_app_or_late_boot(self):
        def target(value):
            return next(row for row in value['targets'] if row['feature'] == 'wifi-capabilities')
        changes = ({'path': '/system_ext/framework/miui-wifi-service.apk',
                    'library': 'miui-wifi-service.apk'},
                   {'path': '/system_ext/framework/custom.jar', 'library': 'custom.jar'},
                   {'phase': 'late'},
                   {'kind': 'app', 'path': '', 'package': 'com.miui.home',
                    'library': 'libapp.so', 'phase': 'late'},
                   {'kind': 'app', 'path': '', 'package': 'com.miui.weather2',
                    'library': 'miui-wifi-service.jar', 'phase': 'early'})
        for change in changes:
            with self.subTest(change=change):
                self.reject(lambda value: target(value).update(change))

    def test_actual_unsigned_wifi_jars_match_producer_without_elf_or_repacking(self):
        import io
        import zipfile
        import patch_wifi_capabilities as wifi
        sources = audited_wifi_inputs()
        if not sources:
            self.skipTest('Private audited WiFi JAR inputs unavailable; no download attempted.')
        rows = {row['before']: row for row in self.value['profiles']
                if row['feature'] == 'wifi-capabilities'}
        for before, original in sources.items():
            with self.subTest(before=before):
                self.assertTrue(original.startswith(b'PK\x03\x04'))
                self.assertFalse(original.startswith(b'\x7fELF'))
                patched = generic_patch(original, rows[before])
                self.assertEqual(patched, wifi.patch_bytes(original))
                self.assertEqual(generic_patch(patched, rows[before]), patched)
                with zipfile.ZipFile(io.BytesIO(patched)) as jar:
                    self.assertEqual(jar.namelist(), ['classes.dex', 'META-INF/MANIFEST.MF'])
                    self.assertIsNone(jar.testzip())
                altered = bytearray(original); altered[-1] ^= 1
                with self.assertRaisesRegex(RuntimeError, 'Unsupported input content'):
                    generic_patch(bytes(altered), rows[before])

    def test_xqos_profiles_and_system_scope_match_only_canonical_recipes(self):
        import patch_xqos as xqos
        rows={row['before']:row for row in self.value['profiles'] if row['feature']=='xqos'}
        self.assertEqual(set(rows),set(xqos.RECIPES))
        for source in xqos.catalog_recipes():
            row=rows[source['before']]
            self.assertEqual(row['after'],source['after'])
            self.assertEqual(row['sites'],[[site['offset'],site['before'],site['after']] for site in source['sites']])
            self.assertEqual(len(row['sites']),7)
        def target(value):return next(row for row in value['targets'] if row['feature']=='xqos')
        self.assertEqual(target(self.value),{'feature':'xqos','phase':'early','kind':'system',
                                            'path':xqos.NATIVE,'package':'','library':'libxqos.so'})
        for change in ({'phase':'late'}, {'kind':'app','path':'','package':'com.miui.home'},
                       {'path':'/system_ext/lib64/libxqos.so'}, {'library':'libunrelated.so'}):
            with self.subTest(change=change):self.reject(lambda value:target(value).update(change))

    def test_vendor_ims_uses_one_existing_feature_and_four_canonical_early_jar_sites(self):
        import patch_xiaomi_ims as ims
        profile=next(row for row in self.value['profiles'] if row['feature']=='vendor-ims')
        receipt=ims.recipe_receipt()
        self.assertEqual(profile['before'],ims.BEFORE);self.assertEqual(profile['after'],ims.AFTER)
        self.assertEqual(profile['sites'],[[site['offset'],site['before'],site['after']] for site in receipt['sites']])
        self.assertEqual(profile['legacy'],[])
        def target(value):return next(row for row in value['targets'] if row['feature']=='vendor-ims')
        self.assertEqual(target(self.value),{'feature':'vendor-ims','phase':'early','kind':'system',
                                             'path':ims.PATH,'package':'','library':'xiaomi-opt-ims.jar'})
        for change in ({'phase':'late'}, {'kind':'app','path':'','package':'com.miui.home'},
                       {'path':'/system_ext/framework/xiaomi-opt-ims.apk','library':'xiaomi-opt-ims.apk'},
                       {'path':'/system/framework/ims-common.jar','library':'ims-common.jar'},
                       {'library':'custom.jar'}):
            with self.subTest(change=change):self.reject(lambda value:target(value).update(change))

    def test_actual_vendor_ims_jar_sites_match_producer_and_preserve_all_other_bytes(self):
        import patch_xiaomi_ims as ims
        from test_xiaomi_ims_patch import actual_input
        original=actual_input()
        if original is None:self.skipTest('Private audited IMS JAR unavailable; no download attempted.')
        row=next(row for row in self.value['profiles'] if row['feature']=='vendor-ims')
        output=generic_patch(original,row)
        self.assertEqual(output,ims.patch_bytes(original));self.assertEqual(generic_patch(output,row),output)
        altered=bytearray(original);altered[ims.ENTRY[0]]^=1
        with self.assertRaisesRegex(RuntimeError,'Unsupported input content'):generic_patch(bytes(altered),row)

    def test_performance_backends_share_one_feature_and_keep_exact_early_scopes(self):
        import patch_qti_perf as qti
        import patch_uniperf as uniperf
        import patch_bufferqueue_perf as bufferqueue
        rows={row['before']:row for row in self.value['profiles'] if row['feature']=='perf-hardware'}
        sources=(*qti.catalog_recipes(),*uniperf.catalog_recipes(),*bufferqueue.catalog_recipes())
        self.assertEqual(set(rows),{source['before'] for source in sources})
        for source in sources:
            row=rows[source['before']]
            self.assertEqual(row['after'],source['after'])
            self.assertEqual(row['sites'],[[site['offset'],site['before'],site['after']] for site in sorted(source['sites'],key=lambda item:item['offset'])])
            self.assertEqual(row['legacy'],[])
        targets=[row for row in self.value['targets'] if row['feature']=='perf-hardware']
        self.assertEqual({row['path'] for row in targets},{qti.NATIVE,uniperf.PATH,uniperf.MIUI_SERVICES,bufferqueue.NATIVE})
        for source in (qti.NATIVE,uniperf.PATH,uniperf.MIUI_SERVICES,bufferqueue.NATIVE):
            def target(value):return next(row for row in value['targets'] if row['path']==source)
            for change in ({'phase':'late'},{'kind':'app','path':'','package':'com.miui.home'},
                           {'path':'/system_ext/lib64/custom.so','library':'custom.so'},
                           {'path':'/system_ext/framework/UniperfClient.apk','library':'UniperfClient.apk'}):
                with self.subTest(source=source,change=change):self.reject(lambda value:target(value).update(change))

    def test_actual_performance_inputs_match_the_offline_producers(self):
        import patch_qti_perf as qti
        import patch_uniperf as uniperf
        import patch_bufferqueue_perf as bufferqueue
        roots=REPO/'work/feedback-investigation-20261013/phone-perf-callers'
        audit=roots.parent
        candidates=((qti,roots/'libqti-perfd-client_system.so'),(uniperf,roots/'UniperfClient.jar'),
                    (uniperf,audit/'phone-uniperf-loaded-caller/miui-services.jar'),
                    (uniperf,audit/'pad-uniperf-loaded-caller/miui-services.jar'),
                    (bufferqueue,audit/'bufferqueue-perf/pad-libgui.so'))
        found=0
        for producer,path in candidates:
            if not path.is_file():continue
            original=path.read_bytes();checksum=hashlib.sha256(original).hexdigest()
            row=next(row for row in self.value['profiles'] if row['before']==checksum)
            output=generic_patch(original,row);self.assertEqual(output,producer.patch_bytes(original))
            self.assertEqual(generic_patch(output,row),output);found+=1
        if not found:self.skipTest('Private audited performance inputs unavailable; no download attempted.')

    def test_display_metadata_profiles_keep_exact_early_consumer_and_mapper_provenance(self):
        import patch_display_metadata as metadata
        import package_native_module as package
        rows={row['before']:row for row in self.value['profiles'] if row['feature']=='display-metadata'}
        self.assertEqual(set(rows),set(metadata.RECIPES))
        for recipe in metadata.catalog_recipes():
            row=rows[recipe['before']]
            self.assertEqual(row['after'],recipe['after']);self.assertEqual(row['legacy'],[])
            self.assertEqual(row['sites'],[[site['offset'],site['before'],site['after']] for site in recipe['sites']])
        targets=[row for row in self.value['targets'] if row['feature']=='display-metadata']
        self.assertEqual({row['path'] for row in targets},{rule['path'] for rule in metadata.RECIPES.values()})
        for target_path in {row['path'] for row in targets}:
            for change in ({'phase':'late'},{'kind':'app','path':'','package':'com.miui.weather2'},
                           {'path':'/vendor/lib64/hw/mapper.ranchu.so','library':'mapper.ranchu.so'},
                           {'path':'/system_ext/lib64/libmisurfaceflinger.so','library':'libmisurfaceflinger.so'},
                           {'library':'foreign.so'}):
                with self.subTest(target=target_path,change=change):
                    self.reject(lambda value:next(row for row in value['targets'] if row['path']==target_path).update(change))
        generated=package.module_files()['display-metadata-capability.tsv']
        self.assertEqual(generated,metadata.capability_recipe())
        self.assertIn(metadata.MAPPER_SHA256.encode(),generated)

    def test_actual_display_metadata_inputs_match_offline_sites_without_mapper_or_property_changes(self):
        import patch_display_metadata as metadata
        root=REPO/'work/feedback-investigation-20261013/pad-metadata-caller-audit'
        found=0
        for name in ('libui.so','phone-libui.so','libsurfaceflinger.so'):
            path=root/name
            if not path.is_file():continue
            original=path.read_bytes();before=hashlib.sha256(original).hexdigest()
            row=next(row for row in self.value['profiles'] if row['before']==before)
            changed=generic_patch(original,row)
            self.assertEqual(changed,metadata.patch_bytes(original));self.assertEqual(generic_patch(changed,row),changed)
            if name=='libsurfaceflinger.so':
                self.assertIn(b'ro.vendor.display.bt2020.supported',changed)
            found+=1
        if not found:self.skipTest('Private audited display consumers unavailable; no download attempted.')

    def test_cli_emits_the_same_catalog_without_workspace_dependencies(self):
        result = subprocess.run([sys.executable, str(REPO / 'scripts/native_patch_catalog.py')],
                                check=True, capture_output=True, text=True, cwd=REPO)
        self.assertEqual(result.stdout, native.dump_catalog())


if __name__ == '__main__':
    unittest.main()
