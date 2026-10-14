"""Exercise shared platform capabilities and identity persistence in real shells."""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import copy

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'scripts'))
import core_platform as platform
import core_legacy as legacy
import package_native_module
import test_native_module_runtime as fixture


class LegacyFlutterReceiptTests(unittest.TestCase):
    """Authenticate the frozen public r4 contract without proprietary binaries."""
    def setUp(self):
        import apply_flutter_fix as flutter
        from phone_profile import profile
        from patch_flutter import PROFILES
        from patch_weather import APK_SHA256
        selected = profile('4.0.18.0.XFRCNXM')
        self.before = selected['pins']['flutter']
        self.after = PROFILES[self.before]['legacy'][0]
        self.hook = '416cb8720a6b7b9e075d0fa607cf7bf42f5c2113bbb31aeb0ce61ca86f878cc0'
        weather = 'com.miui.weather2'
        paths = {'com.miui.home': '/product/priv-app/MiuiHome/MiuiHome.apk',
                 weather: '/product/app/MIUIWeather/MIUIWeather.apk'}
        hashes = {'com.miui.home': selected['pins']['home_apk'], weather: APK_SHA256}
        engine = 'd67e5c634800a97cd853fd425ded4752c43c2c879fe7269c8b9ffab6c5104836'
        self.manifest = {'revision': 7,
            'firmware': {'source': 'official-hongkong-ota', 'incremental': selected['incremental'],
                         'shared_input_sha256': self.before},
            'system': {'target': flutter.SYSTEM_LIB, 'before': self.before, 'after': self.after},
            'apks': [{'package': weather, 'apk_target': paths[weather], 'payload': weather + '.so',
                      'target': '/product/app/MIUIWeather/lib/arm64/libhyper_os_flutter.so',
                      'before': engine, 'after': PROFILES[engine]['output'], 'apk_sha256': APK_SHA256}],
            'packages': paths, 'apk_hashes': hashes, 'startup_script_sha256': self.hook}

    def assets(self, manifest=None):
        value = self.manifest if manifest is None else manifest
        return legacy.reviewed_assets('hyperos_avd_flutter_render', value, json.dumps(value))

    def inventory(self):
        # The frozen producer writes these canonical files. Hash pins for the
        # proprietary ELF and old hooks are checked without executing either.
        item = self.manifest['apks'][0]
        return {'manifest.json': platform.digest(json.dumps(self.manifest)),
                'flutter.so': self.after, item['payload']: item['after'],
                'post-fs-data.sh': self.hook, 'service.sh': self.hook,
                'module.prop': 'd738bf4d476f7fd6deaf77a286848b86fcff7c77e977472e7cca69acded3ee98',
                'targets.conf': platform.digest(f'SYSTEM_BEFORE={self.before}\nSYSTEM_AFTER={self.after}\n'),
                'apks.conf': platform.digest('|'.join(item[key] for key in
                    ('package', 'payload', 'apk_target', 'target', 'before', 'after', 'apk_sha256')) + '\n')}

    def inspect(self, inventory=None, lifecycle='present'):
        supplied = self.inventory() if inventory is None else inventory
        commands = []
        directory = '/data/adb/modules/hyperos_avd_flutter_render'
        def guest(config, command):
            commands.append(command)
            if 'elif [ -e ' in command:
                return lifecycle if directory + ' ]' in command else 'absent'
            if '__HYPEROS_RECORD_END__' in command:
                return 'present\n' + json.dumps(self.manifest) + '\n__HYPEROS_RECORD_END__'
            if '-mindepth 1 -type d' in command:
                return '\n'.join(checksum + '|' + name for name, checksum in sorted(supplied.items()))
            raise AssertionError('Unexpected command: ' + command)
        return legacy.inspect_legacy(guest, {}), commands

    def test_public_r4_revision_seven_authenticates_old_output_and_frozen_hooks(self):
        values = self.assets()
        self.assertEqual(values['flutter.so'], {self.after})
        self.assertEqual(values['post-fs-data.sh'], {self.hook})
        self.assertEqual(values['service.sh'], {self.hook})
        # Bind the property file to the reviewed historical revision, not Core's current producer.
        self.assertEqual(values['module.prop'],
                         {'d738bf4d476f7fd6deaf77a286848b86fcff7c77e977472e7cca69acded3ee98'})

    def test_complete_public_r4_inventory_is_eligible_for_retirement(self):
        items, commands = self.inspect()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]['status'], 'audited')
        self.assertEqual(items[0]['reason'], 'exact-reviewed-owner')
        self.assertIn('snapshot', items[0])
        self.assertTrue(any('-mindepth 1 -type d' in command for command in commands))
        self.assertFalse(any('uninstall.sh' in command or 'sh /data/adb/modules/' in command for command in commands))

    def test_tampered_or_extra_payload_keeps_legacy_owner_and_conflicting_role(self):
        for changed in ('service.sh', 'flutter.so', 'module.prop', 'unreviewed.so'):
            inventory = self.inventory(); inventory[changed] = '0' * 64
            with self.subTest(changed=changed):
                items, commands = self.inspect(inventory)
                self.assertEqual(items[0]['status'], 'preserved')
                self.assertEqual(items[0]['features'], ['flutter'])
                self.assertNotIn('snapshot', items[0])
                self.assertFalse(any('\nmv ' in command for command in commands))

    def test_legacy_lifecycle_choices_are_not_bypassed_by_a_known_revision(self):
        for lifecycle in ('pending', 'disable\npresent', 'remove\npresent'):
            with self.subTest(lifecycle=lifecycle):
                items, commands = self.inspect(lifecycle=lifecycle)
                self.assertEqual(items[0]['status'], 'preserved')
                self.assertEqual(items[0]['reason'], 'legacy-lifecycle-choice')
                self.assertFalse(any('-mindepth 1 -type d' in command for command in commands))

    def test_current_receipt_remains_separate_from_the_frozen_contract(self):
        import apply_flutter_fix as flutter
        from patch_flutter import PROFILES
        value = copy.deepcopy(self.manifest)
        value.update(revision=flutter.REVISION, skipped_apks={})
        value['system']['after'] = PROFILES[self.before]['output']
        value['startup_script_sha256'] = platform.digest(flutter.boot_script(
            value['firmware']['source'], value['firmware']))
        self.assertIn(value['startup_script_sha256'], self.assets(value)['service.sh'])
        self.assertNotIn(self.hook, self.assets(value)['service.sh'])

    def test_unknown_revision_and_changed_historical_schema_are_rejected(self):
        for change in ({'revision': 6}, {'revision': 9}, {'revision': '7'}, {'revision': 7.0},
                       {'skipped_apks': {}}, {'unreviewed': True}):
            value = {**self.manifest, **change}
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'schema'):
                self.assets(value)
        value = copy.deepcopy(self.manifest); del value['apk_hashes']
        with self.assertRaisesRegex(ValueError, 'schema'):
            self.assets(value)

    def test_firmware_pin_and_hook_tampering_cannot_authorize_retirement(self):
        for field, changed in (('shared_input_sha256', '0' * 64),
                               ('incremental', 'OS4.0.17.0.XFRCNXM'), ('unreviewed', True)):
            value = copy.deepcopy(self.manifest); value['firmware'][field] = changed
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'provenance'):
                self.assets(value)
        value = copy.deepcopy(self.manifest); value['startup_script_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'startup receipt'):
            self.assets(value)

    def test_native_hashes_must_belong_to_the_same_audited_edge(self):
        from patch_flutter import PROFILES
        for field, changed in (('before', '0' * 64), ('after', '0' * 64),
                               ('after', PROFILES['d67e5c634800a97cd853fd425ded4752c43c2c879fe7269c8b9ffab6c5104836']['output']),
                               ('after', PROFILES[self.before]['output'])):
            value = copy.deepcopy(self.manifest); value['system'][field] = changed
            with self.subTest(field=field, changed=changed), self.assertRaisesRegex(ValueError, 'system payload'):
                self.assets(value)

    def test_changed_package_inventory_or_payload_contract_is_rejected(self):
        for field, changed in (('payload', 'foreign.so'), ('before', '0' * 64),
                               ('after', '0' * 64), ('apk_sha256', '0' * 64),
                               ('unreviewed', True), ('external', False)):
            value = copy.deepcopy(self.manifest); value['apks'][0][field] = changed
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.assets(value)
        for field in ('packages', 'apk_hashes'):
            value = copy.deepcopy(self.manifest); value[field]['foreign'] = 'unknown'
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'package inventory'):
                self.assets(value)
        value = copy.deepcopy(self.manifest); value['apks'] *= 2
        with self.assertRaisesRegex(ValueError, 'APK receipt'):
            self.assets(value)


class CorePlatformShellTests(unittest.TestCase):
    def setUp(self):
        fixture.NativeModuleRuntimeTests.setUp(self)
        (self.module / 'boot-prerequisites.tsv').write_bytes(package_native_module.boot_prerequisites())
        from rear_display_wake_runtime import files as rear_files
        for name, body in rear_files().items():
            (self.module / name).write_bytes(body)
        fixture.NativeModuleRuntimeTests.checksums(self)
    profile = fixture.NativeModuleRuntimeTests.profile
    file_metadata = fixture.NativeModuleRuntimeTests.file_metadata

    def run_platform(self, body, overrides='', check=True):
        state = self.root / 'persistent'
        state.mkdir(exist_ok=True)
        self.environment.update(HYPEROS_CORE_STATE=str(state), HYPEROS_CORE_PENDING=str(self.root / 'pending'),
                                HYPEROS_CORE_RESETPROP=str(self.bin / 'resetprop'))
        # Android BusyBox metadata uses the guest's root owner, not the host UID.
        busybox = fixture.BUSYBOX.replace("os.environ.get('HYPEROS_NATIVE_TEST_OWNER', f'{value.st_uid}:{value.st_gid}')", "'0:0'")
        self.bb.write_text(busybox)
        trace = self.root / 'effects'
        (self.bin / 'resetprop').write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> ' + shlex.quote(str(trace)) + '\n')
        (self.bin / 'resetprop').chmod(0o755)
        script = 'MODDIR=' + shlex.quote(str(self.module)) + '\n. "$MODDIR/runtime.sh"\n. "$MODDIR/platform.sh"\n'
        script += overrides + '\n' + body
        result = subprocess.run(['sh', '-c', script], env=self.environment, text=True,
                                capture_output=True, check=check)
        return result, trace.read_text() if trace.exists() else ''

    def test_package_policies_require_complete_vendor_proof_and_restore_feature_choices(self):
        for feature in ('finddevice', 'vendor-ims'):
            helper = self.module / (feature + '-policy.sh')
            helper.write_text('#!/bin/sh\nprintf "%s:%s\\n" ' + shlex.quote(feature) +
                              ' "$1" >> ' + shlex.quote(str(self.root / 'effects')) +
                              '\nprintf "ready|owned-package-disabled\\n"\n')
        fixture.NativeModuleRuntimeTests.checksums(self)
        _, effects = self.run_platform('core_policies', 'native_privacy_eligible() { return 1; }')
        self.assertEqual(effects, '')
        _, effects = self.run_platform('core_policies', 'native_privacy_eligible() { return 0; }')
        self.assertEqual(effects, 'finddevice:apply\nvendor-ims:apply\n')
        (self.module / 'features.disabled').write_text('finddevice\n')
        _, effects = self.run_platform('core_policies', 'native_privacy_eligible() { return 0; }')
        self.assertTrue(effects.endswith('finddevice:restore\nvendor-ims:apply\n'))
        (self.module / 'disable').touch()
        _, effects = self.run_platform('core_policies', 'native_privacy_eligible() { return 0; }')
        self.assertTrue(effects.endswith('finddevice:restore\nvendor-ims:restore\n'))
        _, effects = self.run_platform('core_policy_cleanup')
        self.assertTrue(effects.endswith('finddevice:restore\nvendor-ims:restore\n'))

    def test_pending_update_preserves_package_policy_until_explicit_user_disable(self):
        for feature in ('finddevice','vendor-ims'):
            (self.module/(feature+'-policy.sh')).write_text('#!/bin/sh\nprintf "%s:%s\\n" '+shlex.quote(feature)+' "$1" >> '+shlex.quote(str(self.root/'effects'))+'\nprintf "disabled|original-state-restored\\n"\n')
        fixture.NativeModuleRuntimeTests.checksums(self)
        (self.root/'pending').mkdir()
        _,effects=self.run_platform('core_policies;core_policy_cleanup','native_privacy_eligible() { return 0; }')
        self.assertEqual(effects,'')
        self.assertIn('|pending|module-update-staged\n',(self.module/'state/status.tsv').read_text())
        (self.module/'features.disabled').write_text('finddevice\n')
        _,effects=self.run_platform('core_policies;core_policy_cleanup','native_privacy_eligible() { return 0; }')
        self.assertEqual(effects,'finddevice:restore\nfinddevice:restore\n')
        (self.module/'disable').touch()
        _,effects=self.run_platform('core_policy_cleanup')
        self.assertTrue(effects.endswith('finddevice:restore\nvendor-ims:restore\n'))
        (self.module/'disable').unlink();(self.module/'remove').symlink_to(self.root/'missing')
        _,effects=self.run_platform('core_policy_cleanup')
        self.assertTrue(effects.endswith('finddevice:restore\nvendor-ims:restore\n'))

    def test_serial_persists_across_ota_and_never_replays_a_device_table(self):
        state = self.root / 'persistent'; state.mkdir()
        record = platform.serial_record('69704/F5XA01467')
        (state / 'serial.record').write_text(record)
        inode = (state / 'serial.record').stat().st_ino
        _, effects = self.run_platform('core_serial; core_serial')
        self.assertEqual((state / 'serial.record').read_text(), record)
        self.assertEqual((state / 'serial.record').stat().st_ino, inode)
        self.assertEqual(effects.count('-n ro.ril.oem.psno 69704/F5XA01467'), 2)
        self.assertNotIn('hongkong', effects); self.assertNotIn('yingtian', effects)

    def test_invalid_serial_and_alias_are_preserved_without_property_changes(self):
        state = self.root / 'persistent'; state.mkdir()
        target = state / 'serial.record'; target.write_text('1|hyperos_avd_native_compat|unknown\n')
        result, effects = self.run_platform('core_serial', check=False)
        self.assertNotEqual(result.returncode, 0); self.assertEqual(effects, '')
        target.unlink(); target.symlink_to(self.root / 'foreign')
        result, effects = self.run_platform('core_serial', check=False)
        self.assertNotEqual(result.returncode, 0); self.assertEqual(effects, '')
        self.assertTrue(target.is_symlink())

    def test_disable_remove_and_pending_recheck_before_effects(self):
        state = self.root / 'persistent'; state.mkdir()
        (state / 'serial.record').write_text(platform.serial_record('69704/F5XA01467'))
        for flag in ('disable', 'remove'):
            path = self.module / flag; path.symlink_to(self.root / 'missing')
            _, effects = self.run_platform('core_serial; core_refresh; core_rear')
            self.assertEqual(effects, ''); path.unlink()
        (self.root / 'pending').mkdir()
        _, effects = self.run_platform('core_serial; core_refresh; core_rear')
        self.assertEqual(effects, '')

    def test_serial_new_uses_xiaomi_style_once_per_userdata(self):
        _, effects = self.run_platform('core_serial; core_serial')
        record = (self.root / 'persistent/serial.record').read_text().rstrip('\n')
        serial = record.split('|')[-1]
        self.assertRegex(serial, platform.SERIAL)
        self.assertEqual(effects.count('-n ro.serialno ' + serial), 2)

    def test_identity_is_data_and_whitelisted_public_keys_only(self):
        state = self.root / 'persistent'; state.mkdir()
        (state / 'image.tsv').write_text('identity|/system/build.prop|' + 'a' * 64 + '\n')
        source = self.root / 'build.prop'
        source.write_text('ro.product.model=Future Xiaomi\nro.build.fingerprint=Xiaomi/future:user/release-keys\n'
                          'ro.board.platform=vendor-hal\nro.hardware.camera=vendor-hal\nro.boot.serialno=foreign\n'
                          'ro.product.cpu.abilist=x86\nro.vendor.api_level=99\nmalicious=$(touch /tmp/never)\n')
        overrides = 'core_context_ready() { return 0; }\n'
        overrides += 'core_identity_rows() { "$BB" awk -F "=" \'$1=="ro.product.model" || $1=="ro.build.fingerprint" {print $1 "|" $2}\' ' + shlex.quote(str(source)) + '; }'
        _, effects = self.run_platform('core_identity', overrides)
        self.assertIn('-n ro.product.model Future Xiaomi', effects)
        self.assertNotIn('vendor-hal', effects); self.assertNotIn('foreign', effects); self.assertNotIn('x86', effects)
        # Also exercise the actual parser without property mutations.
        parser = (REPO / 'modules/native-compat/platform.sh').read_text().split('core_identity_rows() {', 1)[1].split('\ncore_identity() {', 1)[0]
        parser = 'core_identity_rows() {' + parser.replace('"$path"', shlex.quote(str(source)))
        result, _ = self.run_platform('core_identity_rows', parser)
        self.assertEqual(result.stdout.splitlines(), ['ro.product.model|Future Xiaomi', 'ro.build.fingerprint|Xiaomi/future:user/release-keys'])

    def test_unverified_identity_source_has_no_resetprop_side_effects(self):
        state = self.root / 'persistent'; state.mkdir()
        (state / 'image.tsv').write_text('identity|/system/build.prop|' + '0' * 64 + '\n')
        _, effects = self.run_platform('core_identity')
        self.assertEqual(effects, '')
        self.assertIn('unverified-image-defaults', (self.module / 'state/status.tsv').read_text())

    def test_refresh_requires_actual_primary_mode_and_keeps_settings_choices(self):
        overrides = '''getprop() { case "$1" in ro.boot.qemu.vsync) echo 60;; *) echo 1;; esac; }
dumpsys() { printf 'activeMode={id=0, hwcId=0, resolution=2272x3408, vsyncRate=60.00 Hz} '; if [ -f "$CORE_STATE/refreshed" ]; then echo 'renderRate=60.00 Hz'; else echo 'renderRate=20.00 Hz'; fi; }
service() { echo "$*" >> "$CORE_STATE/refresh-calls"; touch "$CORE_STATE/refreshed"; echo 'Result: Parcel(NULL)'; }
settings() { echo unexpected-settings-write >&2; return 1; }
'''
        self.run_platform('core_refresh; core_refresh', overrides)
        self.assertIn('compositor-60hz', (self.module / 'state/status.tsv').read_text())
        self.assertEqual((self.root / 'persistent/refresh-calls').read_text().splitlines(), ['call SurfaceFlinger 1035 i32 0'])
        self.run_platform('core_refresh', overrides.replace('id=0,', 'id=1,'))
        self.assertIn('unsupported-active-mode', (self.module / 'state/status.tsv').read_text())

    def test_rear_helper_does_not_start_for_tablet_or_unverified_resources(self):
        _, effects = self.run_platform('core_rear')
        self.assertEqual(effects, '')
        self.assertIn('physical-display-prerequisite', (self.module / 'state/status.tsv').read_text())
        self.assertFalse((self.root / 'persistent/rear.guard').exists())

    def test_persistent_conflict_gate_blocks_the_native_and_platform_owner(self):
        state = self.root / 'persistent'; state.mkdir()
        (state / 'legacy-blocked.features').write_text('flutter\nserial\n')
        result, effects = self.run_platform('native_enabled flutter && exit 9; core_serial')
        self.assertEqual(result.returncode, 0); self.assertEqual(effects, '')

    def test_identity_and_status_do_not_rehash_or_rewrite_unchanged_values(self):
        overrides = '''core_context_ready() { echo checked >> "$CORE_STATE/checks"; return 0; }
core_identity_rows() { printf 'ro.product.model|Future Xiaomi\\nro.build.fingerprint|Future/fingerprint\\n'; }
getprop() { case "$1" in ro.product.model) echo 'Future Xiaomi';; ro.build.fingerprint) echo 'Future/fingerprint';; esac; }
'''
        _, effects = self.run_platform('core_identity', overrides)
        status = self.module / 'state/status.tsv'; log = self.module / 'runtime.log'
        inode = status.stat().st_ino; original_log = log.read_bytes()
        self.run_platform('core_identity', overrides)
        self.assertEqual((self.root / 'persistent/checks').read_text().splitlines(), ['checked', 'checked'])
        self.assertEqual(status.stat().st_ino, inode); self.assertEqual(log.read_bytes(), original_log)
        self.assertEqual(effects, '')

    def test_boot_gate_requires_every_reviewed_image_prerequisite(self):
        from patch_boot_services import image_receipts
        state = self.root / 'persistent'; state.mkdir()
        for receipt in image_receipts():
            pins = {item['path']: item['after'] for item in receipt['targets'].values()}
            pins['/system/bin/hyperos_kernel_probe'] = receipt['probe_sha256']
            rows = ''.join('boot|' + path + '|' + checksum + '\n' for path, checksum in pins.items())
            (state / 'image.tsv').write_text(rows)
            overrides = 'core_safe_file() { return 0; }\nnative_ns_hash() { case "$2" in\n'
            overrides += ''.join(shlex.quote(path) + ') echo ' + checksum + ';;\n' for path, checksum in pins.items())
            overrides += 'esac; }'
            self.run_platform('core_context_ready boot', overrides)
            for changed in (rows.replace(receipt['probe_sha256'], '0' * 64),
                            ''.join(rows.splitlines(True)[:-1]), rows + rows.splitlines(True)[0],
                            rows + 'boot|/system/framework/foreign.jar|' + 'a' * 64 + '\n',
                            rows.replace('|/system/framework/services.jar|', '|/system/framework/services.jar|extra|')):
                with self.subTest(recipe=receipt['targets']['services']['after'], changed=changed):
                    (state / 'image.tsv').write_text(changed)
                    result, _ = self.run_platform('core_context_ready boot', overrides, check=False)
                    self.assertNotEqual(result.returncode, 0)
                    # The invalid group precedes any probe or service control.
                    self.run_platform('core_kernel', overrides)
                    self.assertIn('unverified-image-prerequisites', (self.module / 'state/status.tsv').read_text())
            (state / 'image.tsv').write_text(rows)
            result, _ = self.run_platform('core_context_ready boot',
                'core_safe_file() { return 0; }\nnative_ns_hash() { echo ' + 'f' * 64 + '; }', check=False)
            self.assertNotEqual(result.returncode, 0, 'Actual namespace content must also match.')

    def boot_native_derivative_fixture(self, rear=False, thermal=False, brightness=False):
        import patch_uniperf as uniperf
        from patch_boot_services import image_receipt
        source=REPO/'work/feedback-investigation-20261013/phone-uniperf-loaded-caller/miui-services.jar'
        self.boot_path=uniperf.MIUI_SERVICES
        receipt=image_receipt()
        feature='perf-hardware'
        producer=uniperf
        if rear:
            import patch_rear_input_policy as producer
            from patch_boot_services import image_receipts
            self.boot_path=producer.PATH
            receipt=next(row for row in image_receipts()
                         if row['targets']['services']['after']==producer.BEFORE)
            source=REPO/('work/feedback-investigation-20261013/rear-state-sync/phone-services-'+producer.BEFORE+'.jar')
            feature='rear-input'
        pins={row['path']:row['after'] for row in receipt['targets'].values()}
        pins['/system/bin/hyperos_kernel_probe']=receipt['probe_sha256']
        self.boot_expected=pins[self.boot_path]
        derivative=(producer.AFTER if rear else uniperf.RECIPES[self.boot_expected]['after'])
        if source.is_file():
            original=source.read_bytes();self.boot_after=producer.patch_bytes(original)
            self.assertEqual(hashlib.sha256(original).hexdigest(),self.boot_expected)
            self.assertEqual(hashlib.sha256(self.boot_after).hexdigest(),derivative)
        else:
            # Keep guard/provenance coverage in public CI. The namespace hash
            # oracle models the reviewed byte identity; producer tests audit
            # the proprietary JAR independently when that input is available.
            self.boot_after=b'Public namespace fixture for an audited immutable derivative.'
        if thermal:
            import patch_thermal_capability as monitor
            if source.is_file():
                self.boot_after = monitor.patch_bytes(self.boot_after)
            derivative = monitor.RECIPES[derivative]['after']
        if brightness:
            import patch_display_brightness as display
            if source.is_file():
                self.boot_after = display.patch_bytes(self.boot_after)
            derivative = display.AFTER
        # Authenticate real generated controls; path mapping substitutes only
        # the namespace's immutable image files, never catalog/hash semantics.
        for name,body in package_native_module.module_files().items():
            target=self.module/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(body)
        self.boot_actual=self.root/Path(self.boot_path).name;self.boot_actual.write_bytes(self.boot_after)
        state=self.root/'persistent';state.mkdir(exist_ok=True)
        self.boot_rows=''.join('boot|'+path+'|'+checksum+'\n' for path,checksum in pins.items())
        (state/'image.tsv').write_text(self.boot_rows)
        self.boot_mount='40 1 253:1 '+str(self.module/'cache/trusted.so')+' '+self.boot_path+' rw - ext4 /dev/block/test rw\n'
        (self.proc/'1/mountinfo').write_text(self.boot_mount)
        actual=shlex.quote(str(self.boot_actual));path=shlex.quote(self.boot_path)
        overrides='core_safe_file() { case "$1" in\n'+path+') [ -f '+actual+' ] && [ ! -L '+actual+' ] && [ "$("$BB" stat -c %h '+actual+')" = 1 ];;\n'
        overrides+=''.join(shlex.quote(item)+') return 0;;\n' for item in pins if item!=self.boot_path)
        overrides+='*) [ -f "$1" ] && [ ! -L "$1" ] && [ "$("$BB" stat -c %u "$1")" = 0 ] && [ "$("$BB" stat -c %h "$1")" = 1 ];;\nesac; }\n'
        fixture_hash=hashlib.sha256(self.boot_after).hexdigest()
        overrides+='native_ns_hash() { case "$2" in\n'+path+') observed=$(native_hash '+actual+'); if [ "$observed" = '+fixture_hash+' ]; then echo '+derivative+'; else echo "$observed"; fi;;\n'
        overrides+=''.join(shlex.quote(item)+') echo '+checksum+';;\n' for item,checksum in pins.items() if item!=self.boot_path)
        overrides+='*) return 1;;\nesac; }\n'
        overrides+='native_eligible() { [ "$1" = '+feature+' ]'+(' || [ "$1" = thermal-monitor ]' if thermal else '')+(' || [ "$1" = display-brightness ]' if brightness else '')+'; }\n'
        return overrides

    def test_owned_performance_and_thermal_chain_keeps_boot_provenance(self):
        overrides = self.boot_native_derivative_fixture(thermal=True)
        self.run_platform('core_context_ready boot', overrides)
        self.assertEqual((self.root / 'persistent/image.tsv').read_text(), self.boot_rows)
        (self.module / 'features.disabled').write_text('perf-hardware\nthermal-monitor\n')
        self.run_platform('core_context_ready boot', overrides)
        # A present physical node must reject the terminal derived identity.
        self.assertNotEqual(self.run_platform('core_context_ready boot', overrides +
            'native_eligible() { [ "$1" = perf-hardware ]; }\n', check=False)[0].returncode, 0)

    def test_owned_rear_input_and_brightness_chain_keeps_boot_provenance(self):
        overrides = self.boot_native_derivative_fixture(rear=True, brightness=True)
        self.run_platform('core_context_ready boot', overrides)
        self.assertEqual((self.root / 'persistent/image.tsv').read_text(), self.boot_rows)
        self.assertNotEqual(self.run_platform('core_context_ready boot', overrides +
            'native_eligible() { [ "$1" = rear-input ]; }\n', check=False)[0].returncode, 0)

    def test_exact_owned_native_derivative_keeps_independent_boot_provenance_when_feature_off(self):
        overrides=self.boot_native_derivative_fixture()
        self.run_platform('core_context_ready boot',overrides)
        (self.module/'features.disabled').write_text('perf-hardware\n')
        _,effects=self.run_platform('core_context_ready boot',overrides)
        self.assertEqual(effects,'')
        self.assertEqual((self.root/'persistent/image.tsv').read_text(),self.boot_rows)
        self.assertEqual(self.boot_actual.read_bytes(),self.boot_after)

    def test_boot_derivative_rejects_foreign_mount_unconfirmed_capability_and_unknown_bytes(self):
        overrides=self.boot_native_derivative_fixture()
        mount=self.proc/'1/mountinfo'
        for body in ('',self.boot_mount.replace(str(self.module/'cache'),'/foreign/module/cache')):
            mount.write_text(body)
            self.assertNotEqual(self.run_platform('core_context_ready boot',overrides,check=False)[0].returncode,0)
        mount.write_text(self.boot_mount)
        self.assertNotEqual(self.run_platform('core_context_ready boot',overrides+'native_eligible() { return 1; }\n',check=False)[0].returncode,0)
        self.boot_actual.write_bytes(b'unknown framework content')
        self.assertNotEqual(self.run_platform('core_context_ready boot',overrides,check=False)[0].returncode,0)
        self.boot_actual.write_bytes(self.boot_after)
        context=self.root/'persistent/image.tsv'
        context.write_text(self.boot_rows.replace(self.boot_path+'|'+self.boot_expected,self.boot_path+'|'+'a'*64))
        self.assertNotEqual(self.run_platform('core_context_ready boot',overrides,check=False)[0].returncode,0)

    def test_boot_derivative_rejects_changed_current_controls_and_aliases(self):
        overrides=self.boot_native_derivative_fixture()
        profiles=self.module/'profiles.tsv';original=profiles.read_bytes()
        profiles.write_bytes(original+b'\n')
        self.assertNotEqual(self.run_platform('core_context_ready boot',overrides,check=False)[0].returncode,0)
        profiles.write_bytes(original)
        alias=self.module/'profiles-alias';alias.write_bytes(original)
        profiles.unlink();profiles.symlink_to(alias)
        self.assertNotEqual(self.run_platform('core_context_ready boot',overrides,check=False)[0].returncode,0)
        profiles.unlink();profiles.write_bytes(original)
        hardlink=self.module/'profiles-hardlink';os.link(profiles,hardlink)
        self.assertNotEqual(self.run_platform('core_context_ready boot',overrides,check=False)[0].returncode,0)
        hardlink.unlink()
        target_alias=self.root/'actual-alias';self.boot_actual.rename(target_alias);self.boot_actual.symlink_to(target_alias)
        self.assertNotEqual(self.run_platform('core_context_ready boot',overrides,check=False)[0].returncode,0)

    def test_boot_derivative_rejects_duplicate_scopes_and_legacy_or_mixed_edges(self):
        overrides=self.boot_native_derivative_fixture()
        profiles=self.module/'profiles.tsv';targets=self.module/'targets.tsv'
        original_profiles,original_targets=profiles.read_text(),targets.read_text()
        expected=self.boot_expected
        selected=next(line for line in original_profiles.splitlines(True) if line.startswith(expected+'|'))
        scope=next(line for line in original_targets.splitlines(True) if '|'+self.boot_path+'|' in line)
        middle='a'*64;parts=selected.rstrip().split('|')
        cases=((original_profiles+selected,original_targets),
               (original_profiles,original_targets+scope),
               (original_profiles,original_targets.replace(scope,scope.replace('early|system','late|system'))),
               (original_profiles,original_targets.replace(scope,scope.replace('perf-hardware','hwui'))),
               (original_profiles,original_targets.replace(scope,scope.replace('|miui-services.jar','|foreign.jar'))),
               (original_profiles.replace(selected,'|'.join((expected,middle,'',*parts[3:]))+'\n'),original_targets),
               (original_profiles.replace(selected,'|'.join((parts[0],parts[1],middle,*parts[3:]))+'\n'),original_targets),
               (original_profiles.replace(selected,'|'.join((middle,parts[1],expected,*parts[3:]))+'\n'),original_targets),
               (original_profiles.replace(selected,'|'.join((expected,middle,'',*parts[3:]))+'\n'+'|'.join((middle,parts[1],'',parts[3],'foreign-profile'))+'\n'),original_targets))
        for changed_profiles,changed_targets in cases:
            profiles.write_text(changed_profiles);targets.write_text(changed_targets)
            fixture.NativeModuleRuntimeTests.checksums(self)
            self.assertNotEqual(self.run_platform('core_context_ready boot',overrides,check=False)[0].returncode,0)
        profiles.write_text(original_profiles);targets.write_text(original_targets)
        fixture.NativeModuleRuntimeTests.checksums(self)
        self.run_platform('core_context_ready boot',overrides)

    def test_rear_input_owned_derivative_retains_complete_boot_pin_and_feature_choices(self):
        overrides=self.boot_native_derivative_fixture(rear=True)
        self.run_platform('core_context_ready boot',overrides)
        (self.module/'features.disabled').write_text('rear-input\n')
        self.run_platform('core_context_ready boot',overrides)
        self.assertEqual((self.root/'persistent/image.tsv').read_text(),self.boot_rows)
        self.assertEqual(self.boot_actual.read_bytes(),self.boot_after)

    def test_rear_input_derivative_rejects_foreign_mount_capability_unknown_bytes_and_wrong_scope(self):
        overrides=self.boot_native_derivative_fixture(rear=True)
        mount=self.proc/'1/mountinfo'
        mount.write_text(self.boot_mount.replace(str(self.module/'cache'),'/foreign/module/cache'))
        self.assertNotEqual(self.run_platform('core_context_ready boot',overrides,check=False)[0].returncode,0)
        mount.write_text(self.boot_mount)
        self.assertNotEqual(self.run_platform('core_context_ready boot',overrides+'native_eligible() { return 1; }\n',check=False)[0].returncode,0)
        self.boot_actual.write_bytes(b'unknown framework content')
        self.assertNotEqual(self.run_platform('core_context_ready boot',overrides,check=False)[0].returncode,0)
        self.boot_actual.write_bytes(self.boot_after)
        targets=self.module/'targets.tsv';original=targets.read_text()
        selected=next(line for line in original.splitlines(True) if '|'+self.boot_path+'|' in line)
        targets.write_text(original.replace(selected,selected.replace('|rear-input|','|perf-hardware|')))
        fixture.NativeModuleRuntimeTests.checksums(self)
        self.assertNotEqual(self.run_platform('core_context_ready boot',overrides,check=False)[0].returncode,0)

    def test_rear_input_requires_exact_retained_rear_context_and_logical_id_before_boot(self):
        state=self.root/'persistent';state.mkdir()
        record=state/'rear.record';record.write_text('1|1|1|local:4619827551948147201\n')
        properties=fixture.NativeModuleRuntimeTests.rear_properties(self,**{
            'persist.sys.secondary_builtin_display_id':'1','ro.boot.qemu.external.displays':'1,912,596,160,0'})
        overrides=self.rear_hash_override()+properties+'\ncore_context_ready() { [ "$1" = rear ]; }\n'
        # No live display service is needed to mount the method before zygote.
        self.run_platform('native_eligible rear-input',overrides)
        self.assertNotEqual(self.run_platform('native_eligible rear-input',overrides+'core_context_ready() { return 1; }\n',check=False)[0].returncode,0)
        for row in ('1|2|1|local:4619827551948147201\n','1|1|2|local:4619827551948147201\n',
                    '1|1|1|local:unknown\n'):
            record.write_text(row)
            self.assertNotEqual(self.run_platform('native_eligible rear-input',overrides,check=False)[0].returncode,0)
        record.unlink()
        self.assertNotEqual(self.run_platform('native_eligible rear-input',overrides,check=False)[0].returncode,0)
        record.write_text('1|1|1|local:4619827551948147201\n')
        other=fixture.NativeModuleRuntimeTests.rear_properties(self,**{
            'persist.sys.secondary_builtin_display_id':'3','ro.boot.qemu.external.displays':'3,912,596,160,0'})
        self.assertNotEqual(self.run_platform('native_eligible rear-input',self.rear_hash_override()+other+'\ncore_context_ready() { return 0; }\n',check=False)[0].returncode,0)
        self.assertNotEqual(self.run_platform('native_eligible rear-input',self.rear_hash_override(),check=False)[0].returncode,0)
        (self.module/'rear-wake.jar').write_bytes(b'customized unreviewed helper')
        self.assertNotEqual(self.run_platform('native_eligible rear-input',overrides,check=False)[0].returncode,0)

    def test_boot_catalog_is_checked_and_full_recipes_cannot_be_mixed(self):
        from patch_boot_services import image_receipt
        state = self.root / 'persistent'; state.mkdir()
        receipt = image_receipt()
        pins = {item['path']: item['after'] for item in receipt['targets'].values()}
        pins['/system/bin/hyperos_kernel_probe'] = receipt['probe_sha256']
        rows = ''.join('boot|' + path + '|' + checksum + '\n' for path, checksum in pins.items())
        (state / 'image.tsv').write_text(rows)
        catalog = self.module / 'boot-prerequisites.tsv'
        original = catalog.read_bytes()
        # A tampered file is refused even when the requested group still exists.
        catalog.write_bytes(original + b'\n')
        result, _ = self.run_platform('core_boot_recipe', check=False)
        self.assertNotEqual(result.returncode, 0)
        catalog.write_bytes(original)
        alias = self.module / 'catalog-alias'; alias.write_bytes(original)
        catalog.unlink(); catalog.symlink_to(alias)
        result, _ = self.run_platform('core_boot_recipe', check=False)
        self.assertNotEqual(result.returncode, 0)
        catalog.unlink(); catalog.write_bytes(original)
        # Future recipes may change several files. Every hash can be registered
        # individually while their mixture is still an unaudited combination.
        second = dict(pins)
        second['/system/framework/services.jar'] = 'a' * 64
        second['/system_ext/framework/miui-services.jar'] = 'b' * 64
        generated = ['schema|1']
        for identity, group in (('1' * 64, pins), ('2' * 64, second)):
            generated.append(f'recipe|{identity}|{len(group)}')
            generated.extend('|'.join(('file', identity, path, checksum)) for path, checksum in group.items())
        body = '\n'.join(generated) + '\n'
        catalog.write_text(body); fixture.NativeModuleRuntimeTests.checksums(self)
        self.run_platform('core_boot_recipe')
        mixed = dict(pins); mixed['/system/framework/services.jar'] = second['/system/framework/services.jar']
        (state / 'image.tsv').write_text(''.join('boot|' + path + '|' + checksum + '\n' for path, checksum in mixed.items()))
        result, _ = self.run_platform('core_boot_recipe', check=False)
        self.assertNotEqual(result.returncode, 0)
        (state / 'image.tsv').write_text(rows)
        for malformed in (body.replace('schema|1', 'schema|2'),
                          body + generated[2] + '\n',
                          '\n'.join(generated[:2] + generated[3:]) + '\n',
                          body + generated[1] + '\n',
                          body.replace(generated[2], generated[2] + '|extra')):
            catalog.write_text(malformed); fixture.NativeModuleRuntimeTests.checksums(self)
            result, _ = self.run_platform('core_boot_recipe', check=False)
            self.assertNotEqual(result.returncode, 0, malformed)

    def test_boot_group_snapshot_cannot_be_replaced_between_matching_and_hashing(self):
        from patch_boot_services import image_receipt
        state = self.root / 'persistent'; state.mkdir()
        receipt = image_receipt()
        pins = {item['path']: item['after'] for item in receipt['targets'].values()}
        pins['/system/bin/hyperos_kernel_probe'] = receipt['probe_sha256']
        (state / 'image.tsv').write_text(''.join('boot|' + path + '|' + checksum + '\n'
                                              for path, checksum in pins.items()))
        overrides = '''core_safe_file() { return 0; }
native_ns_hash() {
    printf 'boot|/system/framework/foreign.jar|%s\\n' ''' + 'a' * 64 + ''' > "$CORE_STATE/image.tsv"
    echo "$2" >> "$CORE_STATE/hashed-paths"
    case "$2" in
'''
        overrides += ''.join(shlex.quote(path) + ') echo ' + checksum + ';;\n' for path, checksum in pins.items())
        overrides += '*) echo ' + 'a' * 64 + ';;\nesac; }'
        self.run_platform('core_context_ready boot', overrides)
        self.assertCountEqual((state / 'hashed-paths').read_text().splitlines(), list(pins))
        self.assertNotIn('/system/framework/foreign.jar', (state / 'hashed-paths').read_text())
        result, _ = self.run_platform('core_context_ready boot', overrides, check=False)
        self.assertNotEqual(result.returncode, 0, 'The next check must reject the changed userdata context.')

    def rear_process(self, pid, start=42, owned=True, current=False):
        directory = self.proc / str(pid); directory.mkdir(exist_ok=True)
        (directory / 'cmdline').write_bytes(b'app_process\0' + (b'io.github.hyperosavd.RearDisplayWake' if owned else b'foreign.Main') + b'\0')
        classpath = str(self.module / 'rear-wake.jar') if current else '/system_ext/framework/rear-display-wake.jar'
        (directory / 'environ').write_bytes(('CLASSPATH=' + classpath + '\0').encode())
        (directory / 'status').write_text('Uid:\t0\t0\t0\t0\n')
        # Field 22 is the process start tick, after a parenthesized comm.
        (directory / 'stat').write_text(f'{pid} (app process) ' + ' '.join(['S'] + ['0'] * 18 + [str(start)] + ['0'] * 20) + '\n')

    def rear_hash_override(self):
        return '''native_ns_hash() {
    case "$2" in
        /system_ext/framework/rear-display-wake.jar) echo d38aef457215fe9f5f397af2e58ece05c3baa61f742a8a9e3d7a3b577bd5c077 ;;
        /system_ext/bin/rear-display-wake) echo f98ea740ae450ea4e2e0815c7e74f698ee2fe5cfcd6a367247f2f91021ed16e7 ;;
        "$MODDIR/rear-wake.jar") native_hash "$2" ;;
        *) return 1 ;;
    esac
}
'''

    def test_rear_process_requires_one_complete_root_uid_record(self):
        self.rear_process(123)
        status = self.proc / '123/status'
        for value in ('Uid:\t1000\t1000\t1000\t1000\n', 'Uid:\t0\t0\t0\t1000\n',
                      'Uid:\t0\t0\n', 'Uid:\t0\t0\t0\t0\n' * 2, 'Name:\tforeign\n'):
            status.write_text(value)
            self.assertNotEqual(self.run_platform('core_rear_process 123', check=False)[0].returncode, 0)
        status.write_text('Uid:\t0\t0\t0\t0\n')
        self.run_platform('core_rear_process 123')

    def test_rear_disable_stops_only_the_exact_adopted_process_lifetime(self):
        child = subprocess.Popen(['sleep', '30'])
        self.addCleanup(lambda: child.poll() is None and child.kill())
        self.rear_process(child.pid)
        state = self.root / 'persistent'; state.mkdir()
        (state / 'rear-daemon.record').write_text(f'1|test-boot|{child.pid}|42\n')
        (self.module / 'features.disabled').write_text('rear-wake\n')
        overrides = self.rear_hash_override()
        self.run_platform('core_rear', overrides)
        self.assertEqual(child.wait(timeout=2), -15)
        self.assertIn('verified-daemon-stopped', (self.module / 'state/status.tsv').read_text())

    def test_rear_missing_empty_alias_dead_boot_pid_reuse_and_foreign_are_preserved(self):
        state = self.root / 'persistent'; state.mkdir()
        file = state / 'rear-daemon.record'; self.rear_process(123)
        overrides = self.rear_hash_override() + '''kill() { echo unwanted-signal >> "$CORE_STATE/signals"; }
'''
        for record in (None, '', '1|earlier-boot|123|42\n', '1|test-boot|123|99\n', '1|test-boot|124|42\n'):
            if record is None: file.unlink(missing_ok=True)
            else: file.write_text(record)
            self.run_platform('core_rear_cleanup', overrides)
        self.rear_process(124, owned=False)
        file.write_text('1|test-boot|124|42\n'); self.run_platform('core_rear_cleanup', overrides)
        file.unlink(); file.symlink_to(self.root / 'missing'); self.run_platform('core_rear_cleanup', overrides)
        self.assertFalse((state / 'signals').exists()); self.assertTrue(file.is_symlink())

    def test_rear_lease_serializes_start_adoption_and_cleanup(self):
        import fcntl
        state = self.root / 'persistent'; state.mkdir()
        self.rear_process(123, current=True)
        record = state / 'rear-daemon.record'; record.write_text('1|test-boot|123|42\n')
        inode = record.stat().st_ino
        overrides = self.rear_hash_override() + '''core_rear_ready() { return 0; }
kill() { echo unwanted-signal >> "$CORE_STATE/signals"; }
'''
        with (state / 'rear.guard').open('a') as lease:
            fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.run_platform('core_rear; core_rear_cleanup', overrides)
            self.assertEqual(record.stat().st_ino, inode)
            self.assertFalse((state / 'signals').exists())
        self.run_platform('core_rear', overrides)
        self.assertEqual(record.stat().st_ino, inode)
        self.assertIn('verified-existing-daemon', (self.module / 'state/status.tsv').read_text())

    def test_rear_unleased_unknown_or_stale_owner_is_preserved(self):
        state = self.root / 'persistent'; state.mkdir()
        self.rear_process(123)
        record = state / 'rear-daemon.record'
        overrides = self.rear_hash_override() + '''core_rear_ready() { return 0; }
kill() { echo unwanted-signal >> "$CORE_STATE/signals"; }
'''
        for value in (None, '1|earlier-boot|123|42\n', '1|test-boot|123|999\n'):
            if value is None: record.unlink(missing_ok=True)
            else: record.write_text(value)
            self.run_platform('core_rear', overrides)
            self.assertIn('unowned-daemon-preserved', (self.module / 'state/status.tsv').read_text())
        record.write_text('1|test-boot|123|42\n')
        (self.proc / '123/environ').write_bytes(b'CLASSPATH=/data/foreign.jar\0')
        self.run_platform('core_rear', overrides)
        self.assertIn('unowned-daemon-preserved', (self.module / 'state/status.tsv').read_text())
        self.assertFalse((state / 'signals').exists())

    def test_rear_migration_waits_for_the_exact_legacy_owner_to_exit(self):
        state = self.root / 'persistent'; state.mkdir()
        self.rear_process(123)
        (state / 'rear-daemon.record').write_text('1|test-boot|123|42\n')
        overrides = self.rear_hash_override() + '''core_rear_ready() { return 0; }
kill() { printf '%s\n' "$*" >> "$CORE_STATE/signals"; }
sleep() { :; }
'''
        self.run_platform('core_rear', overrides)
        self.assertEqual((state / 'signals').read_text(), '-TERM 123\n')
        self.assertIn('previous-daemon-stopping', (self.module / 'state/status.tsv').read_text())
        # It never starts a second listener or changes the immutable image jar.
        rows = (self.module / 'runtime.log').read_text().splitlines()
        self.assertEqual(len(rows), 2)
        self.assertIn('verified-daemon-stopped', rows[0])
        self.assertIn('previous-daemon-stopping', rows[1])

    def test_rear_runtime_recipe_rejects_unknown_code_and_extra_rows(self):
        valid = (self.module / 'rear-wake.tsv').read_text()
        overrides = self.rear_hash_override()
        self.rear_process(123, current=True)
        self.run_platform('core_rear_kind 123', overrides)
        for changed in (valid + 'extra|ignored\n', valid.replace('schema|1', 'schema|2'),
                        valid.replace('class|io.github.hyperosavd.RearDisplayWake', 'class|foreign.Main'),
                        valid.replace('jar|rear-wake.jar|', 'jar|foreign.jar|'),
                        valid.replace('legacy-launcher|/system_ext/bin/rear-display-wake|',
                                      'legacy-launcher|/data/foreign|')):
            (self.module / 'rear-wake.tsv').write_text(changed)
            fixture.NativeModuleRuntimeTests.checksums(self)
            result, _ = self.run_platform('core_rear_kind 123', overrides, check=False)
            self.assertNotEqual(result.returncode, 0, changed)
        (self.module / 'rear-wake.tsv').write_text(valid)
        (self.module / 'rear-wake.jar').write_bytes(b'unreviewed-runtime')
        fixture.NativeModuleRuntimeTests.checksums(self)
        result, _ = self.run_platform('core_rear_kind 123', overrides, check=False)
        self.assertNotEqual(result.returncode, 0)

    def test_rear_cold_start_executes_only_the_verified_module_jar_and_reuses_lease(self):
        import signal
        import textwrap
        helper = self.bin / 'app_process'
        helper.write_text('#!' + sys.executable + '\n' + textwrap.dedent(r'''
            import os, pathlib, shutil, signal, sys, time
            directory = pathlib.Path(os.environ['HYPEROS_NATIVE_PROC']) / str(os.getpid())
            directory.mkdir()
            (directory / 'cmdline').write_bytes(b'app_process\0io.github.hyperosavd.RearDisplayWake\0')
            (directory / 'environ').write_bytes(('CLASSPATH=' + os.environ['CLASSPATH'] + '\0').encode())
            (directory / 'status').write_text('Uid:\t0\t0\t0\t0\n')
            (directory / 'stat').write_text(str(os.getpid()) + ' (app process) ' +
                                          ' '.join(['S'] + ['0'] * 18 + ['42'] + ['0'] * 20) + '\n')
            (pathlib.Path(os.environ['HYPEROS_CORE_STATE']) / 'started-pid').write_text(str(os.getpid()))
            print('owned-helper-started:' + os.environ['CLASSPATH'], flush=True)
            signal.signal(signal.SIGTERM, lambda *args: sys.exit(0))
            try:
                while True: time.sleep(0.1)
            finally:
                shutil.rmtree(directory)
        '''))
        helper.chmod(0o755)
        script = self.module / 'platform.sh'
        script.write_text(script.read_text().replace('/system/bin/app_process', shlex.quote(str(helper))))
        fixture.NativeModuleRuntimeTests.checksums(self)
        state = self.root / 'persistent'
        def stop_fixture():
            path = state / 'started-pid'
            if path.exists():
                try: os.kill(int(path.read_text()), signal.SIGTERM)
                except ProcessLookupError: pass
        self.addCleanup(stop_fixture)
        overrides = self.rear_hash_override() + 'core_rear_ready() { return 0; }\n'
        self.run_platform('core_rear; core_rear', overrides)
        pid = int((state / 'started-pid').read_text())
        self.assertEqual((state / 'rear-daemon.record').read_text(), f'1|test-boot|{pid}|42\n')
        log = (self.module / 'runtime.log').read_text()
        self.assertEqual(log.count('owned-helper-started:'), 1)
        self.assertIn('owned-helper-started:' + str(self.module / 'rear-wake.jar'), log)
        self.assertIn('verified-existing-daemon', (self.module / 'state/status.tsv').read_text())
        (self.module / 'features.disabled').write_text('rear-wake\n')
        self.run_platform('core_rear', overrides)
        self.assertIn('verified-daemon-stopped', (self.module / 'state/status.tsv').read_text())

    def test_rear_current_helper_disable_uses_the_same_verified_lifetime_lease(self):
        child = subprocess.Popen(['sleep', '30'])
        self.addCleanup(lambda: child.poll() is None and child.kill())
        self.rear_process(child.pid, current=True)
        state = self.root / 'persistent'; state.mkdir()
        (state / 'rear-daemon.record').write_text(f'1|test-boot|{child.pid}|42\n')
        (self.module / 'features.disabled').write_text('rear-wake\n')
        self.run_platform('core_rear', self.rear_hash_override())
        self.assertEqual(child.wait(timeout=2), -15)
        self.assertIn('verified-daemon-stopped', (self.module / 'state/status.tsv').read_text())


class CoreContextTests(unittest.TestCase):
    def context(self):
        return {'schema': 1, 'identity_sources': [{'path': '/system/build.prop', 'sha256': 'a' * 64}], 'rear': None}

    def test_context_is_data_and_never_part_of_the_common_module_artifact(self):
        value = self.context()
        self.assertIn('identity|/system/build.prop|' + 'a' * 64, platform.context_files(value)['image.tsv'])
        before = package_native_module.module_files()
        value['identity_sources'][0]['sha256'] = 'b' * 64
        platform.context_files(value)
        self.assertEqual(before, package_native_module.module_files())
        self.assertNotIn('serial.record', before); self.assertNotIn('image.tsv', before)

    def test_unknown_path_schema_alias_and_nonreviewed_boot_prerequisite_are_rejected(self):
        for change in ({'schema': 2}, {'identity_sources': [{'path': '/data/foreign.prop', 'sha256': 'a' * 64}]},
                       {'identity_sources': [{'path': '/system/../build.prop', 'sha256': 'a' * 64}]},
                       {'boot_services': {'files': [], 'probe': {'path': '/system/bin/foreign', 'sha256': 'a' * 64}}}):
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                platform.context_files({**self.context(), **change})

    def test_reviewed_phone_serial_hex_is_preserved_instead_of_regenerated(self):
        self.assertEqual(platform.serial_record('ABCDEF0123456789'), '1|hyperos_avd_native_compat|ABCDEF0123456789\n')
        with self.assertRaises(RuntimeError):
            platform.serial_record('unknown')

    def test_active_source_mode_check_uses_portable_octal_digits(self):
        manifest = json.loads((REPO / 'tests/fixtures/native-compat-v16-final-manifest.json').read_text())
        guard = platform.active_derivative_guard(manifest)
        body = guard.split('core_active_sealed() {', 1)[1].split('\n}', 1)[0]
        script = ('core_active_sealed() {' + body + '\n}\n'
                  'mode_bb() { printf "%s\\n" "$MODE"; }\nBB=mode_bb\n')
        script += ('while IFS="|" read -r MODE expected; do\n'
                   '  if core_active_sealed ignored; then actual=0; else actual=1; fi\n'
                   '  [ "$actual" = "$expected" ] || exit 1\ndone\n')
        cases = [(format(value, 'o'), int(bool(value & 0o022))) for value in range(0o10000)]
        cases += [('0755', 0), ('0644', 0), ('0777', 1), ('', 1), ('755x', 1), ('888', 1), ('77777', 1)]
        table = ''.join(f'{mode}|{expected}\n' for mode, expected in cases)
        result = subprocess.run(['sh', '-c', script], input=table, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('$((0$', body)


class CoreMigrationShellTests(CorePlatformShellTests):
    """Host-produced guards run against disposable Android-like directories."""
    # Only run migration-specific scenarios in this subclass.
    test_serial_persists_across_ota_and_never_replays_a_device_table = None
    test_invalid_serial_and_alias_are_preserved_without_property_changes = None
    test_disable_remove_and_pending_recheck_before_effects = None
    test_serial_new_uses_xiaomi_style_once_per_userdata = None
    test_identity_is_data_and_whitelisted_public_keys_only = None
    test_unverified_identity_source_has_no_resetprop_side_effects = None
    test_refresh_requires_actual_primary_mode_and_keeps_settings_choices = None
    test_rear_helper_does_not_start_for_tablet_or_unverified_resources = None
    test_persistent_conflict_gate_blocks_the_native_and_platform_owner = None
    test_identity_and_status_do_not_rehash_or_rewrite_unchanged_values = None
    test_boot_gate_requires_every_reviewed_image_prerequisite = None
    test_boot_catalog_is_checked_and_full_recipes_cannot_be_mixed = None
    test_boot_group_snapshot_cannot_be_replaced_between_matching_and_hashing = None
    test_rear_disable_stops_only_the_exact_adopted_process_lifetime = None
    test_rear_missing_empty_alias_dead_boot_pid_reuse_and_foreign_are_preserved = None
    test_rear_lease_serializes_start_adoption_and_cleanup = None
    test_rear_unleased_unknown_or_stale_owner_is_preserved = None
    test_rear_migration_waits_for_the_exact_legacy_owner_to_exit = None
    test_rear_runtime_recipe_rejects_unknown_code_and_extra_rows = None
    test_rear_current_helper_disable_uses_the_same_verified_lifetime_lease = None
    test_rear_cold_start_executes_only_the_verified_module_jar_and_reuses_lease = None
    test_rear_input_owned_derivative_retains_complete_boot_pin_and_feature_choices = None
    test_rear_input_derivative_rejects_foreign_mount_capability_unknown_bytes_and_wrong_scope = None
    test_rear_input_requires_exact_retained_rear_context_and_logical_id_before_boot = None

    def setUp(self):
        super().setUp()
        self.run_platform(':')
        self.registry = self.root / 'data/modules'
        self.registry.mkdir(parents=True)
        self.android_data = self.root / 'android-data'; self.android_data.mkdir()
        self.file_metadata(self.android_data, owner='1000:1000')
        self.owner = self.registry / 'hyperos_avd_native_compat'
        self.owner.mkdir()
        files = package_native_module.module_files()
        for name, body in files.items():
            target = self.owner / name; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(body)
        self.checksum = platform.digest(files['SHA256SUMS'])
        self.image = self.root / 'system/build.prop'; self.image.parent.mkdir()
        self.image.write_text('ro.product.model=Future Xiaomi\n')
        self.context = {'schema': 1, 'identity_sources': [{'path': '/system/build.prop', 'sha256': platform.digest(self.image.read_bytes())}], 'rear': None}
        self.guest_paths = {'/system/build.prop': self.image}

    def guest(self, config, command):
        command = command.replace('/data/adb/ksu/bin/busybox', str(self.bb))
        command = command.replace('/data/adb/hyperos-avd-core', str(self.root / 'persistent'))
        command = command.replace('/data/adb', str(self.root / 'data'))
        command = re.sub(r'(?<=\s)/data(?=[\s);]|$)', str(self.android_data), command)
        # Translate shell path operands, preserving quoted context bytes.
        for original, actual in self.guest_paths.items():
            command = re.sub(r'(?<=\s)' + re.escape(original) + r'(?=[\s);]|$)', str(actual), command)
        command = command.replace('HYPEROS_NATIVE_PROC=/proc', 'HYPEROS_NATIVE_PROC=' + str(self.proc))
        result = subprocess.run(['sh', '-c', 'set -e\n' + command], env=self.environment,
                                capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError('Local authenticated guard rejected unsafe state: ' + result.stderr)
        return result.stdout.strip()

    def image_derivative(self, capability='return 0', rear=False):
        """Use real chain/mount parsing with disposable content and capability."""
        self.pin_path = '/system/framework/services.jar' if rear else '/system_ext/framework/miui-services.jar'
        self.pin_file = self.root / Path(self.pin_path).name
        self.pin_file.write_bytes(b'Final authenticated framework fixture.\n')
        self.pin_before = platform.digest(b'Original immutable framework fixture.\n')
        self.pin_middle = platform.digest(b'First audited framework derivative.\n')
        self.pin_after = platform.digest(self.pin_file.read_bytes())
        self.guest_paths[self.pin_path] = self.pin_file
        self.environment['HYPEROS_NATIVE_TEST_FILES'] = json.dumps({self.pin_path: str(self.pin_file)})
        (self.owner / 'cache').mkdir(); (self.owner / 'state').mkdir()
        features = ('rear-input', 'display-brightness') if rear else ('perf-hardware', 'thermal-monitor')
        (self.owner / 'targets.tsv').write_text(''.join(
            f'early|system|{feature}|{self.pin_path}||{Path(self.pin_path).name}\n' for feature in features))
        prefix = features[0] if rear else 'uniperf'
        (self.owner / 'profiles.tsv').write_text(
            f'{self.pin_before}|{self.pin_middle}||{features[0]}|{prefix}-{self.pin_before[:12]}\n'
            f'{self.pin_middle}|{self.pin_after}||{features[1]}|{features[1]}-{self.pin_middle[:12]}\n')
        # Hardware capability is the only simulated function. The complete
        # catalog parser, canonical asset check and PID1 ownership stay real.
        with (self.owner / 'runtime.sh').open('a') as output:
            output.write('\nnative_eligible() { ' + capability + '; }\n')
        (self.proc / '1/mountinfo').write_text(
            f'40 1 253:1 {self.owner}/cache/trusted.jar {self.pin_path} ro - ext4 /dev/block/test rw\n')
        self.refresh_owner_checksums()
        return {'image.tsv': f'boot|{self.pin_path}|{self.pin_before}\n'}

    def refresh_owner_checksums(self):
        rows = (self.owner / 'SHA256SUMS').read_text().splitlines()
        data = ''.join(platform.digest((self.owner / line.split(None, 1)[1]).read_bytes()) +
                       '  ' + line.split(None, 1)[1] + '\n' for line in rows)
        (self.owner / 'SHA256SUMS').write_text(data)
        self.checksum = platform.digest(data)

    def check_image_pins(self, files):
        return self.guest({}, platform.image_guard(
            files, '/data/adb/modules/hyperos_avd_native_compat', self.checksum))

    def staged_derivative(self, capability='return 0'):
        import native_module_history as history
        files = self.image_derivative(capability)
        manifest = json.loads((self.owner / 'manifest.json').read_text())
        # Exercise complete controls on a small synthetic owner. Production
        # content has hundreds of site files; per-stat Python command doubles
        # would obscure this guard's actual staged-ownership behavior.
        retained = {'module.prop', 'runtime.sh', 'platform.sh', 'device-credential.sh',
                    'tcm-capability.sh', 'profiles.tsv', 'targets.tsv', 'catalog.json'}
        retained.add(next(name for name in manifest['files_sha256'] if name.startswith('sites/')))
        for name in set(manifest['files_sha256']) - retained:
            (self.owner / name).unlink()
        manifest['files_sha256'] = {name: manifest['files_sha256'][name] for name in retained}
        # The test host reviews the entire synthetic active package, never
        # allowing its guest manifest to authorize its own changed catalog.
        for name in manifest['files_sha256']:
            manifest['files_sha256'][name] = platform.digest((self.owner / name).read_bytes())
        (self.owner / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
        controls = {**manifest['files_sha256'],
                    'manifest.json': platform.digest((self.owner / 'manifest.json').read_bytes())}
        (self.owner / 'SHA256SUMS').write_text(''.join(checksum + '  ' + name + '\n'
                                                   for name, checksum in sorted(controls.items())))
        self.checksum = platform.digest((self.owner / 'SHA256SUMS').read_bytes())
        record = {'revision': manifest['revision'],
                  'manifest_sha256': platform.digest((self.owner / 'manifest.json').read_bytes()),
                  'checksums_sha256': self.checksum}
        reviewed = patch.object(history, 'REVIEWED', (*history.REVIEWED, record))
        reviewed.start(); self.addCleanup(reviewed.stop)
        pending = self.root / 'data/modules_update/hyperos_avd_native_compat'
        pending.mkdir(parents=True)
        stage = package_native_module.module_files()
        for name, body in stage.items():
            path = pending / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(body)
        self.pending_checksum = platform.digest(stage['SHA256SUMS'])
        return files, manifest, pending

    def check_staged_pins(self, files, manifest):
        return self.guest({}, platform.image_guard(
            files, '/data/adb/modules_update/hyperos_avd_native_compat', self.pending_checksum, manifest))

    def test_host_image_pins_reuse_authenticated_runtime_chain_without_changing_defaults(self):
        files = self.image_derivative()
        self.check_image_pins(files)
        (self.owner / 'features.disabled').write_text('perf-hardware\nthermal-monitor\n')
        self.check_image_pins(files)
        self.assertFalse((self.root / 'persistent/image.tsv').exists())
        self.assertEqual(files['image.tsv'], f'boot|{self.pin_path}|{self.pin_before}\n')
        self.assertEqual(self.pin_file.read_bytes(), b'Final authenticated framework fixture.\n')

    def test_host_staged_image_pins_keep_the_running_active_mount_owner(self):
        files, manifest, pending = self.staged_derivative()
        self.check_staged_pins(files, manifest)
        self.assertFalse((pending / 'cache').exists())
        self.assertFalse((self.root / 'persistent/image.tsv').exists())
        self.assertEqual(self.pin_file.read_bytes(), b'Final authenticated framework fixture.\n')
        with self.assertRaises(RuntimeError):
            self.guest({}, platform.module_guard('/data/adb/modules/hyperos_avd_native_compat', self.checksum))

    def test_host_staged_derivative_requires_complete_frozen_active_controls(self):
        files, manifest, pending = self.staged_derivative()
        unknown = copy.deepcopy(manifest)
        unknown['files_sha256']['catalog.json'] = '1' * 64
        with self.assertRaisesRegex(RuntimeError, 'Unreviewed active Core'):
            self.check_staged_pins(files, unknown)
        with self.assertRaisesRegex(RuntimeError, 'Core image prerequisite'):
            self.check_staged_pins(files, None)
        runtime = self.owner / 'runtime.sh'; original = runtime.read_bytes()
        marker = self.root / 'untrusted-runtime-sourced'
        runtime.write_text(original.decode() + '\ntouch ' + shlex.quote(str(marker)) + '\n')
        with self.assertRaises(RuntimeError):
            self.check_staged_pins(files, manifest)
        self.assertFalse(marker.exists())
        runtime.write_bytes(original)
        # Re-hashing a self-reported replacement does not extend frozen history.
        (self.owner / 'manifest.json').write_text(json.dumps(unknown))
        self.refresh_owner_checksums()
        with self.assertRaises(RuntimeError):
            self.check_staged_pins(files, manifest)
        self.assertFalse((pending / 'cache').exists())

    def test_host_staged_derivative_rejects_aliases_ownership_and_lifecycle_changes(self):
        files, manifest, pending = self.staged_derivative()
        runtime = self.owner / 'runtime.sh'
        alias = self.root / 'runtime-hardlink'; os.link(runtime, alias)
        with self.assertRaises(RuntimeError): self.check_staged_pins(files, manifest)
        alias.unlink()
        for path in (runtime, self.owner):
            self.file_metadata(path, owner='1000:1000')
            with self.subTest(owner=path.name), self.assertRaises(RuntimeError):
                self.check_staged_pins(files, manifest)
            self.file_metadata(path, owner='0:0')
        for owner in (self.owner, pending):
            for name in ('disable', 'remove'):
                marker = owner / name; marker.touch()
                with self.subTest(marker=marker), self.assertRaises(RuntimeError):
                    self.check_staged_pins(files, manifest)
                marker.unlink()

    def test_host_staged_derivative_requires_active_pid1_mount_and_capability(self):
        files, manifest, pending = self.staged_derivative('[ ! -e "$MODDIR/unsupported-fixture" ]')
        mountinfo = self.proc / '1/mountinfo'; original = mountinfo.read_text()
        for source in (str(pending / 'cache'), '/foreign/cache'):
            mountinfo.write_text(original.replace(str(self.owner / 'cache'), source))
            with self.subTest(source=source), self.assertRaisesRegex(RuntimeError, 'Core image prerequisite'):
                self.check_staged_pins(files, manifest)
        mountinfo.write_text(original)
        (self.owner / 'unsupported-fixture').touch()
        with self.assertRaisesRegex(RuntimeError, 'Core image prerequisite'):
            self.check_staged_pins(files, manifest)

    def test_host_staged_derivative_rejects_writable_source_files_and_ancestors(self):
        files, manifest, pending = self.staged_derivative()
        runtime = self.owner / 'runtime.sh'
        # The test's frozen code would leave a marker if the rejected source
        # were ever executed. Re-review the entire synthetic owner afterward.
        marker = self.root / 'writable-runtime-sourced'
        runtime.write_text(runtime.read_text() + '\ntouch ' + shlex.quote(str(marker)) + '\n')
        manifest['files_sha256']['runtime.sh'] = platform.digest(runtime.read_bytes())
        (self.owner / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
        self.refresh_owner_checksums()
        import native_module_history as history
        record = {'revision': manifest['revision'],
                  'manifest_sha256': platform.digest((self.owner / 'manifest.json').read_bytes()),
                  'checksums_sha256': self.checksum}
        with patch.object(history, 'REVIEWED', (*history.REVIEWED, record)):
            for path in (self.owner, self.owner.parent, self.owner.parent.parent,
                         self.owner / 'sites', runtime):
                original = path.stat().st_mode & 0o7777
                for mask in (0o020, 0o002):
                    path.chmod(original | mask)
                    with self.subTest(path=path.name, mask=oct(mask)), self.assertRaises(RuntimeError):
                        self.check_staged_pins(files, manifest)
                    self.assertFalse(marker.exists())
                    path.chmod(original)
        self.assertFalse((pending / 'cache').exists())

    def test_host_staged_original_pin_never_sources_a_derivative_owner(self):
        files, _, pending = self.staged_derivative('return 1')
        files['image.tsv'] = f'boot|{self.pin_path}|{self.pin_after}\n'
        self.check_staged_pins(files, None)
        self.assertFalse((pending / 'cache').exists())

    def test_host_configure_staged_upgrade_uses_reviewed_active_manifest(self):
        files, _, pending = self.staged_derivative()
        files['image.json'] = json.dumps(self.context, sort_keys=True, indent=2) + '\n'
        with patch.object(platform, 'context_files', return_value=files):
            result = platform.configure(self.guest, {}, self.context,
                                        '/data/adb/modules_update/hyperos_avd_native_compat', self.pending_checksum)
        self.assertEqual(result['serial']['status'], 'pending')
        self.assertEqual((self.root / 'persistent/image.tsv').read_text(), files['image.tsv'])
        self.assertFalse((pending / 'cache').exists())

    def test_host_original_image_pin_does_not_require_derivative_capability(self):
        files = self.image_derivative('return 1')
        files['image.tsv'] = f'boot|{self.pin_path}|{self.pin_after}\n'
        (self.proc / '1/mountinfo').write_text('')
        self.check_image_pins(files)

    def test_host_rear_input_and_brightness_use_the_same_audited_consumer(self):
        files = self.image_derivative(rear=True)
        self.check_image_pins(files)
        self.assertFalse((self.root / 'persistent/image.tsv').exists())

    def test_host_derivative_does_not_bypass_module_lifecycle(self):
        files = self.image_derivative()
        pending = self.root / 'data/modules_update/hyperos_avd_native_compat'
        pending.parent.mkdir()
        for marker in (self.owner / 'disable', self.owner / 'remove', pending):
            with self.subTest(marker=marker.name):
                marker.touch()
                with self.assertRaises(RuntimeError):
                    self.check_image_pins(files)
                marker.unlink()

    def test_host_derivative_rejects_foreign_mount_namespace_and_missing_capability(self):
        files = self.image_derivative('[ ! -e "$MODDIR/unsupported-fixture" ]')
        mountinfo = self.proc / '1/mountinfo'; original_mount = mountinfo.read_text()
        foreign = self.root / 'foreign.jar'; foreign.write_text('Unowned namespace content\n')
        for mode in ('foreign-mount', 'wrong-namespace', 'capability'):
            with self.subTest(mode=mode):
                if mode == 'foreign-mount':
                    mountinfo.write_text(original_mount.replace(str(self.owner / 'cache'), '/foreign/cache'))
                elif mode == 'wrong-namespace':
                    self.environment['HYPEROS_NATIVE_TEST_FILES'] = json.dumps({self.pin_path: str(foreign)})
                else:
                    (self.owner / 'unsupported-fixture').touch()
                with self.assertRaisesRegex(RuntimeError, 'Core image prerequisite.*miui-services.jar'):
                    self.check_image_pins(files)
                mountinfo.write_text(original_mount)
                self.environment['HYPEROS_NATIVE_TEST_FILES'] = json.dumps({self.pin_path: str(self.pin_file)})
                (self.owner / 'unsupported-fixture').unlink(missing_ok=True)

    def test_host_unknown_bytes_aliases_and_nonboot_derivatives_are_preserved(self):
        files = self.image_derivative()
        original = self.pin_file.read_bytes()
        for mode in ('unknown', 'alias', 'identity', 'rear'):
            with self.subTest(mode=mode):
                current = files.copy()
                if mode == 'unknown':
                    self.pin_file.write_text('Unknown customized framework\n')
                elif mode == 'alias':
                    target = self.root / 'aliased.jar'; target.write_bytes(original)
                    self.pin_file.unlink(); self.pin_file.symlink_to(target)
                else:
                    current['image.tsv'] = current['image.tsv'].replace('boot|', mode + '|')
                with self.assertRaisesRegex(RuntimeError, 'Core image prerequisite.*miui-services.jar'):
                    self.check_image_pins(current)
                if self.pin_file.is_symlink():
                    self.pin_file.unlink()
                self.pin_file.write_bytes(original)

    def test_host_derivative_rejects_wrong_scope_ambiguous_chain_and_tampered_controls(self):
        files = self.image_derivative()
        targets, profiles = self.owner / 'targets.tsv', self.owner / 'profiles.tsv'
        original_targets, original_profiles = targets.read_text(), profiles.read_text()
        for mode in ('late', 'foreign-target', 'ambiguous', 'tampered-runtime'):
            with self.subTest(mode=mode):
                if mode == 'late':
                    targets.write_text(original_targets.replace('early|', 'late|'))
                elif mode == 'foreign-target':
                    targets.write_text(original_targets.replace('thermal-monitor|', 'unreviewed|'))
                elif mode == 'ambiguous':
                    profiles.write_text(original_profiles + original_profiles.splitlines(True)[0])
                else:
                    with (self.owner / 'runtime.sh').open('a') as output:
                        output.write('\n# Unauthenticated local customization\n')
                if mode != 'tampered-runtime':
                    self.refresh_owner_checksums()
                with self.assertRaises(RuntimeError):
                    self.check_image_pins(files)
                targets.write_text(original_targets); profiles.write_text(original_profiles)
                self.refresh_owner_checksums()

    def test_host_derivative_rejects_current_inode_replacement_during_capability_check(self):
        replacement = self.root / 'replacement.jar'
        files = self.image_derivative(
            'if [ -f ' + shlex.quote(str(replacement)) + ' ]; then mv ' +
            shlex.quote(str(replacement)) + ' ' + shlex.quote(str(self.root / 'miui-services.jar')) + '; fi; return 0')
        replacement.write_bytes(self.pin_file.read_bytes())
        original_inode = self.pin_file.stat().st_ino
        with self.assertRaisesRegex(RuntimeError, 'Core image prerequisite.*miui-services.jar'):
            self.check_image_pins(files)
        self.assertNotEqual(self.pin_file.stat().st_ino, original_inode)

    def navigation(self):
        import apply_navigation_fix as nav
        from phone_profile import profile
        selected = profile('4.0.18.0.XFRCNXM'); serial = '69704/F5XA01467'
        identity = dict(selected['properties'], **{key: serial for key in ('ro.serialno', 'ro.boot.serialno', 'ro.ril.oem.psno')})
        manifest = {'revision': nav.REVISION, 'hyperos': selected['hyperos'], 'incremental': selected['incremental'],
                    'property': nav.PROPERTY, 'value': 'com.miui.home', 'component': nav.COMPONENT,
                    'animation_backend': 'stock-sf', 'sf_animation': True, 'phone_identity': identity,
                    'serial_number': serial}
        directory = self.registry / 'hyperos_avd_navigation'; directory.mkdir()
        data = {'manifest.json': json.dumps(manifest, indent=2) + '\n',
                'identity.prop': ''.join(key + '=' + value + '\n' for key, value in identity.items()),
                'system.prop': 'ro.miui.product.home=com.miui.home\npersist.miui.home_sf_anim=true\n',
                'module.prop': f'id=hyperos_avd_navigation\nname=HyperOS AVD native Quickstep\nversion={nav.REVISION}\nversionCode={nav.REVISION}\nauthor=HyperOS-AVD\ndescription=Original phone and launcher identity, persistent Xiaomi-style simulated serial and stock SF transitions\n',
                'post-fs-data.sh': nav.startup_script(nav.EARLY_SCRIPT, selected),
                'service.sh': nav.startup_script(nav.BOOT_SCRIPT, selected)}
        for name, value in data.items():
            (directory / name).write_text(value)
        return directory

    def test_known_navigation_is_retired_without_uninstall_or_payload_rewrites(self):
        directory = self.navigation()
        inode = (directory / 'identity.prop').stat().st_ino
        result = platform.configure(self.guest, {}, self.context, '/data/adb/modules/hyperos_avd_native_compat', self.checksum)
        self.assertEqual(result['serial']['serial_number'], '69704/F5XA01467')
        self.assertEqual(result['blocked_features'], [])
        self.assertFalse(directory.exists())
        archive = next((self.root / 'persistent/retired').glob('hyperos_avd_navigation-*'))
        self.assertEqual((archive / 'identity.prop').stat().st_ino, inode)
        self.assertEqual((self.root / 'persistent/serial.record').read_text(), platform.serial_record('69704/F5XA01467'))
        self.assertEqual((self.root / 'persistent/legacy-blocked.features').read_text(), '')

    def test_android_data_system_owner_is_allowed_but_managed_children_require_root(self):
        directory = self.navigation()
        # /data uid1000 is the Android contract, not an untrusted Core owner.
        self.guest({}, platform.module_guard('/data/adb/modules/hyperos_avd_native_compat', self.checksum)
                   + platform.parent_guard(platform.STATE))
        for path, owner in ((self.android_data, '1001:1001'), (self.root / 'data', '1000:1000')):
            self.file_metadata(path, owner=owner)
            with self.assertRaises(RuntimeError):
                platform.configure(self.guest, {}, self.context, '/data/adb/modules/hyperos_avd_native_compat', self.checksum)
            self.assertTrue(directory.exists())
            self.file_metadata(path, owner='1000:1000' if path == self.android_data else '0:0')

    def test_custom_hook_disable_remove_and_pending_are_preserved(self):
        directory = self.navigation()
        for mode in ('custom', 'disable', 'remove', 'pending'):
            with self.subTest(mode=mode):
                hook = directory / 'service.sh'; original = hook.read_bytes()
                if mode == 'custom': hook.write_bytes(original + b'\n# Local customization\n')
                elif mode == 'pending':
                    marker = self.root / 'data/modules_update/hyperos_avd_navigation'; marker.parent.mkdir(exist_ok=True); marker.mkdir()
                else:
                    marker = directory / mode; marker.symlink_to(self.root / 'missing')
                result = platform.configure(self.guest, {}, self.context, '/data/adb/modules/hyperos_avd_native_compat', self.checksum)
                self.assertTrue(directory.is_dir())
                self.assertIn('navigation', result['blocked_features'])
                if mode == 'custom': hook.write_bytes(original)
                elif mode == 'pending': marker.rmdir()
                else: self.assertTrue(marker.is_symlink()); marker.unlink()

    def test_unverified_core_or_image_cannot_retire_a_legacy_owner(self):
        directory = self.navigation()
        self.image.write_text('Changed outside reviewed image\n')
        with self.assertRaises(RuntimeError):
            platform.configure(self.guest, {}, self.context, '/data/adb/modules/hyperos_avd_native_compat', self.checksum)
        self.assertTrue(directory.is_dir()); self.assertFalse((self.root / 'persistent/image.tsv').exists())
        self.image.write_text('ro.product.model=Future Xiaomi\n')
        (self.owner / 'platform.sh').write_text('# Local change\n')
        with self.assertRaises(RuntimeError):
            platform.configure(self.guest, {}, self.context, '/data/adb/modules/hyperos_avd_native_compat', self.checksum)
        self.assertTrue(directory.is_dir())

    def test_unknown_directory_or_hard_link_is_preserved(self):
        directory = self.navigation(); (directory / 'foreign').mkdir()
        items = legacy.inspect_legacy(self.guest, {}, self.context)
        self.assertEqual(items[0]['status'], 'preserved')
        (directory / 'foreign').rmdir()
        os.link(directory / 'service.sh', self.root / 'foreign-hook')
        items = legacy.inspect_legacy(self.guest, {}, self.context)
        self.assertEqual(items[0]['status'], 'preserved')

    def test_global_refresh_is_archived_only_after_exact_owner_and_pin_verification(self):
        from os4_defaults import REFRESH_WRAPPER
        path = self.root / 'data/service.d/hyperos-avd-lock-fps.sh'; path.parent.mkdir(); path.write_bytes(REFRESH_WRAPPER)
        result = platform.configure(self.guest, {}, self.context, '/data/adb/modules/hyperos_avd_native_compat', self.checksum)
        self.assertFalse(path.exists())
        self.assertEqual(result['global_hooks'][0]['status'], 'retired')
        self.assertTrue(next((self.root / 'persistent/retired').glob('hyperos-avd-lock-fps.sh-*')).is_file())

    def test_unknown_platform_state_is_preserved_and_exact_partial_publication_recovers(self):
        directory = self.navigation()
        state = self.root / 'persistent'
        (state / 'image.json').write_text('{"schema": 99}\n')
        with self.assertRaisesRegex(RuntimeError, 'preserved'):
            platform.configure(self.guest, {}, self.context, '/data/adb/modules/hyperos_avd_native_compat', self.checksum)
        self.assertTrue(directory.is_dir()); self.assertEqual((state / 'image.json').read_text(), '{"schema": 99}\n')
        (state / 'image.json').unlink()
        (state / 'image.tsv').write_text(platform.context_files(self.context)['image.tsv'])
        result = platform.configure(self.guest, {}, self.context, '/data/adb/modules/hyperos_avd_native_compat', self.checksum)
        self.assertEqual(result['blocked_features'], [])
        self.assertFalse(directory.exists())
        self.assertEqual(json.loads((state / 'image.json').read_text()), self.context)


if __name__ == '__main__':
    unittest.main()
