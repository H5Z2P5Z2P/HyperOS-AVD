"""Consolidated unit tests for OS4 Pad subsystem:
tablet profile, build defaults, identity sources, settings RRO, and release packaging.
"""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch, patch as mock_patch
import zipfile

REPO = Path(__file__).resolve().parents[1]
ROOT = REPO
sys.path.insert(0, str(REPO / 'scripts'))

from build_os4_pad import identity_values, settings_replacements, verify_identity_sources
import dex2oat_cpu_policy as cpu
from os4_defaults import LOG_SCRIPT, OVERLAY, SCREEN_TIMEOUT
import os4_pad
from os4_pad import PROFILE, SOURCE
import package_release
from patch_assistant import profile as manifest
import patch_flutter
from patch_flutter import PROFILES
import patch_init_capabilities as gates
from patch_pad_hwui import BEFORE, AFTER
import prepare_release_image
import release_pad



# --- tests/test_os4_pad.py ---

'Guard the tablet identity, defaults and audited native engine profile.'

class TabletProfileTests(unittest.TestCase):

    def test_unverifiable_finddevice_still_initializes_pad_sensor_display_and_serial_defaults(self):
        import common
        import os4_defaults
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            (folder / 'local').mkdir()
            (folder / 'local/build.json').write_text(json.dumps({'source': os4_pad.SOURCE, 'device': os4_pad.PROFILE['device']}))
            commands = []

            def root(config, command):
                commands.append(command)
                return ''
            with mock_patch.object(common, 'ROOT', folder), mock_patch('apply_flutter_fix.official'), mock_patch('apply_flutter_fix.root', side_effect=root), mock_patch('common.adb') as device, mock_patch.object(os4_defaults, 'apply_thermal_runtime'), mock_patch.object(os4_defaults, 'apply_refresh_runtime') as refresh, mock_patch.object(os4_defaults, 'apply_finddevice_workaround', return_value='skipped') as finddevice, mock_patch.object(os4_pad, 'apply_serial') as serial:
                os4_pad.apply_runtime({'name': 'Renamed-pad'})
            finddevice.assert_called_once_with({'name': 'Renamed-pad'}, os4_pad.FINDDEVICE_SHA256)
            for arguments in (('emu', 'sensor', 'set', 'proximity', '5'), ('emu', 'sensor', 'set', 'light', '200'), ('emu', 'power', 'ac', 'on')):
                self.assertTrue(any((call.args[1:] == arguments for call in device.call_args_list)))
            self.assertIn(os4_pad.display_settings_script(), commands)
            refresh.assert_called_once()
            serial.assert_called_once()
            self.assertFalse(any((call.args[1] in ('pull', 'push') for call in device.call_args_list)))
            for command in commands:
                for forbidden in ('libhwui.so', 'mount -o bind', 'umount', 'debug.hwui.renderer', 'ro.zygote.disable_gl_preload'):
                    self.assertNotIn(forbidden, command)

    def test_thermal_profile_hook_has_no_independent_hwui_activation(self):
        script = os4_pad.thermal_profile_script()
        subprocess.run(['sh', '-n'], input=script, text=True, check=True)
        self.assertIn('sysfs_thermal', script)
        self.assertIn('key=ro.product.device\nvalue=yingtian', script)
        for forbidden in ('libhwui.so', 'nsenter', 'mount ', 'umount', 'debug.hwui.renderer', 'ro.zygote.disable_gl_preload', '/data/adb/modules/', 'disable', 'remove'):
            self.assertNotIn(forbidden, script)
        self.assertEqual(os4_pad.properties(b'').count(b'debug.hwui.renderer=skiavk'), 1)

    def test_thermal_hook_migration_preserves_unknown_and_aliased_hooks(self):
        for inspection in ('unknown', 'owned:' + '0' * 64, 'owned:', 'unexpected'):
            with self.subTest(inspection=inspection), mock_patch('apply_flutter_fix.root', return_value=inspection) as root, mock_patch('builtins.print') as diagnostic:
                result = os4_pad.apply_thermal_profile({'name': 'Renamed-pad'})
                self.assertEqual(result, {'status': 'skipped', 'reason': 'unknown-startup-hook'})
                self.assertEqual(root.call_count, 1)
                command = root.call_args.args[1]
                self.assertIn('[ ! -L "$parent" ]', command)
                self.assertIn('stat -c %h', command)
                self.assertNotIn('mv -f', command)
                diagnostic.assert_called_once()

    def test_thermal_hook_migration_authenticates_and_atomically_replaces_legacy(self):
        old = os4_pad.LEGACY_THERMAL_HWUI_SHA256
        with mock_patch('apply_flutter_fix.root', side_effect=['owned:' + old, '', '']) as root:
            result = os4_pad.apply_thermal_profile({'name': 'Renamed-pad'})
        self.assertEqual(result, {'status': 'ready', 'migrated': True})
        self.assertEqual(root.call_count, 3)
        write, execute = (call.args[1] for call in root.call_args_list[1:])
        self.assertEqual(write.count('= ' + old), 2)
        self.assertIn('mv -f', write)
        self.assertIn('.stage-', write)
        self.assertIn('sh -n', write)
        self.assertIn('sha256sum', execute)
        for command in (write, execute):
            subprocess.run(['sh', '-n'], input=command, text=True, check=True)
            for forbidden in ('libhwui.so', 'mount -o bind', 'umount', 'debug.hwui.renderer', 'ro.zygote.disable_gl_preload'):
                self.assertNotIn(forbidden, command)

    def test_thermal_migration_keeps_loaded_payload_and_native_lifecycle_choices(self):
        with tempfile.TemporaryDirectory() as temporary:
            guest = Path(temporary)
            adb = guest / 'data/adb'
            (adb / 'post-fs-data.d').mkdir(parents=True)
            busybox = adb / 'ksu/bin/busybox'
            busybox.parent.mkdir(parents=True)
            busybox.write_text("#!/usr/bin/env python3\nimport hashlib, os, subprocess, sys\nargs = sys.argv[1:]\nif args[0] == 'sha256sum':\n    print(hashlib.sha256(open(args[1], 'rb').read()).hexdigest() + '  ' + args[1])\nelif args[:3] == ['stat', '-c', '%h']:\n    print(os.stat(args[3]).st_nlink)\nelif args[0] == 'cut':\n    raise SystemExit(subprocess.call(['/usr/bin/cut', *args[1:]]))\nelse:\n    raise SystemExit(1)\n")
            busybox.chmod(493)
            hook = guest / os4_pad.THERMAL_EARLY.lstrip('/')
            hook.write_bytes(b'known legacy hook\n')
            legacy_hash = hashlib.sha256(hook.read_bytes()).hexdigest()
            payload = adb / 'hyperos-avd-pad/libhwui.so'
            payload.parent.mkdir()
            payload.write_bytes(b'loaded payload inode must stay intact')
            payload_identity = (payload.stat().st_ino, payload.read_bytes())
            module = adb / 'modules/hyperos_avd_native_compat'
            module.mkdir(parents=True)
            for flag in ('disable', 'remove'):
                (module / flag).touch()
            generated = '#!/bin/sh\nprintf ready > ' + str(guest / 'profile-ready') + '\n'

            def root(config, command):
                command = command.replace('/data/', str(guest / 'data') + '/')
                return subprocess.run(['sh', '-c', command], capture_output=True, text=True, check=True).stdout.strip()
            with mock_patch('apply_flutter_fix.root', side_effect=root), mock_patch.object(os4_pad, 'thermal_profile_script', return_value=generated), mock_patch.object(os4_pad, 'LEGACY_THERMAL_HWUI_SHA256', legacy_hash):
                self.assertTrue(os4_pad.apply_thermal_profile({})['migrated'])
                self.assertFalse(os4_pad.apply_thermal_profile({})['migrated'])
            self.assertEqual(hook.read_text(), generated)
            self.assertEqual((guest / 'profile-ready').read_text(), 'ready')
            self.assertEqual((payload.stat().st_ino, payload.read_bytes()), payload_identity)
            self.assertEqual({path.name for path in module.iterdir()}, {'disable', 'remove'})
            self.assertFalse(list(hook.parent.glob('*.stage-*')))

    def test_thermal_hook_aliases_are_preserved_by_real_inspection(self):
        with tempfile.TemporaryDirectory() as temporary:
            guest = Path(temporary)
            directory = guest / 'data/adb/post-fs-data.d'
            directory.mkdir(parents=True)
            busybox = guest / 'data/adb/ksu/bin/busybox'
            busybox.parent.mkdir(parents=True)
            busybox.write_text('#!/bin/sh\nexit 0\n')
            busybox.chmod(493)
            target = guest / 'external-hook'
            target.write_text('custom hook')
            hook = directory / Path(os4_pad.THERMAL_EARLY).name
            hook.symlink_to(target)

            def root(config, command):
                command = command.replace('/data/', str(guest / 'data') + '/')
                return subprocess.run(['sh', '-c', command], capture_output=True, text=True, check=True).stdout.strip()
            with mock_patch('apply_flutter_fix.root', side_effect=root), mock_patch('builtins.print'):
                self.assertEqual(os4_pad.apply_thermal_profile({})['status'], 'skipped')
            self.assertTrue(hook.is_symlink())
            self.assertEqual(target.read_text(), 'custom hook')
            hook.unlink()
            directory.rmdir()
            external = guest / 'external-directory'
            external.mkdir()
            directory.symlink_to(external, target_is_directory=True)
            with mock_patch('apply_flutter_fix.root', side_effect=root), mock_patch('builtins.print'):
                self.assertEqual(os4_pad.apply_thermal_profile({})['status'], 'skipped')
            self.assertTrue(directory.is_symlink())
            self.assertEqual(list(external.iterdir()), [])

    def test_public_identity_script_preserves_hal_selectors_and_serial(self):
        script = os4_pad.profile_properties_script()
        subprocess.run(['sh', '-n'], input=script, text=True, check=True)
        self.assertIn('key=ro.product.device\nvalue=yingtian', script)
        self.assertIn('key=log.tag.RenderEngine\nvalue=S', script)
        for key in ('ro.board.platform', 'ro.hardware.egl', 'ro.boot.hardware', 'ro.vendor.api_level', 'ro.serialno', 'ro.ril.oem.psno'):
            with mock_patch.object(os4_pad, 'PROFILE', dict(os4_pad.PROFILE, properties={key: 'unsafe'})):
                with self.assertRaisesRegex(RuntimeError, 'Unsupported tablet public'):
                    os4_pad.profile_properties_script()

    def test_serial_manifest_preserves_identifier_and_refuses_other_profiles(self):
        serial = '69704/F6X601467'
        with mock_patch('apply_navigation_fix.simulated_serial', return_value=serial):
            state = os4_pad.serial_manifest()
        self.assertEqual(state['source'], os4_pad.SOURCE)
        self.assertEqual(os4_pad.serial_manifest(state), state)
        for field, value in (('source', 'official-hongkong-ota'), ('revision', 2), ('hyperos', 'OS4.0.17.0.XFRCNXM'), ('serial_number', 'unknown')):
            with self.assertRaises(RuntimeError):
                os4_pad.serial_manifest(dict(state, **{field: value}))
        with self.assertRaises(RuntimeError):
            os4_pad.serial_manifest(dict(state, unrelated=True))

    def test_serial_manifest_survives_forward_same_device_firmware(self):
        state = {'revision': 1, 'source': os4_pad.SOURCE, 'hyperos': 'OS4.0.15.0.XBMCNXM', 'serial_number': '69704/F6X601467'}
        updated = dict(os4_pad.PROFILE, hyperos='OS4.0.16.0.XBMCNXM')
        with mock_patch.object(os4_pad, 'PROFILE', updated):
            self.assertEqual(os4_pad.serial_manifest(state), state)
            self.assertIn(updated['hyperos'], os4_pad.serial_script(state))
            for firmware in ('OS4.0.17.0.XBMCNXM', 'OS4.0.15.0.XFRCNXM', 'OS3.0.15.0.XBMCNXM', 'unknown', None):
                with self.subTest(firmware=firmware), self.assertRaises(RuntimeError):
                    os4_pad.serial_manifest(dict(state, hyperos=firmware))
        for changed in ({**state, 'extra': True}, {**state, 'revision': 2}, {**state, 'source': 'official-hongkong-ota'}, {**state, 'serial_number': 'unknown'}):
            with self.subTest(state=changed), self.assertRaises(RuntimeError):
                os4_pad.serial_manifest(changed)

    def test_serial_early_script_changes_only_identifier_fields(self):
        state = {'revision': 1, 'source': os4_pad.SOURCE, 'hyperos': os4_pad.PROFILE['hyperos'], 'serial_number': '69704/F6X601467'}
        script = os4_pad.serial_script(state)
        self.assertIn('getprop ro.product.device', script)
        self.assertIn('yingtian', script)
        self.assertIn(os4_pad.PROFILE['hyperos'], script)
        self.assertEqual([line.strip().split()[2] for line in script.splitlines() if line.strip().startswith('"$RESETPROP" -n')], ['ro.serialno', 'ro.boot.serialno', 'ro.ril.oem.psno'])
        self.assertNotIn('hongkong', script)
        self.assertNotIn(os4_pad.NAME, script)
        self.assertNotIn('5582', script)
        subprocess.run(['sh', '-n'], input=script, text=True, check=True)

    def test_serial_wrong_live_device_is_rejected_before_writes(self):
        with mock_patch('apply_flutter_fix.official'), mock_patch('apply_flutter_fix.root', side_effect=['ranchu', 'hongkong']) as root:
            with self.assertRaisesRegex(RuntimeError, 'different device'):
                os4_pad.apply_serial({'name': 'Renamed Pad', 'port': 6000})
        self.assertEqual(root.call_count, 2)
        self.assertTrue(all((call.args[1].startswith('getprop ') for call in root.call_args_list)))

    def test_serial_restart_keeps_saved_identity_without_rewriting(self):
        state = {'revision': 1, 'source': os4_pad.SOURCE, 'hyperos': os4_pad.PROFILE['hyperos'], 'serial_number': '69704/F6X601467'}
        responses = ['ranchu', 'yingtian', state['hyperos'], json.dumps(state), os4_pad.serial_script(state).strip(), '', *[state['serial_number']] * 3]
        config = {'name': 'Renamed Pad', 'port': 6000}
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            (folder / 'local').mkdir()
            with mock_patch('common.ROOT', folder), mock_patch('apply_flutter_fix.official') as official, mock_patch('apply_flutter_fix.root', side_effect=responses) as root:
                self.assertEqual(os4_pad.apply_serial(config), state)
            official.assert_called_once_with(config, sources=(os4_pad.SOURCE,))
            self.assertFalse(any(('mv -f' in call.args[1] for call in root.call_args_list)))
            self.assertEqual(json.loads((folder / 'local/pad-serial.json').read_text()), state)

    def test_serial_upgrade_migrates_only_a_verified_owned_early_script(self):
        state = {'revision': 1, 'source': os4_pad.SOURCE, 'hyperos': 'OS4.0.15.0.XBMCNXM', 'serial_number': '69704/F6X601467'}
        old_script = os4_pad.serial_script(state).strip()
        updated = dict(os4_pad.PROFILE, hyperos='OS4.0.17.0.XBMCNXM')
        for saved in (old_script, old_script.replace('OS4.0.15.0.', 'OS4.0.16.0.')):
            responses = ['ranchu', 'yingtian', updated['hyperos'], json.dumps(state), saved, '', '', *[state['serial_number']] * 3]
            with self.subTest(script=saved), tempfile.TemporaryDirectory() as temporary:
                folder = Path(temporary)
                (folder / 'local').mkdir()
                with mock_patch.object(os4_pad, 'PROFILE', updated), mock_patch('common.ROOT', folder), mock_patch('apply_flutter_fix.official'), mock_patch('apply_flutter_fix.root', side_effect=responses) as root:
                    self.assertEqual(os4_pad.apply_serial({'name': 'Renamed Pad', 'port': 6000}), state)
                writes = root.call_args_list[5].args[1]
                self.assertIn(updated['hyperos'], writes)
                self.assertIn('mv -f ' + os4_pad.SERIAL_EARLY, writes)
                self.assertNotIn('mv -f ' + os4_pad.SERIAL_FILE, writes)
                self.assertEqual(json.loads((folder / 'local/pad-serial.json').read_text()), state)

    def test_serial_upgrade_rejects_changed_payloads_before_writing(self):
        state = {'revision': 1, 'source': os4_pad.SOURCE, 'hyperos': 'OS4.0.15.0.XBMCNXM', 'serial_number': '69704/F6X601467'}
        old_script = os4_pad.serial_script(state).strip()
        updated = dict(os4_pad.PROFILE, hyperos='OS4.0.16.0.XBMCNXM')
        for saved in (old_script + '\n# unrelated', old_script.replace('getprop ro.product.device', 'getprop ro.product.model'), old_script.replace('OS4.0.15.0.XBMCNXM', 'OS4.0.15.0.XFRCNXM'), old_script.replace('OS4.0.15.0.XBMCNXM', 'OS4.0.17.0.XBMCNXM')):
            responses = ['ranchu', 'yingtian', updated['hyperos'], json.dumps(state), saved]
            with self.subTest(script=saved), mock_patch.object(os4_pad, 'PROFILE', updated), mock_patch('apply_flutter_fix.official'), mock_patch('apply_flutter_fix.root', side_effect=responses) as root:
                with self.assertRaisesRegex(RuntimeError, 'Unknown tablet serial startup'):
                    os4_pad.apply_serial({'name': 'Renamed Pad', 'port': 6000})
                self.assertEqual(root.call_count, 5)

    def test_serial_first_install_stages_and_validates_before_use(self):
        serial = '69704/F6X601467'
        responses = ['ranchu', 'yingtian', os4_pad.PROFILE['hyperos'], '', '', '', '', serial, serial, serial]
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            (folder / 'local').mkdir()
            with mock_patch('common.ROOT', folder), mock_patch('apply_flutter_fix.official'), mock_patch('apply_navigation_fix.simulated_serial', return_value=serial), mock_patch('apply_flutter_fix.root', side_effect=responses) as root:
                state = os4_pad.apply_serial({'name': 'Renamed Pad', 'port': 6000})
            writes = root.call_args_list[5].args[1]
            self.assertIn('trap ', writes)
            self.assertIn('sh -n ', writes)
            self.assertIn('chmod 600 ', writes)
            self.assertIn('chmod 700 ', writes)
            self.assertIn('.stage-', writes)
            self.assertEqual(state['serial_number'], serial)

    def test_serial_refuses_unrelated_early_script_without_writes(self):
        state = {'revision': 1, 'source': os4_pad.SOURCE, 'hyperos': os4_pad.PROFILE['hyperos'], 'serial_number': '69704/F6X601467'}
        responses = ['ranchu', 'yingtian', state['hyperos'], json.dumps(state), '# unrelated']
        with mock_patch('apply_flutter_fix.official'), mock_patch('apply_flutter_fix.root', side_effect=responses) as root:
            with self.assertRaisesRegex(RuntimeError, 'Unknown tablet serial startup'):
                os4_pad.apply_serial({'name': 'Renamed Pad', 'port': 6000})
        self.assertEqual(root.call_count, 5)

    def test_display_defaults_seed_color_once_and_keep_screen_awake(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            with mock_patch.object(os4_pad, 'COLOR_STAMP', str(folder / 'color-stamp')), mock_patch.object(os4_pad, 'DEFAULTS_STAMP', str(folder / 'settings-stamp')), mock_patch('os4_defaults.AWAKE_STAMP', str(folder / 'awake-stamp')):
                script = os4_pad.display_settings_script()
            mock = 'settings() { printf "settings %s\\n" "$*"; }; setprop() { :; }; input() { :; };\n'
            first = subprocess.run(['sh'], input=mock + script, text=True, check=True, capture_output=True).stdout
            second = subprocess.run(['sh'], input=mock + script, text=True, check=True, capture_output=True).stdout
            self.assertIn('settings put secure sleep_timeout -1', first)
            self.assertIn('settings put system screen_off_timeout 2147483647', first)
            self.assertIn('settings put system display_color_mode 0', first)
            self.assertIn('settings put global development_settings_enabled 1', first)
            self.assertEqual(second, '')

    def test_legacy_defaults_markers_preserve_existing_user_choices(self):
        for previous in ('color-stamp', 'awake-stamp'):
            with self.subTest(previous=previous), tempfile.TemporaryDirectory() as temporary:
                folder = Path(temporary)
                (folder / previous).touch()
                with mock_patch.object(os4_pad, 'COLOR_STAMP', str(folder / 'color-stamp')), mock_patch.object(os4_pad, 'DEFAULTS_STAMP', str(folder / 'settings-stamp')), mock_patch('os4_defaults.AWAKE_STAMP', str(folder / 'awake-stamp')):
                    script = os4_pad.display_settings_script()
                mock = 'settings() { printf "settings %s\\n" "$*"; }; setprop() { :; }; input() { :; };\n'
                output = subprocess.run(['sh'], input=mock + script, text=True, check=True, capture_output=True).stdout
                for setting in ('screen_off_timeout', 'sleep_timeout', 'stay_on_while_plugged_in', 'development_settings_enabled'):
                    self.assertNotIn(setting, output)
                self.assertEqual('display_color_mode' in output, previous == 'awake-stamp')
                self.assertTrue((folder / 'settings-stamp').is_file())

    def test_failed_default_write_does_not_mark_settings_initialized(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            with mock_patch.object(os4_pad, 'COLOR_STAMP', str(folder / 'color-stamp')), mock_patch.object(os4_pad, 'DEFAULTS_STAMP', str(folder / 'settings-stamp')), mock_patch('os4_defaults.AWAKE_STAMP', str(folder / 'awake-stamp')):
                script = os4_pad.display_settings_script()
            result = subprocess.run(['sh'], input='settings() { return 1; };\n' + script, text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((folder / 'settings-stamp').exists())
            self.assertFalse((folder / 'color-stamp').exists())

    def test_real_tablet_profile_is_separate_from_phone(self):
        self.assertEqual(os4_pad.PROFILE['device'], 'yingtian')
        self.assertEqual(os4_pad.PROFILE['properties']['ro.product.model'], 'M367FC')
        self.assertEqual(os4_pad.PROFILE['properties']['ro.build.characteristics'], 'tablet')
        self.assertEqual(hashlib.sha256(os4_pad.model_config()).hexdigest(), os4_pad.PROFILE['model_xml_sha256'])
        self.assertIn(b'<bool name="is_pad">true</bool>', os4_pad.model_config())
        self.assertIn(b'<bool name="support_aod">false</bool>', os4_pad.model_config())

    def test_template_uses_source_display_and_no_modem(self):
        values = dict((line.split('=', 1) for line in os4_pad.template('').splitlines()))
        self.assertEqual((values['hw.lcd.width'], values['hw.lcd.height'], values['hw.lcd.density']), ('2272', '3408', '400'))
        self.assertEqual(values['hw.initialOrientation'], 'portrait')
        self.assertEqual(values['hw.audioOutput'], 'yes')
        self.assertEqual(values['hw.gsmModem'], 'no')
        self.assertEqual(values['hw.ramSize'], '4096')

    def test_identity_does_not_replace_hardware_selector(self):
        original = b'ro.boot.hardware=ranchu\nro.hardware.egl=emulation\nro.debuggable=0\n'
        result = os4_pad.properties(original)
        self.assertIn(b'ro.boot.hardware=ranchu\n', result)
        self.assertIn(b'ro.hardware.egl=emulation\n', result)
        self.assertIn(b'ro.product.device=yingtian\n', result)
        self.assertNotIn(b'hongkong', result)
        from os4_defaults import LOG_TAGS
        for tag in LOG_TAGS:
            self.assertIn(('log.tag.' + tag + '=S\n').encode(), result)

    def test_refresh_override_keeps_the_tablet_version_guard(self):
        from os4_defaults import REFRESH_WRAPPER
        data = os4_pad.refresh_script(REFRESH_WRAPPER)
        self.assertIn(b'OS4.0.15.0.XBMCNXM', data)
        self.assertNotIn(b'OS4.0.17.0.XFRCNXM', data)
        self.assertIn(b'[ "$(getprop ro.boot.hardware)" = ranchu ]', data)

    def test_phone_runtime_patches_refuse_tablet_before_adb(self):
        import apply_flutter_fix
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'local').mkdir()
            (root / 'local/build.json').write_text(json.dumps({'source': os4_pad.SOURCE}))
            with mock_patch.object(apply_flutter_fix, 'ROOT', root), mock_patch.object(apply_flutter_fix, 'adb') as adb:
                with self.assertRaisesRegex(RuntimeError, 'firmware profile'):
                    apply_flutter_fix.official({'name': os4_pad.NAME, 'port': os4_pad.PORT})
                adb.assert_not_called()

    def test_real_tablet_engine_when_available(self):
        source = Path(__file__).resolve().parents[1] / 'work/os4-pad/work/source-audit/flutter.so'
        if not source.is_file():
            self.skipTest('Proprietary OTA engine is not distributed in Git.')
        data = source.read_bytes()
        fixed = patch_flutter.patch(data)
        self.assertEqual(patch_flutter.patch(fixed), fixed)
        self.assertEqual(len(fixed), len(data))
        self.assertEqual(struct.unpack_from('<2f', data, 1193856), (0.0, 1.0))
        self.assertEqual(struct.unpack_from('<2f', data, 1193872), (1.0, 0.0))
        for offset in (11287992, 11289420):
            instruction = struct.unpack_from('<I', fixed, offset)[0]
            delta = instruction & 67108863
            if delta & 33554432:
                delta -= 67108864
            self.assertEqual(offset + delta * 4, 6372520)
        allowed = bytearray(len(data))
        _, profile = patch_flutter.profile(data)
        for offset, before, _ in profile['sites']:
            allowed[offset:offset + len(bytes.fromhex(before))] = bytes([1]) * len(bytes.fromhex(before))
        self.assertFalse(any((a != b and (not ok) for a, b, ok in zip(data, fixed, allowed))))

if __name__ == '__main__':
    unittest.main()


# --- tests/test_pad_builder_defaults.py ---

'Verify source-pinned tablet identity and the compiled shared Settings RRO.'

def identity_fixture():
    """Conflicting source identities expose accidental partition merging."""
    parts = ('system', 'system_ext', 'product', 'vendor', 'odm', 'mi_ext')
    props = {}
    for part in parts:
        props[part] = f'ro.product.{part}.brand=Brand-{part}\nro.product.{part}.device=Device-{part}\nro.product.{part}.manufacturer=Maker-{part}\nro.product.{part}.model=Model-{part}\nro.product.{part}.name=Name-{part}\nro.product.{part}.marketname=Market-{part}\nro.product.{part}.cert=Cert-{part}\nro.{part}.build.fingerprint=Brand/{part}/device:17/ID/100:user/release-keys\nro.product.model=Stale-global-{part}\nro.build.fingerprint=Stale-global-fingerprint-{part}\n'.encode()
    props['odm'] += b'ro.product.model_for_attestation=Attested-tablet\nro.product.device_for_attestation=Attested-device\nro.vendor.build.fingerprint=Wrong-vendor-fingerprint-from-odm\n'
    props['product'] += b'ro.build.characteristics=tablet\n'
    props['vendor'] += b'ro.product.first_api_level=35\nro.product.board=Public-board-name\nro.soc.model=Public-SoC-name\nro.soc.manufacturer=Public-SoC-maker\nro.boot.hardware=physical-device\nro.board.platform=physical-platform\nro.hardware.egl=physical-egl\nro.hardware.gralloc=physical-gralloc\n'
    metadata = b'pre-device=Fixture-tablet\npost-sdk-level=37\npost-build=Brand/ota/tablet:17/OTA-ID/200:user/release-keys\n'
    return (props, metadata)

def source_profile(props, metadata):
    sources = {part + '.build.prop': data for part, data in props.items()}
    sources['ota.metadata'] = metadata
    return {'source_sha256': {name: hashlib.sha256(data).hexdigest() for name, data in sources.items()}, 'properties': identity_values(props, metadata)}

class PadIdentitySourcesTests(unittest.TestCase):

    def setUp(self):
        self.props, self.metadata = identity_fixture()
        self.profile = source_profile(self.props, self.metadata)

    def test_global_identity_uses_odm_and_ota_without_merging_partition_fingerprints(self):
        before = self.props.copy()
        selected = identity_values(self.props, self.metadata)
        for field in ('brand', 'device', 'manufacturer', 'model', 'name', 'marketname'):
            self.assertEqual(selected['ro.product.' + field], selected['ro.product.odm.' + field])
        self.assertEqual(selected['ro.product.model'], 'Model-odm')
        self.assertEqual(selected['ro.product.model_for_attestation'], 'Attested-tablet')
        self.assertEqual(selected['ro.build.fingerprint'], 'Brand/ota/tablet:17/OTA-ID/200:user/release-keys')
        for part in ('system', 'system_ext', 'product', 'vendor', 'odm'):
            self.assertEqual(selected[f'ro.{part}.build.fingerprint'], f'Brand/{part}/device:17/ID/100:user/release-keys')
        self.assertEqual(self.props, before)

    def test_public_board_and_soc_do_not_admit_hardware_selectors(self):
        selected = identity_values(self.props, self.metadata)
        self.assertEqual(selected['ro.product.board'], 'Public-board-name')
        self.assertEqual(selected['ro.product.first_api_level'], '35')
        self.assertEqual(selected['ro.soc.model'], 'Public-SoC-name')
        self.assertEqual(selected['ro.build.characteristics'], 'tablet')
        for key in ('ro.boot.hardware', 'ro.board.platform', 'ro.hardware.egl', 'ro.hardware.gralloc'):
            self.assertNotIn(key, selected)

    def test_all_partition_bytes_and_metadata_are_pinned_even_without_identity_changes(self):
        verify_identity_sources(self.profile, self.props, self.metadata)
        for part in self.props:
            changed = self.props.copy()
            changed[part] += b'# Unselected source bytes changed.\n'
            with self.subTest(part=part), self.assertRaisesRegex(RuntimeError, 'verified OTA'):
                verify_identity_sources(self.profile, changed, self.metadata)
        with self.assertRaisesRegex(RuntimeError, 'verified OTA'):
            verify_identity_sources(self.profile, self.props, self.metadata + b'ignored-key=changed\n')

    def test_forged_source_hashes_and_incomplete_pin_maps_are_rejected(self):
        for alias in ('system.build.prop', 'ota.metadata'):
            forged = copy.deepcopy(self.profile)
            forged['source_sha256'][alias] = hashlib.sha256(b'other source').hexdigest()
            with self.subTest(alias=alias), self.assertRaisesRegex(RuntimeError, 'verified OTA'):
                verify_identity_sources(forged, self.props, self.metadata)
        for operation in ('missing', 'extra'):
            forged = copy.deepcopy(self.profile)
            if operation == 'missing':
                del forged['source_sha256']['mi_ext.build.prop']
            else:
                forged['source_sha256']['unverified.build.prop'] = hashlib.sha256(b'').hexdigest()
            with self.subTest(operation=operation), self.assertRaisesRegex(RuntimeError, 'verified OTA'):
                verify_identity_sources(forged, self.props, self.metadata)

    def test_profile_cannot_inject_hal_selectors_despite_valid_source_hashes(self):
        for key in ('ro.boot.hardware', 'ro.board.platform', 'ro.hardware.egl', 'ro.hardware.gralloc'):
            forged = copy.deepcopy(self.profile)
            forged['properties'][key] = 'forged-selector'
            with self.subTest(key=key), self.assertRaisesRegex(RuntimeError, 'public identity'):
                verify_identity_sources(forged, self.props, self.metadata)

    def test_profile_cannot_forge_public_model_or_global_fingerprint(self):
        for key in ('ro.product.model', 'ro.build.fingerprint', 'ro.vendor.build.fingerprint'):
            forged = copy.deepcopy(self.profile)
            forged['properties'][key] = 'different-public-identity'
            with self.subTest(key=key), self.assertRaisesRegex(RuntimeError, 'public identity'):
                verify_identity_sources(forged, self.props, self.metadata)

class PadSettingsRroTests(unittest.TestCase):

    def test_stale_extra_resources_are_refused_before_building_or_signing(self):
        for relative in ('res/values/phone_aod.xml', 'res/drawable/phone_logo.xml'):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as temporary:
                folder = Path(temporary)
                extra = folder / relative
                extra.parent.mkdir(parents=True)
                extra.write_text('<resources><bool name="phone_only">true</bool></resources>')
                with patch('build_os4_pad.subprocess.run') as command:
                    with self.assertRaisesRegex(RuntimeError, 'Unexpected cached resources'):
                        settings_replacements('/unused/sdk', folder)
                    command.assert_not_called()

    def test_signed_rro_contains_only_shared_awake_defaults(self):
        from patch_gnss import java
        candidates = (os.environ.get('ANDROID_SDK_ROOT'), os.environ.get('ANDROID_HOME'), Path.home() / 'Library/Android/sdk')
        required = ('build-tools/37.0.0/aapt2', 'build-tools/37.0.0/apksigner', 'platforms/android-36/android.jar')
        sdk = next((Path(item).expanduser() for item in candidates if item and all(((Path(item).expanduser() / name).is_file() for name in required))), None)
        if sdk is None:
            self.skipTest('Android SDK 37 build-tools and the API 36 framework are unavailable.')
        try:
            java_binary = Path(java())
        except RuntimeError as error:
            self.skipTest(str(error))
        if not (java_binary.parent / 'keytool').is_file():
            self.skipTest('A JDK with keytool is needed to sign the resource-only RRO.')
        environment = dict(os.environ, JAVA_HOME=str(java_binary.parent.parent))
        version = subprocess.run([str(java_binary), '-version'], env=environment, check=False, capture_output=True, timeout=15)
        if version.returncode:
            self.skipTest('The configured Java runtime is unavailable.')
        tools = sdk / 'build-tools/37.0.0'
        with tempfile.TemporaryDirectory(prefix='pad-settings-rro-test-') as temporary:
            folder = Path(temporary)
            edits, marker = settings_replacements(sdk, folder)
            apk_key = 'product/overlay/HyperOSAVDSettingsDefaults/SettingsDefaults.apk'
            log_key = 'system_ext/bin/kill_HyperOS_Log.sh'
            self.assertEqual(set(edits), {apk_key, log_key})
            apk_data, mode, label = edits[apk_key]
            self.assertEqual((mode, label), (420, 'u:object_r:system_file:s0'))
            self.assertEqual(edits[log_key][1:], (493, 'u:object_r:system_file:s0'))
            self.assertEqual(marker['settings_overlay_sha256'], hashlib.sha256(apk_data).hexdigest())
            self.assertEqual(marker['log_script_sha256'], hashlib.sha256(edits[log_key][0]).hexdigest())
            self.assertEqual(marker['sleep_timeout'], -1)
            self.assertEqual(marker['first_boot_stay_on_while_plugged_in'], 1)
            self.assertEqual(marker['stay_on_while_plugged_in'], 7)
            apk = folder / 'SettingsDefaults.apk'
            self.assertEqual(apk.read_bytes(), apk_data)
            with zipfile.ZipFile(apk) as archive:
                self.assertIn('resources.arsc', archive.namelist())
                self.assertFalse(any((name.endswith('.dex') for name in archive.namelist())))
            verified = subprocess.run([str(tools / 'apksigner'), 'verify', '--verbose', str(apk)], env=environment, check=True, capture_output=True, text=True)
            self.assertIn('Verifies', verified.stdout)
            manifest = subprocess.run([str(tools / 'aapt2'), 'dump', 'xmltree', str(apk), '--file', 'AndroidManifest.xml'], check=True, capture_output=True, text=True).stdout
            self.assertRegex(manifest, 'android:targetPackage[^\\n]*="com\\.android\\.providers\\.settings"')
            self.assertRegex(manifest, 'android:isStatic[^\\n]*(?:0xffffffff|true)')
            self.assertRegex(manifest, 'android:hasCode[^\\n]*(?:=false|0x0\\b)')
            self.assertRegex(manifest, 'android:priority[^\\n]*(?:0x3e8|1000)\\b')
            resources = subprocess.run([str(tools / 'aapt2'), 'dump', 'resources', str(apk)], check=True, capture_output=True, text=True).stdout
            blocks = {}
            current = None
            for line in resources.splitlines():
                match = re.search('\\bresource 0x[0-9a-f]+ ([a-z]+/[A-Za-z0-9_]+)', line)
                if match:
                    current = match[1]
                    blocks[current] = []
                elif current:
                    blocks[current].append(line.strip())
            expected_resources = {'integer/def_screen_off_timeout': '2147483647', 'integer/def_sleep_timeout': '-1', 'bool/def_stay_on_while_plugged_in': 'true'}
            self.assertEqual(set(blocks), set(expected_resources), resources)
            for name, value in expected_resources.items():
                self.assertIn('() ' + value, blocks[name], resources)

if __name__ == '__main__':
    unittest.main()


# --- tests/test_pad_release.py ---

'Validate the release boundary without touching any registered AVD.'

def build_info():
    engine = '9caf8bd3413b3093ae0855f86369f31ddf45b46c7ddbaa4c2f656e4f67bb5009'
    return {'source': SOURCE, 'device': 'yingtian', 'android_api': 37, 'hyperos': PROFILE['hyperos'], 'archive_sha256': PROFILE['source_archive_sha256'], 'display': PROFILE['display'], 'model_xml_sha256': PROFILE['model_xml_sha256'], 'identity_source_sha256': PROFILE['source_sha256'], 'hardware_base_api': 36, 'kernel_page_size': 4096, 'gnss_patch': True, 'experimental': True, 'finddevice_provider_disabled': True, 'adb_authentication': True, 'hwui': {'before': BEFORE, 'after': AFTER}, 'flutter_engine': {'before': engine, 'after': PROFILES[engine]['output']}, 'assistant_render_fix': manifest(SOURCE), 'avd_defaults': {'settings_overlay_sha256': 'test', 'settings_overlay': OVERLAY, 'screen_off_timeout': SCREEN_TIMEOUT, 'sleep_timeout': -1, 'first_boot_stay_on_while_plugged_in': 1, 'stay_on_while_plugged_in': 7, 'log_script_sha256': hashlib.sha256(LOG_SCRIPT).hexdigest()}, 'vendor_fixes': {'test': True}}

class PadReleaseTests(unittest.TestCase):

    def test_shared_boot_policy_is_preserved_in_release_metadata(self):
        import dex2oat_cpu_policy as cpu
        import patch_init_capabilities as gates
        targets = list(gates.PROFILES)[:2]
        marker = {'schema': 1, 'targets': {path: {'before': gates.PROFILES[path]['before'], 'after': gates.PROFILES[path]['after'], 'capability': gates.PROFILES[path]['capability']} for path in targets}, 'script': {'path': gates.SCRIPT_PATH, 'sha256': hashlib.sha256(gates.SCRIPT_SOURCE.read_bytes()).hexdigest()}, 'qti_script_sha256': None, 'dex2oat': cpu.receipt()}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'local').mkdir()
            (root / 'local/build.json').write_text(json.dumps({**build_info(), 'boot_policy': marker}))
            value = package_release.release_metadata(root, 'os4-pad')
            self.assertEqual(value['build']['boot_policy'], marker)
        with self.assertRaisesRegex(RuntimeError, 'boot policy metadata'):
            release_pad.validate_build({**build_info(), 'boot_policy': {'unverified': True}})

    def test_metadata_is_a_separate_secure_family(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'local').mkdir()
            (root / 'local/build.json').write_text(json.dumps(build_info()))
            value = package_release.release_metadata(root, 'os4-pad')
            self.assertEqual(value['source_device'], 'yingtian')
            self.assertEqual(value['compatibility'], {'minimum_installer': '1.2.3', 'install_protocol': 'verified-bundle-runtime-v1', 'userdata_family': 'os4-yingtian-api37-ranchu-4k', 'upgrade_from': [], 'runtime_in_bundle': True})
            for key in ('hwui', 'flutter_engine', 'display', 'identity_source_sha256'):
                self.assertEqual(value['build'][key], build_info()[key])
            self.assertNotIn('memory_limit_mib', value['build'])
            for variant in ('os3', 'os4-official'):
                with self.assertRaises(RuntimeError):
                    package_release.release_metadata(root, variant)

    def test_unverified_source_or_diagnostic_metadata_is_rejected(self):
        for key, invalid in (('adb_authentication', False), ('source', 'official-hongkong-ota'), ('device', 'hongkong'), ('model_xml_sha256', 'unknown'), ('kernel_page_size', 16384)):
            with self.subTest(key=key), self.assertRaisesRegex(RuntimeError, key):
                release_pad.validate_build({**build_info(), key: invalid})

    def test_authenticated_properties_retain_all_other_defaults(self):
        original = b'# Accepted defaults\nro.adb.secure=0\nro.debuggable=0\nro.product.device=yingtian\n'
        value = prepare_release_image.authenticated_properties(original)
        self.assertEqual(value, original.replace(b'ro.adb.secure=0', b'ro.adb.secure=1'))
        self.assertEqual(prepare_release_image.authenticated_properties(value), value)
        for invalid in (original + b'ro.adb.secure=1\n', original.replace(b'ro.debuggable=0', b'ro.debuggable=1')):
            with self.assertRaises(RuntimeError):
                prepare_release_image.authenticated_properties(invalid)

    def test_old_overlay_defaults_cannot_be_published(self):
        value = build_info()
        value['avd_defaults']['screen_off_timeout'] = 120000
        with self.assertRaisesRegex(RuntimeError, 'defaults'):
            release_pad.validate_build(value)

    def test_packed_partition_content_and_size_are_verified(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw, packed = (root / 'raw.img', root / 'packed.img')
            raw.write_bytes(bytes(512))
            packed.write_bytes(bytes(512))
            partition = {'name': 'system', 'size': 512, 'extents': [(1, 0, 0, 0)]}
            with patch('lp_image.read_lp', return_value=(0, [partition])):
                release_pad.verify_partition(packed, raw, 'system')
                packed.write_bytes(b'x' + bytes(511))
                with self.assertRaisesRegex(RuntimeError, 'differs'):
                    release_pad.verify_partition(packed, raw, 'system')

    def test_archive_never_accepts_personal_layers_or_cross_variant_payloads(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = root / 'payload'
            payload.write_bytes(b'not personal data')
            for relative in ('avd/userdata-qemu.img', 'images/userdata-qemu.img', 'images/encryptionkey.img.qcow2', 'local/serial.json', 'tools/xiaomi-camera/provider', 'tools/weather-angle/original.so'):
                with self.subTest(relative=relative), self.assertRaisesRegex(RuntimeError, 'Unexpected release path'):
                    package_release.write_bundle(root / 'bundle', 'vtest', {'format': 3, 'variant': 'os4-pad'}, {relative: payload}, 1)

    def test_independent_pad_tag_is_accepted_by_packager(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = root / 'system.img'
            payload.write_bytes(b'fixture')
            version = package_release.default_release_version('os4-pad', {'hyperos': PROFILE['hyperos']})
            self.assertEqual(version, 'pad-v0.1.2-a17-hyperos4-yingtian-r3')
            result = package_release.write_bundle(root / 'bundle', version, {'format': 3, 'variant': 'os4-pad', 'build': {}}, {'images/system.img': payload}, 1)
            self.assertEqual(result['version'], version)

    def test_pad_default_retains_generic_forward_upgrade_compatibility(self):
        import manage
        version = package_release.default_release_version('os4-pad', {'hyperos': PROFILE['hyperos']})
        current = {'format': 3, 'variant': 'os4-pad', 'version': version, 'files': {'images/encryptionkey.img': {'sha256': 'stable-key'}}, 'compatibility': {'userdata_family': 'os4-yingtian-api37-ranchu-4k'}}
        self.assertEqual(manage.release_variant({'tag_name': version}), 'os4-pad')
        for previous in ('pad-v0.1.0-a17-hyperos4-yingtian-r1', 'pad-v0.1.1-a17-hyperos4-yingtian-r2'):
            old = {**current, 'version': previous}
            with self.subTest(previous=previous):
                manage.compatible(old, current)
                with self.assertRaisesRegex(RuntimeError, 'downgrade'):
                    manage.compatible(current, old)
        future = {**current, 'version': 'pad-v0.1.2-a17-hyperos4-yingtian-r999'}
        self.assertEqual(manage.release_variant({'tag_name': future['version']}), 'os4-pad')
        manage.compatible(current, future)
        with self.assertRaisesRegex(RuntimeError, 'downgrade'):
            manage.compatible(future, current)

    def test_signed_factory_apk_keeps_original_native_inputs(self):
        data = io.BytesIO()
        with zipfile.ZipFile(data, 'w') as archive:
            archive.writestr('lib/arm64-v8a/libtest.so', b'original signed native')
        before = hashlib.sha256(b'original signed native').hexdigest()
        release_pad.verify_apk_libraries(data.getvalue(), {'libtest.so': (before, 'patched hash')})
        with self.assertRaisesRegex(RuntimeError, 'native input differs'):
            release_pad.verify_apk_libraries(data.getvalue(), {'libtest.so': ('patched hash', before)})

    def test_conflicting_properties_are_rejected(self):
        release_pad.verify_properties([b'ro.adb.secure=1'], {'ro.adb.secure': '1'})
        for lines in ([], [b'ro.adb.secure=0'], [b'ro.adb.secure=1', b'ro.adb.secure=0']):
            with self.assertRaisesRegex(RuntimeError, 'ambiguous'):
                release_pad.verify_properties(lines, {'ro.adb.secure': '1'})

if __name__ == '__main__':
    unittest.main()
