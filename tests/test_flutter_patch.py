"""Consolidated unit tests for OS4 Flutter engine patch:
binary patching, runtime lifecycle, and Hongkong 18 firmware engine audits.
"""
import hashlib
import json
import lzma
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch as mock_patch
import zipfile

REPO = Path(__file__).resolve().parents[1]
ROOT = REPO
sys.path.insert(0, str(REPO / 'scripts'))

import apply_flutter_fix
import apply_navigation_fix
import module_lifecycle
import patch_flutter



# --- tests/test_flutter_patch.py ---

'Check fail-closed binary patching, APK preservation and AVD isolation.'

class FlutterPatchTests(unittest.TestCase):

    def pad_install_fixture(self, folder, *, old=False, native_hash='', wrong_apk=False, no_engine=False, unknown_engine=False, updated=False):
        root = Path(folder)
        (root / 'local').mkdir()
        (root / 'local/build.json').write_text(json.dumps({'source': apply_flutter_fix.PAD_SOURCE}))
        raw, engine, system, fixed_system = (b'original weather engine', b'fixed weather engine', b'system', b'fixed system')
        apks = {}
        for package, entries in (('com.miui.home', {'assets/home': b'factory Rust launcher'}), ('com.miui.weather2', {apply_flutter_fix.ENGINE_ENTRY: raw, 'assets/data': b'untouched signed APK contents'})):
            path = root / (package + '.apk')
            if package == 'com.miui.weather2' and no_engine:
                entries.pop(apply_flutter_fix.ENGINE_ENTRY)
            with zipfile.ZipFile(path, 'w') as archive:
                for name, data in entries.items():
                    archive.writestr(name, data)
            apks[package] = path.read_bytes()
        weather_hash = hashlib.sha256(apks['com.miui.weather2']).hexdigest()
        before, after = map(lambda data: hashlib.sha256(data).hexdigest(), (raw, engine))
        home_path = '/product/priv-app/MiuiHome/MiuiHome.apk'
        weather_path = '/data/app/~~token/com.miui.weather2-token/base.apk' if updated else apply_flutter_fix.PAD_WEATHER_APK
        packages = {'com.miui.home': home_path, 'com.miui.weather2': weather_path}
        legacy = {'revision': 6, 'system': {'target': apply_flutter_fix.SYSTEM_LIB, 'before': hashlib.sha256(system).hexdigest(), 'after': hashlib.sha256(fixed_system).hexdigest()}, 'packages': packages, 'apks': [{'package': 'com.miui.weather2', 'apk_target': apply_flutter_fix.PAD_WEATHER_APK, 'payload': 'com.miui.weather2.so', 'target': apply_flutter_fix.PAD_WEATHER_ENGINE, 'before': before, 'after': after, 'apk_sha256': weather_hash}]}
        commands = []

        def guest(config, command, **kwargs):
            commands.append(command)
            if command == 'id -u':
                return '0'
            if command == 'getprop sys.boot_completed':
                return '1'
            if command == 'getprop ro.mi.os.version.incremental':
                return 'OS4.0.15.0.XBMCNXM'
            if command.startswith('pm path '):
                return 'package:' + packages[command.removeprefix('pm path ')]
            if command.startswith('if [ -f ' + apply_flutter_fix.MODULE + '/manifest.json'):
                return json.dumps(legacy) if old else ''
            if any(('sha256sum ' + apply_flutter_fix.MODULE + '/' + name in command for name in ('post-fs-data.sh', 'service.sh'))):
                return hashlib.sha256(apply_flutter_fix.legacy_boot_script(apply_flutter_fix.PAD_SOURCE).encode()).hexdigest() + '  owned-hook'
            if command.startswith('if [ -e ' + apply_flutter_fix.PAD_WEATHER_ENGINE):
                return native_hash
            if command.startswith('sha256sum /data/adb/hyperos-render-stage-'):
                name = command.rsplit('/', 1)[1]
                return apply_flutter_fix.sha256(root / 'work/flutter-render-fix' / name) + '  staged'
            return ''

        def adb(config, action, *args, **kwargs):
            if action == 'pull':
                payload = system if args[0] == apply_flutter_fix.SYSTEM_LIB else apks['com.miui.home' if args[0] == home_path else 'com.miui.weather2']
                Path(args[1]).write_bytes(payload)

        def engine_patch(data):
            if data == system:
                return fixed_system
            if data == raw:
                if unknown_engine:
                    raise RuntimeError('Unsupported Flutter engine SHA-256: unknown-private-engine')
                return engine
            raise AssertionError('Unexpected source binary')
        with mock_patch.object(apply_flutter_fix, 'ROOT', root), mock_patch.object(apply_flutter_fix, 'official'), mock_patch.object(apply_flutter_fix, 'root', side_effect=guest), mock_patch.object(apply_flutter_fix, 'adb', side_effect=adb), mock_patch.object(apply_flutter_fix, 'firmware_context', return_value={'source': apply_flutter_fix.PAD_SOURCE, 'incremental': 'OS4.0.15.0.XBMCNXM', 'shared_input_sha256': hashlib.sha256(system).hexdigest()}), mock_patch.object(apply_flutter_fix, 'profile', return_value=(hashlib.sha256(system).hexdigest(), {'name': 'tablet-yingtian', 'output': hashlib.sha256(fixed_system).hexdigest()})), mock_patch.object(apply_flutter_fix, 'patch', side_effect=engine_patch), mock_patch.object(apply_flutter_fix, 'PAD_WEATHER_APK_SHA256', '0' * 64 if wrong_apk else weather_hash), mock_patch.object(apply_flutter_fix, 'PAD_WEATHER_BEFORE', before), mock_patch.object(apply_flutter_fix, 'PAD_WEATHER_AFTER', after), mock_patch.object(apply_flutter_fix, 'rewrite_apk') as rewrite, mock_patch.object(apply_flutter_fix, 'detach') as detach:
            result = apply_flutter_fix.install({'sdk': '/unused'}, sources=(apply_flutter_fix.PAD_SOURCE,))
            self.assertEqual(detach.call_count, int(old))
            if wrong_apk or unknown_engine or (native_hash and native_hash.split()[0] not in (before, after)):
                self.assertEqual(result['apks'], [])
                self.assertIn('com.miui.weather2', result['skipped_apks'])
                self.assertTrue(any((command.removeprefix('set -e\n').removeprefix(module_lifecycle.mutation_guard(apply_flutter_fix.MODULE)).startswith('mkdir ') for command in commands)))
                if old:
                    self.assertIn(apply_flutter_fix.PAD_WEATHER_ENGINE, detach.call_args.kwargs['preserve_paths'])
            rewrite.assert_not_called()
        self.assertEqual((root / 'com.miui.weather2.apk').read_bytes(), apks['com.miui.weather2'])
        return (result, raw, commands)

    def test_pad_factory_engine_missing_restores_external_library_without_apk_rewrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            manifest, raw, _ = self.pad_install_fixture(temporary)
            item, = manifest['apks']
            self.assertEqual(item['target'], apply_flutter_fix.PAD_WEATHER_ENGINE)
            self.assertTrue(item['external'])
            self.assertTrue(item['preserve_original'])
            self.assertEqual((Path(temporary) / 'work/flutter-render-fix/com.miui.weather2.so.original').read_bytes(), raw)

    def test_pad_legacy_manifest_migrates_instead_of_reusing_missing_extracted_engine(self):
        with tempfile.TemporaryDirectory() as temporary:
            manifest, _, _ = self.pad_install_fixture(temporary, old=True)
            self.assertTrue(manifest['apks'][0]['external'])
            self.assertTrue(manifest['apks'][0]['preserve_original'])

    def test_pad_unknown_apk_or_native_skips_private_overlay_and_keeps_shared_install(self):
        for arguments in ({'wrong_apk': True}, {'wrong_apk': True, 'no_engine': True}, {'native_hash': '0' * 64 + '  engine'}):
            with self.subTest(arguments=arguments), tempfile.TemporaryDirectory() as temporary:
                self.pad_install_fixture(temporary, **arguments)

    def test_updated_unknown_private_engine_never_aborts_or_changes_original_apk(self):
        with tempfile.TemporaryDirectory() as temporary:
            manifest, _, commands = self.pad_install_fixture(temporary, unknown_engine=True, updated=True, old=True)
            self.assertEqual(manifest['apks'], [])
            self.assertIn('unknown-private-engine', manifest['skipped_apks']['com.miui.weather2'])
            self.assertFalse(any(('com.miui.weather2.so' in command for command in commands)))
            self.assertIn('target', manifest['system'])

    def test_optional_private_bind_failure_does_not_abort_shared_boot_setup(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            checksum = 'a' * 64
            apk = folder / 'home.apk'
            apk.touch()
            (folder / 'apks.conf').write_text('com.miui.home|private.so|' + str(apk) + '|/private.so|before|after|' + checksum + '\n')
            bb = folder / 'bb'
            bb.touch()
            bb.chmod(448)
            script = apply_flutter_fix.BOOT_SCRIPT
            body = module_lifecycle.BLOCKED_FUNCTION + script[script.index('[ -x "$BB" ] || exit 1\n'):]
            log = folder / 'log'
            program = 'MODDIR=' + str(folder) + '\nBB=' + str(bb) + '\nlog() { echo "$*" >> ' + str(log) + '; }\nbind_target() { [ "$3" != /private.so ]; }\nsha256sum() { echo "' + checksum + '  apk"; }\n' + body
            result = subprocess.run(['sh', '-c', program, 'post-fs-data.sh'], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('Private engine skipped', log.read_text())

    def test_pad_weather_is_deferred_but_system_and_home_keep_early_bind(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            weather, restored, home, executable = (folder / name for name in ('weather.apk', 'restored.apk', 'home.apk', 'bb'))
            weather.touch()
            restored.touch()
            home.touch()
            executable.touch()
            executable.chmod(448)
            checksum = 'a' * 64
            rows = [('com.miui.weather2', weather, apply_flutter_fix.PAD_WEATHER_ENGINE), ('com.miui.weather2', restored, '/data/app/random/lib/arm64/libhyper_os_flutter.so'), ('com.miui.home', home, '/owned/home-engine.so')]
            (folder / 'apks.conf').write_text(''.join((package + '|payload.so|' + str(apk) + '|' + target + '|before|after|' + checksum + '\n' for package, apk, target in rows)))
            with mock_patch.object(apply_flutter_fix, 'PAD_WEATHER_APK', str(weather)):
                script = apply_flutter_fix.boot_script(apply_flutter_fix.PAD_SOURCE)
            body = module_lifecycle.BLOCKED_FUNCTION + script[script.index('[ -x "$BB" ] || exit 1\n'):]
            output = folder / 'binds.txt'
            program = 'MODDIR=' + str(folder) + '\nBB=' + str(executable) + '\nbind_target() { printf "%s\\n" "$3" >> ' + str(output) + '; }\nsha256sum() { printf "' + checksum + '  %s\\n" "$1"; }\n' + body
            subprocess.run(['sh', '-c', program, 'post-fs-data.sh'], check=True, capture_output=True, text=True)
            self.assertEqual(output.read_text().splitlines(), [apply_flutter_fix.SYSTEM_LIB, '/owned/home-engine.so'])

    def test_pad_boot_script_restoration_is_pinned_atomic_and_phone_unchanged(self):
        self.assertEqual(apply_flutter_fix.boot_script(), module_lifecycle.guarded_hook(apply_flutter_fix.BOOT_SCRIPT))
        script = apply_flutter_fix.boot_script(apply_flutter_fix.PAD_SOURCE)
        subprocess.run(['sh', '-n'], input=script, text=True, check=True, capture_output=True)
        for checksum in (apply_flutter_fix.PAD_WEATHER_APK_SHA256, apply_flutter_fix.PAD_WEATHER_BEFORE, apply_flutter_fix.PAD_WEATHER_AFTER):
            self.assertIn(checksum, script)
        self.assertIn('ln "$temporary" "$target"', script)
        self.assertIn('(set -C; cat "$original" > "$temporary")', script)

    def test_pad_restoration_trap_removes_temporary_hardlink(self):
        script = apply_flutter_fix.boot_script(apply_flutter_fix.PAD_SOURCE)
        cleanup = next((line.strip() for line in script.splitlines() if 'trap ' in line))
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            staged, target = (folder / 'original staging file', folder / 'engine.so')
            staged.write_bytes(b'original engine')
            target.hardlink_to(staged)
            subprocess.run(['sh', '-c', 'temporary=$1\n' + cleanup, 'restore', str(staged)], check=True, capture_output=True, text=True)
            self.assertFalse(staged.exists())
            self.assertEqual(target.read_bytes(), b'original engine')
        self.assertIn('[ ! -L "$directory" ] || exit 1', script)
        self.assertNotIn('cp "$original" "$target"', script)
        with self.assertRaisesRegex(RuntimeError, 'Unsupported Flutter firmware'):
            apply_flutter_fix.boot_script('unknown-profile')

    def test_patch_is_guarded_and_idempotent(self):
        original = b'ELF header' + bytes.fromhex('12345678') + b'payload'
        fixed = b'ELF header' + bytes.fromhex('abcdef01') + b'payload'
        profiles = {patch_flutter.digest(original): {'name': 'fixture', 'output': patch_flutter.digest(fixed), 'sites': [(10, '12345678', 'abcdef01')]}}
        with mock_patch.object(patch_flutter, 'PROFILES', profiles):
            self.assertEqual(patch_flutter.patch(original), fixed)
            self.assertEqual(patch_flutter.patch(fixed), fixed)
            with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
                patch_flutter.patch(original + b'changed')

    def test_wrong_instruction_and_output_are_rejected(self):
        original = b'abcd'
        profile = {'name': 'fixture', 'output': patch_flutter.digest(b'efgh'), 'sites': [(0, b'ijkl'.hex(), b'efgh'.hex())]}
        with mock_patch.object(patch_flutter, 'PROFILES', {patch_flutter.digest(original): profile}):
            with self.assertRaisesRegex(RuntimeError, 'Unexpected'):
                patch_flutter.patch(original)
            profile['sites'] = [(0, original.hex(), b'zzzz'.hex())]
            with self.assertRaisesRegex(RuntimeError, 'output checksum'):
                patch_flutter.patch(original)

    def test_pinned_legacy_patch_migrates_with_padding(self):
        original = b'ABCD' + bytes(24) + b'tail'
        legacy = b'EFGH' + bytes(24) + b'tail'
        fixed = b'EFGH' + b'X' * 24 + b'tail'
        profile = {'name': 'fixture', 'output': patch_flutter.digest(fixed), 'legacy': (patch_flutter.digest(legacy),), 'sites': [(0, b'ABCD'.hex(), b'EFGH'.hex()), (4, bytes(24).hex(), (b'X' * 24).hex())]}
        with mock_patch.object(patch_flutter, 'PROFILES', {patch_flutter.digest(original): profile}):
            self.assertEqual(patch_flutter.patch(original), fixed)
            self.assertEqual(patch_flutter.patch(legacy), fixed)
            self.assertEqual(patch_flutter.patch(fixed), fixed)
            with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
                patch_flutter.patch(legacy[:-1])

    def test_real_engine_profiles_when_available(self):
        root = Path(__file__).resolve().parents[1] / 'work/os4-official/work'
        paths = [root / 'flutter-render-fix/system-original.so', root / 'flutter-render-fix/com.miui.home.so.original', root / 'nav-research/weather-flutter.so']
        if not all((p.is_file() for p in paths)):
            self.skipTest('Verified proprietary engines are not distributed in Git.')
        for path in paths:
            original = path.read_bytes()
            _, profile = patch_flutter.profile(original)
            fixed = patch_flutter.patch(original)
            self.assertEqual(patch_flutter.digest(fixed), profile['output'])
            self.assertEqual(patch_flutter.patch(fixed), fixed)
            self.assertEqual(len(fixed), len(original))
            covered = bytearray(len(original))
            legacy = bytearray(original)
            for offset, before, after in profile['sites']:
                size = len(bytes.fromhex(before))
                covered[offset:offset + size] = bytes([1]) * size
                if size == 4 and before not in ('f30300aa', 'f30308aa') and (offset not in profile.get('shadow_sites', ())):
                    legacy[offset:offset + size] = bytes.fromhex(after)
            self.assertIn(patch_flutter.digest(legacy), profile['legacy'])
            self.assertEqual(patch_flutter.patch(legacy), fixed)
            self.assertFalse(any((a != b and (not allowed) for a, b, allowed in zip(original, fixed, covered))))
            if profile.get('shadow_sites'):
                previous = bytearray(fixed)
                for offset, before, _ in profile['sites']:
                    if offset in profile['shadow_sites']:
                        previous[offset:offset + 4] = bytes.fromhex(before)
                self.assertIn(patch_flutter.digest(previous), profile['legacy'])
                self.assertEqual(patch_flutter.patch(previous), fixed)

    def test_apk_overlay_preserves_other_entries_and_original(self):
        with tempfile.TemporaryDirectory() as tmp:
            original, fixed = (Path(tmp) / 'original.apk', Path(tmp) / 'fixed.apk')
            entry = zipfile.ZipInfo('assets/user-data.bin')
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = 420 << 16
            with zipfile.ZipFile(original, 'w') as archive:
                archive.writestr(entry, b'untouched')
                archive.writestr(apply_flutter_fix.ENGINE_ENTRY, b'original engine')
            before = original.read_bytes()
            apply_flutter_fix.rewrite_apk(original, fixed, b'fixed engine')
            self.assertEqual(original.read_bytes(), before)
            with zipfile.ZipFile(fixed) as archive:
                self.assertEqual(archive.read('assets/user-data.bin'), b'untouched')
                self.assertEqual(archive.getinfo('assets/user-data.bin').external_attr, entry.external_attr)
                self.assertEqual(archive.read(apply_flutter_fix.ENGINE_ENTRY), b'fixed engine')

    def test_missing_engine_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            original, fixed = (Path(tmp) / 'original.apk', Path(tmp) / 'fixed.apk')
            with zipfile.ZipFile(original, 'w') as archive:
                archive.writestr('assets/file', b'no engine')
            with self.assertRaisesRegex(RuntimeError, 'exactly one'):
                apply_flutter_fix.rewrite_apk(original, fixed, b'fixed')

    def test_other_avds_are_refused_before_adb(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'local').mkdir()
            (root / 'local/build.json').write_text(json.dumps({'source': 'official-hongkong-ota'}))
            with mock_patch.object(apply_flutter_fix, 'ROOT', root), mock_patch.object(apply_flutter_fix, 'root') as adb:
                for config in ({'name': 'Pixel_10_Pro', 'port': 5554}, {'name': 'HyperOS_4_Official_API_37', 'port': 5554}):
                    with self.assertRaisesRegex(RuntimeError, 'restricted'):
                        apply_flutter_fix.install(config)
                adb.assert_not_called()

    def test_unknown_launcher_aot_is_refused(self):
        with self.assertRaisesRegex(RuntimeError, 'Unsupported launcher AOT'):
            apply_navigation_fix.patch_aot(b'unknown launcher')
        with self.assertRaisesRegex(RuntimeError, 'Unsupported launcher watchdog'):
            apply_navigation_fix.patch_watchdog(b'unknown launcher')

    def test_real_launcher_watchdog_patch_when_available(self):
        apk = Path(__file__).resolve().parents[1] / 'work/os4-official/work/flutter-render-fix/home-original.apk'
        if not apk.is_file():
            self.skipTest('Verified launcher APK is not distributed in Git.')
        with zipfile.ZipFile(apk) as archive:
            original = archive.read('lib/arm64-v8a/libapp_launcher.so')
        fixed = apply_navigation_fix.patch_watchdog(original)
        self.assertEqual(patch_flutter.digest(fixed), apply_navigation_fix.WATCHDOG_AFTER)
        self.assertEqual(apply_navigation_fix.patch_watchdog(fixed), fixed)
        offset = apply_navigation_fix.WATCHDOG_OFFSET
        self.assertEqual(len(fixed), len(original))
        self.assertEqual(fixed[:offset], original[:offset])
        self.assertEqual(fixed[offset + 4:], original[offset + 4:])
        with self.assertRaisesRegex(RuntimeError, 'Unsupported launcher watchdog'):
            apply_navigation_fix.patch_watchdog(original + b'changed')

    def test_real_launcher_deadline_patch_when_available(self):
        apk = Path(__file__).resolve().parents[1] / 'work/os4-official/work/flutter-render-fix/home-original.apk'
        if not apk.is_file():
            self.skipTest('Verified launcher APK is not distributed in Git.')
        with zipfile.ZipFile(apk) as archive:
            original = archive.read('lib/arm64-v8a/libapp.so')
        fixed = apply_navigation_fix.patch_aot(original)
        self.assertEqual(patch_flutter.digest(fixed), apply_navigation_fix.AOT_AFTER)
        self.assertEqual(len(fixed), len(original))
        self.assertEqual(apply_navigation_fix.patch_aot(fixed), fixed)
        offset = apply_navigation_fix.AOT_OFFSET
        self.assertEqual(fixed[:offset], original[:offset])
        self.assertEqual(fixed[offset + 8:], original[offset + 8:])
        with self.assertRaisesRegex(RuntimeError, 'Unsupported launcher AOT'):
            apply_navigation_fix.patch_aot(original + b'changed')

if __name__ == '__main__':
    unittest.main()


# --- tests/test_flutter_hongkong18.py ---

'Verify the independently audited OS4.0.18 native renderer profile.'

INPUT = '7f88d7f4d9a464fdd56fb255642c9d300f28f50272ccf5fd31f082c1a52e17f4'

OUTPUT = '3ce87f3200841ae53cd869c9f939906d2f904f6af6601c1543365052b577e275'

PREVIOUS = '439bb47881f64431ba43dc4de5788e7f0a3a0c4e78102b47cc8f0daa6229b91b'

TRAMPOLINE = 6859112

def sections(data):
    header = struct.unpack_from('<16sHHIQQQIHHHHHH', data)
    rows = [struct.unpack_from('<IIQQQQIIQQ', data, header[6] + index * header[11]) for index in range(header[12])]
    table = rows[header[13]]
    strings = data[table[4]:table[4] + table[5]]
    return {strings[row[0]:].split(b'\x00', 1)[0].decode(): row for row in rows}

def debug_symbols(data):
    section = sections(data)['.gnu_debugdata']
    debug = lzma.decompress(data[section[4]:section[4] + section[5]])
    tables = sections(debug)
    symbols, strings = (tables['.symtab'], tables['.strtab'])
    names = debug[strings[4]:strings[4] + strings[5]]
    result = {}
    for offset in range(symbols[4], symbols[4] + symbols[5], symbols[9]):
        name, info, _, _, address, size = struct.unpack_from('<IBBHQQ', debug, offset)
        if info & 15 == 2:
            result[names[name:].split(b'\x00', 1)[0].decode()] = (address, size)
    return result

def branch_target(offset, instruction):
    value = struct.unpack('<I', bytes.fromhex(instruction))[0]
    if value & 4227858432 != 2483027968:
        raise AssertionError('Expected an ARM64 BL instruction')
    immediate = value & 67108863
    if immediate & 33554432:
        immediate -= 67108864
    return offset + immediate * 4

class Hongkong18FlutterTests(unittest.TestCase):

    def binary(self):
        path = Path(os.environ.get('HYPEROS_AVD_FLUTTER18_ARTIFACT', str(REPO / 'work/os4-r3-build/input/hongkong-4.0.18/flutter.bin')))
        if not path.is_file():
            self.skipTest('Original proprietary OTA engine is not distributed in Git.')
        data = path.read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), INPUT)
        return data

    def test_profile_has_independent_fingerprint_and_both_alignment_call_sites(self):
        profile = patch_flutter.PROFILES[INPUT]
        self.assertEqual(profile['name'], 'system-hongkong-4.0.18')
        self.assertEqual(profile['output'], OUTPUT)
        self.assertEqual(len(profile['sites']), 18)
        sites = {offset: (before, after) for offset, before, after in profile['sites']}
        for offset in (11810512, 11811940):
            self.assertEqual(sites[offset][0], 'f30300aa')
            self.assertEqual(branch_target(offset, sites[offset][1]), TRAMPOLINE)
        self.assertEqual(profile['shadow_sites'], (13883840, 13887004, 13887024))
        with self.assertRaisesRegex(RuntimeError, 'Unsupported Flutter engine'):
            patch_flutter.patch(b'unknown updated engine')

    def test_real_engine_edits_only_audited_sites_and_rejects_other_bytes(self):
        data = self.binary()
        fixed = patch_flutter.patch(data)
        self.assertEqual(hashlib.sha256(fixed).hexdigest(), OUTPUT)
        self.assertEqual(len(data), len(fixed))
        self.assertEqual(patch_flutter.patch(fixed), fixed)
        expected = bytearray(data)
        for offset, before, after in patch_flutter.PROFILES[INPUT]['sites']:
            original, replacement = (bytes.fromhex(before), bytes.fromhex(after))
            self.assertEqual(data[offset:offset + len(original)], original)
            expected[offset:offset + len(original)] = replacement
        self.assertEqual(fixed, expected)
        changed = bytearray(data)
        changed[14549416 + 4] ^= 1
        with self.assertRaisesRegex(RuntimeError, 'Unsupported Flutter engine'):
            patch_flutter.patch(changed)

    def test_large_glyph_threshold_is_bounded_and_old_patch_migrates(self):
        data = self.binary()
        fixed = patch_flutter.patch(data)
        offset = patch_flutter.PROFILES[INPUT]['glyph_raster_site']
        self.assertEqual(offset, 11719848)
        symbols = debug_symbols(data)
        collect = [value for name, value in symbols.items() if 'TypographerContextSkia16CollectNewGlyphs' in name]
        self.assertEqual(len(collect), 1)
        self.assertLessEqual(collect[0][0], offset + 65536)
        self.assertLess(offset + 65536, collect[0][0] + collect[0][1])
        for payload, threshold in ((data, 150.0), (fixed, 512.0)):
            instruction = struct.unpack_from('<I', payload, offset)[0]
            self.assertEqual(instruction & 4292870175, 1386217480)
            bits = (instruction >> 5 & 65535) << 16
            self.assertEqual(struct.unpack('<f', struct.pack('<I', bits))[0], threshold)
        previous = bytearray(fixed)
        previous[offset:offset + 4] = data[offset:offset + 4]
        self.assertEqual(hashlib.sha256(previous).hexdigest(), PREVIOUS)
        self.assertEqual(patch_flutter.patch(previous), fixed)
        self.assertEqual(previous[:offset], fixed[:offset])
        self.assertEqual(previous[offset + 4:], fixed[offset + 4:])

    def test_trampoline_is_executable_padding_outside_neighbor_functions(self):
        data = self.binary()
        header = struct.unpack_from('<16sHHIQQQIHHHHHH', data)
        loads = [struct.unpack_from('<IIQQQQQQ', data, header[5] + index * header[9]) for index in range(header[10])]
        self.assertTrue(any((kind == 1 and flags & 1 and (offset <= TRAMPOLINE) and (TRAMPOLINE + 24 <= offset + filesz) for kind, flags, offset, _, _, filesz, _, _ in loads)))
        symbols = debug_symbols(data)
        aes, aes_size = symbols['aes_gcm_dec_kernel']
        following, _ = symbols['bn_mul_mont_words']
        self.assertEqual(aes + aes_size - 65536, TRAMPOLINE)
        self.assertEqual(following - 65536, TRAMPOLINE + 24)
        self.assertEqual(data[TRAMPOLINE - 4:TRAMPOLINE], bytes.fromhex('c0035fd6'))
        self.assertEqual(data[TRAMPOLINE:TRAMPOLINE + 24], bytes(24))

    def test_changed_constructor_sites_and_viewport_constants_use_new_layout(self):
        data = self.binary()
        symbols = debug_symbols(data)
        constructor = symbols['_ZN8impeller12RenderPassVKC2ERKNSt3_fl10shared_ptrIKNS_7ContextEEERKNS_12RenderTargetENS2_INS_15CommandBufferVKEEE']
        self.assertEqual(constructor, (14604460, 14404))
        for offset in (14549416, 14550576):
            self.assertLessEqual(constructor[0], offset + 65536)
            self.assertLess(offset + 65536, constructor[0] + constructor[1])
        self.assertEqual(symbols['_ZN8impeller12RenderPassVK11SetViewportENS_8ViewportE'], (14624132, 112))
        self.assertEqual(struct.unpack_from('<2f', data, 1200384), (0, 1))
        self.assertEqual(struct.unpack_from('<2f', data, 1200400), (1, 0))
        fixed = patch_flutter.patch(data)
        for offset in (14550576, 14558672):
            before, after = (struct.unpack_from('<I', payload, offset)[0] for payload in (data, fixed))
            self.assertEqual((before >> 10 & 4095) * 8, 256)
            self.assertEqual((after >> 10 & 4095) * 8, 272)
        self.assertEqual(fixed[14549416:14549420], bytes.fromhex('00102e1e'))

if __name__ == '__main__':
    unittest.main()
