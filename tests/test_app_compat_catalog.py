"""Consolidated unit tests for App Compatibility subsystem:
catalog receipts, migration verification, and producer artifact packaging.
"""
from contextlib import ExitStack
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

REPO = Path(__file__).resolve().parents[1]
ROOT = REPO
sys.path.insert(0, str(REPO / 'scripts'))

import app_bridge_module
import app_compat_catalog as catalog
import app_compat_migration as migration
import app_compat_producers as producer
import apply_app_compat
import apply_app_compat as consumer
import apply_camera_fix as parrot
import apply_pad_camera_native_fix as camera_b
import apply_xiaomi_camera_fix as camera_a
from phone_profile import profile
import test_app_bridge_module as fixture

BUSYBOX, digest, REPO = fixture.BUSYBOX, fixture.digest, fixture.REPO



# --- tests/test_app_compat_catalog.py ---

'Exercise the universal artifact and real shell isolated recipe scheduler.'

BUSYBOX, digest, REPO = (fixture.BUSYBOX, fixture.digest, fixture.REPO)

class CatalogTests(unittest.TestCase):
    proc = fixture.AppBridgeTests.proc
    metadata = fixture.AppBridgeTests.metadata
    install_app = fixture.AppBridgeTests.install_app
    publish = fixture.AppBridgeTests.publish

    def test_released_revision_three_is_frozen_in_reviewed_history(self):
        frozen = json.loads((REPO / 'tests/fixtures/app-compat-v3-manifest.json').read_text())
        self.assertEqual(frozen['revision'], 3)
        self.assertIn(frozen, catalog.previous_manifests())
        self.assertEqual(digest(catalog.canonical(frozen)), '291b853daa919f9d06f9a568ad105521e126efa16927c556609d085697ed6c48')

    def test_deployed_revision_four_is_frozen_before_runtime_changes(self):
        frozen = json.loads((REPO / 'tests/fixtures/app-compat-v4-manifest.json').read_text())
        self.assertEqual(frozen['revision'], 4)
        self.assertIn(frozen, catalog.previous_manifests())
        self.assertEqual(digest(catalog.canonical(frozen)), '06780882c2472b78fc2f65b0710f815f4c8e094ed0b8b6db7750e9fd4f978e53')

    def test_deployed_revision_five_is_frozen_with_complete_controls(self):
        frozen = json.loads((REPO / 'tests/fixtures/app-compat-v5-manifest.json').read_text())
        self.assertEqual(frozen['revision'], 5)
        self.assertIn(frozen, catalog.previous_manifests())
        self.assertEqual(digest(catalog.canonical(frozen)), '26130954cc1740faec490beb0412f3507c49324b404ee757c342c4501d4fd4c8')
        checker = consumer._authentication_command('/data/adb/modules/' + catalog.MODULE_ID, frozen)
        for name, checksum in frozen['files_sha256'].items():
            if name == 'customize.sh':
                continue
            self.assertIn(checksum, checker)
            self.assertIn(name, checker)
        self.assertIn('manifest.json', checker)
        self.assertIn('SHA256SUMS', checker)
        changed = copy.deepcopy(frozen)
        changed['files_sha256']['catalog.sh'] = digest(b'unknown replacement')
        with patch.object(catalog, 'PREVIOUS_MANIFESTS', {digest(catalog.canonical(frozen)): changed}):
            with self.assertRaisesRegex(RuntimeError, 'Invalid reviewed'):
                catalog.previous_manifests()

    def test_deployed_revision_six_is_frozen_before_namespace_optimization(self):
        frozen = json.loads((REPO / 'tests/fixtures/app-compat-v6-manifest.json').read_text())
        self.assertEqual(frozen['revision'], 6)
        self.assertIn(frozen, catalog.previous_manifests())
        self.assertEqual(digest(catalog.canonical(frozen)), '3a46a482a1a1ac8581d4959980972b5f01f9a62d49333671c0737ec21606d1f9')

    def test_revision_seven_is_frozen_before_abi_guard_update(self):
        frozen = json.loads((REPO / 'tests/fixtures/app-compat-v7-manifest.json').read_text())
        self.assertEqual(frozen['revision'], 7)
        self.assertIn(frozen, catalog.previous_manifests())
        self.assertEqual(digest(catalog.canonical(frozen)),
                         '7c265a868f7607f52e9b43646926381c26563b0aac1a7729694f8fbc47ea4cd4')

    def test_consumer_rejects_a_different_abi_before_reading_modules(self):
        with patch.object(consumer, 'root', return_value='ranchu\nx86_64'), \
                patch.object(consumer, '_inspect') as inspect:
            with self.assertRaisesRegex(RuntimeError, 'ARM64 ranchu'):
                consumer.install_prebuilt({}, catalog=self.recipes, migration=False)
            inspect.assert_not_called()

    def test_mirror_regular_uses_one_namespace_and_keeps_cache_boundaries(self):
        context = self.module / 'contexts/first'
        cache = context / 'cache'
        cache.mkdir(exist_ok=True)
        mirror = cache / 'mirror-fixture'
        mirror.mkdir()
        target = mirror / 'Fixture.apk'
        target.write_bytes(self.apk_data)
        trace = self.root / 'ns-trace'
        command = 'MODDIR=' + shlex.quote(str(context)) + '\ncatalog_mirror_regular 1 '
        trace.write_text('')
        self.shell(command + shlex.quote(str(target)))
        self.assertEqual(trace.read_text().splitlines(), ['1'])
        alias = mirror / 'other.apk'
        os.link(target, alias)
        self.assertNotEqual(self.shell(command + shlex.quote(str(target)), check=False).returncode, 0)
        alias.unlink()
        target.unlink()
        target.symlink_to(alias)
        alias.write_bytes(self.apk_data)
        self.assertNotEqual(self.shell(command + shlex.quote(str(target)), check=False).returncode, 0)
        target.unlink()
        alias.unlink()
        target.write_bytes(self.apk_data)
        moved = cache / 'other'
        mirror.rename(moved)
        mirror.symlink_to(moved)
        self.assertNotEqual(self.shell(command + shlex.quote(str(target)), check=False).returncode, 0)
        trace.write_text('')
        self.assertNotEqual(self.shell(command + shlex.quote(str(mirror) + '/../Fixture.apk'), check=False).returncode, 0)
        self.assertEqual(trace.read_text(), '')

    def setUp(self):
        fixture.AppBridgeTests.setUp(self)
        body = BUSYBOX.replace('if value in mounts.get(pid, {}): return mounts[pid][value]', "\n    for target, source in sorted(mounts.get(pid, {}).items(), key=lambda item:-len(item[0])):\n        if value == target or value.startswith(target+'/'): return source+value[len(target):]")
        body = body.replace("('/data/', '/product/', '/system/')", "('/data/', '/product/', '/system/', '/system_ext/', '/vendor/')")
        body = body.replace("if value == '/data' or", "if value in ('/data','/product','/system','/system_ext','/vendor') or")
        body = body.replace("if args[0] == '-c':", "if not args:\n        print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest()+'  -'); sys.exit(0)\n    if args[0] == '-c':")
        body = body.replace("form.replace('%u:%g', owner)", "form.replace('%n', args[2]).replace('%y', str(value.st_mtime_ns)).replace('%z', str(value.st_ctime_ns)).replace('%Z', str(int(value.st_ctime))).replace('%f', format(value.st_mode, 'x')).replace('%u:%g', owner)")
        self.bb.write_text(body)
        self.pm_map = {'com.fixture.app': self.apk}
        self.write_pm()
        (self.bin / 'pm').write_text('#!' + sys.executable + '\n' + "\nimport json, os, pathlib, sys\nvalue=json.loads((pathlib.Path(os.environ['BRIDGE_TEST_ROOT'])/'pm-map').read_text()).get(sys.argv[-1])\nif value: print('package:'+value)\n")
        (self.bin / 'settings').write_text('#!' + sys.executable + '\n' + "\nimport json, os, pathlib, sys\np=pathlib.Path(os.environ['BRIDGE_TEST_ROOT'])/'settings.json'\nv=json.loads(p.read_text())\nif sys.argv[1]=='get': print(v.get(sys.argv[3],'null'))\nelse:\n    v[sys.argv[3]]=sys.argv[4]; p.write_text(json.dumps(v))\n")
        (self.bin / 'settings').chmod(493)
        (self.root / 'settings.json').write_text('{}')
        self.env['HYPEROS_APP_COMPAT_PREFS'] = str(self.root / 'preferences')
        self.env['HYPEROS_APP_COMPAT_RECOVERY_DIR'] = str(self.root / 'recovery')
        self.env['HYPEROS_APP_COMPAT_SERVICE_DIR'] = str(self.root / 'service')
        self.env['HYPEROS_APP_COMPAT_TEST_ROOT'] = str(self.root)
        self.preference = self.root / 'preferences'
        self.preference.mkdir()
        self.recipes = [self.recipe('first', 'weather', 'com.fixture.app', True, self.apk_data)]
        self.outputs = {digest(self.after): self.payload}
        self.publish_catalog()

    def recipe(self, identity, feature, package, enabled, apk):
        return {'id': identity, 'feature': feature, 'package': package, 'default_enabled': enabled, 'apk_sha256': digest(apk), 'system_libraries': {}, 'native_libraries': {}, 'libraries': [{'name': 'libtest.so', 'before': digest(self.before), 'after': digest(self.after), 'placeholder': False}], 'system_targets': []}

    def write_pm(self):
        (self.root / 'pm-map').write_text(json.dumps(self.pm_map))

    def publish_catalog(self):
        files = catalog.catalog_files(self.recipes, self.outputs)
        for name, data in files.items():
            path = self.module / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        for path in (self.module / 'cache', self.module / 'state'):
            path.mkdir(exist_ok=True)

    def shell(self, body, *, check=True):
        source = 'MODDIR=' + shlex.quote(str(self.module)) + '\n. "$MODDIR/runtime.sh"\n. "$MODDIR/catalog.sh"\ncatalog_assets || exit 19\n' + body
        return subprocess.run(['sh', '-c', source], env=self.env, text=True, capture_output=True, check=check, timeout=60)

    def mounts(self):
        return json.loads((self.root / 'mounts.json').read_text())

    def statuses(self):
        return {row.split('|')[0]: row.split('|')[2] for row in (self.module / 'state/status.tsv').read_text().splitlines()}

    def second(self, enabled=False):
        package = 'com.fixture.other'
        apk = '/data/app/~~other/' + package + '-A/base.apk'
        previous = self.apk_data
        self.apk_data = b'other exact signed APK'
        self.install_app(apk)
        self.recipes.append(self.recipe('second', 'parrot-camera', package, enabled, self.apk_data))
        self.apk_data = previous
        self.pm_map[package] = apk
        self.write_pm()
        self.publish_catalog()
        return apk

    def test_complete_artifact_deduplicates_objects_and_preserves_independent_defaults(self):
        self.second()
        a, b = (self.root / 'a.zip', self.root / 'b.zip')
        catalog.package_catalog(a, self.recipes, self.outputs)
        catalog.package_catalog(b, self.recipes, self.outputs)
        self.assertEqual(a.read_bytes(), b.read_bytes())
        with zipfile.ZipFile(a) as packed:
            self.assertEqual(len([name for name in packed.namelist() if name.startswith('objects/')]), 1)
            self.assertIn('webroot/index.html', packed.namelist())
            self.assertIn('post-fs-data.sh', packed.namelist())
        self.shell('catalog_pass late')
        self.assertEqual(self.statuses(), {'weather': 'verified', 'parrot-camera': 'disabled'})
        self.assertEqual(set(self.mounts()['1']), {self.native + '/libtest.so'})

    def test_unknown_update_is_isolated_and_explicit_opt_in_survives_reinstall(self):
        second = self.second()
        (self.preference / 'parrot-camera').write_text('on\n')
        self.shell('catalog_pass late')
        self.assertEqual(set(self.statuses().values()), {'verified'})
        (self.root / self.apk.lstrip('/')).write_bytes(b'unknown updated signed APK')
        self.shell('catalog_pass late')
        self.assertEqual(self.statuses()['weather'], 'unsupported')
        self.assertEqual(self.statuses()['parrot-camera'], 'verified')
        self.assertEqual(set(self.mounts()['1']), {second.rsplit('/', 1)[0] + '/lib/arm64/libtest.so'})
        (self.preference / 'parrot-camera').write_text('off\n')
        self.shell('catalog_pass late')
        self.assertEqual(self.mounts()['1'], {})
        self.assertEqual(self.statuses()['parrot-camera'], 'disabled')

    def test_reinstall_path_and_new_namespace_reconcile_without_unchanged_hashing(self):
        self.proc(66)
        self.shell('catalog_pass late\n: > "$BRIDGE_TEST_ROOT/hash-trace"\ncatalog_pass late\n[ ! -s "$BRIDGE_TEST_ROOT/hash-trace" ]')
        second = '/data/app/~~new/com.fixture.app-B/base.apk'
        self.install_app(second)
        self.pm_map['com.fixture.app'] = second
        self.write_pm()
        (self.root / 'pids').write_text('66')
        self.shell('catalog_pass late')
        target = second.rsplit('/', 1)[0] + '/lib/arm64/libtest.so'
        self.assertEqual(set(self.mounts()['1']), {target})
        self.assertIn(target, self.mounts()['66'])
        self.assertEqual((self.root / second.lstrip('/')).read_bytes(), self.apk_data)

    def test_global_flags_pending_and_single_scheduler_lease(self):
        for flag in ('disable', 'remove'):
            (self.module / flag).touch()
            result = self.shell('catalog_service', check=False)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(self.mounts(), {})
            (self.module / flag).unlink()
        self.shell('bridge_lock\n( bridge_lock ) && exit 1\nexit 0')
        self.shell('bridge_lock')
        self.shell('catalog_pass late')
        selection = self.module / 'state/select-late-weather'
        original = selection.read_text().splitlines()[0]
        selection.write_text(original + '\n../../other\n')
        self.shell('catalog_pass late')
        self.assertEqual(self.statuses()['weather'], 'unsupported')

    def test_embedded_abi_and_early_provider_loaded_guard_preserve_targets(self):
        provider = '/vendor/bin/hw/android.hardware.camera.provider@2.7-service-google'
        original = b'original exact provider'
        payload = b'patched exact provider'
        target = self.root / provider.lstrip('/')
        target.parent.mkdir(parents=True)
        target.write_bytes(original)
        target.chmod(493)
        self.metadata(target, context='u:object_r:hal_camera_default_exec:s0', owner='1000:1000')
        factory = '/product/priv-app/Fixture/Fixture.apk'
        factory_path = self.root / factory.lstrip('/')
        factory_path.parent.mkdir(parents=True)
        with zipfile.ZipFile(factory_path, 'w') as apk:
            apk.writestr('lib/arm64-v8a/libtest.so', self.before)
        recipe = self.recipes[0]
        recipe.update(apk_sha256=digest(factory_path.read_bytes()), factory_apk=factory, native='/product/priv-app/Fixture/lib/arm64', factory_overlay=True, apk_libraries={'lib/arm64-v8a/libtest.so': digest(self.before)}, system_targets=[{'target': provider, 'before': digest(original), 'after': digest(payload), 'mount_flags': 'ro,suid,exec'}])
        recipe['libraries'][0]['placeholder'] = True
        provider_payload = self.root / 'provider.so'
        provider_payload.write_bytes(payload)
        self.outputs[digest(payload)] = provider_payload
        self.pm_map['com.fixture.app'] = factory
        self.write_pm()
        self.publish_catalog()
        (self.root / 'proc/1/maps').write_text('0-1 r--p 0 1:2 12 ' + provider + '\n')
        self.shell('catalog_pass early')
        self.assertEqual(self.statuses()['weather'], 'reboot-required')
        self.assertEqual(self.mounts(), {})
        self.assertEqual(target.read_bytes(), original)
        (self.root / 'proc/1/maps').write_text('')
        self.shell('catalog_pass early')
        self.assertEqual(self.statuses()['weather'], 'verified')
        self.assertIn(provider, self.mounts()['1'])
        self.assertIn(factory.rsplit('/', 1)[0], self.mounts()['1'])
        mirror = Path(self.mounts()['1'][factory.rsplit('/', 1)[0]])
        self.assertEqual((mirror / 'Fixture.apk').read_bytes(), factory_path.read_bytes())
        self.assertEqual((mirror / 'lib/arm64/libtest.so').read_bytes(), self.after)
        self.shell('catalog_pass late')
        self.assertEqual(self.statuses()['weather'], 'verified')
        self.assertIn(provider, self.mounts()['1'])
        (self.preference / 'weather').write_text('off\n')
        self.shell('catalog_pass late')
        self.assertEqual(self.mounts()['1'], {})

    def factory_preopt(self):
        factory = '/product/priv-app/Fixture/Fixture.apk'
        apk = self.root / factory.lstrip('/')
        apk.parent.mkdir(parents=True)
        with zipfile.ZipFile(apk, 'w') as archive:
            archive.writestr('lib/arm64-v8a/libtest.so', self.before)
        apk.chmod(420)
        self.metadata(apk, owner='0:0', context='u:object_r:system_file:s0')
        passthrough = {'oat/arm64/Fixture.odex': b'original precompiled code', 'oat/arm64/Fixture.vdex': b'original verified dex'}
        for name, body in passthrough.items():
            target = apk.parent / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
            target.chmod(416)
            self.metadata(target, owner='1000:1015', context='u:object_r:dalvikcache_data_file:s0')
        for directory in (apk.parent, apk.parent / 'oat', apk.parent / 'oat/arm64'):
            directory.chmod(488)
            self.metadata(directory, owner='0:1015', context='u:object_r:system_file:s0')
        recipe = self.recipes[0]
        recipe.update(apk_sha256=digest(apk.read_bytes()), factory_apk=factory, native=str(Path(factory).parent / 'lib/arm64'), factory_overlay=True, apk_libraries={'lib/arm64-v8a/libtest.so': digest(self.before)}, factory_passthrough={name: digest(body) for name, body in passthrough.items()})
        recipe['libraries'][0]['placeholder'] = True
        self.pm_map['com.fixture.app'] = factory
        self.write_pm()
        self.publish_catalog()
        return (factory, apk, passthrough)

    def factory_provider(self):
        provider = '/vendor/bin/hw/android.hardware.camera.provider@2.7-service-google'
        original, patched = (b'original exact provider', b'patched exact provider')
        target = self.root / provider.lstrip('/')
        target.parent.mkdir(parents=True)
        target.write_bytes(original)
        target.chmod(493)
        self.metadata(target, context='u:object_r:hal_camera_default_exec:s0', owner='1000:1000')
        payload = self.root / 'provider.so'
        payload.write_bytes(patched)
        self.outputs[digest(patched)] = payload
        self.recipes[0]['system_targets'] = [{'target': provider, 'before': digest(original), 'after': digest(patched), 'mount_flags': 'ro,suid,exec'}]
        self.publish_catalog()
        return (provider, target, original)

    def test_factory_preflight_runs_once_before_provider_and_cache_effects(self):
        factory, apk, _ = self.factory_preopt()
        provider, _, _ = self.factory_provider()
        source = (REPO / 'modules/app-bridge/catalog.sh').read_text()
        original = source.split('catalog_mirror_validate() {', 1)[1].split('\n}', 1)[0]
        self.shell('original_mirror_validate() {' + original + '\n}\ncatalog_mirror_validate() {\n  [ ! -s "$MODDIR/state/owned.tsv" ] || return 1\n  [ -z "$(ls -A "$MODDIR/cache")" ] || return 1\n  printf "validated\\n" >> "$BRIDGE_TEST_ROOT/preflight-trace"\n  original_mirror_validate "$@"\n}\ncatalog_pass early')
        self.assertEqual((self.root / 'preflight-trace').read_text(), 'validated\n')
        self.assertEqual(self.statuses()['weather'], 'verified')
        self.assertEqual(set(self.mounts()['1']), {provider, str(Path(factory).parent)})
        trace = (self.root / 'hash-trace').read_text().splitlines()
        mirror = Path(self.mounts()['1'][str(Path(factory).parent)])
        self.assertIn(str(mirror / apk.name), trace)
        self.assertIn(str(apk), trace)

    def test_factory_system_failure_and_mirror_rollback_keep_distinct_ownership(self):
        factory, _, _ = self.factory_preopt()
        provider, target, original = self.factory_provider()
        (self.root / 'fail-mount').write_text(provider)
        self.shell('catalog_pass early')
        self.assertEqual(self.statuses()['weather'], 'pending')
        self.assertIn('System namespace overlay deferred', (self.module / 'state/status.tsv').read_text())
        self.assertFalse(any(self.mounts().values()))
        self.assertEqual(target.read_bytes(), original)
        (self.root / 'fail-mount').write_text(str(Path(factory).parent))
        self.shell('catalog_pass early')
        self.assertEqual(self.statuses()['weather'], 'pending')
        self.assertIn('Factory overlay safely deferred', (self.module / 'state/status.tsv').read_text())
        self.assertEqual(set(self.mounts()['1']), {provider})
        self.assertFalse(list((self.module / 'contexts/first/state').glob('transaction.*')))

    def test_factory_preopt_mirror_preserves_exact_bytes_and_metadata(self):
        factory, apk, passthrough = self.factory_preopt()
        original = apk.read_bytes()
        self.shell('catalog_pass early')
        self.assertEqual(self.statuses()['weather'], 'verified')
        mirror = Path(self.mounts()['1'][str(Path(factory).parent)])
        metadata = json.loads((self.root / 'metadata.json').read_text())
        for name, body in passthrough.items():
            source, target = (apk.parent / name, mirror / name)
            self.assertEqual(source.read_bytes(), body)
            self.assertEqual(target.read_bytes(), body)
            self.assertEqual(target.stat().st_mode & 511, 416)
            self.assertEqual(target.stat().st_nlink, 1)
            self.assertEqual(metadata[f'{target.stat().st_dev}:{target.stat().st_ino}'], metadata[f'{source.stat().st_dev}:{source.stat().st_ino}'])
        for name in ('oat', 'oat/arm64'):
            source, target = (apk.parent / name, mirror / name)
            self.assertEqual(target.stat().st_mode & 511, source.stat().st_mode & 511)
            self.assertEqual(metadata[f'{target.stat().st_dev}:{target.stat().st_ino}'], metadata[f'{source.stat().st_dev}:{source.stat().st_ino}'])
        self.assertEqual((mirror / 'Fixture.apk').read_bytes(), original)
        self.assertEqual(apk.read_bytes(), original)
        self.shell('catalog_pass late\n: > "$BRIDGE_TEST_ROOT/hash-trace"\ncatalog_pass late\n[ ! -s "$BRIDGE_TEST_ROOT/hash-trace" ]')
        (mirror / 'oat/arm64/unknown.art').write_bytes(b'foreign addition')
        self.shell('catalog_pass early')
        self.assertEqual(self.statuses()['weather'], 'unsupported')
        self.assertTrue((mirror / 'oat/arm64/unknown.art').is_file())

    def test_factory_preopt_unknown_content_and_aliases_fail_before_any_bind(self):
        _, apk, passthrough = self.factory_preopt()
        _, provider, provider_original = self.factory_provider()
        target = apk.parent / 'oat/arm64/Fixture.vdex'
        original = target.read_bytes()
        target.write_bytes(b'unaudited preopt update')
        self.shell('catalog_pass early')
        self.assertEqual(self.statuses()['weather'], 'unsupported')
        self.assertEqual(self.mounts(), {})
        target.write_bytes(original)
        alias = self.root / 'external-vdex'
        os.link(target, alias)
        self.shell('catalog_pass early')
        self.assertEqual(self.statuses()['weather'], 'unsupported')
        self.assertEqual(self.mounts(), {})
        alias.unlink()
        target.unlink()
        target.symlink_to(alias)
        alias.write_bytes(original)
        self.shell('catalog_pass early')
        self.assertEqual(self.statuses()['weather'], 'unsupported')
        self.assertEqual(self.mounts(), {})
        target.unlink()
        target.write_bytes(original)
        unknown = apk.parent / 'oat/arm64/foreign.art'
        unknown.write_bytes(b'foreign')
        self.shell('catalog_pass early')
        self.assertEqual(self.statuses()['weather'], 'unsupported')
        self.assertEqual(self.mounts(), {})
        self.assertEqual(unknown.read_bytes(), b'foreign')
        self.assertEqual(provider.read_bytes(), provider_original)
        self.assertFalse(list((self.module / 'contexts/first/cache').iterdir()))

    def test_factory_passthrough_schema_requires_explicit_preopt_and_overlay(self):
        for asset in ('../Fixture.odex', 'oat/arm64/../Fixture.odex', 'oat/arm64/unknown.art', 'oat/x86_64/Fixture.odex', 'oat/arm64/sub/Fixture.odex', 'lib/arm64/libtest.so'):
            recipe = copy.deepcopy(self.recipes)
            recipe[0].update(factory_overlay=True, factory_apk='/product/priv-app/Fixture/Fixture.apk', native='/product/priv-app/Fixture/lib/arm64', factory_passthrough={asset: digest(b'original')})
            with self.subTest(asset=asset), self.assertRaisesRegex(RuntimeError, 'passthrough'):
                catalog.validate(recipe)
        recipe = copy.deepcopy(self.recipes)
        recipe[0]['factory_passthrough'] = {'oat/arm64/Fixture.odex': digest(b'original')}
        with self.assertRaisesRegex(RuntimeError, 'passthrough'):
            catalog.validate(recipe)

    def test_factory_inventory_preserves_filename_boundaries_and_rejects_find_error(self):
        factory, apk, _ = self.factory_preopt()
        parent = str(Path(factory).parent)
        for name in ('Fixture.apk\n', 'Fixture.apk ', 'oat\n', 'oat\t'):
            unknown = apk.parent / name
            unknown.write_bytes(b'unknown original must be preserved')
            with self.subTest(name=name):
                result = self.shell('MODDIR="$OWNERDIR/contexts/first"; BRIDGE_CATALOG=1\ncatalog_context_assets || exit 1\ncatalog_mirror_inventory 1 ' + shlex.quote(parent) + ' Fixture.apk', check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(unknown.read_bytes(), b'unknown original must be preserved')
                self.assertEqual(self.mounts(), {})
                self.assertFalse(list((self.module / 'contexts/first/state').glob('inventory.*')))
            unknown.unlink()
        find = self.bin / 'find'
        find.write_text("#!/bin/sh\nprintf './Fixture.apk\\0./oat\\0'\nexit 1\n")
        find.chmod(493)
        result = self.shell('catalog_pass early', check=False)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.statuses()['weather'], 'unsupported')
        self.assertEqual(self.mounts(), {})
        self.assertTrue(apk.is_file())
        self.assertFalse(list((self.module / 'contexts/first/state').glob('inventory.*')))

    def test_owned_angle_cleanup_preserves_unrelated_package_policy(self):
        self.recipes[0]['policy'] = {'angle': {'driver': 'angle', 'features': ['exposeES32ForTesting']}}
        self.publish_catalog()
        self.shell('catalog_pass late')
        values = json.loads((self.root / 'settings.json').read_text())
        self.assertEqual(values['angle_gl_driver_selection_pkgs'], 'com.fixture.app')
        values['angle_gl_driver_selection_pkgs'] += ',com.foreign.app'
        values['angle_gl_driver_selection_values'] += ',native'
        (self.root / 'settings.json').write_text(json.dumps(values))
        receipt = self.module / 'contexts/first/state/angle-owned.tsv'
        before = receipt.read_bytes()
        self.shell('catalog_pass early')
        self.assertEqual(receipt.read_bytes(), before)
        self.assertEqual(json.loads((self.root / 'settings.json').read_text()), values)
        (self.preference / 'weather').write_text('off\n')
        self.shell('catalog_pass late')
        values = json.loads((self.root / 'settings.json').read_text())
        self.assertEqual(values['angle_gl_driver_selection_pkgs'], 'com.foreign.app')
        self.assertEqual(values['angle_gl_driver_selection_values'], 'native')
        self.assertEqual(self.statuses()['weather'], 'disabled')

    def defer_framework(self):
        for name in ('settings', 'pm', 'am', 'cmd'):
            command = self.bin / name
            command.write_text('#!/bin/sh\nprintf "%s\\n" ' + shlex.quote(name) + ' >> "$BRIDGE_TEST_ROOT/framework-trace"\nexit 99\n')
            command.chmod(493)
        prop = self.bin / 'getprop'
        prop.write_text(prop.read_text().replace('sys.boot_completed) echo 1', 'sys.boot_completed) echo 0'))

    def assert_prezygote_cleanup(self, variant):
        if variant != 'late-only':
            self.factory_preopt()
        self.recipes[0]['policy'] = {'angle': {'driver': 'angle', 'features': ['exposeES32ForTesting']}}
        self.publish_catalog()
        self.shell('catalog_pass late')
        receipt = self.module / 'contexts/first/state/angle-owned.tsv'
        original = receipt.read_bytes()
        settings = (self.root / 'settings.json').read_bytes()
        preference = self.preference / 'weather'
        if variant == 'disabled':
            preference.write_text('off\n')
            (self.root / 'proc/1/maps').write_text('0-1 r--p 0 1:2 12 ' + self.pm_map['com.fixture.app'] + '\n')
            loaded_mounts = self.mounts()
        elif variant == 'unmatched':
            (self.root / 'mounts.json').write_text('{}')
            (self.root / self.pm_map['com.fixture.app'].lstrip('/')).write_bytes(b'unknown replacement')
        self.defer_framework()
        self.shell('catalog_early')
        self.assertFalse((self.root / 'framework-trace').exists())
        self.assertEqual(receipt.read_bytes(), original)
        self.assertEqual((self.root / 'settings.json').read_bytes(), settings)
        if variant == 'disabled':
            self.assertEqual(preference.read_text(), 'off\n')
            self.assertEqual(self.mounts(), loaded_mounts)

    def test_prezygote_policy_helpers_and_late_selection_fail_without_framework_calls(self):
        self.defer_framework()
        self.shell('CATALOG_PHASE=early\ncatalog_settings && exit 1\ncatalog_policy_write a b c && exit 1\ncatalog_select weather late com.fixture.app && exit 1\ncatalog_pass late && exit 1\nexit 0')
        self.assertFalse((self.root / 'framework-trace').exists())

    def test_early_late_only_receipt_never_calls_framework(self):
        self.assert_prezygote_cleanup('late-only')

    def test_early_disabled_factory_receipt_never_calls_framework(self):
        self.assert_prezygote_cleanup('disabled')

    def test_early_unmatched_factory_receipt_never_calls_framework(self):
        self.assert_prezygote_cleanup('unmatched')

    def test_late_angle_restore_preserves_changed_driver_and_receipt(self):
        self.recipes[0]['policy'] = {'angle': {'driver': 'angle', 'features': []}}
        self.publish_catalog()
        self.shell('catalog_pass late')
        receipt = self.module / 'contexts/first/state/angle-owned.tsv'
        original = receipt.read_bytes()
        values = json.loads((self.root / 'settings.json').read_text())
        values['angle_gl_driver_selection_values'] = 'native'
        (self.root / 'settings.json').write_text(json.dumps(values))
        (self.preference / 'weather').write_text('off\n')
        self.shell('catalog_pass late')
        self.assertEqual(json.loads((self.root / 'settings.json').read_text()), values)
        self.assertEqual(receipt.read_bytes(), original)
        self.assertEqual(self.statuses()['weather'], 'pending')

    def factory_candidates(self):
        factory, apk, _ = self.factory_preopt()
        recipe = self.recipes[0]
        self.recipes = []
        for identity, checksum in (('candidate-a', digest(b'other signed APK A')), ('candidate-b', digest(b'other signed APK B')), ('candidate-c', digest(apk.read_bytes()))):
            item = copy.deepcopy(recipe)
            item.update(id=identity, apk_sha256=checksum)
            self.recipes.append(item)
        self.publish_catalog()
        return (factory, apk)

    def factory_hashes(self, apk):
        trace = self.root / 'hash-trace'
        return trace.read_text().splitlines().count(str(apk)) if trace.exists() else 0

    def test_early_selection_hashes_one_factory_inode_once_per_call(self):
        _, apk = self.factory_candidates()
        result = self.shell('catalog_select weather early com.fixture.app')
        self.assertEqual(result.stdout.strip(), 'candidate-c')
        self.assertEqual(self.factory_hashes(apk), 1)
        self.shell('catalog_select weather early com.fixture.app')
        self.assertEqual(self.factory_hashes(apk), 2)

    def test_early_selection_rejects_unknown_and_ambiguous_content(self):
        _, apk = self.factory_candidates()
        original = apk.read_bytes()
        apk.write_bytes(b'unknown replacement')
        self.assertNotEqual(self.shell('catalog_select weather early com.fixture.app', check=False).returncode, 0)
        self.assertEqual(self.factory_hashes(apk), 1)
        apk.write_bytes(original)
        profile = 'candidate-b|' + digest(original) + '|' + self.recipes[1]['factory_apk'] + '|' + self.recipes[1]['native']
        result = self.shell('printf "%s\\n" ' + shlex.quote(profile) + ' > "$OWNERDIR/contexts/candidate-b/profiles.tsv"\ncatalog_select weather early com.fixture.app', check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.factory_hashes(apk), 2)

    def changing_factory_identity(self, mutation):
        _, apk = self.factory_candidates()
        injection = "\nif command == 'stat' and args[0] == '-c' and args[1] == '%d:%i:%s:%Y:%y:%Z:%z:%h:%f':\n    calls = root / 'identity-calls'\n    count = int(calls.read_text()) + 1 if calls.exists() else 1\n    calls.write_text(str(count))\n    if count == 3:\n        target = pathlib.Path(args[2])\n        previous = target.stat()\n        MUTATION\n".replace('MUTATION', mutation)
        self.bb.write_text(self.bb.read_text().replace("if command == 'stat' and args[0] == '-c':", injection + "\nif command == 'stat' and args[0] == '-c':"))
        return apk

    def test_early_selection_rehashes_replaced_inode_with_same_size_and_mtime(self):
        apk = self.changing_factory_identity("replacement = target.with_suffix('.replacement'); replacement.write_bytes(target.read_bytes()); os.utime(replacement, ns=(previous.st_atime_ns, previous.st_mtime_ns)); os.replace(replacement, target)")
        result = self.shell('catalog_select weather early com.fixture.app')
        self.assertEqual(result.stdout.strip(), 'candidate-c')
        self.assertEqual(self.factory_hashes(apk), 2)

    def test_early_selection_rehashes_nanosecond_mtime_change(self):
        apk = self.changing_factory_identity('os.utime(target, ns=(previous.st_atime_ns, previous.st_mtime_ns + 1))')
        self.shell('catalog_select weather early com.fixture.app')
        self.assertEqual(self.factory_hashes(apk), 2)

    def test_early_selection_rehashes_size_change_and_rejects_new_unknown_content(self):
        apk = self.changing_factory_identity("target.write_bytes(target.read_bytes() + b'unknown addition')")
        self.assertNotEqual(self.shell('catalog_select weather early com.fixture.app', check=False).returncode, 0)
        self.assertEqual(self.factory_hashes(apk), 2)

    def test_early_selection_rehashes_same_size_write_with_restored_mtime(self):
        apk = self.changing_factory_identity('body = target.read_bytes(); target.write_bytes(bytes([body[0] ^ 1]) + body[1:]); os.utime(target, ns=(previous.st_atime_ns, previous.st_mtime_ns))')
        self.assertNotEqual(self.shell('catalog_select weather early com.fixture.app', check=False).returncode, 0)
        self.assertEqual(self.factory_hashes(apk), 2)

    def test_early_selection_rejects_factory_alias_during_identity_check(self):
        apk = self.changing_factory_identity("saved = target.with_suffix('.saved'); target.rename(saved); target.symlink_to(saved)")
        self.assertNotEqual(self.shell('catalog_select weather early com.fixture.app', check=False).returncode, 0)
        self.assertEqual(self.factory_hashes(apk), 1)
        self.assertTrue(apk.is_symlink())

    def uninstall_handoff(self):
        self.recipes[0]['policy'] = {'angle': {'driver': 'angle', 'features': ['exposeES32ForTesting']}}
        self.publish_catalog()
        self.shell('catalog_pass late')
        commands = {name: (self.bin / name).read_bytes() for name in ('settings', 'pm', 'am', 'cmd') if (self.bin / name).exists()}
        prop = (self.bin / 'getprop').read_bytes()
        original = (self.module / 'contexts/first/state/angle-owned.tsv').read_bytes()
        self.defer_framework()
        self.shell('catalog_uninstall')
        self.assertFalse((self.root / 'framework-trace').exists())
        callbacks = list((self.root / 'service').glob('*.sh'))
        self.assertEqual(len(callbacks), 1)
        receipts = list((self.root / 'recovery').glob('*/state/angle-owned.tsv'))
        self.assertEqual(len(receipts), 1)
        self.assertEqual(receipts[0].read_bytes(), original)
        shutil.rmtree(self.module)
        for name, body in commands.items():
            (self.bin / name).write_bytes(body)
        (self.bin / 'getprop').write_bytes(prop)
        return (callbacks[0], receipts[0])

    def recovery_callback(self, callback):
        return subprocess.run(['sh', str(callback)], env=self.env, text=True, capture_output=True, timeout=20)

    def test_uninstall_handoff_survives_module_deletion_and_cleans_owned_files(self):
        callback, receipt = self.uninstall_handoff()
        values = json.loads((self.root / 'settings.json').read_text())
        values['angle_gl_driver_selection_pkgs'] += ',com.foreign.app'
        values['angle_gl_driver_selection_values'] += ',native'
        (self.root / 'settings.json').write_text(json.dumps(values))
        result = self.recovery_callback(callback)
        self.assertEqual(result.returncode, 0, result.stderr)
        values = json.loads((self.root / 'settings.json').read_text())
        self.assertEqual(values['angle_gl_driver_selection_pkgs'], 'com.foreign.app')
        self.assertEqual(values['angle_gl_driver_selection_values'], 'native')
        self.assertFalse(callback.exists())
        self.assertFalse(receipt.parent.parent.exists())

    def test_uninstall_handoff_preserves_changed_policy_and_receipt(self):
        callback, receipt = self.uninstall_handoff()
        original = receipt.read_bytes()
        values = json.loads((self.root / 'settings.json').read_text())
        values['angle_gl_driver_selection_values'] = 'native'
        (self.root / 'settings.json').write_text(json.dumps(values))
        result = self.recovery_callback(callback)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('preserved unknown or changed state', result.stderr)
        self.assertEqual(json.loads((self.root / 'settings.json').read_text()), values)
        self.assertEqual(receipt.read_bytes(), original)
        self.assertTrue(callback.exists())

    def test_uninstall_handoff_rejects_changed_helper_or_alias(self):
        callback, receipt = self.uninstall_handoff()
        helper = receipt.parent.parent / 'runtime.sh'
        original = helper.read_bytes()
        helper.write_bytes(original + b'\n# foreign change\n')
        self.assertNotEqual(self.recovery_callback(callback).returncode, 0)
        helper.write_bytes(original)
        external = self.root / 'foreign-helper'
        helper.rename(external)
        helper.symlink_to(external)
        self.assertNotEqual(self.recovery_callback(callback).returncode, 0)
        self.assertTrue(helper.is_symlink())
        self.assertTrue(receipt.exists())
        self.assertTrue(callback.exists())

    def test_uninstall_handoff_preserves_active_reinstallation(self):
        callback, receipt = self.uninstall_handoff()
        self.module.mkdir()
        (self.module / 'module.prop').write_text('id=hyperos_avd_app_compat\nauthor=HyperOS-AVD\n')
        values = (self.root / 'settings.json').read_bytes()
        result = self.recovery_callback(callback)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / 'settings.json').read_bytes(), values)
        self.assertTrue(receipt.exists())
        (self.module / 'disable').touch()
        result = self.recovery_callback(callback)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(callback.exists())

    def test_recovery_paths_and_callback_source_reject_noncanonical_values(self):
        for suffix in ('/not-created/..', '/not-created/.', '//child', '/child/', "/quo'te", '/pipe|x', '/amp&x', '/line\nbreak'):
            path = str(self.root) + suffix
            result = self.shell('catalog_recovery_dir ' + shlex.quote(path), check=False)
            self.assertNotEqual(result.returncode, 0, path)
        self.shell('BB="$BB&foreign"\ncatalog_recovery_emit /data/ok /data/callback ' + ' '.join(['0' * 64] * 4) + ' && exit 1\nexit 0')

    def test_uninstall_handoff_rejects_undiscoverable_or_module_internal_overrides(self):
        self.recipes[0]['policy'] = {'angle': {'driver': 'angle', 'features': []}}
        self.publish_catalog()
        self.shell('catalog_pass late')
        (self.bin / 'getprop').write_text((self.bin / 'getprop').read_text().replace('sys.boot_completed) echo 1', 'sys.boot_completed) echo 0'))
        for root in (self.module, self.module / 'contexts', self.root / 'unknown-service-parent'):
            result = self.shell('HYPEROS_APP_COMPAT_RECOVERY_DIR=' + shlex.quote(str(root)) + '\ncatalog_uninstall', check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('preserved unknown state', result.stderr)
        self.env.pop('HYPEROS_APP_COMPAT_TEST_ROOT')
        result = self.shell('catalog_uninstall', check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'service').exists())

    def test_uninstall_handoff_rejects_production_busybox_override_before_path_access(self):
        self.recipes[0]['policy'] = {'angle': {'driver': 'angle', 'features': []}}
        self.publish_catalog()
        self.shell('catalog_pass late')
        self.env.pop('HYPEROS_APP_COMPAT_TEST_ROOT')
        self.env['HYPEROS_APP_COMPAT_RECOVERY_DIR'] = '/data/adb/hyperos_app_compat/restore'
        self.env['HYPEROS_APP_COMPAT_SERVICE_DIR'] = '/data/adb/service.d'
        result = self.shell('catalog_recovery_dir() { echo reached > "$BRIDGE_TEST_ROOT/path-access"; return 1; }\nMODDIR="$OWNERDIR/contexts/first"\ncatalog_angle_handoff', check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'path-access').exists())

    def test_archive_and_recipe_aliases_are_rejected_without_guessing(self):
        self.second()
        unknown = copy.deepcopy(self.recipes)
        unknown[0]['native_libraries'] = []
        with self.assertRaisesRegex(RuntimeError, 'dependency'):
            catalog.validate(unknown)
        unknown = copy.deepcopy(self.recipes)
        unknown[1]['feature'] = 'weather'
        with self.assertRaisesRegex(RuntimeError, 'one package'):
            catalog.validate(unknown)
        control = self.module / 'contexts/first/embedded.tsv'
        alias = self.root / 'alias'
        alias.write_bytes(control.read_bytes())
        control.unlink()
        control.symlink_to(alias)
        self.assertNotEqual(self.shell('catalog_pass late', check=False).returncode, 0)
        self.assertEqual(self.mounts(), {})

    def test_shell_verified_paths_admit_provider_names_and_reject_all_traversal(self):
        self.shell('bridge_path /vendor/bin/hw/android.hardware.camera.provider@2.7-service-google || exit 1\nfor path in /data/app/pkg/.. /data/app/pkg/. /data/app/pkg/../base.apk /data/app//pkg/base.apk /data/app/pkg/; do\n bridge_path "$path" && exit 1\ndone\nexit 0')

    def test_prebuilt_consumer_stages_only_verified_complete_archive_and_preserves_flags(self):
        workspace = self.root / 'workspace'
        folder = workspace / 'tools/os4-app-compat'
        folder.mkdir(parents=True)
        receipt = catalog.package_catalog(folder / 'app-compat.zip', self.recipes, self.outputs)
        (folder / 'receipt.json').write_bytes(catalog.canonical(receipt))
        archive, manifest = catalog.verify_prebuilt(folder, self.recipes)
        commands = []

        def root(config, command):
            commands.append(command)
            if command.startswith('getprop'):
                return 'ranchu\narm64-v8a'
            return ''
        with patch.object(consumer, 'root', side_effect=root), patch.object(consumer, '_inspect', return_value=None), patch.object(consumer, 'adb') as adb:
            result = consumer.install_prebuilt({}, workspace, catalog=self.recipes, migration=False)
        self.assertTrue(result['reboot_required'])
        self.assertEqual(adb.call_count, 1)
        self.assertTrue(any(('ksud module install' in command for command in commands)))
        self.assertFalse(any(('am force-stop' in command or 'nsenter' in command for command in commands)))
        (folder / 'app-compat.zip').unlink()
        with patch.object(consumer, 'root', return_value='ranchu\narm64-v8a'), patch.object(consumer, '_inspect', return_value={'flags': ['disable']}), patch.object(consumer, 'adb') as adb:
            result = consumer.install_prebuilt({}, workspace, catalog=self.recipes, migration=False)
            self.assertTrue(result['preserved'])
            adb.assert_not_called()

    def test_reviewed_universal_history_authorizes_old_bytes_and_normal_update_only(self):
        old_folder = self.root / 'old-prebuilt'
        old_folder.mkdir()
        saved = catalog.package_catalog(old_folder / 'app-compat.zip', self.recipes, self.outputs)
        (old_folder / 'receipt.json').write_bytes(catalog.canonical(saved))
        _, old = catalog.verify_prebuilt(old_folder, self.recipes)
        pin = digest(catalog.canonical(old))
        self.second()
        workspace = self.root / 'next-workspace'
        folder = workspace / 'tools/os4-app-compat'
        folder.mkdir(parents=True)
        current = catalog.package_catalog(folder / 'app-compat.zip', self.recipes, self.outputs)
        (folder / 'receipt.json').write_bytes(catalog.canonical(current))
        active = {'directory': '/data/adb/modules/' + catalog.MODULE_ID, 'properties': 'known ownership', 'flags': []}
        commands = []

        def root(config, command):
            commands.append(command)
            return 'ranchu\narm64-v8a' if command.startswith('getprop') else ''

        def saved(config, module, expected):
            if expected != old:
                raise consumer.CatalogMismatch('Current content differs from prior release')
        with patch.object(catalog, 'PREVIOUS_MANIFESTS', {pin: old}):
            self.assertEqual(catalog.verify_previous_prebuilt(old_folder), old)
            with patch.object(consumer, 'root', side_effect=root), patch.object(consumer, '_inspect', side_effect=[active, None]), patch.object(consumer, '_saved', side_effect=saved), patch.object(consumer, 'adb') as adb:
                result = consumer.install_prebuilt({}, workspace, catalog=self.recipes, migration=False)
                self.assertTrue(result['reboot_required'])
                adb.assert_called_once()
            self.assertTrue(any(('ksud module install' in command for command in commands)))
            self.assertFalse(any(('rm -rf' in command or 'mv /data/adb/modules_update' in command for command in commands)))
        with self.assertRaisesRegex(RuntimeError, 'Unknown previous'):
            catalog.verify_previous_prebuilt(old_folder)

    def test_pending_unknown_catalog_and_preexisting_feature_choices_are_preserved(self):
        workspace = self.root / 'workspace'
        folder = workspace / 'tools/os4-app-compat'
        folder.mkdir(parents=True)
        saved = catalog.package_catalog(folder / 'app-compat.zip', self.recipes, self.outputs)
        (folder / 'receipt.json').write_bytes(catalog.canonical(saved))
        pending = {'directory': '/data/adb/modules_update/' + catalog.MODULE_ID, 'flags': []}
        with patch.object(consumer, 'root', return_value='ranchu\narm64-v8a'), patch.object(consumer, '_inspect', side_effect=[None, pending]), patch.object(consumer, '_saved', side_effect=consumer.CatalogMismatch('Unknown pending')), patch.object(consumer, 'adb') as adb, patch.object(consumer, 'set_features') as choices:
            result = consumer.install_prebuilt({}, workspace, enabled_features={'weather': False}, catalog=self.recipes, migration=False)
            self.assertTrue(result['deferred'])
            adb.assert_not_called()
            choices.assert_not_called()
        with self.assertRaisesRegex(RuntimeError, 'choice'):
            consumer.set_features({}, {'weather': 1}, self.recipes)

    def test_full_production_catalog_asset_check_is_bounded_and_authenticates_every_file(self):
        from app_compat_producers import recipes
        complete = json.loads(catalog.catalog_files(recipes())['manifest.json'])
        directory = '/data/adb/modules/' + catalog.MODULE_ID
        command = consumer._authentication_command(directory, complete)
        self.assertLess(len(command.encode()), 16 * 1024)
        self.assertEqual(command.count('[ -d "$parent" ] && [ ! -L "$parent" ]'), 1)
        names = set(complete['files_sha256']) - {'customize.sh'} | {'manifest.json', 'SHA256SUMS'}
        table = command.split("done <<'HYPEROS_CANONICAL_APP_ASSETS'\n", 1)[1].rsplit('\nHYPEROS_CANONICAL_APP_ASSETS', 1)[0]
        actual = {line.split(' ', 1)[1] for line in table.splitlines()}
        self.assertEqual(actual, names)
        self.assertIn('stat -c %h:%u "$path"', command)
        self.assertIn('[ -f "$path" ] && [ ! -L "$path" ]', command)
        self.assertIn('sha256sum "$path"', command)

    def test_catalog_asset_mismatch_and_adb_transport_failures_are_distinct(self):
        expected = json.loads(catalog.catalog_files(self.recipes, self.outputs)['manifest.json'])
        module = {'directory': '/data/adb/modules/' + catalog.MODULE_ID}
        closed = RuntimeError('Flutter overlay command failed: error: closed')
        with patch.object(consumer, 'root', side_effect=closed):
            with self.assertRaises(RuntimeError) as caught:
                consumer._saved({}, module, expected)
            self.assertIs(caught.exception, closed)
        rejection = RuntimeError('Flutter overlay command failed: ' + consumer.MISMATCH_MARKER + ':/data/adb/module/runtime.sh')
        with patch.object(consumer, 'root', side_effect=rejection):
            with self.assertRaises(consumer.CatalogMismatch):
                consumer._saved({}, module, expected)

    def test_compact_asset_checker_executes_and_rejects_real_aliases_and_changed_bytes(self):
        expected = json.loads(catalog.catalog_files(self.recipes, self.outputs)['manifest.json'])
        for command in ('stat', 'sha256sum'):
            wrapper = self.bin / command
            wrapper.write_text('#!/bin/sh\nexec "$HYPEROS_BRIDGE_BB" ' + command + ' "$@"\n')
            wrapper.chmod(493)

        def root(config, command):
            result = subprocess.run(['sh', '-c', command], env=self.env, text=True, capture_output=True, timeout=30)
            if result.returncode:
                raise RuntimeError('Guest validation failed: ' + result.stdout + result.stderr)
            return result.stdout
        module = {'directory': str(self.module)}
        with patch.object(consumer, 'root', side_effect=root):
            consumer._saved({}, module, expected)
            target = self.module / 'contexts/first/package.txt'
            original = target.read_bytes()
            target.write_bytes(b'unknown local package\n')
            with self.assertRaises(consumer.CatalogMismatch):
                consumer._saved({}, module, expected)
            target.write_bytes(original)
            self.metadata(target, owner='1000:1000')
            with self.assertRaises(consumer.CatalogMismatch):
                consumer._saved({}, module, expected)
            self.metadata(target, owner='0:0')
            self.metadata(target.parent, owner='1000:1000')
            with self.assertRaises(consumer.CatalogMismatch):
                consumer._saved({}, module, expected)
            self.metadata(target.parent, owner='0:0')
            alias = self.root / 'hardlink'
            os.link(target, alias)
            with self.assertRaises(consumer.CatalogMismatch):
                consumer._saved({}, module, expected)

if __name__ == '__main__':
    unittest.main()


# --- tests/test_app_compat_migration.py ---

'Exercise authenticated migration against a local shell guest filesystem.'

REAL_MARKER = migration._marker

def checksum(body):
    return hashlib.sha256(body).hexdigest()

class HistoricalReceiptTests(unittest.TestCase):

    def test_frozen_catalog_is_independent_of_current_templates_and_complete(self):
        values = migration.records()
        self.assertEqual({record['id'] for record in values}, set(migration.MODULES))
        bridges = [record for record in values if record['feature'] != 'oem-camera']
        self.assertEqual(len(bridges), 3)
        for record in bridges:
            self.assertEqual(record['manifest']['revision'], 2)
            self.assertEqual(record['hashes']['runtime.sh'], '84b37d80cbbe7633e4b5debabf694a3252e7e1b8ac1b85f7f979e6b5c71dd59a')
            self.assertEqual(record['manifest']['files_sha256']['runtime.sh'], record['hashes']['runtime.sh'])
            self.assertIn('SHA256SUMS', record['hashes'])
            self.assertTrue(any((name.startswith('payloads/') for name in record['hashes'])))
        cameras = [record for record in values if record['feature'] == 'oem-camera']
        self.assertEqual(len({record['hashes']['app/MiuiCamera.apk'] for record in cameras}), 3)
        self.assertEqual(len({record['hashes']['app/lib/arm64/libcamera_yuv_jni.so'] for record in cameras}), 2)
        for record in cameras:
            self.assertIn('provider', record['hashes'])
            self.assertIn('hwl.so', record['hashes'])
            self.assertIn('post-fs-data.sh', record['hashes'])
            self.assertIn('service.sh', record['hashes'])

    def test_real_full_union_and_each_legacy_guard_fit_one_adb_command(self):
        from app_compat_catalog import MODULE_ID, catalog_files, canonical
        from app_compat_producers import recipes
        files = catalog_files(recipes())
        manifest = json.loads(files['manifest.json'])
        hashes = {name: value for name, value in manifest['files_sha256'].items() if name != 'customize.sh'}
        hashes['manifest.json'] = checksum(canonical(manifest))
        hashes['SHA256SUMS'] = checksum(files['SHA256SUMS'])
        self.assertGreater(len(hashes), 70)
        self.assertEqual(len(manifest['recipes']), 6)
        self.assertEqual(sum((name.startswith('objects/') for name in hashes)), 11)
        active = {'directory': '/data/adb/modules/' + MODULE_ID, 'properties': files['module.prop'].decode(), 'flags': []}
        record = {'id': MODULE_ID, 'properties': active['properties'], 'hashes': hashes, 'optional_hashes': {'customize.sh': manifest['files_sha256']['customize.sh']}}
        for legacy in migration.records():
            with self.subTest(legacy=legacy['id'], assets=len(legacy['hashes'])):
                checked = set()
                old = {'directory': '/data/adb/modules/' + legacy['id'], 'properties': legacy['properties'], 'flags': []}
                guards = migration._checks(old, legacy, checked_parents=checked) + '\n' + migration._checks(active, record, checked_parents=checked)
                transport = 'su -W -c ' + shlex.quote('set -e\n' + guards)
                self.assertLess(len(transport.encode()), 24 * 1024)
                self.assertEqual(guards.count('[ -d /data ] && [ ! -L /data ] || exit 1'), 1)
                self.assertEqual(guards.count('[ -d /data/adb ] && [ ! -L /data/adb ] || exit 1'), 1)
                for name, value in hashes.items():
                    self.assertIn(name + ' ' + value + '\n', guards)
                self.assertIn('stat -c %h:%u "$path"', guards)

    def test_receipt_table_rejects_empty_or_injected_hashes_and_paths(self):
        for name, hashes in (('payloads/a.so', []), ('payloads/a.so', ['x']), ('payloads/a.so', [None]), ('payloads/../a.so', ['0' * 64]), ('payloads/a\n.so', ['0' * 64])):
            with self.subTest(name=name, hashes=hashes), self.assertRaises(RuntimeError):
                migration._asset_path('/data/adb/modules/audited', name, hashes)

class AppCompatMigrationTests(unittest.TestCase):

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.data = self.base / 'data'
        (self.data / 'adb/modules').mkdir(parents=True)
        (self.data / 'adb/modules_update').mkdir()
        self.bin = self.base / 'bin'
        self.bin.mkdir()
        (self.bin / 'stat').write_text(f"#!{sys.executable}\nimport os,sys\ns=os.stat(sys.argv[-1]); value=sys.argv[sys.argv.index('-c')+1]\nprint(value.replace('%h',str(s.st_nlink)).replace('%u','0').replace('%d',str(s.st_dev)).replace('%i',str(s.st_ino)))\n")
        (self.bin / 'sha256sum').write_text(f"#!{sys.executable}\nimport hashlib,sys\nfor name in sys.argv[1:]:\n print(hashlib.sha256(open(name,'rb').read()).hexdigest()+'  '+name)\n")
        for path in self.bin.iterdir():
            path.chmod(493)
        self.calls = []
        self.registry = []
        self.catalog = [{'feature': name} for name in ('weather', 'oem-camera', 'parrot-camera')]
        self.stack = ExitStack()
        self.stack.enter_context(patch.object(migration, 'records', lambda: self.registry))
        for module in (migration, app_bridge_module, apply_app_compat):
            self.stack.enter_context(patch.object(module, 'root', self.root))
        self.stack.enter_context(patch.object(migration, '_marker', return_value=None))
        self.owner_manifest = None

    def tearDown(self):
        self.stack.close()
        self.temporary.cleanup()

    def root(self, config, command):
        self.calls.append(command)
        translated = command.replace('/data', str(self.data))
        env = {**os.environ, 'PATH': str(self.bin) + ':' + os.environ['PATH']}
        result = subprocess.run(['sh', '-e', '-c', translated], env=env, capture_output=True, text=True)
        if result.returncode:
            raise subprocess.CalledProcessError(result.returncode, command, result.stdout, result.stderr)
        return result.stdout.strip()

    def create_old(self, identifier, flags=()):
        feature = migration.MODULES[identifier]
        folder = self.data / 'adb/modules' / identifier
        folder.mkdir()
        props = f'id={identifier}\nname=Audited fixture\nversion=2\nversionCode=2\nauthor=HyperOS-AVD\ndescription=Fixture\n'
        manifest = {'id': identifier, 'revision': 2, 'fixture': 'canonical'}
        assets = {'module.prop': props.encode(), 'manifest.json': (json.dumps(manifest) + '\n').encode(), 'runtime.sh': b'#!/system/bin/sh\nexit 0\n', 'service.sh': b'#!/system/bin/sh\nexit 0\n', 'payloads/helper.so': b'original audited binary'}
        for name, body in assets.items():
            path = folder / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
        for flag in flags:
            (folder / flag).touch()
        self.registry.append({'id': identifier, 'feature': feature, 'manifest': manifest, 'properties': props, 'hashes': {name: checksum(body) for name, body in assets.items()}})
        return folder

    def create_active(self, full_catalog=False):
        identifier = 'hyperos_avd_app_compat'
        folder = self.data / 'adb/modules' / identifier
        folder.mkdir()
        props = f'id={identifier}\nname=Universal\nversion=1\nversionCode=1\nauthor=HyperOS-AVD\ndescription=Fixture\n'
        assets = {'module.prop': props.encode(), 'runtime.sh': b'new runtime', 'objects/helper.bin': b'new binary', 'customize.sh': b'install control'}
        manifest = {'revision': 1, 'files_sha256': {name: checksum(body) for name, body in assets.items()}}
        if full_catalog:
            from app_compat_catalog import catalog_files
            from app_compat_producers import recipes
            assets = catalog_files(recipes())
            manifest = json.loads(assets.pop('manifest.json'))
            assets.pop('SHA256SUMS')
            for name in manifest['files_sha256']:
                if name not in assets:
                    assets[name] = ('binary fixture ' + name).encode()
            manifest['files_sha256'] = {name: checksum(body) for name, body in assets.items()}
            props = assets['module.prop'].decode()
        body = apply_app_compat.canonical(manifest)
        hashes = {name: value for name, value in manifest['files_sha256'].items() if name != 'customize.sh'}
        hashes['manifest.json'] = checksum(body)
        assets['manifest.json'] = body
        assets['SHA256SUMS'] = ''.join((value + '  ' + name + '\n' for name, value in sorted(hashes.items()))).encode()
        for name, contents in assets.items():
            if name == 'customize.sh':
                continue
            path = folder / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(contents)
        self.stack.enter_context(patch('app_compat_catalog.catalog_files', return_value={'module.prop': props.encode(), 'manifest.json': body}))
        self.owner_manifest = manifest
        return folder

    def plan(self):
        return migration.plan({}, self.catalog, workspace=self.base)

    def snapshot(self):
        return {str(path.relative_to(self.data)): path.read_bytes() for path in self.data.rglob('*') if path.is_file()}

    def test_plan_is_read_only_and_imports_only_authenticated_optins(self):
        self.create_old('hyperos_avd_xiaomi_camera')
        self.create_old('hyperos_avd_parrot_camera')
        before = self.snapshot()
        planned = self.plan()
        self.assertEqual(planned['choices'], {'oem-camera': True, 'parrot-camera': True})
        self.assertEqual(self.snapshot(), before)
        migration.import_choices({}, planned)
        self.assertEqual((self.data / 'adb/hyperos_app_compat/features/oem-camera').read_text(), 'on\n')
        self.assertEqual((self.data / 'adb/hyperos_app_compat/features/parrot-camera').read_text(), 'on\n')
        self.assertFalse(any(('mv /data/adb/modules/' in command for command in self.calls)))

    def test_disabled_owner_is_preserved_and_imports_off(self):
        folder = self.create_old('hyperos_avd_weather_gl', ('disable',))
        planned = self.plan()
        self.assertEqual(planned['choices'], {'weather': False})
        self.assertEqual(planned['modules'], [])
        migration.import_choices({}, planned)
        self.assertTrue((folder / 'disable').exists())
        self.assertEqual((self.data / 'adb/hyperos_app_compat/features/weather').read_text(), 'off\n')

    def test_broken_lifecycle_alias_is_preserved_and_imports_off(self):
        folder = self.create_old('hyperos_avd_weather_gl')
        (folder / 'disable').symlink_to('/missing-user-choice')
        planned = self.plan()
        self.assertEqual(planned['choices'], {'weather': False})
        self.assertEqual(planned['modules'], [])
        migration.import_choices({}, planned)
        self.assertTrue((folder / 'disable').is_symlink())
        self.assertEqual((self.data / 'adb/hyperos_app_compat/features/weather').read_text(), 'off\n')

    def test_pending_payload_changes_and_extra_entrypoints_are_preserved(self):
        for kind in ('pending', 'payload', 'control', 'custom'):
            with self.subTest(kind=kind):
                folder = self.create_old('hyperos_avd_weather_gl')
                if kind == 'pending':
                    (self.data / 'adb/modules_update/hyperos_avd_weather_gl').mkdir()
                elif kind == 'payload':
                    (folder / 'payloads/helper.so').write_bytes(b'foreign binary')
                elif kind == 'control':
                    (folder / 'runtime.sh').write_bytes(b'foreign control')
                else:
                    (folder / 'action.sh').write_bytes(b'custom action')
                before = self.snapshot()
                planned = self.plan()
                self.assertEqual(planned['choices'], {})
                self.assertEqual(planned['modules'], [])
                self.assertEqual(len(planned['preserved']), 1)
                self.assertEqual(self.snapshot(), before)
                shutil.rmtree(folder)
                pending = self.data / 'adb/modules_update/hyperos_avd_weather_gl'
                if pending.exists():
                    pending.rmdir()
                self.registry.clear()

    def test_existing_and_concurrent_new_feature_choices_win(self):
        self.create_old('hyperos_avd_parrot_camera')
        planned = self.plan()
        path = self.data / 'adb/hyperos_app_compat/features/parrot-camera'
        path.parent.mkdir(parents=True)
        path.write_text('auto\n')
        migration.import_choices({}, planned)
        self.assertEqual(path.read_text(), 'auto\n')
        self.assertEqual(self.plan()['choices'], {})

    def test_changed_old_payload_after_plan_never_imports_a_choice(self):
        folder = self.create_old('hyperos_avd_xiaomi_camera')
        planned = self.plan()
        (folder / 'payloads/helper.so').write_bytes(b'changed after plan')
        migration.import_choices({}, planned)
        self.assertFalse((self.data / 'adb/hyperos_app_compat/features').exists())

    def test_compact_table_preserves_exact_alternatives_and_single_link_guards(self):
        old = self.create_old('hyperos_avd_weather_gl')
        payload = old / 'payloads/helper.so'
        original = checksum(payload.read_bytes())
        alternative = b'second audited representation'
        self.registry[0]['allowed_hashes'] = {'payloads/helper.so': [original, checksum(alternative)]}
        payload.write_bytes(alternative)
        self.assertEqual(self.plan()['choices'], {'weather': True})
        payload.write_bytes(alternative + b'foreign suffix')
        self.assertEqual(self.plan()['choices'], {})
        payload.write_bytes(alternative)
        alias = self.base / 'linked-original'
        os.link(payload, alias)
        self.assertEqual(self.plan()['choices'], {})
        self.assertEqual(payload.stat().st_nlink, 2)

    def test_host_marker_requires_exact_dynamic_caller_and_never_authorizes_retirement(self):
        apk = '/data/app/~~ABC/com.google.android.GoogleCamera.parrot-XYZ/base.apk'
        native = str(Path(apk).parent / 'lib/arm64')
        folder = self.data / Path(apk).relative_to('/data')
        folder.parent.mkdir(parents=True)
        folder.write_bytes(b'caller APK')
        library = self.data / Path(native + '/libgcastartup.so').relative_to('/data')
        library.parent.mkdir(parents=True)
        library.write_bytes(b'native caller')
        metadata = {'revision': 3, 'module': parrot.MODULE_ID, 'package': parrot.PACKAGE, 'apk_sha256': checksum(b'caller APK'), 'runtime_sha256': parrot.RUNTIME_SHA256, 'source_sha256': parrot.BRIDGE_SOURCE_SHA256, 'sha256': parrot.BRIDGE_SHA256, 'experimental': True}
        path = self.base / 'local/camera-fix.json'
        path.parent.mkdir()
        path.write_text(json.dumps(metadata))
        catalog = [{'feature': 'parrot-camera', 'apk_sha256': metadata['apk_sha256'], 'native_libraries': {'libgcastartup.so': checksum(b'native caller')}}]

        def caller_root(config, command):
            if command == 'pm path ' + parrot.PACKAGE:
                return 'package:' + apk
            if command == 'dumpsys package ' + parrot.PACKAGE:
                return '  nativeLibraryDir=' + native
            return self.root(config, command)
        with patch.object(parrot, 'APK_SHA256', metadata['apk_sha256']), patch.object(migration, 'root', caller_root):
            marker = REAL_MARKER({}, self.base, catalog)
            self.assertEqual(marker['sha256'], checksum(path.read_bytes()))
            library.write_bytes(b'changed caller')
            self.assertIsNone(REAL_MARKER({}, self.base, catalog))
        self.assertFalse((self.data / 'adb/hyperos_app_compat').exists())
        self.assertEqual(list((self.data / 'adb/modules').iterdir()), [])

    def test_retirement_requires_active_owner_and_preserves_all_loaded_inodes(self):
        old = self.create_old('hyperos_avd_parrot_camera')
        planned = self.plan()
        active = self.create_active()
        pending = self.data / 'adb/modules_update/hyperos_avd_app_compat'
        pending.mkdir()
        result = migration.retire({}, planned, self.owner_manifest)
        self.assertTrue(result['deferred'])
        self.assertTrue(old.exists())
        pending.rmdir()
        inode = old.stat().st_ino
        payload_inode = (old / 'payloads/helper.so').stat().st_ino
        result = migration.retire({}, planned, self.owner_manifest)
        self.assertTrue(result['reboot_required'])
        self.assertEqual(result['retired'], ['hyperos_avd_parrot_camera'])
        self.assertFalse(old.exists())
        archived = next((self.data / 'adb/hyperos_app_compat/legacy').iterdir())
        self.assertEqual(archived.stat().st_ino, inode)
        self.assertEqual((archived / 'payloads/helper.so').stat().st_ino, payload_inode)
        self.assertTrue(active.exists())
        for command in self.calls:
            self.assertNotIn('umount', command)
            self.assertNotIn('module uninstall', command)
            self.assertFalse(re.search('(^|\\n)(stop |start |am force-stop)', command))

    def test_current_universal_revision_reuses_through_public_path_with_empty_migration(self):
        from app_compat_catalog import REVISION
        self.assertGreaterEqual(REVISION, 3)
        self.create_active(full_catalog=True)
        before = self.snapshot()

        def public_root(config, command):
            if command.startswith('getprop'):
                return 'ranchu\narm64-v8a'
            return self.root(config, command)
        with patch.object(apply_app_compat, 'root', side_effect=public_root), patch.object(apply_app_compat, 'verify_prebuilt', return_value=(self.base / 'verified.zip', self.owner_manifest)), patch.object(apply_app_compat, 'adb') as adb:
            result = apply_app_compat.install_prebuilt({}, workspace=self.base, catalog=self.catalog, migration=migration)
        self.assertTrue(result['reused'])
        self.assertFalse(result['pending'])
        self.assertFalse(result['reboot_required'])
        self.assertEqual(result['migration'], {'retired': [], 'reboot_required': False})
        self.assertEqual(self.snapshot(), before)
        adb.assert_not_called()

    def test_current_owner_exact_revision_and_full_assets_remain_required(self):
        old = self.create_old('hyperos_avd_parrot_camera')
        planned = self.plan()
        active = self.create_active(full_catalog=True)
        props = active / 'module.prop'
        original = props.read_text()
        props.write_text(re.sub('versionCode=\\d+', 'versionCode=999', original))
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, 'Unknown private bridge module revision'):
            migration.retire({}, planned, self.owner_manifest)
        self.assertEqual(self.snapshot(), before)
        self.assertTrue(old.exists())
        props.write_text(original)
        asset = active / 'webroot/app.js'
        asset.write_bytes(b'unknown local bytes in the exact current revision')
        before = self.snapshot()
        with self.assertRaises(subprocess.CalledProcessError):
            migration.retire({}, planned, self.owner_manifest)
        self.assertEqual(self.snapshot(), before)
        self.assertTrue(old.exists())
        self.assertFalse((self.data / 'adb/hyperos_app_compat/legacy').exists())

    def test_new_lifecycle_flag_and_old_inode_replacement_prevent_retirement(self):
        old = self.create_old('hyperos_avd_xiaomi_camera')
        planned = self.plan()
        active = self.create_active()
        (active / 'disable').touch()
        self.assertTrue(migration.retire({}, planned, self.owner_manifest)['deferred'])
        (active / 'disable').unlink()
        other = old.with_name('replacement')
        shutil.copytree(old, other)
        shutil.rmtree(old)
        other.rename(old)
        self.assertEqual(migration.retire({}, planned, self.owner_manifest)['retired'], [])
        self.assertTrue(old.exists())

    def test_archive_alias_refuses_rename_and_preserves_old_contents(self):
        old = self.create_old('hyperos_avd_weather_gl')
        planned = self.plan()
        self.create_active()
        archive = self.data / 'adb/hyperos_app_compat/legacy'
        archive.parent.mkdir()
        foreign = self.base / 'foreign'
        foreign.mkdir()
        archive.symlink_to(foreign)
        with self.assertRaises(subprocess.CalledProcessError):
            migration.retire({}, planned, self.owner_manifest)
        self.assertTrue(old.exists())
        self.assertEqual(list(foreign.iterdir()), [])

    def test_full_union_retirement_bound_rechecks_late_asset_before_rename(self):
        old = self.create_old('hyperos_avd_parrot_camera')
        planned = self.plan()
        active = self.create_active(full_catalog=True)
        asset = active / 'webroot/app.js'
        original = asset.read_bytes()
        real_active_owner = migration._active_owner
        calls = 0

        def mutate_after_authentication(config, expected, catalog):
            nonlocal calls
            result = real_active_owner(config, expected, catalog)
            calls += 1
            if calls == 2:
                asset.write_bytes(b'changed after active authentication')
            return result
        with patch.object(migration, '_active_owner', mutate_after_authentication), self.assertRaises(subprocess.CalledProcessError):
            migration.retire({}, planned, self.owner_manifest)
        self.assertTrue(old.exists())
        archive_command = self.calls[-1]
        self.assertIn('mv /data/adb/modules/hyperos_avd_parrot_camera', archive_command)
        self.assertLess(len(('su -W -c ' + shlex.quote(archive_command)).encode()), 24 * 1024)
        asset.write_bytes(original)
        self.assertEqual(migration.retire({}, planned, self.owner_manifest)['retired'], ['hyperos_avd_parrot_camera'])

    def test_optional_nested_assets_preserve_missing_directories_and_reject_aliases(self):
        old = self.create_old('hyperos_avd_weather_gl')
        optional = b'optional audited contents'
        self.registry[0]['optional_hashes'] = {'optional/helper.so': checksum(optional)}
        self.assertEqual(self.plan()['choices'], {'weather': True})
        foreign = self.base / 'optional-foreign'
        foreign.mkdir()
        (foreign / 'helper.so').write_bytes(optional)
        (old / 'optional').symlink_to(foreign)
        self.assertEqual(self.plan()['choices'], {})
        self.assertTrue((old / 'optional').is_symlink())

if __name__ == '__main__':
    unittest.main()


# --- tests/test_app_compat_producers.py ---

'Verify the universal producer union and its owned, compiler-free inputs.'

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
        self.assertEqual({row['apk_sha256'] for row in cameras}, {*camera_a.CAMERA_VERSIONS, camera_b.APK_HASH})
        self.assertEqual({row['apk_libraries'][producer.CAMERA_ENTRY] for row in cameras}, {camera_a.YUV_HASH, camera_b.YUV_BEFORE})
        self.assertEqual(len({json.dumps(row['system_targets'], sort_keys=True) for row in cameras}), 1)
        self.assertEqual([row['default_enabled'] for row in cameras].count(True), 1)
        self.assertEqual(next((row for row in cameras if row['default_enabled']))['apk_sha256'], camera_b.APK_HASH)
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
        self.assertEqual(set(producer.CAMERA_FACTORY_PASSTHROUGH), {*camera_a.CAMERA_VERSIONS, camera_b.APK_HASH})
        expected_paths = {'oat/arm64/MiuiCamera.odex', 'oat/arm64/MiuiCamera.vdex'}
        for row in cameras:
            self.assertTrue(row['factory_overlay'])
            self.assertEqual(row['factory_passthrough'], producer.CAMERA_FACTORY_PASSTHROUGH[row['apk_sha256']])
            self.assertEqual(set(row['factory_passthrough']), expected_paths)
            for checksum in row['factory_passthrough'].values():
                self.assertRegex(checksum, '^[0-9a-f]{64}$')
        self.assertTrue(all(('factory_passthrough' not in row for row in values if row['feature'] != 'oem-camera')))
        outputs = {target['after'] for row in values for target in [*row['libraries'], *row['system_targets']]}
        self.assertEqual(len(outputs), 11)
        self.assertFalse(outputs & {value for row in cameras for value in row['factory_passthrough'].values()})
        cameras[0]['factory_passthrough']['oat/arm64/MiuiCamera.odex'] = '0' * 64
        self.assertNotEqual(producer.recipes()[0]['factory_passthrough']['oat/arm64/MiuiCamera.odex'], '0' * 64)
        with self.assertRaisesRegex(RuntimeError, 'No audited OEM factory directory'):
            producer._camera_recipe('unknown', '0' * 64, camera_a.RUNTIME_HASH, camera_a.YUV_HASH, camera_a.PAYLOADS['yuv.so'], False)

    def test_packed_reader_supports_folded_product_and_rejects_split_extents(self):
        root = Path('/audited/renamed-workspace')
        part = {'name': 'system', 'size': 1024, 'extents': [(2, 0, 8, 0)]}
        with patch('packed_source.source_info', return_value=({}, root / 'images/system.img', '0' * 64, {})), patch('lp_image.read_lp', return_value=(4096, [part])), patch.object(producer, 'tool', return_value='/local/dump.erofs'), patch.object(producer.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'input')) as run:
            self.assertEqual(producer.PackedFiles().read(root, 'product', '/app/a/lib.so'), b'input')
            run.assert_called_once_with(['/local/dump.erofs', '--cat', '--offset=8192', '--path=/product/app/a/lib.so', str(root / 'images/system.img')], check=False, capture_output=True)
            part['extents'] = [(1, 0, 8, 0), (1, 0, 16, 0)]
            with self.assertRaisesRegex(RuntimeError, 'one verified linear'):
                producer.PackedFiles().read(root, 'product', '/app/a/lib.so')

class UniversalCameraReceiptTests(unittest.TestCase):

    def make_camera_a(self, folder):
        payloads = {name: digest(name.encode()) for name in ('provider', 'hwl.so', 'yuv.so')}
        inputs = camera_a.camera_inputs(profile('4.0.18.0.XFRCNXM'))
        manifest = {'revision': 2, 'experimental': True, **inputs, 'targets': [{'payload': name, 'target': target, 'before': before, 'after': payloads[name]} for name, target, before in (('provider', camera_a.PROVIDER, camera_a.PROVIDER_HASH), ('hwl.so', camera_a.HWL, camera_a.HWL_HASH))], 'yuv_sha256': payloads['yuv.so']}
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
            with patch.object(camera_b, 'SOURCES', {}), patch.object(camera_b, 'PAYLOADS', payloads), patch.object(camera_b, 'PROVIDER_AFTER', payloads['provider']), patch.object(camera_b, 'HWL_AFTER', payloads['hwl.so']), patch.object(camera_b, 'YUV_AFTER', payloads['yuv.so']):
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
        self.a, self.b = (self.base / 'renamed-a', self.base / 'unrelated-z')
        self.stack = ExitStack()
        self.data = {digest(data): data for data in (b'provider', b'hwl', b'jni-a', b'jni-b', b'allocator', b'bridge', b'egl', b'gles', b'weather-a-patched', b'weather-b-patched')}
        self.a_payloads = {name: digest(data) for name, data in (('provider', b'provider'), ('hwl.so', b'hwl'), ('yuv.so', b'jni-a'))}
        self.b_payloads = {**self.a_payloads, 'yuv.so': digest(b'jni-b')}
        for root, name, payloads in ((self.a, 'xiaomi-camera', self.a_payloads), (self.b, 'pad-camera-native', self.b_payloads)):
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
        for module, name, value in ((producer, '_source_pins', lambda: None), (camera_a, 'PAYLOADS', self.a_payloads), (camera_b, 'PAYLOADS', self.b_payloads), (camera_a, 'verify_universal_prebuilt', lambda folder: {}), (camera_b, 'verify_universal_prebuilt', lambda folder: {}), (producer.parrot, 'prebuilt_receipt', lambda: {}), (producer.parrot, 'BRIDGE_SHA256', digest(b'allocator')), (producer.weather, 'BRIDGE_SHA256', digest(b'bridge')), (producer.weather, 'ANGLE', {'libEGL_angle.so': digest(b'egl'), 'libGLESv2_angle.so': digest(b'gles')}), (producer.weather, 'APK_SHA256', digest(self.apks[0])), (producer.weather, 'PAD_APK_SHA256', digest(self.apks[1])), (producer.weather, 'LIBRARIES', {'libmgl.so': (digest(b'weather-a'), digest(b'weather-a-patched'))}), (producer.weather, 'PAD_LIBRARIES', {'libmgl.so': (digest(b'weather-b'), digest(b'weather-b-patched'))}), (producer.weather, 'patch', lambda name, data, libraries: data + b'-patched'), (producer, 'recipes', lambda: [{'libraries': [{'after': key} for key in self.data], 'system_targets': []}])):
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
        self.catalog, self.consumer = (catalog, consumer)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        payload = self.root / 'payload.so'
        payload.write_bytes(b'complete audited output')
        self.payloads = {digest(payload.read_bytes()): payload}
        first = {'id': 'first', 'feature': 'weather', 'package': 'com.fixture.app', 'default_enabled': True, 'apk_sha256': digest(b'original signed APK'), 'libraries': [{'name': 'libtest.so', 'before': digest(b'input'), 'after': digest(payload.read_bytes())}]}
        self.previous = [first]
        self.current = [first, {**first, 'id': 'second', 'apk_sha256': digest(b'another signed APK')}]
        self.cache = self.root / 'verified-cache'
        self.cached = self.write_prebuilt(self.cache, self.current)
        self.workspace = self.root / 'release'
        self.destination = self.write_prebuilt(self.workspace, self.previous)
        with zipfile.ZipFile(self.destination / 'app-compat.zip') as archive:
            old = json.loads(archive.read('manifest.json'))
        mocked = patch.object(catalog, 'PREVIOUS_MANIFESTS', {digest(catalog.canonical(old)): old})
        mocked.start()
        self.addCleanup(mocked.stop)
        mocked = patch.object(consumer, 'recipes', return_value=self.current)
        mocked.start()
        self.addCleanup(mocked.stop)
        self.collect = patch.object(producer, 'collect_payloads', return_value=self.payloads)
        self.collect_mock = self.collect.start()
        self.addCleanup(self.collect.stop)

    def write_prebuilt(self, workspace, recipes):
        folder = workspace / 'tools/os4-app-compat'
        folder.mkdir(parents=True)
        receipt = self.catalog.package_catalog(folder / 'app-compat.zip', recipes, self.payloads)
        (folder / 'receipt.json').write_bytes(self.catalog.canonical(receipt))
        return folder

    def contents(self, folder):
        return {name: (folder / name).read_bytes() for name in ('app-compat.zip', 'receipt.json')}

    def test_complete_explicit_prebuilt_replaces_reviewed_previous_without_native_caches(self):
        original = self.contents(self.cached)
        self.assertEqual(self.consumer.prepare_prebuilt(self.workspace, sdk='/no-ndk', cache_roots=[self.workspace, self.cache]), self.destination)
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
        result = self.consumer.prepare_prebuilt(self.workspace, sdk='/no-ndk', cache_roots=[self.workspace])
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
        with patch.object(self.consumer.shutil, 'copyfileobj') as copy, self.assertRaisesRegex(RuntimeError, 'Unknown files.*preserved'):
            self.consumer.prepare_prebuilt(self.workspace, cache_roots=[self.cache])
        self.assertEqual(extra.read_bytes(), b'user-owned extra content')
        self.assertEqual(self.contents(self.destination), before)
        copy.assert_not_called()
        self.collect_mock.assert_not_called()

    def test_extra_appearing_during_staging_blocks_previous_directory_replacement(self):
        import shutil
        original_copy, before = (shutil.copyfileobj, self.contents(self.destination))
        extra = self.destination / 'new-custom-directory'
        copied = []

        def copy(source, output):
            original_copy(source, output)
            copied.append(source.name)
            if len(copied) == 2:
                extra.mkdir()
                (extra / 'notes.txt').write_bytes(b'concurrent user content')
        with patch.object(self.consumer.shutil, 'copyfileobj', side_effect=copy), self.assertRaisesRegex(RuntimeError, 'Unknown files.*preserved'):
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
        source, before = (self.contents(self.cached), self.contents(self.destination))
        with self.assertRaises(RuntimeError):
            self.consumer.prepare_prebuilt(self.workspace, cache_roots=[self.cache])
        self.assertEqual(self.contents(self.cached), source)
        self.assertEqual(self.contents(self.destination), before)
        self.collect_mock.assert_not_called()

    def test_valid_source_change_after_copy_aborts_before_replacement(self):
        import shutil
        original_copy, before = (shutil.copyfileobj, self.contents(self.destination))
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
        with patch.object(self.consumer.shutil, 'copyfileobj', side_effect=copy), self.assertRaisesRegex(RuntimeError, 'changed during staging'):
            self.consumer.prepare_prebuilt(self.workspace, cache_roots=[self.cache])
        self.assertEqual(self.contents(self.destination), before)
        self.collect_mock.assert_not_called()
        self.assertEqual(list(self.destination.parent.glob('.app-compat-*')), [])

    def test_stage_corruption_and_publication_failure_preserve_previous_archive(self):
        import shutil
        original_copy, original_rename = (shutil.copyfileobj, Path.rename)
        before = self.contents(self.destination)

        def corrupt(source, output):
            original_copy(source, output)
            if source.name.endswith('app-compat.zip'):
                output.write(b'corrupt staged archive')
        with patch.object(self.consumer.shutil, 'copyfileobj', side_effect=corrupt), self.assertRaises(RuntimeError):
            self.consumer.prepare_prebuilt(self.workspace, cache_roots=[self.cache])
        self.assertEqual(self.contents(self.destination), before)

        def rename(path, target):
            if path.name.startswith('.app-compat-') and (not path.name.endswith('.previous')):
                raise OSError('Publication failed')
            return original_rename(path, target)
        with patch.object(Path, 'rename', rename), self.assertRaisesRegex(OSError, 'Publication failed'):
            self.consumer.prepare_prebuilt(self.workspace, cache_roots=[self.cache])
        self.assertEqual(self.contents(self.destination), before)
        self.collect_mock.assert_not_called()
        self.assertEqual(list(self.destination.parent.glob('.app-compat-*')), [])

if __name__ == '__main__':
    unittest.main()
