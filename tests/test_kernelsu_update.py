"""Check offline KernelSU identity selection and preservation during upgrades."""
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
import zipfile
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import apply_flutter_fix
import apply_kernelsu_update as update
from common import KSU_ASSETS, KSU_VERSION
import kernelsu_release as release
import build_os4_official as phone_builder
import package_release
import patch_kernelsu
import launch
from patch_boot_services import signing_block

DAEMON = 'ksud-aarch64-linux-android'
CURRENT_DAEMON = release.ASSETS[DAEMON]
CURRENT_MANAGER = release.ASSETS[release.MANAGER]
LEGACY_DAEMON = KSU_ASSETS[DAEMON]
LEGACY_MANAGER = KSU_ASSETS[update.LEGACY_MANAGER]
ACTIVE = '/data/app/official-manager/base.apk'


def manager_certificates(data):
    """Read the pinned official APK's v2/v3 DER certificates without a SDK."""
    def field(body, offset=0):
        length, = struct.unpack_from('<I', body, offset)
        result = body[offset + 4:offset + 4 + length]
        if len(result) != length:
            raise AssertionError('Invalid certificate field bounds.')
        return result, offset + 4 + length
    block = signing_block(data)
    position, certificates = 8, set()
    while position < len(block) - 24:
        size, identifier = struct.unpack_from('<QI', block, position)
        value = block[position + 12:position + 8 + size]
        position += 8 + size
        if identifier not in (0x7109871a, 0xf05368c0):
            continue
        signers, _ = field(value)
        signer, _ = field(signers)
        signed, _ = field(signer)
        _, next_field = field(signed)
        certs, _ = field(signed, next_field)
        cert, _ = field(certs)
        certificates.add(hashlib.sha256(cert).hexdigest())
    return certificates


class CanonicalReleaseTests(unittest.TestCase):
    def test_current_names_pins_and_legacy_contract_are_independent(self):
        self.assertEqual((release.VERSION, release.CODE), ('v3.3.1', 32680))
        self.assertEqual(release.MANAGER, 'KernelSU_v3.3.1_32680-release.apk')
        self.assertEqual(release.MANAGER, f'KernelSU_{release.VERSION}_{release.CODE}-release.apk')
        self.assertEqual(release.DIRECTORY, 'kernelsu-' + release.VERSION)
        self.assertEqual(release.MANAGER_CERTIFICATE,
                         'c371061b19d8c7d7d6133c6a9bafe198fa944e50c1b31c9d8daa8d7f1fc2d2d6')
        self.assertEqual(CURRENT_DAEMON, '049491e2b4cc0a6c913d3920cb90b8c94c9e8ca96c0ee92818293304973bfb1b')
        self.assertEqual(CURRENT_MANAGER, 'b4a059ace71de2fa65cc7f12b1c58d55fc23ab25e057ee4230ce779742abe450')
        self.assertEqual(KSU_VERSION, 'v3.3.0')
        self.assertEqual(KSU_ASSETS, {
            'ksud-aarch64-apple-darwin': '40ca97a2fb61284129909abac5325dcae790736d9b88901f4f31cc7ec6d9a705',
            DAEMON: '8614de6cdc2233c71fd0d1c64381ea10fbe6658651bae9b5a8dab4fe08e6344b',
            release.LKM: 'c31d994aaf285e7bf4cf1ec38c2bbf2d7f303d1a4a7d616405bcd9f850d684e5',
            'lkm-aarch64-android16-6.12_kernelsu.ko': '877286f81d500c4ec546c96e9718c186b7379573c97ba5d5a35dd9a91465d076',
            update.LEGACY_MANAGER: 'c197060ecb89702e7d54a4c95e29cf5e8d97369bbbb436979ab7fd6bcde7b077',
        })

    def test_absent_current_assets_keep_legacy_bootstrap_without_network_or_guest(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(update, 'adb') as adb:
            root = Path(directory)
            self.assertFalse(release.available(root))
            self.assertEqual(update.bootstrap(root),
                             (root / 'tools' / DAEMON, root / 'tools' / update.LEGACY_MANAGER))
            self.assertEqual(update.install({}, root)['state'], 'legacy')
            adb.assert_not_called()

    def test_partial_or_symlinked_current_cache_refuses_instead_of_silent_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selected = root / 'tools' / release.DIRECTORY
            selected.mkdir(parents=True)
            with self.assertRaises((RuntimeError, FileNotFoundError)):
                release.available(root)
            selected.rmdir()
            other = root / 'elsewhere'
            other.mkdir()
            selected.symlink_to(other, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, 'aliased'):
                release.available(root)

    def test_asset_authentication_preserves_unknown_bytes_and_rejects_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            selected = root / 'tools' / release.DIRECTORY
            selected.mkdir(parents=True)
            good = b'authenticated fixture'
            expected = hashlib.sha256(good).hexdigest()
            path = selected / DAEMON
            path.write_bytes(good)
            with mock.patch.dict(release.ASSETS, {DAEMON: expected}):
                self.assertEqual(release.asset(root, DAEMON), path)
                alias = selected / 'alias'
                os.link(path, alias)
                with self.assertRaises(RuntimeError):
                    release.asset(root, DAEMON)
                alias.unlink()
                path.write_bytes(b'custom daemon')
                with self.assertRaises(RuntimeError):
                    release.asset(root, DAEMON)
                self.assertEqual(path.read_bytes(), b'custom daemon')
                path.unlink()
                alias.write_bytes(good)
                path.symlink_to(alias)
                with self.assertRaises(RuntimeError):
                    release.asset(root, DAEMON)
                self.assertTrue(path.is_symlink())
            with self.assertRaisesRegex(RuntimeError, 'Unknown'):
                release.asset(root, '../unknown')

    def test_actual_cached_assets_are_exact_and_current_bootstrap_selects_them(self):
        directory = ROOT / 'tools' / release.DIRECTORY
        if not directory.is_dir():
            self.skipTest('Official current assets unavailable; no download attempted.')
        self.assertTrue(release.available(ROOT))
        for name in release.RUNTIME_ASSETS:
            path = release.asset(ROOT, name)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), release.ASSETS[name])
        self.assertEqual(update.bootstrap(ROOT), (directory / DAEMON, directory / release.MANAGER))

    def test_actual_old_and_new_manager_bytes_keep_the_same_official_signer(self):
        paths = [(ROOT / 'tools' / update.LEGACY_MANAGER, LEGACY_MANAGER),
                 (ROOT / 'tools' / release.DIRECTORY / release.MANAGER, CURRENT_MANAGER)]
        if not all(path.is_file() for path, _ in paths):
            self.skipTest('Official old/current Managers unavailable; no download attempted.')
        for path, expected in paths:
            data = path.read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), expected)
            self.assertEqual(manager_certificates(data), {release.MANAGER_CERTIFICATE})

    def test_manager_embedded_daemon_pins_come_from_exact_official_apk_members(self):
        variants = (
            (ROOT / 'tools' / update.LEGACY_MANAGER, LEGACY_MANAGER,
             release.LEGACY_MANAGER_DAEMON, 4892712),
            (ROOT / 'tools' / release.DIRECTORY / release.MANAGER, CURRENT_MANAGER,
             release.CURRENT_MANAGER_DAEMON, 4990848),
        )
        if not all(path.is_file() for path, *_ in variants):
            self.skipTest('Official old/current Managers unavailable; no download attempted.')
        for path, apk_hash, member_hash, length in variants:
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), apk_hash)
            with zipfile.ZipFile(path) as archive:
                self.assertEqual(archive.namelist().count(release.MANAGER_DAEMON), 1)
                member = archive.read(release.MANAGER_DAEMON)
            self.assertEqual(len(member), length)
            self.assertEqual(hashlib.sha256(member).hexdigest(), member_hash)
            self.assertEqual(member[:7], b'\x7fELF\x02\x01\x01')
            self.assertEqual(struct.unpack_from('<H', member, 18)[0], 183)
        self.assertEqual(release.LEGACY_DAEMONS, {LEGACY_DAEMON, release.LEGACY_MANAGER_DAEMON})
        self.assertEqual(release.CURRENT_DAEMONS, {CURRENT_DAEMON, release.CURRENT_MANAGER_DAEMON})


class UpdateTests(unittest.TestCase):
    def harness(self, daemon=CURRENT_DAEMON, manager=CURRENT_MANAGER, package=None, fail_stage=False):
        """Mock only guest boundaries; keep real upgrade decisions and commands."""
        hashes = {'/data/adb/ksud': daemon, ACTIVE: manager}
        paths = ['package:' + ACTIVE] if package is None else list(package)
        staged = []

        def adb(_config, kind, command, **_options):
            self.assertEqual((kind, command), ('shell', 'pm path ' + update.PACKAGE))
            return SimpleNamespace(returncode=0 if paths else 1,
                                   stdout='\n'.join(paths) + ('\n' if paths else ''), stderr='')

        def stage(_config, source, execute):
            command = execute('/data/local/tmp/owned-' + source.name)
            staged.append((source.name, command))
            if fail_stage:
                raise RuntimeError('simulated staging failure')
            if source.name == DAEMON:
                hashes['/data/adb/ksud'] = CURRENT_DAEMON
            elif source.name == release.MANAGER:
                paths[:] = ['package:' + ACTIVE]
                hashes[ACTIVE] = CURRENT_MANAGER
            else:
                raise AssertionError('Unexpected asset selected: ' + source.name)
            return 'Success'

        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(mock.patch.object(release, 'available', return_value=True))
        stack.enter_context(mock.patch.object(release, 'asset', side_effect=lambda _root, name: Path('/cache') / name))
        stack.enter_context(mock.patch.object(update, '_hash', side_effect=lambda _config, path: hashes.get(path)))
        stack.enter_context(mock.patch.object(update, 'adb', side_effect=adb))
        stack.enter_context(mock.patch.object(update, '_stage', side_effect=stage))
        return hashes, paths, staged

    def test_exact_current_stack_is_verified_without_mutation(self):
        _, _, staged = self.harness()
        result = update.install({}, ROOT)
        self.assertEqual((result['daemon'], result['manager']), ('verified', 'verified'))
        self.assertEqual(staged, [])

    def test_current_manager_embedded_daemon_is_verified_without_replacement(self):
        _, _, staged = self.harness(daemon=release.CURRENT_MANAGER_DAEMON)
        result = update.install({}, ROOT)
        self.assertEqual((result['daemon'], result['manager']), ('verified', 'verified'))
        self.assertEqual(staged, [])

    def test_legacy_manager_embedded_daemon_updates_with_its_actual_before_guard(self):
        _, _, staged = self.harness(daemon=release.LEGACY_MANAGER_DAEMON)
        result = update.install({}, ROOT)
        self.assertEqual((result['daemon'], result['manager']), ('updated', 'verified'))
        self.assertEqual([name for name, _ in staged], [DAEMON])
        command = staged[0][1]
        self.assertEqual(command.count('= ' + release.LEGACY_MANAGER_DAEMON + ' ]'), 2)
        self.assertNotIn('= ' + LEGACY_DAEMON + ' ]', command)
        self.assertNotIn(' install', command)
        self.assertIn('mv -f', command)

    def test_replace_daemon_refuses_an_unregistered_before_identity(self):
        with self.assertRaisesRegex(RuntimeError, 'Unreviewed'):
            update._replace_daemon('/data/local/tmp/owned', '0' * 64)

    def test_custom_or_missing_daemon_and_custom_manager_are_preserved(self):
        for daemon in (None, 'custom daemon', 'unavailable'):
            with self.subTest(daemon=daemon):
                _, _, staged = self.harness(daemon=daemon, manager='custom manager')
                result = update.install({}, ROOT)
                self.assertEqual((result['daemon'], result['manager']), ('preserved-custom', 'preserved-custom'))
                self.assertEqual(staged, [])

    def test_split_or_unknown_package_layout_is_preserved(self):
        for package in (['package:' + ACTIVE, 'package:/data/app/split.apk'],):
            with self.subTest(package=package):
                _, _, staged = self.harness(package=package)
                self.assertEqual(update.install({}, ROOT)['manager'], 'preserved-custom-layout')
                self.assertEqual(staged, [])

    def test_failed_or_ambiguous_presence_probe_never_authorizes_an_install(self):
        for status, output, error in ((0, '', ''), (1, 'package:' + ACTIVE, ''),
                                      (1, '', 'permission denied'), (2, '', ''),
                                      (0, 'unknown package path', ''),
                                      (0, 'package:' + ACTIVE, 'unexpected warning')):
            with self.subTest(status=status, output=output, error=error):
                _, _, staged = self.harness()
                result = SimpleNamespace(returncode=status, stdout=output, stderr=error)
                with mock.patch.object(update, 'adb', return_value=result):
                    with self.assertRaisesRegex(RuntimeError, 'presence was not confirmed'):
                        update.install({}, ROOT)
                self.assertEqual(staged, [])

    def test_known_legacy_stack_updates_without_install_reset_or_restart(self):
        hashes, _, staged = self.harness(daemon=LEGACY_DAEMON, manager=LEGACY_MANAGER)
        result = update.install({}, ROOT)
        self.assertEqual((result['daemon'], result['manager']), ('updated', 'updated'))
        self.assertEqual(hashes['/data/adb/ksud'], CURRENT_DAEMON)
        self.assertEqual(hashes[ACTIVE], CURRENT_MANAGER)
        self.assertEqual([name for name, _ in staged], [DAEMON, release.MANAGER])
        daemon_command = staged[0][1]
        # Existing userspace must not run official install(), which rewrites
        # helper binaries and publishes the daemon by unlink-then-copy.
        self.assertNotIn(' install', daemon_command)
        self.assertIn('/data/adb/ksud', daemon_command)
        self.assertIn('mv', daemon_command)
        self.assertEqual(staged[1][1], 'pm install -r /data/local/tmp/owned-' + release.MANAGER)
        for _, command in staged:
            for forbidden in ('pm clear', 'pm uninstall', 'rm -rf', 'killall', 'reboot', 'feature reset'):
                self.assertNotIn(forbidden, command)

    def test_missing_manager_is_installed_and_verified(self):
        _, _, staged = self.harness(package=[])
        result = update.install({}, ROOT)
        self.assertEqual(result['manager'], 'installed')
        self.assertEqual([name for name, _ in staged], [release.MANAGER])

    def test_failed_staging_does_not_continue_to_manager_mutation(self):
        _, _, staged = self.harness(daemon=LEGACY_DAEMON, manager=LEGACY_MANAGER, fail_stage=True)
        with self.assertRaisesRegex(RuntimeError, 'staging failure'):
            update.install({}, ROOT)
        self.assertEqual([name for name, _ in staged], [DAEMON])

    def test_confirmation_refuses_a_failed_or_custom_manager_output(self):
        _, _, _ = self.harness(manager=LEGACY_MANAGER)
        with mock.patch.object(update, '_hash', side_effect=[CURRENT_DAEMON, LEGACY_MANAGER, 'custom changed APK']):
            with self.assertRaisesRegex(RuntimeError, 'Manager update was not confirmed'):
                update.install({}, ROOT)

    def test_missing_manager_install_cannot_report_success_without_output_confirmation(self):
        _, _, _ = self.harness(package=[])
        with mock.patch.object(update, '_hash', return_value=CURRENT_DAEMON):
            with self.assertRaisesRegex(RuntimeError, 'Manager .*not confirmed'):
                update.install({}, ROOT)


class BoundaryTests(unittest.TestCase):
    def test_hash_probes_only_nonaliased_regular_files_and_quotes_path(self):
        path = "/data/app/odd ' name/base.apk"
        with mock.patch.object(update, 'root', return_value='unavailable') as root:
            self.assertEqual(update._hash({}, path), 'unavailable')
        command = root.call_args.args[1]
        self.assertIn('[ -f ' + shlex.quote(path) + ' ]', command)
        self.assertIn('[ ! -L ' + shlex.quote(path) + ' ]', command)
        self.assertIn('stat -c %h ' + shlex.quote(path), command)
        self.assertIn(' = 1 ]', command)

    def test_stage_uses_root_wrapper_without_duplicate_timeout_and_always_cleans_owned_stage(self):
        events = []
        response = SimpleNamespace(returncode=0, stdout='Success', stderr='')

        def adb(_config, *arguments, **_options):
            events.append(arguments)
            return response

        source = Path('/verified') / release.MANAGER
        with mock.patch.object(update, 'adb', side_effect=adb), \
                mock.patch.object(apply_flutter_fix, 'adb', side_effect=adb):
            update._stage({}, source, lambda remote: 'pm install -r ' + remote)
        self.assertEqual(events[0][:2], ('push', str(source)))
        self.assertEqual(events[-1][0], 'shell')
        self.assertTrue(events[-1][1].startswith('rm -f /data/local/tmp/hyperos-avd-ksu-'))
        self.assertEqual(sum(row[0] == 'push' for row in events), 1)
        script = events[1][1]
        self.assertIn(CURRENT_MANAGER, script)
        self.assertIn('stat -c %h', script)
        self.assertIn('chmod 700', script)

    def test_staging_command_failure_keeps_guest_state_and_cleans_only_unique_stage(self):
        response = SimpleNamespace(returncode=0, stdout='', stderr='')
        with mock.patch.object(update, 'adb', return_value=response) as adb, \
                mock.patch.object(update, 'root', side_effect=RuntimeError('guest command failed')):
            with self.assertRaisesRegex(RuntimeError, 'guest command failed'):
                update._stage({}, Path('/cache') / DAEMON, lambda remote: remote + ' --version')
        self.assertEqual(adb.call_count, 2)
        last = adb.call_args.args
        self.assertEqual(last[1], 'shell')
        self.assertTrue(last[2].startswith('rm -f /data/local/tmp/hyperos-avd-ksu-'))
        self.assertNotIn('/data/adb/', last[2])


class FreshBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.adb = self.root / 'adb'
        self.remote = self.root / 'official-bootstrap'
        self.marker = self.root / 'install-called'
        self.remote.write_text('''#!/bin/sh
[ "$1" = install ] || exit 3
printf called > "$FIXTURE_INSTALL_MARKER"
mkdir -p "$FIXTURE_ADB"
chmod 700 "$FIXTURE_ADB"
cp "$0" "$FIXTURE_ADB/ksud"
chmod 755 "$FIXTURE_ADB/ksud"
''')
        self.remote.chmod(0o700)
        self.digest = hashlib.sha256(self.remote.read_bytes()).hexdigest()
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        (self.bin / 'stat').write_text('#!' + sys.executable + '''
import os,stat,sys
fmt,path=sys.argv[2],sys.argv[3];info=os.stat(path)
values={'%u':'0','%g':'0','%a':oct(stat.S_IMODE(info.st_mode))[2:],'%h':str(info.st_nlink)}
for key,value in values.items():fmt=fmt.replace(key,value)
print(fmt)
''')
        (self.bin / 'id').write_text('#!/bin/sh\nprintf "%s\\n" "${FIXTURE_UID:-0}"\n')
        (self.bin / 'getenforce').write_text('#!/bin/sh\nprintf "%s\\n" "${FIXTURE_SELINUX:-Enforcing}"\n')
        for path in self.bin.iterdir():
            path.chmod(0o755)

    def run_script(self, **environment):
        script = update._fresh_bootstrap_command(str(self.remote), self.digest, 'verified-fresh')
        script = script.replace('/data/adb', str(self.adb))
        return subprocess.run(['/bin/sh', '-c', script], capture_output=True, text=True,
                              env={**os.environ, 'PATH': str(self.bin) + ':' + os.environ['PATH'],
                                   'FIXTURE_INSTALL_MARKER': str(self.marker),
                                   'FIXTURE_ADB': str(self.adb), **environment})

    def test_absent_or_private_empty_userdata_allows_first_official_install(self):
        for empty in (False, True):
            with self.subTest(empty=empty):
                if empty:
                    (self.adb / 'ksud').unlink()
                    self.marker.unlink()
                result = self.run_script()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('verified-fresh', result.stdout.splitlines())
                self.assertEqual(self.adb.joinpath('ksud').read_bytes(), self.remote.read_bytes())
                self.assertTrue(self.marker.is_file())

    def test_any_existing_daemon_helper_module_profile_or_hidden_state_is_preserved(self):
        self.adb.mkdir(mode=0o700)
        for name in ('ksud', 'ksu', 'modules', 'modules_update', 'tools', 'allowlist', '.unknown'):
            selected = self.adb / name
            selected.write_bytes(b'user state and loaded executable')
            inode = selected.stat().st_ino
            with selected.open('rb') as loaded, self.subTest(name=name):
                result = self.run_script()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('state was preserved', result.stderr)
                self.assertFalse(self.marker.exists())
                self.assertEqual(selected.stat().st_ino, inode)
                self.assertEqual(loaded.read(), b'user state and loaded executable')
            selected.unlink()
        (self.adb / 'empty-custom-directory').mkdir()
        self.assertNotEqual(self.run_script().returncode, 0)
        self.assertTrue((self.adb / 'empty-custom-directory').is_dir())
        self.assertFalse(self.marker.exists())

    def test_alias_wrong_permissions_nonroot_and_permissive_refuse_without_install(self):
        elsewhere = self.root / 'elsewhere'
        elsewhere.mkdir(mode=0o700)
        self.adb.symlink_to(elsewhere)
        self.assertNotEqual(self.run_script().returncode, 0)
        self.adb.unlink()
        self.adb.mkdir(mode=0o755)
        self.assertNotEqual(self.run_script().returncode, 0)
        self.adb.chmod(0o700)
        for values in ({'FIXTURE_UID': '2000'}, {'FIXTURE_SELINUX': 'Permissive'}):
            self.assertNotEqual(self.run_script(**values).returncode, 0)
        self.assertFalse(self.marker.exists())
        self.assertEqual(list(self.adb.iterdir()), [])
        self.assertEqual(list(elsewhere.iterdir()), [])

    def test_unknown_local_bootstrap_never_reaches_adb(self):
        with mock.patch.object(update, 'adb') as adb:
            with self.assertRaisesRegex(RuntimeError, 'Unknown'):
                update.initialize_fresh({}, self.remote)
            adb.assert_not_called()
        alias = self.root / 'alias'
        alias.symlink_to(self.remote)
        with self.assertRaisesRegex(RuntimeError, 'unverified'):
            update.initialize_fresh({}, alias)

    def test_transport_requires_fresh_success_marker_and_cleans_only_unique_stage(self):
        events = []

        def adb(_config, *arguments, **options):
            events.append((arguments, options))
            if arguments[-1].endswith(' debug su'):
                return SimpleNamespace(returncode=0, stdout='no actual bootstrap\n', stderr='')
            return SimpleNamespace(returncode=0, stdout='', stderr='')

        with mock.patch.dict(KSU_ASSETS, {DAEMON: self.digest}), \
                mock.patch.object(update, 'adb', side_effect=adb):
            with self.assertRaisesRegex(RuntimeError, 'not confirmed'):
                update.initialize_fresh({}, self.remote)
        self.assertEqual(events[0][0][:2], ('push', str(self.remote)))
        remote = events[0][0][2]
        self.assertTrue(remote.startswith('/data/local/tmp/hyperos-avd-bootstrap-'))
        script = events[2][1]['input']
        self.assertLess(script.index('entries=$(find'), script.index(' install || refuse'))
        self.assertEqual(events[-1][0], ('shell', 'rm -f ' + remote))
        self.assertNotIn('/data/adb', events[-1][0][1])


class LaunchBootstrapTests(unittest.TestCase):
    def test_existing_su_refusal_uses_safe_helper_and_stops_without_persistent_changes(self):
        def adb(_config, *arguments, **_options):
            return SimpleNamespace(returncode=0, stdout='uid=2000(shell)\n', stderr='')

        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(launch, 'ROOT', Path(directory)), \
                mock.patch.object(launch, 'is_os4', return_value=False), \
                mock.patch.object(launch, 'adb', side_effect=adb) as transport, \
                mock.patch.object(update, 'initialize_fresh', side_effect=RuntimeError('Existing state preserved')) as fresh:
            with self.assertRaisesRegex(RuntimeError, 'Existing state'):
                launch.initialize({})
            fresh.assert_called_once_with({}, Path(directory) / 'tools' / DAEMON)
            self.assertEqual(transport.call_count, 2)
            self.assertFalse((Path(directory) / 'local/last-boot.json').exists())

    def test_existing_authorized_su_never_runs_bootstrap(self):
        def adb(_config, *arguments, **_options):
            command = arguments[-1]
            output = ('1\n' if command == 'getprop sys.boot_completed' else
                      'package:/known/Manager.apk\n' if command == 'pm path me.weishu.kernelsu' else
                      'uid=0(root)\nEnforcing\n')
            return SimpleNamespace(returncode=0, stdout=output, stderr='')

        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(launch, 'ROOT', Path(directory)), \
                mock.patch.object(launch, 'is_os4', return_value=False), \
                mock.patch.object(launch, 'adb', side_effect=adb), \
                mock.patch.object(update, 'initialize_fresh') as fresh:
            launch.initialize({'name': 'Renamed_Legacy_AVD', 'port': 5566})
            fresh.assert_not_called()


class AtomicDaemonTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.adb = self.root / 'adb'
        self.adb.mkdir(mode=0o700)
        self.old = self.adb / 'ksud'
        self.old.write_bytes(b'old loaded executable')
        self.old.chmod(0o755)
        self.remote = self.root / 'remote'
        self.remote.write_bytes(b'new official executable')
        self.before = hashlib.sha256(self.old.read_bytes()).hexdigest()
        self.after = hashlib.sha256(self.remote.read_bytes()).hexdigest()
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        # Emulate only Linux stat/SELinux/root metadata on ordinary local
        # fixtures. The script's copy/hash/rename/trap operations run for real.
        stat_code = '''import os,stat,sys
fmt,path=sys.argv[2],sys.argv[3];info=os.stat(path)
values={'%u':'0','%g':'0','%a':oct(stat.S_IMODE(info.st_mode))[2:],'%h':str(info.st_nlink),'%d':str(info.st_dev)}
for key,value in values.items():fmt=fmt.replace(key,value)
print(fmt)
'''
        (self.bin / 'stat').write_text('#!' + sys.executable + '\n' + stat_code)
        (self.bin / 'ls').write_text('#!/bin/sh\nprintf "%s %s\\n" "${FIXTURE_LABEL:-u:object_r:ksu_file:s0}" "$2"\n')
        (self.bin / 'chown').write_text('#!/bin/sh\nexit 0\n')
        (self.bin / 'chcon').write_text('#!/bin/sh\nexit "${FIXTURE_CONTEXT_FAILURE:-0}"\n')
        for path in self.bin.iterdir():
            path.chmod(0o755)

    def run_script(self, **environment):
        with mock.patch.dict(KSU_ASSETS, {DAEMON: self.before}), \
                mock.patch.dict(release.ASSETS, {DAEMON: self.after}), \
                mock.patch.object(release, 'LEGACY_DAEMONS', frozenset((self.before,))):
            script = update._replace_daemon(shlex.quote(str(self.remote)))
        script = 'set -e\n' + script.replace('/data/adb', str(self.adb))
        return subprocess.run(['/bin/sh', '-c', script],
                              env={**os.environ, 'PATH': str(self.bin) + ':' + os.environ['PATH'], **environment},
                              capture_output=True, text=True)

    def test_atomic_success_keeps_open_old_inode_and_does_not_rewrite_helpers(self):
        sentinel = self.adb / 'modules-and-allowlist-sentinel'
        sentinel.write_bytes(b'userdata state')
        old_inode = self.old.stat().st_ino
        with self.old.open('rb') as loaded:
            result = self.run_script()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(loaded.read(), b'old loaded executable')
            self.assertEqual(os.fstat(loaded.fileno()).st_ino, old_inode)
            self.assertNotEqual(self.old.stat().st_ino, old_inode)
        self.assertEqual(self.old.read_bytes(), b'new official executable')
        self.assertEqual(self.old.stat().st_mode & 0o777, 0o755)
        self.assertEqual(self.old.stat().st_nlink, 1)
        self.assertEqual(sentinel.read_bytes(), b'userdata state')
        self.assertFalse(list(self.adb.glob('.hyperos-avd-ksud-*')))


    def test_staged_context_or_content_failure_preserves_old_inode_and_metadata(self):
        for environment, tamper in (({'FIXTURE_CONTEXT_FAILURE': '1'}, False), ({}, True)):
            with self.subTest(environment=environment, tamper=tamper):
                before = self.old.stat()
                if tamper:
                    self.remote.write_bytes(b'not the authenticated new executable')
                    expected = self.after
                    self.after = '0' * 64
                result = self.run_script(**environment)
                if tamper:
                    self.after = expected
                self.assertNotEqual(result.returncode, 0)
                after = self.old.stat()
                self.assertEqual((after.st_ino, after.st_mode, after.st_uid, after.st_gid, after.st_mtime_ns),
                                 (before.st_ino, before.st_mode, before.st_uid, before.st_gid, before.st_mtime_ns))
                self.assertEqual(self.old.read_bytes(), b'old loaded executable')
                self.assertFalse(list(self.adb.glob('.hyperos-avd-ksud-*')))

    def test_custom_mode_label_and_hardlink_refuse_before_publication(self):
        before = self.old.stat().st_ino
        self.old.chmod(0o700)
        self.assertNotEqual(self.run_script().returncode, 0)
        self.old.chmod(0o755)
        self.assertNotEqual(self.run_script(FIXTURE_LABEL='u:object_r:custom_file:s0').returncode, 0)
        alias = self.adb / 'custom-alias'
        os.link(self.old, alias)
        self.assertNotEqual(self.run_script().returncode, 0)
        self.assertEqual(self.old.stat().st_ino, before)
        self.assertEqual(self.old.read_bytes(), b'old loaded executable')
        self.assertFalse(list(self.adb.glob('.hyperos-avd-ksud-*')))


class ProducerAndBundleTests(unittest.TestCase):
    def setUp(self):
        official = ROOT / 'tools' / release.DIRECTORY / release.LKM
        if not official.is_file():
            self.skipTest('Current official LKM unavailable; no download attempted.')
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        base = Path(self.temporary.name)
        self.repo, self.workspace = base / 'repo', base / 'workspace'
        self.assets = {name: (official.read_bytes() if name == release.LKM else name.encode())
                       for name in release.ASSETS}
        namespace = self.repo / 'tools' / release.DIRECTORY
        namespace.mkdir(parents=True)
        for name, body in self.assets.items():
            (namespace / name).write_bytes(body)
        self.legacy = {DAEMON: b'legacy floor daemon', update.LEGACY_MANAGER: b'legacy floor Manager'}
        for name, body in self.legacy.items():
            (self.repo / 'tools' / name).write_bytes(body)
        for name in ('tools', 'work', 'images', 'logs', 'local'):
            (self.workspace / name).mkdir(parents=True, exist_ok=True)
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(mock.patch.dict(release.ASSETS, {name: hashlib.sha256(body).hexdigest()
                                                            for name, body in self.assets.items()}))
        stack.enter_context(mock.patch.dict(KSU_ASSETS, {name: hashlib.sha256(body).hexdigest()
                                                       for name, body in self.legacy.items()}))
        self.fetch = stack.enter_context(mock.patch.object(release, 'fetch'))

    def test_shared_builder_uses_current_receipt_and_content_addressed_quiet_lkm(self):
        old = self.workspace / 'work/kernelsu-marker.ko'
        old.write_bytes(b'prior producer output')
        stack = phone_builder.prepare_kernelsu(self.repo, self.workspace)
        self.fetch.assert_called_once_with(self.repo)
        self.assertEqual(stack['receipt'], patch_kernelsu.receipt(self.assets[release.LKM]))
        self.assertEqual(stack['receipt']['version'], release.VERSION)
        self.assertIn(stack['receipt']['after'], stack['lkm'].name)
        self.assertEqual(stack['host'].parent.name, release.DIRECTORY)
        self.assertEqual(hashlib.sha256(stack['lkm'].read_bytes()).hexdigest(), stack['receipt']['after'])
        self.assertEqual(old.read_bytes(), b'prior producer output')
        for name, body in self.legacy.items():
            self.assertEqual((self.workspace / 'tools' / name).read_bytes(), body)
        inode = stack['lkm'].stat().st_ino
        self.assertEqual(phone_builder.prepare_kernelsu(self.repo, self.workspace), stack)
        self.assertEqual(stack['lkm'].stat().st_ino, inode)
        source = (ROOT / 'scripts/build_os4_pad.py').read_text()
        self.assertIn('ksu = prepare_kernelsu(repo, ROOT)', source)
        self.assertIn('patch_kernelsu_ramdisk(ROOT, ksu)', source)
        self.assertNotIn('ksu_marker_receipt()', source)

    def test_unknown_current_workspace_attachment_is_retained(self):
        target = self.workspace / 'tools' / release.DIRECTORY / release.MANAGER
        target.parent.mkdir()
        target.write_bytes(b'custom Manager')
        with self.assertRaisesRegex(RuntimeError, 'Preserving an unknown'):
            phone_builder.prepare_kernelsu(self.repo, self.workspace)
        self.assertEqual(target.read_bytes(), b'custom Manager')

    def test_boot_output_is_staged_and_never_overwrites_unknown_existing_output(self):
        from test_ksu_ramdisk import cpio
        stack = phone_builder.prepare_kernelsu(self.repo, self.workspace)
        expected_ramdisk = cpio([(b'kernelsu.ko', stack['lkm'].read_bytes(), {})])
        source = self.workspace / 'images/ramdisk.img'
        source.write_bytes(b'base ramdisk')
        old = self.workspace / 'work/ramdisk-kernelsu.img'
        old.write_bytes(b'prior producer output')

        def build(command, **options):
            self.assertEqual(command[0], str(stack['host']))
            self.assertEqual(command[command.index('-m') + 1], str(stack['lkm']))
            destination = Path(command[command.index('-o') + 1]) / command[command.index('--out-name') + 1]
            self.assertNotEqual(destination.parent, self.workspace / 'work')
            destination.write_bytes(expected_ramdisk)

        with mock.patch.object(phone_builder.subprocess, 'run', side_effect=build):
            output = phone_builder.patch_kernelsu_ramdisk(self.workspace, stack)
            self.assertEqual(source.read_bytes(), expected_ramdisk)
            self.assertEqual(old.read_bytes(), b'prior producer output')
            source.write_bytes(b'base ramdisk')
            output.write_bytes(b'custom cached output')
            with self.assertRaisesRegex(RuntimeError, 'Preserving an unknown'):
                phone_builder.patch_kernelsu_ramdisk(self.workspace, stack)
            self.assertEqual(source.read_bytes(), b'base ramdisk')
            self.assertEqual(output.read_bytes(), b'custom cached output')
            self.assertFalse(list((self.workspace / 'work').glob('.kernelsu-boot-*')))

    def test_zero_filled_host_output_is_normalized_only_after_full_stream_and_lkm_audit(self):
        import ksu_ramdisk
        from test_ksu_ramdisk import cpio
        stack = phone_builder.prepare_kernelsu(self.repo, self.workspace)
        archive = cpio([(b'kernelsu.ko', stack['lkm'].read_bytes(), {})])
        canonical = ksu_ramdisk.pack('lz4-legacy', archive)
        source = self.workspace / 'images/ramdisk.img'
        for padding in (b'', bytes(4), bytes(128)):
            with self.subTest(padding=len(padding)):
                source.write_bytes(b'base ramdisk')
                produced = canonical + padding
                if padding:
                    with self.assertRaises(RuntimeError):
                        ksu_ramdisk.unpack(produced)

                def build(command, **options):
                    output = Path(command[command.index('-o') + 1]) / command[command.index('--out-name') + 1]
                    output.write_bytes(produced)

                with mock.patch.object(phone_builder.subprocess, 'run', side_effect=build):
                    output = phone_builder.patch_kernelsu_ramdisk(self.workspace, stack)
                self.assertEqual(output.read_bytes(), canonical)
                self.assertEqual(source.read_bytes(), canonical)
                self.assertEqual(ksu_ramdisk.unpack(source.read_bytes()), ('lz4-legacy', archive))

    def test_producer_padding_does_not_allow_truncation_concatenation_or_unknown_lkm(self):
        import ksu_ramdisk
        from test_ksu_ramdisk import cpio
        stack = phone_builder.prepare_kernelsu(self.repo, self.workspace)
        archive = cpio([(b'kernelsu.ko', stack['lkm'].read_bytes(), {})])
        canonical = ksu_ramdisk.pack('lz4-legacy', archive)
        other = cpio([(b'kernelsu.ko', b'unknown module', {})])
        invalid = (canonical[:-1], canonical + b'\0' * 3,
                   canonical + bytes(4) + b'nonzero', canonical + canonical,
                   canonical + bytes(4) + canonical,
                   ksu_ramdisk.pack('lz4-legacy', other) + bytes(128),
                   ksu_ramdisk.LZ4_MAGIC + bytes(128))
        source = self.workspace / 'images/ramdisk.img'
        source.write_bytes(b'base ramdisk')
        for produced in invalid:
            with self.subTest(size=len(produced)):
                def build(command, **options):
                    output = Path(command[command.index('-o') + 1]) / command[command.index('--out-name') + 1]
                    output.write_bytes(produced)

                with mock.patch.object(phone_builder.subprocess, 'run', side_effect=build), \
                        self.assertRaises(RuntimeError):
                    phone_builder.patch_kernelsu_ramdisk(self.workspace, stack)
                self.assertEqual(source.read_bytes(), b'base ramdisk')
                self.assertFalse(list((self.workspace / 'work').glob('ramdisk-kernelsu-*.img')))
                self.assertFalse(list((self.workspace / 'work').glob('.kernelsu-boot-*')))

    def test_real_pinned_host_zero_filled_output_keeps_exact_cpio_and_current_lkm(self):
        import ksu_ramdisk
        path = ROOT / 'work/formal-release-validation-20261014/ksu-lz4-format-probe/producer.img'
        if not path.is_file():
            self.skipTest('Private pinned-host output fixture unavailable; no producer execution attempted.')
        produced = path.read_bytes()
        self.assertEqual(hashlib.sha256(produced).hexdigest(),
                         '8f3d8c512a79f81e284897eba99d299807647eac0dbfc423a541a861921895b1')
        with self.assertRaises(RuntimeError):
            ksu_ramdisk.unpack(produced)
        stack = phone_builder.prepare_kernelsu(self.repo, self.workspace)
        source = self.workspace / 'images/ramdisk.img'
        source.write_bytes(b'base ramdisk')

        def build(command, **options):
            output = Path(command[command.index('-o') + 1]) / command[command.index('--out-name') + 1]
            output.write_bytes(produced)

        with mock.patch.object(phone_builder.subprocess, 'run', side_effect=build):
            output = phone_builder.patch_kernelsu_ramdisk(self.workspace, stack)
        self.assertEqual(output.stat().st_size, 2290636)
        self.assertEqual(hashlib.sha256(output.read_bytes()).hexdigest(),
                         '7ab2ab7c861d842e7022c8bc99d816d03ed333e7d0bf5db5ba37723e89517acf')
        _, archive = ksu_ramdisk.unpack(output.read_bytes())
        self.assertEqual(hashlib.sha256(archive).hexdigest(),
                         '6fa595d97e598a5c2a28b5be6e0f225efe51c85331b95e305c73695fa3510c5e')
        entries = ksu_ramdisk.parse_cpio(archive)
        self.assertEqual(len(entries), 32)
        member = next(entry for entry in entries if entry['name'] == b'kernelsu.ko')
        audited = patch_kernelsu.audit(archive[member['body']:member['body'] + member['size']])
        self.assertEqual(audited['receipt'], stack['receipt'])
        self.assertEqual(source.read_bytes(), output.read_bytes())
        self.assertEqual(path.read_bytes(), produced)

    def test_portable_current_trio_requires_complete_authenticated_cache(self):
        metadata = {'format': 3, 'variant': 'os4-pad'}
        self.assertEqual(package_release.current_kernelsu_paths(self.workspace, metadata), {})
        phone_builder.prepare_kernelsu(self.repo, self.workspace)
        paths = package_release.current_kernelsu_paths(self.workspace, metadata)
        self.assertEqual(set(paths), {'tools/' + release.DIRECTORY + '/' + name
                                    for name in release.RUNTIME_ASSETS})
        for legacy in ({'format': 1}, {'format': 3, 'variant': 'os3'}, {'format': 2, 'variant': 'os4-official'}):
            self.assertEqual(package_release.current_kernelsu_paths(self.workspace, legacy), {})
        (self.workspace / 'tools' / release.DIRECTORY / release.MANAGER).write_bytes(b'custom Manager')
        with self.assertRaises(RuntimeError):
            package_release.current_kernelsu_paths(self.workspace, metadata)

    def test_partial_current_runtime_attachments_are_refused_before_archive_creation(self):
        phone_builder.prepare_kernelsu(self.repo, self.workspace)
        metadata = {'format': 3, 'variant': 'os4-pad', 'build': {}}
        paths = package_release.current_kernelsu_paths(self.workspace, metadata)
        only_one = {next(iter(paths)): next(iter(paths.values()))}
        destination = self.workspace / 'bundle'
        with self.assertRaisesRegex(RuntimeError, 'every verified runtime asset'):
            package_release.write_bundle(destination, 'pad-vtest', metadata, only_one, 1)
        self.assertFalse(destination.exists())

    def test_complete_runtime_attachment_bytes_are_verified_before_archiving(self):
        phone_builder.prepare_kernelsu(self.repo, self.workspace)
        metadata = {'format': 3, 'variant': 'os4-pad', 'build': {}}
        paths = package_release.current_kernelsu_paths(self.workspace, metadata)
        system = self.workspace / 'images/system.img'
        system.write_bytes(b'packed system fixture')
        paths['images/system.img'] = system
        bad = paths['tools/' + release.DIRECTORY + '/' + release.MANAGER]
        bad.write_bytes(b'unknown Manager output')
        destination = self.workspace / 'bundle'
        with self.assertRaisesRegex(RuntimeError, 'official pin'):
            package_release.write_bundle(destination, 'pad-vtest', metadata, paths, 1)
        self.assertFalse(destination.exists())

    def test_current_image_without_its_runtime_trio_cannot_silently_use_legacy(self):
        metadata = {'format': 3, 'variant': 'os4-pad',
                    'build': {'kernelsu_marker_fix': patch_kernelsu.receipt(self.assets[release.LKM])}}
        with self.assertRaisesRegex(RuntimeError, 'complete verified offline'):
            package_release.current_kernelsu_paths(self.workspace, metadata)
        system = self.workspace / 'images/system.img'
        system.write_bytes(b'current image fixture')
        destination = self.workspace / 'bundle'
        with self.assertRaisesRegex(RuntimeError, 'every verified runtime asset'):
            package_release.write_bundle(destination, 'pad-vtest', metadata, {'images/system.img': system}, 1)
        self.assertFalse(destination.exists())
        self.assertEqual(system.read_bytes(), b'current image fixture')

    def test_actual_current_receipt_updates_metadata_and_refuses_legacy_format2(self):
        from test_pad_release import build_info
        info = build_info()
        path = self.workspace / 'local/build.json'
        path.write_text(json.dumps(info))
        legacy = package_release.release_metadata(self.workspace, 'os4-pad')
        self.assertEqual(legacy['kernelsu'], '3.3.0 (32601)')
        info['kernelsu_marker_fix'] = patch_kernelsu.receipt(self.assets[release.LKM])
        path.write_text(json.dumps(info))
        current = package_release.release_metadata(self.workspace, 'os4-pad')
        self.assertEqual(current['kernelsu'], '3.3.1 (32680)')
        self.assertEqual(current['build']['kernelsu_marker_fix'], info['kernelsu_marker_fix'])
        # A future or current source must not be misrepresented through the
        # historical nonportable schema. Its old release contract stays intact.
        nonportable = {'format': 2, 'variant': 'os4-official', 'build': info}
        with self.assertRaisesRegex(RuntimeError, 'portable format3'):
            package_release.current_kernelsu_paths(self.workspace, nonportable)
        with self.assertRaisesRegex(RuntimeError, 'portable format3'):
            package_release.write_bundle(self.workspace / 'bundle', 'vtest', nonportable, {}, 1)
        self.assertFalse((self.workspace / 'bundle').exists())



if __name__ == '__main__':
    unittest.main()
