"""Consolidated unit tests for guest storage & userdata capacity management."""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import struct
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

REPO = Path(__file__).resolve().parents[1]
ROOT = REPO
sys.path.insert(0, str(REPO / 'scripts'))

import common
import manage
import userdata_guest as guest
import userdata_resize



# --- tests/test_manage_guest_storage.py ---

'Bound decrypted capacity repair to one verified, backed-up AVD process.'

GIB = 1024 ** 3

BOOT_FILES = ('images/system.img', 'images/vendor.img', 'images/kernel-ranchu', 'images/ramdisk.img', 'tools/ksud-aarch64-linux-android')

class ManageGuestStorageTests(unittest.TestCase):

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = (Path(self.temporary.name) / 'Renamed instance').resolve()
        self.name, self.port = ('Renamed_AVD', 5598)
        self.sdk = Path(self.temporary.name) / 'SDK'
        self.folder = self.root / 'backups' / 'before-storage-repair'
        self.folder.mkdir(parents=True)
        self.avd = self.root / 'avd' / (self.name + '.avd')
        self.avd.mkdir(parents=True)
        (self.avd / 'config.ini').write_text('hw.ramSize=6144\nhw.cpu.ncore=4\ndisk.dataPartition.size=32G\n')
        self.saved = {'name': self.name, 'port': self.port, 'sdk': '/old/sdk', 'hardware': {'disk.dataPartition.size': '32G'}, 'camera_bridge': False}
        (self.root / 'local').mkdir()
        self.write_runtime()
        self.manifest = {'variant': 'os4-official', 'version': 'v0.2.1-a17-hyperos4-hongkong-r2', 'build': {'source': 'official-hongkong-ota', 'hyperos': '4.0.17.0.XFRCNXM'}, 'files': {}}
        for name in BOOT_FILES:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            data = ('verified ' + name).encode()
            path.write_bytes(data)
            self.manifest['files'][name] = {'sha256': hashlib.sha256(data).hexdigest()}
        self.write_manifest()
        self.protected = {'encryptionkey.img': b'original key', 'encryptionkey.img.qcow2': b'original key overlay', 'qemu-version.txt': b'2'}
        for name, data in self.protected.items():
            (self.avd / name).write_bytes(data)
        self.events, self.adb_calls = ([], [])
        self.token = {'schema': 1, 'data': 'verified private capacity token'}
        self.record = {'schema': 1, 'filesystem_bytes': 32 * GIB, 'proof': 'owned decrypted guest'}
        self.guest = types.ModuleType('userdata_guest')
        self.guest.verify_and_grow = Mock(side_effect=self.verify)
        self.process = Mock()
        self.process.pid = 43210
        self.process.poll.return_value = None
        self.process.wait.side_effect = self.wait
        self.process.terminate.side_effect = lambda: self.events.append('terminate-own-pid')
        self.mocks = {}
        self.registry = Path(self.temporary.name) / 'isolated-registry'
        self.registry.mkdir()
        self.install_mock('avd_home', patch.object(manage, 'avd_home', return_value=self.registry))
        self.install_mock('idle', patch.object(manage, 'idle', side_effect=lambda *_: self.events.append('idle')))
        self.install_mock('resize', patch.object(manage, 'resize', side_effect=self.resize))
        self.install_mock('popen', patch.object(manage.subprocess, 'Popen', side_effect=self.spawn))
        self.install_mock('adb', patch.object(common, 'adb', side_effect=self.adb))
        self.install_mock('sleep', patch.object(manage.time, 'sleep'))
        self.install_mock('publish', patch.object(userdata_resize, 'publish_guest_capacity', side_effect=self.publish, create=True))
        self.install_mock('features', patch('launch.vulkan_features', return_value=['-feature', 'VerifiedVulkan']))
        self.install_mock('rear', patch('rear_display_config.runtime_options', return_value=['-verified-rear-panel']))
        self.install_mock('guest_module', patch.dict(sys.modules, {'userdata_guest': self.guest}))

    def install_mock(self, name, context):
        self.mocks[name] = context.start()
        self.addCleanup(context.stop)

    def write_manifest(self):
        (self.root / 'local/installed-release.json').write_text(json.dumps(self.manifest))

    def write_runtime(self):
        (self.root / 'local/runtime.json').write_text(json.dumps(self.saved))

    def resize(self, *_args, **_kwargs):
        self.events.append('offline-proof')
        return {'guest_required': True, 'userdata_capacity_token': self.token}

    def spawn(self, *_args, **_kwargs):
        self.events.append('spawn')
        return self.process

    def verify(self, *_args, **_kwargs):
        self.events.append('verify-and-grow')
        return self.record

    def wait(self, **_kwargs):
        self.events.append('wait-owned-exit')
        self.process.poll.return_value = 0
        return 0

    def publish(self, *_args, **_kwargs):
        self.events.append('publish')
        return {'changed': True, 'filesystem_bytes': 32 * GIB}

    def adb(self, config, *arguments, **_kwargs):
        self.assertEqual(config['name'], self.name)
        self.assertEqual(config['port'], self.port)
        self.assertEqual(config['sdk'], str(self.sdk))
        self.assertEqual(config['userdata_capacity_token'], self.token)
        self.adb_calls.append(arguments)
        outputs = {('get-state',): 'device', ('emu', 'avd', 'name'): self.name + '\nOK', ('shell', 'getprop sys.boot_completed'): '1', ('shell', 'su -W -c sync'): '', ('emu', 'kill'): ''}
        self.assertIn(arguments, outputs, 'Storage orchestration exceeded its ADB scope.')
        self.events.append('adb:' + ' '.join(arguments))
        return subprocess.CompletedProcess(arguments, 0, outputs[arguments], '')

    def prepare(self):
        return manage.prepare_storage(self.root, self.name, self.port, self.sdk, 32, self.folder)

    def assert_no_publish(self):
        self.mocks['publish'].assert_not_called()
        self.assertFalse((self.folder / 'storage-repair.json').exists())

    def test_verified_offline_noop_does_not_read_manifest_or_boot_a_guest(self):
        proof = {'changed': False, 'filesystem_bytes': 32 * GIB}
        self.mocks['resize'].side_effect = None
        self.mocks['resize'].return_value = proof
        (self.root / 'local/installed-release.json').unlink()
        self.assertEqual(self.prepare(), proof)
        self.mocks['resize'].assert_called_once_with(self.sdk, self.avd, 32, allow_guest=True, backup=self.folder)
        self.mocks['popen'].assert_not_called()
        self.mocks['adb'].assert_not_called()
        self.guest.verify_and_grow.assert_not_called()
        self.assert_no_publish()

    def test_owned_guest_proof_is_published_only_after_sync_exit_and_idle(self):
        result = self.prepare()
        self.assertEqual(result, {'changed': True, 'filesystem_bytes': 32 * GIB})
        config = {**self.saved, 'sdk': str(self.sdk), 'userdata_capacity_token': self.token}
        self.guest.verify_and_grow.assert_called_once_with(config, 32 * GIB, backup=self.folder)
        self.mocks['publish'].assert_called_once_with(self.sdk, self.avd, 32 * GIB, self.record)
        self.assertEqual(json.loads((self.folder / 'storage-repair.json').read_text()), self.record)
        tail = self.events[self.events.index('verify-and-grow'):]
        self.assertEqual(tail, ['verify-and-grow', 'adb:shell su -W -c sync', 'adb:emu avd name', 'adb:emu kill', 'wait-owned-exit', 'idle', 'publish'])
        self.process.terminate.assert_not_called()
        self.process.wait.assert_called_once_with(timeout=60)
        command = self.mocks['popen'].call_args.args[0]
        for option, expected in (('-avd', self.name), ('-sysdir', str(self.root / 'images')), ('-port', str(self.port)), ('-memory', '6144'), ('-cores', '4')):
            self.assertEqual(command[command.index(option) + 1], expected)
        for option in ('-no-window', '-no-snapshot-load', '-no-snapshot-save', 'VerifiedVulkan', '-verified-rear-panel'):
            self.assertIn(option, command)
        self.assertTrue(self.mocks['popen'].call_args.kwargs['start_new_session'])
        for name, data in self.protected.items():
            self.assertEqual((self.avd / name).read_bytes(), data)

    def test_unknown_firmware_variant_refuses_before_spawn(self):
        self.manifest['variant'] = 'foreign-firmware'
        self.write_manifest()
        with self.assertRaisesRegex(RuntimeError, 'known installed release'):
            self.prepare()
        self.mocks['popen'].assert_not_called()
        self.assert_no_publish()

    def test_local_os4_build_without_release_manifest_uses_pinned_boot_inputs(self):
        (self.root / 'local/installed-release.json').unlink()
        build = {'source': 'official-yingtian-ota', 'android_api': 37, 'hyperos': 'OS4.0.15.0.XBMCNXM'}
        (self.root / 'local/build.json').write_text(json.dumps(build))
        self.assertTrue(self.prepare()['changed'])
        proof = json.loads((self.folder / 'storage-boot-inputs.json').read_text())
        self.assertEqual(proof['variant'], 'os4-pad')
        self.assertEqual(proof['files'], self.manifest['files'])
        self.mocks['features'].assert_called_once_with(build)
        self.mocks['rear'].assert_called_once_with(build)
        self.assertFalse((self.root / 'local/installed-release.json').exists())

    def test_missing_or_unknown_local_build_refuses_before_spawn(self):
        (self.root / 'local/installed-release.json').unlink()
        for build in ({}, {'source': 'foreign', 'android_api': 37, 'hyperos': 'OS4'}, {'source': 'official-yingtian-ota', 'android_api': 36, 'hyperos': 'OS4'}, {'source': 'official-yingtian-ota', 'android_api': 37, 'hyperos': 'OS3.0'}, {'source': 'official-yingtian-ota', 'android_api': 37, 'hyperos': True}):
            with self.subTest(build=build):
                (self.root / 'local/build.json').write_text(json.dumps(build))
                with self.assertRaisesRegex(RuntimeError, 'known installed release or local OS4 build'):
                    self.prepare()
        self.mocks['popen'].assert_not_called()
        self.assert_no_publish()

    def test_existing_release_manifest_cannot_fall_back_to_local_build(self):
        (self.root / 'local/build.json').write_text(json.dumps({'source': 'official-yingtian-ota', 'android_api': 37, 'hyperos': 'OS4.0'}))
        self.manifest['files']['images/system.img']['sha256'] = '0' * 64
        self.write_manifest()
        with self.assertRaisesRegex(RuntimeError, 'firmware differs'):
            self.prepare()
        self.mocks['popen'].assert_not_called()

    def test_local_build_mutation_after_snapshot_refuses_before_spawn(self):
        (self.root / 'local/installed-release.json').unlink()
        (self.root / 'local/build.json').write_text(json.dumps({'source': 'official-yingtian-ota', 'android_api': 37, 'hyperos': 'OS4.0'}))
        snapshot = manage.storage_boot_metadata

        def mutate(root, folder):
            result = snapshot(root, folder)
            (root / 'images/vendor.img').write_bytes(b'changed after pinning')
            return result
        with patch.object(manage, 'storage_boot_metadata', side_effect=mutate):
            with self.assertRaisesRegex(RuntimeError, 'firmware differs'):
                self.prepare()
        self.mocks['popen'].assert_not_called()
        self.assert_no_publish()

    def test_foreign_avd_registry_refuses_before_idle_or_capacity_probe(self):
        foreign = self.root.parent / 'another-workspace' / 'Foreign.avd'
        (self.registry / (self.name + '.ini')).write_text('path=' + str(foreign) + '\n')
        with self.assertRaisesRegex(RuntimeError, 'another workspace'):
            self.prepare()
        self.mocks['idle'].assert_not_called()
        self.mocks['resize'].assert_not_called()
        self.mocks['popen'].assert_not_called()
        self.mocks['adb'].assert_not_called()
        self.assert_no_publish()

    def test_matching_registry_allows_the_owned_capacity_probe(self):
        (self.registry / (self.name + '.ini')).write_text('path=' + str(self.avd) + '\n')
        self.mocks['resize'].side_effect = None
        self.mocks['resize'].return_value = {'changed': False, 'filesystem_bytes': 32 * GIB}
        self.prepare()
        self.mocks['resize'].assert_called_once_with(self.sdk, self.avd, 32, allow_guest=True, backup=self.folder)
        self.mocks['popen'].assert_not_called()

    def test_invalid_avd_name_refuses_before_scope_or_capacity_probe(self):
        with self.assertRaisesRegex(RuntimeError, 'AVD names'):
            manage.prepare_storage(self.root, '../Other_AVD', self.port, self.sdk, 32, self.folder)
        self.mocks['idle'].assert_not_called()
        self.mocks['resize'].assert_not_called()
        self.mocks['popen'].assert_not_called()
        self.assert_no_publish()

    def test_mismatched_registered_name_or_port_refuses_before_spawn(self):
        for field, value in (('name', 'Another_AVD'), ('port', 5574)):
            with self.subTest(field=field):
                original = self.saved[field]
                self.saved[field] = value
                self.write_runtime()
                with self.assertRaisesRegex(RuntimeError, 'different instance'):
                    self.prepare()
                self.saved[field] = original
                self.write_runtime()
        self.mocks['popen'].assert_not_called()
        self.assert_no_publish()

    def test_each_mutated_boot_input_refuses_before_spawn(self):
        for relative in BOOT_FILES:
            with self.subTest(relative=relative):
                path = self.root / relative
                original = path.read_bytes()
                path.write_bytes(original + b'mutated')
                try:
                    with self.assertRaisesRegex(RuntimeError, 'firmware differs'):
                        self.prepare()
                finally:
                    path.write_bytes(original)
        self.mocks['popen'].assert_not_called()
        self.assert_no_publish()

    def test_missing_boot_input_hash_refuses_before_spawn(self):
        self.manifest['files']['images/vendor.img'] = {}
        self.write_manifest()
        with self.assertRaisesRegex(RuntimeError, 'firmware differs'):
            self.prepare()
        self.mocks['popen'].assert_not_called()
        self.assert_no_publish()

    def test_wrong_adb_guest_terminates_only_owned_child_without_console_kill(self):
        normal = self.mocks['adb'].side_effect

        def wrong_identity(config, *arguments, **kwargs):
            if arguments == ('emu', 'avd', 'name'):
                self.adb_calls.append(arguments)
                return subprocess.CompletedProcess(arguments, 0, 'Other_AVD\nOK', '')
            return normal(config, *arguments, **kwargs)
        self.mocks['adb'].side_effect = wrong_identity
        with self.assertRaisesRegex(RuntimeError, 'different AVD'):
            self.prepare()
        self.process.terminate.assert_called_once_with()
        self.process.wait.assert_called_once_with(timeout=60)
        self.assertNotIn(('emu', 'kill'), self.adb_calls)
        self.guest.verify_and_grow.assert_not_called()
        self.assert_no_publish()

    def test_unverified_adb_timeout_terminates_only_owned_child(self):
        self.mocks['adb'].side_effect = subprocess.TimeoutExpired('adb get-state', 10)
        with patch.object(manage.time, 'monotonic', side_effect=[0, 1, 301]):
            with self.assertRaisesRegex(RuntimeError, 'did not finish booting'):
                self.prepare()
        self.process.terminate.assert_called_once_with()
        self.process.wait.assert_called_once_with(timeout=60)
        self.assertNotIn(('emu', 'kill'), self.adb_calls)
        self.guest.verify_and_grow.assert_not_called()
        self.assert_no_publish()

    def test_exited_child_never_calls_or_kills_another_guest(self):
        self.process.poll.return_value = 1
        with self.assertRaisesRegex(RuntimeError, 'emulator exited'):
            self.prepare()
        self.mocks['adb'].assert_not_called()
        self.process.terminate.assert_not_called()
        self.guest.verify_and_grow.assert_not_called()
        self.assert_no_publish()

    def test_guest_proof_failure_stops_owned_child_without_publication(self):
        self.guest.verify_and_grow.side_effect = RuntimeError('Unsafe decrypted capacity proof')
        with self.assertRaisesRegex(RuntimeError, 'Unsafe decrypted'):
            self.prepare()
        self.assertIn(('emu', 'kill'), self.adb_calls)
        self.process.wait.assert_called_once_with(timeout=60)
        self.assert_no_publish()

    def test_cleanup_identity_timeout_terminates_owned_child_before_publication(self):
        normal = self.mocks['adb'].side_effect
        identities = 0

        def timeout_on_cleanup(config, *arguments, **kwargs):
            nonlocal identities
            if arguments == ('emu', 'avd', 'name'):
                identities += 1
                if identities == 2:
                    raise subprocess.TimeoutExpired('adb emu avd name', 15)
            return normal(config, *arguments, **kwargs)
        self.mocks['adb'].side_effect = timeout_on_cleanup
        self.assertEqual(self.prepare(), {'changed': True, 'filesystem_bytes': 32 * GIB})
        self.process.terminate.assert_called_once_with()
        self.process.wait.assert_called_once_with(timeout=60)
        self.assertNotIn(('emu', 'kill'), self.adb_calls)
        self.assertEqual(self.events[-4:], ['terminate-own-pid', 'wait-owned-exit', 'idle', 'publish'])

    def test_failed_console_stop_falls_back_to_owned_pid_before_publication(self):
        normal = self.mocks['adb'].side_effect

        def refused_stop(config, *arguments, **kwargs):
            if arguments == ('emu', 'kill'):
                self.adb_calls.append(arguments)
                return subprocess.CompletedProcess(arguments, 1, '', 'console unavailable')
            return normal(config, *arguments, **kwargs)
        self.mocks['adb'].side_effect = refused_stop
        self.prepare()
        self.process.terminate.assert_called_once_with()
        self.assertEqual(self.events[-4:], ['terminate-own-pid', 'wait-owned-exit', 'idle', 'publish'])

    def test_post_exit_port_collision_prevents_proof_publication(self):
        self.mocks['idle'].side_effect = [None, RuntimeError('Port now belongs to another AVD')]
        with self.assertRaisesRegex(RuntimeError, 'another AVD'):
            self.prepare()
        self.process.wait.assert_called_once_with(timeout=60)
        self.assert_no_publish()

    def test_guest_sync_failure_stops_owned_child_without_publication(self):
        normal = self.mocks['adb'].side_effect

        def failed_sync(config, *arguments, **kwargs):
            if arguments == ('shell', 'su -W -c sync'):
                raise subprocess.CalledProcessError(1, 'owned guest sync')
            return normal(config, *arguments, **kwargs)
        self.mocks['adb'].side_effect = failed_sync
        with self.assertRaises(subprocess.CalledProcessError):
            self.prepare()
        self.assertIn(('emu', 'kill'), self.adb_calls)
        self.process.wait.assert_called_once_with(timeout=60)
        self.assert_no_publish()

    def test_offline_proof_failure_leaves_recovery_to_the_caller(self):
        self.mocks['resize'].side_effect = RuntimeError('Unverified disk ownership')
        with patch.object(manage, 'restore') as restore:
            with self.assertRaisesRegex(RuntimeError, 'disk ownership'):
                self.prepare()
        restore.assert_not_called()
        self.mocks['popen'].assert_not_called()
        self.mocks['adb'].assert_not_called()
        self.assert_no_publish()

    def test_child_wait_timeout_blocks_capacity_publication(self):
        self.process.wait.side_effect = subprocess.TimeoutExpired('owned emulator', 60)
        with self.assertRaisesRegex(RuntimeError, 'still running'):
            self.prepare()
        self.assertIn(('emu', 'kill'), self.adb_calls)
        self.assert_no_publish()

if __name__ == '__main__':
    unittest.main()


# --- tests/test_userdata_guest.py ---

'Exercise guest-only ext4 capacity guards without connecting to any AVD.'

GIB = 1024 ** 3

TARGET = 32 * GIB

BOOT = '01234567-89ab-cdef-0123-456789abcdef'

def superblock(size, identity=bytes(range(16)), *, incompatible=132):
    data = bytearray(4096)
    blocks = size // 4096
    struct.pack_into('<I', data, 1028, blocks & 4294967295)
    struct.pack_into('<I', data, 1048, 2)
    struct.pack_into('<H', data, 1080, 61267)
    struct.pack_into('<I', data, 1120, incompatible)
    struct.pack_into('<I', data, 1360, blocks >> 32)
    data[1128:1144] = identity
    return bytes(data)

class FakeGuest:
    """Model binary reads, mounted identity and the externally observable writes."""

    def __init__(self, config, *, filesystem_bytes=6 * GIB):
        self.config = config
        self.identity = ['0', 'Enforcing', config['name'], 'ranchu', 'hongkong', 'OS4.0.18.0.XFRCNXM', '1', BOOT]
        self.device, self.capacity = ('/dev/block/dm-56', TARGET)
        self.filesystem_bytes, self.uuid = (filesystem_bytes, bytes(range(16)))
        self.mounts = None
        self.header_override = None
        self.serial = 'emulator-' + str(config['port'])
        self.tool_available = True
        self.calls, self.events, self.probes = ([], [], {})
        self.before = None
        self.after_resize = None
        self.resize_failure = None
        self.corrupt_probe = False

    def mount_lines(self):
        return self.mounts if self.mounts is not None else [f'{self.device} /data ext4 rw,seclabel 0 0']

    def invoke(self, config, *arguments, **kwargs):
        self.assert_config(config, kwargs)
        self.calls.append((arguments, kwargs))
        if arguments == ('get-serialno',):
            return subprocess.CompletedProcess(arguments, 0, self.serial + '\n', '')
        if arguments[0] not in ('shell', 'exec-out') or len(arguments) != 2:
            raise AssertionError('Unscoped or unexpected ADB command: ' + repr(arguments))
        wrapper = shlex.split(arguments[1])
        if wrapper[:3] != ['su', '-W', '-c'] or len(wrapper) != 4:
            raise AssertionError('Sensitive command did not use the expected root wrapper.')
        script = wrapper[3]
        if not script.startswith('set -eu\n'):
            raise AssertionError('Root shell must stop after a failed guard.')
        if script == 'set -eu\n' + guest.IDENTITY_QUERY:
            phase = 'identity'
        elif re.search('^/system/bin/resize2fs /dev/block/dm-[0-9]+$', script, re.M):
            phase = 'resize'
        elif 'printf ' in script:
            phase = 'probe-create'
        elif re.search('^rm /data/local/tmp/', script, re.M):
            phase = 'probe-remove'
        elif re.search('^sha256sum /data/local/tmp/', script, re.M):
            phase = 'probe-check'
        elif 'test -x /system/bin/resize2fs' in script:
            phase = 'tool'
        elif re.search('^dd if=/dev/block/dm-', script, re.M):
            phase = 'header'
        elif re.search('^/system/bin/blockdev --getsize64 ', script, re.M):
            phase = 'capacity'
        elif script.endswith('\nsync'):
            phase = 'sync'
        else:
            raise AssertionError('Unexpected root command: ' + script)
        self.events.append(phase)
        if self.before:
            self.before(phase, self)
        output, status = ('', 0)
        if phase == 'identity':
            output = '\n'.join(self.identity + self.mount_lines()) + '\n'
        elif not self.guard_matches(script):
            status = 1
        elif phase == 'capacity':
            output = str(self.capacity) + '\n'
        elif phase == 'header':
            self.assert_binary(arguments, kwargs)
            output = self.header_override if self.header_override is not None else superblock(self.filesystem_bytes, self.uuid)
        elif phase == 'tool':
            status = 0 if self.tool_available else 1
        elif phase == 'probe-create':
            match = re.search("printf '%s\\\\n' ([a-f0-9]{64}) > (/data/local/tmp/hyperos-avd-userdata-probe-[a-f0-9]{32})", script)
            if not match:
                raise AssertionError('Probe contents/path were not bounded random values.')
            nonce, path = match.groups()
            self.probes[path] = hashlib.sha256((nonce + '\n').encode()).hexdigest()
        elif phase == 'probe-check':
            path = script.splitlines()[-1].split()[-1]
            checksum = '0' * 64 if self.corrupt_probe else self.probes[path]
            output = checksum + '  ' + path + '\n'
        elif phase == 'probe-remove':
            path = script.splitlines()[-1].split()[-1]
            del self.probes[path]
        elif phase == 'resize':
            if kwargs['timeout'] != guest.GROW_TIMEOUT:
                raise AssertionError('Online resize must have a bounded growth timeout.')
            if f'--getsize64 {self.device})" = {self.capacity}' not in script:
                status = 1
            elif isinstance(self.resize_failure, Exception):
                raise self.resize_failure
            elif self.resize_failure:
                status = 1
            else:
                self.filesystem_bytes = self.capacity
                if self.after_resize:
                    self.after_resize(self)
        return subprocess.CompletedProcess(arguments, status, output, 'private error detail must not leak')

    def guard_matches(self, script):
        expected = [('id -u', self.identity[0]), ('getenforce', self.identity[1]), ('getprop ro.boot.qemu.avd_name', self.identity[2]), ('getprop ro.boot.hardware', self.identity[3]), ('getprop ro.product.device', self.identity[4]), ('getprop ro.mi.os.version.incremental', self.identity[5]), ('getprop sys.boot_completed', self.identity[6]), ('cat /proc/sys/kernel/random/boot_id', self.identity[7])]
        for command, value in expected:
            quoted = shlex.quote(value)
            if f'test "$({command})" = {quoted}' not in script:
                return False
        return f'test "$source" = {self.device}' in script and self.mount_lines() == [f'{self.device} /data ext4 rw,seclabel 0 0']

    def assert_config(self, config, kwargs):
        for key in ('sdk', 'name', 'port'):
            if config[key] != self.config[key]:
                raise AssertionError('ADB was redirected to a different guest.')
        if not kwargs.get('capture_output') or kwargs.get('timeout') not in (guest.QUERY_TIMEOUT, guest.GROW_TIMEOUT):
            raise AssertionError('All guest commands must be captured and bounded.')

    def assert_binary(self, arguments, kwargs):
        if arguments[0] != 'exec-out' or kwargs.get('text') is not False:
            raise AssertionError('Superblock reads must preserve binary bytes.')

class GuestCapacityTests(unittest.TestCase):

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name) / 'offline backup'
        self.config = {'sdk': '/unused/SDK', 'name': 'Renamed_Private_AVD', 'port': 5588, 'product_device': 'hongkong', 'incremental': 'OS4.0.18.0.XFRCNXM', 'userdata_capacity_token': {'nonce': 'opaque immutable host binding'}}
        self.fake = FakeGuest(self.config)
        self.mock_adb = patch.object(guest, 'adb', side_effect=self.fake.invoke).start()
        self.addCleanup(patch.stopall)

    def backup(self):
        (self.folder / 'avd').mkdir(parents=True)
        files = {}
        for name in guest.LAYER_NAMES:
            path = self.folder / 'avd' / name
            path.write_bytes(('offline only ' + name).encode())
            files['avd/' + name] = hashlib.sha256(path.read_bytes()).hexdigest()
        (self.folder / 'backup.json').write_text(json.dumps({'name': self.config['name'], 'files': files}))
        return self.folder

    def grow(self, **kwargs):
        return guest.verify_and_grow(self.config, TARGET, **kwargs)

    def assert_no_writes(self):
        self.assertFalse(set(self.fake.events) & {'probe-create', 'probe-remove', 'resize', 'sync'})

    def test_already_sized_guest_is_read_only_and_echoes_a_detached_token(self):
        self.fake.filesystem_bytes = TARGET
        record = self.grow(allow_grow=False)
        self.assertTrue(record['verified'])
        self.assertFalse(record['changed'])
        self.assertEqual(record['capacity_proof'], 'verified-in-guest')
        self.assertEqual(record['filesystem']['bytes'], TARGET)
        self.assertEqual(record['filesystem']['uuid'], bytes(range(16)).hex())
        self.assertEqual(record['filesystem']['incompatible'], 128)
        self.assertEqual(record['mapped_device_bytes'], TARGET)
        self.assertEqual(record['host_token'], self.config['userdata_capacity_token'])
        self.assertIsNot(record['host_token'], self.config['userdata_capacity_token'])
        self.assertIsNone(record['probe_verified'])
        self.assertIsNone(record['backup'])
        self.assert_no_writes()

    def test_64_bit_superblock_count_is_read_as_binary(self):
        size = ((1 << 32) + 7) * 4096
        self.fake.capacity = self.fake.filesystem_bytes = size
        record = guest.verify_and_grow(self.config, size)
        self.assertEqual(record['filesystem']['bytes'], size)
        self.assert_no_writes()

    def test_invalid_explicit_config_is_refused_before_adb(self):
        for field, value in (('port', 5589), ('port', True), ('port', 1), ('name', 'bad;name'), ('name', ''), ('sdk', ''), ('serial', 'emulator-5590')):
            with self.subTest(field=field, value=value):
                config = dict(self.config, **{field: value})
                with self.assertRaises(guest.GuestCapacityError):
                    guest.verify_and_grow(config, TARGET)
        self.mock_adb.assert_not_called()

    def test_wrong_serial_is_refused(self):
        self.fake.serial = 'emulator-5590'
        with self.assertRaisesRegex(guest.GuestCapacityError, 'serial'):
            self.grow()
        self.assert_no_writes()

    def test_guest_identity_and_root_guards_refuse_before_mutation(self):
        for index, value in ((0, '2000'), (1, 'Permissive'), (2, 'Another_AVD'), (3, 'other'), (4, 'yingtian'), (5, 'foreign incremental'), (6, '0'), (7, 'malformed')):
            with self.subTest(index=index):
                original = self.fake.identity[index]
                self.fake.identity[index] = value
                try:
                    with self.assertRaises(guest.GuestCapacityError):
                        self.grow()
                finally:
                    self.fake.identity[index] = original
        self.assert_no_writes()

    def test_unsafe_mounts_are_refused(self):
        for mounts in (['/dev/block/vda /data ext4 rw 0 0'], ['/dev/block/dm-56 /data f2fs rw 0 0'], ['/dev/block/dm-56 /data ext4 ro 0 0'], ['/dev/block/dm-56 /data ext4 rw,ro 0 0'], ['/dev/block/dm-56;bad /data ext4 rw 0 0'], [], ['/dev/block/dm-56 /data ext4 rw 0 0'] * 2):
            with self.subTest(mounts=mounts):
                self.fake.mounts = mounts
                with self.assertRaises(guest.GuestCapacityError):
                    self.grow()
        self.assert_no_writes()

    def test_short_or_opaque_superblock_is_refused(self):
        for header in (b'\x00' * 1024, b'\x00' * 4096):
            with self.subTest(length=len(header)):
                self.fake.header_override = header
                with self.assertRaises(guest.GuestCapacityError):
                    self.grow()
        self.assert_no_writes()

    def test_wrong_mapping_capacity_and_shrink_are_refused(self):
        self.fake.capacity = 64 * GIB
        with self.assertRaisesRegex(guest.GuestCapacityError, 'mapped device'):
            self.grow()
        self.fake.capacity, self.fake.filesystem_bytes = (TARGET, 64 * GIB)
        with self.assertRaisesRegex(guest.GuestCapacityError, 'shrink'):
            self.grow()
        self.assert_no_writes()

    def test_growth_policy_and_absent_backup_refuse_without_probe(self):
        with self.assertRaisesRegex(guest.GuestCapacityError, 'disabled'):
            self.grow(allow_grow=False)
        with self.assertRaisesRegex(guest.GuestCapacityError, 'offline'):
            self.grow()
        self.assert_no_writes()

    def test_backup_name_missing_layers_and_hashes_are_verified_before_probe(self):
        folder = self.backup()
        receipt = folder / 'backup.json'
        original = json.loads(receipt.read_text())
        bad_name = dict(original, name='Another_AVD')
        missing = dict(original, files={key: value for key, value in original['files'].items() if not key.endswith('encryptionkey.img.qcow2')})
        changed_hash = dict(original, files=dict(original['files'], **{'avd/userdata-qemu.img': '0' * 64}))
        for malformed in (bad_name, missing, changed_hash):
            with self.subTest(receipt=malformed):
                receipt.write_text(json.dumps(malformed))
                with self.assertRaisesRegex(guest.GuestCapacityError, 'backup'):
                    self.grow(backup=folder)
        self.assert_no_writes()

    def test_symlinked_backup_layer_is_refused(self):
        folder = self.backup()
        path = folder / 'avd/encryptionkey.img'
        saved = folder / 'original-key'
        path.rename(saved)
        path.symlink_to(saved)
        with self.assertRaisesRegex(guest.GuestCapacityError, 'backup'):
            self.grow(backup=folder)
        self.assert_no_writes()

    def test_growth_preserves_uuid_probe_and_offline_backup_bytes(self):
        folder = self.backup()
        hashes_before = {path.name: path.read_bytes() for path in (folder / 'avd').iterdir()}
        record = self.grow(backup=folder)
        self.assertTrue(record['changed'])
        self.assertTrue(record['probe_verified'])
        self.assertEqual(record['filesystem']['bytes'], TARGET)
        self.assertEqual(record['filesystem']['uuid'], bytes(range(16)).hex())
        self.assertEqual(record['backup'], str(folder.resolve()))
        self.assertEqual(record['schema'], guest.SCHEMA)
        self.assertEqual(record['host_token'], self.config['userdata_capacity_token'])
        self.assertEqual(self.fake.events.count('resize'), 1)
        self.assertLess(self.fake.events.index('probe-check'), self.fake.events.index('resize'))
        self.assertGreater(self.fake.events.index('probe-remove'), self.fake.events.index('resize'))
        self.assertEqual(self.fake.events[-1], 'sync')
        self.assertFalse(self.fake.probes)
        self.assertEqual(hashes_before, {path.name: path.read_bytes() for path in (folder / 'avd').iterdir()})

    def test_missing_resize_binary_is_refused_before_probe(self):
        self.fake.tool_available = False
        with self.assertRaises(guest.GuestCapacityError) as error:
            self.grow(backup=self.backup())
        self.assertFalse(error.exception.resize_attempted)
        self.assert_no_writes()

    def test_pre_resize_superblock_change_is_refused_and_keeps_probe(self):

        def change(phase, model):
            if phase == 'header' and model.probes:
                model.uuid = bytes(reversed(range(16)))
        self.fake.before = change
        with self.assertRaisesRegex(guest.GuestCapacityError, 'before resize') as error:
            self.grow(backup=self.backup())
        self.assertFalse(error.exception.resize_attempted)
        self.assertNotIn('resize', self.fake.events)
        self.assertTrue(self.fake.probes)

    def test_final_root_guard_refuses_capacity_change_before_resize(self):
        self.fake.before = lambda phase, model: setattr(model, 'capacity', 64 * GIB) if phase == 'resize' else None
        with self.assertRaises(guest.GuestCapacityError) as error:
            self.grow(backup=self.backup())
        self.assertTrue(error.exception.resize_attempted)
        self.assertEqual(self.fake.filesystem_bytes, 6 * GIB)
        self.assertTrue(self.fake.probes)

    def test_post_resize_uuid_reboot_or_mapping_changes_never_claim_success(self):
        for index, change in enumerate((lambda model: setattr(model, 'uuid', bytes(reversed(range(16)))), lambda model: model.identity.__setitem__(7, '11111111-2222-3333-4444-555555555555'), lambda model: setattr(model, 'device', '/dev/block/dm-57'))):
            with self.subTest(change=change):
                self.fake = FakeGuest(self.config)
                self.mock_adb.side_effect = self.fake.invoke
                self.fake.after_resize = change
                folder = self.folder / str(index)
                saved_folder = self.folder
                self.folder = folder
                try:
                    with self.assertRaises(guest.GuestCapacityError) as error:
                        self.grow(backup=self.backup())
                finally:
                    self.folder = saved_folder
                self.assertTrue(error.exception.resize_attempted)
                self.assertIn('cannot be rolled back', str(error.exception))
                self.assertTrue(self.fake.probes)
                self.assertNotIn('probe-remove', self.fake.events)

    def test_resize_failure_or_timeout_keeps_backup_and_never_retries(self):
        folder = self.backup()
        for failure in (True, subprocess.TimeoutExpired('resize', guest.GROW_TIMEOUT)):
            with self.subTest(failure=type(failure).__name__):
                self.fake = FakeGuest(self.config)
                self.mock_adb.side_effect = self.fake.invoke
                self.fake.resize_failure = failure
                with self.assertRaises(guest.GuestCapacityError) as error:
                    self.grow(backup=folder)
                self.assertTrue(error.exception.resize_attempted)
                self.assertEqual(self.fake.events.count('resize'), 1)
                self.assertNotIn('probe-remove', self.fake.events)
                self.assertTrue((folder / 'backup.json').is_file())
                self.assertNotIn('private error detail', str(error.exception))

    def test_changed_probe_after_resize_is_retained_and_refuses_attestation(self):
        self.fake.after_resize = lambda model: setattr(model, 'corrupt_probe', True)
        with self.assertRaisesRegex(guest.GuestCapacityError, 'probe changed') as error:
            self.grow(backup=self.backup())
        self.assertTrue(error.exception.resize_attempted)
        self.assertTrue(self.fake.probes)
        self.assertNotIn('probe-remove', self.fake.events)

if __name__ == '__main__':
    unittest.main()
