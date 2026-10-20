"""Exercise GUI-domain detachment, instance ownership, and private launch records."""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'scripts'))
import host_launch
import launch


class HostLaunchTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.sdk = self.root / 'sdk'
        self.executable = self.sdk / 'emulator/emulator'
        self.executable.parent.mkdir(parents=True)
        self.executable.write_text('#!/bin/sh\nexit 0\n')
        self.executable.chmod(0o755)
        self.config = {'sdk': str(self.sdk), 'name': 'Renamed_Own_Device', 'port': 5586}
        self.avd = self.root / 'avd/Renamed_Own_Device.avd'
        self.avd.mkdir(parents=True)
        (self.avd / 'config.ini').write_text('hw.ramSize=6144\n')
        (self.root / 'images').mkdir()
        self.command = [str(self.executable), '-avd', self.config['name'],
                        '-sysdir', str(self.root / 'images'), '-port', '5586', '-no-snapshot-load']
        self.log = self.root / 'logs/emulator-current.log'
        self.domain = 'gui/' + str(os.getuid())
        self.label = host_launch.LABEL_PREFIX + hashlib.sha256(str(self.avd).encode()).hexdigest()[:24]
        self.service = self.domain + '/' + self.label
        self.directory = self.root / 'owned-user-launchd'
        self.plist = self.directory / (self.label + '.plist')
        self.receipt = self.directory / (self.label + '.json')
        self.host_log = self.directory / (self.label + '.log')
        self.existing = None
        self.calls = []
        self.addCleanup(patch.stopall)
        patch.object(host_launch.platform, 'system', return_value='Darwin').start()
        patch.object(host_launch, 'job_directory', return_value=self.directory).start()
        self.control_patch = patch.object(host_launch, 'run_control', side_effect=self.run_control)
        self.control = self.control_patch.start()
        self.app_patch = patch.object(host_launch, 'gui_application', side_effect=lambda directory:
            directory.parent / 'gui-app' / ('f' * 64) / host_launch.GUI_APP_NAME).start()
        patch.object(host_launch, 'child_alive', return_value=True).start()

    def description(self, state='running', pid=8123, path=None, executable=None):
        value = (self.service + ' = {\n\tpath = ' + str(path or self.plist)
                 + '\n\tprogram = ' + str(executable or '/usr/bin/open') + '\n\tstate = ' + state + '\n')
        if pid is not None:
            value += '\tpid = ' + str(pid) + '\n'
        return value + '}\n'

    def run_control(self, *arguments):
        self.calls.append(arguments)
        output, result = '', 0
        if arguments == ('print', self.domain):
            output = self.domain + ' = {}\n'
        elif arguments == ('print', self.service):
            if any(call[0] == 'kickstart' for call in self.calls):
                output = self.description()
            elif self.existing is None:
                result = 113
            else:
                output = self.existing
        elif arguments == ('kickstart', '-p', self.service):
            definition = plistlib.loads(self.plist.read_bytes())
            request = json.loads(Path(definition['ProgramArguments'][7]).read_text())
            report = {'schema': 1, 'token': request['token'], 'pid': 8123, 'supervisor_pid': 8124,
                      'command_sha256': hashlib.sha256(json.dumps(request['command'], separators=(',', ':')).encode()).hexdigest()}
            host_launch.write_private(Path(request['report']), json.dumps(report).encode())
            output = '8123\n'
        return subprocess.CompletedProcess(arguments, result, output, '')

    def start(self, environment=None):
        return host_launch.start(self.root, self.config, self.command,
                                 environment or {}, self.log)

    def seed_idle(self):
        self.start()
        self.calls.clear()
        self.existing = self.description(state='not running', pid=None)

    def test_gui_job_contains_only_owned_command_and_survives_caller_exit(self):
        result = self.start()
        self.assertEqual((result.pid, result.service), (8123, self.service))
        payload = plistlib.loads(self.plist.read_bytes())
        self.assertEqual(payload['ProgramArguments'][8:], self.command)
        self.assertEqual(payload['Program'], '/usr/bin/open')
        self.assertEqual(payload['ProgramArguments'][:4], ['/usr/bin/open', '-W', '-n', '-a'])
        self.assertEqual(payload['WorkingDirectory'], str(self.directory))
        self.assertEqual(payload['ProcessType'], 'Interactive')
        self.assertFalse(payload['RunAtLoad'])
        self.assertFalse(payload['KeepAlive'])
        self.assertEqual(payload['LimitLoadToSessionType'], 'Aqua')
        self.assertEqual(payload['StandardOutPath'], str(self.host_log))
        self.assertEqual(payload['StandardErrorPath'], str(self.host_log))
        self.assertTrue(self.log.is_symlink())
        self.assertEqual(os.readlink(self.log), str(self.host_log))
        self.assertEqual(self.host_log.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.host_log.read_bytes(), b'')
        self.assertIn(('bootstrap', self.domain, str(self.plist)), self.calls)
        self.assertIn(('kickstart', '-p', self.service), self.calls)
        self.assertFalse(any(call[0] in ('kill', 'bootout', 'remove', 'stop', 'setenv') for call in self.calls))

    def test_environment_keeps_color_sdk_and_render_settings_without_caller_secrets(self):
        environment = {'HOME': '/Users/example', 'ANDROID_AVD_HOME': '/tmp/owned-avd',
            'DYLD_INSERT_LIBRARIES': '/tmp/owned-srgb.dylib', 'HYPEROS_AVD_SRGB': '1',
            'HYPEROS_AVD_SRGB_AVD': self.config['name'], 'HYPEROS_AVD_MULTI_DISPLAY': '1',
            'HYPEROS_AVD_DISPLAY_RECIPE': '/tmp/owned-recipe.json',
            'HYPEROS_AVD_TRACKPAD': '1',
            'QT_SCALE_FACTOR': '0.7',
            'MVK_CONFIG_LOG_LEVEL': '0', 'VK_ICD_FILENAMES': '/tmp/driver.json',
            'GITHUB_TOKEN': 'private-token', 'OPENAI_API_KEY': 'private-key',
            'AWS_SECRET_ACCESS_KEY': 'private-cloud', 'PYTHONPATH': '/private/injected',
            'HYPEROS_AVD_WORKSPACE': '/private/caller', 'CODEX_HOME': '/private/codex'}
        self.start(environment)
        payload = plistlib.loads(self.plist.read_bytes())
        self.assertEqual(payload['EnvironmentVariables'], {})
        request = Path(payload['ProgramArguments'][7])
        selected = json.loads(request.read_text())['environment']
        self.assertEqual(set(selected), {'HOME', 'ANDROID_AVD_HOME', 'DYLD_INSERT_LIBRARIES',
            'HYPEROS_AVD_SRGB', 'HYPEROS_AVD_SRGB_AVD', 'HYPEROS_AVD_MULTI_DISPLAY', 'QT_SCALE_FACTOR',
            'HYPEROS_AVD_DISPLAY_RECIPE', 'HYPEROS_AVD_TRACKPAD',
            'MVK_CONFIG_LOG_LEVEL', 'VK_ICD_FILENAMES'})
        for data in (self.plist.read_bytes(), self.receipt.read_bytes(), request.read_bytes()):
            for value in ('private-token', 'private-key', 'private-cloud', '/private/injected',
                          '/private/caller', '/private/codex'):
                self.assertNotIn(value.encode(), data)
        self.assertEqual(self.directory.stat().st_mode & 0o777, 0o700)
        for path in (self.plist, self.receipt, self.directory / 'launch.lock'):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(request.stat().st_mode & 0o777, 0o600)

    def test_raw_cli_idle_job_migrates_to_launch_services_without_stopping_another_job(self):
        self.seed_idle()
        definition = plistlib.loads(self.plist.read_bytes())
        definition.update(Program=str(self.executable), ProgramArguments=self.command,
                          EnvironmentVariables={'DYLD_INSERT_LIBRARIES': '/private/old-color.dylib'})
        payload = plistlib.dumps(definition)
        self.plist.write_bytes(payload)
        saved = json.loads(self.receipt.read_text())
        saved['plist_sha256'] = hashlib.sha256(payload).hexdigest()
        self.receipt.write_text(json.dumps(saved))
        self.existing = self.description(state='not running', pid=None, executable=self.executable)
        self.start()
        current = plistlib.loads(self.plist.read_bytes())
        self.assertEqual(current['Program'], '/usr/bin/open')
        self.assertEqual(current['EnvironmentVariables'], {})
        self.assertEqual(sum(call[0] == 'bootout' for call in self.calls), 1)

    def test_owned_gui_envelope_rejects_foreign_app_request_and_control_dyld(self):
        self.seed_idle()
        original = plistlib.loads(self.plist.read_bytes())
        saved = json.loads(self.receipt.read_text())
        for change in ('app', 'request', 'environment'):
            with self.subTest(change=change):
                current = dict(original, ProgramArguments=list(original['ProgramArguments']))
                if change == 'app':
                    current['ProgramArguments'][4] = '/Applications/Foreign.app'
                elif change == 'request':
                    current['ProgramArguments'][7] = '/private/foreign.request.json'
                else:
                    current['EnvironmentVariables'] = {'DYLD_INSERT_LIBRARIES': '/private/foreign.dylib'}
                payload = plistlib.dumps(current)
                self.plist.write_bytes(payload)
                self.receipt.write_text(json.dumps(dict(saved, plist_sha256=hashlib.sha256(payload).hexdigest())))
                self.calls.clear()
                with self.assertRaisesRegex(RuntimeError, 'GUI.*runtime'):
                    self.start()
                self.assertFalse(any(call[0] in ('bootout', 'bootstrap', 'kickstart') for call in self.calls))

    def test_gui_child_report_has_its_own_pid_and_cannot_select_a_previous_launch(self):
        self.start()
        arguments = plistlib.loads(self.plist.read_bytes())['ProgramArguments']
        request = json.loads(Path(arguments[7]).read_text())
        report = Path(request['report'])
        original = json.loads(report.read_text())
        for update in ({'token': '0' * 32}, {'pid': True}, {'command_sha256': 'f' * 64}):
            with self.subTest(update=update):
                report.write_text(json.dumps(dict(original, **update)))
                with self.assertRaisesRegex(RuntimeError, 'another launch'):
                    host_launch.reported_child(report, request['token'], self.command)

    def test_missing_native_child_report_does_not_claim_the_open_pid_as_emulator(self):
        def without_report(*arguments):
            result = self.run_control(*arguments)
            if arguments[0] == 'kickstart':
                definition = plistlib.loads(self.plist.read_bytes())
                request = json.loads(Path(definition['ProgramArguments'][7]).read_text())
                Path(request['report']).unlink()
            return result
        self.control.side_effect = without_report
        with patch.object(host_launch.time, 'monotonic', side_effect=[0, 1, 11]), \
                patch.object(host_launch.time, 'sleep'), \
                self.assertRaisesRegex(RuntimeError, 'owned child'):
            self.start()
        self.assertEqual(sum(call[0] == 'kickstart' for call in self.calls), 1)
        self.assertFalse(any(call[0] in ('bootout', 'kill', 'stop') for call in self.calls))

    def test_exited_reported_child_is_not_reported_as_a_successful_sdk_launch(self):
        with patch.object(host_launch, 'child_alive', return_value=False), \
                patch.object(host_launch.time, 'monotonic', side_effect=[0, 1, 11]), \
                patch.object(host_launch.time, 'sleep'), \
                self.assertRaisesRegex(RuntimeError, 'did not remain running'):
            self.start()

    def test_record_hash_binds_exact_private_plist(self):
        self.start()
        receipt = json.loads(self.receipt.read_text())
        self.assertEqual(receipt['plist_sha256'], hashlib.sha256(self.plist.read_bytes()).hexdigest())
        self.assertEqual(receipt['avd'], str(self.avd))
        self.assertEqual(receipt['executable'], str(self.executable))
        self.assertEqual(receipt['uid'], os.getuid())

    def test_completed_owned_job_can_be_replaced_without_killing_any_process(self):
        self.seed_idle()
        self.command += ['-memory', '8192']
        self.start()
        self.assertIn(('bootout', self.service), self.calls)
        self.assertEqual(sum(call[0] == 'bootout' for call in self.calls), 1)
        self.assertFalse(any('-k' in call or call[0] in ('kill', 'stop', 'remove') for call in self.calls))
        self.assertEqual(plistlib.loads(self.plist.read_bytes())['ProgramArguments'][8:], self.command)

    def test_internal_log_rotation_preserves_readable_workspace_history(self):
        self.seed_idle()
        self.host_log.write_bytes(b'previous private launch output\n')
        self.host_log.chmod(0o600)
        old_inode = self.host_log.stat().st_ino
        self.start()
        histories = [path for path in self.log.parent.glob('emulator-*.log') if path != self.log]
        self.assertEqual(len(histories), 1)
        self.assertTrue(histories[0].is_symlink())
        self.assertEqual(histories[0].read_bytes(), b'previous private launch output\n')
        self.assertEqual(histories[0].stat().st_ino, old_inode)
        self.assertNotEqual(os.readlink(histories[0]), str(self.host_log))
        self.assertEqual(os.readlink(self.log), str(self.host_log))

    def test_legacy_launchd_0644_log_is_archived_without_chmod_and_new_log_is_precreated_private(self):
        self.seed_idle()
        self.host_log.write_bytes(b'legacy launchd output\n')
        self.host_log.chmod(0o644)
        inode = self.host_log.stat().st_ino
        self.start()
        histories = [path for path in self.log.parent.glob('emulator-*.log') if path != self.log]
        self.assertEqual(len(histories), 1)
        self.assertEqual(histories[0].read_bytes(), b'legacy launchd output\n')
        self.assertEqual(histories[0].stat().st_ino, inode)
        self.assertEqual(histories[0].stat().st_mode & 0o777, 0o644)
        self.assertEqual(self.host_log.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.host_log.read_bytes(), b'')

    def test_group_writable_host_log_is_retained_without_chmod_or_job_actions(self):
        self.seed_idle()
        self.host_log.write_bytes(b'custom mutable output\n')
        self.host_log.chmod(0o660)
        with self.assertRaisesRegex(RuntimeError, 'aliased Emulator host log'):
            self.start()
        self.assertEqual(self.host_log.stat().st_mode & 0o777, 0o660)
        self.assertEqual(self.host_log.read_bytes(), b'custom mutable output\n')
        self.assertFalse(any(call[0] in ('bootout', 'bootstrap', 'kickstart') for call in self.calls))

    def test_legacy_regular_log_is_archived_without_changing_its_bytes(self):
        self.log.parent.mkdir()
        self.log.write_bytes(b'original regular Emulator log\n')
        self.start()
        histories = [path for path in self.log.parent.glob('emulator-*.log') if path != self.log]
        self.assertEqual(len(histories), 1)
        self.assertFalse(histories[0].is_symlink())
        self.assertEqual(histories[0].read_bytes(), b'original regular Emulator log\n')
        self.assertEqual(os.readlink(self.log), str(self.host_log))

    def test_foreign_workspace_log_link_is_preserved_before_launchctl_actions(self):
        foreign = self.root / 'foreign-log'
        foreign.write_bytes(b'foreign evidence\n')
        self.log.parent.mkdir()
        self.log.symlink_to(foreign)
        with self.assertRaisesRegex(RuntimeError, 'foreign Emulator log link'):
            self.start()
        self.assertEqual(foreign.read_bytes(), b'foreign evidence\n')
        self.assertEqual(os.readlink(self.log), str(foreign))
        self.control.assert_not_called()

    def test_hardlinked_workspace_and_internal_logs_are_preserved(self):
        self.seed_idle()
        self.log.unlink()
        foreign = self.root / 'foreign-log'
        foreign.write_bytes(b'foreign evidence\n')
        foreign.chmod(0o600)
        for target in (self.log, self.host_log):
            with self.subTest(target=target):
                target.unlink(missing_ok=True)
                os.link(foreign, target)
                with self.assertRaisesRegex(RuntimeError, 'aliased'):
                    self.start()
                self.assertEqual(foreign.read_bytes(), b'foreign evidence\n')
                self.assertFalse(any(call[0] in ('bootout', 'bootstrap', 'kickstart') for call in self.calls))
                target.unlink()

    def test_authenticated_inactive_legacy_external_job_migrates_to_internal_paths(self):
        self.seed_idle()
        self.log.unlink()
        self.log.write_bytes(b'legacy launch output\n')
        definition = plistlib.loads(self.plist.read_bytes())
        definition['Program'] = str(self.executable)
        definition['ProgramArguments'] = self.command
        self.existing = self.description(state='not running', pid=None, executable=self.executable)
        definition['WorkingDirectory'] = str(self.root)
        definition['StandardOutPath'] = definition['StandardErrorPath'] = str(self.log)
        payload = plistlib.dumps(definition)
        self.plist.write_bytes(payload)
        identity = json.loads(self.receipt.read_text())
        identity.pop('host_log')
        identity.pop('working_directory')
        identity['schema'] = 1
        identity['plist_sha256'] = hashlib.sha256(payload).hexdigest()
        self.receipt.write_text(json.dumps(identity))
        self.start()
        current = plistlib.loads(self.plist.read_bytes())
        self.assertEqual(current['WorkingDirectory'], str(self.directory))
        self.assertEqual(current['StandardOutPath'], str(self.host_log))
        self.assertEqual(json.loads(self.receipt.read_text())['schema'], 2)
        self.assertEqual([path for path in self.log.parent.glob('emulator-*.log') if path != self.log][0].read_bytes(), b'legacy launch output\n')

    def test_running_owned_job_is_preserved(self):
        self.seed_idle()
        previous = self.plist.read_bytes(), self.receipt.read_bytes()
        self.existing = self.description()
        with self.assertRaisesRegex(RuntimeError, 'still active'):
            self.start()
        self.assertEqual(previous, (self.plist.read_bytes(), self.receipt.read_bytes()))
        self.assertFalse(any(call[0] in ('bootout', 'bootstrap', 'kickstart') for call in self.calls))

    def test_foreign_job_cannot_authorize_bootout(self):
        for description in (self.description(state='not running', pid=None, path='/tmp/foreign.plist'),
                            self.description(state='not running', pid=None, executable='/tmp/foreign-emulator'),
                            self.description(state='not running', pid=None).replace(self.service, 'gui/0/foreign')):
            with self.subTest(description=description):
                self.calls.clear()
                self.existing = description
                with self.assertRaisesRegex(RuntimeError, 'ownership'):
                    self.start()
                self.assertFalse(any(call[0] in ('bootout', 'bootstrap', 'kickstart') for call in self.calls))

    def test_missing_or_tampered_receipt_preserves_idle_job(self):
        self.seed_idle()
        original = self.receipt.read_bytes()
        for data in (None, b'{}\n', original.replace(b'"schema": 2', b'"schema": 3')):
            with self.subTest(data=data):
                self.calls.clear()
                if self.receipt.exists():
                    self.receipt.unlink()
                if data is not None:
                    self.receipt.write_bytes(data)
                    self.receipt.chmod(0o600)
                with self.assertRaisesRegex(RuntimeError, 'ownership'):
                    self.start()
                self.assertFalse(any(call[0] in ('bootout', 'bootstrap', 'kickstart') for call in self.calls))

    def test_modified_plist_preserves_idle_job_even_when_runtime_paths_still_match(self):
        self.seed_idle()
        self.plist.write_bytes(self.plist.read_bytes().replace(b'Interactive', b'Background'))
        with self.assertRaisesRegex(RuntimeError, 'ownership'):
            self.start()
        self.assertFalse(any(call[0] == 'bootout' for call in self.calls))

    def test_unregistered_unknown_file_is_not_overwritten(self):
        self.seed_idle()
        self.existing = None
        self.receipt.write_bytes(b'{}\n')
        with self.assertRaisesRegex(RuntimeError, 'ownership'):
            self.start()
        self.assertEqual(self.receipt.read_bytes(), b'{}\n')
        self.assertFalse(any(call[0] in ('bootout', 'bootstrap', 'kickstart') for call in self.calls))

    def test_alias_and_hardlink_records_are_not_used_for_job_removal(self):
        self.seed_idle()
        contents = self.receipt.read_bytes()
        target = self.root / 'foreign'
        target.write_bytes(contents)
        target.chmod(0o600)
        self.receipt.unlink()
        for linked in ('symlink', 'hardlink'):
            with self.subTest(linked=linked):
                if linked == 'symlink':
                    self.receipt.symlink_to(target)
                else:
                    os.link(target, self.receipt)
                with self.assertRaisesRegex(RuntimeError, 'aliased'):
                    self.start()
                self.assertEqual(target.read_bytes(), contents)
                self.assertFalse(any(call[0] == 'bootout' for call in self.calls))
                self.receipt.unlink()

    def test_launch_directory_alias_is_refused(self):
        foreign = self.root / 'foreign'
        foreign.mkdir()
        self.directory.symlink_to(foreign)
        with self.assertRaisesRegex(RuntimeError, 'aliased'):
            self.start()
        self.control.assert_not_called()
        self.assertEqual(list(foreign.iterdir()), [])

    def test_avd_alias_or_mismatched_command_is_refused(self):
        self.command[self.command.index('-avd') + 1] = 'Foreign_Device'
        with self.assertRaisesRegex(RuntimeError, 'owned AVD'):
            self.start()
        self.control.assert_not_called()

    def test_invalid_environment_is_refused_before_registration(self):
        with self.assertRaisesRegex(RuntimeError, 'environment'):
            self.start({'DYLD_INSERT_LIBRARIES': 'invalid\0value'})
        self.assertFalse(any(call[0] in ('bootstrap', 'kickstart') for call in self.calls))

    def test_missing_gui_session_does_not_fallback_to_caller_child(self):
        self.control.side_effect = lambda *args: subprocess.CompletedProcess(args, 125, '', 'unavailable')
        with patch.object(host_launch.subprocess, 'Popen') as child, \
                self.assertRaisesRegex(RuntimeError, 'GUI launchd session'):
            self.start()
        child.assert_not_called()
        self.assertFalse(self.plist.exists())

    def test_service_inspection_failure_does_not_replace_inaccessible_job(self):
        def fail(*args):
            if args == ('print', self.service):
                return subprocess.CompletedProcess(args, 1, '', 'permission failure')
            return self.run_control(*args)
        self.control.side_effect = fail
        with self.assertRaisesRegex(RuntimeError, 'inspect'):
            self.start()
        self.assertFalse(any(call[0] in ('bootout', 'bootstrap', 'kickstart') for call in self.calls))

    def test_bootstrap_failure_retains_evidence_without_kickstart_or_job_cleanup(self):
        def fail(*args):
            if args[0] == 'bootstrap':
                self.calls.append(args)
                return subprocess.CompletedProcess(args, 5, '', 'Bootstrap failed: 5: Input/output error')
            return self.run_control(*args)
        self.control.side_effect = fail
        with self.assertRaisesRegex(RuntimeError, 'register.*launchctl exit 5.*Input/output error'):
            self.start()
        self.assertTrue(self.receipt.is_file())
        self.assertTrue(self.plist.is_file())
        self.assertFalse(any(call[0] in ('kickstart', 'bootout') for call in self.calls))

    def test_kickstart_failure_retains_ownership_without_restarting_or_killing_job(self):
        def fail(*args):
            if args[0] == 'kickstart':
                self.calls.append(args)
                return subprocess.CompletedProcess(args, 1, '', 'failed')
            return self.run_control(*args)
        self.control.side_effect = fail
        with self.assertRaisesRegex(RuntimeError, 'launch failed'):
            self.start()
        self.assertTrue(self.receipt.is_file())
        self.assertEqual(sum(call[0] == 'kickstart' for call in self.calls), 1)
        self.assertFalse(any(call[0] in ('bootout', 'kill', 'stop') for call in self.calls))

    def test_job_exiting_immediately_is_reported_without_automatic_restart(self):
        def exit_early(*args):
            value = self.run_control(*args)
            if args == ('print', self.service) and any(call[0] == 'kickstart' for call in self.calls):
                value.stdout = self.description(state='not running', pid=None).replace('}\n', '\tlast exit code = 1\n}\n')
            return value
        self.control.side_effect = exit_early
        with self.assertRaisesRegex(RuntimeError, 'did not remain running'):
            self.start()
        self.assertEqual(sum(call[0] == 'kickstart' for call in self.calls), 1)
        self.assertFalse(any(call[0] == 'bootout' for call in self.calls))

    def test_authenticated_running_service_uses_current_pid_after_sdk_launcher_replacement(self):
        def replaced(*args):
            result = self.run_control(*args)
            if args == ('print', self.service) and any(call[0] == 'kickstart' for call in self.calls):
                result.stdout = self.description(pid=8456).replace('}\n', '\tlast exit code = (never exited)\n}\n')
            return result
        self.control.side_effect = replaced
        result = self.start()
        self.assertEqual(result.pid, 8123)
        self.assertEqual(result.service, self.service)
        self.assertEqual(sum(call[0] == 'kickstart' for call in self.calls), 1)

    def test_never_exited_placeholder_does_not_abort_startup_before_pid_is_published(self):
        pending = [True]
        def starting(*args):
            result = self.run_control(*args)
            if (args == ('print', self.service) and any(call[0] == 'kickstart' for call in self.calls)
                    and pending):
                pending.clear()
                result.stdout = self.description(state='not running', pid=None).replace(
                    '}\n', '\tlast exit code = (never exited)\n}\n')
            return result
        self.control.side_effect = starting
        with patch.object(host_launch.time, 'sleep'):
            self.assertEqual(self.start().pid, 8123)
        self.assertEqual(sum(call[0] == 'kickstart' for call in self.calls), 1)

    def external_state(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.plist = self.directory / (self.label + '.plist')
        self.receipt = self.directory / (self.label + '.json')
        self.host_log = self.directory / (self.label + '.log')
        patch.object(host_launch, 'job_directory', return_value=self.directory).start()

    def reidentify(self, root=None, name='New_Chosen_Name'):
        old_service = self.service
        old_description = self.description(state='not running', pid=None)
        self.root = root or self.root
        self.config['name'] = name
        self.config['sdk'] = str(self.root / 'sdk')
        self.executable = self.root / 'sdk/emulator/emulator'
        self.avd = self.root / 'avd' / (name + '.avd')
        self.avd.mkdir(parents=True, exist_ok=True)
        (self.avd / 'config.ini').write_text('hw.ramSize=6144\n')
        self.command = [str(self.executable), '-avd', name, '-sysdir', str(self.root / 'images'),
                        '-port', str(self.config['port']), '-no-snapshot-load']
        self.log = self.root / 'logs/emulator-current.log'
        self.label = host_launch.LABEL_PREFIX + hashlib.sha256(str(self.avd).encode()).hexdigest()[:24]
        self.service = self.domain + '/' + self.label
        self.plist = self.directory / (self.label + '.plist')
        self.receipt = self.directory / (self.label + '.json')
        self.host_log = self.directory / (self.label + '.log')
        self.existing = None
        def previous(*arguments):
            if arguments == ('print', old_service):
                self.calls.append(arguments)
                return subprocess.CompletedProcess(arguments, 0, old_description, '')
            return self.run_control(*arguments)
        self.control.side_effect = previous
        return old_service

    def test_renamed_avd_authenticates_inactive_old_log_without_stopping_its_job(self):
        self.seed_idle()
        old_plist, old_receipt = self.plist, self.receipt
        saved = old_plist.read_bytes(), old_receipt.read_bytes()
        self.host_log.write_bytes(b'owned prior-name log\n')
        old_service = self.reidentify()
        self.start()
        self.assertEqual(saved, (old_plist.read_bytes(), old_receipt.read_bytes()))
        self.assertNotIn(('bootout', old_service), self.calls)
        history = [path for path in self.log.parent.glob('emulator-*.log') if path != self.log]
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0].read_bytes(), b'owned prior-name log\n')
        self.assertEqual(os.readlink(self.log), str(self.host_log))

    def managed_image_fixture(self, absolute=False):
        version = 'v0.2.5-a17-hyperos4-hongkong-r6'
        target = self.root / 'versions' / version
        target.mkdir(parents=True)
        (self.root / 'images').rename(target / 'images')
        link = target / 'images' if absolute else Path('versions') / version / 'images'
        (self.root / 'images').symlink_to(link, target_is_directory=True)
        (self.root / 'local').mkdir()
        (target / 'local').mkdir()
        manifest = {'project': 'HyperOS-AVD', 'format': 3, 'version': version}
        for folder in (self.root, target):
            (folder / 'local/installed-release.json').write_text(json.dumps(manifest))
        (self.root / 'local/manager.json').write_text(json.dumps(
            {'schema': 1, 'version': version, 'runtime': str(target / 'runtime')}))
        return target

    def assert_managed_image_rename(self, absolute):
        self.managed_image_fixture(absolute=absolute)
        self.seed_idle()
        old_plist, old_receipt = self.plist, self.receipt
        previous = old_plist.read_bytes(), old_receipt.read_bytes()
        self.host_log.write_bytes(b'owned managed-image log\n')
        old_service = self.reidentify()
        self.start()
        self.assertEqual(previous, (old_plist.read_bytes(), old_receipt.read_bytes()))
        self.assertNotIn(('bootout', old_service), self.calls)
        self.assertEqual(os.readlink(self.log), str(self.host_log))

    def test_renamed_avd_accepts_only_the_authenticated_managed_image_link(self):
        self.assert_managed_image_rename(absolute=False)

    def test_renamed_avd_accepts_the_authenticated_legacy_absolute_image_link(self):
        self.assert_managed_image_rename(absolute=True)

    def test_managed_image_log_migration_refuses_changed_provenance_and_aliases(self):
        target = self.managed_image_fixture()
        self.seed_idle()
        old_plist, old_receipt, old_log = self.plist, self.receipt, self.host_log
        previous = old_plist.read_bytes(), old_receipt.read_bytes(), os.readlink(self.log)
        self.reidentify()
        manager = self.root / 'local/manager.json'
        active = self.root / 'local/installed-release.json'
        manager_bytes, active_bytes = manager.read_bytes(), active.read_bytes()
        image_link = self.root / 'images'
        original_link = os.readlink(image_link)
        foreign = self.root / 'foreign-images'
        foreign.mkdir()
        alias_record = self.root / 'alias-record'

        def refused():
            self.calls.clear()
            with self.assertRaisesRegex(RuntimeError, 'managed Emulator image'):
                self.start()
            self.assertEqual(previous, (old_plist.read_bytes(), old_receipt.read_bytes(), os.readlink(self.log)))
            self.assertFalse(any(call[0] in ('bootout', 'bootstrap', 'kickstart') for call in self.calls))
            self.assertTrue(old_log.exists())

        manager.write_text(json.dumps({'schema': 1, 'version': 'v0.2.4-other-r5'}))
        refused(); manager.write_bytes(manager_bytes)
        active.write_text(json.dumps({'project': 'HyperOS-AVD', 'format': 3, 'version': target.name,
                                      'unreviewed': True}))
        refused(); active.write_bytes(active_bytes)
        image_link.unlink(); image_link.symlink_to(foreign, target_is_directory=True)
        refused(); image_link.unlink(); image_link.symlink_to(original_link, target_is_directory=True)
        manager.rename(alias_record); manager.symlink_to(alias_record)
        refused(); manager.unlink(); alias_record.rename(manager)
        os.link(active, alias_record)
        refused(); alias_record.unlink()
        active.chmod(0o666)
        refused(); active.chmod(0o644)
        images = target / 'images'
        images.rename(foreign / 'nested')
        images.symlink_to(foreign / 'nested', target_is_directory=True)
        refused(); images.unlink(); (foreign / 'nested').rename(images)

    def test_unmanaged_image_alias_cannot_authorize_a_renamed_log_bridge(self):
        foreign = self.root / 'foreign-images'
        (self.root / 'images').rename(foreign)
        (self.root / 'images').symlink_to(foreign, target_is_directory=True)
        self.seed_idle()
        previous = self.plist.read_bytes(), self.receipt.read_bytes(), os.readlink(self.log)
        old_plist, old_receipt = self.plist, self.receipt
        self.reidentify()
        self.calls.clear()
        with self.assertRaisesRegex(RuntimeError, 'managed Emulator image'):
            self.start()
        self.assertEqual(previous, (old_plist.read_bytes(), old_receipt.read_bytes(), os.readlink(self.log)))
        self.assertFalse(self.calls)

    def test_active_managed_image_log_owner_remains_untouched(self):
        self.managed_image_fixture()
        self.seed_idle()
        old_service, old_description = self.service, self.description()
        previous = self.plist.read_bytes(), self.receipt.read_bytes(), os.readlink(self.log)
        old_plist, old_receipt = self.plist, self.receipt
        self.reidentify()
        def active(*arguments):
            if arguments == ('print', old_service):
                self.calls.append(arguments)
                return subprocess.CompletedProcess(arguments, 0, old_description, '')
            return self.run_control(*arguments)
        self.control.side_effect = active
        with self.assertRaisesRegex(RuntimeError, 'prior.*still active'):
            self.start()
        self.assertEqual(previous, (old_plist.read_bytes(), old_receipt.read_bytes(), os.readlink(self.log)))
        self.assertFalse(any(call[0] in ('bootout', 'bootstrap', 'kickstart') for call in self.calls))

    def test_idle_same_avd_can_change_its_port_and_sdk_location(self):
        self.seed_idle()
        old_executable = self.executable
        old_description = self.description(state='not running', pid=None)
        self.config['port'] = 5590
        self.executable = self.root / 'new-sdk/emulator/emulator'
        self.executable.parent.mkdir(parents=True)
        self.executable.write_text('#!/bin/sh\nexit 0\n')
        self.executable.chmod(0o755)
        self.config['sdk'] = str(self.root / 'new-sdk')
        self.command[0] = str(self.executable)
        self.command[self.command.index('-port') + 1] = '5590'
        self.existing = old_description
        self.start()
        definition = plistlib.loads(self.plist.read_bytes())
        self.assertEqual(definition['Program'], '/usr/bin/open')
        self.assertEqual(definition['ProgramArguments'][8:], self.command)
        self.assertNotEqual(definition['ProgramArguments'][8], str(old_executable))
        saved = json.loads(self.receipt.read_text())
        self.assertEqual(saved['port'], 5590)
        self.assertEqual(saved['executable'], str(self.executable))
        self.assertEqual(sum(call[0] == 'bootout' for call in self.calls), 1)

    def test_active_same_avd_is_not_stopped_when_its_requested_port_changes(self):
        self.seed_idle()
        saved = self.plist.read_bytes(), self.receipt.read_bytes()
        self.existing = self.description()
        self.config['port'] = 5590
        self.command[self.command.index('-port') + 1] = '5590'
        with self.assertRaisesRegex(RuntimeError, 'still active'):
            self.start()
        self.assertEqual(saved, (self.plist.read_bytes(), self.receipt.read_bytes()))
        self.assertFalse(any(call[0] in ('bootout', 'bootstrap', 'kickstart') for call in self.calls))

    def test_moved_workspace_authenticates_its_previous_absent_path(self):
        self.external_state()
        self.seed_idle()
        self.host_log.write_bytes(b'owned pre-move log\n')
        old_root = self.root
        moved = self.root.with_name(self.root.name + '-moved')
        self.addCleanup(lambda: shutil.rmtree(moved, ignore_errors=True))
        old_root.rename(moved)
        self.reidentify(root=moved, name=self.config['name'])
        self.start()
        self.assertFalse(old_root.exists())
        history = [path for path in self.log.parent.glob('emulator-*.log') if path != self.log]
        self.assertEqual(history[0].read_bytes(), b'owned pre-move log\n')

    def test_copied_foreign_workspace_cannot_claim_an_existing_log_owner(self):
        self.external_state()
        self.seed_idle()
        original_root, original_log = self.root, self.log
        copied = self.root.with_name(self.root.name + '-copy')
        self.addCleanup(lambda: shutil.rmtree(copied, ignore_errors=True))
        shutil.copytree(original_root, copied, symlinks=True)
        self.reidentify(root=copied, name=self.config['name'])
        with self.assertRaisesRegex(RuntimeError, 'foreign workspace'):
            self.start()
        self.assertTrue(original_root.exists())
        self.assertEqual(os.readlink(self.log), os.readlink(original_log))
        self.assertFalse(any(call[0] in ('bootout', 'bootstrap', 'kickstart') for call in self.calls))

    def test_prior_active_identity_preserves_its_log_and_records(self):
        self.seed_idle()
        old_service, old_description = self.service, self.description()
        previous = self.plist.read_bytes(), self.receipt.read_bytes(), os.readlink(self.log)
        old_plist, old_receipt = self.plist, self.receipt
        self.reidentify()
        def active(*arguments):
            if arguments == ('print', old_service):
                self.calls.append(arguments)
                return subprocess.CompletedProcess(arguments, 0, old_description, '')
            return self.run_control(*arguments)
        self.control.side_effect = active
        with self.assertRaisesRegex(RuntimeError, 'prior.*still active'):
            self.start()
        self.assertEqual(previous, (old_plist.read_bytes(), old_receipt.read_bytes(), os.readlink(self.log)))
        self.assertFalse(any(call[0] in ('bootout', 'bootstrap', 'kickstart') for call in self.calls))

    def test_tampered_previous_identity_cannot_authorize_a_renamed_log_bridge(self):
        self.seed_idle()
        old_receipt = self.receipt
        self.reidentify()
        old_receipt.write_bytes(b'{}\n')
        with self.assertRaisesRegex(RuntimeError, 'prior.*identity'):
            self.start()
        self.assertEqual(old_receipt.read_bytes(), b'{}\n')
        self.assertFalse(any(call[0] in ('bootout', 'bootstrap', 'kickstart') for call in self.calls))

    def interrupt_receipt(self):
        real = host_launch.write_private
        def failure(path, data, **options):
            if path == self.receipt:
                raise OSError('simulated ENOSPC during receipt publication')
            return real(path, data, **options)
        with patch.object(host_launch, 'write_private', side_effect=failure), \
                self.assertRaisesRegex(OSError, 'ENOSPC'):
            self.start()

    def test_interrupted_first_definition_pair_recovers_without_external_repair(self):
        self.interrupt_receipt()
        pending = self.plist.with_suffix('.pending.json')
        self.assertTrue(pending.is_file())
        self.assertTrue(self.plist.is_file())
        self.assertFalse(self.receipt.exists())
        inode = self.plist.stat().st_ino
        self.calls.clear()
        self.start()
        self.assertFalse(pending.exists())
        self.assertEqual(json.loads(self.receipt.read_text())['plist_sha256'], hashlib.sha256(self.plist.read_bytes()).hexdigest())
        self.assertEqual(sum(call[0] == 'kickstart' for call in self.calls), 1)

    def test_interrupted_idle_job_replacement_recovers_both_consistent_records(self):
        self.seed_idle()
        self.command += ['-memory', '8192']
        self.interrupt_receipt()
        self.calls.clear()
        self.start()
        saved = json.loads(self.receipt.read_text())
        self.assertEqual(saved['plist_sha256'], hashlib.sha256(self.plist.read_bytes()).hexdigest())
        self.assertEqual(plistlib.loads(self.plist.read_bytes())['ProgramArguments'][8:], self.command)
        self.assertFalse(self.plist.with_suffix('.pending.json').exists())

    def test_log_preparation_failure_leaves_a_recoverable_complete_ownership_pair(self):
        with patch.object(host_launch, 'prepare_log', side_effect=OSError('simulated log failure')), \
                self.assertRaisesRegex(OSError, 'log failure'):
            self.start()
        self.assertTrue(self.plist.is_file())
        self.assertTrue(self.receipt.is_file())
        self.calls.clear()
        self.start()
        self.assertTrue(self.log.is_symlink())

    def test_modified_partial_state_is_preserved_instead_of_recovered(self):
        self.interrupt_receipt()
        self.receipt.write_bytes(b'unknown user content')
        self.receipt.chmod(0o600)
        self.calls.clear()
        with self.assertRaisesRegex(RuntimeError, 'Modified pending'):
            self.start()
        self.assertEqual(self.receipt.read_bytes(), b'unknown user content')
        self.assertTrue(self.plist.with_suffix('.pending.json').is_file())
        self.assertFalse(any(call[0] in ('bootout', 'bootstrap', 'kickstart') for call in self.calls))

    def test_active_job_is_not_repaired_or_stopped_by_a_pending_transaction(self):
        self.interrupt_receipt()
        pending = self.plist.with_suffix('.pending.json')
        previous = self.plist.read_bytes(), pending.read_bytes()
        self.existing = self.description()
        self.calls.clear()
        with self.assertRaisesRegex(RuntimeError, 'still active'):
            self.start()
        self.assertEqual(previous, (self.plist.read_bytes(), pending.read_bytes()))
        self.assertFalse(self.receipt.exists())
        self.assertFalse(any(call[0] in ('bootout', 'bootstrap', 'kickstart') for call in self.calls))

    def test_unknown_pending_transaction_and_racing_new_file_are_preserved(self):
        self.directory.mkdir()
        pending = self.plist.with_suffix('.pending.json')
        pending.write_bytes(b'unknown transaction')
        pending.chmod(0o600)
        with self.assertRaisesRegex(RuntimeError, 'Unknown pending'):
            self.start()
        self.assertEqual(pending.read_bytes(), b'unknown transaction')
        target = self.directory / 'new-private-file'
        real_link = os.link
        def raced(temporary, destination):
            Path(destination).write_bytes(b'unknown racing file')
            Path(destination).chmod(0o600)
            return real_link(temporary, destination)
        with patch.object(host_launch.os, 'link', side_effect=raced), \
                self.assertRaisesRegex(RuntimeError, 'unexpectedly created'):
            host_launch.write_private(target, b'expected')
        self.assertEqual(target.read_bytes(), b'unknown racing file')

    def test_control_environment_never_inherits_secrets_or_emulator_dyld_hook(self):
        self.control_patch.stop()
        with patch.dict(os.environ, {'GITHUB_TOKEN': 'secret', 'DYLD_INSERT_LIBRARIES': '/tmp/color.dylib'}), \
                patch.object(host_launch.subprocess, 'run') as control:
            host_launch.run_control('print', self.domain)
        arguments, options = control.call_args
        self.assertEqual(arguments[0], ['/bin/launchctl', 'print', self.domain])
        self.assertEqual(set(options['env']) - {'HOME'}, {'PATH'})
        self.assertTrue(options['capture_output'])
        self.assertLessEqual(options['timeout'], 15)


class NativeGuiApplicationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.directory = self.root / 'launchd'
        self.directory.mkdir(mode=0o700)
        self.calls = []

    def compile(self, arguments, **options):
        self.calls.append((arguments, options))
        if arguments[0] == '/usr/bin/osacompile':
            app = Path(arguments[2])
            executable = app / 'Contents/MacOS/applet'
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b'owned native applet')
            executable.chmod(0o755)
            (app / 'Contents/Resources').mkdir()
            (app / 'Contents/Info.plist').write_bytes(plistlib.dumps({
                'CFBundleExecutable': 'applet', 'NSContactsUsageDescription': 'Generic scripting addition.'}))
        return subprocess.CompletedProcess(arguments, 0, '', '')

    def test_app_is_offline_native_and_privacy_scoped_with_checked_cache(self):
        with patch.object(host_launch.subprocess, 'run', side_effect=self.compile), \
                patch.dict(os.environ, {'OPENAI_API_KEY': 'private-secret', 'DYLD_INSERT_LIBRARIES': '/private/render.dylib'}):
            app = host_launch.gui_application(self.directory)
            second = host_launch.gui_application(self.directory)
        self.assertEqual(second, app)
        self.assertEqual([call[0][0] for call in self.calls], ['/usr/bin/osacompile', '/usr/bin/codesign'])
        for _, options in self.calls:
            self.assertNotIn('OPENAI_API_KEY', options['env'])
            self.assertNotIn('DYLD_INSERT_LIBRARIES', options['env'])
        info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
        self.assertEqual(info['CFBundleIdentifier'], host_launch.GUI_APP_IDENTIFIER)
        self.assertIn('NSRemovableVolumesUsageDescription', info)
        self.assertNotIn('NSContactsUsageDescription', info)
        self.assertNotIn('NSAppleEventsUsageDescription', info)
        self.assertEqual((app / 'Contents/Resources/runner.py').read_text(), host_launch.GUI_RUNNER)

    def test_modified_native_app_or_added_resource_is_preserved_without_recompiling(self):
        with patch.object(host_launch.subprocess, 'run', side_effect=self.compile):
            app = host_launch.gui_application(self.directory)
        extra = app / 'Contents/Resources/user-owned-resource'
        extra.write_bytes(b'custom content')
        with patch.object(host_launch.subprocess, 'run') as compiler, \
                self.assertRaisesRegex(RuntimeError, 'Modified GUI application'):
            host_launch.gui_application(self.directory)
        compiler.assert_not_called()
        self.assertEqual(extra.read_bytes(), b'custom content')

    def test_failed_native_compilation_does_not_publish_or_reuse_partial_cache(self):
        failure = subprocess.CompletedProcess([], 1, '', 'compiler diagnostic')
        with patch.object(host_launch.subprocess, 'run', return_value=failure), \
                self.assertRaisesRegex(RuntimeError, 'native GUI launcher.*compiler diagnostic'):
            host_launch.gui_application(self.directory)
        self.assertEqual(list((self.root / 'gui-app').iterdir()), [])

    def request(self):
        label = host_launch.LABEL_PREFIX + '1' * 24
        log = self.directory / (label + '.log')
        log.touch(mode=0o600)
        marker = self.root / 'child-arguments.json'
        executable = self.root / 'emulator'
        executable.write_text('#!' + str(Path(sys.executable).resolve()) + '\n'
                              'import json, pathlib, sys\n'
                              'pathlib.Path(' + repr(str(marker)) + ').write_text(json.dumps(sys.argv[1:]))\n')
        executable.chmod(0o700)
        identity = {'label': label, 'workspace': str(self.root), 'name': 'Private_Probe',
                    'port': 5586, 'host_log': str(log)}
        command = [str(executable), '-avd', identity['name'], '-sysdir', str(self.root / 'images'),
                   '-port', '5586', '-literal-test', '$HOME `secret` a b']
        request, report, token = host_launch.launch_request(self.directory, identity, command,
                                                          {'PATH': '/usr/bin:/bin'})
        runner = self.root / 'runner.py'
        runner.write_text(host_launch.GUI_RUNNER)
        return runner, request, report, token, command, marker

    def test_private_runner_preserves_literal_arguments_and_reports_exact_child(self):
        runner, request, report, token, command, marker = self.request()
        result = subprocess.run([sys.executable, '-I', '-B', str(runner), str(request)],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(marker.read_text()), command[1:])
        self.assertGreater(host_launch.reported_child(report, token, command), 0)
        self.assertEqual(report.stat().st_mode & 0o777, 0o600)

    def test_private_runner_refuses_unowned_aliases_and_runtime_argument_mismatch(self):
        runner, request, report, token, command, marker = self.request()
        original = request.read_bytes()
        data = json.loads(original)
        data['command'][data['command'].index('-avd') + 1] = 'Foreign_Device'
        request.write_text(json.dumps(data))
        result = subprocess.run([sys.executable, '-I', '-B', str(runner), str(request)],
                                capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(marker.exists())
        self.assertFalse(report.exists())
        request.unlink()
        foreign = self.root / 'foreign-request'
        foreign.write_bytes(original)
        foreign.chmod(0o600)
        request.symlink_to(foreign)
        result = subprocess.run([sys.executable, '-I', '-B', str(runner), str(request)],
                                capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(foreign.read_bytes(), original)
        self.assertFalse(marker.exists())

    def test_report_publication_failure_keeps_the_created_child_supervised(self):
        runner, request, report, token, command, marker = self.request()
        process = type('Child', (), {'pid': 123, 'wait': lambda child: 0})()
        with patch.object(sys, 'argv', [str(runner), str(request)]), \
                patch.object(subprocess, 'Popen', return_value=process), \
                patch.object(process, 'wait', return_value=0) as waited, \
                patch.object(os, 'link', side_effect=OSError('ENOSPC publishing child report')), \
                self.assertRaises(SystemExit):
            exec(compile(host_launch.GUI_RUNNER, str(runner), 'exec'), {})
        waited.assert_called_once_with()
        self.assertFalse(report.exists())
        log = Path(json.loads(request.read_text())['log'])
        self.assertIn('keeping its supervisor alive', log.read_text())


class DiagnosticCommandTests(unittest.TestCase):
    def test_normal_and_opt_in_diagnostic_commands_use_same_detached_launcher(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'images').mkdir()
            (root / 'images/userdata.img').write_bytes(b'template')
            avd = root / 'avd/Own_Device.avd'
            avd.mkdir(parents=True)
            (avd / 'config.ini').write_text('hw.ramSize=6144\nhw.cpu.ncore=4\n')
            config = {'sdk': str(root / 'sdk'), 'name': 'Own_Device', 'port': 5586}
            for diagnostic in (False, True):
                with self.subTest(diagnostic=diagnostic), \
                        patch.object(launch, 'ROOT', root), \
                        patch.object(launch, 'host_check'), patch.object(launch, 'runtime', return_value=config), \
                        patch.object(launch, 'port_free'), patch.object(launch, 'configure'), \
                        patch.object(launch, 'fetch_ksu'), patch.object(launch, 'prepare_userdata'), \
                        patch.object(launch, 'initialize') as initialize, \
                        patch('host_color.environment', return_value={'HYPEROS_AVD_SRGB': '1'}), \
                        patch('host_launch.start', return_value=host_launch.LaunchResult(8123, 'owned/service')) as start, \
                        patch.object(sys, 'argv', ['launch.py'] + (['--diagnostic'] if diagnostic else [])):
                    launch.main()
                arguments = start.call_args.args
                command = arguments[2]
                self.assertEqual('-show-kernel' in command, diagnostic)
                self.assertEqual('-verbose' in command, diagnostic)
                self.assertEqual(command.count('-avd'), 1)
                self.assertEqual(command[command.index('-memory') + 1], '6144')
                self.assertEqual(arguments[3], {'HYPEROS_AVD_SRGB': '1'})
                initialize.assert_called_once_with(config, bypass_oobe=False, rotate_window=True)

    def test_multi_display_discovery_uses_owned_gui_launch_without_guest_profile_gates(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'images').mkdir()
            (root / 'images/userdata.img').write_bytes(b'template')
            avd = root / 'avd/Renamed_Device.avd'
            avd.mkdir(parents=True)
            (avd / 'config.ini').write_text('hw.ramSize=6144\nhw.cpu.ncore=4\n')
            (root / 'local').mkdir()
            config = {'sdk': str(root / 'sdk'), 'name': 'Renamed_Device', 'port': 5586}
            verified = ['-append-userspace-opt', 'verified-rear-panel']
            for metadata, flags, rear_options, color, multi_display, trackpad in (
                    (None, [], [], True, True, True),
                    ({'source': 'custom'}, [], [], True, True, True),
                    ({'source': 'google-apis'}, ['--no-host-color-fix'], [], False, True, True),
                    ({'source': 'custom'}, ['--no-host-trackpad'], [], True, True, False),
                    ({'source': 'official-hongkong-ota'}, [], verified, True, True, True),
                    ({'source': 'official-hongkong-ota'}, ['--headless'], verified, False, False, False)):
                manifest = root / 'local/build.json'
                if metadata is None:
                    manifest.unlink(missing_ok=True)
                else:
                    manifest.write_text(json.dumps(metadata))
                with self.subTest(metadata=metadata, flags=flags), \
                        patch.object(launch, 'ROOT', root), \
                        patch.object(launch, 'host_check'), patch.object(launch, 'runtime', return_value=config), \
                        patch.object(launch, 'port_free'), patch.object(launch, 'configure'), \
                        patch.object(launch, 'fetch_ksu'), patch.object(launch, 'prepare_userdata'), \
                        patch.object(launch, 'initialize'), \
                        patch('kernelsu_release.available', return_value=True), \
                        patch('host_adb.adapter', return_value=root / 'owned-adb'), \
                        patch('rear_display_config.runtime_options', return_value=rear_options) as rear, \
                        patch('host_color.environment', return_value={}) as environment, \
                        patch('host_launch.start', return_value=host_launch.LaunchResult(8123, 'owned/service')) as start, \
                        patch.object(sys, 'argv', ['launch.py', *flags]):
                    launch.main()
                if metadata is None:
                    rear.assert_not_called()
                else:
                    rear.assert_called_once_with(metadata)
                environment.assert_called_once_with(root, config['name'], enabled=color,
                                                    multi_display=multi_display,
                                                    trackpad=trackpad,
                                                    emulator=(root / 'sdk/emulator/qemu/darwin-aarch64/qemu-system-aarch64').resolve())
                self.assertEqual('-no-window' in start.call_args.args[2], '--headless' in flags)


class OwnedUserLaunchDirectoryTests(unittest.TestCase):
    def test_private_job_state_uses_account_home_instead_of_external_workspace_or_caller_home(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            account = type('Account', (), {'pw_dir': str(home)})()
            with patch.object(host_launch.pwd, 'getpwuid', return_value=account), \
                    patch.dict(os.environ, {'HOME': '/Volumes/External/foreign-home'}):
                directory = host_launch.job_directory()
            self.assertEqual(directory, home / 'Library/Application Support/HyperOS-AVD/launchd')
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            self.assertEqual(directory.parent.stat().st_mode & 0o777, 0o700)
            self.assertFalse((home / 'Library/LaunchAgents').exists())

    def test_unowned_or_aliased_user_job_directory_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            support = home / 'Library/Application Support'
            support.mkdir(parents=True)
            foreign = home / 'foreign'
            foreign.mkdir()
            (support / 'HyperOS-AVD').symlink_to(foreign)
            account = type('Account', (), {'pw_dir': str(home)})()
            with patch.object(host_launch.pwd, 'getpwuid', return_value=account), \
                    self.assertRaisesRegex(RuntimeError, 'aliased'):
                host_launch.job_directory()
            self.assertEqual(list(foreign.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
