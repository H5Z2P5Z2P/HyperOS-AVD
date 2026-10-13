"""Exercise the internal SDK ADB no-op without an Android device or SDK mutation."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'scripts'))
import host_adb


class HostAdbTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.sdk = self.root / "SDK 'with space'"
        self.original = self.sdk / 'platform-tools/adb'
        self.original.parent.mkdir(parents=True)
        self.calls = self.root / 'calls.jsonl'
        self.serial = 'emulator-5588'
        self.state = self.root / 'private/launchd'
        self.state.mkdir(parents=True, mode=0o700)
        self.original.write_text('#!' + str(Path(sys.executable).resolve()) + '\n'
            'import json, os, pathlib, sys\n'
            'with pathlib.Path(' + repr(str(self.calls)) + ').open("a") as log:\n'
            ' log.write(json.dumps(sys.argv[1:]) + "\\n")\n'
            'if len(sys.argv) == 8 and sys.argv[5] == "get":\n'
            ' print(os.environ.get("FAKE_ADB_SETTING", "2147483647"))\n'
            ' raise SystemExit(int(os.environ.get("FAKE_QUERY_EXIT", "0")))\n'
            'print("original output")\n'
            'print("original error", file=sys.stderr)\n'
            'raise SystemExit(int(os.environ.get("FAKE_FORWARD_EXIT", "0")))\n')
        self.original.chmod(0o755)
        self.addCleanup(patch.stopall)
        patch.object(host_adb, 'job_directory', return_value=self.state).start()
        # This suite also runs on CI hosts without macOS. The native exclusive
        # rename itself has a separate host-gated racing-destination test.
        patch.object(host_adb, '_publish_directory', side_effect=lambda source, destination:
                     os.rename(source, destination)).start()

    def executable(self):
        return host_adb.adapter(self.sdk, self.serial)

    def command(self, serial=None, value='2147483647'):
        return ['-s', serial or self.serial, 'shell', 'settings', 'put', 'system', 'screen_off_timeout', value]

    def run_adapter(self, arguments, **environment):
        return subprocess.run([str(self.executable()), *arguments],
                              env=dict(os.environ, **environment), capture_output=True,
                              text=True, timeout=10)

    def requests(self):
        return [json.loads(line) for line in self.calls.read_text().splitlines()] if self.calls.exists() else []

    def test_exact_same_setting_is_a_real_idempotent_no_op_without_put_or_extra_grants(self):
        result = self.run_adapter(self.command(), FAKE_FORWARD_EXIT='23')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, '')
        self.assertEqual(self.requests(), [['-s', self.serial, 'shell', 'settings', 'get',
                                            'system', 'screen_off_timeout']])

    def test_different_value_and_failed_query_transparently_forward_all_output_and_error(self):
        for options in ({'FAKE_ADB_SETTING': '60000'}, {'FAKE_QUERY_EXIT': '4'}):
            with self.subTest(options=options):
                self.calls.unlink(missing_ok=True)
                result = self.run_adapter(self.command(), FAKE_FORWARD_EXIT='23', **options)
                self.assertEqual(result.returncode, 23)
                self.assertEqual(result.stdout, 'original output\n')
                self.assertEqual(result.stderr, 'original error\n')
                self.assertEqual(self.requests()[-1], self.command())
                self.assertEqual(len(self.requests()), 2)

    def test_other_device_global_options_combined_shell_and_dynamic_values_are_exact_passthrough(self):
        variants = [self.command(serial='emulator-5590'), ['version'],
                    ['-P', '5039', *self.command()], ['-e', *self.command()[2:]],
                    ['-s', self.serial, 'shell', 'settings put system screen_off_timeout 2147483647'],
                    self.command(value='2147483647; echo private'), self.command(value='$VALUE'),
                    self.command(value='01'), self.command() + ['extra'],
                    ['-s', self.serial, 'shell', 'settings', 'put', 'secure', 'sleep_timeout', '-1']]
        for arguments in variants:
            with self.subTest(arguments=arguments):
                self.calls.unlink(missing_ok=True)
                result = self.run_adapter(arguments, FAKE_FORWARD_EXIT='17')
                self.assertEqual(result.returncode, 17)
                self.assertEqual(self.requests(), [arguments])
                self.assertEqual(result.stdout, 'original output\n')
                self.assertEqual(result.stderr, 'original error\n')

    def test_wrapper_quoting_and_cache_reuse_preserve_sdk_and_do_not_persist_secrets(self):
        original = self.original.read_bytes(), self.original.stat().st_ino
        with patch.dict(os.environ, {'OPENAI_API_KEY': 'private-token', 'GITHUB_TOKEN': 'private-key'}):
            executable = self.executable()
            entries = {path: (path.read_bytes(), path.stat().st_ino) for path in executable.parent.iterdir()}
            self.assertEqual(self.executable(), executable)
        self.assertEqual(original, (self.original.read_bytes(), self.original.stat().st_ino))
        self.assertEqual(entries, {path: (path.read_bytes(), path.stat().st_ino) for path in entries})
        for path, (data, _) in entries.items():
            self.assertNotIn(b'private-token', data)
            self.assertNotIn(b'private-key', data)
            self.assertEqual(path.stat().st_mode & 0o777, 0o700 if path.name == 'adb' else 0o600)
        self.assertEqual(executable.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.run_adapter(['version']).returncode, 0)

    def test_valid_sdk_path_with_recipe_like_text_is_not_interpolated_again(self):
        changed = self.root / "__DIGEST__ __SERIAL__ __MAX_ADB__ SDK '{literal}'"
        self.sdk.rename(changed)
        self.sdk = changed
        self.original = changed / 'platform-tools/adb'
        result = self.run_adapter(['version'])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.requests(), [['version']])

    def test_modified_extra_or_aliased_cache_resources_are_preserved(self):
        executable = self.executable()
        runner = executable.parent / 'runner.py'
        original = runner.read_bytes()
        runner.write_bytes(b'custom code')
        with self.assertRaisesRegex(RuntimeError, 'Modified SDK ADB'):
            self.executable()
        self.assertEqual(runner.read_bytes(), b'custom code')
        runner.write_bytes(original)
        extra = executable.parent / 'extra'
        extra.write_text('user content')
        with self.assertRaisesRegex(RuntimeError, 'Unknown SDK ADB'):
            self.executable()
        self.assertEqual(extra.read_text(), 'user content')
        extra.unlink()
        target = self.root / 'foreign-runner'
        runner.rename(target)
        runner.symlink_to(target)
        with self.assertRaisesRegex(RuntimeError, 'aliased'):
            self.executable()
        self.assertEqual(target.read_bytes(), original)

    def test_runtime_sdk_change_is_diagnosed_and_a_new_preparation_does_not_rewrite_old_cache(self):
        executable = self.executable()
        old = executable.read_bytes(), (executable.parent / 'receipt.json').read_bytes()
        self.original.write_text(self.original.read_text() + '# official SDK update\n')
        result = subprocess.run([str(executable), 'version'], capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('original SDK ADB changed', result.stderr)
        self.assertEqual(self.requests(), [])
        updated = self.executable()
        self.assertNotEqual(updated, executable)
        self.assertEqual(old, (executable.read_bytes(), (executable.parent / 'receipt.json').read_bytes()))

    def test_recursive_sdk_adapter_and_invalid_or_writable_source_are_refused(self):
        for serial in ('-e', 'emulator-1; unsafe', 'device other'):
            with self.subTest(serial=serial), self.assertRaisesRegex(RuntimeError, 'identity'):
                host_adb.adapter(self.sdk, serial)
        executable = self.executable()
        self.original.unlink()
        self.original.symlink_to(executable)
        with self.assertRaisesRegex(RuntimeError, 'recursive'):
            self.executable()
        self.original.unlink()
        self.original.write_text('writable SDK input')
        self.original.chmod(0o777)
        with self.assertRaisesRegex(RuntimeError, 'unsafe'):
            self.executable()

    def test_failed_private_publication_leaves_no_partial_adapter_and_next_try_recovers(self):
        real = host_adb.write_private
        def fail(path, content):
            if path.name == 'receipt.json':
                raise OSError('ENOSPC')
            return real(path, content)
        with patch.object(host_adb, 'write_private', side_effect=fail), self.assertRaisesRegex(OSError, 'ENOSPC'):
            self.executable()
        self.assertEqual(list((self.state.parent / 'host-adb').iterdir()), [])
        self.assertTrue(self.executable().is_file())

    def test_query_timeout_still_executes_original_command(self):
        executable = self.executable()
        source = (executable.parent / 'runner.py').read_text()
        with patch.object(sys, 'argv', [str(executable), *self.command()]), \
                patch.object(subprocess, 'run', side_effect=subprocess.TimeoutExpired(['adb'], 5)), \
                patch.object(os, 'execv') as forwarded:
            exec(compile(source, str(executable), 'exec'), {})
        forwarded.assert_called_once_with(str(self.original), [str(self.original), *self.command()])


@unittest.skipUnless(sys.platform == 'darwin', 'Native exclusive rename is a macOS API.')
class NativePublicationTests(unittest.TestCase):
    def test_exclusive_directory_publication_preserves_even_an_empty_racing_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            staged, destination = root / 'staged', root / 'destination'
            staged.mkdir(); destination.mkdir()
            with self.assertRaises(FileExistsError):
                host_adb._publish_directory(staged, destination)
            self.assertTrue(staged.is_dir())
            self.assertEqual(list(destination.iterdir()), [])
            destination.rmdir()
            host_adb._publish_directory(staged, destination)
            self.assertFalse(staged.exists())
            self.assertTrue(destination.is_dir())


if __name__ == '__main__':
    unittest.main()
