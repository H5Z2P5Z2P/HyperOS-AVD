"""Exercise generated first-boot authorization and capability effects offline."""
from contextlib import ExitStack
import hashlib
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
import image_kernel_services as helper
import patch_boot_services as services
import package_release as release
import prepare_release_image as prepare


def digest(data):
    return hashlib.sha256(data).hexdigest()


class ImageKernelServicesTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.temporary = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.root = Path(self.temporary)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.events = self.root / 'events'
        self.payloads = {path: ('audited fixture ' + name).encode()
                         for name, (path, _, _) in services.TARGETS.items()}
        self.probe = b'''#!/bin/sh
printf 'probe:%s\n' "$1" >> "$EVENTS"
if [ "$1" = gnss-extension ]; then exit "$GNSS_RESULT"; fi
exit "$MILLET_RESULT"
'''
        self.payloads[helper.PROBE_PATH] = self.probe
        after = {name: digest(self.payloads[path]) for name, (path, _, _) in services.TARGETS.items()}
        modern = b'audited modern GNSS fixture'
        self.modern = modern
        modern_before = next(reversed(services.SERVICE_RECIPES))
        variants = {services.TARGETS['services'][1]: after['services'], modern_before: digest(modern)}
        self.stack.enter_context(patch.object(services, 'AFTER', after))
        self.stack.enter_context(patch.object(services, 'SERVICE_RECIPES', variants))
        self.stack.enter_context(patch.object(services, 'PROBE_SHA256', digest(self.probe)))
        self.write_bin('id', '#!/bin/sh\nprintf "%s\\n" "$USER_ID"\n')
        self.write_bin('uname', '#!/bin/sh\nprintf "%s\\n" "$KERNEL_ABI"\n')
        self.write_bin('getprop', '''#!/bin/sh
case "$1" in
    ro.boot.hardware) printf '%s\n' "$HARDWARE" ;;
    ro.product.cpu.abi) printf '%s\n' "$ANDROID_ABI" ;;
    ro.millet.netlink) printf '30\n' ;;
    *) printf 'deliberately-unrelated\n' ;;
esac
''')
        self.write_bin('setprop', '#!/bin/sh\nprintf "property:%s:%s\\n" "$1" "$2" >> "$EVENTS"\n')
        self.write_bin('sha256sum', '#!' + sys.executable + '\nimport hashlib, pathlib, sys\n'
                       'print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest(), sys.argv[1])\n')
        self.environment = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                                EVENTS=str(self.events), USER_ID='0', HARDWARE='ranchu',
                                ANDROID_ABI='arm64-v8a', KERNEL_ABI='aarch64',
                                MILLET_RESULT='2', GNSS_RESULT='2')

    def write_bin(self, name, content):
        path = self.bin / name
        path.write_text(content)
        path.chmod(0o755)

    def run_helper(self, *, modern=False, mutate=None, environment=None):
        for path, content in self.payloads.items():
            file = self.root / path.lstrip('/')
            file.parent.mkdir(parents=True, exist_ok=True)
            file.unlink(missing_ok=True)
            file.write_bytes(self.modern if modern and path == services.TARGETS['services'][0] else content)
            file.chmod(0o755 if path == helper.PROBE_PATH else 0o644)
        if mutate is not None:
            mutate(self.root)
        script = helper.image_script()
        for path in sorted(self.payloads, key=len, reverse=True):
            script = script.replace(path.encode(), str(self.root / path.lstrip('/')).encode())
        path = self.root / 'helper.sh'
        path.write_bytes(script)
        result = subprocess.run(['sh', str(path)], env={**self.environment, **(environment or {})},
                                text=True, capture_output=True)
        events = self.events.read_text().splitlines() if self.events.exists() else []
        return result, events

    def test_full_old_and_modern_recipes_work_without_ksu_or_version_identity(self):
        for modern in (False, True):
            with self.subTest(modern=modern):
                self.events.unlink(missing_ok=True)
                result, events = self.run_helper(modern=modern)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('verified recipe', result.stderr)
                self.assertEqual(events, ['probe:30', 'property:sys.hyperos_avd.millet_supported:0',
                                         'property:ctl.stop:millet_monitor', 'probe:gnss-extension',
                                         'property:ctl.stop:loc_sys_service'])
        script = helper.image_script().decode()
        for value in ('/data/adb', 'OS4.0.', 'ro.product.device', 'ro.mi.os.version', 'HyperOS_4_'):
            self.assertNotIn(value, script)

    def test_supported_capabilities_keep_hardware_daemons(self):
        result, events = self.run_helper(environment={'MILLET_RESULT': '0', 'GNSS_RESULT': '0'})
        self.assertEqual(result.returncode, 0)
        self.assertEqual(events, ['probe:30', 'property:sys.hyperos_avd.millet_supported:1',
                                 'probe:gnss-extension'])

    def test_failed_probe_reports_failure_without_treating_unknown_as_unsupported(self):
        result, events = self.run_helper(environment={'MILLET_RESULT': '1'})
        self.assertEqual(result.returncode, 1)
        self.assertIn('failed (millet-probe)', result.stderr)
        self.assertEqual(events, ['probe:30'])

    def test_foreign_hardware_or_abi_cannot_probe_or_change_properties(self):
        for environment in ({'USER_ID': '1000'}, {'HARDWARE': 'qcom'},
                            {'ANDROID_ABI': 'x86_64'}, {'KERNEL_ABI': 'x86_64'}):
            with self.subTest(environment=environment):
                result, events = self.run_helper(environment=environment)
                self.assertEqual(result.returncode, 0)
                self.assertIn('skip (', result.stderr)
                self.assertFalse(events)

    def test_unknown_missing_mixed_and_aliased_recipes_skip_before_effects(self):
        target = services.TARGETS['qualcomm'][0]
        def changed(root):
            (root / target.lstrip('/')).write_bytes(b'foreign service')
        def missing(root):
            (root / target.lstrip('/')).unlink()
        def alias(root):
            path = root / target.lstrip('/')
            saved = path.with_suffix('.known')
            path.rename(saved)
            path.symlink_to(saved)
        def altered_probe(root):
            (root / helper.PROBE_PATH.lstrip('/')).write_bytes(b'#!/bin/sh\nexit 2\n')
        for mutate in (changed, missing, alias, altered_probe):
            with self.subTest(mutate=mutate.__name__):
                result, events = self.run_helper(mutate=mutate)
                self.assertEqual(result.returncode, 0)
                self.assertIn('skip (', result.stderr)
                self.assertFalse(events)

    def test_known_individual_pins_cannot_authorize_a_mixed_recipe(self):
        frozen, modern = services.image_receipts()
        modern = json.loads(json.dumps(modern))
        modern['targets']['qualcomm']['after'] = digest(b'audited second Qualcomm fixture')
        with patch.object(services, 'image_receipts', return_value=(frozen, modern)):
            result, events = self.run_helper(modern=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn('unknown-mixed-or-incomplete-image-recipe', result.stderr)
        self.assertFalse(events)

    def test_generator_rejects_duplicate_incomplete_and_noncanonical_receipts(self):
        receipt = services.image_receipt()
        with patch.object(services, 'image_receipts', return_value=(receipt, receipt)):
            with self.assertRaisesRegex(RuntimeError, 'Duplicate'):
                helper.image_script()
        bad = json.loads(json.dumps(receipt))
        del bad['targets']['qualcomm']
        with patch.object(services, 'image_receipts', return_value=(bad,)):
            with self.assertRaisesRegex(RuntimeError, 'Incomplete image kernel-service recipe'):
                helper.image_script()

    def test_published_phone_helpers_stay_accepted_only_for_their_frozen_source(self):
        from apply_boot_service_fix import KERNEL_SCRIPT_SHA256, KERNEL_SCRIPT_HASHES
        from phone_profile import profile
        old = profile('4.0.18.0.XFRCNXM')
        build = {'hyperos': old['hyperos'], 'archive_sha256': old['archive_sha256'],
                 'boot_service_fix': services.image_receipt()}
        self.assertTrue(set(KERNEL_SCRIPT_HASHES) <= set(helper.accepted_hashes(build)))
        self.assertIn(KERNEL_SCRIPT_SHA256, helper.accepted_hashes({**build, 'boot_policy': {}}))
        modern = profile('4.0.24.0.XFRCNXM')
        new = {**build, 'hyperos': modern['hyperos'], 'archive_sha256': modern['archive_sha256']}
        self.assertEqual(helper.accepted_hashes(new), (helper.image_script_sha256(),))
        for marker in services.image_receipts()[1:]:
            self.assertEqual(helper.accepted_hashes({**build, 'boot_service_fix': marker}),
                             (helper.image_script_sha256(),))

    def test_current_image_producer_uses_the_same_exact_generated_helper(self):
        originals = {name: ('original ' + name).encode() for name in services.TARGETS}
        selected = {name: {'before': services.TARGETS[name][1]} for name in originals}
        probe = self.root / 'probe'
        probe.write_bytes(self.probe)
        def patched(name, source, destination):
            destination.write_bytes(self.payloads[services.TARGETS[name][0]])
            return destination
        original_select = services.select_recipe
        with patch.object(services, 'select_recipe', side_effect=lambda name, data:
                          selected[name] if isinstance(data, bytes) else original_select(name, data)), \
                patch.object(services, 'patch', side_effect=patched), \
                patch.object(services, 'kernel_probe', return_value=probe):
            edits, _ = services.image_replacements(originals, self.root / 'work')
        self.assertEqual(edits[helper.PATH.lstrip('/')],
                         (helper.image_script(), 0o755, 'u:object_r:system_file:s0'))

    def test_release_checks_current_helper_instead_of_version_gated_old_script(self):
        from apply_boot_service_fix import PERF_SCRIPT
        from phone_profile import profile
        selected = profile('4.0.24.0.XFRCNXM')
        build = {'hyperos': selected['hyperos'], 'archive_sha256': selected['archive_sha256'],
                 'boot_service_fix': services.image_receipt()}
        files = {**self.payloads, helper.PATH: helper.image_script(),
                 '/system_ext/etc/init/init.hyperos_avd.rc': services.BOOT_INIT,
                 '/system_ext/etc/selinux/system_ext_sepolicy.cil': services.BOOT_SEPOLICY}
        self.assertEqual(release.verify_boot_services(build, files.__getitem__), 7)
        files[helper.PATH] = PERF_SCRIPT.read_bytes()
        with self.assertRaisesRegex(RuntimeError, 'checksum mismatch: ' + helper.PATH):
            release.verify_boot_services(build, files.__getitem__)

    def test_preparer_refreshes_frozen_or_current_helper_and_rejects_unknown(self):
        import os4_boot_policy as policy
        from apply_boot_service_fix import PERF_SCRIPT
        init = services.BOOT_INIT
        graph = {policy.INIT_PATH: init}
        files = {'/' + policy.INIT_PATH: init, '/' + policy.POLICY_PATH: b'enforcing fixture'}
        for previous in (PERF_SCRIPT.read_bytes(), helper.image_script(), b'unknown helper'):
            with self.subTest(previous=digest(previous)):
                edits = {helper.PATH.lstrip('/'): (previous, 0o755, 'u:object_r:system_file:s0')}
                with patch.object(policy, 'init_files', return_value=graph), \
                        patch.object(policy, 'image_replacements', return_value=({}, {'fixture': True})), \
                        patch.object(prepare, 'erofs', side_effect=lambda raw, path: files[path]):
                    if previous == b'unknown helper':
                        with self.assertRaisesRegex(RuntimeError, 'Unknown existing image kernel helper'):
                            prepare.shared_boot_edits(self.root / 'system.img', self.root / 'vendor.img', edits,
                                                      self.root / 'prepared')
                    else:
                        prepare.shared_boot_edits(self.root / 'system.img', self.root / 'vendor.img', edits,
                                                  self.root / 'prepared')
                        self.assertEqual(edits[helper.PATH.lstrip('/')][0], helper.image_script())


if __name__ == '__main__':
    unittest.main()
