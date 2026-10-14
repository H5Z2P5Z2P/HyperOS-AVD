"""Verify the narrow OEM TCM opt-out without changing any real property."""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'scripts'))
import tcm_capability as producer
import package_native_module
import test_native_module_runtime as fixture


class TcmCapabilityAssetsTests(unittest.TestCase):
    def test_offline_recipe_is_exact_and_packaged_with_feature(self):
        files = producer.files()
        self.assertEqual(set(files), {'tcm-capability.tsv'})
        self.assertEqual(files['tcm-capability.tsv'].decode().splitlines(), [
            'schema|1', *('file|' + path + '|' + checksum for path, checksum in producer.PINS),
            'property|' + producer.PROPERTY + '|1', 'policy|unset-current-boot-only'])
        packaged = package_native_module.module_files()
        self.assertEqual(packaged['tcm-capability.tsv'], files['tcm-capability.tsv'])
        self.assertEqual(packaged['tcm-capability.sh'], (REPO / 'modules/native-compat/tcm-capability.sh').read_bytes())
        self.assertIn(b'network-tcm\n', packaged['features.tsv'])
        self.assertIn('network-tcm', json.loads(packaged['manifest.json'])['features'])

    def test_hook_is_early_only_and_never_persists_or_restarts(self):
        source = (REPO / 'modules/native-compat/platform.sh').read_text()
        early = source.split('core_early() {', 1)[1].split('\n}', 1)[0]
        late = source.split('core_late() {', 1)[1].split('\n}', 1)[0]
        self.assertIn('core_network_tcm', early)
        self.assertNotIn('core_network_tcm', late)
        script = (REPO / 'modules/native-compat/tcm-capability.sh').read_text()
        self.assertIn('"$CORE_RESETPROP" -n persist.vendor.dpm.tcm 1', script)
        self.assertNotIn('setprop ', script)
        self.assertNotIn('--persistent', script)
        self.assertNotIn('ctl.', script)


class TcmCapabilityShellTests(unittest.TestCase):
    profile = fixture.NativeModuleRuntimeTests.profile
    file_metadata = fixture.NativeModuleRuntimeTests.file_metadata

    def setUp(self):
        fixture.NativeModuleRuntimeTests.setUp(self)
        self.state = self.root / 'persistent'
        self.state.mkdir()
        self.pinned = {}
        body = producer.files()['tcm-capability.tsv'].decode()
        for path, checksum in producer.PINS:
            target = self.root.resolve() / path.lstrip('/')
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(('Audited TCM content fixture: ' + path).encode())
            self.pinned[path] = target
            body = body.replace(path, str(target)).replace(checksum, hashlib.sha256(target.read_bytes()).hexdigest())
        self.client = self.pinned[producer.CLIENT_PATH]
        (self.module / 'tcm-capability.tsv').write_text(body)
        script = (self.module / 'tcm-capability.sh').read_text()
        script = re.sub(r'/(system_ext|system|vendor)(?=/)',
                        lambda match: str(self.root.resolve() / match[1]), script)
        (self.module / 'tcm-capability.sh').write_text(script)
        self.props = self.root / 'properties.json'
        self.base = {'ro.boot.hardware': 'ranchu', 'ro.mi.os.version.incremental': 'OS4.99.TEST',
                     'sys.boot_completed': '0', 'ro.kernel.qemu': '1', 'ro.boot.qemu': '1'}
        self.props.write_text(json.dumps(self.base))
        self.trace = self.root / 'effects'
        (self.bin / 'getprop').write_text('#!' + sys.executable + '\n' + '''import json,os,sys
state=json.load(open(os.environ['TCM_TEST_PROPERTIES']))
if len(sys.argv)==1:
    for key,value in sorted(state.items()): print('['+key+']: ['+value+']')
else: print(state.get(sys.argv[1],''))
''')
        resetprop = self.bin / 'resetprop'
        resetprop.write_text('#!' + sys.executable + '\n' + '''import json,os,sys
args=sys.argv[1:]
with open(os.environ['TCM_TEST_TRACE'],'a') as output: output.write(' '.join(args)+'\\n')
if args != ['-n','persist.vendor.dpm.tcm','1']: sys.exit(1)
path=os.environ['TCM_TEST_PROPERTIES']
state=json.load(open(path));state[args[1]]=args[2]
with open(path,'w') as output: json.dump(state,output)
''')
        resetprop.chmod(0o755)
        self.environment.update(HYPEROS_CORE_STATE=str(self.state), HYPEROS_CORE_PENDING=str(self.root / 'pending'),
            HYPEROS_CORE_RESETPROP=str(resetprop), HYPEROS_NATIVE_TEST_OWNER='0:0',
            TCM_TEST_PROPERTIES=str(self.props), TCM_TEST_TRACE=str(self.trace), TCM_TEST_VENDOR='1')
        fixture.NativeModuleRuntimeTests.checksums(self)

    def run_tcm(self, overrides='', body='core_network_tcm', interpreter='/bin/sh'):
        source = ("MODDIR=" + shlex.quote(str(self.module)) + '\n. "$MODDIR/runtime.sh"\n'
                  '. "$MODDIR/platform.sh"\n'
                  'native_privacy_eligible() { [ "$TCM_TEST_VENDOR" = 1 ]; }\n'
                  'native_assets() { (cd "$MODDIR" && "$BB" sha256sum -c SHA256SUMS >/dev/null); }\n'
                  'native_ns() { shift; "$@"; }\n' + overrides + '\n' + body)
        if interpreter == '/bin/ksh':
            source = 'alias local=typeset\n' + source
        result = subprocess.run([interpreter, '-c', source], env=self.environment,
                                text=True, capture_output=True)
        effects = self.trace.read_text() if self.trace.exists() else ''
        return result, effects

    def status(self):
        path = self.module / 'state/status.tsv'
        return path.read_text() if path.exists() else ''

    def set_properties(self, **updates):
        self.props.write_text(json.dumps(dict(self.base, **updates)))

    def test_verified_unset_boot_property_uses_only_the_oem_nonpersistent_switch(self):
        result, effects = self.run_tcm()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(effects, '-n persist.vendor.dpm.tcm 1\n')
        self.assertIn('ready|verified-oem-runtime-opt-out', self.status())

    def test_all_existing_values_including_empty_are_preserved(self):
        for value in ('', '0', '1', '2', 'custom'):
            with self.subTest(value=value):
                self.set_properties(**{producer.PROPERTY: value})
                result, effects = self.run_tcm()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(effects, '')
                self.assertEqual(json.loads(self.props.read_text())[producer.PROPERTY], value)
                self.assertIn('property-present-or-inventory-unavailable', self.status())

    def test_reconcile_after_boot_or_zygote_start_never_changes_properties(self):
        self.set_properties(sys_boot_completed='0')
        state = dict(self.base); state['sys.boot_completed'] = '1'; self.props.write_text(json.dumps(state))
        self.assertEqual(self.run_tcm()[1], '')
        self.props.write_text(json.dumps(self.base))
        self.assertEqual(self.run_tcm('pidof() { echo 88; }')[1], '')

    def test_nonranchu_or_unverified_complete_inventory_has_no_effect(self):
        self.environment['TCM_TEST_VENDOR'] = '0'
        self.assertEqual(self.run_tcm()[1], '')
        self.assertIn('unaudited-ranchu-vendor', self.status())
        self.environment['TCM_TEST_VENDOR'] = '1'
        state = dict(self.base); state['ro.boot.hardware'] = 'physical'; self.props.write_text(json.dumps(state))
        self.assertEqual(self.run_tcm()[1], '')

    def test_feature_disable_module_disable_remove_and_pending_are_preserved(self):
        for flag in ('features.disabled', 'disable', 'remove'):
            with self.subTest(flag=flag):
                path = self.module / flag
                path.write_text('network-tcm\n' if flag == 'features.disabled' else '')
                self.assertEqual(self.run_tcm()[1], '')
                path.unlink()
        (self.root / 'pending').mkdir()
        self.assertEqual(self.run_tcm()[1], '')

    def test_absent_unknown_aliased_or_nonroot_client_is_retained(self):
        original = self.client.read_bytes()
        self.client.write_bytes(b'Customized client')
        self.assertEqual(self.run_tcm()[1], '')
        self.assertIn('unsupported-tcm-content', self.status())
        self.client.unlink()
        self.assertEqual(self.run_tcm()[1], '')
        donor = self.client.with_name('donor.jar'); donor.write_bytes(original)
        self.client.symlink_to(donor)
        self.assertEqual(self.run_tcm()[1], '')
        self.client.unlink(); self.client.write_bytes(original)
        self.file_metadata(self.client, owner='1000:1000')
        self.assertEqual(self.run_tcm()[1], '')

    def test_each_server_and_policy_file_is_required_exactly(self):
        for original, path in self.pinned.items():
            with self.subTest(path=original):
                body = path.read_bytes()
                path.write_bytes(body + b'custom')
                self.assertEqual(self.run_tcm()[1], '')
                path.write_bytes(body)

    def test_extra_tampered_or_arbitrary_property_recipe_never_writes(self):
        recipe = self.module / 'tcm-capability.tsv'
        original = recipe.read_text()
        for changed in (original + 'extra|data\n', original.replace('|1\npolicy|', '|2\npolicy|'),
                        original.replace(producer.PROPERTY, 'persist.unsafe.property')):
            with self.subTest(changed=changed):
                recipe.write_text(changed)
                fixture.NativeModuleRuntimeTests.checksums(self)
                self.assertEqual(self.run_tcm()[1], '')
        recipe.write_text(original + 'unverified')
        self.assertEqual(self.run_tcm()[1], '')

    def test_property_inventory_failure_is_not_absence(self):
        result, effects = self.run_tcm('getprop() { return 1; }')
        self.assertEqual(effects, '')

    def test_empty_or_incomplete_successful_inventory_is_not_absence(self):
        for output in ('', '[ro.boot.hardware]: [ranchu]'):
            with self.subTest(output=output):
                command = 'getprop() { if [ "$#" = 0 ]; then printf "%s\\n" ' + shlex.quote(output) + '; else command getprop "$@"; fi; }'
                self.assertEqual(self.run_tcm(command)[1], '')

    def test_property_choice_during_revalidation_is_preserved(self):
        overrides = '''checks=0
core_tcm_file_matches() {
    checks=$((checks + 1))
    if [ "$checks" = 2 ]; then
        printf '%s' '{"persist.vendor.dpm.tcm":"2"}' > "$TCM_TEST_PROPERTIES"
    fi
    return 0
}'''
        self.assertEqual(self.run_tcm(overrides)[1], '')
        self.assertEqual(json.loads(self.props.read_text())[producer.PROPERTY], '2')

    @unittest.skipUnless(Path('/bin/ksh').is_file(), 'Korn shell is unavailable')
    def test_korn_shell_reads_same_audited_recipe(self):
        result, _ = self.run_tcm(body='core_tcm_recipe', interpreter='/bin/ksh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip().splitlines(), [str(path) + '|' + hashlib.sha256(path.read_bytes()).hexdigest()
            for path in self.pinned.values()])
