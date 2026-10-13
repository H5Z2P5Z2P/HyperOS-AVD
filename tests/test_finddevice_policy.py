"""Exercise package-state ownership and restoration without an Android guest."""
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

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'scripts'))
import finddevice_policy as policy


class FindDevicePolicyTests(unittest.TestCase):
    feature = 'finddevice'
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve(); self.bin = self.root / 'bin'; self.bin.mkdir()
        self.adb = self.root / 'data/adb'; self.module = self.adb / 'modules/hyperos_avd_native_compat'
        self.module.mkdir(parents=True)
        (self.module / 'module.prop').write_text('id=hyperos_avd_native_compat\nauthor=HyperOS-AVD\nversionCode=11\n')
        (self.module / 'features.disabled').write_text('')
        self.apk = self.root / 'data/app/audited/base.apk'; self.apk.parent.mkdir(parents=True); self.apk.write_bytes(b'signed apk')
        self.userdata = self.root / 'userdata'; self.userdata.write_bytes(b'accounts are preserved')
        self.meta = self.root / 'metadata.json'; self.trace = self.root / 'commands'; self.trace.write_text('')
        self.package = policy.PROFILES[self.feature]['package']
        self.update(uid=6110, enabled=0, certificate='01020304', apk=str(self.apk), system=True, hardware='ranchu', package=self.package, hidden=False, installed=True, suspended=False)
        bb = self.adb / 'ksu/bin/busybox'; bb.parent.mkdir(parents=True)
        bb.write_text('#!' + sys.executable + '\n' + r'''
import fcntl,hashlib,os,pathlib,subprocess,sys
command,args=sys.argv[1],sys.argv[2:]
if command=='stat':
 p=pathlib.Path(args[-1]);s=p.stat();print(args[1].replace('%u','1000' if str(p).endswith('/data') else '0').replace('%h',str(s.st_nlink)).replace('%a',format(s.st_mode & 0o777,'o')).replace('%s',str(s.st_size)));sys.exit(0)
if command=='sha256sum':
 if not args: print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest()+'  -')
 else:
  for p in args: print(hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()+'  '+p)
 sys.exit(0)
if command=='flock':
 try: fcntl.flock(int(args[-1]),fcntl.LOCK_EX|fcntl.LOCK_NB)
 except OSError:sys.exit(1)
 sys.exit(0)
os.execvp(command,[command]+args)
'''); bb.chmod(0o755)
        common = r'''
import json,os,pathlib,sys
p=pathlib.Path(os.environ['FD_METADATA']);m=json.loads(p.read_text());a=sys.argv[1:]
'''
        commands = {
            'id': 'print(0)',
            'getprop': "print({'ro.boot.hardware':m['hardware'],'ro.mi.os.version.incremental':'OS4.99.TEST','sys.boot_completed':'1'}.get(a[0],''))",
            'dumpsys': r'''
user='    User 0: installed='+str(m['installed']).lower()+' hidden='+str(m['hidden']).lower()+' suspended='+str(m['suspended']).lower()+' stopped=false enabled='+str(m['enabled'])+' instant=false'
block='  Package ['+m['package']+'] (abc):\n    appId='+str(m['uid'])+'\n    pkgFlags=[ '+('SYSTEM HAS_CODE' if m['system'] else 'HAS_CODE')+' ]\n'+user+'\n'
text=('Packages:\n' if not m.get('missing_packages_header') else '')+block
if m.get('duplicate_user'):text+=user+'\n'
if m.get('duplicate_package'):text+=block
# Real shared-UID dumps contain additional User 0 rows outside Packages.
# These must neither override the active app state nor count as duplicates.
text+='\nQueries:\n  queryable via interaction:\n    User 0:\n      unrelated-package\n\nShared users:\n  SharedUser [android.uid.vendor] (123):\n    appId=10999\n    User 0:\n      runtime permissions:\n        android.permission.CAMERA: granted=true\n'
print(text)
''',
            'pm': r'''
if a[0]=='path':print('package:'+m['apk'])
elif a[:2]==['list','packages']:print('package:'+m['apk']+'='+m['package'])
elif a[0] in ('disable-user','default-state','enable','hide','unhide'):
 with open(os.environ['FD_TRACE'],'a') as t:t.write(a[0]+'\n')
 if not m.get('reject'):
  if a[0] in ('hide','unhide'):m['hidden']=(a[0]=='hide')
  else:m['enabled']={'disable-user':3,'default-state':0,'enable':1}[a[0]]
 if m.get('race_uid'):m['uid']+=1
 p.write_text(json.dumps(m))
 if a[0] in ('hide','unhide'):print('Package '+m['package']+' new hidden state: '+str(m['hidden']).lower())
 else:print('Package '+m['package']+' new state: '+{'disable-user':'disabled-user','default-state':'default','enable':'enabled'}[a[0]])
else:sys.exit(1)
''',
            'abx2xml': "print('<packages><cert index=\"0\" key=\"'+m['certificate']+'\"/><package name=\"'+m['package']+'\"><sigs count=\"1\"><cert index=\"0\"/></sigs></package></packages>')",
        }
        for name, script in commands.items():
            path = self.bin / name; path.write_text('#!' + sys.executable + '\n' + common + script + '\n'); path.chmod(0o755)
        mapping = {'/data':str(self.root/'data'), '/data/adb': str(self.adb), '/data/app': str(self.root / 'data/app'),
                   '/system/bin/abx2xml': str(self.bin / 'abx2xml')}
        pattern = r'(?<![A-Za-z0-9_/])(?:' + '|'.join(map(re.escape, sorted(mapping, key=len, reverse=True))) + ')'
        body = policy.files()[self.feature+'-policy.sh'].decode()
        body = re.sub(pattern, lambda match: mapping[match[0]], body)
        body = body.replace(policy.PROFILES[self.feature]['signer'], hashlib.sha256(b'01020304').hexdigest())
        body = body.replace(str(policy.PROFILES[self.feature]['signer_bytes'] * 2), '8')
        if self.feature == 'vendor-ims':
            body = body.replace(policy.PROFILES[self.feature]['apk'], hashlib.sha256(self.apk.read_bytes()).hexdigest())
        self.helper = self.module / (self.feature+'-policy.sh'); self.helper.write_text(body); self.helper.chmod(0o755)
        self.state = self.adb / ('hyperos-avd-core/'+self.feature+'-policy')
        self.wrapper = self.adb / ('service.d/hyperos-avd-'+self.feature+'-restore.sh')
        self.env = {**os.environ, 'PATH': str(self.bin) + ':' + os.environ['PATH'],
                    'FD_METADATA': str(self.meta), 'FD_TRACE': str(self.trace)}

    def update(self, **values):
        current = json.loads(self.meta.read_text()) if self.meta.exists() else {}
        current.update(values); self.meta.write_text(json.dumps(current))

    def run_policy(self, mode, check=True):
        return subprocess.run(['sh', str(self.helper), mode], env=self.env,
                              capture_output=True, text=True, check=check)

    def enabled(self): return json.loads(self.meta.read_text())['enabled']

    def owned_state(self):
        value=json.loads(self.meta.read_text())
        return value['hidden'] if self.feature=='finddevice' else value['enabled']==3

    def test_default_and_explicit_enabled_states_restore_exactly(self):
        for state in (0, 1):
            self.update(enabled=state)
            before = self.apk.read_bytes(), self.userdata.read_bytes(), self.apk.stat().st_ino
            self.assertIn('ready|owned-package-'+policy.PROFILES[self.feature]['operation'], self.run_policy('apply').stdout)
            self.assertTrue(self.owned_state()); self.assertTrue(self.wrapper.is_file())
            self.run_policy('apply')
            self.run_policy('restore'); self.assertEqual(self.enabled(), state)
            self.assertFalse((self.state / 'receipt.tsv').exists()); self.assertFalse(self.wrapper.exists())
            self.assertEqual(before, (self.apk.read_bytes(), self.userdata.read_bytes(), self.apk.stat().st_ino))

    def test_existing_user_disables_and_unknown_signatures_are_unowned(self):
        for state in (2, 3, 4):
            self.update(enabled=state)
            self.assertIn('user-state-preserved', self.run_policy('apply').stdout)
            self.assertEqual(self.enabled(), state); self.assertFalse((self.state / 'receipt.tsv').exists())
        self.update(enabled=0, certificate='aabbccdd')
        self.assertIn('unsupported-package-identity', self.run_policy('apply', False).stdout)
        self.assertEqual(self.trace.read_text(), '')

    def test_changed_apk_uid_or_user_state_never_restores(self):
        self.run_policy('apply')
        for change in ({'uid':6111}, {'enabled':2}):
            self.update(**change); before=self.trace.read_text()
            self.run_policy('restore',False); self.assertEqual(self.trace.read_text(),before)
            self.update(uid=6110,enabled=0 if self.feature=='finddevice' else 3,hidden=self.feature=='finddevice')
        self.apk.write_bytes(b'updated signed apk'); before=self.trace.read_text()
        self.run_policy('restore',False); self.assertEqual(self.trace.read_text(),before)

    def test_disabled_and_removed_module_boots_restore_without_module_hooks(self):
        self.run_policy('apply'); (self.module/'disable').touch()
        copied = self.state/'helper.sh'
        subprocess.run(['sh',str(copied),'boot'],env=self.env,check=True,capture_output=True)
        self.assertEqual(self.enabled(),0)
        (self.module/'disable').unlink(); self.run_policy('apply')
        self.module.rename(self.root/'removed-module')
        subprocess.run(['sh',str(copied),'boot'],env=self.env,check=True,capture_output=True)
        self.assertEqual(self.enabled(),0);self.assertFalse(self.wrapper.exists())

    def test_active_module_callback_preserves_the_owned_disable(self):
        self.run_policy('apply');before=self.trace.read_text()
        self.run_policy('boot');self.assertEqual(self.trace.read_text(),before);self.assertTrue(self.owned_state())
        (self.module/'features.disabled').write_text(self.feature+'\n')
        self.run_policy('boot');self.assertEqual(self.enabled(),0)

    def test_aliases_modified_recovery_and_unknown_receipts_are_preserved(self):
        self.run_policy('apply')
        receipt=self.state/'receipt.tsv';original=receipt.read_text();receipt.unlink()
        other=self.root/'user-receipt';other.write_text(original);receipt.symlink_to(other)
        before=self.trace.read_text();self.run_policy('restore',False)
        self.assertEqual(self.trace.read_text(),before);self.assertTrue(receipt.is_symlink())
        receipt.unlink();receipt.write_text('unknown user state\n');self.run_policy('restore',False)
        self.assertEqual(receipt.read_text(),'unknown user state\n')

    def test_hardware_and_non_system_identity_fail_before_package_changes(self):
        self.update(hardware='physical');self.run_policy('apply',False)
        self.update(hardware='ranchu',system=False);self.run_policy('apply',False)
        self.assertEqual(self.trace.read_text(),'')

    def test_uid_race_during_disable_retains_uncertain_receipt(self):
        self.update(race_uid=True);self.run_policy('apply',False)
        self.assertIn('|prepared', (self.state/'receipt.tsv').read_text())
        before=self.trace.read_text();self.run_policy('restore',False)
        self.assertEqual(self.trace.read_text(),before)

    def test_prepared_receipt_resumes_only_unchanged_original_state(self):
        self.run_policy('apply');receipt=self.state/'receipt.tsv'
        receipt.write_text(receipt.read_text().replace('|owned','|prepared'));self.update(enabled=0,hidden=False)
        self.run_policy('apply');self.assertTrue(self.owned_state())
        self.assertIn('|owned',receipt.read_text())

    def test_unknown_helpers_wrappers_and_locks_are_preserved(self):
        self.state.mkdir(parents=True, mode=0o700)
        lock=self.state/'lock';lock.write_text('custom lock content')
        self.run_policy('apply',False);self.assertEqual(lock.read_text(),'custom lock content')
        self.assertEqual(self.trace.read_text(),'');lock.unlink()
        helper=self.state/'helper.sh';helper.write_text('custom helper')
        self.run_policy('apply',False);self.assertEqual(helper.read_text(),'custom helper')
        self.assertEqual(self.trace.read_text(),'');helper.unlink()
        self.wrapper.parent.mkdir(exist_ok=True);self.wrapper.write_text('custom boot service')
        self.run_policy('apply',False);self.assertEqual(self.wrapper.read_text(),'custom boot service')
        self.assertEqual(self.trace.read_text(),'')

    def test_unknown_private_directory_contents_are_untouched(self):
        self.state.mkdir(parents=True,mode=0o700)
        note=self.state/'custom-note';note.write_text('retain this directory')
        before={p.name:p.read_bytes() for p in self.state.iterdir()}
        self.run_policy('apply',False)
        self.assertEqual({p.name:p.read_bytes() for p in self.state.iterdir()},before)
        self.assertEqual(self.trace.read_text(),'')

    def test_modified_helper_cannot_authorize_wrapper_cleanup(self):
        self.run_policy('apply')
        (self.state/'helper.sh').write_text('custom helper')
        self.wrapper.write_text('custom boot service')
        self.run_policy('restore');self.assertEqual(self.enabled(),0)
        self.assertEqual(self.wrapper.read_text(),'custom boot service')

    def test_preexisting_hidden_or_suspended_and_rejected_requests_are_not_claimed(self):
        for change in ({'hidden':True},{'suspended':True},{'installed':False}):
            self.update(**change);self.run_policy('apply')
            self.assertFalse((self.state/'receipt.tsv').exists())
            self.assertEqual(self.trace.read_text(),'')
            self.update(hidden=False,suspended=False,installed=True)
        self.update(reject=True)
        result=self.run_policy('apply',False)
        self.assertIn('package-policy-unconfirmed',result.stdout)
        self.assertFalse(self.owned_state())
        self.assertIn('|prepared', (self.state/'receipt.tsv').read_text())

    def test_queries_and_shared_users_do_not_change_the_active_package_snapshot(self):
        self.run_policy('apply');before=self.trace.read_text()
        self.run_policy('apply');self.assertEqual(self.trace.read_text(),before)
        self.run_policy('restore');self.assertEqual(self.enabled(),0)
        self.assertFalse(self.owned_state())

    def test_duplicate_active_package_user_and_missing_section_fail_closed(self):
        for field in ('duplicate_package','duplicate_user','missing_packages_header'):
            with self.subTest(field=field):
                self.update(**{field:True})
                result=self.run_policy('apply',False)
                self.assertIn('unsupported-package-identity',result.stdout)
                self.assertEqual(self.trace.read_text(),'')
                self.assertFalse((self.state/'receipt.tsv').exists())
                self.update(**{field:False})

    def current_schema_previous_controls(self, revision=8):
        from native_module_history import REVIEWED
        controls=next(row['policy_controls'][self.feature] for row in REVIEWED if row['revision']==revision)
        old_helper=('#!/bin/sh\n# Reviewed Core'+str(revision)+' fixture helper\n').encode()
        old_callback=('#!/bin/sh\n# Reviewed Core'+str(revision)+' fixture callback\n').encode()
        source=self.helper.read_text().replace(controls['helper'],hashlib.sha256(old_helper).hexdigest())
        source=source.replace(controls['recovery'],hashlib.sha256(old_callback).hexdigest())
        self.helper.write_text(source)
        (self.state/'helper.sh').write_bytes(old_helper)
        self.wrapper.write_bytes(old_callback)
        return old_helper,old_callback

    def test_exact_core8_owned_state_updates_controls_without_reclaiming_package_state(self):
        self.run_policy('apply');original=(self.state/'receipt.tsv').read_bytes()
        self.current_schema_previous_controls();before=self.trace.read_text()
        self.run_policy('apply')
        self.assertEqual(self.trace.read_text(),before)
        self.assertEqual((self.state/'receipt.tsv').read_bytes(),original)
        self.assertEqual((self.state/'helper.sh').read_bytes(),self.helper.read_bytes())
        self.run_policy('restore');self.assertFalse(self.owned_state())

    def test_exact_core9_owned_state_retains_user_choices_and_replaces_only_reviewed_controls(self):
        self.run_policy('apply');original=(self.state/'receipt.tsv').read_bytes()
        self.current_schema_previous_controls(9);before=self.trace.read_text()
        self.run_policy('apply')
        self.assertEqual(self.trace.read_text(),before)
        self.assertEqual((self.state/'receipt.tsv').read_bytes(),original)
        self.assertEqual((self.state/'helper.sh').read_bytes(),self.helper.read_bytes())
        (self.module/'features.disabled').write_text(self.feature+'\n')
        self.run_policy('boot');self.assertFalse(self.owned_state())
        self.assertFalse((self.state/'receipt.tsv').exists());self.assertFalse(self.wrapper.exists())

    def test_exact_core10_owned_state_retains_package_identity_and_feature_off_restoration(self):
        self.run_policy('apply');original=(self.state/'receipt.tsv').read_bytes()
        self.current_schema_previous_controls(10);before=self.trace.read_text()
        self.run_policy('apply')
        self.assertEqual(self.trace.read_text(),before)
        self.assertEqual((self.state/'receipt.tsv').read_bytes(),original)
        self.assertEqual((self.state/'helper.sh').read_bytes(),self.helper.read_bytes())
        (self.module/'features.disabled').write_text(self.feature+'\n')
        self.run_policy('boot');self.assertFalse(self.owned_state())
        self.assertFalse((self.state/'receipt.tsv').exists());self.assertFalse(self.wrapper.exists())

    def test_current_callback_with_reviewed_core8_helper_resumes_control_publication(self):
        self.run_policy('apply');self.current_schema_previous_controls()
        source=self.helper.read_text().split('\nguard ||',1)[0]
        body=source+'\nemit_recovery '+shlex.quote(hashlib.sha256(self.helper.read_bytes()).hexdigest())+'\n'
        result=subprocess.run(['sh','-c',body],env=self.env,capture_output=True,text=True,check=True)
        self.wrapper.write_text(result.stdout);before=self.trace.read_text()
        self.run_policy('apply');self.assertEqual(self.trace.read_text(),before)
        self.assertEqual((self.state/'helper.sh').read_bytes(),self.helper.read_bytes())
        self.run_policy('restore');self.assertFalse(self.owned_state())

    def test_mixed_reviewed_helpers_and_callbacks_do_not_authorize_migration(self):
        from native_module_history import REVIEWED
        self.run_policy('apply');self.current_schema_previous_controls()
        controls=next(row['policy_controls'][self.feature] for row in REVIEWED if row['revision']==7)
        unrelated_callback=b'#!/bin/sh\n# Reviewed Core7 callback with mismatched helper\n'
        self.helper.write_text(self.helper.read_text().replace(controls['recovery'],hashlib.sha256(unrelated_callback).hexdigest()))
        self.wrapper.write_bytes(unrelated_callback)
        before=self.trace.read_text(),(self.state/'receipt.tsv').read_bytes(),(self.state/'helper.sh').read_bytes(),self.wrapper.read_bytes()
        result=self.run_policy('apply',False)
        self.assertIn('recovery-owner-conflict',result.stdout)
        self.assertEqual(before,(self.trace.read_text(),(self.state/'receipt.tsv').read_bytes(),(self.state/'helper.sh').read_bytes(),self.wrapper.read_bytes()))

    def legacy_transaction(self, phase='prepared'):
        from native_module_history import REVIEWED
        controls=next(row['policy_controls'][self.feature] for row in REVIEWED if row['revision']==7 and 'policy_controls' in row)
        # Namespace-adjusted stand-ins bind the same complete-control ownership
        # boundary; production pins remain the exact frozen canonical archive.
        old_helper=b'#!/bin/sh\n# Reviewed legacy fixture helper\n'
        old_callback=b'#!/bin/sh\n# Reviewed legacy fixture callback\n'
        source=self.helper.read_text().replace(controls['helper'],hashlib.sha256(old_helper).hexdigest())
        source=source.replace(controls['recovery'],hashlib.sha256(old_callback).hexdigest())
        self.helper.write_text(source)
        self.state.mkdir(parents=True,mode=0o700)
        (self.state/'helper.sh').write_bytes(old_helper)
        self.wrapper.parent.mkdir(parents=True,exist_ok=True);self.wrapper.write_bytes(old_callback)
        row='1|6110|'+str(self.apk)+'|'+hashlib.sha256(self.apk.read_bytes()).hexdigest()+'|0|'+hashlib.sha256(b'01020304').hexdigest()+'|'+phase+'\n'
        (self.state/'receipt.tsv').write_text(row)
        return row

    def test_exact_legacy_prepared_baseline_migrates_without_claiming_a_failed_disable(self):
        self.legacy_transaction();self.run_policy('apply')
        self.assertTrue(self.owned_state())
        self.assertTrue((self.state/'receipt.tsv').read_text().startswith('2|'+self.feature+'|'))
        self.assertEqual(self.trace.read_text(), ('hide' if self.feature=='finddevice' else 'disable-user')+'\n')
        self.run_policy('restore');self.assertEqual(self.enabled(),0)
        self.assertFalse(json.loads(self.meta.read_text())['hidden'])

    def test_exact_legacy_owned_disable_retains_or_restores_before_new_policy(self):
        self.legacy_transaction('owned');self.update(enabled=3)
        self.run_policy('apply');self.assertTrue(self.owned_state())
        self.assertEqual(self.trace.read_text(), 'default-state\nhide\n' if self.feature=='finddevice' else '')
        self.run_policy('restore');self.assertEqual(self.enabled(),0)

    def test_known_partial_legacy_publication_recovers_after_control_inode_replacement(self):
        self.legacy_transaction()
        source=self.helper.read_text().split('\nguard ||',1)[0]
        body=source+'\nemit_recovery '+shlex.quote(hashlib.sha256(self.helper.read_bytes()).hexdigest())+'\n'
        result=subprocess.run(['sh','-c',body],env=self.env,capture_output=True,text=True,check=True)
        self.wrapper.write_text(result.stdout)
        (self.state/'helper.sh').write_bytes(self.helper.read_bytes())
        self.run_policy('apply');self.assertTrue(self.owned_state())
        self.assertTrue((self.state/'receipt.tsv').read_text().startswith('2|'))
        self.run_policy('restore');self.assertFalse(self.owned_state())

    def test_legacy_changed_controls_or_external_hide_are_never_claimed(self):
        row=self.legacy_transaction()
        helper=self.state/'helper.sh';original=helper.read_bytes();helper.write_bytes(original+b'changed')
        self.run_policy('apply',False)
        self.assertEqual(self.trace.read_text(),'');self.assertEqual((self.state/'receipt.tsv').read_text(),row)
        helper.write_bytes(original);self.update(hidden=True)
        self.run_policy('apply',False)
        self.assertEqual(self.trace.read_text(),'');self.assertEqual((self.state/'receipt.tsv').read_text(),row)
        self.update(hidden=False);(self.state/'receipt.tsv').write_text(row.replace('|prepared','|owned'))
        self.run_policy('apply',False)
        self.assertEqual(self.trace.read_text(),'');self.assertFalse(self.owned_state())

    def test_package_contains_compiled_helpers_and_exact_recovery_hash(self):
        from package_native_module import module_files
        files=module_files();compiled=policy.files()
        self.assertIn(hashlib.sha256(compiled['finddevice-policy.sh']).hexdigest().encode(), compiled['finddevice-recovery.sh'])
        self.assertEqual(files['finddevice-policy.sh'],compiled['finddevice-policy.sh'])
        self.assertEqual(files['finddevice-recovery.sh'],compiled['finddevice-recovery.sh'])
        self.assertIn(b'finddevice\n',files['features.tsv']);self.assertIn(b'vendor-ims\n',files['features.tsv'])
        self.assertIn('uninstall.sh',files)
        for feature in policy.PROFILES:
            self.assertIn(hashlib.sha256(compiled[feature+'-policy.sh']).hexdigest().encode(), compiled[feature+'-recovery.sh'])
            self.assertNotIn(b'@FEATURE@',files[feature+'-policy.sh'])


class VendorImsPolicyTests(FindDevicePolicyTests):
    feature = 'vendor-ims'


if __name__ == '__main__': unittest.main()
