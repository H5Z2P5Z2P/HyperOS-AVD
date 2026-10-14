"""Exercise the shipped truthful SEDC Binder protocol without Android or hardware."""
import hashlib
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import os
import shlex
import json
import unittest
from unittest.mock import patch
import zipfile

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'scripts'))
import device_credential_runtime as runtime
from patch_gnss import java

STUBS = {
    'IBinder': '''package android.os;
public interface IBinder {
 int FLAG_ONEWAY=1, INTERFACE_TRANSACTION=0x5f4e5446;
 boolean transact(int code, Parcel data, Parcel reply, int flags) throws RemoteException;
}''',
    'Binder': '''package android.os;
public class Binder implements IBinder {
 public boolean transact(int code, Parcel data, Parcel reply, int flags) throws RemoteException {
  data.setDataPosition(0); boolean result=onTransact(code,data,reply,flags);
  if(reply!=null)reply.setDataPosition(0); return result;
 }
 protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) throws RemoteException {return false;}
}''',
    'RemoteException': '''package android.os;
public class RemoteException extends Exception { public RemoteException(String text){super(text);} }''',
    'ServiceSpecificException': '''package android.os;
public class ServiceSpecificException extends RuntimeException {
 public final int errorCode;
 public ServiceSpecificException(int code,String text){super(text);errorCode=code;}
}''',
    'ServiceManager': '''package android.os;
public class ServiceManager {
 public static IBinder existing; public static int additions;
 public static IBinder checkService(String name){return existing;}
 public static void addService(String name,IBinder binder){additions++;existing=binder;}
}''',
    'Parcel': '''package android.os;
import java.util.ArrayList;
public class Parcel {
 public static int outstanding;
 private final ArrayList<Object> values=new ArrayList<Object>(); private int position;
 public static Parcel obtain(){outstanding++;return new Parcel();}
 public void recycle(){outstanding--;}
 public int dataPosition(){return position;}
 public int dataAvail(){return values.size()-position;}
 public void setDataPosition(int p){position=p;}
 public void writeInterfaceToken(String s){writeString(s);}
 public void enforceInterface(String s){if(!s.equals(readString()))throw new SecurityException("Wrong descriptor");}
 public void writeInt(int n){values.add(Integer.valueOf(n));}
 public int readInt(){return ((Integer)values.get(position++)).intValue();}
 public void writeString(String s){values.add(s);}
 public String readString(){return (String)values.get(position++);}
 public void writeStrongBinder(IBinder b){values.add(b);}
 public IBinder readStrongBinder(){return (IBinder)values.get(position++);}
 public void writeByteArray(byte[] b){values.add(b);}
 public byte[] createByteArray(){return (byte[])values.get(position++);}
 public void writeNoException(){values.add(null);}
 public void writeException(Exception e){values.add(e);}
 public void readException(){Exception e=(Exception)values.get(position++);if(e!=null)throw (RuntimeException)e;}
}''',
}

HARNESS = r'''package io.github.hyperosavd;
import android.os.*;
import java.io.File;
import java.nio.file.Files;

public class CredentialHarness {
 static void require(boolean value){if(!value)throw new AssertionError("Protocol requirement failed");}
 static Parcel request(String descriptor,int code,IBinder callback,int reload){
  Parcel p=Parcel.obtain();p.writeInterfaceToken(descriptor);
  if(code!=1 && descriptor.equals(DeviceCredentialRuntime.LEGACY))p.writeStrongBinder(callback);
  if(code==3){p.writeInt(1);p.writeByteArray(new byte[]{3,4});p.writeInt(reload);}
  return p;
 }
 public static void main(String[] args) throws Exception {
  DeviceCredentialRuntime service=new DeviceCredentialRuntime();
  String action=args[0];
  if(action.equals("roundtrip")){
   for(String descriptor:new String[]{DeviceCredentialRuntime.LEGACY,DeviceCredentialRuntime.BOUND})
    for(int code=1;code<=4;code++)DeviceCredentialRuntime.verify(service,descriptor,code);
  } else if(action.equals("single")) {
   DeviceCredentialRuntime.verify(service,args[1].equals("legacy")?DeviceCredentialRuntime.LEGACY:DeviceCredentialRuntime.BOUND,Integer.parseInt(args[2]));
  } else if(action.equals("unknown")) {
   Parcel p=Parcel.obtain(),r=Parcel.obtain();require(!service.transact(99,p,r,0));p.recycle();r.recycle();
  } else if(action.equals("descriptor")) {
   Parcel p=Parcel.obtain(),r=Parcel.obtain();require(service.transact(IBinder.INTERFACE_TRANSACTION,p,r,0));require(r.readString().equals(DeviceCredentialRuntime.LEGACY));p.recycle();r.recycle();
  } else if(action.equals("preserve")) {
   ServiceManager.existing=new Binder();
   try{DeviceCredentialRuntime.register("miui.sedc");throw new AssertionError("Existing service replaced");}
   catch(IllegalStateException expected){require(ServiceManager.additions==0);}
  } else if(action.equals("probe")) {
   require(DeviceCredentialRuntime.probeName(args[1])==Boolean.parseBoolean(args[2]));
  } else if(action.equals("lifecycle")) {
   File module=new File(args[1]).getCanonicalFile(),lease=new File(module,"lease");module.mkdirs();Files.write(lease.toPath(),"owned".getBytes("UTF-8"));
   require(DeviceCredentialRuntime.live(module,lease,"owned"));require(!DeviceCredentialRuntime.live(module,lease,"other"));
   for(String flag:new String[]{"disable","remove"}){File f=new File(module,flag);f.createNewFile();require(!DeviceCredentialRuntime.live(module,lease,"owned"));f.delete();}
   for(String name:new String[]{"features.disabled","legacy-blocked.features"}){
    File f=new File(module,name);Files.write(f.toPath(),"device-credential\n".getBytes("UTF-8"));require(!DeviceCredentialRuntime.live(module,lease,"owned"));
    Files.write(f.toPath(),"finddevice\n".getBytes("UTF-8"));require(!DeviceCredentialRuntime.live(module,lease,"owned"));
    Files.write(f.toPath(),"unrelated\n".getBytes("UTF-8"));require(DeviceCredentialRuntime.live(module,lease,"owned"));f.delete();
   }
   lease.delete();require(!DeviceCredentialRuntime.live(module,lease,"owned"));
  } else {
   final DeviceCredentialRuntime.Result result=new DeviceCredentialRuntime.Result(2);
   int code=action.equals("trailing")?1:3;
   String token=action.equals("bad-token")?"untrusted":DeviceCredentialRuntime.LEGACY;
   Parcel p=request(token,code,action.equals("null-callback")?null:result,action.equals("bad-boolean")?7:0),r=Parcel.obtain();
   if(action.equals("trailing"))p.writeInt(77);
   try{
    service.transact(code,p,action.equals("no-reply")?null:r,action.equals("oneway")?1:0);
    throw new AssertionError("Malformed request accepted");
   }catch(SecurityException expected){require(action.equals("bad-token"));}
   catch(IllegalArgumentException expected){require(!action.equals("bad-token"));}
   finally{p.recycle();r.recycle();}
   require(result.arrived.getCount()==1);
  }
  require(Parcel.outstanding==0);System.out.println("PASS");
 }
}'''


class DeviceCredentialJavaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.java = Path(java())
        except RuntimeError as error:
            raise unittest.SkipTest(str(error))
        javac = cls.java.with_name('javac')
        if not javac.is_file():
            raise unittest.SkipTest('Host JDK is unavailable')
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.folder = Path(cls.temp.name)
        android, package = cls.folder / 'android/os', cls.folder / 'io/github/hyperosavd'
        android.mkdir(parents=True)
        package.mkdir(parents=True)
        for name, source in STUBS.items():
            (android / (name + '.java')).write_text(source)
        (package / 'DeviceCredentialRuntime.java').write_text(runtime.JAVA_SOURCE)
        (package / 'CredentialHarness.java').write_text(HARNESS)
        subprocess.run([str(javac), '-source', '8', '-target', '8', '-d', str(cls.folder),
                        *map(str, cls.folder.rglob('*.java'))],
                       check=True, capture_output=True)

    def execute(self, *args):
        result = subprocess.run([str(self.java), '-cp', str(self.folder),
                                 'io.github.hyperosavd.CredentialHarness', *args],
                                capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout.strip(), 'PASS')

    def test_all_eight_transactions_reject_without_credentials(self):
        self.execute('roundtrip')

    def test_legacy_capability_is_false(self):
        self.execute('single', 'legacy', '1')

    def test_legacy_get_id_callback_is_not_supported_with_null_id(self):
        self.execute('single', 'legacy', '2')

    def test_legacy_sign_callback_is_not_supported_with_null_signature(self):
        self.execute('single', 'legacy', '3')

    def test_legacy_reload_callback_is_not_supported(self):
        self.execute('single', 'legacy', '4')

    def test_bound_capability_is_false(self):
        self.execute('single', 'bound', '1')

    def test_bound_operations_return_typed_not_supported(self):
        for code in (2, 3, 4):
            with self.subTest(code=code):
                self.execute('single', 'bound', str(code))

    def test_interface_descriptor_is_audited_legacy_contract(self):
        self.execute('descriptor')

    def test_unknown_transactions_are_not_handled(self):
        self.execute('unknown')

    def test_unknown_descriptor_is_rejected_before_callback(self):
        self.execute('bad-token')

    def test_missing_callback_is_rejected(self):
        self.execute('null-callback')

    def test_malformed_boolean_is_rejected_before_callback(self):
        self.execute('bad-boolean')

    def test_trailing_payload_is_rejected_before_callback(self):
        self.execute('trailing')

    def test_oneway_and_missing_reply_are_rejected_before_callback(self):
        for action in ('oneway', 'no-reply'):
            with self.subTest(action=action):
                self.execute(action)

    def test_existing_service_is_preserved(self):
        self.execute('preserve')

    def test_probe_names_cannot_target_production_or_other_services(self):
        self.execute('probe', 'hyperosavd.sedc.probe.' + 'a' * 32, 'true')
        for name in ('miui.sedc', 'hyperosavd.sedc.probe.', '../miui.sedc',
                     'hyperosavd.sedc.probe.' + 'A' * 32, 'power'):
            with self.subTest(name=name):
                self.execute('probe', name, 'false')

    def test_module_flags_lease_change_and_removal_end_ownership(self):
        with tempfile.TemporaryDirectory() as folder:
            self.execute('lifecycle', folder)


class DeviceCredentialAssetsTest(unittest.TestCase):
    def test_offline_assets_are_source_and_hash_bound(self):
        with patch.object(runtime, 'compile_assets', side_effect=AssertionError('Offline consumer')):
            files = runtime.files()
        self.assertEqual(set(files), {'device-credential.jar', 'device-credential.tsv'})
        self.assertEqual(hashlib.sha256(files['device-credential.jar']).hexdigest(), runtime.JAR_SHA256)
        with zipfile.ZipFile(io.BytesIO(files['device-credential.jar'])) as archive:
            self.assertEqual(archive.namelist(), ['classes.dex'])
            self.assertTrue(archive.read('classes.dex').startswith(b'dex\n'))
        rows = files['device-credential.tsv'].decode().splitlines()
        self.assertEqual(len(rows), 10)
        self.assertIn('client-dex|' + runtime.CLIENT_DEX_SHA256, rows)
        self.assertIn('unsupported|-100', rows)

    def test_changed_source_is_preserved_and_requires_rebuild(self):
        with patch.object(runtime, 'JAVA_SOURCE', runtime.JAVA_SOURCE + '\n'):
            with self.assertRaisesRegex(RuntimeError, 'source changed'):
                runtime.files()

    def test_changed_dex_is_rejected(self):
        with patch.object(runtime, 'JAR_HEX', '00' + runtime.JAR_HEX[2:]):
            with self.assertRaisesRegex(RuntimeError, 'DEX asset changed'):
                runtime.files()

    def test_source_regenerates_exact_embedded_asset(self):
        sdk = Path.home() / 'Library/Android/sdk'
        if not (sdk / 'platforms/android-36/android.jar').is_file():
            self.skipTest('Android maintenance toolchain is unavailable')
        with tempfile.TemporaryDirectory() as folder:
            self.assertEqual(runtime.compile_assets(sdk, Path(folder)),
                             runtime.files()['device-credential.jar'])


class DeviceCredentialShellTest(unittest.TestCase):
    def setUp(self):
        import test_native_module_runtime as fixture
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.module, self.state, self.proc = [self.folder / name for name in ('module', 'state', 'proc')]
        for path in (self.module, self.state, self.proc / '123', self.proc / 'sys/kernel/random'):
            path.mkdir(parents=True, exist_ok=True)
        self.bb = self.folder / 'busybox'
        self.bb.write_text(fixture.BUSYBOX.replace('/usr/bin/env python3', sys.executable))
        self.bb.chmod(0o755)
        self.metadata = self.folder / 'metadata.json'
        self.metadata.write_text('{}')
        for name, data in runtime.files().items():
            (self.module / name).write_bytes(data)
        (self.module / 'device-credential.sh').write_bytes(
            (REPO / 'modules/native-compat/device-credential.sh').read_bytes())
        (self.module / 'tcm-capability.sh').write_bytes(
            (REPO / 'modules/native-compat/tcm-capability.sh').read_bytes())
        self.sums()
        self.boot = '12345678-1234-1234-1234-123456789abc'
        (self.proc / 'sys/kernel/random/boot_id').write_text(self.boot + '\n')
        (self.proc / '123/cmdline').write_bytes(('\0'.join(['/system/bin/app_process', '/system/bin',
            runtime.CLASS, '--serve', str(self.module), str(self.state / 'credential-daemon.record')]) + '\0').encode())
        (self.proc / '123/environ').write_bytes(('CLASSPATH=' + str(self.module / 'device-credential.jar') + '\0').encode())
        (self.proc / '123/status').write_text('Uid:\t0\t0\t0\t0\n')
        (self.proc / '123/stat').write_text('123 (credential helper) ' + ' '.join(['S'] + ['0'] * 18 + ['456']) + '\n')
        self.record()

    def sums(self):
        (self.module / 'SHA256SUMS').write_text(''.join(hashlib.sha256(path.read_bytes()).hexdigest()
            + '  ' + path.name + '\n' for path in sorted(self.module.iterdir()) if path.name != 'SHA256SUMS'))

    def record(self, *, boot=None, pid='123', start='456', jar=None, path=None):
        row = '|'.join(['1', self.boot if boot is None else boot, pid, start,
            runtime.JAR_SHA256 if jar is None else jar,
            str(self.module / 'device-credential.jar') if path is None else path])
        (self.state / 'credential-daemon.record').write_text(row + '\n')

    def shell(self, body, interpreter='/bin/sh'):
        environment = {**os.environ, 'MODDIR': str(self.module), 'CORE_STATE': str(self.state),
                       'HYPEROS_CORE_STATE': str(self.state),
                       'BB': str(self.bb), 'PROC': str(self.proc),
                       'HYPEROS_NATIVE_TEST_METADATA': str(self.metadata), 'HYPEROS_NATIVE_TEST_OWNER': '0:0'}
        prelude = f'''. {shlex.quote(str(REPO / 'modules/native-compat/runtime.sh'))}
. {shlex.quote(str(REPO / 'modules/native-compat/platform.sh'))}
. {shlex.quote(str(REPO / 'modules/native-compat/device-credential.sh'))}
BB={shlex.quote(str(self.bb))}
PROC={shlex.quote(str(self.proc))}
core_state_safe() {{ return 0; }}
native_assets() {{ return 0; }}
native_ns_hash() {{ native_hash "$2"; }}
kill() {{ printf 'SIGNAL %s\\n' "$*"; }}
native_status() {{ printf 'STATUS %s\\n' "$*"; }}
'''
        if interpreter == '/bin/ksh':
            # macOS ksh spells Android mksh's local builtin as typeset.
            prelude = 'alias local=typeset\n' + prelude
        return subprocess.run([interpreter, '-c', prelude + body], env=environment,
                              capture_output=True, text=True, check=False)

    def test_canonical_recipe_and_process_lifetime_are_recognized(self):
        result = self.shell('core_credential_lease_pid')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), '123')

    @unittest.skipUnless(Path('/bin/ksh').is_file(), 'Korn shell is unavailable')
    def test_korn_shell_pipe_patterns_preserve_verified_lease_identity(self):
        # Android mksh interprets an unquoted pipe as pattern alternation.
        result = self.shell('core_credential_lease_pid', '/bin/ksh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), '123')

    def test_unknown_source_or_extra_recipe_rows_are_preserved(self):
        recipe = self.module / 'device-credential.tsv'
        for text in (recipe.read_text() + 'unknown|data\n', recipe.read_text().replace('unsupported|-100', 'unsupported|-101')):
            recipe.write_text(text)
            self.sums()
            result = self.shell('core_credential_lease_pid')
            self.assertNotEqual(result.returncode, 0)

    def test_tampered_recipe_checksum_and_jar_do_not_authorize_a_signal(self):
        for name in ('device-credential.tsv', 'device-credential.jar'):
            original = (self.module / name).read_bytes()
            (self.module / name).write_bytes(original + b'x')
            result = self.shell('core_device_credential_cleanup')
            self.assertNotIn('SIGNAL', result.stdout)
            (self.module / name).write_bytes(original)

    def test_boot_start_hash_classpath_and_identity_mismatches_never_signal(self):
        for fields in ({'boot': '12345678-1234-1234-1234-000000000000'}, {'start': '457'},
                       {'jar': '0' * 64}, {'path': '/custom/helper.jar'}, {'pid': '999'}):
            with self.subTest(fields=fields):
                self.record(**fields)
                result = self.shell('core_device_credential_cleanup')
                self.assertNotIn('SIGNAL', result.stdout)

    def test_custom_commandline_uid_or_environment_never_signal(self):
        for name, value in (('cmdline', b'io.github.hyperosavd.DeviceCredentialRuntime\0'),
                            ('status', b'Uid:\t1000\t1000\t1000\t1000\n'),
                            ('environ', b'CLASSPATH=/custom/helper.jar\0')):
            path = self.proc / ('123/' + name)
            original = path.read_bytes()
            path.write_bytes(value)
            self.assertNotIn('SIGNAL', self.shell('core_device_credential_cleanup').stdout)
            path.write_bytes(original)

    def test_alias_and_malformed_receipts_never_signal(self):
        path = self.state / 'credential-daemon.record'
        text = path.read_text()
        path.write_text(text + text)
        self.assertNotIn('SIGNAL', self.shell('core_device_credential_cleanup').stdout)
        original = self.state / 'copied-record'
        original.write_text(text)
        path.unlink()
        path.symlink_to(original)
        self.assertNotIn('SIGNAL', self.shell('core_device_credential_cleanup').stdout)

    def test_cleanup_signals_only_one_verified_process(self):
        result = self.shell('core_device_credential_cleanup')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count('SIGNAL'), 1)
        self.assertIn('SIGNAL -TERM 123', result.stdout)

    def test_unowned_registered_service_is_retained(self):
        (self.state / 'credential-daemon.record').unlink()
        result = self.shell('core_permitted() { return 0; }; core_credential_present() { return 0; }; core_device_credential')
        self.assertIn('existing-service-preserved', result.stdout)
        self.assertNotIn('SIGNAL', result.stdout)

    def test_unknown_lease_is_retained_when_no_service_is_registered(self):
        path = self.state / 'credential-daemon.record'
        path.write_text('unknown custom owner\n')
        result = self.shell('core_permitted() { return 0; }; core_credential_present() { return 1; }; core_device_credential')
        self.assertIn('unknown-daemon-lease-preserved', result.stdout)
        self.assertEqual(path.read_text(), 'unknown custom owner\n')

    def test_missing_hardware_proof_prevents_start(self):
        (self.state / 'credential-daemon.record').unlink()
        (self.proc / '123/cmdline').unlink()
        result = self.shell('core_permitted() { return 0; }; core_credential_present() { return 1; }; native_privacy_eligible() { return 1; }; core_device_credential')
        self.assertIn('unaudited-ranchu-vendor', result.stdout)
        self.assertFalse((self.state / 'credential-daemon.record').exists())

    def test_unleased_helper_is_preserved_without_duplicate_start(self):
        (self.state / 'credential-daemon.record').unlink()
        result = self.shell('core_permitted() { return 0; }; core_credential_present() { return 1; }; core_device_credential')
        self.assertIn('unowned-daemon-preserved', result.stdout)
        self.assertNotIn('SIGNAL', result.stdout)

    def test_user_feature_choice_invokes_only_owned_cleanup(self):
        result = self.shell('core_permitted() { return 1; }; core_device_credential')
        self.assertIn('SIGNAL -TERM 123', result.stdout)

    def apk_case(self, *, owner='1000:1000', factory=False, alias=False, hardlink=False):
        root = self.folder.resolve() / ('product' if factory else 'data/app')
        path = root / 'app/package/base.apk'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'PackageManager-authenticated APK fixture')
        value = path.stat()
        self.metadata.write_text(json.dumps({f'{value.st_dev}:{value.st_ino}': {'owner': owner}}))
        if hardlink:
            os.link(path, path.with_name('hardlinked.apk'))
        if alias:
            source = path.with_name('original.apk')
            path.rename(source)
            path.symlink_to(source)
        # Redirect only the immutable guest roots to isolated fixture roots;
        # execute the actual validator, including owner/link/ancestor checks.
        source = (REPO / 'modules/native-compat/device-credential.sh').read_text()
        source = source.replace('/data/app/', str(self.folder.resolve() / 'data/app') + '/')
        source = source.replace('/product/', str(self.folder.resolve() / 'product') + '/')
        return self.shell(source + '\ncore_credential_apk ' + shlex.quote(str(path)))

    def test_pm_data_apk_owner_1000_and_factory_owner_zero_are_supported(self):
        self.assertEqual(self.apk_case().returncode, 0)
        self.assertEqual(self.apk_case(owner='0:0', factory=True).returncode, 0)

    def test_other_data_apk_owners_and_nonroot_factory_apks_are_preserved(self):
        self.assertNotEqual(self.apk_case(owner='0:0').returncode, 0)
        self.assertNotEqual(self.apk_case(owner='10001:10001').returncode, 0)
        self.assertNotEqual(self.apk_case(owner='1000:1000', factory=True).returncode, 0)

    def test_aliased_or_hardlinked_apks_are_preserved(self):
        self.assertNotEqual(self.apk_case(alias=True).returncode, 0)

    def test_hardlinked_apk_is_preserved(self):
        self.assertNotEqual(self.apk_case(hardlink=True).returncode, 0)

    def test_owned_process_without_registered_service_is_pending(self):
        result = self.shell('core_permitted() { return 0; }; core_credential_present() { return 1; }; core_device_credential')
        self.assertIn('pending owned-service-not-yet-registered', result.stdout)
        self.assertNotIn('ready', result.stdout)


if __name__ == '__main__':
    unittest.main()
