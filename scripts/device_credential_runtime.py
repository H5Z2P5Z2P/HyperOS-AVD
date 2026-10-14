"""Offline, truthful unsupported SEDC capability service for audited virtual devices.

This helper never generates, loads, stores, or returns device credentials. Core
must validate its client/content contract and own the production daemon lease.
The global service advertises the legacy descriptor. Bound tokens are only a
typed rejection alias, not a replacement for either signed bound service.
"""
import argparse
import hashlib
import io
import os
from pathlib import Path
import subprocess
import zipfile

CLASS = 'io.github.hyperosavd.DeviceCredentialRuntime'
CLIENT_DEX_SHA256 = 'e08467ac0331689545f059e09254dde548d551ef7ed85b808934ccab574e7199'

JAVA_SOURCE = r'''package io.github.hyperosavd;

import android.os.Binder;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import java.io.File;
import java.io.FileInputStream;
import java.io.ByteArrayOutputStream;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.security.MessageDigest;
import java.util.zip.ZipFile;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Files;

public final class DeviceCredentialRuntime extends Binder {
    static final String SERVICE = "miui.sedc";
    static final String LEGACY = "com.xiaomi.security.devicecredential.ISecurityDeviceCredentialManager.v1";
    static final String BOUND = "com.xiaomi.security.devicecredential.ISecurityDeviceCredentialManager";
    static final String CALLBACK = "com.xiaomi.security.devicecredential.ionremotecallfinishedlistener.v0";
    static final int NOT_SUPPORTED = -100;
    static final String PROBE_PREFIX = "hyperosavd.sedc.probe.";
    static final String CLIENT_DEX = "@CLIENT_DEX_SHA256@";

    static void exhausted(Parcel data) {
        if (data.dataAvail() != 0) throw new IllegalArgumentException("Unexpected SEDC payload");
    }

    static RuntimeException unsupported() {
        try {
            return (RuntimeException) Class.forName("android.os.ServiceSpecificException")
                    .getConstructor(int.class, String.class).newInstance(NOT_SUPPORTED,
                            "Device credential hardware unavailable");
        } catch (Exception error) { throw new IllegalStateException("Missing typed service error", error); }
    }

    static void callback(IBinder listener, int transaction) throws RemoteException {
        if (listener == null) throw new IllegalArgumentException("Missing SEDC callback");
        Parcel result = Parcel.obtain();
        try {
            result.writeInterfaceToken(CALLBACK);
            result.writeInt(NOT_SUPPORTED);
            if (transaction == 1) result.writeString(null);
            if (transaction == 2) result.writeByteArray(null);
            if (!listener.transact(transaction, result, null, IBinder.FLAG_ONEWAY)) {
                throw new RemoteException("Unsupported SEDC callback transaction");
            }
        } finally { result.recycle(); }
    }

    protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) throws RemoteException {
        if (code == IBinder.INTERFACE_TRANSACTION) {
            if (reply != null) reply.writeString(LEGACY);
            return true;
        }
        if (code < 1 || code > 4) return super.onTransact(code, data, reply, flags);
        if (reply == null || (flags & IBinder.FLAG_ONEWAY) != 0) {
            throw new IllegalArgumentException("SEDC request must be synchronous");
        }
        int position = data.dataPosition();
        boolean legacy = true;
        try { data.enforceInterface(LEGACY); }
        catch (SecurityException wrongLegacy) {
            data.setDataPosition(position);
            data.enforceInterface(BOUND);
            legacy = false;
        }
        if (code == 1) {
            exhausted(data);
            reply.writeNoException();
            reply.writeInt(0);
            return true;
        }
        IBinder listener = legacy ? data.readStrongBinder() : null;
        if (code == 3) {
            data.readInt();
            data.createByteArray();
            int reload = data.readInt();
            if (reload != 0 && reload != 1) throw new IllegalArgumentException("Invalid SEDC boolean");
        }
        exhausted(data);
        if (legacy) {
            if (listener == null) throw new IllegalArgumentException("Missing SEDC callback");
            // -101 means transient hardware-not-ready and causes an endless SDK
            // retry. -100 truthfully reports that this virtual device lacks TZ.
            callback(listener, code == 2 ? 1 : code == 3 ? 2 : 3);
            reply.writeNoException();
        } else {
            // The bound AIDL protocol is synchronous. Use its standard typed
            // service error, never an empty/fabricated credential or success.
            reply.writeException(unsupported());
        }
        return true;
    }

    static Object serviceManager(String method, Class<?>[] types, Object... args) throws Exception {
        return Class.forName("android.os.ServiceManager").getMethod(method, types).invoke(null, args);
    }

    static IBinder check(String name) throws Exception {
        return (IBinder) serviceManager("checkService", new Class<?>[]{String.class}, name);
    }

    static String context() throws Exception {
        return (String) Class.forName("android.os.SELinux").getMethod("getContext").invoke(null);
    }

    static boolean allowed(String target, String permission) throws Exception {
        return allowedFrom(context(), target, "service_manager", permission);
    }

    static boolean allowedFrom(String source, String target, String type, String permission) throws Exception {
        return ((Boolean) Class.forName("android.os.SELinux").getMethod("checkSELinuxAccess",
                String.class, String.class, String.class, String.class)
                .invoke(null, source, target, type, permission)).booleanValue();
    }

    static String property(String name) throws Exception {
        return (String) Class.forName("android.os.SystemProperties").getMethod("get", String.class)
                .invoke(null, name);
    }

    static void virtualHardware() throws Exception {
        if (!"1".equals(property("ro.kernel.qemu")) || !"1".equals(property("ro.boot.qemu"))
                || !"ranchu".equals(property("ro.hardware"))
                || !"ranchu".equals(property("ro.boot.hardware"))
                || !"arm64-v8a".equals(property("ro.product.cpu.abi"))
                || !new File("/sys/bus/virtio/devices").isDirectory()
                || check("vendor.xiaomi.hardware.aidl.mtdservice.IMTService/default") != null) {
            throw new IllegalStateException("Unsupported credential hardware capability");
        }
    }

    static String read(File file) throws Exception {
        try (FileInputStream input = new FileInputStream(file)) {
            ByteArrayOutputStream value = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024]; int count;
            while ((count = input.read(buffer)) >= 0) {
                if (value.size() + count > 4096) throw new IllegalArgumentException("Oversized SEDC lease");
                value.write(buffer, 0, count);
            }
            return new String(value.toByteArray(), "UTF-8").trim();
        }
    }

    static boolean probeName(String name) {
        return name != null && name.matches("hyperosavd\\.sedc\\.probe\\.[a-f0-9]{32}");
    }

    static IBinder register(String name) throws Exception {
        if (check(name) != null) throw new IllegalStateException("Existing credential service preserved");
        IBinder binder = new DeviceCredentialRuntime();
        serviceManager("addService", new Class<?>[]{String.class, IBinder.class},
                name, binder);
        if (check(name) != binder) throw new IllegalStateException("Credential service owner unconfirmed");
        return binder;
    }

    static String ownLease() throws Exception {
        String boot = read(new File("/proc/sys/kernel/random/boot_id"));
        String stat = read(new File("/proc/self/stat"));
        String pid = stat.substring(0, stat.indexOf(' '));
        String[] fields = stat.substring(stat.lastIndexOf(')') + 2).split(" +");
        if (!boot.matches("[a-f0-9-]{36}") || !pid.matches("[0-9]+") || fields.length < 20
                || !fields[19].matches("[0-9]+")) throw new IllegalStateException("Invalid daemon identity");
        return "1|" + boot + "|" + pid + "|" + fields[19];
    }

    static boolean live(File module, File lease, String expected) throws Exception {
        if (!module.isDirectory() || !module.getCanonicalFile().equals(module)
                || !lease.isFile() || Files.isSymbolicLink(lease.toPath())
                || !expected.equals(read(lease))) return false;
        for (String flag : new String[]{"disable", "remove"}) {
            File file = new File(module, flag);
            if (file.exists() || Files.isSymbolicLink(file.toPath())) return false;
        }
        for (File file : new File[]{new File(module, "features.disabled"),
                new File(lease.getParentFile(), "legacy-blocked.features")}) {
            if (Files.isSymbolicLink(file.toPath())) return false;
            if (!file.exists()) continue;
            if (!file.isFile()) return false;
            for (String row : read(file).split("\\n"))
                if (row.equals("device-credential") || row.equals("finddevice")) return false;
        }
        return true;
    }

    static boolean findDeviceHidden() throws Exception {
        Object manager = Class.forName("android.app.ActivityThread").getMethod("getPackageManager").invoke(null);
        return ((Boolean) Class.forName("android.content.pm.IPackageManager")
                .getMethod("getApplicationHiddenSettingAsUser", String.class, int.class)
                .invoke(manager, "com.xiaomi.finddevice", 0)).booleanValue();
    }

    static String hash(File file) throws Exception {
        if (!file.isFile() || Files.isSymbolicLink(file.toPath()))
            throw new IllegalStateException("Unsupported credential asset alias");
        try (FileInputStream input = new FileInputStream(file)) { return hash(input); }
    }

    static boolean productionLive(File module, File lease, String expected,
            String policyHash, IBinder binder) throws Exception {
        File pending = new File("/data/adb/modules_update/hyperos_avd_native_compat");
        if (pending.exists() || Files.isSymbolicLink(pending.toPath()) || !live(module, lease, expected)
                || !findDeviceHidden() || !policyHash.equals(hash(new File(lease.getParentFile(), "finddevice-policy/receipt.tsv")))) return false;
        String[] fields = expected.split("\\|", -1);
        return fields.length == 6 && fields[4].equals(hash(new File(fields[5])))
                && (binder == null || check(SERVICE) == binder);
    }

    static final class Result extends Binder {
        final int expected;
        final CountDownLatch arrived = new CountDownLatch(1);
        volatile boolean valid;
        Result(int expected) { this.expected = expected; }
        protected boolean onTransact(int code, Parcel data, Parcel reply, int flags) {
            data.enforceInterface(CALLBACK);
            valid = code == expected && data.readInt() == NOT_SUPPORTED;
            if (expected == 1) valid &= data.readString() == null;
            if (expected == 2) valid &= data.createByteArray() == null;
            exhausted(data);
            arrived.countDown(); return true;
        }
    }

    static void verify(IBinder binder, String descriptor, int code) throws Exception {
        Parcel request = Parcel.obtain(), reply = Parcel.obtain();
        Result listener = new Result(code == 2 ? 1 : code == 3 ? 2 : 3);
        try {
            request.writeInterfaceToken(descriptor);
            if (code != 1 && descriptor.equals(LEGACY)) request.writeStrongBinder(listener);
            if (code == 3) { request.writeInt(1); request.writeByteArray(new byte[]{1}); request.writeInt(0); }
            if (!binder.transact(code, request, reply, 0)) throw new IllegalStateException("Missing SEDC transaction");
            if (code == 1) {
                reply.readException();
                if (reply.readInt() != 0) throw new IllegalStateException("Unsupported service claimed support");
            } else if (descriptor.equals(LEGACY)) {
                reply.readException();
                if (!listener.arrived.await(2, TimeUnit.SECONDS) || !listener.valid)
                    throw new IllegalStateException("Missing truthful SEDC rejection");
            } else {
                try { reply.readException(); throw new IllegalStateException("Bound service claimed success"); }
                catch (RuntimeException error) {
                    if (!error.getClass().getName().equals("android.os.ServiceSpecificException")
                            || error.getClass().getField("errorCode").getInt(error) != NOT_SUPPORTED) throw error;
                }
            }
        } finally { request.recycle(); reply.recycle(); }
    }

    static String hash(InputStream input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[8192]; int count;
        while ((count = input.read(buffer)) >= 0) digest.update(buffer, 0, count);
        StringBuilder value = new StringBuilder();
        for (byte octet : digest.digest()) value.append(String.format("%02x", octet & 255));
        return value.toString();
    }

    static void verifyClient(IBinder binder, String apk) throws Exception {
        if (!(apk.matches("/product/app/AnalyticsCore/AnalyticsCore\\.apk")
                || apk.matches("/data/app/[A-Za-z0-9_+=~-]+/com\\.miui\\.analytics-[A-Za-z0-9_+=~-]+/base\\.apk")))
            throw new IllegalArgumentException("Unsupported probe client path");
        try (ZipFile archive = new ZipFile(apk);
                InputStream input = archive.getInputStream(archive.getEntry("classes.dex"))) {
            if (!CLIENT_DEX.equals(hash(input))) throw new IllegalStateException("Unknown probe client DEX");
        }
        Class<?> client = Class.forName("com.xiaomi.security.devicecredential.SecurityDeviceCredentialManager");
        if (!client.getClassLoader().toString().contains(apk))
            throw new IllegalStateException("Unexpected probe client class loader");
        Field service = client.getDeclaredField("sService"); service.setAccessible(true);
        Object previous = service.get(null); service.set(null, binder);
        try {
            if (((Boolean) client.getMethod("isThisDeviceSupported").invoke(null)).booleanValue())
                throw new IllegalStateException("Original SDK claimed credential support");
            String[] methods = {"getSecurityDeviceId", "sign", "forceReload"};
            for (String method : methods) {
                try {
                    if (method.equals("sign")) client.getMethod(method, int.class, byte[].class, boolean.class)
                            .invoke(null, 1, new byte[]{1}, false);
                    else client.getMethod(method).invoke(null);
                    throw new IllegalStateException("Original SDK returned credential success");
                } catch (InvocationTargetException wrapped) {
                    Throwable cause = wrapped.getCause();
                    if (!cause.getClass().getName().equals("com.xiaomi.security.devicecredential.SecurityDeviceCredentialManager$OperationFailedException")
                            || cause.getClass().getField("errorCode").getInt(cause) != NOT_SUPPORTED) throw wrapped;
                }
            }
        } finally { service.set(null, previous); }
    }

    public static void main(String[] args) throws Exception {
        int status = 0;
        try {
            if ((args.length == 1 || args.length == 2) && args[0].equals("--permissions")) {
                System.out.println("context=" + context() + " sedc_add="
                        + allowed("u:object_r:sedc_service:s0", "add") + " probe_add="
                        + allowed("u:object_r:default_android_service:s0", "add"));
                if (args.length == 2) {
                    String client = args[1];
                    if (!client.matches("u:r:[a-z0-9_]+:s0(?::c[0-9]+(?:,c[0-9]+)*)?"))
                        throw new IllegalArgumentException("Invalid client SELinux identity");
                    System.out.println("client_find=" + allowedFrom(client, "u:object_r:sedc_service:s0", "service_manager", "find")
                            + " client_call=" + allowedFrom(client, context(), "binder", "call")
                            + " client_transfer=" + allowedFrom(client, context(), "binder", "transfer")
                            + " server_call=" + allowedFrom(context(), client, "binder", "call")
                            + " server_transfer=" + allowedFrom(context(), client, "binder", "transfer"));
                }
                System.out.println("finddevice_hidden=" + findDeviceHidden());
            } else if (args.length == 3 && args[0].equals("--probe") && probeName(args[1])) {
                long duration = Long.parseLong(args[2]);
                if (duration < 100 || duration > 30000) throw new IllegalArgumentException("Invalid probe lifetime");
                if (!allowed("u:object_r:default_android_service:s0", "add"))
                    throw new SecurityException("Existing SELinux policy denies probe registration");
                register(args[1]);
                System.out.println("READY " + args[1] + " " + context());
                Thread.sleep(duration);
            } else if (args.length == 2 && args[0].equals("--check") && probeName(args[1])) {
                IBinder binder = check(args[1]);
                if (binder == null) throw new IllegalStateException("Probe service unavailable");
                for (String descriptor : new String[]{LEGACY, BOUND})
                    for (int code = 1; code <= 4; code++) verify(binder, descriptor, code);
                System.out.println("PASS 8 truthful unsupported transactions");
            } else if (args.length == 3 && args[0].equals("--check-client") && probeName(args[1])) {
                IBinder binder = check(args[1]);
                if (binder == null) throw new IllegalStateException("Probe service unavailable");
                verifyClient(binder, args[2]);
                System.out.println("PASS 4 original SDK capability/error paths");
            } else if (args.length == 3 && args[0].equals("--serve")) {
                File module = new File(args[1]).getCanonicalFile();
                File lease = new File(args[2]).getCanonicalFile();
                if (!module.getPath().equals("/data/adb/modules/hyperos_avd_native_compat")
                        || !lease.getPath().equals("/data/adb/hyperos-avd-core/credential-daemon.record"))
                    throw new IllegalArgumentException("Unsupported SEDC lifecycle owner");
                // The parent records the launched PID lifetime. Wait briefly
                // for that exclusive receipt before registering any service.
                for (int attempt = 0; attempt < 50 && !lease.exists()
                        && !Files.isSymbolicLink(lease.toPath()); attempt++) Thread.sleep(100);
                String identity = read(lease);
                String[] fields = identity.split("\\|", -1);
                if (fields.length != 6 || !identity.startsWith(ownLease() + "|")
                        || !fields[4].matches("[a-f0-9]{64}")
                        || !fields[5].equals(new File(module, "device-credential.jar").getPath()))
                    throw new IllegalStateException("Unowned SEDC daemon");
                String policyHash = hash(new File(lease.getParentFile(), "finddevice-policy/receipt.tsv"));
                if (!productionLive(module, lease, identity, policyHash, null))
                    throw new IllegalStateException("Credential policy owner unavailable");
                virtualHardware();
                if (!allowed("u:object_r:sedc_service:s0", "add"))
                    throw new SecurityException("Existing SELinux policy denies SEDC registration");
                IBinder binder = register(SERVICE);
                while (productionLive(module, lease, identity, policyHash, binder)) Thread.sleep(1000);
            } else throw new IllegalArgumentException("Unsupported SEDC helper arguments");
        } catch (Exception error) {
            System.err.println("Credential capability helper refused: " + error);
            status = 1;
        } finally {
            // Binder thread pools must not retain a task-owned probe or a daemon
            // after its owning module/lease is removed. No global service kill.
            System.exit(status);
        }
    }
}
'''.replace('@CLIENT_DEX_SHA256@', CLIENT_DEX_SHA256)

COMPILED_SOURCE_SHA256 = 'cb044650e654cc9b05392c45055f7c122d486581b6cec3b511a39c59d4f2c289'
JAR_SHA256 = 'e73e1a3979113fee129c4be5097264694f5e611641016fdf975dcb22c9248cea'
JAR_HEX = (
    "504b030414000000080000002100e6af9a699b230000484300000b000000636c61737365732e646578ad7c0b7c9c4791"
    "67f5370fcd4bd268245bf2588fd1e8e9c7e835922dd972225992b112397664d9896507339af9647df168469a19c9529e"
    "26c9da0e0b1ccb11c84260c341b8e436dc42708e1c97844036c042d885c07201c242800d0b1bb8b03c8e6503de7f75f7"
    "8c4671b8ddfbfd36ce7faababbbeeeeaeeeaaaea6f2425cc154f57b49f5e5d7ce8abb6df7fb3e6c8e4fb1e69bee3d783"
    "e92f56d60d7eee995fef1f215a20a295a3bd01d2ffadec251a11aabe0fb8c541f406d0434ea272d00fbb51075aeb2132"
    "405f2d25f24170b08ce8f976a26f03df057e06882d44654010d8020c027b8131603f700d701d700a58066e072e004f00"
    "3f01eab71225815b810f005f065e027e0cfc14f815f02ab0791b510bd00d1c036e033e0c3c0bfc04a8dd4e7410580656"
    "815b813703ef011e03be0afc1878197805f805f02fc025c01e217201a54000a8016a816ee00dc009e026e003c093c08b"
    "00754006380cdc097c18b808fc0df012f03b20d049b41db81298044e0377000f025f02be07fc13e0ec226a064680eb80"
    "0c700e782ff071e039e0a7406d37513f70103081bb803f079e055e022e011b7b88ba806b8114702bf011e02bc04b4020"
    "8a3d02ae024c601e58026e03ee071e021e011e033e0d3c0ffc1ea8e9258a0053c019e04f8127801f032ed84604e8027a"
    "817eb6156018780330014c02478163c09b0013b0801490036e06ee04ce016f07de097c08f824f02cf022f00af07bc0d8"
    "8135032a811aa019880283c03860027703ef071e03be03fc163076628f818d401dd0024481016004b80a782390045681"
    "f3c0db81078097811dfd3817c0b781f000f616e803ae04ae028e03b3400e380f7c00f808f017c0cf01db2e222fe00736"
    "03ad4007d00b5c015c0b5c0758c012f02ee041e0e3c093c0e7802f013f0368379107a8029a815e600898044e00b3c032"
    "7027f0c7c0bb813f031e013e037c11f82ef0f7c0efb88f41ec21d007ec05ae02a68145e036e03dc0fb810f010f039f04"
    "9e00be083c07fc1df003e0a7c06f00b1073e03a8055a810ea01718012680eb811b812c702bf047c07b8007804780cf02"
    "df00be07bc02882bb0e7c006a015d80ef40003c01030015c07248024b00c9c05de02bc03f824f03580ae840d001b805a"
    "a009d80e9c02d2c0adc0db817b80078047814f035f075e027e01388788dc00dc1fe1f892de0ec2b409aa921e862042c3"
    "00dc2dc10dd3283006ec23e56ff703e3c055c0d5c004700d70907d31702d30091c06a68023c051e03ae07ae018300d1c"
    "074e0037006f044e026f0262c00c1007128009cc02e780ff04fc29f05ee07dc07dc0fb49cd29ffdf164d2fb4116dd5fc"
    "3b8af87bc1c32d114209dd0f1eee876cbaad4ff3f97abbae67beac48c60f3c08191c0fe200f5312d5f55245355d4cf06"
    "5d0f97449bb46e2cb359ebb653f38f81efd7fc534532cfea7e6a8bf4a92feab35ef7d9abf9afeb67997fa188ff61117f"
    "bf1e97f997757d83d627cfdfafe7d85034c770d11c9b805f6af9e6a23e5b8157b57c7b91fc162dc3fc76cdf3be766899"
    "f39ae7b95cd0bc1d1ddcad791ff8b768be0afc5b355f0bfe6d9a6f2e92ef2ae2791df2f2fd45f54345fdec2faabfbf48"
    "fe5051fdf5e0dfae795e937c3ddbd51f6bfe4d457d268b9ecdb52b1beed4f37d87e66f41fd9f68fe02f87769fe1de0df"
    "adf9fbc0bf53f30f17f1bc5f799e75fecf9abf08997b34ff7891fc17dad5be7415ed4baf7e7687e6bf02192f4eccc788"
    "29d1df4ada493d38343e580cdb21d37a4d1b34ed911439832e2f6a7a86f89c54d12ab1fd2b1aa20afa8aa64ef4bb0dff"
    "968873b71669f3063c9443f079dc455b059fc551fa1ca933f9794dbf206937fdb5a4256497722d542e54bb5fd22aaa90"
    "d44101dd5e29692b8524eda35d9276d26e5d3f2854bf7bb4fc15ba7ca5a4ed3404ea4079b35c97564d95be3eadbf0f5e"
    "f42392eea5ff2ae9167a545227fd0f49abe86949b7d373920ed0f39256d32f24add174907e2f693f5d92343f4e159548"
    "3a441e49f79057d24de413aa9f32a1c6ab92b4826a25ada42e49b7d10e49b7d24ead773f68a9d61fe93385657994da24"
    "dd410382fd60876c2fd3f32f43d4f81b4907e86b92bae8454d5f91b48a7eaedb7fa3e93f4b1aa676c1b97b44f6538e71"
    "ff97a436a9b75f97fdba5c81f1dc82ed68803e21edc943bd82fdac8f5e607f000d7f286903fdbda421fa91a63f96b491"
    "7e2a6915fd0cb45aeb5f53a03d926e8266dc6f103bed12ec7fbdf403625a455b50aed3f2f5f0748a5e419f9554ad433d"
    "9efc3b4905fd5ad357251d9241a71ed1b459d27d9a0e518ba41ba855d28d9a56d176c1be57ed47033effbba4b59ad669"
    "aaf40ac10ebf8e7223b55193603f1da507887d74806c82fd73397d97981af4b2a45d542feb7ba901b405237e9fd877fb"
    "e9ff82b621faff96d8678fd297246da27f947407750b8ea7caeeb7228bf8b8a42df40c6844af4f44ef5f0423fc83a46e"
    "fa89f6277e5277342215371e43c2f1f2902ab3ffa8784dfb173821019600274e1eb7255b546e12b47f86522127b49d84"
    "99071c017f74af8f527e37ecc66354daefbb14dd6b2761b41b62f244c0a0493881a8e1a723e0537e0fa47cf6013b24ec"
    "90987a746f5e26d01cdd5ba6a56c5aca46c2f1a8ec65d15f8fba2904ff94ff0cf42987b51852afb32d2a5758f0f31cc2"
    "589740c5426809733e1e42f683ad2983ac9079c68516951b04fc4db0be80a835eae98041a2d91fe5116d41f1182d766d"
    "2361f3d91a6c36aab0b1df51cfbead45e50a8bfe5af4c7de633b46f361dc1aeeb1b1a9023d1ab536f468134620508be7"
    "996b0e4559de08da3e2cfbae34740ff628e65741617b0d2c384c0ba16b50db6657e5b64299e7c9bef57d2d6a2f176187"
    "bc6b41512716878214eaf618e5580817a458ee832d2a4709d27f83aefba46c60f872ed34172e703d792e687c92525d57"
    "c35bfba879284a53cb3e7bc091ea5aa043769fbdc11ec01e8c622c8fbddccef6a172b88fb6a8fc35480fae8d2b9a023d"
    "14b4fd1fd95f97811aa3a9324adc57c88639180f495903eb13686a8af650ad1d3ad86d225035e3f0d20187cd1eb47f4f"
    "3ebdd7e6c3ca1dc26ef844d0f638f1ba5682e7be0c68da404a2fdc78e4fb09b634d6eb71e8c5fe3fe5df8d88e5814efd"
    "88b3297f3f4ab0dbd00e5a406d3f6247ca3f885564fe7ef07bc0fba0dda2ec6b0079c1a27f8bac4b85aec3d9f2b807dc"
    "769cceb750d0fd2c66bd4134877a51ef730b7f20dc1782bf31dc14b695d142572f658d947fa73c2103380bdc3beccde0"
    "de0dd4f51b366ab7231a89f61f948ba62dddb08732acdb37e4b30bb603f0c4e192323c37c01ab882f43bd9729e023507"
    "4adc2e51ddd73606ffe62ee19eb1f236ee19a3d9fa6185e582c7c62c6c0328b547789ef952b9e059497bb261d6a113f0"
    "523e6ab489aabede4db4cf41f6a0f3afe48c4df238079cd0caf9cd7cd9d1ef907adbeda2fdc7e5e2f99212d1fe78b9ab"
    "5cb8716af8dc7cbf45e55c55b46fea9a9341f124050251878bfa4b1ce8a31231a1dce86db99502433b1dbc962b6849d1"
    "a3ed03aed398ab03b6e57171e4617fb3118bd3ee2d15a9502972d8a0eb09597b8e842bdae293fec1896702d8d554c88f"
    "cf72a3df05deef45bd8fda8d0005baa31b36494fe5943ec6a9795ea5528a36612eeeb0a31a33dc86d37700336c73a87e"
    "fb5d9b61151514688d9af0258dedf6e806f8a6d8626833f9f5a8ed7ef5eca9b56765ceed73a442e5b88d951baa7db9d0"
    "9ebe5ee06c791ce58e903c438284a86b813b927eadb455f9b57ed876907e85591d478b47f40b3b3c1ce623ca850babcc"
    "365e09598bf307b61a518911faa45e72d745c0181027485b4691454fc21f8569c4c1f39f805f699056d16fdb27ad966d"
    "8dbd5490be256d6d044f86a497e4dddf91b7a6cea0ed8314f865aaeb06eab3fb6c8dbd01333a851838bacf6eb3871d65"
    "1438bacf6673b2467db20787eea1578e55861df7c0f68460afc8bd47b3985fa01d4b502efd9a5d9fe3adad2a8e05e9cf"
    "0bfe85fd82dff06186ec051a6d3e5121ec7a2dbb5bf37ef0e1357f24bdf48ce1a580ed80216cecff0395cca542fbd13b"
    "723571dfa58297319aa49769642f13ba51b673365081cc272ce0a58d1bb132073903102a766e917bb871ab5dfbc4c156"
    "75ff5ce78bb54f7ca9d82756689f28fd58bd8ec74246b8a156758fe0532ba4776a927b29d6ede526ec7d39f6fd0a68b9"
    "e86fe49170eaf9fd428528d55cbba3145664e1c93621f5a73b649411527f8e8b1c27eba5ee368c5c27ef9e4ed4f17c26"
    "5ad53b8b204ee9a23f2be782bc3ed454d1855ef7e2798f11b0ed3270aa8672e46f6aff75d8d180e838831d4ff93352be"
    "51f4550669bf41b6bf0d5f225e67f6fc1c7d9906ed2e5a0c5d8f0cc467a44209e433cfdb6ca2fd4729ff2c5b8da3c291"
    "8f35c7a0cb1d057bdfa8ed3defc9c202b5c60659db286b79372b8d10f43c861ad633d5f526ea367c46a56d0b6aa79143"
    "796c180de39e04cf1146486fa8f80fc8d3d7252d76187b77af2cf72002f6db07a8b1aad25145bd53bd5469af84cf1476"
    "6eed93d25b7196d42ad828e80812cfebb03c0109b676f4352c98ef92712581ac52512eef13dc5342da1daf81ba538491"
    "39074544ee9c1f79423e3f39ddca3929efcf47d76cad627ddc0f1adf5d8bec7e9997d8033282fa656487e5d9d57e1b94"
    "6b55ef9ff2767588c2b09f057f1746c4bedbd5be0f41078fb1cba88186dd68f1d83ed6546927ff8e91129cb114b2870d"
    "4ded3f959e4fa4a4e7db00cf1716f590ef91bb1a346ec2293a42d72242c678a71cda6e1da58ef576ebc0939c8ff19d59"
    "485b5476ba47be3b13f21fd1b9567517e57c903da813129cc1bea555bd7bebb7f7c2d795e81c8a73d90acc81cf3dc70d"
    "3fd62c604437a8f814a24053b48ff932f0996b0d9a0af19e73e4f0c9dec37607f6f576cc6c034d215b2bb5ab16cee330"
    "67878a06dcc2b6bb99cf1a71aec6ba7652ded7bfbf557da792f2dba58f1f1036ee5ba007ba59f620f49d50c8c8fa61c8"
    "5f3278afb789a0b8086b7f047e2c606f7c26e88c8860498708ba3e44812d3dd0bdf199e83ddf8355c2937bca64e47e40"
    "46ee6fd00cd635ec51d6091fecfd4b69799f229f47e798de7c39e875acb5853621eff0a0cdd46df6756de7902770db8d"
    "e473b2d53a99864610f158935b699f0f79b6a353f01939213539ad34712a4d9c88ed9f923d9ec39341579d08baff3771"
    "a67bcbbd9e12ee7999eb4b0c29c3bcd6b644ca048a656caf2f6314cb385f57e6f3018f60998d7cfe9d255226065ecb38"
    "59e67386c7c7329f219f8f67ea638a993ec379848ff76ebbdc3b1fb5f9667c9821a91962dfc4b7297fb275dc95a3159f"
    "74ee89df613c211a9fda281214e88b1e4a22c7e37d2c97fb78bf8c06335c877caf5546827e9ae6b27bd1cfef85bd6ebe"
    "c3efa2fd9847d712789c80bda47709b2bdfa597e573b23a39ad250c0a2b252438e7dbc63ccf33c83b042e66bc1ebb510"
    "f972f11a3c8551e6e821e87f8308fbeab016ad588b29b9166a6d3a0a6bd3f854605fd093a1e83b46d5fcbc2ac7fe98d4"
    "71d76be6d7232d88b3051eabdfd78cbe9ec48a3e419c7ff30a8ae1be3ff123fb4628eedb6122a6744568bbe3798743b4"
    "fff3f34288f69ff36e0491f7e7d7d80b1d6ba4477d58ea133dd4a535292dd2a4f5359ad4ebb27a3bd78fb1a1997b31d4"
    "81d9ab11d28511be45af1de1576a04875f8e7048f6f88f32a2e1acda38761d92b71419d1904771df5cfb8cac75c8f5de"
    "25f3cba03b20fbb8479e267834d4fb647d4551fda324c62add3dd4774f8dcc0c7df2061390b9844f5acca2bed5b8e4de"
    "35925cb11f71fcf4c96c0879deaf38cf6b74f88cc6968015bde74e5a8bf18b88d7d0c6cdd6708f1c5d45b67ba4475711"
    "3c157a235d2bb599c52c0d67d0f9673292aabbc4090a1cd967180e9e6dd0f94599753a9c3c1bf5ec75c858f9aeb49fc2"
    "86ca4fe52c9d2a3f9d747276296f928ec5236df45423f7b9157a71f6a4bd166a36c12b73b6b955f6aa259dfd4e176d74"
    "fe838d67be4cedbfe27bfe297ef7b85f596f4b91f572e6d428f772ad7c5b5199adfbcd05eb56e5b38572a9af3d54ea9b"
    "9179cada690b154e5b2a14bfcca33c454a1f9b8c394ab3361fc71115f7f83b914921c812fc9dbda0470cfe1e40d0770c"
    "7ecf5642c6ed1b5f707ccb41f85fde8b39860411883e25df27a858a8a90873761c0d54055aa2c7108dc6da1dd101e4f9"
    "86e85b086dc40e70bc3c8b357c927ac6bdd2beae275e3f8e10fcee2fe08c0e94cb3bd810358d74d141bbcdc9f1b34bd6"
    "bd8932470d7a8fdf53c237bde87815f691a321dfc410f94a06e0b3db8f854bb0a6ae3f926b7a9eda4af42878a65ecb4f"
    "41fb1957196db4210e0c2dd3cebbb8b5848eb419b851a08f9daa0f6bad0ff99caaad2bd496a27e92df04b852fe0975b7"
    "763f2c67752fee9e7cefcbb707dd5f45fd55a8876c28892cd8e3aa74df77297aaf5b6703fcc96f9bda4ad42873eb4659"
    "93682ba9d17714f6fc474073ecabb1a76749bdbf7c08d42d738347c4edb5b73fc2794d294a36480d63e6dbe4fbd246c4"
    "fe6a797e6a65ce50092f585528f70b799ff5c2fa7c7749ebfb12b579c332735c8185058dff09d99bd8e690f5de2c69d0"
    "f665797bc029b2f31a8cc81cf69bd46f700e3f4cfc6e6e95ed557c5ae69842de32dec014d9db6179fa52a1a3f459f2c0"
    "333f8a9137c39ec7a53d0702a9500a11115961e834e21046e89aa7416fd0fb2f1470341ded9199e9c79d3e6fd351751b"
    "da0dbec1abdeea7891710c786f4796f24ff00ddfa1669c782fdac5d1c0cebee534ed73799dacb10b1eacdfbd859acee0"
    "9ee7f6d2017789a3d6ddc5d498717b28b0159c87477a730922bdba81b89ab6c04e0d376efb63ec153ccd5d51bad7837d"
    "86163b5dedbea6eb9476fc4cd3f54abb9d2eb5cbf3eb7639ad6d69926dc9cd36c56f84829ea7a44d3d24b5aba67c7bd0"
    "a36cea21e937937477c1a61cf4bcd329dadf09bbe555b2231bf4b29f49cad1bcd8c952af6ac19e728bef16d922f75896"
    "6f2d944bbdfd8647ef1f72691fe7d2aa5eed66719dba437850bb5552bb7ce7c9b6cadf0db76076fcddda105abec87772"
    "947f23f3d9122a15ea1d648dfc0ec94f7542dd27c3b25c89bcee8306dd63d059e3f696bf12670dbacfa08f18eabd3363"
    "b94d7d1f1da44df0ceed3a3fdf24d74ddd7b27d0565d685bab1f427d4dd133fc8e28df869b366d7c9d675a511f2c7ae6"
    "2f8ada6af4bdb2a6f01e65b78ef85e3cd527f2117f8064962eef637716ee632fc8371054362d2acb45a05c54940fd2b7"
    "e093cb062ed01cbb87f772c19a161bfd562d2ee006bbf49c7a46b4f93f4e4fa1596ce4672d51e5a38f0ae9f5d1cfa5a7"
    "5f9c1615be3d0dcf7de6f8c595954ba2a274d0b8a96ec4c8d6d14ed5c1f9e986951357d71f6caf1f9c6e880c0e0e369c"
    "c7c7d55f1b8c745edcf7f655e386babbe8dd3c3efdb570c85716652ba2ba5cd496af88cde58f6ca6840a315800567f63"
    "69081657469fe74784df2faa4be99254ffea8bd3a2a19c3e04fee2c58b3ccf4d50b7bd946e62c99af2657a0bcb4d4f5f"
    "6dbdfbfabb5fd965acd6c106ca680b4f3732313dbd629d1e0c5e30968fb1a19459b5f4a0017a23ba81222f3e75c560e4"
    "0206e08ee5ffbf1d7f9ba82f47c7d603374e8bf6f2c1f6bbdecaa5c873efdab3d29e141bc04eaf6c39fddcc58b4f7fae"
    "7edcba74f58a6829bff4915756076fb49e6e3696afbaf34e63f99c5179ee6dc64ddbebf168e360fde6417a49adee794c"
    "6ef0b94b5664f0156b104b7de162fd2511a8b03619b93aa3fc1c5d3058ef07de7d7efa81a7cf5bdf7fe082a8f69f97ca"
    "56955f3c5f7ff525e38c08948d86068dc53aa3ec9c317fec8ebbe876ac44b0fcc5a759b9bbf92b1ad2af8924ddac69fe"
    "6723ea35ddae69a73e179b292ae33e7fdb1bd56d515afbbe46907a4fc834ff3d4f3d24b8dc5328f7c8721e365dbf46eb"
    "256fd33fe5c03276dd56262312e10691d767b3ee332cebc3ba9ffcf7db86e4d533bd94ff990e7ba13f41db741e532647"
    "731478a5033f5759d0bb5e3e57afff715b7ba10db248f842dba834144f5a662a77321e4b26f75045be98cbc452d95933"
    "b387bca1854c7ac63c194b24f6902794351371c59782cf2c9b99c2a3bab8f6a8bda5ab6785443bff10a37deb15bb8f53"
    "4924129f33e3a761c88a89a8f1a83412593033f356366ba553599693a33223bba5686722968b75c612339d73ab104d67"
    "23b1e544249ece989df18c994027562c1949c4ccf974aa2363a22141dbd61e9a4f2796926636fff0493c7c3215cb59cb"
    "e6c9787a7e2196a39ecb844f2e2da0cafc7f3c33a19f5958e83c3e1c998e456eea8a0c9cdcb6e7b6c80ddb3a2173a263"
    "de5ab24e74c452b1e46ace8a6723978bcdc4b22624164e537927261defcc9ac9d9ce6c0edd37e88ad56ce76933933293"
    "9d58db447abe73269dce9db412146181c4523c275518ce8f32c2abb2aea406a8965dcd2c653b97ad4cce4a7726cc652b"
    "6e66497493d17d0b3907ad9495bb821c7b0f1eb96694eaf6a6975209b9af908269c4ac7913e5a5389ec9926b64786262"
    "eff0c8d5e41999181fbb66eae4e8d8f5d43a52d88d503cb6109bb192566e35346726b188a18c39bb0413da154282bb26"
    "b7904e5af1d550fa4c0a224ba9d872cc4ac6669226351709e5d5c84bc5d3a9592b0385a875d4540aae09cfc5328933b1"
    "8cb9aeb75a25b7d6e7e412c8bcd9712364a86b6cc5cae6acd4a9d0e1b1092bb5b492570bc2969945ede808f43f05a10c"
    "8c209da2ee7fe30969c2eb1f69293c12bf7c660b19531a7b82c43819e38c09aa1a4f2dc79256428d8f8d4f9ab11435e4"
    "6bd5f9292860c93e73ab549d17502762ad6163be416997b4664d5e0312579171d5048909724e8cbd6178e4181913e364"
    "9b60352626c0c81238fb047f1a13d35439016bcca4ad44673adbb9d74a25cccc6eaa2aae1ccfd7ae133d14cbc4cde46e"
    "aa2dae9c849a39736c256e2ef04aeda6f04422965cb64e77c652a9744e2e5fe7582a9e4c67b17c23c95836bb9bea5f47"
    "663c05fbd0ed8dafd37ec09c9fd1022644ea5e47e4b0750ae77c2963eea6e0eb344fcd65d267f068df048ed0292b37b7"
    "54704a70119d7fc0ca9a27cdec5232b79b3afebf1edb4d0d136c9f9d7868ef6ace1cce6462ab0797720b4bb9c3b98c19"
    "9bdf4d6505817d56120f6c5a571e4f15896e2834fd81ea43192b55a8ae54d5c958ea54e75e6579bba9a6a87204e7ecb0"
    "b9b864a6e218b7a2b8456dc065558354fddaaa89744cdac886a286223b682eaa1e4f26cd53b1e470e6d4d23c56a948aa"
    "f172a9c3d8ae62832a9ecd782a679ee241fd459513e9d4a9dd1428aa393873a319cfb1a5aed5e97d29eab8aea8f5b019"
    "5fcae09c153517778895b578904d97d5ed5db2927219d689af6673e6fcfa3a589f194bac5f2e6991ece30ad622abe16d"
    "93d0bf730431359741984867d60f9d17d86799497419799d26b88b745cdafd542c73ca2c5ef3e0eb881f307373e935ed"
    "5230a95918a1b4c42c7b87f5d58762b9b9c20266f5daa1936c3676ca1cb54e9959ac7e8b6a5eca594904d5148432d87c"
    "cc0a3b318a703011cbc5e70a337fadd81436eb08c25ac172a5c04dd642e7b4b53096ca655677e76db2b8451da50d0738"
    "25911e1ede97339d9918d2979a75d532e389c5a5836fc8b760bd7373b34bc97cdc60436281cd05011cfdb5e06a6632e9"
    "0c955e7370eae4e123870e1d9c9c1a1ba5b68319eb9485381e3a3c7a7521fe16478ea58585742647edeb0433267c57ea"
    "b5922a68571d448e96b56e327540c199ce9ab4f5d0f0e1c3a1de507add7885e8dd29b50b21e399cb52bb94ed5f9be052"
    "4aab813e8b96224bbe439307f78e9d3c3439b66ffc7ada7448069cfc848b03b373726c78f4580854ba482a393c3672f0"
    "9ad1c3945f3c78986c2e34bf840fee62351587c1a7d24b59169d3c3a3e320666ff70a4a76f07d9a78e1d1a23c791a97d"
    "917eaa3e92325716b0f4f9f92ec45693f037d45cd4a022a18ea4717649a1a4f449547324753a050b5b2fc2694ee511ae"
    "cff7aa822cb51c295a8a7516b3ce461a2f13d3d9514cfbb52c852e13e1401d5f8d27750244e16289a28de6b0960b21c2"
    "c7b2b4f50fc814b2a3b52da6ba62d975d3e56da7a6e2e6cb33426586e2281947912f1c452e711439c351e40cf6a39c42"
    "809d6076825ba7494c93637a5ca614d3483a8c69084fb3c434e7168e6999623825414a729c9cc79130dfb08d8ce37ba9"
    "fcf86bc25de0f8e571a7f2f8eb78f17595794f5c7a3c169945ef911b6e8eeeb8957cba78c3cd3b7a6f25e3440ab885bc"
    "31797af62563a7b264c3f5873cf838ac96814a99c712207d436e4b25d8f3f419305ecdeccba4e729a8731d24e20b1dc3"
    "308465acbaf2e514ceb7c16de5b0e41d0bf31de3876036708207707740a4a2405e269dedd0d91e6d2aae53cae4c59b2e"
    "6f3a0c73b766ad78c183d3e66221196a704661883964afe484a2662a41ee58667e476f64b93f8699653216e7a78ed899"
    "989523e78c4cefc8a7d3d2a3b1e4924976367a72159ca5435df9029268d5879537f2a93abd8edeb84aca3a12e60a9ad4"
    "4d741643ec411fc8fb4cda803b55c78a154bcf5b1ddca0ee2f3456549d0f221daa6dcdea3bc6f3b1f9b599567ecdf6ff"
    "8774d3b1dc4da3ffae9efe2d7d6ef88fe8a5f9203654c6ef7d70b766626df7ff7dab06c98c4ccd793fb1e65676ce4c24"
    "718931533cd72e6c348c3666f1ad5d9aef4a4e5581d943ee783e4853393a454256c861c9cd77e7610e02e463f610327b"
    "a958855222b2a6056db8ac0a97b60c39133245a0928495959164c8eceaefddb13316ef8a46bb77f40ff4f5f6cd76f50d"
    "985d033d7dbd3097bedefe445f5fb739bbd34cf4f7cdf477f50f447be3f1d84cdfce5e7367f7c000f9cdd46c1af713ce"
    "1033b331589713e12796c4b9471424b70c8523e9840976652e869084f3e034f95a97253b28a69f8f2c54316bca7b044c"
    "5a2998203bdb2df9f953edd87e0b7aa5c85364cf756b7c445d29915fc54d6b21d791cb2e5360adf9e49c7c7a0f9540e9"
    "6b62b8c779a5f693a68c724e14e66339b22171a3467c0c2f2ca03b690e6adcc3668eafa3c3d92370eae487c8482c954e"
    "4126c9de955cb2067776c5f101a5b23ca73277555e4b31c9a3cad214b8c75113071b1b27b34cd98f4cbb24a7eab887a2"
    "0b097965399b8ba578fd6521476e50955e52095839db0a30af7194a5b28a533f398112594404ab04b3feac8c6337e662"
    "d939dab8760debe0175c1d32fe7550cb5afd09d97042b59ce828448968cfad54c25e70e5e02c392d24cba7b1075676d4"
    "c28e6131565199958a9459d9c3abf333bc9d7081a76983959d9a83a054e5703eb692170b8be9aa0eabf922135f8dcc24"
    "d3f1d366a2236f4e644fc20f937d1ee78e4ae639ff45a59b5f36493dc99e92b69032cfac2d637a868f297990c9eb6484"
    "6ce925982ba7d0320d742fc4325993af4154b2c017c1640a753c63b9d865fa65138c678287772da8688139a2c3f8dc12"
    "d965382be5cf353f53c245de400f332aee925ff3184bbd23603199df904bbd314195933d0f06f267d21dfccaab239fb8"
    "902f5fb368ce2f9117a54253190aea6d996a0ca0ac15ef882f2c7520e12157361f73cab2ebe366b92e9f9cd71536a453"
    "548a0f15b22cf63210ca8d167b2c7bd63a253f6f32c9914d9ae602084e1ae68cd5cfe4b2d7e1ba4feeecd24c564ddf9b"
    "4baf3942672e2d2dd4954bebd571e5d345cdcd42113b9ae6a96569575aa6332733bb12e66c0ce9f2491dc54f6ad57765"
    "bb285824265fd916b56d5bda95d9755cbf84bc611baadaafdcb52bae522cb0db35bb65eb962bc95b94dd9353bd102587"
    "7c832409e27d8924b0d68165e40be94c3ea6e477a4236625921df3b984d6a163fcc0945efe4e3d0572e25662cdae924f"
    "d111f556b89c5f53c2f7eecfefade30c4e2f364d92b50554e5358b73c9329b5c659e53be7c0aa733457e59794d7aed01"
    "afacd18b5f912facd9a6b885ee13b7dd36da7f7398531a4c33bc2b8c231ade1ee637c1b8c6703791798405d930b3740a"
    "4df02dea2d7776693e1bde358b20626e0fcf5ba9486cc10aefead9b13d9c9d8b45baf108a256ac7fa0bb6747cc44b8da"
    "11ef1b18e8ee8d2666fb76c676f4f5eee8dd119bede98f7647d1abbcbfa5537868a0a3a7a33782401046a65a62fc1761"
    "afb9c3a8ce194ef109a3c66778406a458d23cf6c34dcccb8aaddd5d755bfa7fa40b5b77aaada533d65b854bb976c4290"
    "5ff8c5d0c6b367ed5fafabb63f5e5b42d5c256238afed5bcf9acfd87ddc2f5788370fd107815fcd97ae17a65ab70dd1b"
    "15ae1742c275711bdab70bd72f1b85fb0b51c3f58588703ddc265ccf032f7482ef427bbdb8201edf225c2f036f1d12ae"
    "bf1c11aefbc69bedaf3497543f51fd99ea2f573f69bfaffa973b85d0df5b7c6288e8c121f53dc7a78654ddb3a04febba"
    "3cfd01e885615af7dfc77439ff7baffcb3c50f0ef377a68af2774aef1a56bfb7cae53a4d1b340d69daa86958d3264d9b"
    "f5f32dbadca669bba65b34ddaae936d0fb86f9778d54b943d34e4d2b8abea3cad3fcdf94e079e7ffae047fef93ffdb12"
    "fc7d4ffeef4bf07743f9bf31e1a4b5bf3321426acefcb7266c9ae7df4f127ef5bbb0fcfbac46488dc57f8bc21e52cff3"
    "baf322703ffcfb4ffc83f7ac13ff9e93cdafc6e335776a19fe3d29fe528d65f8ef61fc2b504b01021403140000000800"
    "00002100e6af9a699b230000484300000b0000000000000000000000800100000000636c61737365732e646578504b05"
    "06000000000100010039000000c42300000000"
)


def compile_assets(sdk, work):
    """Build an audited asset during maintenance, never in offline consumers."""
    from patch_gnss import java
    sdk, work = Path(sdk), Path(work)
    package = work / 'src/io/github/hyperosavd'
    package.mkdir(parents=True, exist_ok=True)
    source = package / 'DeviceCredentialRuntime.java'
    source.write_text(JAVA_SOURCE)
    revision = hashlib.sha256(JAVA_SOURCE.encode()).hexdigest()[:16]
    classes, dex = work / 'classes' / revision, work / 'dex' / revision
    classes.mkdir(parents=True, exist_ok=True)
    dex.mkdir(parents=True, exist_ok=True)
    jdk = Path(java()).parent.parent
    android = sdk / 'platforms/android-36/android.jar'
    environment = {**os.environ, 'JAVA_HOME': str(jdk)}
    subprocess.run([str(jdk / 'bin/javac'), '-source', '8', '-target', '8',
                    '-classpath', str(android), '-d', str(classes), str(source)],
                   check=True, capture_output=True, env=environment)
    compiled = sorted(classes.glob('io/github/hyperosavd/DeviceCredentialRuntime*.class'))
    subprocess.run([str(sdk / 'build-tools/37.0.0/d8'), '--min-api', '26',
                    '--lib', str(android), '--output', str(dex), *map(str, compiled)],
                   check=True, capture_output=True, env=environment)
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as archive:
        entry = zipfile.ZipInfo('classes.dex', (1980, 1, 1, 0, 0, 0))
        entry.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(entry, (dex / 'classes.dex').read_bytes())
    return output.getvalue()


def files():
    """Decode the exact audited runtime without a JDK, NDK, or donor cache."""
    from finddevice_policy import SIGNER_HEX_SHA256, SIGNER_BYTES
    if hashlib.sha256(JAVA_SOURCE.encode()).hexdigest() != COMPILED_SOURCE_SHA256:
        raise RuntimeError('Credential source changed; rebuild its audited DEX.')
    jar = bytes.fromhex(JAR_HEX)
    if hashlib.sha256(jar).hexdigest() != JAR_SHA256:
        raise RuntimeError('Credential DEX asset changed.')
    rows = ('schema|1', 'class|' + CLASS, 'jar|device-credential.jar|' + JAR_SHA256,
            'client-dex|' + CLIENT_DEX_SHA256,
            'client-signer|' + SIGNER_HEX_SHA256 + '|' + str(SIGNER_BYTES * 2), 'service|miui.sedc',
            'legacy|com.xiaomi.security.devicecredential.ISecurityDeviceCredentialManager.v1',
            'bound|com.xiaomi.security.devicecredential.ISecurityDeviceCredentialManager',
            'callback|com.xiaomi.security.devicecredential.ionremotecallfinishedlistener.v0',
            'unsupported|-100')
    return {'device-credential.jar': jar,
            'device-credential.tsv': ('\n'.join(rows) + '\n').encode()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    args = parser.parse_args()
    jar = compile_assets(args.sdk, args.work)
    path = Path(__file__)
    text = path.read_text()
    start, end = text.index('COMPILED_SOURCE_SHA256 = '), text.index('\n\ndef compile_assets')
    asset = ("COMPILED_SOURCE_SHA256 = '" + hashlib.sha256(JAVA_SOURCE.encode()).hexdigest() + "'\n"
             + "JAR_SHA256 = '" + hashlib.sha256(jar).hexdigest() + "'\nJAR_HEX = (\n"
             + ''.join('    "' + jar.hex()[i:i + 96] + '"\n' for i in range(0, len(jar.hex()), 96))
             + ')\n')
    path.write_text(text[:start] + asset + text[end:])
    print('Credential source/DEX rebuilt: ' + hashlib.sha256(jar).hexdigest())


if __name__ == '__main__':
    main()
