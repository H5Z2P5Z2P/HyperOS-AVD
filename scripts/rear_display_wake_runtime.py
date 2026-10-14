"""Current Core-owned rear wake helper; the baked v2 recipe remains immutable.

Consumers decode the audited DEX without a Java toolchain. Source/DEX identity
must be regenerated together with --sdk/--work after changing JAVA_SOURCE.
"""
import argparse
import hashlib
from pathlib import Path

from rear_display_wake import CLASS, compile_assets

JAVA_SOURCE = r'''package io.github.hyperosavd;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class RearDisplayWake {
    static final String UNIQUE_ID = "local:4619827551948147201";
    static final String INPUT_NAME = "virtio_input_multi_touch_7";
    static final int DISPLAY_ID = 1;
    static final int GROUP_ID = 1;
    // Match the audited OEM sleep detector in physical panel pixels.
    static final long DOUBLE_TAP_MS = 400;
    static final double TAP_DISTANCE = 100.0;
    static final double AXIS_MAX = 32767.0;
    static final double PANEL_WIDTH = 912.0, PANEL_HEIGHT = 596.0;

    static final class Snapshot {
        final int state;
        final long asleepSince;
        Snapshot(String uniqueId, int displayId, int groupId, int state) {
            this(uniqueId, displayId, groupId, state, Long.MIN_VALUE);
        }
        Snapshot(String uniqueId, int displayId, int groupId, int state, long asleepSince) {
            if (!UNIQUE_ID.equals(uniqueId) || displayId != DISPLAY_ID || groupId != GROUP_ID) {
                throw new IllegalStateException("Rear display identity/group changed");
            }
            this.state = state;
            this.asleepSince = asleepSince;
        }
        boolean asleep() { return state == 1 || state == 3 || state == 4; }
    }

    interface DisplayState { Snapshot snapshot() throws Exception; }
    interface Wake { void run() throws Exception; }

    static final class DisplayBinder implements DisplayState {
        final Object manager;
        final Method getInfo, uptimeMillis;
        Snapshot observed;
        volatile Exception failure;
        DisplayBinder() throws Exception {
            Object binder = Class.forName("android.os.ServiceManager")
                    .getMethod("getService", String.class).invoke(null, "display");
            if (binder == null) throw new IllegalStateException("Display service unavailable");
            manager = Class.forName("android.hardware.display.IDisplayManager$Stub")
                    .getMethod("asInterface", Class.forName("android.os.IBinder"))
                    .invoke(null, binder);
            getInfo = Class.forName("android.hardware.display.IDisplayManager")
                    .getMethod("getDisplayInfo", int.class);
            uptimeMillis = Class.forName("android.os.SystemClock").getMethod("uptimeMillis");
        }
        static Snapshot observe(Snapshot previous, Snapshot current, long uptime) {
            long since = previous != null && previous.asleep() && current.asleep()
                    ? previous.asleepSince : uptime;
            return new Snapshot(UNIQUE_ID, DISPLAY_ID, GROUP_ID, current.state,
                    current.asleep() ? since : Long.MAX_VALUE);
        }
        public synchronized Snapshot snapshot() throws Exception {
            if (failure != null) throw new IllegalStateException("Rear display observer failed", failure);
            Object info = getInfo.invoke(manager, DISPLAY_ID);
            if (info == null) throw new IllegalStateException("Rear display unavailable");
            Class<?> type = Class.forName("android.view.DisplayInfo");
            Snapshot current = new Snapshot((String) type.getField("uniqueId").get(info),
                    type.getField("displayId").getInt(info),
                    type.getField("displayGroupId").getInt(info),
                    type.getField("state").getInt(info));
            observed = observe(observed, current, ((Number) uptimeMillis.invoke(null)).longValue());
            return observed;
        }
    }

    static final class Detector {
        final DisplayState display;
        final Wake wake;
        boolean down, valid;
        long started, firstStarted, firstUp = -1;
        double x = Double.NaN, y, latestX, latestY, firstX, firstY;
        Detector(DisplayState display, Wake wake) { this.display = display; this.wake = wake; }
        void begin(long time) throws Exception {
            if (down) { cancel(); return; }
            down = true;
            started = time;
            x = Double.NaN;
            Snapshot state = display.snapshot();
            valid = state.asleep() && time >= state.asleepSince;
            if (!valid || time < firstUp || time - firstStarted >= DOUBLE_TAP_MS
                    || (firstUp >= 0 && firstStarted < state.asleepSince)) firstUp = -1;
        }
        void position(int rawX, int rawY) {
            if (!down || !valid) return;
            if (rawX < 0 || rawY < 0 || rawX > AXIS_MAX || rawY > AXIS_MAX) {
                cancel(); return;
            }
            double nx = rawX / AXIS_MAX * PANEL_WIDTH, ny = rawY / AXIS_MAX * PANEL_HEIGHT;
            if (Double.isNaN(x)) {
                x = nx; y = ny;
                if (firstUp >= 0 && !near(x, y, firstX, firstY)) firstUp = -1;
            }
            // The OEM detector compares DOWN/UP positions, not every MOVE.
            latestX = nx; latestY = ny;
        }
        void cancel() { valid = false; firstUp = -1; }
        void end(long time) throws Exception {
            if (!down) return;
            down = false;
            if (!valid || Double.isNaN(x) || time < started
                    || (firstUp < 0 && !near(latestX, latestY, x, y))) {
                firstUp = -1; return;
            }
            if (firstUp >= 0) {
                boolean recognized = started >= firstUp && started - firstStarted < DOUBLE_TAP_MS
                        && time >= firstUp && time - firstUp < DOUBLE_TAP_MS
                        && near(x, y, firstX, firstY) && near(latestX, latestY, firstX, firstY);
                firstUp = -1;
                if (!recognized) return;
                // Both taps must belong to one continuously asleep epoch.
                // In particular, original double-tap sleep must not re-wake.
                Snapshot state = display.snapshot();
                if (state.asleep() && started >= state.asleepSince
                        && firstStarted >= state.asleepSince) wake.run();
            } else {
                firstUp = time; firstStarted = started; firstX = x; firstY = y;
            }
        }
        static boolean near(double x1, double y1, double x2, double y2) {
            return Math.abs(x1 - x2) < TAP_DISTANCE && Math.abs(y1 - y2) < TAP_DISTANCE;
        }
    }

    static final class PowerWake implements Wake {
        final Object manager;
        final Method wakeUp, uptimeMillis;
        PowerWake() throws Exception {
            Object binder = Class.forName("android.os.ServiceManager")
                    .getMethod("getService", String.class).invoke(null, "power");
            if (binder == null) throw new IllegalStateException("Power service unavailable");
            manager = Class.forName("android.os.IPowerManager$Stub")
                    .getMethod("asInterface", Class.forName("android.os.IBinder"))
                    .invoke(null, binder);
            wakeUp = Class.forName("android.os.IPowerManager").getMethod("wakeUpWithDisplayId",
                    long.class, int.class, String.class, String.class, int.class);
            uptimeMillis = Class.forName("android.os.SystemClock").getMethod("uptimeMillis");
        }
        public void run() throws Exception {
            wakeUp.invoke(manager, ((Number) uptimeMillis.invoke(null)).longValue(),
                    1, "HyperOS-AVD: rear double tap", "android", DISPLAY_ID);
            System.err.println("rear-display-wake: rear double-tap wake");
        }
    }

    static final class Point { int x = -1, y = -1; }
    static final class EventReader {
        static final Pattern EVENT = Pattern.compile(
                "\\[\\s*([0-9]+\\.[0-9]+)\\]\\s+(?:(/dev/input/event[0-9]+):\\s+)?"
                + "(EV_[A-Z]+)\\s+([A-Z0-9_]+)\\s+([a-fA-F0-9]{8}|DOWN|UP)\\s*");
        final Detector detector;
        final String device;
        final Point[] points = new Point[11];
        final int[] lastX = new int[11], lastY = new int[11];
        int slot, active;
        EventReader(Detector detector, String device) {
            this.detector = detector; this.device = device;
            for (int i = 0; i < points.length; i++) { lastX[i] = -1; lastY[i] = -1; }
        }
        static long timestampMillis(String value) {
            int dot = value.indexOf('.');
            String fraction = value.substring(dot + 1) + "000";
            return Long.parseLong(value.substring(0, dot)) * 1000
                    + Long.parseLong(fraction.substring(0, 3));
        }
        void feed(String line) throws Exception {
            Matcher event = EVENT.matcher(line);
            if (!event.matches()) return;
            if (event.group(2) != null && !device.equals(event.group(2))) {
                throw new IllegalStateException("Unexpected input device in event stream");
            }
            long time = timestampMillis(event.group(1));
            String type = event.group(3), code = event.group(4);
            String text = event.group(5);
            int value = text.equals("DOWN") ? 1 : text.equals("UP") ? 0
                    : (int) Long.parseLong(text, 16);
            if (type.equals("EV_ABS")) {
                if (code.equals("ABS_MT_SLOT")) {
                    if (value < 0 || value >= points.length) throw new IllegalStateException("Invalid MT slot");
                    slot = value;
                } else if (code.equals("ABS_MT_TRACKING_ID")) {
                    if (value == -1) {
                        if (points[slot] != null) {
                            Point finalPoint = points[slot];
                            if (active == 1 && finalPoint.x >= 0 && finalPoint.y >= 0)
                                detector.position(finalPoint.x, finalPoint.y);
                            points[slot] = null; active--;
                        }
                    } else {
                        if (value < 0 || value > 65535) throw new IllegalStateException("Invalid tracking ID");
                        if (points[slot] != null) detector.cancel();
                        else {
                            points[slot] = new Point();
                            // Type B retains slot axes after UP; input core can
                            // omit unchanged positions on the next tracking ID.
                            points[slot].x = lastX[slot]; points[slot].y = lastY[slot];
                            active++;
                        }
                        if (active == 1 && !detector.down) detector.begin(time);
                        else detector.cancel();
                    }
                } else {
                    // Protocol B does not require axes to follow tracking ID.
                    if (code.equals("ABS_MT_POSITION_X")) {
                        lastX[slot] = value;
                        if (points[slot] != null) points[slot].x = value;
                    }
                    if (code.equals("ABS_MT_POSITION_Y")) {
                        lastY[slot] = value;
                        if (points[slot] != null) points[slot].y = value;
                    }
                }
            } else if (type.equals("EV_SYN")) {
                if (code.equals("SYN_DROPPED")) throw new IllegalStateException("Input events dropped");
                if (code.equals("SYN_REPORT")) {
                    if (active == 0) detector.end(time);
                    else if (active == 1) {
                        for (Point point : points) {
                            if (point != null && point.x >= 0 && point.y >= 0) {
                                detector.position(point.x, point.y); break;
                            }
                        }
                    } else detector.cancel();
                }
            }
        }
    }

    static String read(File file) throws Exception {
        StringBuilder result = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                new FileInputStream(file), "UTF-8"))) {
            String line;
            while ((line = reader.readLine()) != null) result.append(line).append('\n');
        }
        return result.toString();
    }
    static void validateIdc(String data) {
        int association = 0;
        for (String line : data.split("\\n")) {
            line = line.split("#", 2)[0].trim();
            String[] item = line.split("\\s*=\\s*", 2);
            if (item.length != 2) continue;
            if (item[0].equals("touch.displayId")) {
                if (!item[1].equals(UNIQUE_ID)) throw new IllegalStateException("Rear IDC display association changed");
                association++;
            }
            if (item[0].equals("touch.wake") && !item[1].equals("false") && !item[1].equals("0")) {
                throw new IllegalStateException("Single-touch wake is incompatible with double-tap wake");
            }
        }
        if (association != 1) throw new IllegalStateException("Missing/ambiguous rear IDC association");
    }
    static String findDevice() throws Exception {
        validateIdc(read(new File("/vendor/usr/idc/" + INPUT_NAME + ".idc")));
        File[] entries = new File("/sys/class/input").listFiles();
        if (entries == null) throw new IllegalStateException("Input sysfs unavailable");
        String result = null;
        for (File entry : entries) {
            if (!entry.getName().matches("event[0-9]+")) continue;
            if (INPUT_NAME.equals(read(new File(entry, "device/name")).trim())) {
                if (result != null) throw new IllegalStateException("Ambiguous rear input device");
                result = "/dev/input/" + entry.getName();
            }
        }
        if (result == null || !new File(result).exists()) throw new IllegalStateException("Rear input device unavailable");
        return result;
    }

    public static void main(String[] args) throws Exception {
        final DisplayBinder display = new DisplayBinder();
        display.snapshot();
        String device = findDevice();
        Detector detector = new Detector(display, new PowerWake());
        EventReader events = new EventReader(detector, device);
        final Process input = new ProcessBuilder("/system/bin/getevent", "-lt", device)
                .redirectError(ProcessBuilder.Redirect.INHERIT).start();
        Thread observer = new Thread(new Runnable() {
            public void run() {
                while (!Thread.currentThread().isInterrupted()) {
                    try {
                        display.snapshot();
                        Thread.sleep(20);
                    } catch (InterruptedException stopped) {
                        return;
                    } catch (Exception error) {
                        display.failure = error;
                        System.err.println("rear-display-wake: display observer failed: " + error);
                        input.destroy();
                        return;
                    }
                }
            }
        }, "rear-display-state");
        observer.setDaemon(true);
        observer.start();
        System.err.println("rear-display-wake: monitoring " + device + " for " + UNIQUE_ID);
        try (BufferedReader lines = new BufferedReader(new InputStreamReader(input.getInputStream(), "UTF-8"))) {
            String line;
            while ((line = lines.readLine()) != null) events.feed(line);
        } finally {
            observer.interrupt();
            input.destroy();
        }
        throw new IllegalStateException("Rear input event stream ended");
    }
}
'''

COMPILED_SOURCE_SHA256 = "f01bb5e354f1be3d0740b623ecddede0e7eb903ca6896ffb22a6264ec934099f"
JAR_SHA256 = "e427bf37c2b9646a8d0c0087f56a2eb6621aa203db048849fc19ee668ed797c9"
JAR_HEX = (
    "504b030414000000080000002100f308be01141d0000803700000b000000636c61737365732e646578a57b0b7cdb5775ffb9"
    "bf87244bb22dcb89232b7efc2c3bb193467e3b911f6dedd84ee2f811d792d3d80e75654b8e45654991e43c484b53c29a1418"
    "4b4709a5eb207d040aa3a5a585f1285b473bc678f7315658f7a765b0c2d66d65ec3fda8d91fff7dedf952da7e9ff9ffde77c"
    "be3ee79e731fe79e7beeb9f72a72247accdedc16a0ef056f3af1d1ec7fee397160c677f52b855b4e3d71dbf7c66bbfb9efe4"
    "0ea214111ddbdfee26f9f3e876222b33e5ddc00734a2edbc8e4ed4cc2bd88826414e1610d9411b9c449ead448b85e07d444d"
    "402bb003e801868019e030701ff020f029e071e02bc0778157807f06945a2227b005d80634016dc0b5c01810026e004e00ef"
    "03ee063e0e7c12f82cf024f075e0a7c0abc03f02ff02bc016875445ea00d1800a68083c08d40145804e2400a58068e03b700"
    "ef014e03bf0b3c06fc00f877a07c1351000801ef063e0bfc0cf06e86adc0cdc023c08f01673d513b3006dc001c07ce020f03"
    "cf003f005e07d406a20d4023701db0009c01ee013e033c05bc00fc0228da42b415e80542401238057c047804f84be0670061"
    "6d3602fdc075c00d40143809bc1f780cf801f06f40d155447e6004980392c009e071e0abc0b7806781978097815701d736a2"
    "52c003540006500f3401ed4000b806e803068111601c0801a780bb808780af02cf01bbfd44c340089802168004700b703bf0"
    "28f063e057406123e204d80dcc02c781db800f02e78007804f039f03be047c0d7816f811f053e035e04d406922720395402d"
    "d00034031dc04e602f1004a6811b8138f02ee014f07ee043c0bdc07dc063c057806780178097805781d781df002a369113d8"
    "0054038d4007d003f40323c02470237002b81df800f061e063c027818781c7812781af03cf023f04fe0ef807e057c09b80da"
    "82718041200a7c10f843e07ee061e009e0cbc033c0b780e780bf017e02fc13f05bc0d68a5807360157011d403f300ecc0073"
    "40123802dc0afc01701ff029e04f803f039e0178822905b0cd096143483d14003a812e996b7a80ab816b806b815ea00fd809"
    "f40303c020b00bd80dec018680bdc03030028c0263c03e601cb80e9800824088ccdcb51fb81e38004c01d3c00c7010780770"
    "03300bdc08848139601e880051e016e076e07dc0fb798e047e17f820f07bc03a002994da6b104fa00a9f1bf83ac90fd4983e"
    "5065cedd26f911c8fd920f8147685289acb35df207a57c8394b70115b22dcfcf861cab55fa7ab1c6acb3498edb21f994ec67"
    "735e3f0d3ccf4bf956296f963cefb345f227659f9c3f03be49aee95929bf4a8e95e347649ffebcb19aa4bc438e71b7accfc7"
    "382ff95659e716d986ffbc5bf2dc865b25cfe7784af20fe5f18fe6f15f047f52f267f2e44fe5f1dfc8abf3fd3cf98b79726e"
    "cf6d927f19fc7b24ff5a5efddfe4d5d7b008ef95bcd3b72a5fe73363a85dceebb4e479cc9c917c05eadc2179eecf1c9ff3e7"
    "8e3c7f764979bbe479fcd8c949ff419c6ea6ff047550213d2c683b3d2aa84a5f96f42b82327a52d2af4afa7d499f95f55e97"
    "ed7f23a89b1833f59aa43aa893aae80b7cbe58d9af09ba897e206809bd24e56f821661852b0455e8c3823ae8d3826ea53f12"
    "b483be2be9f704dd4eff4bd67f0db418948fcb291fd725c771c9fe395518df372a3d409c2af44be2798841c7a942eb0555a9"
    "4c960d41b78a7dc1eb1d927451d2a3527f9cf85eaba063c4f79949ebf18fefad6d544e8f0bbf1b9811a715f40be1af1a5176"
    "c03f0f0a5a411764f931419be9478256d28f859f2a447d2759e96f04b5d03f81164a5a04bd5dd06a51af08e37f51508d7e25"
    "fc63b677e5d15f083f348872096d91b491ee279ea34d7da9ac5f8a165f12d44f7f256829fd44d07afa2f1ec398ad43d00afa"
    "84a02efa3bd0f5c87a0e41eb256da4cf0beaa2af0bda46cf8196c1735cef4166e4b41cf55fe1714f05f427827ae8cf042da7"
    "3f07ad44d6f80e68b5ecb71aebe010eb60a78b621d34fa5b4175491d42ce73f08788e75f955e209effccf96d06fd94a0367a"
    "9a78fef30b79033cf773418be85f88e7b916fa9ca08cfe52d0567a51d076fa67413b242da17f15d42da98b7e4d3c079ae35d"
    "050f9d1774bda46592bae8df88e7c7cda29e1fd9fd21412be89b8236d2b705dd46ff206815fda3d473fb1ad1c339e239d549"
    "7f2aa842cf10cfab85f42de239b584be2168a3b0bb9536d22705f5d25f93798f2732cf850ae48d34e84348ccbf9549d78c1d"
    "53cf7fb8fe29e8dd327915f25f96b5fa97a1df2bf5cebcf675b2ff37a09f90faa2cbf4efc1819792fae2cbe89ba1bf5beadd"
    "9719bf17fa4f48bd2baffd3639fe01e81f91fa92cbf47f0cfaaf497da9ac93af3f03fd8fa0b774f0f35a15e7fd74b5781ed1"
    "0c0a33483c29579b989d0ead0284abcd3b0e5e43e2fee2a4846b48f8bf136b11eac54dd7c5d7a20c7172d818864d0daf1552"
    "0857a0195731cdb126f22957a1d73ef4e6557f46096300ed9c4ac2e88784f73668f66a6cc668a15e0649bbb0a0102892b988"
    "11536a3aabcab8ad36711f395acdf720d1b77b0f1b2d18d541e5da542f4e65ad1b2dbf3dc7a5ad223b7189466e5783e2c6aa"
    "e872de27ab4dfff1f92ab0fee2c56943c79e7de3d669a390666a159aa973627cabac7f47b5793f9bec557107b4c04a0dbd16"
    "a1df83904c0fdaa99ca16d1f9fbb4269173f579c2ce15a0f6a57024a0105dd35d4a2e84a97a212b7e560af03bd39d05b0d05"
    "77ea8874e810e5c19d1a3db9a94c39cb5a745de9d6dd141cd4a90c93e6e52ebd08658d82ae1a5ea66edd42653aac471d1e93"
    "a6b58833b9ae18c770acccaf089c2ae4f742cff3a40d91a2b37534a9aad4096046ea41d049cd21fa0d689fa0a0b5106bbb15"
    "e7bd5debd43e86b29d5a3466edd2ee060fdbf0ae6ed1ac05ddda7a0a3a6c142c2c106d822ae2a84425edd6a3360bd6c2ae76"
    "aa1af2f72dd060beaa5ad0a52e82b78b5e50b676a90159860f326556f800d26ed52f5b30b54bad17fc932d2d8c59bb99618e"
    "5400af382c18d94a7c2c2bd95980c1735658535070191d22a214aba04ec387e6bc43ec72ebb681820aec59c7d74ed1ba9462"
    "9435b3cc506656b473a25d19ea37144f339d82cc4ed3e83fc80a41312e2b02b562043e5691886d730dbe5c6ddee1271fe531"
    "7500d4815d85e898e8728e5257e1309d7acac3839d9ebaf8e3de2627293dce3e3af55293e654aed650afebbb864713cb7df2"
    "03bddfe9fdee36b3369d7f4fef77b6053f67ae5aab988741d38fc29e27e1a7cf61c5d0ca9ccf3a0a3e0eff7d1ef23f86ad5f"
    "327da4a24da782c8521037a83ffda80d6d0b60398f7b87d8993cc76af026d1f7aacd3b73c05a42dc73f030e6e310bc4df0f0"
    "caf11a443d3fdf4a68e2bdbe9cce1ab0621e164fc145f3e756edc35ef63cb9ddeed223d6753287d9f81d0dbbf4a56af32e5d"
    "690da58ae1a90485522e0a1d2e41fdc32e3fcf274a9dab53d044f338b91427c60e92977d9c0ebbeac5cafa9412e4a137906f"
    "1ab0e39c6ac218c36c9d6ab5ba95bcda6785bc8f9c5ac2d887d9d935affe88905d474e9dcb74b2eb5ecb2f852ccc23053244"
    "0aa5c64ba935144ab9614f29f6506d5b27b9356e459fea64d5ac0e336e454d877ab8b7808c7e27cdf0ba4015bce6c3bdc0cb"
    "929432f8b95a2fcb985fba9852cddb30937a64b52a6bbdd8dd0bf81d237e77415ea413c23ffcfdf5afd53c4b9b39cd8a73f2"
    "0fc5ac79767597d4ba03548139bab55155d1bcea5f50a2790b35c3435ee561ca79cdad728b9b85df7643f351d103d7d4ae0f"
    "90d7728f285bc86919b5e89ad7729fe8654e37fd2ef238da23bf6376f033ddbd62416d4980e6946d34aa30cdab3c25da198c"
    "d773a1dec756ea79d99b54bb3320f47cfd6652a58835d31fe52bfea195395b0df39d598a7b42c2e812b1e763e689c3e8451c"
    "6109e31ab4e027ce0032ad9379918b733c3f7d7854b8112fd7f25ad6c3ae46f4e150cbf49fab5f0dba7770798d75454e5f51"
    "5d2a5f038e528c8dd407fbcfc2fea0b03f8655e17b2377ce780cf38d6a9e33a5e8a1966da7991a2f6807a807373d50a31c67"
    "4e19ce9c0d889d509d976a063afa9193ea3ce47e7d9834c8ca89d317559535bccecf4545cc7f33fa7f84f1f7fe3acc2a84bb"
    "99d39e704dc00b76914b90cf8d84711d7f5721eb6da0d09d1b4896413b45ec0678ce29f0d9e163ba59f8d84ef576b72bd7ee"
    "304e72442e73b7714917768b7b80737bb14fdc939c9bc6a85e7d83e8711a3bc46d09e81a317b83dbabbf6b452a64ef6cb095"
    "ea2e64a626c81cd6f7becbab578a1a4151e3d7d89d45a2dc8ef322a0aea72ebb834267e111eab05b68ea9e8d38417630d3da"
    "2d2bd67ad5e2bc561f21f7afdabada28748f9726eedc48bbecc8f9f60a965f9eb813777a564a13f75550172b06ad04c55877"
    "96d1c4fd1534f169d8d56ca51a7bae955b1955d0ee9ef5f4987d0abfb7e0c5d2659fa275ea455cd9b77785ccf13e24fa5703"
    "761bca652263daa9c19fd3f934ec69970bd96554b3abf92d421ff2d0c45d1b694055b5a9072a68adae3c4f5749dc8a478515"
    "9c6bb3178bb1263f8d53dc5e608edbac62076fa1fbf2acd842f790e9b9adab9e9391a08948f0c0d71e31db615cbbb8df85bf"
    "10f001e8f3cb53f60af45398d7360e7df9dbb4bde192b695d410f2daab44eb07c86e0fd847c96bcf88f2832877daaf4639bb"
    "520ea0cc67da99f36ab38ed935b49ab3af11beaa39df6141ffcc6e09e04633e1c6ba2a2e50ac2b32096f35e1c2ba9698eb6a"
    "670dda8b160b6bf8fb86e2bc7592fba07ec53f45e21eccf77252ee77be9719f6e5147a9b72558afd9ecb4759d4f99dff8f1c"
    "fcf26573f00c34f7fe0f7270152cf883550b266a7dc8c2b84df1f1e7d46d9c32770db749702d2b5c5f4eeb652a5bcdc5c6ff"
    "235757afe4ea77e6e56aab38bf89de6f989f9b856e342814aea2d05cf59a9372a7ea54aa15f3a454c8a11c369ac55bc15dca"
    "4f777e4a7bb58f9057afa1ba205e1f83b9537e0eaf472f7b55bc215ce29304f30e7cce30df5913cd3e78bfd5556472adad46"
    "81c9ed6c33c45d9c15e324d2c55de61ec37c3b96eb74d29ab2dec67e9f3dc09e30ef22e63a5bc5fbe30183bfed73b1e0a5e7"
    "45a41ae2ae054fbbdb6a0ba8adce4a53eb7d345d56c3fda2c02fea92f04b2bd52b24c6e331f398617e2eebc31bdb8b9b62ca"
    "30308fc32eaff0f261d7c6159d2e750957add005c43da006e7975bed281da55d1aa90917ff4cc1895bca13b0a99ba2c8ab9d"
    "3abf2dfa74f461f90c6e14d53468e1fdebfc56e3ea15d46be1676527ed1779b88e3a156ffedb0db99b9f9a13fc243547d078"
    "79a7280f8af8c4de116b5fb2b2f6e2b47a22a01409fbb9ed066caf116f3a7eea9428668bd425379f8695b22ef69542df34cc"
    "cfde7d645a040e7bdca778c8a796a1761df5e3fe760273db44ad5acaa8c079917055f1d35d0b684e617b2ff852dce613c64e"
    "aaa3865f26b07759ee05aa9568859a2969d079561bc51ceb35fe191b3ffd9ac87c332bb867b489f3dfcc093f845d9a8c0312"
    "ef456eaf4e7f0b39ffbcc267714267132f463b7e1f16af5627ac77c07a1774fc13be54b34261c5073fa59a0b11b33e78c0ab"
    "5a302395ea9abb3037a79a32b6e3c63aa7f27bce0e7e77c5ed2560de69b1a37d1aeea0d85c11e6b5fc14dc2eeab7b8cb12c6"
    "5e9ac7c823b069ce82b7b8667a4fc37afebdf04948aea3c6f7332622fd04fef9153eff8d6ec18ce077cc22e1ea10def5eaa6"
    "d77b75ee758bf0ba45c426788367cf865f73bf72cd1ed8c1dff74c7886e7d9c362a52d546f81cf452d78dfc2bd7f23561f5c"
    "5e9b7a0b89787781e79f6516c0ea53f2cd7b4e502bb21d89fdafd2c7197d98d13d8cd73373334202b7651237b63b615b0f76"
    "b3d35673d2cd989bd5bad7752811daa5db14af05d9bd3ed17c3545ad4e7d97aeb3d53df2fb9493d7ec6f3d825db57b974567"
    "5eebff16fbff08e1ecb16ca05d3c335b9fcf93e9e65e28f0d9f8ace362d636aab799adff3daf66b56cfdc72bb24ecb7aec6c"
    "c8749b9085f02e0968e2ce267a5b5ee9ed4545610df7b6f5f37b9fa95b58d19d57141ea0f72b54f4f9e9b072a2b26a98798a"
    "a7957755566da2534cbc23f10ae4953a8787699251d1e91eff70ec22ab2d1ea69ba05b82e85c0fab2bfe428c35b8d88662ff"
    "353156563c5df513255549b3bce539b6aee495d3c3cc5b32ac1caddc435ddcef45af0c0fb3758588a5ca615652ec8f5dbc70"
    "e1098cad1cdffbde07b09f8a7a5ee1e2d3cc5d1c7bfaf445e57825fd11c35831565efcf403f431b0f409c6bb0fc4ee18462d"
    "7a4ca88fb175c567ce5d9866eb8b8f9d3e7d6ce8cce99ed3b1a7cf3ddd78ec275f6015c533e85439725429bafd748cb95cf8"
    "555272faf4e90bc3c72edcbf4f39baa8386fa77b79dfef636b4cc0dc840de7208695dfbffa18eee8456277c0840b54a18b18"
    "2aea79c1ef2fa73be0cf579ef0571d7b8e3b84790a4fed7cae42397a3bbdce6d9cc698177b941353e2d1fc51858b7a862f4c"
    "bf7e5a29f9da30f7252cbbd0d3d353a51cbffda1e11e7a93b7aa7afdb9d8f0850b5d77b0ea6274a538bbfd15f2cdb145d242"
    "49dd92e6a048ba49d2ad52b655be174ac4ff2c983a55ea3651a728d7cbb2226e3c24fe9fc13c49737d044479a32c3b44af3c"
    "336c1694672e45b433e51bc4a7cf7cb799f5b7a0ac495bf83f3d8f5757c668146d1ae5d8ed927691996799fca71b0bc9b441"
    "ac96d4862dfb49f5c7b3e4688a448f34c512a9e56c13b99a32c7334df3f17026638a681d9764a34b4d73b144d3a168367a24"
    "9ac85263134824996e5acea49b6291f9a623b17436969c156d669796e3d9d86c36b93cbf38bba3116a62cda436373793ad67"
    "3e1e4bc4b2d790a5c7a4257d3b83b3a3a1d9f17dc1a1d0d0beb1d9036f15210ea42838b22f446e59084df4f50f0f8ded9e1d"
    "1a205bdf812108fb0ed0c6bea5b9d8a1e5e472c64847c369439864608eb1f928b17e6203a40c0c907d6028383ed237c51b17"
    "0eec9bdc3932381bea1b9f1d0d9236b0effa31b20d60b2f3d9649a360ec432a978f8b89189a6792fc672227c241c8b87e7e2"
    "51b435953b638948344d4e590c66c3d928e983fb07c7426419dc3f0b9b050d4e8d9163903b71221ae62d6cbb27f64d8e7333"
    "2af61c4f45d3fb82febefd035da6f191e4320631b2e114b12152863846c83a34b667706208196d686c7c32343bd6373a48eb"
    "86c444c5fa648c483a994a4523b4c194620d17326bec2e1e4a1c09c7631163346464e2c92c95e604d97478fea658e2900193"
    "d85e52f6e21cdc3b32446c8494917e6088d4116ec9089423508e0809380dbff6926f24128e1f89ddd4144e249270432c9968"
    "1a4cccc7931974dacf43ab9b6aff6f7546a3d9c564a49baa2e5369289188a665273597d18f4697e6648528aa545ea64a3076"
    "2811ce2ea7a3dde4bd8c3ab4984e1e45d3869158b2e9502cbbb83cd7b4c8172699091f893461d5d2728daf0fdf14ad6be9a6"
    "a62bab998ba76e6abfc206f991d54d6dffad562200bba9f5ca1ae50564376dbbb236e3c95822db4dcd575afb6834cdb92bf6"
    "5730114e65169318e2aa2b6b60f6bef98a2a779367e49dd80d4da8bc737961219a8e4672f32f5ad1ec8ac551b37c4d596ca8"
    "6016db73a99bd6afa8d688375e4e9ceb7eb5cd781a1eccb571ad887315a585f170e25053ff62381d8c1e5e8e26e6615149be"
    "c6dc0cee3cd180c81a2b2309d9e0b1f9688a0738df37abe2a1783c7a281c17d19257a534bf4a221b3dc4ed312e11a6d3cba9"
    "6c3492d7cc955763249938b456321ace2eae35746c99efd6b5b27d73efc436596bc2783a391f35f3c65b843b976371b8ab6e"
    "221a89a5454befdb56eaa67579ba89e544222c1c953f3ed623c62d2f7f8b6ca59335d5c5e9b856861482255ceb7f9156ccd1"
    "f27b4e4717e2301a91158d47d69a9e53e5d2a16cb69c8dc5a13b143dc61d3abfc80d7aab6a3c9cc5026149368fc6323ca936"
    "85d71e8b4303fd060227391f13698f9ce37d638323b37b068776ef0991c32c5d3f3410da43bad8e9542eb6f0650fc18295dd"
    "4d7513b9de23f2d4cc1bc5985fc4cc702cd58a5ab91ab108b24f2c7bbce9503ab99c5aa954b1a652728e8f0c0316302ab49e"
    "35da7c6b2a272e3df7df562d4e4b2323b6a0811b0dfa5d7749a668e4ae2507ceedd981897de3e383b83bf0c2c4e0f8be8910"
    "6d0fc2b9f1a85fdc768ca36860c432e87d3eb994c29cf9e97d14c9489ee47e9ce4a212d972e98d9cfcda81db48a86fac7f90"
    "b4d0d4f820154c8e0d5d3739c86f05cae438e993a15dfe00d54f26a2c75288896864edf4628935332186bbdd7e7e44efc711"
    "bd7f84f4fd38b087c822c85ee870582bfba749134bc6a649991e207d7a003f60a19b1922ffcc7feb18289eb9246bba67de9a"
    "a44a672eb7d1672eb3fb3207670e66b636cc34fb3bdf71d5c146936e39f88e8399ab1aaeed6ac8bbb38a894b7d17d45bae6d"
    "c0356ba6cf3fcd1ba03a67a19ecd15c3fe853eff2edee044e0969bf95defe6c971a870a93e98202b98ab79410dcf65c8119e"
    "e7e963573c7c284396f07c36760457be7024125c4ea5d2d02060ace1046e5bb1083548a611b93a72349c8e36cae86c1c920e"
    "1b0d27c248a5e4bfd29a75c1ecf21cb973d59399c62179d1f4e4cbc4f6cb755ef9761ab3b3f23c75d0dccbb99665f92a91d7"
    "fae3c9f99b56c73a128b1e6d94160e25169270096e998908fc941127c24218976c4b38138f46535cc829360884fa5cf4502c"
    "4196f9304a71d2f95d2f4a56be4d62fc1a3dbf9c4e6321cdd449d64814a19c3c4eb648ee166e91577887499b12e125b4977e"
    "a322c9ece61964284205b20c568b248f2648e5665a708286e31914d26972e4450e34c762996c86ac3cbbe06e48fa022a4649"
    "5b886289ed0b70fa8039be732196cee0d40ea7b37cf14569324516c11c90740a8a647a8c9ba8e2d14445f895ef371bca22e5"
    "93159c10150966e5b6401651ce5201a8790488baa24f3b18b976a48ba449561e16c7f62d50412c77349325963892c4062f8c"
    "65f2ce6bd26399b1f018e9d893305810d81bc70d809725334505717884efe50c95230cc2f1aef6ed2d9d81d61d1d1d2d9ded"
    "8196f61dadcd2da885737e7f38be0c5f2d85b1c2d625194d60c4f1946332a48935d312c8206495f99c6c92c19aa5c2e94c94"
    "df1bc892e2592543b6145e04e27cd2533c92c99ae277a6788234112736fe7b249688929b9f6a7eb9eafe8c787e6d5b23e369"
    "b7ebed8e932e83aa2e537b2989476a92a72483ea2fa3cf7ba4ada6f6c2b4bc8a0ca6d3085c35bd9ca0820c02201c5de23331"
    "7787265e5db64cee18d0d16f8c131e5964cdc800d3cda9146496e7322237527136b684050a2fa5466371ac11d9b2c9604ec5"
    "4fa1c6d5d8b79b026196863a4b645b4ec4708d84ce8968404fb213071e7f75b9dd54c00be6fb5f178f42a18e4560c9105ef3"
    "5c86f5b60a8290f3befdeb9f3431b685ffc62e2935e9f5385506568c64c7881da77bd9bbdf3d1038e19bc3eb137bd5d7e543"
    "3cfbb6f9cc0c21ae0ffea564242a1473cb87a05a0c67fc08acf99b32cb4b195f97d8b1db7c4bb1843f9c8af9ba5ab76ff365"
    "16c3fe1634690eb487039d2daddbc3d1e68eceedf31d9d9d2ded6d91858e1de1ed1deddbdbb787175a036d2d6de8154191c1"
    "6068d4d9d8dad8ee47bef1dd428a8dfd9655b00d8aa283f1962b16e52ea6d10f59955220349e2a53e4f921dbe05134c83ca5"
    "425267b340b47155eb5d65ab57d9585ee5df5915dfb4ca1e51ac7c249bc7e929f1383c2e4fa1c7ed29f21493c2189d35d859"
    "834e9ed47eee65eccc462a5434c5c5e82dff844c41bd972b34dbf90a95ce56327aaa8ad1cb550afd94ff270373dc6623d215"
    "56dc8bdabcbecb86fa4f6c66b6cfd4da6f3b69bbab8e5955b6ceb39e84defc47ce3327b507b730d4fcc616c5f65043113db4"
    "957f29b7827f0717d2bbf817be5919ef5b65ac4ab42a81fc8b2d6ef6421b290aab81a4149237da792fe73bd6d333ed05a453"
    "ad875df26fc36d27b5873a99edb50e56f014e8d900b3bdd05370987fe347639bcf328ded2076ddf9f7f45e77f203bd2d53bd"
    "1b9e179f87cdb7999f97c541336de66764b748d99da0b7e7f177e7f10fe6f19fcde3bf9cc7ff791eff6c1eff921ce755d06d"
    "1de6e782b9cf07f94f1d64bd1dab9f1792fc8c31d041e2b33e4e472e69e790f20397b4b349b95dd2c825ed8aa43cd5416b7e"
    "6ebea45e99ac77e692fe4ba4dc2de95d97f473be63d57efee391f5ca25f54a9afb5b079647737f8bc6c7cafd3d1aef27f737"
    "69fc73ccdcdfa571bfe4fe36cd42ab7f9fc60c730cfe376aaae4f97735998b7f87d8fcceab629863f1bf61d30cd3273c2ef8"
    "17c2793ffcbbb0ba61da24bef3e932bfd7cad7c922ebf0efccf22f42f23afcefe8fe0f504b01021403140000000800000021"
    "00f308be01141d0000803700000b0000000000000000000000800100000000636c61737365732e646578504b050600000000"
    "01000100390000003d1d00000000"
)

def files():
    """Return canonical offline runtime assets and their exact image contract."""
    from apply_rear_display_fix import EXPECTED_WAKE_MANIFEST
    if hashlib.sha256(JAVA_SOURCE.encode()).hexdigest() != COMPILED_SOURCE_SHA256:
        raise RuntimeError("Rear wake source changed; rebuild the audited DEX asset.")
    jar = bytes.fromhex(JAR_HEX)
    if hashlib.sha256(jar).hexdigest() != JAR_SHA256:
        raise RuntimeError("Rear wake DEX asset changed.")
    legacy = EXPECTED_WAKE_MANIFEST
    rows = ("schema|1", "class|" + CLASS, "jar|rear-wake.jar|" + JAR_SHA256,
            "legacy-jar|" + legacy["jar_path"] + "|" + legacy["jar_sha256"],
            "legacy-launcher|" + legacy["script_path"] + "|" + legacy["script_sha256"])
    return {"rear-wake.jar": jar, "rear-wake.tsv": ("\n".join(rows) + "\n").encode()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    jar = compile_assets(args.sdk, args.work, JAVA_SOURCE)
    source_hash = hashlib.sha256(JAVA_SOURCE.encode()).hexdigest()
    jar_hash = hashlib.sha256(jar).hexdigest()
    path = Path(__file__)
    text = path.read_text()
    start = text.index('COMPILED_SOURCE_SHA256 = ')
    end = text.index('\n\ndef files():', start)
    hex_lines = "\n".join('    "' + jar.hex()[i:i + 100] + '"' for i in range(0, len(jar) * 2, 100))
    replacement = (f'COMPILED_SOURCE_SHA256 = "{source_hash}"\n'
                   f'JAR_SHA256 = "{jar_hash}"\nJAR_HEX = (\n{hex_lines}\n)')
    path.write_text(text[:start] + replacement + text[end:])
    print("Verified rear wake source", source_hash, "DEX", jar_hash)


if __name__ == "__main__":
    main()
