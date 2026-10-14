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
        final boolean interactive;
        final long asleepSince;
        Snapshot(String uniqueId, int displayId, int groupId, int state) {
            this(uniqueId, displayId, groupId, state, Long.MIN_VALUE);
        }
        Snapshot(String uniqueId, int displayId, int groupId, int state, long asleepSince) {
            this(uniqueId, displayId, groupId, state,
                    !(state == 1 || state == 3 || state == 4), asleepSince);
        }
        Snapshot(String uniqueId, int displayId, int groupId, int state,
                boolean interactive, long asleepSince) {
            if (!UNIQUE_ID.equals(uniqueId) || displayId != DISPLAY_ID || groupId != GROUP_ID) {
                throw new IllegalStateException("Rear display identity/group changed");
            }
            this.state = state;
            this.interactive = interactive;
            this.asleepSince = asleepSince;
        }
        boolean asleep() { return !interactive && state >= 1 && state <= 6; }
    }

    interface DisplayState { Snapshot snapshot() throws Exception; }
    interface Wake { void run() throws Exception; }

    static final class DisplayBinder implements DisplayState {
        final Object manager, power;
        final Method getInfo, isInteractive, uptimeMillis;
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
            Object powerBinder = Class.forName("android.os.ServiceManager")
                    .getMethod("getService", String.class).invoke(null, "power");
            if (powerBinder == null) throw new IllegalStateException("Power service unavailable");
            power = Class.forName("android.os.IPowerManager$Stub")
                    .getMethod("asInterface", Class.forName("android.os.IBinder"))
                    .invoke(null, powerBinder);
            isInteractive = Class.forName("android.os.IPowerManager")
                    .getMethod("isDisplayInteractive", int.class);
            uptimeMillis = Class.forName("android.os.SystemClock").getMethod("uptimeMillis");
        }
        static Snapshot observe(Snapshot previous, Snapshot current, long uptime) {
            long since = previous != null && previous.asleep() && current.asleep()
                    ? previous.asleepSince : uptime;
            return new Snapshot(UNIQUE_ID, DISPLAY_ID, GROUP_ID, current.state,
                    current.interactive, current.asleep() ? since : Long.MAX_VALUE);
        }
        public synchronized Snapshot snapshot() throws Exception {
            if (failure != null) throw new IllegalStateException("Rear display observer failed", failure);
            Object info = getInfo.invoke(manager, DISPLAY_ID);
            if (info == null) throw new IllegalStateException("Rear display unavailable");
            Class<?> type = Class.forName("android.view.DisplayInfo");
            Snapshot identity = new Snapshot((String) type.getField("uniqueId").get(info),
                    type.getField("displayId").getInt(info),
                    type.getField("displayGroupId").getInt(info),
                    type.getField("state").getInt(info));
            // Power-group wakefulness changes before a physical fade finishes.
            // Validate identity first, then query only this display's logical state.
            boolean interactive = ((Boolean) isInteractive.invoke(power, DISPLAY_ID)).booleanValue();
            Snapshot current = new Snapshot(UNIQUE_ID, DISPLAY_ID, GROUP_ID,
                    identity.state, interactive, Long.MIN_VALUE);
            observed = observe(observed, current, ((Number) uptimeMillis.invoke(null)).longValue());
            return observed;
        }
    }

    static final class Position {
        final int x, y, slot;
        Position(int x, int y, int slot) { this.x = x; this.y = y; this.slot = slot; }
        static boolean axisNear(int a, int b, double extent, boolean sameSlot) {
            // Suppressed Type-B axes have not changed. Preserve their unknown
            // baseline symbol instead of guessing an absolute panel coordinate.
            if (a == -1 || b == -1) return a == b && sameSlot;
            return Math.abs((double) a - b) / AXIS_MAX * extent < TAP_DISTANCE;
        }
        boolean near(Position other) {
            return other != null && axisNear(x, other.x, PANEL_WIDTH, slot == other.slot)
                    && axisNear(y, other.y, PANEL_HEIGHT, slot == other.slot);
        }
    }

    static final class Detector {
        final DisplayState display;
        final Wake wake;
        boolean down, valid;
        long started, firstStarted, firstUp = -1;
        Position origin, latest, first;
        Detector(DisplayState display, Wake wake) { this.display = display; this.wake = wake; }
        void begin(long time) throws Exception {
            if (down) { cancel(); return; }
            down = true;
            started = time;
            origin = null;
            Snapshot state = display.snapshot();
            valid = state.asleep() && time >= state.asleepSince;
            if (!valid || time < firstUp || time - firstStarted >= DOUBLE_TAP_MS
                    || (firstUp >= 0 && firstStarted < state.asleepSince)) firstUp = -1;
        }
        void position(int rawX, int rawY, int slot) {
            if (!down || !valid) return;
            if (rawX < -1 || rawY < -1 || rawX > AXIS_MAX || rawY > AXIS_MAX) {
                cancel(); return;
            }
            Position current = new Position(rawX, rawY, slot);
            if (origin == null) {
                origin = current;
                if (firstUp >= 0 && !origin.near(first)) { cancel(); return; }
            }
            // The OEM detector compares DOWN/UP positions, not every MOVE.
            latest = current;
        }
        void cancel() { valid = false; firstUp = -1; }
        void end(long time) throws Exception {
            if (!down) return;
            down = false;
            if (!valid || origin == null || time < started
                    || (firstUp < 0 && !latest.near(origin))) {
                firstUp = -1; return;
            }
            if (firstUp >= 0) {
                boolean recognized = started >= firstUp && started - firstStarted < DOUBLE_TAP_MS
                        && time >= firstUp && time - firstUp < DOUBLE_TAP_MS
                        && origin.near(first) && latest.near(first);
                firstUp = -1;
                if (!recognized) return;
                // Both taps must belong to one continuously asleep epoch.
                // In particular, original double-tap sleep must not re-wake.
                Snapshot state = display.snapshot();
                if (state.asleep() && started >= state.asleepSince
                        && firstStarted >= state.asleepSince) wake.run();
            } else {
                firstUp = time; firstStarted = started; first = origin;
            }
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
        static final int SLOT_COUNT = 11, INITIAL_SLOT = SLOT_COUNT;
        // The current kernel slot can also be suppressed at reader startup.
        // Its symbolic baseline must never alias an explicitly reported slot.
        final Point[] points = new Point[SLOT_COUNT + 1];
        final int[] lastX = new int[SLOT_COUNT + 1], lastY = new int[SLOT_COUNT + 1];
        int slot = INITIAL_SLOT, active;
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
                    if (value < 0 || value >= SLOT_COUNT) throw new IllegalStateException("Invalid MT slot");
                    slot = value;
                } else if (code.equals("ABS_MT_TRACKING_ID")) {
                    if (value == -1) {
                        if (points[slot] != null) {
                            Point finalPoint = points[slot];
                            if (active == 1) detector.position(finalPoint.x, finalPoint.y, slot);
                            points[slot] = null; active--;
                        } else if (slot != INITIAL_SLOT && points[INITIAL_SLOT] != null) {
                            // An implicit contact can reveal its numeric slot on UP.
                            // Retire the ambiguous contact without recognizing it.
                            detector.cancel();
                            points[INITIAL_SLOT] = null; active--;
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
                        lastX[slot] = value < 0 || value > AXIS_MAX ? Integer.MIN_VALUE : value;
                        if (points[slot] != null) points[slot].x = lastX[slot];
                    }
                    if (code.equals("ABS_MT_POSITION_Y")) {
                        lastY[slot] = value < 0 || value > AXIS_MAX ? Integer.MIN_VALUE : value;
                        if (points[slot] != null) points[slot].y = lastY[slot];
                    }
                }
            } else if (type.equals("EV_SYN")) {
                if (code.equals("SYN_DROPPED")) throw new IllegalStateException("Input events dropped");
                if (code.equals("SYN_REPORT")) {
                    if (active == 0) detector.end(time);
                    else if (active == 1) {
                        for (int index = 0; index < points.length; index++) {
                            Point point = points[index];
                            if (point != null) {
                                detector.position(point.x, point.y, index); break;
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

COMPILED_SOURCE_SHA256 = "8e677823a247225e4c2d4cfbeb3ad5ca041ea77845d785ef2a5e6e07110f1242"
JAR_SHA256 = "d3b5f0be1bfa77939d39c034ce703c191765dd4dfd34dfcfbbb171e72b378be6"
JAR_HEX = (
    "504b0304140000000800000021001be65418861f0000443b00000b000000636c61737365732e646578957b0b7c9bc595ef99"
    "efa197655b965fb2e2872c3bb1f390df7664d9013bb19328b61363cb01db6113d95212812dc992ec2450da84002194b6e1b9"
    "94521a9686b62cdd6db7946e2fec164a6f6fbb4bd996a577c3be0a5ddac22ddb9b6de996bbe56eee7fe61bd97208f797b57f"
    "7f9d9973e671e6cc9933e7fb6c45a2476d2ded7eead6037fb0ade0eb9bda4b37f5be376ced99fdc481a25b8a3f767aa08728"
    "494447f7763849fe64024405cce0f7025fd48836833ea41375826eb2105d07faaa95280ff47e3bd1a88fe8dd7c22db5aa222"
    "a004a800aa818dc016601c3809dc017c1c7800f82cf015e045e087c09bc0af80bc75d00128024a815aa005e802fa80eb8139"
    "e026e004701ab8077814f822f05de0fbc00f801f017f0fbc05bc0bd81a88ea800e20080c03a3c004701db00f380044811830"
    "0fa48023c02dc063c077819f03d646a246600088039f037e0cd8d6135d05cc019f05fe06a00d443e600248001f031e06be0a"
    "bc0cfc0cf81d60df48b40ee8064681347027f024f01cf032f053e0df81bc4db00b300ccc004bc03dc039e09bc00f815f0266"
    "ec8f17d802448134701c3805dc033c057c03f827406922f200016012380a7c127818f802f035e097c06f01b51936004a0017"
    "5003ec0486806b8009601238001c06168025e026e0387012b80bf824702ff002f00af073e0f780a385e876e034702ff087c0"
    "e781a7806781ef00bf02aa5a895a8121e006e076e0b3c037806f012f01af026f00bf047e0d501b910528045c4003d0020480"
    "adc01ee03ae03090068e011f05ee003e0e3c049c05be047c057806f836f07de0ef80d781b7815f01ffc9e76a873f03b5c07a"
    "a003d802048151601238082c00c7804f018f025f069e069e055e045e06de06de05fe03503be0334029b006a80536001d402f"
    "b003d8034c0207801890008e019f009e05fe01d070b88b011750076c005a8000d00fec04ae01ae0366810cf051e053c06780"
    "c7803f06be097c17f811701ef819f00ef05ba0a88ba81ca8013a80cd4000e0c1a718f0f2f802f8816e00a1887a641cda025c"
    "055c0df401fdc056601b30000c02db811dc04e2008ec028680616004d80dec0146816b8031601c080113c05ee05a32e2db24"
    "30054c03fb80eb813f00f6030780303003cc0211200a1c040e0127808f039f043e059c01ee01ee05ee034a0084587ab70eb6"
    "065580f751a89765addeb0832a63b24f96ede037c97209ca3822940ddc9b65b952f25d928fada56ad997bb7dad9c0bae23e6"
    "6eac37daac93f376c9728b1ca721671c1ec6fc92bf51f25b65998fd926cb7d724c5ede89728bdcd751c9df24e7ca96ed72cc"
    "a69cb95a24bf4bce719d6ccfe73820cbedb2cd09d987ffdc2acb87c13f29cb7c8d77ca7226a7fc919cf26d28df26cb3b73f8"
    "77e794efcf69f3480efff3397caecfedb2fc14ca77c8f29fa37c4a96bf97d3f77c4edfd7513e2dcb6fe5f02fd41bfed429d7"
    "78b72cbf07fe2764595b9b53cee1676debcfb16d8fe477ca32f7251bd989314e1b4861fc6ecfa7af11a79df48ca00e7a5e50"
    "955e90f4db92ff7792fe8be4ff4ef653c538c56401b5530d3dc7e7c56efe0f49ff56d075f48f823ae9a7b2fe0b29e787a400"
    "bb5c499c2ac22f395d92f4d382e6d15704dd485f15b48b7e2ce9ff147433fd4cb6ff0d6821681e33a81dd421f90ec977487e"
    "91d4ab48eac1a995f133a6d21788d34efa1b41157a8fdb108d1c822a542aa84a65b2ee1174a3384bbc5d4cd21b24bd59ca6f"
    "217e3eabe923c4cfa6411bf18bad450c70d33789ef8f47e45d3658e582b073ada8e7a1fd9704ada43f96f56f085a453f17f6"
    "ac14edec64a6370435d1bba0f99216406e13b446b42b80b67f29a846ff21ec66f477603c83b6d017056da5d7859d0c7991d4"
    "cb09bdf3045d2fe906499be909e2f1de685722fb9560a46f09da44ff206831bd2d680369b07b29acc0db95a2fd53823ae87f"
    "8196c15279823648da4ccf0aeaa0bf16b483ce8396e376e1f20a44594edd68ff166825da3f493c465ae945415df45d412be8"
    "af403d725c0ff6274fec8f8d4c8cef8f466f8a7dd225cd137c1ec3ff10588bfdff7be2b1d4585f03e89f0a6aa1ef118fa54d"
    "82bf1e96fddf8216d0bf138f996df4e782327a59d076fa67413be9b78276495a44ff4750a7a40efa4fe2f1d4986f132cf779"
    "414b252d93d441bf271e6bd789764db0cc9f085a493f14b4995e15d447ff266835fd5acab97ecd18e161e2f1d94edf1154a1"
    "ef138fd1f9f423e2f1b9887e2068b3d0bb9dd6d0970575d33f09bf357ef859fe47dc198ba0fb70d99fd86cf00ddf32e4fc87"
    "cb33903f20e5f9fcc3b45a7e3fe42f4ab93da7ff9b72fca720ff6b292fb8ccf82f41feaf907fc1cffdfc83f23721af9001d4"
    "7119f9bb90374879f165f4d390c85c2de54539fddf91fa5542be43ca9d9719bf17f269292f9163e4ca8721bf19f22ffb796e"
    "a08adce29f71d1e3518da6519946404f3abac4ea754815e067b5465e858c53e449768a3b86c5fe7463ef427d78a271e0110f"
    "5e53420b9eddd0a9f19d7c0a21ed9a76d86986759057d9845107309a5b7d87e29e1de86757e29eed3c82a2f74e6354cf7acc"
    "16ea63e06c161ae40305328631628ab7bb068152977affbed6d843aeaf82d92f5e9cf29868ba4ea1e9fa3cf433cb76aad7c8"
    "e726fa54dc6d268caee1441690d3b10f9ca9412b39d974bf051a2b9472f099ec2cee7081da14bf62a571e75a6a557425a0a8"
    "d4a838695f9f0d63d930562d8d6f35c19f2183ef8e6fd5e9b9b565ca19d6aaeb4a8feea4f1411395214de3f5805e80ba4ee3"
    "8eb5bc4e3d3a643a74469b02a929f6d46bec0566f1d896d75420ee4a9eef9543fe285fcb7115d657f92a681fca1327d05ab9"
    "78d1cf3e45a11316f2b38fd3f86d566a65562dc06e4719b3c1d75a9966ea61056863a6d06d16d8dc89fcd8c6ba9986b8b220"
    "daf136017640f41fbf235b6f9175ac315266c21ac5486b650f3e4b8d283f176cb55a4d3d5617854ec3a67769628e2f91cdea"
    "b762ded3e64b781af6a1114b9bbad52457143a6dec8395ec56be0f56b2d9fcb6721a3f8ef9ef85f56ca4046c85a8c39a9f46"
    "dd4ad68015e39ece43bf0ab46fcc9b3a6da2f1d3569a3aad0b3da64ff31de77314c0be7cff912f7a8d6700c32f06c49e720d"
    "1aaf725ee8d0fdd461eaa293a32e6e767afee24ffa901b29bd886927f943aab285b75ceb85b727fb1c34ba141ab450b7eea6"
    "e93e8bb1ef4cec3b0be80ee2b2d07663d551b2e9ddfa8a174ef799f199ad158893a0091f18f11af9bcdf5244dc0e16e23e97"
    "47d2262863fd77ad256e3d2ffc60ecfe069a78605d566ef15ba0a1c965bb68fc7c4c7bc2cd5e23a7d359bc642997b1211f7e"
    "6781674d61aec750afb2879eb7c30af750e8799ce1170ad17ec1c123b75dad7704b066bb1a6f1927876ac7fc4be4668fd382"
    "63a338335ed5496eed2256b9093e65d7e29e6bb012bb56a36d24b7fe75c1bf86ec7adc3306cd6dbadbf4b4e085c96ee23c13"
    "d94c6ef37b82b7c0cf20783883941c2da56dd1d0f3f08c178a486aa3706d3815da283c67acc4ca37f05861f56ad0447f8dc6"
    "fc0d5461a3e3ce3267395fb3865561375e709253a9f306c829d6d2aad8590d3c39eee8c47c796c013bd8576ba769de16a8b6"
    "17c1be1eac3545494f1376bc41d61728f46d3b255b9aa141036c596de7791b3fc9a7f1793719391ba347591e3ef9b3580676"
    "7e51c62c1beeb9c784f5b0e7cce9acabeba64ad8caa98f68aaeed65ea2788b8ffa553b73ab5fa3acf59d26ae73185c3ffb34"
    "e2e967c5085c52d7d04d6ecba3a26ec1d919b19a75b7f59c18e53eb3b17f22b6a1ff2cb3b3e9c70ab1864796f78fcf3f636e"
    "a511336637ff77d16f41e5edf2b35a525d2d745437d288ca742eef63768cf10bca1dfb00e3beb10dfcb3abc6967a697c75bc"
    "ef3d189bf713b19faf0974fa6c11acf2b955f3cd28d04961ba5b7945e8e461bc5d01dafdd1723b37cc5c37d62de4dc1ba6cf"
    "3a71968c5d9abf64d72a96eb3cd61afb72bfd7787e2c46f612f76cc1dd61232f336e2d46e7710dc63dfde8c16fad1d88fbd8"
    "13dc0cd932bfc1f82a9df0c6adbc9579c1d18a31f2d432fd2df52fc69d9b39bfd6bccca76755077fe411be721673f3fbd34d"
    "f7633d7bc57a62d084c782ec5d77ce6b3cff1a775d31b70cdb4cd3b56b40bb402b9055827adc90e5d1a4a712f76039ee4117"
    "7c3c54bf866a073ab7e1fcd45790f3c21069e0b989d3f3aaca1a2ff0fb451131f169ccf32f8cbfaf28c6eaaea5b364b7c51d"
    "13b0862d7bdf78e29e107f0684ff9553e81e17c93a68af38af7e1e19ad5e1b6c4dc785adf1a468733ab2fd161c05e29c39db"
    "3927c07d7a809776c1379c13bc348559dd7ab918710a91c269f2eb1a315ba3d3ad7f74992b7837345a8a1161173c6de0e599"
    "6fbbc9ad578916e3a2452bce4e81a877904d2dd6f3c88f2815b059a873ca44930f57e2d69b6786ae1b967575ab85cb7dfcea"
    "53e4fc4d7b6027851e5e4363f754d2769b8d3999df566770ee151c65ecde326a571033ef2da7b1c7ab68ecc96a4464c4a43e"
    "13b5edcab61c6168f970197dd53689cfc63563d0a06dca2546c228badfe644b95cdc0736c1450f7da5c77adc2beba984056c"
    "9354a25ebc08af0d840c3dee137aa87eac6d6584465f56e6d50ae13d85d8e511cda6e6f608dd5721341d50556d129aaf96b9"
    "7364581174f88ad08497da710bf3b9269e443662b31af3b6a8e456d6e3897f458bf578ce326cbc71c5c6d263b8dcc5b2776c"
    "a94ac7fd681f3a039d1ea8c44ed9e8e413cd2613db628257a9ec894685750d99480f9d59235a6cc721f1e334e7d6430fa0f7"
    "83d05ad74d93f007376273762e3ff2e0d0196355019b994e9e6b663adbc270ce024336d2c4eacf88d593dfb69f72eba21f3c"
    "60000777f26c3535ee71dbaac5c88f8b1c6527b96d4744fdf3a877dbfca81f5daefb51e756ebceee508b0e4b35fa0c4bf237"
    "177caeda273b9f28cdfa83c96fb3635678d4638647716f72dcd0a89d87451adf6e2cccd96979e21a972dcce38722ee1fd03a"
    "23c6f0f8c11003261d5534e9a81631c68a28c3931c739df1ace0743899f3d76df595d4be1636779ddc7a32f4d2d6054f07b2"
    "f63c6d251f7ab9fe07910ad3645f8b864c50e3b931837fb58774129987a82155c3e888ab75c67b2527f9ad9d3476c283d300"
    "9cacc13ed490b3b47d1bcef238faa82e9348848fdfddb7305e44b54b36c4994af4a8458f5aa3c7a76ba8fd3eb49f447babcb"
    "78f579f6d6be8549b4df66e4946c9467458522d3e3ebafac339e278d679b49e6a149a59626d51a910f1a77405d9df13e8eb7"
    "31e7decde42caa731af79e531b5115cdad1a77730b6e1ab762dc7e3c1731f209cef5d33424c6fdc72575a5b89b4dc6dd6c42"
    "be3362d235b7c9b89b6774239bc9de836dfc1e4c7a57dd83ceb13a2f6e42b58df8fc336a2ba7cc596bdcc528b52e97fab352"
    "37b3b1e5fb3059ffc1fb726bce7d99acbbcc7d099f806df8fe05ea8cf7aca103f5140a7b293453879ba5ae1d3994c675deaa"
    "da951ac5c8a114ca53163cede219cf59ccf3359e9db8b5cf2027aba5faf100b50d66f3b619c45837fb9578f673883748c673"
    "d0609d919f4eb4acc3bd934f632d0dd8850e87c528cd7479c4b3182b14ef0b75e84914ac33de0954e874dc9c349f60f7b2c7"
    "d9d34be63222e9e716e1e7636857b37c16dcf49a38a11ef1b487fbcdd95e9747edf5569a2c6da07d65eb68aa7c2db78d02db"
    "a849619b366a50f8b3b759e4e9913a12efef9c8eb67c3c4bb6b65599c8d9df56653c2d3293f91ef31fb1afb1efb01f6bbfe0"
    "592813cfa6c6bb79989dee229ebf97c10e668c5e877117703af9ba161cd5cb325dcae28e7542e617ef066b917338d5cee211"
    "c2e3851ac7b325326e64d6ff0d6bba4a3e6b408f8057c718a63f43aeeaa541131f5fe799b8639ba06e9399711bec1577663d"
    "752beedc67765d1399ce18cf7e8c19345edf2aea3b857f23fa08df295af61d91593ccd2dcaf5e7ba7ba07bbd7896e7194291"
    "62f4485f929dad5faeebe25c2a745ac60e2f191aa1c44aa15f0579d572b46ee0b9a6f631acad91dab4a4a7063959dc51cb33"
    "32cdafd985ee7d28172b369407a99e1aff2deef010cbbe79d08ab47ccde034eafca618c51a1b34bea785e03593f1ae44416e"
    "d82e723623a63e04bdb4e5985220ce8a0aad1f019fbff7f59af06ce0308b370e567c2ed01ab1735e3c0d781558ca518c3193"
    "2d0a85152fec946ce16fb6bdb0805b3561452ad5b7f4606d7635e9e9a6569cfe76e8164089679c3df299ab09373b9e917038"
    "23cc6dfa254a41da667296c53d23348b99f740a71953075a19d6d3b09fff2a6c1292fba8f1788085483ba1fcda7239f7dd8c"
    "092b82dda9025cbfb0ae5b37acdea773ab9b84d54dc23751f6e463758dbfe376e59221e8c1dfeb3061197e5365c44e9ba8c1"
    "049b8b56b0be895bff00761fa59c3e0db815b8bf3b503e26ceb226fe66c3b3e3070535d3678844fc50e9738c1e60f430e3ed"
    "8cd8fe2decc9cd22b2b8e901e876357f12b1d41e7732a47275ce924e2542db758be236e1766c88b7f451d46cd7b7e3f97de5"
    "8c3c48597eeddeb6259caa1ddb4d3a739bdf17f163094faf7e53396de791ddfc5a0e4f37ce82d56be1ab4e88555ba8c162f4"
    "febf392d6b64efbf58e675c3e2db35f0748be02183864f8bfc5a8c766c79b4f38ac21a1f69dfc6737443767859f63d45e10e"
    "fa570a157c7d2aacdc5c553dc45c8553ca4d55d56b6989cbba87e928e2d2a95e5f6fec22ab2b1ca24ff2307586e173aa9755"
    "169e8ee1598d1517faae8ab1b2c2a9ea27946415ddcab86d0b1e64a54553433e5656e4538e54eda4a0e0be31146325f9b487"
    "aa865851a12f76f1dcb967d0f56f31b392d975dbe3d44905bd6f70d129e62c8cbd78eadc1bbe536f805e548e552947efa097"
    "f9e4315651f8e2e3f4975c9bef33aeaa3f766a78083de855213fca4a0aef7cf0dc142b2d3c7aeadc50f0ce53bd0fc62ebcf8"
    "85a93f6d3ffad367a0f934a650968e2805775c408995394ebdc1ca8b4e9d42e3d890efb15165e9b0927f073dc76738c4cf33"
    "ccc0caf3e94630d8fac29fd0ac580e3dc956e9cb1a1d5c517a86377315fe70cb513c4014d01a638473f071e16ee8f3aacfe7"
    "83cda95a3718acd4415fc556bcf1b4affae82bacbcd0c75cf927b7be52a91cb9831e52b8c55951d1c55ee5e649e2ef315f10"
    "acdea17353174e2945df1eea65f585cce138d7dbdb5bad1cbbe38b43bdf4186f527de195d8d0b97381d3aca6104329f61e1f"
    "4f2ac589db2069bea4c59266a148ba4ed28d92c7b31755e46d4e4199bcb714d13620ea8db2ae886cd3b80b8d5b3c3b46b7a8"
    "572df755647b7e5f6f14d4ceff9628f42b16b44cf25de2af1b2422a722d6b151c4dc8d72143da7ccc736e5d43be53bd38d88"
    "e07c8c66a957a7a43d64c46f43ef4ec17390ee399848e12aa823b571fd5e527d7319ca6b8e44979a63f1e462a6991ccde963"
    "e9e6d9b9703a6db0a8847332d1f9e69958bcf95034135d8ac633d4d40c1249a49a17d3a9e65864b6792996cac412fb459ffd"
    "f38b7399d8fe4c6271f6f0fecd4d1013439ed4d2d24296ded9b9583c96b98a4cbd062deadf3abe7f24b47f74cf783014dcb3"
    "7bff751f64c155246b7c784f08f98751098df56f1b0aeedeb13f384096feeb8260f65f476bfae767628716138b694f2a1a4e"
    "79844a1eac31361b25b68d18aefd8101b20d04c74787fb2779e7fc813d135b8707f787fa47f78f8c9336b0e7dadd6419c062"
    "67338914ad1988a59373e1639e7434c547f12cc6c34be1d85c78662e8abe86706b2c1e89a6c82eabe39970264afae0dec1dd"
    "21320deedd0f9d051d9fdc4d7983dc8863d130ef61d931b6676294ab51b9f358329ada33eeebdf3b1030948f241631892713"
    "4e120b9212e418267370f7cec1b120eeb8e06e58a87fd8b08b2db87b7422b47f77ffc8209504c5b2c56ea53d915422998c46"
    "a8dce062470fa657ada230185f0acfc5229e9190273d97c8507196914985676f8cc50f79a020db45caae6152770d07890d93"
    "32bc0d08923accf51a867018c261c14149c3c72ef20e47c2734bb11b9bc3f17802468925e2cd83f1d9b9441a836ee38ed643"
    "75ffbf3623d1cce144a487aa2fd328188f47537290dacbc847a2f333b241144daa2ed3643c76281ece2ca6a23de4be8c3874"
    "38953882ae8dc3b144f3a158e6f0e24cf361be4d89747829d28c3d4cc91dbf367c63b4beb5879aafac65d6bb7aa8e30a3be4"
    "fa590fb5ff977a0977eca1b62beb94e39e3db4e9cafa8c2662f1cc15af7e145bcbeddb432d57dae14834c54b573cc5783c9c"
    "4c1f4e40a78d57d6c1187ddd1535ee21d7f00d383ecd68bc75f1e0c1682a1ac91aac6059b23d36879615abeae2048e6770ba"
    "e77ba87459b48abde672ececf02b7d46533079b68f63999d6d586c70e6c2f143cd5b1389b96838beacb6606e3b1c4e8d4717"
    "16a3f159a859942b318e54690e6bf0e86c34696c596d0e3b3837173d149e13fe95d32477ee603c133dc415f25cc24ca51693"
    "996824a79b23a7c570227e683567249c39dc43ce1cceee457ebe57f3f6ccdc8083b55a85d15462366a449a0f30b72ec6e660"
    "affab1682496123ddd1fdaa8874a7264638bf1388f9eabe7c786c4b8e6151fe02d0fb2aab9b85d57f31074b087abed2f0291"
    "315beec8a9e8c139280dd78ace4556ab9e156503a8ecb69889cd4176287a941b74f63057e883a2d170061b842d5937124bf3"
    "30dc1c5e7dad0607b679e02489d9980894641feddf3d38bc7fe76070c7ce10e519b56b8303a19da48bd84096eca1a70a719a"
    "2f7b9d5a970f3ad58f65e789c8fb37673ecfec61ac11575a9d68956d118b2072c532c79a0fa5128bc9e54695ab1a2566f8cc"
    "50e0206685d4b54a9aab4dd5d8a519c4878ac54deb498bd3e8416e84714b2e091a4ddcc864e377f5fe6d7b269018e4211bd8"
    "3f30b6677474101909af8c0d8eee190b51d7384c3e17f5891cca73049d3db134669a4dcc27b17e9e131c418c92f9810ff981"
    "6844966cd4233b4f6690e384fa776f1b242d34393a48d689ddc16b260679aea14c8c923e11daeef353c3443c7a34094f8946"
    "562f35165fb52a627b49db1be477fd5edcf57b8749df3bccab2641769159d0a95da4eec5f5afec9d224d6c249b227d2a181c"
    "9822650afce920f9a6ff4b974ae1f42521d539fdc160553c7db920307d999399de37bd2fbda171bac5d77dfdc67d4d065dbf"
    "effa7de98d8d57071a73f261b17c290f40bcfeea46a470d3fdbe29de01cd7911e2fdd96ad877b0dfb79d77b8d97fcb47781e"
    "f9918951883690b22f4e6614b6f08a1a9e49535e78968796ed73e1436932856733b125a493e148647c31994c4102173287e3"
    "c8dd62116a948526c4ecc891702ada24fdb529280d36128e871166c977a52debc7338b33e4cc364fa49b82328975e5f2c481"
    "cc0e5ef5611263b08a1cf1b871bab33dcb724522e66d9b4bccdeb832d7522c7aa4496a188c1f4cc024c859e311d8292d6e8b"
    "836124f0a6707a2e1a4d7226a73826605ac24763e9ddf01dd267a28762084633c67db7373cb7883eb361b49a239d67945132"
    "f34314e3a9fbec622a850d36c22d992351387ae2185922d9ccdf241f1bf20cda1c0fcfa3bfb42715c8c20e1e6b8211b2ca3a"
    "8a5a2471244e2a57df841b363c97462595a2bc1c8f82046a67d264e671081928e907d1304adac128b6de76109b3160ccaf1f"
    "8ca5d238d382e0ae4d65b86f88da441285446a37d74cc5f31915e023d78c16d4c5ed40669404ab401496330b32897a86aca0"
    "c66d21da8a316d28c8ad245d445532732f39bae720e5c5f8be48cfb5c6b2573a9962f1a5040e7e492cbdacc94ac3fc58fa72"
    "552319201da739739d4126c93487bc022bb7cec152fceca7a9026e139e0b7474b576fbdb367776b67677f85b3b36b7b5b4a2"
    "15720663cfb5f930fcc03c2fbd0f0571d5650b69d2c45e6a71ee35667923904516b06b89548c7b9235194ea5a33c17215392"
    "47a3345992d97b4c4ff21340e6244fc4e6e2a4093fb2f0cfe1583c4a4e7e53faa457f8d2e29170d32a1e0fda810fbb98021e"
    "aabe4cebf9041e9c133c9479a8e132f29c07c7958b213f25d39bc1540a8eada616b1b6343c251c9de72b314e95269efd2ce9"
    "ec25a263dc1827dce5c89c969ea71b4bb1a61767d222a6526126368f7d0acf27476273d82bb26412e35911bfc39a56ce86cd"
    "6008b534b49927cb623c863414323b9c0023c941f2f0085a9f3d6d565e31de49e8e2d15488631168128ccc0a1ef6dd2c087c"
    "d3fde16f244813739bf8278e4fb141afc56d34b0ac243b4aec183dc23efad101ffcdde193c03e32c7b035e38be7793d78820"
    "2211f1cd2722512198593c04d1e170da07079bbd31bd389ff606c489dee49d8fc57de164cc1b68ebdae44d1f0efb5ad1a5c5"
    "df11f677b7b67585a32d9ddd5db39dddddad1ded91839d9bc35d9d1d5d1d5de1836dfef6d6768c0aa748633274ea6e6a6bea"
    "f0211e796f21c5c26e572a59b9a2e828b82b1593f210d3e827ac5ab10a89abc660b97ec2ca5d8a069eab4470ea2d26b0d6ac"
    "48dd2bc59c3e37ae14e772faddb5c28eaf146f52cc7c52abcbee72baf25c45ae7c57b1abc055e87290c2189df1b0331e3a7e"
    "5c7b770d63f757928d698a83d125bf0e052d9eaa52e9d52a46c76b189d05dee1dfd660b6131622b3c2ec7dcc217e897f9ad1"
    "fef575cc72779df5c471cb7b75aa5965c52e86df3292ed44dbbc3b31f30686d60f6d542cefadcfa7e39bf87ff85761d64270"
    "cfb793aab01ad1dac1eb9dccf27ebb93cef36f0ab00a3eb7ca9857c88b217fbfb3843de42755656b05af14bce7baf9f84f07"
    "f8e79bdd2ebab39bfff9b9516893fbeb3e81355ec52c1702ccfa1dd0fbb730cbf97eb55acbd3f2ac0bfccfcf1a5b7786696c"
    "b3995d73f6d6be6b8edfddd73ad957fe9af16eefb52ee37de14f41dfee3278bf913cf366a2f773ca059b57caee9cf2da9c72"
    "4b4eb927a7bc3da73c9653be7eb331e761d057e5ffe366df89f29f97c07bcbbff28e94e4bbd1d7fd24de6972faee25fd6c92"
    "2fbef094d3cf2cf95649edddabfbe54bbeab9b56fdd45f526fb9a45f85ecd77bc97cc5925f22e9ce4bc60975afac87ffac91"
    "ed2a25ad92b48856cfc769f6fba47caeec774af938d9ef95f2f7b5d9ef96723b65bf5fcadffb66bf63ca3cc61cfc7ba6aa2c"
    "f3ff71660ee37b63fc7fc9158f3117ff1eaae631fe979bfb0cff02061f87ff8fb9ee31f4e0ffebad3a0c3bf27d33c936fc7f"
    "d1f93f6073bdf97761ff1f504b01021403140000000800000021001be65418861f0000443b00000b00000000000000000000"
    "00800100000000636c61737365732e646578504b0506000000000100010039000000af1f00000000"
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
