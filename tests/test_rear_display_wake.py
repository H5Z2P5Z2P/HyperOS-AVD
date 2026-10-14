"""Execute the shipped Java protocol parser and double-tap state machine."""
import hashlib
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'scripts'))
import rear_display_wake as bridge
from patch_gnss import java

SDK = Path.home() / 'Library/Android/sdk'
IDC = (REPO / 'work/os4-r3-build/work/vendor-rear-tree/'
       'extract-system-8eb9f9313bfb9951/usr/idc/virtio_input_multi_touch_7.idc')
HARNESS = r'''package io.github.hyperosavd;
import java.io.BufferedReader;
import java.io.InputStreamReader;

public class WakeHarness {
    static final class History implements RearDisplayWake.DisplayState {
        final int[] queries;
        RearDisplayWake.Snapshot observed;
        int state = 1;
        long uptime;
        History(int[] queries) { this.queries = queries; }
        void sample(int state, long uptime, boolean poll) {
            this.state = state; this.uptime = uptime;
            if (poll) observe();
        }
        RearDisplayWake.Snapshot observe() {
            observed = RearDisplayWake.DisplayBinder.observe(observed,
                    new RearDisplayWake.Snapshot(RearDisplayWake.UNIQUE_ID, 1, 1, state), uptime);
            return observed;
        }
        public RearDisplayWake.Snapshot snapshot() { queries[0]++; return observe(); }
    }
    public static void main(String[] args) throws Exception {
        BufferedReader input = new BufferedReader(new InputStreamReader(System.in, "UTF-8"));
        if (args[0].equals("idc")) {
            StringBuilder text = new StringBuilder(); String line;
            while ((line = input.readLine()) != null) text.append(line).append('\n');
            RearDisplayWake.validateIdc(text.toString()); return;
        }
        if (args[0].equals("identity")) {
            new RearDisplayWake.Snapshot(args[1], Integer.parseInt(args[2]),
                    Integer.parseInt(args[3]), 1); return;
        }
        final String[] states = args[0].split(",");
        final int[] queries = {0}, wakes = {0};
        final History history = new History(queries);
        RearDisplayWake.DisplayState display = args[0].equals("history") ? history
                : new RearDisplayWake.DisplayState() {
                    public RearDisplayWake.Snapshot snapshot() {
                        int state = Integer.parseInt(states[Math.min(queries[0]++, states.length - 1)]);
                        return new RearDisplayWake.Snapshot(RearDisplayWake.UNIQUE_ID, 1, 1, state);
                    }
                };
        RearDisplayWake.Detector detector = new RearDisplayWake.Detector(display,
                new RearDisplayWake.Wake() { public void run() { wakes[0]++; } });
        RearDisplayWake.EventReader events = new RearDisplayWake.EventReader(detector, "/dev/input/event7");
        String line;
        while ((line = input.readLine()) != null) {
            if (args[0].equals("history") && (line.startsWith("STATE ") || line.startsWith("CURRENT "))) {
                String[] value = line.split(" ");
                history.sample(Integer.parseInt(value[1]), Long.parseLong(value[2]), value[0].equals("STATE"));
            } else events.feed(line);
        }
        System.out.println("WAKES=" + wakes[0] + " QUERIES=" + queries[0]);
    }
}
'''


def event(time, code, value=0, device=False):
    kind = 'EV_SYN' if code.startswith('SYN_') else 'EV_ABS'
    prefix = '/dev/input/event7: ' if device else ''
    return f'[{time // 1000:8d}.{time % 1000:03d}000] {prefix}{kind:8s} {code:20s} {value & 0xffffffff:08x}\n'


def tap(time, duration=80, x=16000, y=12000, slot=0, coordinates=True):
    data = event(time, 'ABS_MT_SLOT', slot) + event(time, 'ABS_MT_TRACKING_ID', 17)
    if coordinates:
        data += event(time, 'ABS_MT_POSITION_X', x) + event(time, 'ABS_MT_POSITION_Y', y)
    return (data + event(time, 'SYN_REPORT')
            + event(time + duration, 'ABS_MT_TRACKING_ID', -1)
            + event(time + duration, 'SYN_REPORT'))


class RearDisplayWakeJavaTest(unittest.TestCase):
    JAVA_SOURCE = bridge.JAVA_SOURCE
    HARNESS = HARNESS

    @classmethod
    def setUpClass(cls):
        try:
            cls.java = Path(java())
        except RuntimeError as error:
            raise unittest.SkipTest(str(error))
        javac = cls.java.with_name('javac')
        if not javac.is_file():
            raise unittest.SkipTest('Host JDK javac is unavailable')
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.folder = Path(cls.temp.name)
        package = cls.folder / 'src/io/github/hyperosavd'
        package.mkdir(parents=True)
        source, harness = package / 'RearDisplayWake.java', package / 'WakeHarness.java'
        source.write_text(cls.JAVA_SOURCE)
        harness.write_text(cls.HARNESS)
        subprocess.run([str(javac), '-source', '8', '-target', '8', '-d', str(cls.folder),
                        str(source), str(harness)], check=True, capture_output=True)

    def execute(self, text, states='1', args=None, check=True):
        return subprocess.run([str(self.java), '-cp', str(self.folder),
                               'io.github.hyperosavd.WakeHarness', *(args or [states])],
                              input=text, text=True, capture_output=True, check=check)

    def test_only_two_short_stationary_taps_wake(self):
        for state in (1, 3, 4):
            with self.subTest(state=state):
                result = self.execute(tap(1000) + tap(1250, x=16200, y=12200), str(state))
                self.assertEqual(result.stdout.strip(), 'WAKES=1 QUERIES=3')

    def test_single_tap_hold_drag_and_distant_or_late_taps_do_not_wake(self):
        drag = (event(1000, 'ABS_MT_TRACKING_ID', 4)
                + event(1000, 'ABS_MT_POSITION_X', 16000)
                + event(1000, 'ABS_MT_POSITION_Y', 12000) + event(1000, 'SYN_REPORT')
                + event(1050, 'ABS_MT_POSITION_X', 24000) + event(1050, 'SYN_REPORT')
                + event(1080, 'ABS_MT_TRACKING_ID', -1) + event(1080, 'SYN_REPORT'))
        for trace in (tap(1000), tap(1000, duration=400) + tap(1550), drag + tap(1250),
                      tap(1000) + tap(1250, x=26000), tap(1000) + tap(1600)):
            with self.subTest(trace=trace):
                self.assertIn('WAKES=0', self.execute(trace).stdout)

    def test_original_time_and_panel_pixel_distance_boundaries(self):
        self.assertIn('WAKES=1', self.execute(tap(1000) + tap(1480)).stdout)
        self.assertIn('WAKES=0', self.execute(tap(1000) + tap(1481)).stdout)
        # 3592 raw X units map to 99.976 pixels; 3593 exceed 100 pixels.
        self.assertIn('WAKES=1', self.execute(tap(1000) + tap(1250, x=19592)).stdout)
        self.assertIn('WAKES=0', self.execute(tap(1000) + tap(1250, x=19593)).stdout)

    def test_awake_first_down_cannot_rewake_original_doubletap_sleep(self):
        trace = tap(1000) + tap(1250)
        for states in ('2', '2,1', '2,2,1', '5', '6', '0'):
            with self.subTest(states=states):
                self.assertIn('WAKES=0', self.execute(trace, states).stdout)
        # First/second taps arm asleep, but another route wakes before second UP.
        self.assertEqual(self.execute(trace, '1,1,2').stdout.strip(), 'WAKES=0 QUERIES=3')

    def test_delayed_awake_trace_is_rejected_by_observed_sleep_history(self):
        old_trace = 'STATE 2 900\nSTATE 1 1400\n' + tap(1000) + tap(1250)
        self.assertEqual(self.execute(old_trace, 'history').stdout.strip(), 'WAKES=0 QUERIES=2')
        # A query on DOWN must record a new sleep transition even if the poll
        # has not observed it yet. CURRENT changes only the fake Binder result.
        late_poll = 'STATE 2 900\nCURRENT 1 1400\n' + tap(1000) + tap(1250)
        self.assertIn('WAKES=0', self.execute(late_poll, 'history').stdout)
        new_trace = 'STATE 2 900\nSTATE 1 1400\n' + tap(1500) + tap(1750)
        self.assertEqual(self.execute(new_trace, 'history').stdout.strip(), 'WAKES=1 QUERIES=3')
        # Repeated observations retain the original transition time.
        repeated = ('STATE 1 900\n' + tap(1000) + 'STATE 1 1200\n' + tap(1250))
        self.assertIn('WAKES=1', self.execute(repeated, 'history').stdout)

    def test_taps_cannot_span_an_observed_wake_and_sleep_cycle(self):
        trace = ('STATE 1 900\n' + tap(1000) + 'STATE 2 1100\nSTATE 1 1200\n' + tap(1250))
        self.assertIn('WAKES=0', self.execute(trace, 'history').stdout)
        second = tap(1250)
        up = second.index(event(1330, 'ABS_MT_TRACKING_ID', -1))
        trace = ('STATE 1 900\n' + tap(1000) + second[:up]
                 + 'STATE 2 1300\nSTATE 1 1350\n' + second[up:])
        self.assertIn('WAKES=0', self.execute(trace, 'history').stdout)

    def test_unchanged_type_b_axes_and_nonzero_slot_are_retained(self):
        trace = tap(1000, slot=3) + tap(1250, slot=3, coordinates=False)
        self.assertEqual(self.execute(trace).stdout.strip(), 'WAKES=1 QUERIES=3')
        trace = trace.replace('EV_ABS', '/dev/input/event7: EV_ABS')
        self.assertIn('WAKES=1', self.execute(trace).stdout)
        axes_first = (event(1000, 'ABS_MT_POSITION_X', 16000)
                      + event(1000, 'ABS_MT_POSITION_Y', 12000)
                      + tap(1000, coordinates=False) + tap(1250, coordinates=False))
        self.assertIn('WAKES=1', self.execute(axes_first).stdout)

    def test_multitouch_and_axis_out_of_range_do_not_wake(self):
        multi = (event(1000, 'ABS_MT_TRACKING_ID', 1)
                 + event(1000, 'ABS_MT_POSITION_X', 16000)
                 + event(1000, 'ABS_MT_POSITION_Y', 12000) + event(1000, 'SYN_REPORT')
                 + event(1040, 'ABS_MT_SLOT', 1) + event(1040, 'ABS_MT_TRACKING_ID', 2)
                 + event(1040, 'ABS_MT_POSITION_X', 16100)
                 + event(1040, 'ABS_MT_POSITION_Y', 12100) + event(1040, 'SYN_REPORT')
                 + event(1080, 'ABS_MT_TRACKING_ID', -1) + event(1080, 'ABS_MT_SLOT', 0)
                 + event(1080, 'ABS_MT_TRACKING_ID', -1) + event(1080, 'SYN_REPORT'))
        self.assertIn('WAKES=0', self.execute(multi + tap(1250)).stdout)
        self.assertIn('WAKES=0', self.execute(tap(1000, x=40000) + tap(1250)).stdout)

    def test_event_device_and_dropped_events_fail_closed(self):
        wrong_device = tap(1000).replace('EV_ABS', '/dev/input/event2: EV_ABS')
        for trace in (wrong_device, event(1000, 'SYN_DROPPED'), event(1000, 'ABS_MT_SLOT', 11)):
            result = self.execute(trace, check=False)
            self.assertNotEqual(result.returncode, 0)

    def test_display_identity_and_group_fail_fast(self):
        for unique, display_id, group in ((bridge.UNIQUE_ID, 1, 0), (bridge.UNIQUE_ID, 0, 1),
                                          ('local:wrong', 1, 1)):
            result = self.execute('', args=['identity', unique, str(display_id), str(group)], check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('identity/group changed', result.stderr)

    def test_idc_requires_exact_association_and_no_single_touch_wake(self):
        valid = 'touch.displayId = ' + bridge.UNIQUE_ID + '\n'
        self.execute(valid, args=['idc'])
        for text in ('', valid * 2, valid + 'touch.wake = true\n', valid.replace(bridge.UNIQUE_ID, '1')):
            self.assertNotEqual(self.execute(text, args=['idc'], check=False).returncode, 0)
        if IDC.is_file():
            self.execute(IDC.read_text(), args=['idc'])

    @unittest.skipUnless((SDK / 'build-tools/37.0.0/d8').is_file(), 'Android D8 is unavailable')
    def test_assets_compile_and_manifest_hashes_match(self):
        edits, manifest = bridge.image_replacements(SDK, self.folder / 'assets')
        self.assertEqual(set(edits), {bridge.JAR_PATH, bridge.SCRIPT_PATH})
        jar, mode, label = edits[bridge.JAR_PATH]
        self.assertEqual((mode, label), (0o644, bridge.LABEL))
        with zipfile.ZipFile(io.BytesIO(jar)) as archive:
            self.assertEqual(archive.namelist(), ['classes.dex'])
            self.assertTrue(archive.read('classes.dex').startswith(b'dex\n'))
        self.assertEqual(manifest['jar_sha256'], hashlib.sha256(jar).hexdigest())
        self.assertEqual(manifest['script_sha256'], hashlib.sha256(bridge.LAUNCHER).hexdigest())
        self.assertEqual(manifest['state_poll_ms'], 20)
        self.assertTrue(manifest['require_down_after_observed_sleep'])
        self.assertEqual(edits[bridge.SCRIPT_PATH], (bridge.LAUNCHER, 0o755, bridge.LABEL))
        self.assertNotIn('touch.wake', bridge.LAUNCHER.decode())
        self.assertIn('"-d", "1", "keyevent", "224"', bridge.JAVA_SOURCE)
        self.assertEqual(bridge.compile_assets(SDK, self.folder / 'second-assets'), jar)


class CoreRearDisplayWakeJavaTest(RearDisplayWakeJavaTest):
    from rear_display_wake_runtime import JAVA_SOURCE
    HARNESS = HARNESS.replace('int state = 1;', 'int state = 1; Boolean interactive;').replace(
        'new RearDisplayWake.Snapshot(RearDisplayWake.UNIQUE_ID, 1, 1, state), uptime);',
        'new RearDisplayWake.Snapshot(RearDisplayWake.UNIQUE_ID, 1, 1, state, '
        'interactive != null ? interactive.booleanValue() : !(state == 1 || state == 3 || state == 4), '
        'Long.MIN_VALUE), uptime);').replace(
        'if (args[0].equals("history") && (line.startsWith("STATE ")',
        'if (args[0].equals("history") && line.startsWith("INTERACTIVE ")) {\n'
        '                String[] value = line.split(" ");\n'
        '                history.interactive = Boolean.valueOf(value[1]);\n'
        '                history.sample(history.state, Long.parseLong(value[2]), true);\n'
        '            } else if (args[0].equals("history") && (line.startsWith("STATE ")')

    def test_cold_stationary_mouse_omits_initial_axes_and_reuses_id_zero(self):
        for slot in (0, 3):
            trace = (tap(1000, slot=slot, coordinates=False) + tap(1250, slot=slot, coordinates=False))
            trace = trace.replace('00000011', '00000000')
            self.assertIn('WAKES=1', self.execute(trace).stdout)
        # A single unknown axis is stationary; the known axis still has bounds.
        first = tap(1000).replace(event(1000, 'ABS_MT_POSITION_Y', 12000), '')
        second = tap(1250).replace(event(1250, 'ABS_MT_POSITION_Y', 12000), '')
        self.assertIn('WAKES=1', self.execute(first + second).stdout)
        far = second.replace(event(1250, 'ABS_MT_POSITION_X', 16000),
                             event(1250, 'ABS_MT_POSITION_X', 24000))
        self.assertIn('WAKES=0', self.execute(first + far).stdout)

    def test_unknown_axes_cannot_cross_slots_or_become_numeric_mid_gesture(self):
        self.assertIn('WAKES=0', self.execute(tap(1000, coordinates=False)
                                             + tap(1250, slot=1, coordinates=False)).stdout)
        unknown_then_known = tap(1000, coordinates=False) + tap(1250)
        self.assertIn('WAKES=0', self.execute(unknown_then_known).stdout)

    def test_unreported_initial_slot_cannot_alias_explicit_slot_zero(self):
        implicit = ''.join(line for line in tap(1000, coordinates=False).splitlines(True)
                           if 'ABS_MT_SLOT' not in line)
        second_implicit = ''.join(line for line in tap(1250, coordinates=False).splitlines(True)
                                  if 'ABS_MT_SLOT' not in line)
        self.assertIn('WAKES=1', self.execute(implicit + second_implicit).stdout)
        self.assertIn('WAKES=0', self.execute(implicit + tap(1250, coordinates=False)).stdout)
        invalid = event(1000, 'ABS_MT_SLOT', 11)
        self.assertNotEqual(self.execute(invalid, check=False).returncode, 0)
        # Both endpoints of a candidate must share their own immutable baseline.
        first = tap(1000, coordinates=False).replace(event(1080, 'ABS_MT_TRACKING_ID', -1),
                event(1080, 'ABS_MT_POSITION_X', 16000) + event(1080, 'ABS_MT_TRACKING_ID', -1))
        self.assertIn('WAKES=0', self.execute(first + tap(1250, coordinates=False)).stdout)
        self.assertIn('WAKES=1', self.execute(first + tap(1250, coordinates=False)
                                             + tap(1500, coordinates=False)).stdout)
        # A reported invalid axis is not the sentinel for an unobserved axis.
        bad = tap(1000, x=-1) + tap(1250, coordinates=False)
        self.assertIn('WAKES=0', self.execute(bad).stdout)

    def test_initial_implicit_contact_released_by_explicit_slot_does_not_stick(self):
        # The initial contact belongs to physical slot 3, which was selected
        # before this reader opened. A second contact explicitly selects slot 0.
        trace = (event(1000, 'ABS_MT_TRACKING_ID', 0) + event(1000, 'SYN_REPORT')
                 + event(1030, 'ABS_MT_SLOT', 0) + event(1030, 'ABS_MT_TRACKING_ID', 1)
                 + event(1030, 'SYN_REPORT') + event(1060, 'ABS_MT_TRACKING_ID', -1)
                 + event(1060, 'SYN_REPORT') + event(1080, 'ABS_MT_SLOT', 3)
                 + event(1080, 'ABS_MT_TRACKING_ID', -1) + event(1080, 'SYN_REPORT'))
        self.assertIn('WAKES=0', self.execute(trace).stdout)
        self.assertIn('WAKES=1', self.execute(trace + tap(2000) + tap(2250)).stdout)
        # The same recovery applies when no second contact was introduced.
        single = (event(1000, 'ABS_MT_TRACKING_ID', 0) + event(1000, 'SYN_REPORT')
                  + event(1080, 'ABS_MT_SLOT', 3) + event(1080, 'ABS_MT_TRACKING_ID', -1)
                  + event(1080, 'SYN_REPORT'))
        self.assertIn('WAKES=0', self.execute(single).stdout)
        self.assertIn('WAKES=1', self.execute(single + tap(2000) + tap(2250)).stdout)

    def test_logical_sleep_arms_before_physical_fade_and_rejects_stale_sleep_taps(self):
        fade = ('STATE 2 900\nINTERACTIVE false 1000\n' + tap(1100) + tap(1350))
        self.assertIn('WAKES=1', self.execute(fade, 'history').stdout)
        physical = ('STATE 2 900\nINTERACTIVE false 1000\n' + tap(1100)
                    + 'STATE 4 1250\n' + tap(1350))
        self.assertIn('WAKES=1', self.execute(physical, 'history').stdout)
        awake = ('STATE 4 900\nINTERACTIVE true 1000\n' + tap(1100) + tap(1350))
        self.assertIn('WAKES=0', self.execute(awake, 'history').stdout)
        # A queued original sleep gesture cannot become a wake gesture.
        stale = 'STATE 2 900\nINTERACTIVE false 1400\n' + tap(1000) + tap(1250)
        self.assertIn('WAKES=0', self.execute(stale, 'history').stdout)
        original = ('STATE 2 900\n' + tap(1000) + 'INTERACTIVE false 1200\n' + tap(1250))
        self.assertIn('WAKES=0', self.execute(original, 'history').stdout)

    def test_original_time_and_panel_pixel_distance_boundaries(self):
        # Both DOWN->DOWN and UP->UP must match the OEM's strict 400 ms.
        self.assertIn('WAKES=1', self.execute(tap(1000) + tap(1399)).stdout)
        self.assertIn('WAKES=0', self.execute(tap(1000) + tap(1400)).stdout)
        self.assertIn('WAKES=0', self.execute(tap(1000) + tap(1250, duration=230)).stdout)
        # OEM distance uses a rectangle, including its diagonal corners.
        self.assertIn('WAKES=1', self.execute(tap(1000) + tap(1250, x=19592, y=17496)).stdout)
        self.assertIn('WAKES=0', self.execute(tap(1000) + tap(1250, x=19593)).stdout)

    def test_oem_press_duration_and_mouse_drift_are_accepted(self):
        self.assertIn('WAKES=1', self.execute(tap(1000, duration=300) + tap(1350)).stdout)
        first = (event(1000, 'ABS_MT_TRACKING_ID', 1)
                 + event(1000, 'ABS_MT_POSITION_X', 16000)
                 + event(1000, 'ABS_MT_POSITION_Y', 12000) + event(1000, 'SYN_REPORT')
                 + event(1050, 'ABS_MT_POSITION_X', 17600) + event(1050, 'SYN_REPORT')
                 + event(1080, 'ABS_MT_TRACKING_ID', -1) + event(1080, 'SYN_REPORT'))
        # 44.5 physical pixels of mouse drift exceed the old 24-pixel guard.
        self.assertIn('WAKES=1', self.execute(first + tap(1250, x=17600)).stdout)
        # Moving outside the rectangle and returning before UP matches stock.
        excursion = first.replace(event(1050, 'ABS_MT_POSITION_X', 17600),
                                  event(1040, 'ABS_MT_POSITION_X', 26000) + event(1040, 'SYN_REPORT')
                                  + event(1050, 'ABS_MT_POSITION_X', 17600))
        self.assertIn('WAKES=1', self.execute(excursion + tap(1250, x=17600)).stdout)

    def test_final_up_axes_and_each_endpoint_match_first_down(self):
        first = tap(1000)
        second = tap(1250, x=12408).replace(event(1330, 'ABS_MT_TRACKING_ID', -1),
                event(1330, 'ABS_MT_POSITION_X', 19592) + event(1330, 'ABS_MT_TRACKING_ID', -1))
        # Opposite rectangle corners are both within the first DOWN tolerance.
        self.assertIn('WAKES=1', self.execute(first + second).stdout)
        outside = second.replace(event(1330, 'ABS_MT_POSITION_X', 19592),
                                 event(1330, 'ABS_MT_POSITION_X', 24000))
        self.assertIn('WAKES=0', self.execute(first + outside).stdout)

    def test_equivalent_sleep_states_keep_one_epoch(self):
        for before, after in ((1, 3), (3, 4), (4, 1)):
            trace = f'STATE {before} 900\n' + tap(1000) + f'STATE {after} 1200\n' + tap(1250)
            self.assertIn('WAKES=1', self.execute(trace, 'history').stdout)

    def test_failed_second_up_cannot_seed_a_third_tap(self):
        dragged = tap(1200, x=17000).replace(event(1280, 'ABS_MT_TRACKING_ID', -1),
                event(1280, 'ABS_MT_POSITION_X', 26000) + event(1280, 'ABS_MT_TRACKING_ID', -1))
        self.assertIn('WAKES=0', self.execute(tap(1000) + dragged + tap(1400, x=17000)).stdout)

    @unittest.skipUnless((SDK / 'build-tools/37.0.0/d8').is_file(), 'Android D8 is unavailable')
    def test_assets_compile_and_manifest_hashes_match(self):
        from unittest.mock import patch
        import rear_display_wake_runtime as current
        assets = current.files()
        self.assertEqual(bridge.compile_assets(SDK, self.folder / 'current-assets', self.JAVA_SOURCE),
                         assets['rear-wake.jar'])
        self.assertEqual(hashlib.sha256(self.JAVA_SOURCE.encode()).hexdigest(),
                         current.COMPILED_SOURCE_SHA256)
        with patch.object(current, 'compile_assets', side_effect=AssertionError('Offline consumer')):
            self.assertEqual(current.files(), assets)
        with patch.object(current, 'JAVA_SOURCE', self.JAVA_SOURCE + '// changed'):
            with self.assertRaisesRegex(RuntimeError, 'rebuild'):
                current.files()
        with patch.object(current, 'JAR_HEX', '00'):
            with self.assertRaisesRegex(RuntimeError, 'asset changed'):
                current.files()
        self.assertIn('wakeUpWithDisplayId', self.JAVA_SOURCE)
        self.assertNotIn('"/system/bin/input"', self.JAVA_SOURCE)
        self.assertEqual(len(assets['rear-wake.tsv'].decode().splitlines()), 5)


if __name__ == '__main__':
    unittest.main()
