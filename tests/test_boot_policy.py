"""Consolidated unit tests for OS4 boot policy:
init graph parsing, boot capability gates, release preparation, and boot policy metadata.
"""
from contextlib import ExitStack
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

REPO = Path(__file__).resolve().parents[1]
ROOT = REPO
sys.path.insert(0, str(REPO / 'scripts'))

import apply_boot_service_fix as legacy
import dex2oat_cpu_policy as cpu
import os4_boot_policy as boot
import os4_pad
import package_release as release
import patch_boot_services as services
import patch_init_capabilities as gates
import phone_profile
import prepare_release_image as prepare

def digest(data):
    return hashlib.sha256(data).hexdigest()



# --- tests/test_os4_boot_policy.py ---

'Exercise the shared pre-init edit bundle without images, guests or compilers.'

class BootPolicyBundleTests(unittest.TestCase):

    def fixture(self, *, qti=True):
        graph, profiles = ({}, {})
        for path, value in gates.PROFILES.items():
            if value['capability'] == 'qti_display' and (not qti):
                continue
            row = dict(value)
            options = b'    class main\n    user system\n'
            if row['disabled']:
                options += b'    disabled\n'
            original = b'service ' + row['service'].encode() + b' /system_ext/bin/fixture\n'
            original += options + b'\n' + row['trigger']
            original += b'    start ' + row['service'].encode() + b'\n'
            original += b'\non boot\n    setprop unrelated.fixture 1\n'
            row['before'] = gates.digest(original)
            row['after'] = gates.digest(gates._transform(original, row))
            profiles[path], graph[path] = (row, original)
        graph['vendor/etc/init/vendor.fixture.rc'] = b'on boot\n    start unrelated-service\n'
        return (graph, profiles)

    def bundle(self, graph, profiles, folder, *, qti_script=b'verified fixture qti script\n', init=b'on boot\n    setprop unrelated.value 1\n', policy=b'; existing grants\n'):
        probe = folder / 'probe-fixture'
        probe.write_bytes(b'bounded native capability probe fixture')
        with patch.dict(gates.PROFILES, profiles, clear=True), patch.object(gates, 'QTI_SCRIPT_SHA256', gates.digest(qti_script)), patch.object(boot, 'kernel_probe', return_value=probe) as builder:
            edits, receipt = boot.image_replacements(graph, qti_script, init, policy, folder)
        builder.assert_called_once_with(folder / 'kernel-probe')
        return (edits, receipt)

    def test_complete_bundle_preserves_inputs_emits_narrow_helpers_and_verified_receipt(self):
        for qti in (False, True):
            with self.subTest(qti=qti), tempfile.TemporaryDirectory() as temporary:
                folder = Path(temporary)
                graph, profiles = self.fixture(qti=qti)
                preserved = dict(graph)
                edits, receipt = self.bundle(graph, profiles, folder)
                self.assertEqual(graph, preserved)
                self.assertEqual(set(receipt['targets']), set(profiles))
                for path, row in profiles.items():
                    self.assertEqual(edits[path][1:], (420, 'u:object_r:system_file:s0'))
                    self.assertEqual(hashlib.sha256(edits[path][0]).hexdigest(), row['after'])
                    self.assertEqual(receipt['targets'][path]['before'], row['before'])
                for path in (gates.SCRIPT_PATH, cpu.SYSTEM_TARGET.lstrip('/'), boot.PROBE_PATH):
                    self.assertEqual(edits[path][1:], (493, 'u:object_r:system_file:s0'))
                self.assertEqual(receipt['dex2oat'], cpu.receipt())
                self.assertEqual(receipt['qti_script_sha256'] is not None, qti)
                self.assertIn(b'    exec_start hyperos-dex2oat-cpu\n', edits[boot.INIT_PATH][0])
                self.assertIn(b'    start hyperos-init-capabilities\n', edits[boot.INIT_PATH][0])

    def test_unknown_start_route_or_known_file_content_refuses_before_probe_build(self):
        graph, profiles = self.fixture()
        cases = [dict(graph, **{'vendor/etc/init/extra.rc': b'on boot\n    exec_start millet_monitor\n'}), dict(graph, **{'vendor/etc/init/extra.rc': b'on boot\n    start ${ro.boot.service}\n'}), dict(graph, **{'vendor/etc/init/extra.rc': b'on boot\n    setprop ${ro.boot.control} millet_monitor\n'}), dict(graph, **{next(iter(profiles)): graph[next(iter(profiles))] + b'# changed\n'})]
        for candidate in cases:
            with self.subTest(candidate=candidate), patch.dict(gates.PROFILES, profiles, clear=True), patch.object(boot, 'kernel_probe') as builder:
                with self.assertRaises(RuntimeError):
                    boot.image_replacements(candidate, b'unknown', b'', b'', Path('/unused'))
                builder.assert_not_called()

    def test_missing_required_service_and_unknown_qti_script_refuse_before_probe_build(self):
        graph, profiles = self.fixture()
        cases = [({path: data for path, data in graph.items() if path != next(iter(profiles))}, b'unknown'), (graph, b'unknown')]
        for candidate, script in cases:
            with patch.dict(gates.PROFILES, profiles, clear=True), patch.object(boot, 'kernel_probe') as builder:
                with self.assertRaises(RuntimeError):
                    boot.image_replacements(candidate, script, b'', b'', Path('/unused'))
                builder.assert_not_called()

    def test_second_bundle_is_idempotent_for_already_patched_rc_init_and_policy(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            graph, profiles = self.fixture()
            edits, receipt = self.bundle(graph, profiles, folder)
            updated = {path: edits[path][0] if path in edits else data for path, data in graph.items()}
            again, second = self.bundle(updated, profiles, folder, init=edits[boot.INIT_PATH][0], policy=edits[boot.POLICY_PATH][0])
            self.assertEqual(edits, again)
            self.assertEqual(receipt, second)

    def test_conflicting_helper_service_definition_is_never_silently_appended(self):
        for name in (b'hyperos-init-capabilities', b'hyperos-dex2oat-cpu'):
            with self.subTest(name=name):
                for whitespace in (b' ', b'\t', b'   '):
                    unknown = b'service' + whitespace + name + whitespace + b'/system/bin/unknown\n    disabled\n'
                    with self.assertRaisesRegex(RuntimeError, 'Unexpected existing boot policy service'):
                        boot.append_init(unknown)
                    with self.assertRaisesRegex(RuntimeError, 'Unexpected existing boot policy service'):
                        boot.append_init(boot.append_init(b'') + unknown)

    def test_complete_graph_rejects_foreign_duplicate_helpers_before_native_builder(self):
        graph, profiles = self.fixture(qti=False)
        canonical = boot.append_init(b'')
        for body in (b'service\thyperos-init-capabilities\t/vendor/bin/foreign\n', b'service hyperos-dex2oat-cpu /vendor/bin/foreign\n', b'service \\\n    hyperos-init-capabilities /vendor/bin/foreign\n', b'"service" "hyperos-dex2oat-cpu" /vendor/bin/foreign\n', canonical):
            for also_canonical in (False, True):
                candidate = dict(graph, **{'vendor/etc/init/foreign.rc': body})
                if also_canonical:
                    candidate[boot.INIT_PATH] = canonical
                with self.subTest(body=body, also_canonical=also_canonical), patch.dict(gates.PROFILES, profiles, clear=True), patch.object(boot, 'kernel_probe') as builder:
                    with self.assertRaisesRegex(RuntimeError, 'Unexpected existing boot policy service'):
                        boot.image_replacements(candidate, None, canonical if also_canonical else b'', b'', Path('/unused'))
                    builder.assert_not_called()

    def test_effective_init_mismatch_refuses_before_native_builder(self):
        graph, profiles = self.fixture(qti=False)
        graph[boot.INIT_PATH] = b'on boot\n    setprop known 1\n'
        with patch.dict(gates.PROFILES, profiles, clear=True), patch.object(boot, 'kernel_probe') as builder:
            with self.assertRaisesRegex(RuntimeError, 'differs from its effective graph'):
                boot.image_replacements(graph, None, b'on boot\n    setprop unknown 1\n', b'', Path('/unused'))
            builder.assert_not_called()

    def test_policy_preserves_existing_grants_without_importing_runtime_stop_or_binder_permissions(self):
        original = b'; preserved\n(allow original own_type (file (read)))\n'
        policy = boot.append_policy(original)
        self.assertTrue(policy.startswith(original))
        self.assertEqual(boot.append_policy(policy), policy)
        added = policy[len(original):]
        for permission in (b'permissive', b'dontaudit', b'ctl_stop_prop', b'binder', b'service_manager', b'process (kill)', b'sysfs (file (write'):
            self.assertNotIn(permission, added)
        for line in cpu.SEPOLICY.splitlines():
            self.assertEqual(policy.splitlines().count(line), 1)

class InitGraphReaderTests(unittest.TestCase):

    def test_subtree_overlays_replacements_removals_and_qti_use_final_image_precedence(self):
        first, overlay = (Mock(), Mock())
        regular = {'mode': stat.S_IFREG | 420, 'nid': 3}
        first.walk.return_value = [('etc/init/known.rc', regular), ('etc/init/removed.rc', regular)]
        overlay.walk.side_effect = [[('system_ext', {'mode': stat.S_IFDIR | 493, 'nid': 100}), ('system_ext/etc/init/known.rc', regular), ('system_ext/etc/init/added.rc', regular)], [('etc/init/known.rc', regular), ('etc/init/added.rc', regular)]]
        replacements = {'system_ext/etc/init/known.rc': (b'explicit edit', 420, 'label'), gates.QTI_SCRIPT: (b'final QTI script', 493, 'label')}
        with patch.object(boot, 'Reader', side_effect=[first, overlay]), patch.object(boot, 'erofs', return_value=b'added') as read:
            graph = boot.init_files([('system_ext', Path('/first')), ('system_ext:system_ext', Path('/mi_ext'))], replacements, ('system_ext/etc/init/removed.rc',))
        self.assertEqual(graph, {'system_ext/etc/init/known.rc': b'explicit edit', 'system_ext/etc/init/added.rc': b'added', gates.QTI_SCRIPT: b'final QTI script'})
        self.assertEqual(read.call_args.args, (Path('/mi_ext'), '/system_ext/etc/init/added.rc'))
        overlay.walk.assert_any_call(100)
        first.close.assert_called_once()
        overlay.close.assert_called_once()

    def test_rc_graph_audits_all_image_rc_and_final_partition_precedence(self):
        first, second = (Mock(), Mock())
        first.walk.return_value = [('etc/init/known.rc', {'mode': stat.S_IFREG | 420}), ('etc/init/service.sh', {'mode': stat.S_IFREG | 493}), ('etc/not-init/no.rc', {'mode': stat.S_IFREG | 420})]
        second.walk.return_value = [('etc/init/known.rc', {'mode': stat.S_IFREG | 420})]
        with patch.object(boot, 'Reader', side_effect=[first, second]), patch.object(boot, 'erofs', return_value=b'final') as read:
            graph = boot.init_files([('system_ext', Path('/first')), ('system_ext', Path('/second'))])
        self.assertEqual(graph, {'system_ext/etc/init/known.rc': b'final', 'system_ext/etc/not-init/no.rc': b'final'})
        self.assertEqual(read.call_count, 2)
        read.assert_any_call(Path('/second'), '/etc/init/known.rc')
        read.assert_any_call(Path('/first'), '/etc/not-init/no.rc')
        first.close.assert_called_once()
        second.close.assert_called_once()

    def alias_reader(self, paths, links=None):
        reader = Mock()
        entries = [(path, {'mode': mode, 'nid': index}) for index, (path, mode) in enumerate(paths)]
        reader.walk.return_value = entries
        reader.flat.side_effect = lambda inode: (links or {})[entries[inode['nid']][0]].encode()
        return reader

    def test_valid_file_alias_reads_final_overlaid_target_without_host_path_resolution(self):
        regular, alias = (stat.S_IFREG | 420, stat.S_IFLNK | 511)
        first = self.alias_reader([('system/etc/init/alias.rc', alias), ('system/etc/shared/target.rc', regular)], {'system/etc/init/alias.rc': '../shared/target.rc'})
        second = self.alias_reader([('etc/shared/target.rc', regular)])
        with patch.object(boot, 'Reader', side_effect=[first, second]), patch.object(boot, 'erofs', return_value=b'final target') as read:
            graph = boot.init_files([('', Path('/base')), ('system', Path('/overlay'))])
        self.assertEqual(graph, {'system/etc/init/alias.rc': b'final target', 'system/etc/shared/target.rc': b'final target'})
        read.assert_called_once_with(Path('/overlay'), '/etc/shared/target.rc')
        first.close.assert_called_once()
        second.close.assert_called_once()

    def test_file_alias_can_follow_directory_alias_and_explicit_final_replacement(self):
        alias, directory, regular = (stat.S_IFLNK | 511, stat.S_IFDIR | 493, stat.S_IFREG | 420)
        reader = self.alias_reader([('system/etc/init/alias.rc', alias), ('system/shared', alias), ('product/shared', directory), ('product/shared/target.rc', regular)], {'system/etc/init/alias.rc': '/system/shared/target.rc', 'system/shared': '/product/shared'})
        replacement = {'product/shared/target.rc': (b'explicit final target', 420, 'preserved-label')}
        with patch.object(boot, 'Reader', return_value=reader), patch.object(boot, 'erofs') as read:
            graph = boot.init_files([('', Path('/image'))], replacement)
        self.assertEqual(graph, {'system/etc/init/alias.rc': b'explicit final target', 'product/shared/target.rc': b'explicit final target'})
        read.assert_not_called()
        reader.close.assert_called_once()

    def test_unsafe_alias_cycle_escape_missing_or_nonregular_target_is_refused(self):
        alias, directory = (stat.S_IFLNK | 511, stat.S_IFDIR | 493)
        alias_path = 'system/etc/init/alias.rc'
        cases = [([(alias_path, alias)], {alias_path: 'alias.rc'}), ([(alias_path, alias), ('system/etc/init/other.rc', alias)], {alias_path: 'other.rc', 'system/etc/init/other.rc': 'alias.rc'}), ([(alias_path, alias)], {alias_path: '../../../../outside.rc'}), ([(alias_path, alias)], {alias_path: '/../../outside.rc'}), ([(alias_path, alias)], {alias_path: '../missing.rc'}), ([(alias_path, alias), ('system/target', directory)], {alias_path: '/system/target'}), ([(alias_path, alias)], {alias_path: ''}), ([(alias_path, alias)], {alias_path: '/system/invalid\x00target.rc'})]
        for paths, links in cases:
            with self.subTest(links=links):
                reader = self.alias_reader(paths, links)
                with patch.object(boot, 'Reader', return_value=reader), patch.object(boot, 'erofs') as read:
                    with self.assertRaises(RuntimeError):
                        boot.init_files([('', Path('/image'))])
                    read.assert_not_called()
                reader.close.assert_called_once()

    def test_shadowed_or_removed_bad_alias_is_not_resolved_from_a_stale_layer(self):
        alias, regular = (stat.S_IFLNK | 511, stat.S_IFREG | 420)
        first = self.alias_reader([('system/etc/init/known.rc', alias), ('system/etc/init/removed.rc', alias)], {'system/etc/init/known.rc': '/missing/target.rc', 'system/etc/init/removed.rc': '/missing/target.rc'})
        second = self.alias_reader([('etc/init/known.rc', regular)])
        with patch.object(boot, 'Reader', side_effect=[first, second]), patch.object(boot, 'erofs', return_value=b'final') as read:
            graph = boot.init_files([('', Path('/base')), ('system', Path('/overlay'))], removals=('system/etc/init/removed.rc',))
        self.assertEqual(graph, {'system/etc/init/known.rc': b'final'})
        read.assert_called_once_with(Path('/overlay'), '/etc/init/known.rc')

    def test_reader_is_closed_after_rc_read_failure(self):
        reader = Mock()
        reader.walk.return_value = [('system/etc/init/init.rc', {'mode': stat.S_IFREG | 420})]
        with patch.object(boot, 'Reader', return_value=reader), patch.object(boot, 'erofs', side_effect=RuntimeError('unreadable rc')):
            with self.assertRaisesRegex(RuntimeError, 'unreadable rc'):
                boot.init_files([('', Path('/image'))])
        reader.close.assert_called_once()

    def test_directory_alias_and_recursive_imports_cannot_hide_non_rc_start_paths(self):
        regular, alias, directory = (stat.S_IFREG | 420, stat.S_IFLNK | 511, stat.S_IFDIR | 493)
        reader = self.alias_reader([('system/etc/init/main.rc', regular), ('system/etc/init/hw', alias), ('product/routes', directory), ('product/routes/hidden.conf', regular), ('product/routes/deeper.settings', regular)], {'system/etc/init/hw': '/product/routes'})
        bodies = {'/system/etc/init/main.rc': b'import /system/etc/init/hw/hidden.conf\n', '/product/routes/hidden.conf': b'import /product/routes/deeper.settings\n', '/product/routes/deeper.settings': b'on boot\n    start iorapd\n'}
        with patch.object(boot, 'Reader', return_value=reader), patch.object(boot, 'erofs', side_effect=lambda image, path: bodies[path]) as read:
            graph = boot.init_files([('', Path('/image'))])
        self.assertEqual(graph['system/etc/init/hw/hidden.conf'], bodies['/product/routes/hidden.conf'])
        self.assertEqual(graph['product/routes/deeper.settings'], bodies['/product/routes/deeper.settings'])
        read.assert_any_call(Path('/image'), '/product/routes/hidden.conf')
        with patch.object(boot, 'kernel_probe') as builder:
            with self.assertRaisesRegex(RuntimeError, 'Unreviewed init service start path'):
                boot.image_replacements(graph, None, b'', b'', Path('/unused'))
            builder.assert_not_called()

    def test_continued_imports_refuse_before_a_non_rc_leaf_can_be_hidden(self):
        regular = stat.S_IFREG | 420
        main = 'system/etc/init/main.rc'
        hidden = 'product/routes/hidden.conf'
        cases = (b'import \\\n    /product/routes/hidden.conf\n', b'import /product/routes/hid\\\nden.conf\n', b'im\\\nport /product/routes/hidden.conf\n', b'"import" \\\n    /product/routes/hidden.conf\n', b'import /product/routes/${ro.hardware}.\\\nconf\n', b'import \\\r\n    /product/routes/hidden.conf\r\n', b'im\\\r\nport /product/routes/hidden.conf\r\n')
        for body in cases:
            with self.subTest(body=body):
                reader = self.alias_reader([(main, regular), (hidden, regular)])
                with patch.object(boot, 'Reader', return_value=reader), patch.object(boot, 'erofs', return_value=body) as read:
                    with self.assertRaisesRegex(RuntimeError, 'Unsupported continued init import'):
                        boot.init_files([('', Path('/image'))])
                read.assert_called_once_with(Path('/image'), '/' + main)
                reader.close.assert_called_once()

    def test_comment_ending_in_backslash_cannot_mask_a_non_rc_import(self):
        regular = stat.S_IFREG | 420
        main, hidden = ('system/etc/init/main.rc', 'product/routes/hidden.conf')
        for ending in (b'\n', b'\r\n'):
            body = b'on boot' + ending + b'    write /sys/x 1 # comment \\' + ending
            body += ('import /' + hidden).encode() + ending
            reader = self.alias_reader([(main, regular), (hidden, regular)])
            with self.subTest(ending=ending), patch.object(boot, 'Reader', return_value=reader), patch.object(boot, 'erofs', return_value=body) as read:
                with self.assertRaisesRegex(RuntimeError, 'Ambiguous commented init continuation'):
                    boot.init_files([('', Path('/image'))])
            read.assert_called_once_with(Path('/image'), '/' + main)
            reader.close.assert_called_once()

    def test_escaped_terminal_backslash_keeps_a_non_rc_import_independent(self):
        regular = stat.S_IFREG | 420
        main, hidden = ('system/etc/init/main.rc', 'product/routes/hidden.conf')
        for ending in (b'\n', b'\r\n'):
            bodies = {'/' + main: b'on boot' + ending + b'    write /sys/x literal \\\\' + ending + ('import /' + hidden).encode() + ending, '/' + hidden: b'on boot\n    start iorapd\n'}
            reader = self.alias_reader([(main, regular), (hidden, regular)])
            with self.subTest(ending=ending), patch.object(boot, 'Reader', return_value=reader), patch.object(boot, 'erofs', side_effect=lambda image, path: bodies[path]) as read:
                graph = boot.init_files([('', Path('/image'))])
            self.assertEqual(graph[hidden], bodies['/' + hidden])
            self.assertEqual(read.call_count, 2)
            with self.assertRaisesRegex(RuntimeError, 'Unreviewed init service start path'):
                gates.audit_start_commands(graph)

    def test_recursive_continued_import_is_refused_after_literal_non_rc_import(self):
        regular = stat.S_IFREG | 420
        main, nested = ('system/etc/init/main.rc', 'product/routes/nested.conf')
        reader = self.alias_reader([(main, regular), (nested, regular)])
        bodies = {'/' + main: ('import /' + nested + '\n').encode(), '/' + nested: b'import \\\n    /product/routes/hidden.conf\n'}
        with patch.object(boot, 'Reader', return_value=reader), patch.object(boot, 'erofs', side_effect=lambda image, path: bodies[path]) as read:
            with self.assertRaisesRegex(RuntimeError, 'Unsupported continued init import'):
                boot.init_files([('', Path('/image'))])
        self.assertEqual(read.call_count, 2)
        reader.close.assert_called_once()

    def test_dynamic_imports_audit_all_possible_final_non_rc_targets_without_guessed_properties(self):
        regular = stat.S_IFREG | 420
        paths = ['system/etc/init/main.rc', 'product/routes/init.ranchu.conf', 'product/routes/init.hardware.conf', 'product/routes/unrelated.bin']
        reader = self.alias_reader([(path, regular) for path in paths])
        bodies = {'/' + paths[0]: b'import /product/routes/init.${ro.boot.hardware:-ranchu}.conf\n', '/' + paths[1]: b'on boot\n    start unrelated-service\n', '/' + paths[2]: b'on boot\n    start millet_monitor\n'}
        with patch.object(boot, 'Reader', return_value=reader), patch.object(boot, 'erofs', side_effect=lambda image, path: bodies[path]) as read:
            graph = boot.init_files([('', Path('/image'))])
        self.assertEqual(set(graph), set(paths[:3]))
        self.assertEqual(read.call_count, 3)
        with self.assertRaisesRegex(RuntimeError, 'Unreviewed init service start path'):
            gates.audit_start_commands(graph)

    def test_optional_missing_imports_and_missing_leaf_after_directory_alias_are_skipped(self):
        regular, alias = (stat.S_IFREG | 420, stat.S_IFLNK | 511)
        reader = self.alias_reader([('system/etc/init/main.rc', regular), ('odm', alias)], {'odm': '/vendor/odm'})
        main = b'import /init.ramdisk-missing.rc\nimport /odm/etc/ueventd.rc\nimport /vendor/etc/init/hw/init.${ro.hardware}.rc\n'
        with patch.object(boot, 'Reader', return_value=reader), patch.object(boot, 'erofs', return_value=main) as read:
            graph = boot.init_files([('', Path('/image'))])
        self.assertEqual(graph, {'system/etc/init/main.rc': main})
        read.assert_called_once_with(Path('/image'), '/system/etc/init/main.rc')

    def test_dynamic_non_rc_import_resolves_its_static_directory_alias_before_matching(self):
        regular, alias, directory = (stat.S_IFREG | 420, stat.S_IFLNK | 511, stat.S_IFDIR | 493)
        reader = self.alias_reader([('system/etc/init/main.rc', regular), ('system/etc/init/hw', alias), ('product/routes', directory), ('product/routes/init.ranchu.conf', regular)], {'system/etc/init/hw': '/product/routes'})
        bodies = {'/system/etc/init/main.rc': b'import /system/etc/init/hw/init.${ro.hardware}.conf\n', '/product/routes/init.ranchu.conf': b'on boot\n    start iorapd\n'}
        with patch.object(boot, 'Reader', return_value=reader), patch.object(boot, 'erofs', side_effect=lambda image, path: bodies[path]):
            graph = boot.init_files([('', Path('/image'))])
        self.assertEqual(set(graph), {'system/etc/init/main.rc', 'product/routes/init.ranchu.conf'})
        with self.assertRaisesRegex(RuntimeError, 'Unreviewed init service start path'):
            gates.audit_start_commands(graph)

    def test_invalid_import_syntax_escape_or_alias_cycle_is_refused(self):
        regular, alias = (stat.S_IFREG | 420, stat.S_IFLNK | 511)
        for command in (b'import\n', b'import /system/first.rc /system/second.rc\n', b'import "/system/missing.rc\n', b'import /../../outside.conf\n', b'import /system/${unknown\n', b'import /system/invalid\x00name.conf\n', b'import /system/${ro.hardware}/hidden.conf\n', b'import /system/loop/hidden.conf\n'):
            with self.subTest(command=command):
                reader = self.alias_reader([('system/etc/init/main.rc', regular), ('system/loop', alias)], {'system/loop': '/system/loop'})
                with patch.object(boot, 'Reader', return_value=reader), patch.object(boot, 'erofs', return_value=command):
                    with self.assertRaises(RuntimeError):
                        boot.init_files([('', Path('/image'))])
                reader.close.assert_called_once()

    def test_helper_definition_file_alias_is_rejected_as_duplicate_effective_owner(self):
        regular, alias = (stat.S_IFREG | 420, stat.S_IFLNK | 511)
        alias_path = 'system/etc/init/helper-alias.rc'
        reader = self.alias_reader([(boot.INIT_PATH, regular), (alias_path, alias)], {alias_path: '/' + boot.INIT_PATH})
        canonical = boot.append_init(b'')
        with patch.object(boot, 'Reader', return_value=reader), patch.object(boot, 'erofs', return_value=canonical) as read:
            graph = boot.init_files([('', Path('/image'))])
        self.assertEqual(graph, {boot.INIT_PATH: canonical, alias_path: canonical})
        read.assert_called_once()
        with patch.object(boot, 'kernel_probe') as builder:
            with self.assertRaisesRegex(RuntimeError, 'Unexpected existing boot policy service'):
                boot.image_replacements(graph, None, canonical, b'', Path('/unused'))
            builder.assert_not_called()

if __name__ == '__main__':
    unittest.main()


# --- tests/test_boot_policy_prepare.py ---

'Verify data-neutral packed boot-policy staging without proprietary images.'

class SharedBootEditsTests(unittest.TestCase):

    def test_final_graph_uses_existing_firmware_edits_and_preserves_prior_repairs(self):
        raw, vendor, work = (Path('/accepted/system.img'), Path('/accepted/vendor.img'), Path('/policy'))
        init, policy = (b'previous firmware init edits', b'previous firmware policy edits')
        edits = {boot.INIT_PATH: (init, 420, 'preserved-label'), boot.POLICY_PATH: (policy, 420, 'preserved-label'), 'system/framework/accepted.jar': (b'existing DEX repair', 420, 'preserved-label')}
        original = edits.copy()
        graph = {boot.INIT_PATH: init, gates.QTI_SCRIPT: b'final QTI script'}
        extra = {'system/etc/hyperos-init-capabilities.sh': (b'boot helper', 493, 'system-file-label')}
        receipt = {'schema': 1, 'targets': {'fixture': {'after': 'verified'}}}

        def init_files(partitions, replacements):
            self.assertEqual(partitions, [('', raw), ('vendor', vendor)])
            self.assertEqual(replacements, original)
            return graph
        with patch.object(boot, 'init_files', side_effect=init_files) as reader, patch.object(boot, 'image_replacements', return_value=(extra, receipt)) as bundle, patch.object(prepare, 'erofs', return_value=b'original raw bytes'):
            result = prepare.shared_boot_edits(raw, vendor, edits, work)
        reader.assert_called_once()
        bundle.assert_called_once_with(graph, b'final QTI script', init, policy, work)
        self.assertEqual(result, receipt)
        self.assertEqual(edits, dict(original, **extra))

    def test_init_graph_includes_every_accepted_logical_partition(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            for name in ('system', 'vendor', 'odm', 'vendor_dlkm'):
                (folder / (name + '.img')).write_bytes(('original ' + name).encode())
            edits = {}
            receipt = {'schema': 1, 'targets': {'fixture': {}}}
            with patch.object(boot, 'init_files', return_value={}) as reader, patch.object(boot, 'image_replacements', return_value=({}, receipt)), patch.object(prepare, 'erofs', return_value=b'original bytes'):
                self.assertEqual(prepare.shared_boot_edits(folder / 'system.img', folder / 'vendor.img', edits, folder / 'policy'), receipt)
            reader.assert_called_once_with([('', folder / 'system.img'), ('vendor', folder / 'vendor.img'), ('odm', folder / 'odm.img'), ('vendor_dlkm', folder / 'vendor_dlkm.img')], {})

    def test_retained_kernel_helper_is_refreshed_only_from_known_input_to_canonical_output(self):
        import apply_boot_service_fix as legacy
        import image_kernel_services as current
        generated = current.image_script()
        init = services.BOOT_INIT
        helper = current.PATH.lstrip('/')
        for old_input, error in ((legacy.PERF_SCRIPT.read_bytes(), None), (generated, None), (b'unknown old helper', 'existing image kernel helper')):
            with self.subTest(error=error, source=digest(old_input)):
                edits = {boot.INIT_PATH: (init, 420, 'old-label'), helper: (old_input, 493, 'old-label')}
                with patch.object(boot, 'init_files', return_value={boot.INIT_PATH: init}), patch.object(boot, 'image_replacements', return_value=({}, {'schema': 1})) as bundle, patch.object(prepare, 'erofs', return_value=b'raw bytes'):
                    if error is None:
                        prepare.shared_boot_edits(Path('/raw/system.img'), Path('/raw/vendor.img'), edits, Path('/work'))
                        self.assertEqual(edits[helper], (generated, 493, 'u:object_r:system_file:s0'))
                        self.assertEqual(digest(edits[helper][0]), current.image_script_sha256())
                        bundle.assert_called_once()
                    else:
                        with self.assertRaisesRegex(RuntimeError, error):
                            prepare.shared_boot_edits(Path('/raw/system.img'), Path('/raw/vendor.img'), edits, Path('/work'))
                        self.assertEqual(edits[helper][0], old_input)
                        bundle.assert_not_called()

    def test_invalid_canonical_recipe_cannot_generate_a_refreshed_helper(self):
        import apply_boot_service_fix as legacy
        import image_kernel_services as current
        prior = legacy.PERF_SCRIPT.read_bytes()
        init = services.BOOT_INIT
        helper = current.PATH.lstrip('/')
        edits = {boot.INIT_PATH: (init, 420, 'old-label'), helper: (prior, 493, 'old-label')}
        receipt = services.image_receipt()
        receipt['targets']['services']['after'] = 'unreviewed-producer-output'
        with patch.object(boot, 'init_files', return_value={boot.INIT_PATH: init}), patch.object(boot, 'image_replacements') as bundle, patch.object(prepare, 'erofs', return_value=b'raw bytes'), patch.object(services, 'image_receipts', return_value=(receipt,)):
            with self.assertRaisesRegex(RuntimeError, 'Invalid image kernel-service prerequisite'):
                prepare.shared_boot_edits(Path('/raw/system.img'), Path('/raw/vendor.img'), edits, Path('/work'))
            self.assertEqual(edits[helper][0], prior)
            bundle.assert_not_called()

    def test_kernel_helper_tab_duplicate_or_foreign_owner_refuses_before_bundle(self):
        canonical = services.BOOT_INIT
        tabbed = canonical.replace(b'service hyperos-kernel-services ', b'service\thyperos-kernel-services\t')
        folded = canonical.replace(b'service hyperos-kernel-services ', b'service \\\n    hyperos-kernel-services ')
        quoted = canonical.replace(b'service hyperos-kernel-services ', b'"service" "hyperos-kernel-services" ')
        cases = [(tabbed, {boot.INIT_PATH: tabbed}), (canonical + canonical, {boot.INIT_PATH: canonical + canonical}), (canonical, {boot.INIT_PATH: canonical, 'vendor/etc/init/foreign.rc': tabbed}), (canonical, {boot.INIT_PATH: canonical, 'product/routes/hidden.conf': tabbed}), (canonical, {boot.INIT_PATH: canonical, 'product/routes/hidden.conf': folded}), (canonical, {boot.INIT_PATH: canonical, 'product/routes/hidden.conf': quoted})]
        for init, graph in cases:
            with self.subTest(graph=graph):
                edits = {boot.INIT_PATH: (init, 420, 'preserved-label')}
                with patch.object(boot, 'init_files', return_value=graph), patch.object(boot, 'image_replacements') as bundle, patch.object(prepare, 'erofs', return_value=b'raw bytes'):
                    with self.assertRaisesRegex(RuntimeError, 'Unknown existing image kernel helper service'):
                        prepare.shared_boot_edits(Path('/raw/system.img'), Path('/raw/vendor.img'), edits, Path('/work'))
                    self.assertEqual(edits[boot.INIT_PATH][0], init)
                    bundle.assert_not_called()

class PackedBootPolicyPreparationTests(unittest.TestCase):

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.source, self.output = (self.root / 'source', self.root / 'output')
        for directory in ('images', 'local', 'avd', 'config', 'tools'):
            (self.source / directory).mkdir(parents=True)
        self.packed = self.source / 'images/system.img'
        self.packed.write_bytes(b'original packed firmware')
        for path, data in {'avd/userdata-qemu.img.qcow2': b'encrypted private user data', 'avd/encryptionkey.img': b'private encryption key', 'config/avd.ini': b'custom device settings', 'tools/owned-helper': b'original executable'}.items():
            (self.source / path).write_bytes(data)
        value = os4_pad.PROFILE
        self.info = {'source': os4_pad.SOURCE, 'device': value['device'], 'hyperos': value['hyperos'], 'archive_sha256': value['source_archive_sha256'], 'display': value['display'], 'model_xml_sha256': value['model_xml_sha256'], 'identity_source_sha256': value['source_sha256'], 'system_sha256': digest(self.packed.read_bytes()), 'retained': {'fixture': True}}
        self.partitions = {'system': b'original raw system', 'vendor': b'original vendor', 'system_dlkm': b'original modules', 'vendor_dlkm': b'additional logical partition', 'odm': b'additional OEM logical partition'}
        self.receipt = {'schema': 1, 'targets': {'fixture': {'after': 'known'}}}
        self.edits = {'system/etc/hyperos-init-capabilities.sh': (b'audited capability helper', 493, 'u:object_r:system_file:s0')}
        self.builds, self.packs, self.boot_inputs = ([], [], [])
        self.write_info()

    def write_info(self):
        (self.source / 'local/build.json').write_text(json.dumps(self.info))

    def source_files(self):
        return {str(path.relative_to(self.source)): path.read_bytes() for path in self.source.rglob('*') if path.is_file()}

    def pipeline(self, *, corrupt_read=False, mutate_source=False):
        stack = ExitStack()
        self.addCleanup(stack.close)

        def unpack(source, destination):
            self.assertEqual(source, self.packed)
            self.assertEqual(destination.parent.parent, self.output)
            destination.mkdir(parents=True)
            for name, data in self.partitions.items():
                (destination / (name + '.img')).write_bytes(data)

        def read(image, path):
            if image.name == 'system-fixed.img':
                return b'incorrect candidate data' if corrupt_read else self.builds[-1]['edits'][path.lstrip('/')][0]
            self.assertEqual(image.name, 'system.img')
            if path == '/' + boot.INIT_PATH:
                return b'original init\n'
            if path == '/' + boot.POLICY_PATH:
                return b'original policy\n'
            self.assertIn(path, {entry[0] for entry in services.TARGETS.values()})
            return ('original DEX target ' + path).encode()

        def shared(raw, vendor, edits, work):
            self.assertEqual(raw.parent.name, 'accepted')
            self.assertEqual(vendor, raw.with_name('vendor.img'))
            self.assertEqual(work, raw.parent.parent / 'policy')
            self.boot_inputs.append(edits.copy())
            edits.update(self.edits)
            return self.receipt

        def build(destination, partitions, tree, edits):
            self.assertEqual(partitions, [('', destination.parent / 'accepted/system.img')])
            self.builds.append({'edits': edits.copy(), 'partitions': partitions})
            destination.write_bytes(b'updated raw firmware')

        def pack(source, destination, partitions):
            self.assertEqual(source, self.packed)
            self.packs.append([(name, path.read_bytes()) for name, path in partitions])
            destination.write_bytes(b'updated packed firmware')
            if mutate_source:
                self.packed.write_bytes(b'concurrent firmware replacement')
        self.unpack_mock = stack.enter_context(patch.object(prepare, 'unpack', side_effect=unpack))
        stack.enter_context(patch.object(prepare, 'erofs', side_effect=read))
        self.boot_mock = stack.enter_context(patch.object(prepare, 'shared_boot_edits', side_effect=shared))
        self.build_mock = stack.enter_context(patch.object(prepare, 'build', side_effect=build))
        self.pack_mock = stack.enter_context(patch.object(prepare, 'pack', side_effect=pack))
        return stack

    def test_stage_pins_original_firmware_retains_all_partitions_and_never_copies_userdata(self):
        original = self.source_files()
        self.pipeline()
        prepare.prepare_boot_policy(self.source, self.output)
        self.assertEqual(self.source_files(), original)
        self.assertEqual({str(path.relative_to(self.output)) for path in self.output.rglob('*') if path.is_file()}, {'images/system.img', 'local/build.json', 'local/boot-policy-source.json'})
        self.assertFalse(list(self.output.glob('boot-policy-*')))
        packed = dict(self.packs[0])
        self.assertEqual(packed['system'], b'updated raw firmware')
        self.assertEqual({name: packed[name] for name in self.partitions if name != 'system'}, {name: data for name, data in self.partitions.items() if name != 'system'})
        self.assertEqual(self.builds[0]['edits'], self.edits)
        value = json.loads((self.output / 'local/build.json').read_text())
        self.assertEqual(value['retained'], self.info['retained'])
        self.assertEqual(value['boot_policy'], self.receipt)
        self.assertEqual(value['system_sha256'], digest(b'updated packed firmware'))
        self.assertEqual(value['raw_sha256'], digest(b'updated raw firmware'))
        proof = json.loads((self.output / 'local/boot-policy-source.json').read_text())
        self.assertEqual(proof, {'system_sha256': digest(b'original packed firmware'), 'boot_policy': self.receipt})

    def test_owned_original_pad_without_packed_receipt_still_records_snapshot_pin(self):
        del self.info['system_sha256']
        self.write_info()
        original = self.source_files()
        self.pipeline()
        prepare.prepare_boot_policy(self.source, self.output)
        self.assertEqual(self.source_files(), original)
        proof = json.loads((self.output / 'local/boot-policy-source.json').read_text())
        self.assertEqual(proof['system_sha256'], digest(b'original packed firmware'))

    def test_present_packed_receipt_mismatch_refuses_before_output_or_unpack(self):
        self.info['system_sha256'] = digest(b'foreign image')
        self.write_info()
        self.pipeline()
        with self.assertRaisesRegex(RuntimeError, 'differs from its build receipt'):
            prepare.prepare_boot_policy(self.source, self.output)
        self.assertFalse(self.output.exists())
        self.unpack_mock.assert_not_called()

    def test_foreign_source_refuses_before_output_or_unpack(self):
        self.info['source'] = 'foreign-workspace'
        self.write_info()
        self.pipeline()
        with self.assertRaises(RuntimeError):
            prepare.prepare_boot_policy(self.source, self.output)
        self.assertFalse(self.output.exists())
        self.unpack_mock.assert_not_called()

    def test_unknown_pad_version_or_identity_refuses_before_output_or_unpack(self):
        self.pipeline()
        original = self.info.copy()
        for key, value in (('hyperos', 'OS4.999.0.0.UNKNOWN'), ('archive_sha256', 'unknown'), ('model_xml_sha256', 'unknown'), ('identity_source_sha256', {}), ('display', {'width': 100, 'height': 100, 'density': 100})):
            with self.subTest(key=key):
                self.info = dict(original, **{key: value})
                self.write_info()
                with self.assertRaisesRegex(RuntimeError, 'source-pinned official yingtian'):
                    prepare.prepare_boot_policy(self.source, self.output)
                self.assertFalse(self.output.exists())
        self.unpack_mock.assert_not_called()

    def test_phone_profile_is_always_validated_even_when_legacy_fixes_already_exist(self):
        self.info.update(source='official-hongkong-ota', hyperos='4.999.0.0.UNKNOWN', boot_service_fix={'accepted': True})
        self.write_info()
        self.pipeline()
        with self.assertRaisesRegex(RuntimeError, 'Unsupported official hongkong firmware'):
            prepare.prepare_boot_policy(self.source, self.output)
        self.assertFalse(self.output.exists())
        self.unpack_mock.assert_not_called()

    def test_same_nested_and_existing_workspaces_are_rejected_before_mutation(self):
        original = self.source_files()
        self.pipeline()
        for output in (self.source, self.source / 'nested', self.root, self.source / 'images'):
            with self.subTest(output=output), self.assertRaisesRegex(RuntimeError, 'new separate sibling'):
                prepare.prepare_boot_policy(self.source, output)
        self.assertEqual(self.source_files(), original)
        self.unpack_mock.assert_not_called()

    def test_candidate_verification_failure_prevents_pack_or_acceptance_receipts(self):
        original = self.source_files()
        self.pipeline(corrupt_read=True)
        with self.assertRaisesRegex(RuntimeError, 'Boot policy image verification failed'):
            prepare.prepare_boot_policy(self.source, self.output)
        self.assertEqual(self.source_files(), original)
        self.pack_mock.assert_not_called()
        self.assertFalse((self.output / 'local/build.json').exists())
        self.assertFalse((self.output / 'local/boot-policy-source.json').exists())
        self.assertFalse(list(self.output.glob('boot-policy-*')))

    def test_source_hash_is_rechecked_after_packing_before_acceptance_receipts(self):
        private = {path: self.source_files()[path] for path in ('avd/userdata-qemu.img.qcow2', 'avd/encryptionkey.img')}
        self.pipeline(mutate_source=True)
        with self.assertRaisesRegex(RuntimeError, 'Source firmware changed'):
            prepare.prepare_boot_policy(self.source, self.output)
        self.assertFalse((self.output / 'local/build.json').exists())
        self.assertFalse((self.output / 'local/boot-policy-source.json').exists())
        self.assertFalse(list(self.output.glob('boot-policy-*')))
        for path, data in private.items():
            self.assertEqual((self.source / path).read_bytes(), data)

    def test_original_phone_stage_preserves_all_four_pinned_dex_repairs_before_shared_policy(self):
        selected = phone_profile.profile('4.0.18.0.XFRCNXM')
        self.info.update(source='official-hongkong-ota', device='hongkong', hyperos=selected['hyperos'], archive_sha256=selected['archive_sha256'])
        self.write_info()
        extra = {path.lstrip('/'): (('patched ' + name).encode(), 420, 'u:object_r:system_file:s0') for name, (path, _, _) in services.TARGETS.items()}
        legacy = {'targets': {name: {'after': 'known'} for name in services.TARGETS}}
        original = self.source_files()
        self.pipeline()
        with patch.object(services, 'image_replacements', return_value=(extra, legacy)) as legacy_patch:
            prepare.prepare_boot_policy(self.source, self.output)
        self.assertEqual(self.source_files(), original)
        self.assertEqual(set(legacy_patch.call_args.args[0]), set(services.TARGETS))
        shared_input = self.boot_inputs[0]
        for path, edit in extra.items():
            self.assertEqual(shared_input[path], edit)
            self.assertEqual(self.builds[0]['edits'][path], edit)
        self.assertEqual(shared_input[boot.INIT_PATH][0], b'original init\n' + services.BOOT_INIT)
        self.assertEqual(shared_input[boot.POLICY_PATH][0], b'original policy\n' + services.BOOT_SEPOLICY)
        value = json.loads((self.output / 'local/build.json').read_text())
        self.assertEqual(value['boot_service_fix'], legacy)
        self.assertEqual(value['boot_policy'], self.receipt)

if __name__ == '__main__':
    unittest.main()


# --- tests/test_boot_policy_release.py ---

'Verify claimed shared boot policies against actual bytes and the init graph.'

class BootPolicyReleaseTests(unittest.TestCase):

    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        rows, self.fixed = ({}, {})
        for path, row in gates.PROFILES.items():
            original = ('service ' + row['service'] + ' /system/bin/example\n' + ('    disabled\n' if row['disabled'] else '') + '    class main\n').encode() + row['trigger'] + ('    start ' + row['service'] + '\n').encode()
            fixed = gates._transform(original, row)
            rows[path] = {**row, 'before': digest(original), 'after': digest(fixed)}
            self.fixed[path] = fixed
        self.stack.enter_context(patch.dict(gates.PROFILES, rows, clear=True))
        self.probe = b'small verified probe fixture\n'
        self.qti = b'audited QTI script fixture\n'
        self.stack.enter_context(patch.object(services, 'PROBE_SHA256', digest(self.probe)))
        self.stack.enter_context(patch.object(gates, 'QTI_SCRIPT_SHA256', digest(self.qti)))

    def fixture(self, qti=False):
        targets = list(gates.PROFILES) if qti else list(gates.PROFILES)[:2]
        marker = {'schema': 1, 'targets': {path: {'before': gates.PROFILES[path]['before'], 'after': gates.PROFILES[path]['after'], 'capability': gates.PROFILES[path]['capability']} for path in targets}, 'script': {'path': gates.SCRIPT_PATH, 'sha256': digest(gates.SCRIPT_SOURCE.read_bytes())}, 'qti_script_sha256': digest(self.qti) if qti else None, 'dex2oat': cpu.receipt()}
        init = b'on boot\n    setprop unrelated keep\n' + gates.BOOT_INIT + cpu.BOOT_INIT
        graph = {path: self.fixed[path] for path in targets}
        graph[boot.INIT_PATH] = init
        files = {'/' + path: data for path, data in graph.items()}
        files['/' + gates.SCRIPT_PATH] = gates.SCRIPT_SOURCE.read_bytes()
        files[cpu.SYSTEM_TARGET] = cpu.policy_script()
        files['/' + boot.PROBE_PATH] = self.probe
        files['/' + boot.POLICY_PATH] = boot.HELPER_POLICY + cpu.SEPOLICY
        if qti:
            files['/' + gates.QTI_SCRIPT] = self.qti
        return (marker, files, graph)

    def test_absent_marker_does_not_reinterpret_old_releases(self):
        read = Mock()
        self.assertEqual(release.verify_boot_policy({}, read), 0)
        read.assert_not_called()

    def test_phone_and_pad_verify_actual_sources_and_keep_the_receipt(self):
        for qti, count in ((False, 7), (True, 9)):
            with self.subTest(qti=qti):
                marker, files, graph = self.fixture(qti)
                self.assertEqual(release.verify_boot_policy({'boot_policy': marker}, files.__getitem__, graph), count)
                self.assertEqual(release.validate_boot_policy_receipt(marker), marker)
        self.assertIn('boot_policy', release.BUILD_KEYS)

    def test_unknown_or_incomplete_receipts_are_rejected_before_reading(self):
        marker, _, _ = self.fixture()
        values = [None, [], {}, {**marker, 'schema': 999}, {**marker, 'probe_sha256': 'unknown'}]
        for key in marker:
            value = copy.deepcopy(marker)
            del value[key]
            values.append(value)
        value = copy.deepcopy(marker)
        value['targets'].pop(next(iter(value['targets'])))
        values.append(value)
        for value in values:
            with self.subTest(value=value), self.assertRaisesRegex(RuntimeError, 'boot policy'):
                release.validate_boot_policy_receipt(value)

    def test_every_claimed_file_must_match_its_actual_checksum(self):
        marker, files, graph = self.fixture(True)
        for path in ('/' + gates.SCRIPT_PATH, cpu.SYSTEM_TARGET, '/' + boot.PROBE_PATH, '/' + gates.QTI_SCRIPT, *('/' + item for item in marker['targets'])):
            with self.subTest(path=path):
                changed = {**files, path: files[path] + b'changed'}
                with self.assertRaisesRegex(RuntimeError, 'checksum mismatch'):
                    release.verify_boot_policy({'boot_policy': marker}, changed.__getitem__, graph)

    def test_missing_extra_or_alternate_helper_definitions_cannot_pass(self):
        marker, files, graph = self.fixture()
        path = '/' + boot.INIT_PATH
        for change in (files[path].replace(gates.BOOT_INIT, b''), files[path] + cpu.BOOT_INIT, files[path] + b'\nservice hyperos-init-capabilities /system/bin/another\n'):
            with self.subTest(change=change):
                changed_graph = {**graph, boot.INIT_PATH: change}
                with self.assertRaisesRegex(RuntimeError, 'Missing or duplicate'):
                    release.verify_boot_policy({'boot_policy': marker}, {**files, path: change}.__getitem__, changed_graph)
        with self.assertRaisesRegex(RuntimeError, 'Missing or duplicate'):
            release.verify_boot_policy({'boot_policy': marker}, files.__getitem__, {**graph, 'vendor/etc/init/alias.rc': cpu.BOOT_INIT})
        for declaration in (b'service \\\n    hyperos-dex2oat-cpu /system/bin/foreign\n', b'"service" "hyperos-init-capabilities" /system/bin/foreign\n'):
            with self.subTest(declaration=declaration):
                with self.assertRaisesRegex(RuntimeError, 'Missing or duplicate'):
                    release.verify_boot_policy({'boot_policy': marker}, files.__getitem__, {**graph, 'vendor/routes/hidden-helper': declaration})

    def test_complete_graph_cannot_omit_qti_or_add_unguarded_start_routes(self):
        marker, files, graph = self.fixture(True)
        missing = copy.deepcopy(marker)
        del missing['targets']['product/etc/init/init.qti.display.rc']
        missing['qti_script_sha256'] = None
        with self.assertRaisesRegex(RuntimeError, 'service targets'):
            release.verify_boot_policy({'boot_policy': missing}, files.__getitem__, graph)
        with self.assertRaisesRegex(RuntimeError, 'Unreviewed init service start'):
            release.verify_boot_policy({'boot_policy': marker}, files.__getitem__, {**graph, 'vendor/etc/init/extra.rc': b'on boot\n    restart iorapd\n'})
        with self.assertRaisesRegex(RuntimeError, 'Unreviewed init service start'):
            release.verify_boot_policy({'boot_policy': marker}, files.__getitem__, {**graph, 'vendor/etc/imported-starts': b'on boot\n    start iorapd\n'})
        with self.assertRaisesRegex(RuntimeError, 'Missing or duplicate'):
            release.verify_boot_policy({'boot_policy': marker}, files.__getitem__, {**graph, 'vendor/etc/imported-helper': cpu.BOOT_INIT})

    def test_enforcing_rules_and_effective_init_identity_are_required(self):
        marker, files, graph = self.fixture()
        policy = '/' + boot.POLICY_PATH
        with self.assertRaisesRegex(RuntimeError, 'enforcing rule'):
            release.verify_boot_policy({'boot_policy': marker}, {**files, policy: files[policy].replace(cpu.SEPOLICY.splitlines()[0] + b'\n', b'')}.__getitem__, graph)
        with self.assertRaisesRegex(RuntimeError, 'effective graph'):
            release.verify_boot_policy({'boot_policy': marker}, files.__getitem__, {**graph, boot.INIT_PATH: b'different init'})

    def test_retained_phone_helper_requires_the_new_policy_without_old_opt_out(self):
        marker, files, graph = self.fixture()
        init = files['/' + boot.INIT_PATH] + services.BOOT_INIT
        files['/' + boot.INIT_PATH] = init
        graph[boot.INIT_PATH] = init
        from image_kernel_services import image_script
        files['/system/etc/hyperos-kernel-services.sh'] = image_script()
        release.verify_boot_policy({'boot_policy': marker}, files.__getitem__, graph)
        files['/system/etc/hyperos-kernel-services.sh'] = b'old property mutator'
        with self.assertRaisesRegex(RuntimeError, 'conflicts with shared boot policy'):
            release.verify_boot_policy({'boot_policy': marker}, files.__getitem__, graph)

    def test_foreign_folded_legacy_helper_is_rejected_even_without_direct_starts(self):
        marker, files, graph = self.fixture()
        for declaration in (b'service \\\n    hyperos-kernel-services /system/bin/foreign\n', b'"service" "hyperos-kernel-services" /system/bin/foreign\n'):
            with self.subTest(declaration=declaration):
                with self.assertRaisesRegex(RuntimeError, 'Unexpected legacy helper'):
                    release.verify_boot_policy({'boot_policy': marker}, files.__getitem__, {**graph, 'vendor/routes/hidden-helper': declaration})

class LegacyBootServiceReleaseTests(unittest.TestCase):

    def test_published_receipt_accepts_only_known_helpers_and_new_policy_requires_current(self):
        files = {path: ('fixture-' + name).encode() for name, (path, _, _) in services.TARGETS.items()}
        after = {name: digest(files[path]) for name, (path, _, _) in services.TARGETS.items()}
        probe = b'pinned probe fixture'
        with patch.object(services, 'AFTER', after), patch.object(services, 'PROBE_SHA256', digest(probe)), patch.object(services, 'SERVICE_RECIPES', {services.TARGETS['services'][1]: after['services']}):
            marker = {'schema': 1, 'firmware': 'OS4.0.18.0.XFRCNXM', 'targets': {name: {'path': path, 'before': before, 'after': after[name]} for name, (path, before, _) in services.TARGETS.items()}, 'probe_sha256': digest(probe)}
            files['/system/bin/hyperos_kernel_probe'] = probe
            files['/system_ext/etc/init/init.hyperos_avd.rc'] = services.BOOT_INIT
            files['/system_ext/etc/selinux/system_ext_sepolicy.cil'] = services.BOOT_SEPOLICY
            current = legacy.PERF_SCRIPT.read_bytes()
            block = b"if [ ! -e /dev/iorap_dev ]; then\n    # Use the service's own documented opt-out; retain data and other preloaders.\n    setprop persist.sys.stability.PrereadEnable false\n    setprop ctl.stop iorapd\nfi\n"
            previous = current.replace(b'PROBE=${1:-', block + b'PROBE=${1:-', 1)
            self.assertEqual(digest(previous), legacy.LEGACY_KERNEL_SCRIPT_SHA256)
            from phone_profile import profile
            build = {'hyperos': '4.0.18.0.XFRCNXM', 'boot_service_fix': marker, 'archive_sha256': profile('4.0.18.0.XFRCNXM')['archive_sha256']}
            for helper in (previous, current):
                files['/system/etc/hyperos-kernel-services.sh'] = helper
                release.verify_boot_services(build, files.__getitem__)
            files['/system/etc/hyperos-kernel-services.sh'] = previous
            with self.assertRaisesRegex(RuntimeError, 'checksum mismatch'):
                release.verify_boot_services({**build, 'boot_policy': {'current': True}}, files.__getitem__)
            files['/system/etc/hyperos-kernel-services.sh'] = current
            release.verify_boot_services({**build, 'boot_policy': {'current': True}}, files.__getitem__)
            files['/system/etc/hyperos-kernel-services.sh'] = b'unknown mutation'
            with self.assertRaisesRegex(RuntimeError, 'checksum mismatch'):
                release.verify_boot_services(build, files.__getitem__)

if __name__ == '__main__':
    unittest.main()
