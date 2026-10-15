"""Verify source-independent handoff and rejection before userdata changes."""
import copy
import hashlib
import io
import importlib.util
import json
import marshal
import os
from pathlib import Path
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import bundle_runtime as protocol
import common
import manage
import setup


class BundleRuntimeTests(unittest.TestCase):
    def poison_cache(self, source, marker):
        """Create a valid timestamp cache which normal Python would execute."""
        code = compile(f"from pathlib import Path\nPath({str(marker)!r}).write_text('unverified bytecode')\n"
                       "VALUE = 'unverified bytecode'\n", str(source), 'exec')
        metadata = source.stat()
        data = (importlib.util.MAGIC_NUMBER
                + struct.pack('<III', 0, int(metadata.st_mtime), metadata.st_size)
                + marshal.dumps(code))
        cache = Path(importlib.util.cache_from_source(str(source)))
        cache.parent.mkdir(exist_ok=True)
        cache.write_bytes(data)
        return cache

    def bundle(self, directory, variant='os4-official'):
        directory.mkdir()
        source, device, family = protocol.FAMILIES[variant]
        entry = b'''import argparse, json
from pathlib import Path
p = argparse.ArgumentParser()
p.add_argument('--request'); p.add_argument('--report')
a = p.parse_args(); r = json.loads(Path(a.request).read_text())
folder = Path(r['root']) / 'backups' / 'verified-test'; folder.mkdir(parents=True)
(Path(r['root']) / 'executed').write_text('verified bundle entrypoint')
Path(a.report).write_text(json.dumps({'schema': 1, 'protocol': r['protocol'], 'backup': str(folder)}))
'''
        payloads = {'images/system.img': b'new', 'images/encryptionkey.img': b'stable-key',
                    'config/avd.ini': b'target=android-37.0\nhw.cpu.arch=arm64\nhw.ramSize=6144\n',
                    protocol.ENTRYPOINT: entry, 'runtime/scripts/manage.py': b'# new source recipes',
                    'runtime/scripts/setup.py': b'# strict source authentication',
                    'runtime/scripts/common.py': b'# portable common',
                    'tools/os4-core/context.json': b'{}', 'tools/os4-core/receipt.json': b'{}',
                    'tools/os4-app-compat/app-compat.zip': b'catalog fixture',
                    'tools/os4-app-compat/receipt.json': b'{}'}
        archive = directory / 'bundle.part001'
        with tarfile.open(archive, 'w:gz') as output:
            for name, data in payloads.items():
                item = tarfile.TarInfo(name)
                item.size = len(data)
                output.addfile(item, io.BytesIO(data))
        firmware = '4.0.999.0.XFRCNXM' if variant == 'os4-official' else setup.PAD_HYPEROS
        version = ('v9.0.0-a17-hyperos4-hongkong-r999' if variant == 'os4-official'
                   else 'pad-v9.0.0-a17-hyperos4-yingtian-r999')
        manifest = {'project': 'HyperOS-AVD', 'format': 3, 'platform': 'macos-arm64',
                    'version': version, 'variant': variant, 'source': source, 'source_device': device,
                    'android_api': 37, 'hyperos': firmware,
                    'build': {'source': source, 'device': device, 'android_api': 37, 'hyperos': firmware,
                              'adb_authentication': True},
                    'compatibility': {'install_protocol': protocol.INSTALL_PROTOCOL,
                                      'minimum_installer': protocol.PROTOCOL_MINIMUM,
                                      'userdata_family': family, 'runtime_in_bundle': True},
                    'files': {name: {'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                              for name, data in payloads.items()},
                    'parts': [{'name': archive.name, 'size': archive.stat().st_size,
                               'sha256': common.sha256(archive)}]}
        path = directory / 'manifest.json'
        path.write_text(json.dumps(manifest))
        return path, manifest

    def install(self, root, path):
        with patch('userdata_resize.check_dependencies'), patch.object(manage, 'idle'), \
                patch.object(manage, 'avd_home', return_value=root.parent / 'registry'):
            return manage.install(root, path, 'Custom_Name', 5584, Path('/sdk'), manage.hardware(6, 32, 4))

    def test_unknown_source_reaches_only_verified_runtime_without_bootstrap_registry(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            path, manifest = self.bundle(folder / 'bundle')
            with self.assertRaises(RuntimeError):
                setup.read_manifest(str(path))
            with patch('phone_profile.profile_from_build', side_effect=AssertionError('old registry used')):
                self.assertEqual(setup.read_install_manifest(str(path))[0], manifest)
                backup = self.install(folder / 'instance', path)
            self.assertEqual(backup, (folder / 'instance/backups/verified-test').resolve())
            self.assertEqual((folder / 'instance/executed').read_text(), 'verified bundle entrypoint')
            self.assertFalse((folder / 'instance/avd').exists())

    def test_pad_envelope_uses_actual_prefixed_firmware_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path, manifest = self.bundle(Path(directory) / 'bundle', 'os4-pad')
            self.assertEqual(setup.read_install_manifest(str(path))[0], manifest)
            self.assertEqual(setup.read_manifest(str(path))[0], manifest)

    def test_future_installer_version_does_not_raise_protocol_baseline(self):
        import package_release
        from test_os4_pad import build_info
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / 'local').mkdir()
            (root / 'local/build.json').write_text(json.dumps(build_info()))
            with patch.object(manage, 'VERSION', '99.0.0'):
                value = package_release.release_metadata(root, 'os4-pad')
            self.assertEqual(value['compatibility']['minimum_installer'], protocol.PROTOCOL_MINIMUM)
            self.assertEqual(value['compatibility']['install_protocol'], protocol.INSTALL_PROTOCOL)

    def test_retained_data_checks_family_key_order_and_ignores_old_source_registry(self):
        for failure in (None, 'family', 'key', 'downgrade'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                folder = Path(directory); path, manifest = self.bundle(folder / 'bundle')
                manifest['compatibility'].update(upgrade_policy=manage.FORWARD_UPGRADE_POLICY,
                    module_upgrade_preflight=manage.MODULE_UPGRADE_PREFLIGHT)
                path.write_text(json.dumps(manifest))
                root = folder / 'instance'; (root / 'local').mkdir(parents=True)
                data = root / 'avd/Custom_Name.avd'; data.mkdir(parents=True)
                userdata = data / 'userdata-qemu.img'; userdata.write_bytes(b'original personal userdata')
                old = copy.deepcopy(manifest)
                old['version'] = 'v1.0.0-a17-hyperos4-hongkong-r1'
                old['build']['hyperos'] = old['hyperos'] = '4.0.888.0.XFRCNXM'
                if failure == 'family':
                    old['compatibility']['userdata_family'] = setup.PAD_FAMILY
                elif failure == 'key':
                    old['files']['images/encryptionkey.img']['sha256'] = 'f' * 64
                elif failure == 'downgrade':
                    old['version'] = 'v99.0.0-a17-hyperos4-hongkong-r999'
                (root / 'local/installed-release.json').write_text(json.dumps(old))
                with patch.object(manage, 'validate_userdata'), \
                        patch.object(manage, 'data_size', return_value={'virtual-size': 32 * 1024**3}), \
                        patch('phone_profile.profile_from_build', side_effect=AssertionError('bootstrap registry used')):
                    if failure:
                        with self.assertRaises(RuntimeError), patch.object(manage.subprocess, 'run') as execute:
                            self.install(root, path)
                        execute.assert_not_called()
                    else:
                        self.install(root, path)
                self.assertEqual(userdata.read_bytes(), b'original personal userdata')
                self.assertEqual((root / 'executed').exists(), failure is None)

    def test_unknown_protocol_invalid_family_paths_types_and_minimum_refuse_before_execution(self):
        for case in ('protocol', 'family', 'runtime', 'entrypoint', 'traversal', 'alias', 'bool-size',
                     'part-path', 'part-duplicate', 'minimum'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                folder = Path(directory)
                path, manifest = self.bundle(folder / 'bundle')
                if case == 'protocol':
                    manifest['compatibility']['install_protocol'] = 'future-unknown-v2'
                elif case == 'family':
                    manifest['compatibility']['userdata_family'] = setup.PAD_FAMILY
                elif case == 'runtime':
                    manifest['compatibility']['runtime_in_bundle'] = False
                elif case == 'entrypoint':
                    manifest['files']['runtime/execute.py'] = manifest['files'].pop(protocol.ENTRYPOINT)
                elif case == 'traversal':
                    manifest['files']['runtime/../untrusted.py'] = manifest['files'][protocol.ENTRYPOINT]
                elif case == 'alias':
                    manifest['files']['runtime//execute.py'] = manifest['files'][protocol.ENTRYPOINT]
                elif case == 'bool-size':
                    manifest['files'][protocol.ENTRYPOINT]['size'] = True
                elif case == 'part-path':
                    manifest['parts'][0]['name'] = '../bundle.part001'
                elif case == 'part-duplicate':
                    manifest['parts'].append(copy.deepcopy(manifest['parts'][0]))
                else:
                    manifest['compatibility']['minimum_installer'] = '1.2.2'
                path.write_text(json.dumps(manifest))
                with patch.object(manage.subprocess, 'run') as execute, self.assertRaises(RuntimeError):
                    self.install(folder / 'instance', path)
                execute.assert_not_called()
                self.assertFalse((folder / 'instance').exists())

    def test_archive_hash_failure_never_executes_release_code_or_changes_userdata(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            path, manifest = self.bundle(folder / 'bundle')
            (folder / 'bundle' / manifest['parts'][0]['name']).write_bytes(b'corrupt archive')
            with patch.object(manage.subprocess, 'run') as execute, self.assertRaisesRegex(RuntimeError, 'checksum'):
                self.install(folder / 'instance', path)
            execute.assert_not_called()
            self.assertFalse((folder / 'instance/avd').exists())

    def test_cached_manifest_size_link_and_unlisted_source_tampering_block_handoff(self):
        for case in ('manifest', 'bytes', 'size', 'link', 'hardlink', 'source', 'bytecode-link', 'bytecode-fifo'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                folder = Path(directory)
                path, manifest = self.bundle(folder / 'bundle')
                root = folder / 'instance'
                target = root / 'versions' / manifest['version']
                target.mkdir(parents=True)
                with manage.scope(target):
                    setup.stage_bundle(str(path))
                entry = target / protocol.ENTRYPOINT
                if case == 'manifest':
                    saved = target / 'local/installed-release.json'
                    value = json.loads(saved.read_text()); value['hyperos'] = '4.0.998.0.XFRCNXM'
                    saved.write_text(json.dumps(value))
                elif case == 'bytes':
                    entry.write_bytes(b'x' * entry.stat().st_size)
                elif case == 'size':
                    entry.write_bytes(entry.read_bytes() + b'\n')
                elif case == 'link':
                    copied = folder / 'copied.py'; copied.write_bytes(entry.read_bytes())
                    entry.unlink(); entry.symlink_to(copied)
                elif case == 'hardlink':
                    import os
                    os.link(entry, folder / 'aliased.py')
                elif case == 'source':
                    (target / 'runtime/scripts/injected.py').write_text('raise AssertionError()')
                elif case == 'bytecode-link':
                    cache = target / 'runtime/scripts/__pycache__'; cache.mkdir()
                    (cache / 'common.pyc').symlink_to(folder / 'untrusted')
                else:
                    import os
                    cache = target / 'runtime/scripts/__pycache__'; cache.mkdir()
                    os.mkfifo(cache / 'common.pyc')
                with patch.object(manage.subprocess, 'run') as execute, self.assertRaises(RuntimeError):
                    self.install(root, path)
                execute.assert_not_called()
                self.assertFalse((root / 'executed').exists())

    def test_timestamp_valid_unlisted_bytecode_blocks_handoff_before_userdata_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            path, manifest = self.bundle(folder / 'bundle')
            root = folder / 'instance'; target = root / 'versions' / manifest['version']
            target.mkdir(parents=True)
            with manage.scope(target):
                setup.stage_bundle(str(path))
            marker = folder / 'bytecode-executed'
            self.poison_cache(target / 'runtime/scripts/common.py', marker)
            private = root / 'private-userdata'; private.write_bytes(b'personal userdata')
            with patch.object(manage.subprocess, 'run') as execute, \
                    self.assertRaisesRegex(RuntimeError, 'Unlisted bundle runtime'):
                self.install(root, path)
            execute.assert_not_called()
            self.assertEqual(private.read_bytes(), b'personal userdata')
            self.assertFalse(marker.exists())
            self.assertFalse((root / 'executed').exists())

    def test_cached_verified_handoff_stays_reusable_without_runtime_caches(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory); path, manifest = self.bundle(folder / 'bundle')
            root = folder / 'instance'
            self.install(root, path)
            target = root / 'versions' / manifest['version']
            self.assertFalse(list((target / 'runtime').rglob('__pycache__')))
            (root / 'backups/verified-test').rmdir()
            self.install(root, path)
            protocol.verify_staged(target, manifest)
            self.assertFalse(list((target / 'runtime').rglob('*.pyc')))

    def test_normal_start_and_wrapper_ignore_poisoned_cache_and_write_no_runtime_bytecode(self):
        for wrapper in (False, True):
            with self.subTest(wrapper=wrapper), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); scripts = root / 'versions/test/runtime/scripts'
                scripts.mkdir(parents=True); (root / 'local').mkdir()
                (root / 'local/manager.json').write_text(json.dumps({'runtime': 'versions/test/runtime'}))
                source = scripts / 'common.py'; source.write_text("VALUE = 'verified source'\n")
                marker, observed = root / 'poison-executed', root / 'observed'
                cache = self.poison_cache(source, marker)
                # Prove this fixture is a usable timestamp-valid Python cache.
                env = os.environ.copy()
                for key in ('PYTHONPATH', 'PYTHONHOME', 'PYTHONSTARTUP', 'PYTHONPYCACHEPREFIX'):
                    env.pop(key, None)
                subprocess.run([sys.executable, '-c', 'import common'], cwd=scripts,
                               env=env, check=True)
                self.assertTrue(marker.is_file()); marker.unlink()
                (scripts / 'launch.py').write_text("import common\nfrom pathlib import Path\n"
                    f"Path({str(observed)!r}).write_text(common.VALUE)\n")
                if wrapper:
                    manage.wrapper(root)
                    subprocess.run(['zsh', str(root / 'Start.command')], env=env, check=True)
                else:
                    manage.start({'root': root}, headless=True, skip_oobe=True)
                self.assertEqual(observed.read_text(), 'verified source')
                self.assertFalse(marker.exists())
                self.assertEqual(list(scripts.rglob('*.pyc')), [cache])
                self.assertFalse(list((root / 'local').glob('python-launch-*')))

    def test_setup_preserves_phone_and_pad_existing_hardware_and_camera_choices(self):
        for variant in ('os4-official', 'os4-pad'):
            for camera in (False, True):
                with self.subTest(variant=variant, camera=camera), tempfile.TemporaryDirectory() as directory:
                    folder = Path(directory); path, manifest = self.bundle(folder / 'bundle', variant)
                    root = folder / 'instance'; (root / 'local').mkdir(parents=True)
                    options = manage.hardware(8, 48, 2, variant=variant)
                    (root / 'local/build.json').write_text(json.dumps(manifest['build']))
                    (root / 'local/runtime.json').write_text(json.dumps({'name': 'Preserved_Name',
                        'port': 5590, 'hardware': options, 'camera_bridge': camera}))
                    with manage.scope(root), patch.dict(os.environ, {'HYPEROS_AVD_WORKSPACE': str(root)}), \
                            patch('sys.argv', ['setup.py', '--bundle', str(path)]), \
                            patch.object(setup, 'host_check'), patch.object(setup, 'port_free'), \
                            patch.object(setup, 'avd_home', return_value=folder / 'registry'), \
                            patch.object(setup, 'sdk_path', return_value=Path('/sdk')), \
                            patch('userdata_resize.check_dependencies'), \
                            patch.object(manage, 'install') as install, patch('sys.stdout', new_callable=io.StringIO):
                        setup.main()
                    self.assertEqual(install.call_args.args, (root.resolve(), str(path), 'Preserved_Name',
                                                             5590, Path('/sdk'), options))
                    self.assertEqual(install.call_args.kwargs, {'camera': camera})

    def test_child_validates_then_calls_transaction_directly_without_recursion(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            path, manifest = self.bundle(folder / 'bundle')
            root = folder / 'instance'; target = root / 'versions' / manifest['version']
            target.mkdir(parents=True)
            with manage.scope(target):
                setup.stage_bundle(str(path))
            request, report = folder / 'request.json', folder / 'report.json'
            request.write_text(json.dumps({'schema': 1, 'protocol': protocol.INSTALL_PROTOCOL,
                'root': str(root), 'target': str(target), 'name': 'Custom_Name', 'port': 5584,
                'sdk': '/sdk', 'options': manage.hardware(6, 32, 4), 'camera': False,
                'manifest_sha256': protocol.manifest_digest(manifest)}))
            backup = root / 'backups/verified-test'
            with patch.object(setup, 'read_manifest', return_value=(manifest, target)), \
                    patch.object(protocol, 'validate_runtime_assets') as assets, \
                    patch.object(manage, 'install_transaction', return_value=backup) as transaction, \
                    patch.object(manage, 'install') as recursive:
                protocol.execute_request(request, report)
            transaction.assert_called_once()
            assets.assert_called_once_with(target.resolve())
            recursive.assert_not_called()
            self.assertEqual(json.loads(report.read_text())['backup'], str(backup))
            with self.assertRaises(RuntimeError), patch.object(manage, 'install_transaction') as transaction:
                protocol.execute_request(request, report)
            transaction.assert_not_called()
            with patch.object(setup, 'read_manifest', return_value=(manifest, target)), \
                    patch.object(protocol, 'validate_runtime_assets', side_effect=RuntimeError('catalog changed')), \
                    patch.object(manage, 'install_transaction') as transaction, \
                    self.assertRaisesRegex(RuntimeError, 'catalog changed'):
                protocol.execute_request(request, report)
            transaction.assert_not_called()

    def test_legacy_manifest_uses_unchanged_strict_reader_and_transaction(self):
        import test_manager
        with tempfile.TemporaryDirectory() as directory:
            path, manifest = test_manager.ManagerTests().bundle(Path(directory) / 'bundle')
            self.assertEqual(setup.read_install_manifest(str(path)), setup.read_manifest(str(path)))
            with patch.object(manage, 'install_transaction', return_value='legacy') as transaction, \
                    patch.object(manage, 'install_via_runtime') as handoff:
                self.assertEqual(manage.install(Path('/unused'), path, 'Custom_Name', 5584, Path('/sdk'), {}), 'legacy')
            transaction.assert_called_once()
            handoff.assert_not_called()

    def test_download_and_cli_accept_future_source_before_firmware_handoff(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory); path, manifest = self.bundle(folder / 'bundle')
            part = manifest['parts'][0]
            assets = {'manifest.json': {'browser_download_url': path.as_uri(),
                'size': path.stat().st_size, 'digest': 'sha256:' + common.sha256(path)},
                part['name']: {'browser_download_url': (path.parent / part['name']).as_uri(),
                               'size': part['size']}}
            with patch('phone_profile.profile_from_build', side_effect=AssertionError('old registry used')), \
                    patch('sys.stdout', new_callable=io.StringIO):
                downloaded = manage.fetch_release({'tag_name': manifest['version'], 'asset_map': assets},
                                                  folder / 'cache')
            self.assertEqual(json.loads(downloaded.read_text()), manifest)
            arguments = ['manage.py', 'install', '--bundle', str(path), '--root', str(folder / 'instance'),
                         '--name', 'Custom_Name', '--port', '5584']
            with patch('sys.argv', arguments), patch.object(manage, 'host_check'), \
                    patch.object(manage, 'sdk_path', return_value=Path('/sdk')), \
                    patch('phone_profile.profile_from_build', side_effect=AssertionError('old registry used')), \
                    patch.object(manage, 'install') as install:
                manage.main()
            self.assertEqual(install.call_args.args[1], path.resolve())


if __name__ == '__main__':
    unittest.main()
