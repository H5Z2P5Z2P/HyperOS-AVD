"""Exercise standard KernelSU delivery without a guest or proprietary payload."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / 'scripts'))
import package_native_module as package
import dex2oat_cpu_policy as cpu_policy


class NativeModulePackageTests(unittest.TestCase):
    def test_boot_catalog_uses_complete_canonical_image_receipts(self):
        from patch_boot_services import image_receipts
        files = package.module_files()
        rows = [row.split('|') for row in files['boot-prerequisites.tsv'].decode().splitlines()]
        self.assertEqual(rows.pop(0), ['schema', '1'])
        declared = {row[1]: int(row[2]) for row in rows if row[0] == 'recipe'}
        groups = {identity: {} for identity in declared}
        for row in rows:
            if row[0] == 'file':
                self.assertNotIn(row[2], groups[row[1]])
                groups[row[1]][row[2]] = row[3]
        expected = []
        for receipt in image_receipts():
            pins = {item['path']: item['after'] for item in receipt['targets'].values()}
            pins['/system/bin/hyperos_kernel_probe'] = receipt['probe_sha256']
            expected.append(pins)
        self.assertCountEqual(list(groups.values()), expected)
        self.assertTrue(all(len(group) == declared[identity] == 5 for identity, group in groups.items()))
        self.assertEqual(hashlib.sha256(files['boot-prerequisites.tsv']).hexdigest(),
                         json.loads(files['manifest.json'])['files_sha256']['boot-prerequisites.tsv'])

    def test_boot_catalog_cannot_broaden_unknown_or_duplicate_receipts(self):
        import patch_boot_services
        receipt = patch_boot_services.image_receipt()
        with patch.object(patch_boot_services, 'image_receipts', return_value=(receipt, receipt)):
            with self.assertRaisesRegex(RuntimeError, 'Duplicate'):
                package.boot_prerequisites()
        receipt['probe_sha256'] = 'a' * 64
        with patch.object(patch_boot_services, 'image_receipts', return_value=(receipt,)), \
                patch.object(patch_boot_services, 'validate_image_receipt',
                             side_effect=RuntimeError('Unsupported boot service image receipt.')) as validate:
            with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
                package.boot_prerequisites()
            validate.assert_called_once_with(receipt)

    def test_deterministic_zip_is_self_contained_and_checked(self):
        with tempfile.TemporaryDirectory() as temporary:
            first, second = Path(temporary) / 'a.zip', Path(temporary) / 'b.zip'
            one, two = package.package(first), package.package(second)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(one['sha256'], two['sha256'])
            with zipfile.ZipFile(first) as archive:
                names = archive.namelist()
                self.assertEqual(len(names), len(set(names)))
                self.assertIn('customize.sh', names)
                self.assertIn('post-fs-data.sh', names)
                self.assertIn('service.sh', names)
                self.assertIn('skip_mount', names)
                self.assertFalse(any(name.startswith('system/') for name in names))
                self.assertFalse(any(name.endswith(('.so', '.apk', '.jar')) for name in names))
                for row in archive.read('SHA256SUMS').decode().splitlines():
                    expected, name = row.split('  ', 1)
                    self.assertEqual(hashlib.sha256(archive.read(name)).hexdigest(), expected)
                    self.assertNotEqual(name, 'customize.sh')
                manifest = json.loads(archive.read('manifest.json'))
                self.assertEqual(manifest['id'], package.MODULE_ID)
                self.assertFalse(manifest['automatic_reboot'])
                self.assertEqual(manifest['catalog_sha256'], hashlib.sha256(archive.read('catalog.json')).hexdigest())
                for name in names:
                    self.assertFalse(Path(name).is_absolute())
                    self.assertNotIn('..', Path(name).parts)
                    if name.endswith('.sh'):
                        self.assertEqual((archive.getinfo(name).external_attr >> 16) & 0o777, 0o755)

    def test_every_packaged_shell_script_parses(self):
        with tempfile.TemporaryDirectory() as temporary:
            for name, body in package.module_files().items():
                if name.endswith('.sh'):
                    target = Path(temporary) / Path(name).name
                    target.write_bytes(body)
                    result = subprocess.run(['sh', '-n', str(target)], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_cpu_helper_is_self_contained_and_bound_to_installed_integrity_manifest(self):
        files = package.module_files()
        name = 'dex2oat-cpu-policy.sh'
        self.assertEqual(files[name], cpu_policy.policy_script())
        manifest = json.loads(files['manifest.json'])
        self.assertEqual(manifest['revision'], package.REVISION)
        self.assertEqual(manifest['files_sha256'][name], hashlib.sha256(files[name]).hexdigest())
        checked = dict(row.split('  ', 1)[::-1]
                       for row in files['SHA256SUMS'].decode().splitlines())
        self.assertEqual(checked[name], manifest['files_sha256'][name])
        self.assertNotIn(name, manifest['install_only_files'])
        self.assertFalse((REPO / 'modules/native-compat' / name).exists(),
                         'The module must reuse the canonical CPU helper, not a second copy.')

    def test_foreign_template_ownership_is_rejected_before_cpu_policy_delivery(self):
        import shutil
        with tempfile.TemporaryDirectory() as temporary:
            template = Path(temporary) / 'template'
            shutil.copytree(REPO / 'modules/native-compat', template)
            props = template / 'module.prop'
            props.write_text(props.read_text().replace('id=' + package.MODULE_ID, 'id=unrelated_module'))
            output = Path(temporary) / 'module.zip'
            with self.assertRaisesRegex(RuntimeError, 'ownership'):
                package.package(output, template=template)
            self.assertFalse(output.exists())
            self.assertFalse(output.with_name(output.name + '.next').exists())

    def test_package_does_not_follow_an_output_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            original = Path(temporary) / 'original'
            original.write_text('preserved')
            link = Path(temporary) / 'module.zip'
            link.symlink_to(original)
            with self.assertRaisesRegex(RuntimeError, 'non-regular'):
                package.package(link)
            self.assertEqual(original.read_text(), 'preserved')

    def test_release_source_list_carries_module_templates(self):
        import package_release
        paths = package_release.runtime_files()
        for name in ('runtime.sh', 'module.prop', 'customize.sh', 'post-fs-data.sh', 'service.sh'):
            self.assertEqual(paths['modules/native-compat/' + name], REPO / 'modules/native-compat' / name)
        self.assertEqual(paths['config/dex2oat_cpu_policy.sh'], cpu_policy.POLICY)
        self.assertEqual(paths['scripts/dex2oat_cpu_policy.py'], REPO / 'scripts/dex2oat_cpu_policy.py')

    def test_lost_staging_race_preserves_the_other_packager_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'module.zip'
            staging = output.with_name(output.name + '.next')
            original_open = Path.open

            def racing_open(path, mode='r', *args, **kwargs):
                if path == staging and mode == 'xb':
                    with original_open(path, 'wb') as other:
                        other.write(b'other operation')
                    raise FileExistsError(str(path))
                return original_open(path, mode, *args, **kwargs)

            with patch.object(Path, 'open', racing_open):
                with self.assertRaises(FileExistsError):
                    package.package(output)
            self.assertEqual(staging.read_bytes(), b'other operation')
            self.assertFalse(output.exists())

    def test_installed_checksums_survive_kernel_su_customizer_removal(self):
        import shutil
        checker = shutil.which('sha256sum') or shutil.which('gsha256sum')
        if checker is None:
            self.skipTest('A SHA256SUMS-compatible host verifier is unavailable.')
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name, data in package.module_files().items():
                path = directory / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            (directory / 'customize.sh').unlink()
            result = subprocess.run([checker, '-c', 'SHA256SUMS'], cwd=directory,
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
