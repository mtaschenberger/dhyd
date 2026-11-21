import os
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import dhydlib as d

class Integration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=Path(__file__).parent.parent)
        self.addCleanup(self.tmp.cleanup)
        mount = patch.object(d, 'mounted_network', return_value=True)
        mount.start()
        self.addCleanup(mount.stop)
        base = Path(self.tmp.name)
        self.project = base / 'project'
        self.root = base / 'nas'
        self.project.mkdir(); self.root.mkdir()
        (self.project / 'README.md').write_text('readme')
        (self.project / '.hidden').write_text('secret')
        (self.project / 'folder').mkdir()
        (self.project / 'folder' / 'file').write_text('contents')
        (self.project / 'link').symlink_to('folder/file')

    def test_round_trip(self):
        d.backup(self.project, self.root, yes=True)
        self.assertEqual({p.name for p in self.project.iterdir()}, {'README.md', 'DHYD.md'})
        d.hydrate(self.project, self.root)
        self.assertEqual((self.project / '.hidden').read_text(), 'secret')
        self.assertEqual((self.project / 'folder/file').read_text(), 'contents')
        self.assertTrue((self.project / 'link').is_symlink())
        self.assertFalse((self.project / 'DHYD.md').exists())

    def empty_project(self):
        # Move disposable fixture contents aside, preserving the original path.
        saved = self.project.parent / 'saved'
        self.project.rename(saved)
        self.project.mkdir()

    def test_backup_only_restore_latest_via_cli(self):
        d.backup(self.project, self.root, backup_only=True)
        (self.project / '.hidden').write_text('latest')
        d.backup(self.project, self.root, backup_only=True)
        self.empty_project()
        with patch.dict(os.environ, {'DHYD_BACKUP_ROOT': str(self.root)}):
            self.assertEqual(d.main('hyd', ['--backup', str(self.project)]), 0)
        self.assertEqual((self.project / '.hidden').read_text(), 'latest')
        self.assertEqual((self.project / 'folder/file').read_text(), 'contents')
        self.assertTrue((self.project / 'link').is_symlink())
        self.assertFalse((self.project / d.MARKER).exists())

    def test_backup_restore_refuses_nonempty_and_preserves_marker(self):
        d.backup(self.project, self.root, backup_only=True)
        self.empty_project()
        for name in ('other', d.MARKER):
            with self.subTest(name=name):
                (self.project / name).write_text('mine')
                with self.assertRaises(d.Error): d.hydrate_backup(self.project, self.root)
                self.assertEqual((self.project / name).read_text(), 'mine')
                (self.project / name).unlink()

    def test_backup_restore_invalid_latest_does_not_create_marker(self):
        generation = d.backup(self.project, self.root, backup_only=True)
        slot = d.location(self.root, self.project)
        self.empty_project()
        for latest in ('', '.', '..', '../escape', generation + '\nother', 'missing'):
            with self.subTest(latest=latest):
                (slot / 'LATEST').write_text(latest + '\n')
                with self.assertRaises((d.Error, OSError)): d.hydrate_backup(self.project, self.root)
                self.assertFalse((self.project / d.MARKER).exists())
        (slot / 'LATEST').write_text(generation + '\n')
        (slot / 'generations' / generation / 'COMPLETE').unlink()
        with self.assertRaises((d.Error, OSError)): d.hydrate_backup(self.project, self.root)
        self.assertFalse((self.project / d.MARKER).exists())

    def test_backup_restore_failure_leaves_recovery_marker(self):
        generation = d.backup(self.project, self.root, backup_only=True)
        self.empty_project()
        with patch.object(d, 'rename_exclusive', side_effect=d.Error('injected')):
            with self.assertRaises(d.Error): d.hydrate_backup(self.project, self.root)
        self.assertEqual(d.read_marker(self.project)['generation'], generation)
        d.hydrate(self.project, self.root)
        self.assertEqual((self.project / '.hidden').read_text(), 'secret')

    def test_backup_restore_corrupt_object_before_marker(self):
        d.backup(self.project, self.root, backup_only=True)
        obj = d.location(self.root, self.project) / 'objects' / hashlib.sha256(b'secret').hexdigest()
        obj.write_text('corrupt')
        self.empty_project()
        with self.assertRaises(d.Error): d.hydrate_backup(self.project, self.root)
        self.assertEqual(list(self.project.iterdir()), [])

    def test_backup_restore_marker_collision_race_is_preserved(self):
        d.backup(self.project, self.root, backup_only=True)
        self.empty_project()
        original = d.write_exclusive
        def collide(path, text):
            if path == self.project / d.MARKER:
                path.write_text('concurrent marker')
            return original(path, text)
        with patch.object(d, 'write_exclusive', side_effect=collide):
            with self.assertRaises(FileExistsError): d.hydrate_backup(self.project, self.root)
        self.assertEqual((self.project / d.MARKER).read_text(), 'concurrent marker')

    def test_backup_restore_publication_collision_preserves_file_and_marker(self):
        d.backup(self.project, self.root, backup_only=True)
        self.empty_project()
        original = d.rename_exclusive
        def collide(src, dst):
            if dst.name == '.hidden': dst.write_text('concurrent')
            return original(src, dst)
        with patch.object(d, 'rename_exclusive', side_effect=collide):
            with self.assertRaises(d.Error): d.hydrate_backup(self.project, self.root)
        self.assertEqual((self.project / '.hidden').read_text(), 'concurrent')
        self.assertTrue((self.project / d.MARKER).exists())

    def test_backup_only_is_incremental_and_preserves_contents(self):
        g1 = d.backup(self.project, self.root, backup_only=True)
        slot = d.location(self.root, self.project)
        before = {p.name: (p.stat().st_ino, p.stat().st_mtime_ns) for p in (slot / 'objects').iterdir()}
        (self.project / '.hidden').write_text('changed')
        g2 = d.backup(self.project, self.root, backup_only=True)
        after = {p.name: (p.stat().st_ino, p.stat().st_mtime_ns) for p in (slot / 'objects').iterdir()}
        self.assertNotEqual(g1, g2)
        self.assertEqual(len(after), len(before) + 1)
        self.assertTrue(all(after[k] == v for k, v in before.items()))
        self.assertEqual((slot / 'objects' / hashlib.sha256(b'secret').hexdigest()).read_text(), 'secret')
        g3 = d.backup(self.project, self.root, yes=True)
        self.assertEqual(after, {p.name: (p.stat().st_ino, p.stat().st_mtime_ns) for p in (slot / 'objects').iterdir()})
        self.assertTrue((slot / 'generations' / g3 / 'COMPLETE').exists())
        d.hydrate(self.project, self.root)
        self.assertEqual((self.project / '.hidden').read_text(), 'changed')

    def test_modes_restored_even_if_backup_modes_differ(self):
        (self.project / 'folder/file').chmod(0o751)
        (self.project / 'folder').chmod(0o750)
        d.backup(self.project, self.root, yes=True)
        objects = d.location(self.root, self.project) / 'objects'
        for item in objects.iterdir(): item.chmod(0o600)
        d.hydrate(self.project, self.root)
        self.assertEqual((self.project / 'folder/file').stat().st_mode & 0o7777, 0o751)
        self.assertEqual((self.project / 'folder').stat().st_mode & 0o7777, 0o750)

    def test_manifest_tamper_refuses_restore(self):
        g = d.backup(self.project, self.root, yes=True)
        manifest = d.location(self.root, self.project) / 'generations' / g / 'manifest.json'
        manifest.write_text('{}')
        with self.assertRaises(d.Error): d.hydrate(self.project, self.root)
        self.assertTrue((self.project / d.MARKER).exists())

    def test_mode_change_during_backup_refuses_deletion(self):
        original = d.store_objects
        def change(*a):
            original(*a)
            (self.project / 'folder/file').chmod(0o700)
        with patch.object(d, 'store_objects', side_effect=change):
            with self.assertRaises(d.Error): d.backup(self.project, self.root, yes=True)
        self.assertTrue((self.project / 'folder/file').exists())

    def test_quarantine_mode_change_is_retained(self):
        original = d.check_inventory
        def change(root, *a, **kw):
            if root.name == d.QUARANTINE: (root / 'folder/file').chmod(0o700)
            return original(root, *a, **kw)
        with patch.object(d, 'check_inventory', side_effect=change):
            with self.assertRaises(d.Error): d.backup(self.project, self.root, yes=True)
        self.assertTrue((self.project / d.QUARANTINE / 'folder/file').exists())

    def test_inventory_catches_missing_entry_independently_of_rsync(self):
        original = d.store_objects
        def missing(*a):
            original(*a)
            (self.project / '.hidden').unlink()
        with patch.object(d, 'store_objects', side_effect=missing):
            with self.assertRaisesRegex(d.Error, 'Inventory'): d.backup(self.project, self.root, yes=True)
        self.assertFalse((self.project / d.MARKER).exists())

    def test_existing_marker_rejected(self):
        (self.project / 'DHYD.md').write_text('mine')
        with self.assertRaises(d.Error): d.backup(self.project, self.root, yes=True)
        self.assertEqual((self.project / 'DHYD.md').read_text(), 'mine')

    def test_failed_verification_never_removes_files(self):
        with patch.object(d, 'verify_objects', side_effect=d.Error('injected mismatch')):
            with self.assertRaises(d.Error): d.backup(self.project, self.root, yes=True)
        self.assertTrue((self.project / '.hidden').exists())
        self.assertFalse((self.project / d.MARKER).exists())

    def test_conflict_and_readme_edits_refused(self):
        d.backup(self.project, self.root, yes=True)
        (self.project / 'new').write_text('do not overwrite')
        with self.assertRaises(d.Error): d.hydrate(self.project, self.root)
        (self.project / 'new').unlink()
        (self.project / 'README.md').write_text('edited')
        with self.assertRaises(d.Error): d.hydrate(self.project, self.root)
        self.assertEqual((self.project / 'README.md').read_text(), 'edited')

    def test_corrupt_nas_before_deletion_retains_quarantine(self):
        original = d.verify_objects
        def corrupt(slot, manifest):
            if (self.project / d.QUARANTINE).exists():
                (slot / 'objects' / manifest['.hidden'][2]).write_text('corrupt')
            return original(slot, manifest)
        with patch.object(d, 'verify_objects', side_effect=corrupt):
            with self.assertRaises(d.Error): d.backup(self.project, self.root, yes=True)
        self.assertEqual((self.project / d.QUARANTINE / '.hidden').read_text(), 'secret')

    def test_corrupt_nas_after_backup_refuses_restore(self):
        d.backup(self.project, self.root, yes=True)
        objects = d.location(self.root, self.project) / 'objects'
        (objects / hashlib.sha256(b'secret').hexdigest()).write_text('xxxxxx')
        with self.assertRaises(d.Error): d.hydrate(self.project, self.root)
        self.assertTrue((self.project / d.MARKER).exists())
        self.assertFalse((self.project / '.hidden').exists())

    def test_corrupt_staged_copy_refuses_publication(self):
        d.backup(self.project, self.root, yes=True)
        original = d.stage_objects
        def corrupt(slot, manifest, stage):
            original(slot, manifest, stage)
            (stage / '.hidden').write_text('xxxxxx')
        with patch.object(d, 'stage_objects', side_effect=corrupt):
            with self.assertRaises(d.Error): d.hydrate(self.project, self.root)
        self.assertTrue((self.project / d.MARKER).exists())
        self.assertFalse((self.project / '.hidden').exists())

    def test_corruption_after_publication_keeps_marker(self):
        d.backup(self.project, self.root, yes=True)
        original = d.rename_exclusive
        def corrupt(src, dst):
            original(src, dst)
            if dst.name == '.hidden':
                dst.write_text('xxxxxx')
        with patch.object(d, 'rename_exclusive', side_effect=corrupt):
            with self.assertRaises(d.Error): d.hydrate(self.project, self.root)
        self.assertTrue((self.project / d.MARKER).exists())
        self.assertEqual((self.project / '.hidden').read_text(), 'xxxxxx')

    def test_concurrent_conflicts_never_replaced(self):
        for name, source_kind in [('folder', 'directory'), ('link', 'symlink'), ('.hidden', 'file')]:
            with self.subTest(source_kind=source_kind):
                # Use a fresh disposable project for each case.
                project = self.project.parent / ('race-' + source_kind)
                project.mkdir()
                (project / name).mkdir() if source_kind == 'directory' else ((project / name).symlink_to('target') if source_kind == 'symlink' else (project / name).write_text('backup'))
                d.backup(project, self.root, yes=True)
                original = d.rename_exclusive
                def race(src, dst):
                    if dst.name == name:
                        dst.write_text('concurrent')
                    return original(src, dst)
                with patch.object(d, 'rename_exclusive', side_effect=race):
                    with self.assertRaises(d.Error): d.hydrate(project, self.root)
                self.assertEqual((project / name).read_text(), 'concurrent')
                self.assertTrue((project / d.MARKER).exists())

    def test_unsupported_atomic_rename_fails_closed(self):
        d.backup(self.project, self.root, yes=True)
        with patch.object(d.sys, 'platform', 'unsupported'):
            with self.assertRaisesRegex(d.Error, 'unsupported'): d.hydrate(self.project, self.root)
        self.assertTrue((self.project / d.MARKER).exists())
        self.assertFalse((self.project / '.hidden').exists())

    def test_legacy_manifest_without_file_hash_refused(self):
        g = d.backup(self.project, self.root, yes=True)
        dest = d.location(self.root, self.project) / 'generations' / g
        import json, hashlib
        manifest = json.loads((dest / 'manifest.json').read_text())
        manifest['.hidden'] = manifest['.hidden'][:2]
        raw = json.dumps(manifest).encode()
        (dest / 'manifest.json').write_bytes(raw)
        (dest / 'COMPLETE').write_text(hashlib.sha256(raw).hexdigest())
        with self.assertRaises(d.Error): d.hydrate(self.project, self.root)
        self.assertTrue((self.project / d.MARKER).exists())

    def test_local_directory_is_not_network_mount(self):
        with patch.dict(os.environ, {'DHYD_BACKUP_ROOT': str(self.root)}), patch.object(d, 'mounted_network', return_value=False):
            with self.assertRaises(d.Error): d.root_path()

    def test_mount_loss_keeps_quarantine(self):
        with patch.object(d, 'mounted_network', return_value=False):
            with self.assertRaisesRegex(d.Error, 'mount changed'):
                d.backup(self.project, self.root, yes=True)
        self.assertTrue((self.project / d.QUARANTINE / '.hidden').exists())
        self.assertTrue((self.project / d.MARKER).exists())

    def test_unsupported_readme_keeps_source(self):
        (self.project / 'README.md').unlink()
        (self.project / 'README.md').symlink_to('.hidden')
        with self.assertRaises(d.Error): d.backup(self.project, self.root, yes=True)
        self.assertTrue((self.project / '.hidden').exists())

    def test_interrupted_quarantine_is_preserved(self):
        original = d.check_inventory
        def fail(root, *a, **kw):
            if root.name == d.QUARANTINE: raise d.Error('interruption')
            return original(root, *a, **kw)
        with patch.object(d, 'check_inventory', side_effect=fail):
            with self.assertRaises(d.Error): d.backup(self.project, self.root, yes=True)
        self.assertTrue((self.project / d.QUARANTINE / '.hidden').exists())
        with self.assertRaises(d.Error): d.hydrate(self.project, self.root)

    def test_only_new_contents_are_uploaded(self):
        original = d.shutil.copyfileobj
        uploads = []
        def copy(src, dst, *args):
            if '/objects/.tmp-' in dst.name: uploads.append(dst.name)
            return original(src, dst, *args)
        with patch.object(d.shutil, 'copyfileobj', side_effect=copy):
            d.backup(self.project, self.root, backup_only=True)
            self.assertEqual(len(uploads), 3)
            uploads.clear()
            d.backup(self.project, self.root, backup_only=True)
            self.assertEqual(uploads, [])
            (self.project / '.hidden').write_text('different')
            d.backup(self.project, self.root, backup_only=True)
            self.assertEqual(len(uploads), 1)
            uploads.clear()
            d.backup(self.project, self.root, yes=True)
            self.assertEqual(uploads, [])

    def test_source_changes_during_upload_are_refused(self):
        original = d.shutil.copyfileobj
        def change(src, dst, *args):
            if src.name.endswith('.hidden'):
                (self.project / '.hidden').write_text('changed')
            return original(src, dst, *args)
        with patch.object(d.shutil, 'copyfileobj', side_effect=change):
            with self.assertRaises(d.Error): d.backup(self.project, self.root, yes=True)
        self.assertEqual((self.project / '.hidden').read_text(), 'changed')
        self.assertFalse((self.project / d.MARKER).exists())

    def test_legacy_full_copy_restore(self):
        g = d.backup(self.project, self.root, backup_only=True)
        dest = d.location(self.root, self.project) / 'generations' / g
        data = dest / 'data'; data.mkdir()
        d.rsync(self.project, data)
        (dest / 'FORMAT').unlink()
        for item in list(self.project.iterdir()):
            if item.name == 'README.md': continue
            if item.is_dir() and not item.is_symlink():
                import shutil
                shutil.rmtree(item)
            else: item.unlink()
        d.write_exclusive(self.project / d.MARKER, d.marker_text(self.project, d.location(self.root, self.project), g))
        d.hydrate(self.project, self.root)
        self.assertEqual((self.project / '.hidden').read_text(), 'secret')
        self.assertTrue((self.project / 'link').is_symlink())

    def test_corrupt_reused_object_refuses_backup(self):
        d.backup(self.project, self.root, backup_only=True)
        objects = d.location(self.root, self.project) / 'objects'
        (objects / hashlib.sha256(b'secret').hexdigest()).write_text('bad')
        with self.assertRaises(d.Error): d.backup(self.project, self.root, yes=True)
        self.assertEqual((self.project / '.hidden').read_text(), 'secret')
        self.assertFalse((self.project / d.MARKER).exists())

    def test_failed_object_write_keeps_source(self):
        with patch.object(d.shutil, 'copyfileobj', side_effect=OSError('disk full')):
            with self.assertRaises(OSError): d.backup(self.project, self.root, yes=True)
        self.assertEqual((self.project / '.hidden').read_text(), 'secret')
        self.assertFalse((self.project / d.MARKER).exists())

if __name__ == '__main__': unittest.main()
