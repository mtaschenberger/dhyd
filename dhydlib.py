"""Conservative content-addressed project dehydration. See README for guarantees."""
import argparse
from contextlib import nullcontext
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time
import tempfile
import uuid

MARKER = 'DHYD.md'
QUARANTINE = '.dhyd-pending'

class Error(Exception):
    pass

def mounted_network(path):
    """Require an actual supported network mount enclosing path, not a mountpoint stub."""
    result = subprocess.run(['/sbin/mount'], text=True, capture_output=True, check=True).stdout
    best = None
    for line in result.splitlines():
        if ' on ' not in line or ' (' not in line:
            continue
        point, opts = line.split(' on ', 1)[1].rsplit(' (', 1)
        point = point.replace('\\040', ' ')
        try:
            if os.path.commonpath([str(path), point]) != point:
                continue
        except ValueError:
            continue
        if best is None or len(point) > len(best[0]):
            best = (point, opts.split(',', 1)[0].rstrip(')'))
    return bool(best and best[1] in {'smbfs', 'nfs', 'cifs', 'afpfs', 'webdav'})

def root_path():
    p = Path(os.environ.get('DHYD_BACKUP_ROOT', '~/DataLoot')).expanduser().resolve(strict=True)
    if not p.is_dir() or not mounted_network(p):
        raise Error(f'Backup root is not on a supported mounted network filesystem: {p}')
    return p

def project_path(value):
    p = Path(value).expanduser().resolve(strict=True)
    if not p.is_dir() or p == Path(p.anchor):
        raise Error('Project must be an existing non-root directory')
    return p

def inspect_tree(root):
    dev = root.stat().st_dev
    for base, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            p = Path(base) / name
            st = p.lstat()
            if st.st_dev != dev:
                raise Error(f'Nested filesystem is not supported: {p}')
            if not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode)):
                raise Error(f'Special file is not supported: {p}')

def inventory(root, *, excludes=()):
    """Independent inventory: names, types, link targets, and local mode bits."""
    entries = {}
    def visit(directory, prefix=''):
        with os.scandir(directory) as scan:
            items = list(scan)
        for item in items:
            rel = prefix + item.name
            if not prefix and item.name in excludes:
                continue
            st = item.stat(follow_symlinks=False)
            if stat.S_ISLNK(st.st_mode):
                entries[rel] = ['link', os.readlink(item.path)]
            elif stat.S_ISREG(st.st_mode):
                with open(item.path, 'rb') as f:
                    digest = hashlib.file_digest(f, 'sha256').hexdigest()
                entries[rel] = ['file', stat.S_IMODE(st.st_mode), digest]
            elif stat.S_ISDIR(st.st_mode):
                entries[rel] = ['dir', stat.S_IMODE(st.st_mode)]
                visit(item.path, rel + '/')
            else:
                raise Error(f'Unsupported entry: {item.path}')
    visit(root)
    return entries

def shape(entries):
    return {name: ([value[0], value[2]] if value[0] == 'file' else
                   value if value[0] == 'link' else [value[0]])
            for name, value in entries.items()}

def check_inventory(root, expected, *, modes=True, excludes=()):
    actual = inventory(root, excludes=excludes)
    if (actual if modes else shape(actual)) != (expected if modes else shape(expected)):
        raise Error(f'Inventory or permissions changed or differ: {root}')

def read_manifest(dest):
    raw = (dest / 'manifest.json').read_bytes()
    digest = (dest / 'COMPLETE').read_text().strip()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise Error('Manifest checksum mismatch')
    manifest = json.loads(raw)
    if not isinstance(manifest, dict):
        raise Error('Invalid manifest')
    return manifest

def rsync(src, dst, *, verify=False, excludes=(), link_dest=None, ignore_existing=False):
    # SMB synthesizes Unix permissions; directory times are not portable either.
    cmd = ['/usr/bin/rsync', '-ac', '--no-perms', '--no-owner', '--no-group', '--omit-dir-times', '--delete']
    if verify:
        cmd += ['--dry-run', '--itemize-changes']
    if link_dest:
        cmd.append('--link-dest=' + str(link_dest))
    if ignore_existing:
        cmd.remove('--delete')
        cmd.append('--ignore-existing')
    for x in excludes:
        cmd.extend(['--exclude', '/' + x])
    cmd += [str(src) + '/', str(dst) + '/']
    p = subprocess.run(cmd, capture_output=True)
    if p.returncode:
        raise Error('rsync failed: ' + p.stderr.decode(errors='replace'))
    if verify and p.stdout.strip():
        raise Error('Verification failed; files differ or changed during operation:\n' + p.stdout.decode(errors='replace'))

def write_exclusive(path, text):
    with open(path, 'x', encoding='utf-8') as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())

def file_hash(path):
    if path.is_symlink() or not path.is_file():
        raise Error(f'Invalid object: {path}')
    with open(path, 'rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()

def verify_objects(slot, manifest):
    objects = slot / 'objects'
    for digest in {v[2] for v in manifest.values() if v[0] == 'file'}:
        if file_hash(objects / digest) != digest:
            raise Error(f'Object checksum mismatch: {digest}')

def store_objects(project, slot, manifest):
    objects = slot / 'objects'
    objects.mkdir(exist_ok=True)
    seen = set()
    for name, entry in manifest.items():
        if entry[0] != 'file' or entry[2] in seen:
            continue
        digest = entry[2]
        seen.add(digest)
        target = objects / digest
        if target.exists() or target.is_symlink():
            if file_hash(target) != digest:
                raise Error(f'Object checksum mismatch: {digest}')
            continue
        temp = objects / ('.tmp-' + uuid.uuid4().hex)
        try:
            with open(project / name, 'rb') as src, open(temp, 'xb') as dst:
                shutil.copyfileobj(src, dst, 1024 * 1024)
                dst.flush()
                os.fsync(dst.fileno())
            if file_hash(temp) != digest:
                raise Error(f'Source changed or object copy corrupted: {name}')
            # Only one dhyd/hyd process may operate on this slot under LOCK.
            # Never intentionally replace a pre-existing immutable object.
            if target.exists() or target.is_symlink():
                raise Error(f'Object appeared during publication: {digest}')
            os.rename(temp, target)
            if file_hash(target) != digest:
                raise Error(f'Published object checksum mismatch: {digest}')
        finally:
            if temp.exists():
                temp.unlink()

def stage_objects(slot, manifest, stage):
    # Parent types must be validated before creating paths or following links.
    for name in manifest:
        parts = name.split('/')
        for i in range(1, len(parts)):
            parent = '/'.join(parts[:i])
            if parent not in manifest or manifest[parent][0] != 'dir':
                raise Error('Invalid manifest parent')
    for name, entry in sorted(manifest.items(), key=lambda x: x[0].count('/')):
        dest = stage / name
        if entry[0] == 'dir':
            dest.mkdir()
        elif entry[0] == 'link':
            os.symlink(entry[1], dest)
        else:
            with open(slot / 'objects' / entry[2], 'rb') as src, open(dest, 'xb') as out:
                shutil.copyfileobj(src, out, 1024 * 1024)
    check_inventory(stage, manifest, modes=False)

def location(root, project):
    if root == project or root in project.parents or project in root.parents:
        raise Error('Project and backup root must not contain one another')
    key = hashlib.sha256(os.fsencode(str(project))).hexdigest()
    return root / 'dhyd-backups' / key

def marker_text(project, slot, generation):
    info = {'project': str(project), 'slot': str(slot), 'generation': generation}
    return ('# Dehydrated project\n\nDo not delete this file. Restore with `hyd` from this directory.\n'
            'Keep the backup root mounted. If restoration reports conflicts, preserve all files and see the dhyd README.\n\n'
            '<!-- dhyd-json: ' + json.dumps(info, ensure_ascii=True) + ' -->\n')

def read_marker(project):
    p = project / MARKER
    if p.is_symlink() or not p.is_file():
        raise Error('No valid DHYD.md found')
    text = p.read_text(encoding='utf-8')
    prefix = '<!-- dhyd-json: '
    lines = [x for x in text.splitlines() if x.startswith(prefix) and x.endswith(' -->')]
    if len(lines) != 1:
        raise Error('Invalid DHYD.md metadata')
    try:
        return json.loads(lines[0][len(prefix):-4])
    except (ValueError, TypeError) as e:
        raise Error('Invalid DHYD.md metadata') from e

class Lock:
    def __init__(self, slot):
        self.path = slot / 'LOCK'
    def __enter__(self):
        try:
            self.path.mkdir()
        except FileExistsError:
            raise Error(f'Backup locked or interrupted: {self.path}; inspect before manual removal')
        return self
    def __exit__(self, *args):
        self.path.rmdir()

def prepare_slot(root, project):
    slot = location(root, project)
    slot.mkdir(parents=True, exist_ok=True)
    identity = slot / 'project.json'
    if identity.exists():
        if json.loads(identity.read_text()) != {'project': str(project)}:
            raise Error('Backup identity collision')
    else:
        try:
            write_exclusive(identity, json.dumps({'project': str(project)}))
        except FileExistsError:
            if json.loads(identity.read_text()) != {'project': str(project)}:
                raise Error('Backup identity collision')
    return slot

def confirm():
    if not sys.stdin.isatty():
        raise Error('Dehydration needs interactive confirmation or --yes')
    if input('Delete local project contents after verification? Type DELETE: ') != 'DELETE':
        raise Error('Cancelled')

def backup(project, root, backup_only=False, yes=False):
    if (project / MARKER).exists() or (project / MARKER).is_symlink() or (project / QUARANTINE).exists():
        raise Error('Project already contains DHYD.md or an interrupted quarantine; refusing to proceed')
    inspect_tree(project)
    manifest = inventory(project)
    readme = project / 'README.md'
    if (readme.exists() or readme.is_symlink()) and (readme.is_symlink() or not readme.is_file()):
        raise Error('README.md must be a regular file if present')
    root_device = root.stat().st_dev
    if not backup_only and not yes:
        confirm()
    slot = prepare_slot(root, project)
    with Lock(slot):
        gens = slot / 'generations'
        gens.mkdir(exist_ok=True)
        generation = time.strftime('%Y%m%dT%H%M%S') + '-' + uuid.uuid4().hex
        dest = gens / generation
        dest.mkdir()
        store_objects(project, slot, manifest)
        check_inventory(project, manifest)
        verify_objects(slot, manifest)
        write_exclusive(dest / 'FORMAT', 'objects-v1\n')
        manifest_text = json.dumps(manifest, ensure_ascii=True, sort_keys=True, separators=(',', ':'))
        write_exclusive(dest / 'manifest.json', manifest_text)
        write_exclusive(dest / 'COMPLETE', hashlib.sha256(manifest_text.encode('utf-8')).hexdigest() + '\n')
        if read_manifest(dest) != manifest:
            raise Error('Manifest read-back differs')
        latest = slot / 'LATEST'
        tmp = slot / ('LATEST.' + uuid.uuid4().hex)
        write_exclusive(tmp, generation + '\n')
        os.replace(tmp, latest)
        if backup_only:
            return generation
        # Recheck after publishing, then move all non-README entries into a local
        # quarantine. No deletion occurs until the moved tree verifies as well.
        check_inventory(project, manifest)
        verify_objects(slot, manifest)
        if read_manifest(dest) != manifest:
            raise Error('Manifest changed')
        write_exclusive(project / MARKER, marker_text(project, slot, generation))
        pending = project / QUARANTINE
        pending.mkdir()
        for item in list(project.iterdir()):
            if item.name not in {MARKER, QUARANTINE, 'README.md'}:
                os.rename(item, pending / item.name)
        # The quarantine inventory detects additions, removals and changes before deletion.
        unexpected = [p.name for p in project.iterdir() if p.name not in {MARKER, QUARANTINE, 'README.md'}]
        if unexpected:
            raise Error('Concurrent project changes; quarantine retained: ' + ', '.join(unexpected))
        if root.stat().st_dev != root_device or not mounted_network(root):
            raise Error('Network mount changed or disappeared; quarantine retained')
        check_inventory(pending, {k: v for k, v in manifest.items() if k != 'README.md'})
        verify_objects(slot, manifest)
        check_inventory(project, {k: v for k, v in manifest.items() if k == 'README.md'},
                        excludes=(MARKER, QUARANTINE))
        if read_manifest(dest) != manifest:
            raise Error('Manifest changed; quarantine retained')
        shutil.rmtree(pending)
        return generation

def rename_exclusive(src, dst):
    """Atomic local publication; never fall back to a replacing rename."""
    if sys.platform != 'darwin':
        raise Error('Atomic no-replace restore is unsupported on this platform')
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        rename = libc.renamex_np
    except AttributeError as e:
        raise Error('Atomic no-replace rename unavailable') from e
    rename.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(os.fsencode(src), os.fsencode(dst), 0x00000004):  # RENAME_EXCL
        code = ctypes.get_errno()
        raise Error(f'Atomic restore publication failed for {dst}: {os.strerror(code)}')

def hydrate(project, root, *, backup_generation=None):
    # backup_generation is used only while hydrate_backup holds the slot lock.
    info = (read_marker(project) if backup_generation is None else
            {'project': str(project), 'slot': str(location(root, project)), 'generation': backup_generation})
    slot = location(root, project)
    if info.get('project') != str(project) or info.get('slot') != str(slot):
        raise Error('Marker does not match this project and backup root')
    generation = info.get('generation')
    if not isinstance(generation, str) or not generation or Path(generation).name != generation:
        raise Error('Invalid generation in marker')
    with Lock(slot) if backup_generation is None else nullcontext():
        dest = slot / 'generations' / generation
        data = dest / 'data'
        if not (dest / 'COMPLETE').is_file():
            raise Error('Verified backup generation missing')
        fmt = (dest / 'FORMAT').read_text().strip() if (dest / 'FORMAT').exists() else 'legacy'
        if fmt not in ('objects-v1', 'legacy') or (fmt == 'legacy' and not data.is_dir()):
            raise Error('Unsupported or missing backup generation format')
        manifest = read_manifest(dest)
        for name, entry in manifest.items():
            if (not isinstance(name, str) or not name or name.startswith('/') or
                    any(part in ('', '.', '..') for part in name.split('/')) or
                    not isinstance(entry, list) or not entry):
                raise Error('Invalid manifest entry')
            kind = entry[0]
            if kind == 'file':
                if (len(entry) != 3 or type(entry[1]) is not int or
                        not 0 <= entry[1] <= 0o7777 or
                        not isinstance(entry[2], str) or len(entry[2]) != 64 or
                        any(c not in '0123456789abcdef' for c in entry[2])):
                    raise Error('Invalid manifest file hash or mode')
            elif kind == 'dir':
                if len(entry) != 2 or type(entry[1]) is not int or not 0 <= entry[1] <= 0o7777:
                    raise Error('Invalid manifest mode')
            elif kind == 'link':
                if len(entry) != 2 or not isinstance(entry[1], str):
                    raise Error('Invalid manifest link')
            else:
                raise Error('Invalid manifest type')
        if fmt == 'legacy':
            check_inventory(data, manifest, modes=False)
        else:
            verify_objects(slot, manifest)
        if backup_generation is not None:
            # Validate parents before creating a recovery marker.
            for name in manifest:
                parts = name.split('/')
                for i in range(1, len(parts)):
                    parent = '/'.join(parts[:i])
                    if parent not in manifest or manifest[parent][0] != 'dir':
                        raise Error('Invalid manifest parent')
            if MARKER in manifest:
                raise Error('Backup contains reserved recovery marker')
            if any(project.iterdir()):
                raise Error('Backup restore requires an empty project directory')
            write_exclusive(project / MARKER, marker_text(project, slot, generation))
        if (project / QUARANTINE).exists() or (project / QUARANTINE).is_symlink():
            raise Error('Interrupted dehydration: quarantine exists; recover it manually before hyd')
        extras = [p.name for p in project.iterdir() if p.name not in {MARKER, 'README.md'}]
        if extras:
            raise Error('Local files would conflict; move them aside first: ' + ', '.join(extras))
        readme = project / 'README.md'
        retained = readme.exists() or readme.is_symlink()
        if retained:
            entry = manifest.get('README.md')
            if readme.is_symlink() or not readme.is_file() or not entry or entry[0] != 'file' or file_hash(readme) != entry[2]:
                raise Error('README.md differs from backup; move it aside first')
        # Stage on the local filesystem, apply modes before publishing. Each top-level
        # rename is atomic and exclusive, including directories and symlinks.
        with tempfile.TemporaryDirectory(prefix='.hyd-stage-', dir=project) as stage_name:
            stage = Path(stage_name)
            if fmt == 'legacy':
                rsync(data, stage)
                check_inventory(stage, manifest, modes=False)
            else:
                stage_objects(slot, manifest, stage)
            for name in sorted(manifest, key=lambda n: n.count('/'), reverse=True):
                entry = manifest[name]
                if entry[0] != 'link':
                    os.chmod(stage / name, entry[1], follow_symlinks=False)
            check_inventory(stage, manifest)
            if fmt == 'legacy':
                check_inventory(data, manifest, modes=False)
            else:
                verify_objects(slot, manifest)
            if read_manifest(dest) != manifest:
                raise Error('Manifest changed during restore')
            for item in list(stage.iterdir()):
                if item.name == 'README.md' and retained:
                    continue
                rename_exclusive(item, project / item.name)
        check_inventory(project, manifest, excludes=(MARKER,))
        if fmt == 'legacy':
            check_inventory(data, manifest, modes=False)
        else:
            verify_objects(slot, manifest)
        if read_manifest(dest) != manifest:
            raise Error('Manifest changed during restore')
        (project / MARKER).unlink()

def hydrate_backup(project, root):
    slot = location(root, project)
    if any(project.iterdir()):
        raise Error('Backup restore requires an empty project directory')
    if not slot.is_dir():
        raise Error('No backup exists for this project path')
    with Lock(slot):
        if json.loads((slot / 'project.json').read_text()) != {'project': str(project)}:
            raise Error('Backup identity collision')
        latest = (slot / 'LATEST').read_text()
        if not latest.endswith('\n') or latest.count('\n') != 1:
            raise Error('Invalid LATEST generation')
        generation = latest[:-1]
        if (not generation or generation in ('.', '..') or
                Path(generation).name != generation or
                any(c.isspace() or ord(c) < 32 for c in generation)):
            raise Error('Invalid LATEST generation')
        hydrate(project, root, backup_generation=generation)

def main(mode=None, argv=None):
    mode = mode or ('hyd' if Path(sys.argv[0]).name == 'hyd' else 'dhyd')
    parser = argparse.ArgumentParser(prog=mode)
    parser.add_argument('folder', nargs='?', default='.')
    if mode == 'dhyd':
        parser.add_argument('-b', '--backup-only', action='store_true')
        parser.add_argument('-y', '--yes', action='store_true')
    else:
        parser.add_argument('--backup', action='store_true', help='restore latest backup into an empty original project folder')
    args = parser.parse_args(argv)
    try:
        project = project_path(args.folder)
        root = root_path()
        if mode == 'hyd':
            if args.backup:
                hydrate_backup(project, root)
            else:
                hydrate(project, root)
            print('Restored:', project)
        else:
            generation = backup(project, root, args.backup_only, args.yes)
            print(('Backup completed: ' if args.backup_only else 'Dehydrated: ') + generation)
        return 0
    except (Error, OSError, subprocess.SubprocessError, ValueError) as e:
        print(f'{mode}: {e}', file=sys.stderr)
        return 1
