import os
import stat
from pathlib import Path
from sealvault.codec import path, sha256, fail, text, canonical, digest
from sealvault.objects import Objects, MAX_OBJECT
from sealvault.custody.cases import Cases
from sealvault.custody.seals import Seals
from sealvault.retention.policy import assert_available


def inventory(root, maximum_files=1000):
    from sealvault.codec import integer
    integer(maximum_files, 'maximum_files', 1, 10000)
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        fail('directory_root', 'Input root must be an ordinary directory')
    rows = []
    total = 0
    for current, directories, files in os.walk(root, followlinks=False):
        directories.sort()
        files.sort()
        for name in directories:
            location = Path(current) / name
            if location.is_symlink():
                fail('directory_symlink', 'Directory intake does not follow symbolic links')
        for name in files:
            location = Path(current) / name
            info = location.lstat()
            if not stat.S_ISREG(info.st_mode):
                fail('directory_type', 'Only regular files may be accessioned')
            relative = path(location.relative_to(root).as_posix())
            if info.st_size > MAX_OBJECT:
                fail('directory_object_size', 'Input file exceeds object size limit', path=relative)
            rows.append({'path': relative, 'size': info.st_size, 'mtime_ns': info.st_mtime_ns, 'device': info.st_dev, 'inode': info.st_ino})
            total += info.st_size
            if len(rows) > maximum_files or total > 67108864:
                fail('directory_limit', 'Directory exceeds bounded intake limits')
    if not rows:
        fail('directory_empty', 'Input directory has no regular files')
    return {'root': str(root.resolve()), 'files': rows, 'bytes': total, 'fingerprint': digest(rows)}


def read_relative(root, descriptor):
    components = path(descriptor['path']).split('/')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    directory_flags = flags | getattr(os, 'O_DIRECTORY', 0)
    handles = []
    try:
        parent = os.open(root, directory_flags)
        handles.append(parent)
        for component in components[:-1]:
            parent = os.open(component, directory_flags, dir_fd=parent)
            handles.append(parent)
        handle = os.open(components[-1], flags, dir_fd=parent)
        handles.append(handle)
        before = os.fstat(handle)
        if not stat.S_ISREG(before.st_mode):
            fail('directory_type', 'Intake file is no longer regular')
        observed = (before.st_size, before.st_mtime_ns, before.st_dev, before.st_ino)
        expected = tuple(descriptor[field] for field in ('size', 'mtime_ns', 'device', 'inode'))
        if observed != expected:
            fail('directory_changed', 'Intake file changed since inventory', path=descriptor['path'])
        data = bytearray()
        while len(data) <= MAX_OBJECT:
            chunk = os.read(handle, min(65536, MAX_OBJECT + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(handle)
        if len(data) != before.st_size or (after.st_size, after.st_mtime_ns, after.st_ino) != (before.st_size, before.st_mtime_ns, before.st_ino):
            fail('directory_changed', 'File changed while being read')
        return bytes(data)
    except OSError as exc:
        from sealvault.codec import VaultError
        raise VaultError('directory_io', 'Cannot open intake file safely') from exc
    finally:
        for handle in reversed(handles):
            os.close(handle)


def ingest(db, root, case_id, expected_revision, owner, media_type='application/octet-stream'):
    from sealvault.codec import media_type as validate_media
    validate_media(media_type)
    scanned = inventory(root)
    objects = Objects(db)
    cases = Cases(db)
    with db.transaction():
        cases.editable(case_id, expected_revision, owner)
        revision = expected_revision
        attached = []
        for descriptor in scanned['files']:
            data = read_relative(scanned['root'], descriptor)
            stored = objects.put(data)
            entry = {'path': descriptor['path'], 'digest': stored['digest'], 'size': len(data), 'media_type': media_type, 'metadata': {}}
            case = cases.attach(case_id, revision, owner, entry)
            revision = case['revision']
            attached.append(entry)
        db.log('directory.ingested', {'case_id': case_id, 'inventory_hash': scanned['fingerprint'], 'entries': len(attached), 'owner': owner})
        return {'case_id': case_id, 'revision': revision, 'entries': attached, 'bytes': scanned['bytes']}


def export(db, manifest_id, destination):
    from sealvault import manifests
    seal = Seals(db).get(manifest_id)
    if seal['state'] != 'sealed':
        fail('directory_seal', 'Only sealed manifests can export files')
    assert_available(db, manifest_id)
    target = Path(destination)
    if target.exists() or target.is_symlink():
        fail('directory_destination', 'Export destination must not already exist')
    entries = manifests.entries(seal['manifest']['body']['entries'])
    objects = Objects(db)
    for item in entries:
        if len(objects.read(item['digest'])) != item['size']:
            fail('directory_size', 'Evidence object length differs')
    target.mkdir(mode=0o700)
    written = []
    try:
        for item in entries:
            output = target.joinpath(*item['path'].split('/'))
            output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with output.open('xb') as stream:
                content = objects.read(item['digest'])
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            written.append(item['path'])
        return {'manifest_id': manifest_id, 'destination': str(target), 'paths': written, 'manifest_hash': seal['body_hash']}
    except BaseException:
        import shutil
        shutil.rmtree(target)
        raise
