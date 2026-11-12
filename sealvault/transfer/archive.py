import io
import tarfile
from sealvault.codec import canonical, loads, sha256, digest, fail, integer, envelope, unwrap
from sealvault.custody.seals import Seals, verify_export
from sealvault.objects import Objects
from sealvault.custody import actors

MAX_ARCHIVE = 67108864


def member_name(identity):
    from sealvault.codec import checksum
    return 'objects/' + checksum(identity)


def create(db, manifest_id):
    seals = Seals(db)
    objects = Objects(db)
    evidence = seals.export(manifest_id)
    body = evidence['payload']['data']['manifest']['body']
    unique = {row['digest']: row['size'] for row in body['entries']}
    if sum(unique.values()) > MAX_ARCHIVE - 1048576:
        fail('archive_size', 'Archive exceeds supported local transport size')
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        manifest_bytes = canonical(evidence).encode()
        members = [('seal.json', manifest_bytes)]
        members.extend((member_name(identity), objects.read(identity)) for identity in sorted(unique))
        for name, content in members:
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mode = 0o600
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ''
            info.gname = ''
            archive.addfile(info, io.BytesIO(content))
    result = buffer.getvalue()
    if len(result) > MAX_ARCHIVE:
        fail('archive_size', 'Archive headers exceed supported transport size')
    return result


def inspect_bytes(content):
    if not isinstance(content, bytes) or len(content) > MAX_ARCHIVE:
        fail('archive_size', 'Archive must be bounded raw bytes')
    files = {}
    total_size = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(content), mode='r:') as archive:
            for ordinal, info in enumerate(archive):
                if ordinal > 10000:
                    fail('archive_members', 'Archive contains too many members')
                if not info.isreg() or info.linkname or info.pax_headers:
                    fail('archive_member_type', 'Only ordinary files are accepted')
                if info.name in files:
                    fail('archive_duplicate', 'Archive repeats a member name')
                if info.name != 'seal.json':
                    if not info.name.startswith('objects/') or info.name != member_name(info.name[8:]):
                        fail('archive_path', 'Archive contains a non-protocol path')
                if not 0 <= info.size <= 16777216:
                    fail('archive_member_size', 'Archive member exceeds object limit')
                total_size += info.size
                if total_size > MAX_ARCHIVE:
                    fail('archive_size', 'Expanded archive exceeds supported limit')
                stream = archive.extractfile(info)
                if stream is None:
                    fail('archive_member', 'Cannot read regular archive member')
                data = stream.read(info.size + 1)
                if len(data) != info.size:
                    fail('archive_truncated', 'Archive member length differs')
                files[info.name] = data
    except (tarfile.TarError, EOFError, OSError) as exc:
        from sealvault.codec import VaultError
        raise VaultError('archive_decode', 'Cannot decode uncompressed evidence archive') from exc
    if 'seal.json' not in files:
        fail('archive_manifest', 'Archive has no seal evidence')
    evidence = loads(files.pop('seal.json'))
    verified = verify_export(evidence)
    entries = evidence['payload']['data']['manifest']['body']['entries']
    expected = {member_name(row['digest']): row['size'] for row in entries}
    if set(files) != set(expected):
        fail('archive_inventory', 'Archive objects differ from manifest inventory')
    for name, data in files.items():
        if len(data) != expected[name] or sha256(data) != name[8:]:
            fail('archive_object', 'Archive object fails content-address validation')
    return {'evidence': evidence, 'objects': {name[8:]: data for name, data in files.items()}, 'archive_digest': sha256(content), 'verified': verified}


def verify(content):
    report = inspect_bytes(content)
    return {'valid': True, 'manifest_id': report['verified']['manifest_id'], 'objects': len(report['objects']), 'bytes': sum(len(value) for value in report['objects'].values()), 'archive_digest': report['archive_digest'], 'authentication': 'unsigned_local_evidence'}


def import_objects(db, content, actor):
    actors.require(db, actor, {'collector', 'custodian'})
    report = inspect_bytes(content)
    objects = Objects(db)
    with db.transaction():
        created = []
        duplicates = []
        for identity, data in sorted(report['objects'].items()):
            stored = objects.put(data, identity)
            (duplicates if stored['duplicate'] else created).append(identity)
        db.log('archive.objects_imported', {'archive_digest': report['archive_digest'], 'actor': actor, 'created': created, 'duplicates': duplicates})
        return {'evidence': report['evidence'], 'created': created, 'duplicates': duplicates, 'archive_digest': report['archive_digest'], 'replica_registered': False}


def extract_selected(db, manifest_id, selected_path):
    seals = Seals(db)
    seal = seals.get(manifest_id)
    from sealvault.retention.policy import assert_available
    assert_available(db, manifest_id)
    if seal['state'] != 'sealed':
        fail('archive_state', 'Only sealed evidence can be extracted')
    item = next((row for row in seal['manifest']['body']['entries'] if row['path'] == selected_path), None)
    if item is None:
        fail('archive_selection', 'Selected path is absent from sealed manifest')
    return {'entry': item, 'object': Objects(db).export(item['digest']), 'proof': seals.proof(manifest_id, selected_path)}


def export_file(db, manifest_id, destination):
    from pathlib import Path
    content = create(db, manifest_id)
    target = Path(destination)
    if target.is_symlink():
        fail('archive_destination', 'Archive output cannot be a symbolic link')
    with target.open('xb') as stream:
        stream.write(content)
        stream.flush()
        import os
        os.fsync(stream.fileno())
    return {'path': str(target), 'bytes': len(content), 'sha256': sha256(content)}


def read_file(filename):
    from pathlib import Path
    source = Path(filename)
    if source.is_symlink() or not source.is_file() or source.stat().st_size > MAX_ARCHIVE:
        fail('archive_source', 'Archive input must be bounded regular file')
    return source.read_bytes()
