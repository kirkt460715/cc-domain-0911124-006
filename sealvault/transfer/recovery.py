from sealvault.codec import key, text, canonical, loads, digest, fail, envelope, unwrap, fields
from sealvault.custody import actors
from sealvault.objects import Objects
from sealvault.transfer.packages import Packages, validate_package
from sealvault.retention.policy import references


def missing_request(db, import_id):
    row = db.one('SELECT * FROM imports WHERE import_id=?', (import_id,))
    if row is None:
        fail('import_missing', 'Import does not exist')
    body = loads(row['body'])
    if digest(body) != row['digest']:
        fail('import_corrupt', 'Import manifest checksum differs')
    missing = []
    for item in db.all('SELECT * FROM imported_objects WHERE import_id=? ORDER BY object_digest', (import_id,)):
        if item['state'] == 'available':
            continue
        descriptor = next(value for value in body['objects'] if value['digest'] == item['object_digest'])
        received = {value['ordinal'] for value in db.all('SELECT ordinal FROM stage_chunks WHERE session_id=?', (item['session_id'],))}
        for ordinal in sorted(set(range(len(descriptor['chunks']))) - received):
            missing.append({'digest': item['object_digest'], 'ordinal': ordinal, 'chunk_digest': descriptor['chunks'][ordinal]})
    return envelope('sealvault-resume-request', {'import_id': import_id, 'package_digest': row['digest'], 'missing': missing})


def serve_request(db, export_id, request, limit=100):
    from sealvault.codec import integer
    integer(limit, 'limit', 1, 1000)
    data = unwrap(request, 'sealvault-resume-request')
    fields(data, {'import_id', 'package_digest', 'missing'})
    package = db.one('SELECT * FROM exports WHERE export_id=?', (export_id,))
    if package is None or package['digest'] != data['package_digest']:
        fail('resume_package', 'Resume request refers to another package')
    if not isinstance(data['missing'], list) or len(data['missing']) > 100000:
        fail('resume_size', 'Missing chunk request exceeds supported size')
    service = object.__new__(Packages)
    service.db = db
    service.objects = Objects(db)
    chunks = []
    seen = set()
    for item in data['missing'][:limit]:
        fields(item, {'digest', 'ordinal', 'chunk_digest'})
        identity = (item['digest'], item['ordinal'])
        if identity in seen:
            fail('resume_duplicate', 'Resume request repeats a chunk')
        seen.add(identity)
        chunk = service.chunk(export_id, item['digest'], item['ordinal'])
        if chunk['chunk_digest'] != item['chunk_digest']:
            fail('resume_checksum', 'Resume request expected another chunk checksum')
        chunks.append(chunk)
    return envelope('sealvault-resume-response', {'import_id': data['import_id'], 'package_digest': data['package_digest'], 'chunks': chunks, 'remaining_requested': max(0, len(data['missing']) - len(chunks))})


def receive_response(db, response, owner):
    from sealvault.transfer.staging import Staging
    data = unwrap(response, 'sealvault-resume-response')
    fields(data, {'import_id', 'package_digest', 'chunks', 'remaining_requested'})
    row = db.one('SELECT digest FROM imports WHERE import_id=?', (data['import_id'],))
    if row is None or row['digest'] != data['package_digest']:
        fail('resume_package', 'Response does not match local import')
    if not isinstance(data['chunks'], list) or len(data['chunks']) > 1000:
        fail('resume_chunks', 'Resume response has invalid chunk collection')
    service = object.__new__(Packages)
    service.db = db
    service.objects = Objects(db)
    service.staging = Staging(db)
    with db.transaction():
        for chunk in data['chunks']:
            fields(chunk, {'digest', 'ordinal', 'chunk_digest', 'content'})
            service.receive(data['import_id'], owner, chunk['digest'], chunk['ordinal'], chunk['content'])
        return {'import_id': data['import_id'], 'received': len(data['chunks']), 'remaining': missing_request(db, data['import_id'])}


def cancel(db, import_id, owner, reason):
    actors.require(db, owner)
    reason = text(reason)
    with db.transaction():
        row = db.one('SELECT * FROM imports WHERE import_id=?', (import_id,))
        if row is None or row['owner'] != owner or row['state'] != 'receiving':
            fail('import_cancel', 'Only owner may cancel a receiving import')
        for item in db.all('SELECT * FROM imported_objects WHERE import_id=?', (import_id,)):
            db.execute("UPDATE staging SET state='cancelled' WHERE session_id=? AND state='receiving'", (item['session_id'],))
            db.execute('DELETE FROM stage_chunks WHERE session_id=?', (item['session_id'],))
            pin_id = 'replica-' + digest([import_id, item['object_digest']])[:32]
            db.execute('DELETE FROM pins WHERE pin_id=?', (pin_id,))
        db.execute("UPDATE imports SET state='cancelled' WHERE import_id=?", (import_id,))
        db.log('import.cancelled', {'import_id': import_id, 'owner': owner, 'reason': reason})
        return {'import_id': import_id, 'state': 'cancelled'}


def export_close(db, export_id, owner, receipt):
    key(receipt)
    actors.require(db, owner)
    with db.transaction():
        row = db.one('SELECT * FROM exports WHERE export_id=?', (export_id,))
        if row is None or row['owner'] != owner:
            fail('export_owner', 'Export does not belong to caller')
        body = loads(row['body'])
        for item in body['objects']:
            pin_id = 'export-' + digest([export_id, item['digest']])[:32]
            db.execute('DELETE FROM pins WHERE pin_id=?', (pin_id,))
        db.execute("UPDATE exports SET state='closed' WHERE export_id=?", (export_id,))
        db.log('export.closed', {'export_id': export_id, 'owner': owner, 'receipt': receipt})
        return {'export_id': export_id, 'state': 'closed', 'receipt': receipt}
