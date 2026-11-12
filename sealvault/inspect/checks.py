from sealvault.codec import digest, loads, VaultError
from sealvault.custody import chain
from sealvault.custody.seals import Seals
from sealvault.objects import Objects
from sealvault.retention.policy import references


def journal(db):
    previous = '0' * 64
    count = 0
    for row in db.all('SELECT * FROM journal ORDER BY position'):
        expected = digest([previous, row['action'], row['body'], row['at']])
        if row['previous_hash'] != previous or row['entry_hash'] != expected:
            return {'valid': False, 'position': row['position'], 'count': count}
        previous = expected
        count += 1
    return {'valid': True, 'head': previous, 'count': count}


def run(db, verify_bytes=True):
    problems = []
    database = db.integrity()
    audit = journal(db)
    if not database['ok']:
        problems.append({'code': 'database', 'details': database})
    if not audit['valid']:
        problems.append({'code': 'journal', 'details': audit})
    for row in db.all('SELECT case_id FROM cases ORDER BY case_id'):
        try:
            chain.verify(db, row['case_id'])
        except VaultError as exc:
            problems.append({'case_id': row['case_id'], **exc.payload()})
    seals = Seals(db)
    objects = Objects(db)
    for row in db.all('SELECT manifest_id,state FROM manifests ORDER BY manifest_id'):
        try:
            manifest = seals.get(row['manifest_id'])
            retained = db.one("SELECT manifest_id FROM retention WHERE manifest_id=? AND state='active'", (row['manifest_id'],))
            if retained or row['state'] == 'prepared':
                for item in manifest['manifest']['body']['entries']:
                    info = objects.info(item['digest'])
                    if info['size'] != item['size']:
                        problems.append({'code': 'manifest_object_size', 'manifest_id': row['manifest_id'], 'digest': item['digest']})
                    if verify_bytes:
                        objects.read(item['digest'])
        except VaultError as exc:
            problems.append({'manifest_id': row['manifest_id'], **exc.payload()})
    for row in db.all('SELECT digest FROM objects ORDER BY digest'):
        if verify_bytes:
            result = objects.verify(row['digest'])
            if not result['valid']:
                problems.append({'code': 'object_corrupt', **result})
    if db.one("SELECT name FROM sqlite_master WHERE name='replicas'"):
        problems.extend(replicas(db, verify_bytes)['problems'])
    return {'ok': not problems, 'problems': problems, 'database': database, 'journal': audit}


def overview(db):
    objects = db.one('SELECT COUNT(*) AS count,COALESCE(SUM(size),0) AS bytes FROM objects')
    manifests = db.all('SELECT state,COUNT(*) AS count FROM manifests GROUP BY state ORDER BY state')
    cases = db.all('SELECT state,COUNT(*) AS count FROM cases GROUP BY state ORDER BY state')
    retention = db.all('SELECT state,COUNT(*) AS count FROM retention GROUP BY state ORDER BY state')
    return {'objects': objects, 'manifests': manifests, 'cases': cases, 'retention': retention}


def object_impact(db, identity):
    info = Objects(db).info(identity)
    uses = references(db, identity)
    manifests = db.all('SELECT m.manifest_id,m.case_id,m.state FROM manifest_objects o JOIN manifests m ON m.manifest_id=o.manifest_id WHERE o.digest=? ORDER BY m.manifest_id', (identity,))
    return {'object': info, 'active_references': uses, 'historical_manifests': manifests, 'collectible': not uses}


def replicas(db, verify_bytes=True):
    from sealvault.custody.seals import verify_export
    problems = []
    count = 0
    objects = Objects(db)
    for row in db.all('SELECT * FROM replicas ORDER BY import_id'):
        count += 1
        try:
            evidence = loads(row['evidence'])
            verify_export(evidence)
            data = evidence['payload']['data']
            if row['manifest_id'] != data['manifest_id'] or row['body_hash'] != data['manifest']['sha256']:
                problems.append({'code': 'replica_index', 'import_id': row['import_id']})
            expected = {item['digest']: item['size'] for item in data['manifest']['body']['entries']}
            indexed = {item['object_digest'] for item in db.all('SELECT object_digest FROM imported_objects WHERE import_id=?', (row['import_id'],))}
            if indexed != set(expected):
                problems.append({'code': 'replica_references', 'import_id': row['import_id']})
            if row['state'] == 'retained':
                for identity, size in expected.items():
                    info = objects.info(identity)
                    if info['size'] != size:
                        problems.append({'code': 'replica_size', 'import_id': row['import_id'], 'digest': identity})
                    if verify_bytes:
                        objects.read(identity)
        except VaultError as exc:
            problems.append({'import_id': row['import_id'], **exc.payload()})
    return {'valid': not problems, 'count': count, 'problems': problems}
