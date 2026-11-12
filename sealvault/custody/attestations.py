from sealvault.codec import key, text, canonical, loads, digest, fail, envelope, unwrap, fields
from sealvault.custody import actors, chain
from sealvault.custody.seals import Seals
from sealvault.objects import Objects
from sealvault.retention.policy import assert_available

DDL = '''
CREATE TABLE IF NOT EXISTS attestations(attestation_id TEXT PRIMARY KEY,manifest_id TEXT NOT NULL,author TEXT NOT NULL,body TEXT NOT NULL,digest TEXT NOT NULL,state TEXT NOT NULL,reviewer TEXT,reason TEXT NOT NULL);
'''


class Attestations:
    def __init__(self, database):
        self.db = database
        self.seals = Seals(database)
        self.objects = Objects(database)
        if database.depth:
            fail('attestation_transaction', 'Initialize attestations outside transactions')
        database.connection.executescript(DDL)

    def inspect(self, attestation_id, manifest_id, author, reason):
        key(attestation_id)
        actors.require(self.db, author, {'auditor', 'custodian'})
        reason = text(reason)
        with self.db.transaction():
            if self.db.one('SELECT attestation_id FROM attestations WHERE attestation_id=?', (attestation_id,)):
                fail('attestation_exists', 'Attestation identity is immutable')
            seal = self.seals.get(manifest_id)
            if seal['state'] != 'sealed':
                fail('attestation_seal', 'Only sealed evidence can be inspected')
            assert_available(self.db, manifest_id)
            custody = chain.verify(self.db, seal['case_id'])
            objects = []
            seen = set()
            for item in seal['manifest']['body']['entries']:
                if item['digest'] not in seen:
                    checked = self.objects.verify(item['digest'])
                    objects.append({'digest': item['digest'], 'expected_size': item['size'], 'actual_size': checked['actual_size'], 'valid': checked['valid'], 'state': checked['state']})
                    seen.add(item['digest'])
            body = {'manifest_id': manifest_id, 'manifest_hash': seal['body_hash'], 'custody_head': custody['head'], 'custody_count': custody['count'], 'objects': sorted(objects, key=lambda row: row['digest']), 'at': self.db.clock(), 'valid': all(row['valid'] and row['state'] == 'available' and row['expected_size'] == row['actual_size'] for row in objects)}
            self.db.execute("INSERT INTO attestations VALUES(?,?,?,?,?,'proposed',NULL,?)", (attestation_id, manifest_id, author, canonical(body), digest(body), reason))
            return self.get(attestation_id)

    def get(self, attestation_id):
        row = self.db.one('SELECT * FROM attestations WHERE attestation_id=?', (attestation_id,))
        if row is None:
            fail('attestation_missing', 'Attestation does not exist')
        row['body'] = loads(row['body'])
        if digest(row['body']) != row['digest']:
            fail('attestation_corrupt', 'Attestation checksum differs')
        return row

    def approve(self, attestation_id, reviewer, expected_digest):
        actors.require(self.db, reviewer, {'custodian'})
        with self.db.transaction():
            row = self.get(attestation_id)
            if row['state'] != 'proposed' or row['author'] == reviewer:
                fail('attestation_review', 'Independent custodian must approve a proposed attestation')
            if row['digest'] != expected_digest or not row['body']['valid']:
                fail('attestation_invalid', 'Only acknowledged successful inspection can be approved')
            seal = self.seals.get(row['manifest_id'])
            assert_available(self.db, row['manifest_id'])
            current = chain.verify(self.db, seal['case_id'])
            if current['head'] != row['body']['custody_head'] or seal['body_hash'] != row['body']['manifest_hash']:
                fail('attestation_stale', 'Custody or manifest changed after inspection')
            for item in row['body']['objects']:
                if len(self.objects.read(item['digest'])) != item['expected_size']:
                    fail('attestation_object', 'Object changed after inspection')
            self.db.execute("UPDATE attestations SET state='approved',reviewer=? WHERE attestation_id=?", (reviewer, attestation_id))
            chain.append(self.db, seal['case_id'], 'attested', reviewer, {'attestation_id': attestation_id, 'digest': row['digest'], 'inspected_head': current['head']})
            return self.get(attestation_id)

    def export(self, attestation_id):
        row = self.get(attestation_id)
        if row['state'] != 'approved':
            fail('attestation_state', 'Only approved attestations are exportable')
        seal = self.seals.get(row['manifest_id'])
        return envelope('sealvault-attestation', {'attestation_id': attestation_id, 'body': row['body'], 'digest': row['digest'], 'author': row['author'], 'reviewer': row['reviewer'], 'custody': chain.export(self.db, seal['case_id'])})


def verify(value):
    data = unwrap(value, 'sealvault-attestation')
    fields(data, {'attestation_id', 'body', 'digest', 'author', 'reviewer', 'custody'})
    if digest(data['body']) != data['digest'] or data['author'] == data['reviewer'] or not data['body']['valid']:
        fail('attestation_binding', 'Attestation identity, separation or inspection checksum differs')
    chain.verify_export(data['custody'])
    events = data['custody']['payload']['data']['events']
    inspected = [row for row in events if row['entry_hash'] == data['body']['custody_head']]
    committed = [row for row in events if row['action'] == 'attested' and row['body'].get('attestation_id') == data['attestation_id']]
    if len(inspected) != 1 or len(committed) != 1:
        fail('attestation_chain', 'Custody chain omits inspection anchor or committed attestation')
    if committed[0]['body']['digest'] != data['digest'] or committed[0]['actor'] != data['reviewer']:
        fail('attestation_chain', 'Custody attestation binding differs')
    return {'valid': True, 'manifest_id': data['body']['manifest_id'], 'objects': len(data['body']['objects']), 'authentication': 'local_hash_chain_only', 'current_bytes_checked': False}
