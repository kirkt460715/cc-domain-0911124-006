from sealvault.codec import key, timestamp, canonical, loads, digest, envelope, unwrap, fields, fail, text
from sealvault.custody import actors, chain
from sealvault.custody.seals import Seals, verify_export
from sealvault import manifests
from sealvault.objects import Objects
from sealvault.retention.policy import assert_available

DDL = '''
CREATE TABLE IF NOT EXISTS disclosures(disclosure_id TEXT PRIMARY KEY,manifest_id TEXT NOT NULL,recipient TEXT NOT NULL,expires_at TEXT NOT NULL,state TEXT NOT NULL,body TEXT NOT NULL,digest TEXT NOT NULL,author TEXT NOT NULL,reviewer TEXT,reason TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS disclosure_receipts(disclosure_id TEXT PRIMARY KEY,receipt TEXT NOT NULL,digest TEXT NOT NULL,received_at TEXT NOT NULL);
'''


class Disclosures:
    def __init__(self, database):
        self.db = database
        self.seals = Seals(database)
        self.objects = Objects(database)
        if database.depth:
            fail('disclosure_transaction', 'Initialize disclosure desk outside transactions')
        database.connection.executescript(DDL)

    def propose(self, disclosure_id, manifest_id, paths, recipient, expires_at, author, reason):
        key(disclosure_id)
        key(recipient)
        actors.require(self.db, author, {'custodian'})
        expires_at = timestamp(expires_at)
        reason = text(reason)
        if expires_at <= self.db.clock():
            fail('disclosure_expiry', 'Disclosure must expire in future')
        if not isinstance(paths, list) or not paths or len(paths) > 1000 or len(set(paths)) != len(paths):
            fail('disclosure_paths', 'Select distinct bounded evidence paths')
        with self.db.transaction():
            if self.db.one('SELECT disclosure_id FROM disclosures WHERE disclosure_id=?', (disclosure_id,)):
                fail('disclosure_exists', 'Disclosure identity already exists')
            seal = self.seals.get(manifest_id)
            if seal['state'] != 'sealed':
                fail('disclosure_seal', 'Disclosure requires a sealed manifest')
            assert_available(self.db, manifest_id)
            proofs = [manifests.proof(seal['manifest'], path) for path in sorted(paths)]
            body = {'manifest_id': manifest_id, 'manifest_sha256': seal['body_hash'], 'root': seal['merkle_root'], 'recipient': recipient, 'expires_at': expires_at, 'classification': seal['manifest']['body']['classification'], 'proofs': proofs}
            self.db.execute("INSERT INTO disclosures VALUES(?,?,?,?,'proposed',?,?,?,NULL,?)", (disclosure_id, manifest_id, recipient, expires_at, canonical(body), digest(body), author, reason))
            chain.append(self.db, seal['case_id'], 'disclosure_proposed', author, {'disclosure_id': disclosure_id, 'recipient': recipient, 'paths': sorted(paths), 'digest': digest(body)})
            return self.get(disclosure_id)

    def get(self, disclosure_id):
        row = self.db.one('SELECT * FROM disclosures WHERE disclosure_id=?', (disclosure_id,))
        if row is None:
            fail('disclosure_missing', 'Disclosure does not exist')
        row['body'] = loads(row['body'])
        if digest(row['body']) != row['digest']:
            fail('disclosure_corrupt', 'Disclosure checksum differs')
        row['expired'] = row['expires_at'] <= self.db.clock()
        return row

    def approve(self, disclosure_id, reviewer, expected_digest):
        actors.require(self.db, reviewer, {'custodian'})
        with self.db.transaction():
            row = self.get(disclosure_id)
            if row['state'] != 'proposed' or row['expired']:
                fail('disclosure_state', 'Disclosure is no longer awaiting approval')
            if row['author'] == reviewer:
                fail('disclosure_separation', 'Independent custodian must approve disclosure')
            if expected_digest != row['digest']:
                fail('disclosure_acknowledgement', 'Reviewer must acknowledge exact disclosure contents')
            assert_available(self.db, row['manifest_id'])
            for proof in row['body']['proofs']:
                self.objects.read(proof['entry']['digest'])
            self.db.execute("UPDATE disclosures SET state='approved',reviewer=? WHERE disclosure_id=?", (reviewer, disclosure_id))
            case_id = self.seals.get(row['manifest_id'])['case_id']
            chain.append(self.db, case_id, 'disclosure_approved', reviewer, {'disclosure_id': disclosure_id, 'digest': row['digest']})
            return self.get(disclosure_id)

    def revoke(self, disclosure_id, actor, reason):
        actors.require(self.db, actor, {'custodian', 'administrator'})
        reason = text(reason)
        with self.db.transaction():
            row = self.get(disclosure_id)
            self.db.execute("UPDATE disclosures SET state='revoked' WHERE disclosure_id=?", (disclosure_id,))
            case_id = self.seals.get(row['manifest_id'])['case_id']
            chain.append(self.db, case_id, 'disclosure_revoked', actor, {'disclosure_id': disclosure_id, 'reason': reason})
            return self.get(disclosure_id)

    def export(self, disclosure_id, recipient, include_bytes=True):
        if type(include_bytes) is not bool:
            fail('disclosure_flag', 'include_bytes must be boolean')
        row = self.get(disclosure_id)
        if row['recipient'] != recipient or row['state'] != 'approved' or row['expired']:
            fail('disclosure_access', 'Recipient or active disclosure permission differs')
        assert_available(self.db, row['manifest_id'])
        items = []
        for proof in row['body']['proofs']:
            item = {'proof': proof}
            if include_bytes:
                item['object'] = self.objects.export(proof['entry']['digest'])
            items.append(item)
        return envelope('sealvault-disclosure', {'disclosure_id': disclosure_id, 'recipient': recipient, 'expires_at': row['expires_at'], 'manifest_sha256': row['body']['manifest_sha256'], 'root': row['body']['root'], 'items': items, 'disclosure_digest': row['digest']})

    def acknowledge(self, disclosure_id, recipient, expected_digest, receipt):
        key(receipt)
        with self.db.transaction():
            row = self.get(disclosure_id)
            if row['recipient'] != recipient or expected_digest != row['digest'] or row['state'] != 'approved' or row['expired']:
                fail('disclosure_receipt', 'Acknowledgement does not match active disclosure')
            previous = self.db.one('SELECT * FROM disclosure_receipts WHERE disclosure_id=?', (disclosure_id,))
            if previous:
                if previous['receipt'] != receipt:
                    fail('disclosure_receipt_conflict', 'Disclosure has another receipt')
                return previous
            self.db.execute('INSERT INTO disclosure_receipts VALUES(?,?,?,?)', (disclosure_id, receipt, expected_digest, self.db.clock()))
            return self.db.one('SELECT * FROM disclosure_receipts WHERE disclosure_id=?', (disclosure_id,))


def verify(value, expected_root, at=None):
    from sealvault.codec import decode, sha256
    data = unwrap(value, 'sealvault-disclosure')
    fields(data, {'disclosure_id', 'recipient', 'expires_at', 'manifest_sha256', 'root', 'items', 'disclosure_digest'})
    if data['root'] != expected_root:
        fail('disclosure_root', 'Disclosure root differs from expected trusted root')
    if at is not None and timestamp(at) >= timestamp(data['expires_at']):
        fail('disclosure_expired', 'Disclosure has expired at verification time')
    paths = set()
    for item in data['items']:
        fields(item, {'proof'}, {'object'})
        proof = item['proof']
        manifests.verify_proof(proof, expected_root)
        if proof['manifest_sha256'] != data['manifest_sha256'] or proof['entry']['path'] in paths:
            fail('disclosure_binding', 'Disclosure proof binding or path uniqueness differs')
        paths.add(proof['entry']['path'])
        if 'object' in item:
            content = decode(item['object']['base64'])
            if sha256(content) != proof['entry']['digest'] or len(content) != proof['entry']['size']:
                fail('disclosure_bytes', 'Disclosure object differs from inclusion proof')
    if not paths:
        fail('disclosure_empty', 'Disclosure contains no evidence')
    return {'valid': True, 'paths': sorted(paths), 'root': expected_root, 'revocation_checked': False}
