from sealvault.codec import key, text, canonical, loads, digest, envelope, fail, integer
from sealvault.custody import actors
from sealvault.retention import policy
from sealvault.custody.seals import Seals

DDL = '''
CREATE TABLE IF NOT EXISTS disposal_reviews(review_id TEXT PRIMARY KEY,manifest_id TEXT NOT NULL,author TEXT NOT NULL,body TEXT NOT NULL,digest TEXT NOT NULL,state TEXT NOT NULL,reviewer TEXT,reason TEXT NOT NULL);
'''


class DisposalDesk:
    def __init__(self, database):
        self.db = database
        if database.depth:
            fail('disposal_transaction', 'Initialize disposal desk outside transactions')
        database.connection.executescript(DDL)

    def impact(self, manifest_id):
        manifest = Seals(self.db).get(manifest_id)
        retention = policy.get(self.db, manifest_id)
        objects = []
        for row in self.db.all('SELECT digest,size FROM manifest_objects WHERE manifest_id=? ORDER BY digest', (manifest_id,)):
            references = policy.references(self.db, row['digest'])
            remaining = [ref for ref in references if not (ref['kind'] == 'manifest' and ref['manifest_id'] == manifest_id)]
            objects.append({**row, 'remaining_references': remaining, 'reclaimable_after_disposal': not remaining})
        return {'manifest_id': manifest_id, 'manifest_hash': manifest['body_hash'], 'retention_revision': retention['revision'], 'retain_until': retention['retain_until'], 'holds': [row['hold_id'] for row in retention['holds']], 'eligible': retention['eligible'], 'objects': objects, 'reclaimable_bytes': sum(row['size'] for row in objects if row['reclaimable_after_disposal'])}

    def propose(self, review_id, manifest_id, author, reason):
        key(review_id)
        actors.require(self.db, author, {'custodian', 'administrator'})
        reason = text(reason)
        with self.db.transaction():
            if self.db.one('SELECT review_id FROM disposal_reviews WHERE review_id=?', (review_id,)):
                fail('disposal_exists', 'Disposal review identity exists')
            body = self.impact(manifest_id)
            if not body['eligible']:
                fail('disposal_protected', 'Manifest is not eligible for disposal')
            self.db.execute("INSERT INTO disposal_reviews VALUES(?,?,?,?,?,'proposed',NULL,?)", (review_id, manifest_id, author, canonical(body), digest(body), reason))
            self.db.log('disposal.proposed', {'review_id': review_id, 'author': author, 'digest': digest(body)})
            return self.get(review_id)

    def get(self, review_id):
        row = self.db.one('SELECT * FROM disposal_reviews WHERE review_id=?', (review_id,))
        if row is None:
            fail('disposal_missing', 'Disposal review does not exist')
        row['body'] = loads(row['body'])
        if digest(row['body']) != row['digest']:
            fail('disposal_corrupt', 'Disposal review checksum differs')
        row['fresh'] = digest(self.impact(row['manifest_id'])) == row['digest']
        return row

    def approve(self, review_id, reviewer, expected_digest):
        actors.require(self.db, reviewer, {'administrator'})
        with self.db.transaction():
            row = self.get(review_id)
            if row['state'] != 'proposed' or row['author'] == reviewer:
                fail('disposal_review', 'Independent administrator must approve proposed disposal')
            if row['digest'] != expected_digest or not row['fresh']:
                fail('disposal_stale', 'Disposal protections or object references changed')
            policy.dispose(self.db, row['manifest_id'], row['body']['retention_revision'], reviewer, row['reason'])
            self.db.execute("UPDATE disposal_reviews SET state='approved',reviewer=? WHERE review_id=?", (reviewer, review_id))
            return self.get(review_id)

    def reject(self, review_id, reviewer, reason):
        actors.require(self.db, reviewer, {'administrator'})
        reason = text(reason)
        with self.db.transaction():
            row = self.get(review_id)
            if row['state'] != 'proposed':
                fail('disposal_state', 'Disposal review already decided')
            self.db.execute("UPDATE disposal_reviews SET state='rejected',reviewer=? WHERE review_id=?", (reviewer, review_id))
            self.db.log('disposal.rejected', {'review_id': review_id, 'reviewer': reviewer, 'reason': reason})
            return self.get(review_id)

    def certificate(self, review_id):
        row = self.get(review_id)
        if row['state'] != 'approved':
            fail('disposal_certificate', 'Only approved disposal issues a certificate')
        manifest = Seals(self.db).get(row['manifest_id'])
        from sealvault.custody.chain import export
        return envelope('sealvault-disposal', {'review_id': review_id, 'manifest_id': row['manifest_id'], 'manifest_hash': manifest['body_hash'], 'review_digest': row['digest'], 'impact': row['body'], 'author': row['author'], 'reviewer': row['reviewer'], 'custody': export(self.db, manifest['case_id']), 'physical_deletion_guaranteed': False})
