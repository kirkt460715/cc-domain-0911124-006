from sealvault.codec import key, text, decode, encode, sha256, canonical, loads, digest, fail
from sealvault.custody import actors
from sealvault.objects import Objects
from sealvault.retention.policy import references

DDL = '''
CREATE TABLE IF NOT EXISTS repairs(repair_id TEXT PRIMARY KEY,object_digest TEXT NOT NULL,author TEXT NOT NULL,content BLOB NOT NULL,proposal TEXT NOT NULL,digest TEXT NOT NULL,state TEXT NOT NULL,reviewer TEXT,reason TEXT NOT NULL);
'''


class Repairs:
    def __init__(self, database):
        self.db = database
        self.objects = Objects(database)
        if database.depth:
            fail('repair_transaction', 'Initialize repair desk outside transactions')
        database.connection.executescript(DDL)

    def propose(self, repair_id, identity, replacement, author, source, reason):
        key(repair_id)
        actors.require(self.db, author, {'custodian'})
        source = text(source, 500)
        reason = text(reason)
        content = decode(replacement)
        with self.db.transaction():
            if self.db.one('SELECT repair_id FROM repairs WHERE repair_id=?', (repair_id,)):
                fail('repair_exists', 'Repair identity is immutable')
            current = self.objects.info(identity)
            if current['state'] != 'quarantined':
                fail('repair_state', 'Only quarantined objects require repair')
            if sha256(content) != identity or len(content) != current['size']:
                fail('repair_content', 'Replacement must match original digest and declared size')
            old = self.db.scalar('SELECT content FROM objects WHERE digest=?', (identity,))
            proposal = {'digest': identity, 'size': current['size'], 'damaged_digest': sha256(old), 'damaged_size': len(old), 'source': source, 'references': references(self.db, identity), 'at': self.db.clock()}
            self.db.execute("INSERT INTO repairs VALUES(?,?,?,?,?,?,'proposed',NULL,?)", (repair_id, identity, author, content, canonical(proposal), digest(proposal), reason))
            self.db.log('repair.proposed', {'repair_id': repair_id, 'author': author, 'proposal_digest': digest(proposal)})
            return self.get(repair_id)

    def get(self, repair_id):
        row = self.db.one('SELECT repair_id,object_digest,author,proposal,digest,state,reviewer,reason FROM repairs WHERE repair_id=?', (repair_id,))
        if row is None:
            fail('repair_missing', 'Repair proposal does not exist')
        row['proposal'] = loads(row['proposal'])
        if digest(row['proposal']) != row['digest']:
            fail('repair_corrupt', 'Repair proposal checksum differs')
        return row

    def apply(self, repair_id, reviewer, expected_digest):
        actors.require(self.db, reviewer, {'custodian', 'administrator'})
        with self.db.transaction():
            row = self.get(repair_id)
            if row['state'] != 'proposed' or row['author'] == reviewer:
                fail('repair_review', 'Independent reviewer must approve a proposed repair')
            if row['digest'] != expected_digest:
                fail('repair_acknowledgement', 'Reviewer must acknowledge exact repair evidence')
            current = self.objects.info(row['object_digest'])
            old = self.db.scalar('SELECT content FROM objects WHERE digest=?', (row['object_digest'],))
            if sha256(old) != row['proposal']['damaged_digest'] or len(old) != row['proposal']['damaged_size']:
                fail('repair_stale', 'Damaged object changed after proposal')
            replacement = self.db.scalar('SELECT content FROM repairs WHERE repair_id=?', (repair_id,))
            self.objects.repair(row['object_digest'], replacement, row['reason'])
            self.db.execute("UPDATE repairs SET state='applied',reviewer=? WHERE repair_id=?", (reviewer, repair_id))
            self.db.log('repair.applied', {'repair_id': repair_id, 'reviewer': reviewer, 'digest': row['object_digest']})
            return self.get(repair_id)

    def reject(self, repair_id, reviewer, reason):
        actors.require(self.db, reviewer, {'custodian', 'administrator'})
        reason = text(reason)
        with self.db.transaction():
            row = self.get(repair_id)
            if row['state'] != 'proposed':
                fail('repair_state', 'Repair has already been decided')
            self.db.execute("UPDATE repairs SET state='rejected',reviewer=? WHERE repair_id=?", (reviewer, repair_id))
            self.db.log('repair.rejected', {'repair_id': repair_id, 'reviewer': reviewer, 'reason': reason})
            return self.get(repair_id)

    def pending(self):
        return [self.get(row['repair_id']) for row in self.db.all("SELECT repair_id FROM repairs WHERE state='proposed' ORDER BY repair_id")]
