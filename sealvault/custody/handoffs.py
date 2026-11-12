from sealvault.codec import key, text, timestamp, canonical, loads, digest, fail
from sealvault.custody import actors, chain
from sealvault.custody.cases import Cases

DDL = '''
CREATE TABLE IF NOT EXISTS handoffs(handoff_id TEXT PRIMARY KEY,case_id TEXT NOT NULL,revision INTEGER NOT NULL,source TEXT NOT NULL,destination TEXT NOT NULL,fingerprint TEXT NOT NULL,state TEXT NOT NULL,expires_at TEXT NOT NULL,reason TEXT NOT NULL,receipt TEXT);
'''


def fingerprint(case):
    return digest({name: case[name] for name in ('case_id', 'revision', 'owner', 'state', 'classification', 'entries')})


class Handoffs:
    def __init__(self, database):
        self.db = database
        self.cases = Cases(database)
        if database.depth:
            fail('handoff_transaction', 'Initialize handoffs outside transactions')
        database.connection.executescript(DDL)

    def propose(self, handoff_id, case_id, source, destination, expected_revision, expires_at, reason):
        key(handoff_id)
        actors.require(self.db, source, {'collector', 'custodian'})
        actors.require(self.db, destination, {'collector', 'custodian'})
        if source == destination:
            fail('handoff_same', 'Handoff requires different custodians')
        expires_at = timestamp(expires_at)
        if expires_at <= self.db.clock():
            fail('handoff_expiry', 'Handoff must expire in future')
        reason = text(reason)
        with self.db.transaction():
            case = self.cases.get(case_id)
            if case['owner'] != source or case['revision'] != expected_revision or case['state'] == 'abandoned':
                fail('handoff_source', 'Owner, revision or case state changed')
            if self.db.one('SELECT handoff_id FROM handoffs WHERE handoff_id=?', (handoff_id,)):
                fail('handoff_exists', 'Handoff identifier already exists')
            self.db.execute("INSERT INTO handoffs VALUES(?,?,?,?,?,?,'proposed',?,?,NULL)", (handoff_id, case_id, expected_revision, source, destination, fingerprint(case), expires_at, reason))
            chain.append(self.db, case_id, 'handoff_proposed', source, {'handoff_id': handoff_id, 'destination': destination, 'fingerprint': fingerprint(case), 'expires_at': expires_at})
            return self.get(handoff_id)

    def get(self, handoff_id):
        row = self.db.one('SELECT * FROM handoffs WHERE handoff_id=?', (handoff_id,))
        if row is None:
            fail('handoff_missing', 'Handoff does not exist')
        row['fresh'] = fingerprint(self.cases.get(row['case_id'])) == row['fingerprint']
        row['expired'] = row['expires_at'] <= self.db.clock()
        return row

    def accept(self, handoff_id, destination, expected_fingerprint, receipt):
        actors.require(self.db, destination, {'collector', 'custodian'})
        key(receipt)
        with self.db.transaction():
            handoff = self.get(handoff_id)
            if handoff['destination'] != destination or handoff['fingerprint'] != expected_fingerprint:
                fail('handoff_acknowledgement', 'Destination must acknowledge exact case fingerprint')
            if handoff['state'] == 'accepted':
                if handoff['receipt'] != receipt:
                    fail('handoff_receipt', 'Handoff already has a different receipt')
                return handoff
            if handoff['state'] != 'proposed' or handoff['expired'] or not handoff['fresh']:
                fail('handoff_stale', 'Handoff expired, changed or was already decided')
            actors.require(self.db, handoff['source'])
            self.db.execute('UPDATE cases SET owner=?,revision=revision+1 WHERE case_id=?', (destination, handoff['case_id']))
            self.db.execute("UPDATE handoffs SET state='accepted',receipt=? WHERE handoff_id=?", (receipt, handoff_id))
            chain.append(self.db, handoff['case_id'], 'handoff_accepted', destination, {'handoff_id': handoff_id, 'source': handoff['source'], 'receipt': receipt, 'fingerprint': expected_fingerprint})
            return self.get(handoff_id)

    def reject(self, handoff_id, destination, reason):
        actors.require(self.db, destination)
        reason = text(reason)
        with self.db.transaction():
            handoff = self.get(handoff_id)
            if handoff['destination'] != destination or handoff['state'] != 'proposed':
                fail('handoff_reject', 'Only destination may reject proposed handoff')
            self.db.execute("UPDATE handoffs SET state='rejected' WHERE handoff_id=?", (handoff_id,))
            chain.append(self.db, handoff['case_id'], 'handoff_rejected', destination, {'handoff_id': handoff_id, 'reason': reason})
            return self.get(handoff_id)

    def cancel(self, handoff_id, source, reason):
        actors.require(self.db, source)
        reason = text(reason)
        with self.db.transaction():
            handoff = self.get(handoff_id)
            if handoff['source'] != source or handoff['state'] != 'proposed':
                fail('handoff_cancel', 'Only source may cancel proposed handoff')
            self.db.execute("UPDATE handoffs SET state='cancelled' WHERE handoff_id=?", (handoff_id,))
            chain.append(self.db, handoff['case_id'], 'handoff_cancelled', source, {'handoff_id': handoff_id, 'reason': reason})
            return self.get(handoff_id)
