from sealvault.codec import key, canonical, loads, digest, envelope, unwrap, fields, fail, timestamp
from sealvault.custody import actors, chain

DDL = '''
CREATE TABLE IF NOT EXISTS custody_checkpoints(checkpoint_id TEXT PRIMARY KEY,case_id TEXT NOT NULL,sequence INTEGER NOT NULL,head TEXT NOT NULL,body TEXT NOT NULL,digest TEXT NOT NULL,author TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS witness_receipts(checkpoint_id TEXT NOT NULL,witness TEXT NOT NULL,receipt TEXT NOT NULL,acknowledged_at TEXT NOT NULL,PRIMARY KEY(checkpoint_id,witness));
'''


class Checkpoints:
    def __init__(self, database):
        self.db = database
        if database.depth:
            fail('checkpoint_transaction', 'Initialize custody checkpoints outside transactions')
        database.connection.executescript(DDL)

    def capture(self, checkpoint_id, case_id, author):
        key(checkpoint_id)
        actors.require(self.db, author, {'auditor', 'custodian'})
        with self.db.transaction():
            if self.db.one('SELECT checkpoint_id FROM custody_checkpoints WHERE checkpoint_id=?', (checkpoint_id,)):
                fail('checkpoint_exists', 'Checkpoint identity is immutable')
            verified = chain.verify(self.db, case_id)
            case = self.db.one('SELECT * FROM cases WHERE case_id=?', (case_id,))
            if case is None:
                fail('case_missing', 'Custody case is absent')
            body = {'case_id': case_id, 'sequence': verified['count'], 'head': verified['head'], 'case_revision': case['revision'], 'state': case['state'], 'owner': case['owner'], 'captured_at': self.db.clock()}
            self.db.execute('INSERT INTO custody_checkpoints VALUES(?,?,?,?,?,?,?)', (checkpoint_id, case_id, verified['count'], verified['head'], canonical(body), digest(body), author))
            self.db.log('custody.checkpoint', {'checkpoint_id': checkpoint_id, 'case_id': case_id, 'head': verified['head'], 'author': author})
            return self.get(checkpoint_id)

    def get(self, checkpoint_id):
        row = self.db.one('SELECT * FROM custody_checkpoints WHERE checkpoint_id=?', (checkpoint_id,))
        if row is None:
            fail('checkpoint_missing', 'Custody checkpoint does not exist')
        row['body'] = loads(row['body'])
        if digest(row['body']) != row['digest']:
            fail('checkpoint_corrupt', 'Checkpoint checksum differs')
        if (row['case_id'], row['sequence'], row['head']) != (row['body']['case_id'], row['body']['sequence'], row['body']['head']):
            fail('checkpoint_index', 'Checkpoint index differs from captured body')
        row['receipts'] = self.db.all('SELECT * FROM witness_receipts WHERE checkpoint_id=? ORDER BY witness', (checkpoint_id,))
        return row

    def acknowledge(self, checkpoint_id, witness, expected_digest, receipt):
        key(witness)
        key(receipt)
        with self.db.transaction():
            row = self.get(checkpoint_id)
            if row['digest'] != expected_digest:
                fail('checkpoint_acknowledgement', 'Witness must acknowledge exact checkpoint')
            if witness == row['author']:
                fail('checkpoint_witness', 'Checkpoint author cannot act as independent witness')
            previous = self.db.one('SELECT * FROM witness_receipts WHERE checkpoint_id=? AND witness=?', (checkpoint_id, witness))
            if previous:
                if previous['receipt'] != receipt:
                    fail('checkpoint_receipt', 'Witness already acknowledged with another receipt')
                return previous
            self.db.execute('INSERT INTO witness_receipts VALUES(?,?,?,?)', (checkpoint_id, witness, receipt, self.db.clock()))
            self.db.log('custody.witness_receipt', {'checkpoint_id': checkpoint_id, 'witness': witness, 'receipt': receipt})
            return self.db.one('SELECT * FROM witness_receipts WHERE checkpoint_id=? AND witness=?', (checkpoint_id, witness))

    def verify_live(self, checkpoint_id):
        row = self.get(checkpoint_id)
        event = self.db.one('SELECT entry_hash FROM custody WHERE case_id=? AND sequence=?', (row['case_id'], row['sequence']))
        if event is None or event['entry_hash'] != row['head']:
            fail('checkpoint_diverged', 'Local custody history diverges from captured checkpoint')
        verified = chain.verify(self.db, row['case_id'])
        return {'valid': True, 'checkpoint_id': checkpoint_id, 'captured_sequence': row['sequence'], 'current_sequence': verified['count'], 'additional_events': verified['count'] - row['sequence'], 'head': verified['head'], 'witnesses': [item['witness'] for item in row['receipts']]}

    def extension(self, checkpoint_id):
        row = self.get(checkpoint_id)
        current = self.verify_live(checkpoint_id)
        events = chain.history(self.db, row['case_id'], row['sequence'], 10000)
        return envelope('sealvault-custody-extension', {'checkpoint_id': checkpoint_id, 'checkpoint': row['body'], 'checkpoint_digest': row['digest'], 'events': events, 'head': current['head'], 'witness_receipts': row['receipts']})

    def export(self, checkpoint_id):
        row = self.get(checkpoint_id)
        return envelope('sealvault-checkpoint', {'checkpoint_id': checkpoint_id, 'body': row['body'], 'digest': row['digest'], 'author': row['author'], 'witness_receipts': row['receipts']})


def verify_extension(value, expected_checkpoint_digest):
    data = unwrap(value, 'sealvault-custody-extension')
    fields(data, {'checkpoint_id', 'checkpoint', 'checkpoint_digest', 'events', 'head', 'witness_receipts'})
    checkpoint = data['checkpoint']
    if digest(checkpoint) != data['checkpoint_digest'] or data['checkpoint_digest'] != expected_checkpoint_digest:
        fail('extension_anchor', 'Extension does not start at expected checkpoint')
    previous = checkpoint['head']
    sequence = checkpoint['sequence']
    at = checkpoint['captured_at']
    if not isinstance(data['events'], list) or len(data['events']) > 10000:
        fail('extension_events', 'Extension contains invalid event collection')
    for row in data['events']:
        sequence += 1
        if row['case_id'] != checkpoint['case_id'] or row['sequence'] != sequence or row['previous_hash'] != previous:
            fail('extension_sequence', 'Extension skips or changes predecessor event')
        if timestamp(row['at']) != row['at'] or row['at'] < at:
            fail('extension_time', 'Extension event time precedes anchor')
        computed = digest([row['case_id'], sequence, previous, row['action'], row['actor'], canonical(row['body']), row['at']])
        if row['entry_hash'] != computed:
            fail('extension_digest', 'Extension event checksum differs')
        previous = computed
        at = row['at']
    if previous != data['head']:
        fail('extension_head', 'Extension does not reach declared final head')
    return {'valid': True, 'case_id': checkpoint['case_id'], 'from_sequence': checkpoint['sequence'], 'to_sequence': sequence, 'head': previous, 'authentication': 'requires_independently_trusted_checkpoint_digest'}


def compare_checkpoints(left, right):
    before = unwrap(left, 'sealvault-checkpoint')
    after = unwrap(right, 'sealvault-checkpoint')
    for value in (before, after):
        if digest(value['body']) != value['digest']:
            fail('checkpoint_corrupt', 'Exported checkpoint checksum differs')
    if before['body']['case_id'] != after['body']['case_id']:
        fail('checkpoint_scope', 'Checkpoints refer to different cases')
    first = before['body']['sequence']
    second = after['body']['sequence']
    if first == second:
        state = 'same_history' if before['body']['head'] == after['body']['head'] else 'conflicting_history'
    else:
        state = 'extension_proof_required'
    return {'case_id': before['body']['case_id'], 'state': state, 'before_sequence': first, 'after_sequence': second, 'sequence_delta': second - first}


def audit_all(db):
    desk = object.__new__(Checkpoints)
    desk.db = db
    from sealvault.codec import VaultError
    results = []
    failures = []
    for row in db.all('SELECT checkpoint_id FROM custody_checkpoints ORDER BY checkpoint_id'):
        try:
            results.append(desk.verify_live(row['checkpoint_id']))
        except VaultError as exc:
            failures.append({'checkpoint_id': row['checkpoint_id'], **exc.payload()})
    return {'valid': not failures, 'verified': results, 'failures': failures}
