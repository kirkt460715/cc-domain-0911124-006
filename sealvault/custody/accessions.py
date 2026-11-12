from sealvault.codec import key, fields, integer, canonical, loads, digest, decode, sha256, fail, VaultError, text
from sealvault import manifests
from sealvault.objects import Objects
from sealvault.custody import actors, chain
from sealvault.custody.cases import Cases

DDL = '''
CREATE TABLE IF NOT EXISTS accessions(accession_id TEXT PRIMARY KEY,case_id TEXT NOT NULL,owner TEXT NOT NULL,revision INTEGER NOT NULL,body TEXT NOT NULL,digest TEXT NOT NULL,cursor INTEGER NOT NULL,state TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS accession_rows(accession_id TEXT NOT NULL,ordinal INTEGER NOT NULL,state TEXT NOT NULL,result TEXT NOT NULL,PRIMARY KEY(accession_id,ordinal));
'''


class Accessions:
    def __init__(self, database):
        self.db = database
        self.objects = Objects(database)
        self.cases = Cases(database)
        if database.depth:
            fail('accession_transaction', 'Initialize accession desk outside transactions')
        database.connection.executescript(DDL)

    def start(self, accession_id, case_id, expected_revision, owner, records):
        key(accession_id)
        if not isinstance(records, list) or not 1 <= len(records) <= 1000:
            fail('accession_records', 'Accession requires one to one thousand records')
        if len(canonical(records).encode()) > 33554432:
            fail('accession_size', 'Accession input exceeds 32 MiB')
        with self.db.transaction():
            self.cases.editable(case_id, expected_revision, owner)
            previous = self.db.one('SELECT * FROM accessions WHERE accession_id=?', (accession_id,))
            if previous:
                if (previous['case_id'], previous['owner'], previous['digest']) != (case_id, owner, digest(records)):
                    fail('accession_conflict', 'Accession identifier binds different input')
                return self.get(accession_id)
            self.db.execute("INSERT INTO accessions VALUES(?,?,?,?,?,?,0,'running')", (accession_id, case_id, owner, expected_revision, canonical(records), digest(records)))
            chain.append(self.db, case_id, 'accession_started', owner, {'accession_id': accession_id, 'records': len(records), 'digest': digest(records)})
            return self.get(accession_id)

    def get(self, accession_id):
        row = self.db.one('SELECT * FROM accessions WHERE accession_id=?', (accession_id,))
        if row is None:
            fail('accession_missing', 'Accession does not exist')
        records = loads(row.pop('body'))
        if digest(records) != row['digest']:
            fail('accession_corrupt', 'Accession source records checksum differs')
        row['total'] = len(records)
        row['results'] = self.db.all('SELECT ordinal,state,result FROM accession_rows WHERE accession_id=? ORDER BY ordinal', (accession_id,))
        for item in row['results']:
            item['result'] = loads(item['result'])
        row['failed'] = sum(item['state'] == 'rejected' for item in row['results'])
        return row

    def advance(self, accession_id, owner, limit=50):
        integer(limit, 'limit', 1, 500)
        with self.db.transaction():
            accession = self.get(accession_id)
            if accession['owner'] != owner:
                fail('accession_owner', 'Accession owner differs')
            if accession['state'] != 'running':
                return accession
            self.cases.editable(accession['case_id'], accession['revision'], owner)
            records = loads(self.db.scalar('SELECT body FROM accessions WHERE accession_id=?', (accession_id,)))
            stop = min(len(records), accession['cursor'] + limit)
            revision = accession['revision']
            for ordinal in range(accession['cursor'], stop):
                try:
                    with self.db.transaction():
                        record = records[ordinal]
                        fields(record, {'path', 'content', 'media_type'}, {'metadata', 'expected_digest'})
                        content = decode(record['content'])
                        stored = self.objects.put(content, record.get('expected_digest'))
                        entry = {'path': record['path'], 'digest': stored['digest'], 'size': len(content), 'media_type': record['media_type'], 'metadata': record.get('metadata', {})}
                        case = self.cases.attach(accession['case_id'], revision, owner, entry)
                        revision = case['revision']
                        state = 'accepted'
                        result = {'entry': manifests.entry(entry), 'duplicate_object': stored['duplicate']}
                except VaultError as exc:
                    state = 'rejected'
                    result = exc.payload()
                self.db.execute('INSERT INTO accession_rows VALUES(?,?,?,?)', (accession_id, ordinal, state, canonical(result)))
            state = 'review' if stop == len(records) else 'running'
            self.db.execute('UPDATE accessions SET cursor=?,revision=?,state=? WHERE accession_id=?', (stop, revision, state, accession_id))
            return self.get(accession_id)

    def rebase(self, accession_id, owner, expected_case_revision, reason):
        reason = text(reason)
        with self.db.transaction():
            accession = self.get(accession_id)
            if accession['owner'] != owner or accession['state'] != 'running':
                fail('accession_rebase', 'Only owner can rebase a running accession')
            self.cases.editable(accession['case_id'], expected_case_revision, owner)
            self.db.execute('UPDATE accessions SET revision=? WHERE accession_id=?', (expected_case_revision, accession_id))
            chain.append(self.db, accession['case_id'], 'accession_rebased', owner, {'accession_id': accession_id, 'revision': expected_case_revision, 'reason': reason})
            return self.get(accession_id)

    def finish(self, accession_id, owner, allow_rejected=False):
        if type(allow_rejected) is not bool:
            fail('accession_flag', 'allow_rejected must be boolean')
        with self.db.transaction():
            accession = self.get(accession_id)
            if accession['owner'] != owner or accession['state'] not in {'review', 'complete', 'partial'}:
                fail('accession_finish', 'Accession must reach review before completion')
            if accession['state'] in {'complete', 'partial'}:
                return accession
            if accession['failed'] and not allow_rejected:
                fail('accession_failures', 'Explicit partial acceptance required for rejected source records')
            state = 'partial' if accession['failed'] else 'complete'
            self.db.execute('UPDATE accessions SET state=? WHERE accession_id=?', (state, accession_id))
            chain.append(self.db, accession['case_id'], 'accession_finished', owner, {'accession_id': accession_id, 'state': state, 'rejected': accession['failed']})
            return self.get(accession_id)
