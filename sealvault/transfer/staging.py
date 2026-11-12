from sealvault.codec import key, checksum, integer, timestamp, sha256, decode, fail, text
from sealvault.objects import Objects, MAX_OBJECT
from sealvault.custody import actors


class Staging:
    def __init__(self, database):
        self.db = database
        self.objects = Objects(database)

    def begin(self, session_id, expected_digest, total_size, chunk_size, owner, expires_at):
        key(session_id)
        checksum(expected_digest)
        integer(total_size, 'total_size', 0, MAX_OBJECT)
        integer(chunk_size, 'chunk_size', 1, 1048576)
        actors.require(self.db, owner, {'collector', 'custodian'})
        expires_at = timestamp(expires_at)
        if expires_at <= self.db.clock():
            fail('stage_expiry', 'Staging session must expire in future')
        with self.db.transaction():
            prior = self.db.one('SELECT * FROM staging WHERE session_id=?', (session_id,))
            expected = (expected_digest, total_size, chunk_size, owner, expires_at)
            if prior:
                if (prior['expected_digest'], prior['total_size'], prior['chunk_size'], prior['owner'], prior['expires_at']) != expected:
                    fail('stage_conflict', 'Staging session binds other transfer parameters')
                return self.status(session_id)
            from sealvault.quotas import stage_capacity
            stage_capacity(self.db, total_size)
            self.db.execute("INSERT INTO staging VALUES(?,?,?,?,'receiving',?,?)", (session_id, expected_digest, total_size, chunk_size, expires_at, owner))
            self.db.log('stage.started', {'session_id': session_id, 'expected_digest': expected_digest, 'total_size': total_size})
            return self.status(session_id)

    def status(self, session_id):
        row = self.db.one('SELECT * FROM staging WHERE session_id=?', (session_id,))
        if row is None:
            fail('stage_missing', 'Staging session does not exist')
        row['count'] = (row['total_size'] + row['chunk_size'] - 1) // row['chunk_size']
        row['received'] = [item['ordinal'] for item in self.db.all('SELECT ordinal FROM stage_chunks WHERE session_id=? ORDER BY ordinal', (session_id,))]
        row['missing'] = sorted(set(range(row['count'])) - set(row['received']))
        row['expired'] = row['expires_at'] <= self.db.clock()
        return row

    def receive(self, session_id, owner, ordinal, content, chunk_digest):
        integer(ordinal, 'ordinal')
        checksum(chunk_digest)
        data = decode(content, 1048576)
        if sha256(data) != chunk_digest:
            fail('stage_chunk_digest', 'Chunk content differs from declared checksum')
        actors.require(self.db, owner)
        with self.db.transaction():
            session = self.status(session_id)
            if session['owner'] != owner:
                fail('stage_owner', 'Transfer owner differs')
            if session['state'] != 'receiving' or session['expired']:
                fail('stage_state', 'Staging session is terminal or expired')
            if ordinal >= session['count']:
                fail('stage_ordinal', 'Chunk ordinal exceeds declared object')
            length = min(session['chunk_size'], session['total_size'] - ordinal * session['chunk_size'])
            if len(data) != length:
                fail('stage_chunk_size', 'Chunk length differs from its declared range')
            prior = self.db.one('SELECT digest,content FROM stage_chunks WHERE session_id=? AND ordinal=?', (session_id, ordinal))
            if prior:
                if prior['digest'] != chunk_digest or prior['content'] != data:
                    fail('stage_chunk_conflict', 'Chunk ordinal already binds different bytes')
                return self.status(session_id)
            self.db.execute('INSERT INTO stage_chunks VALUES(?,?,?,?)', (session_id, ordinal, chunk_digest, data))
            return self.status(session_id)

    def commit(self, session_id, owner):
        actors.require(self.db, owner)
        with self.db.transaction():
            session = self.status(session_id)
            if session['owner'] != owner:
                fail('stage_owner', 'Transfer owner differs')
            if session['state'] == 'committed':
                self.objects.read(session['expected_digest'])
                return self.objects.info(session['expected_digest'])
            if session['state'] != 'receiving' or session['expired']:
                fail('stage_state', 'Only a live receiving session may commit')
            if session['missing']:
                fail('stage_incomplete', 'Some chunks have not arrived', missing=session['missing'])
            rows = self.db.all('SELECT * FROM stage_chunks WHERE session_id=? ORDER BY ordinal', (session_id,))
            for row in rows:
                if sha256(row['content']) != row['digest']:
                    fail('stage_corrupt', 'Stored staging chunk checksum differs')
            content = b''.join(row['content'] for row in rows)
            if len(content) != session['total_size'] or sha256(content) != session['expected_digest']:
                fail('stage_object_digest', 'Assembled object differs from declaration')
            result = self.objects.put(content, session['expected_digest'])
            self.db.execute("UPDATE staging SET state='committed' WHERE session_id=?", (session_id,))
            self.db.execute('DELETE FROM stage_chunks WHERE session_id=?', (session_id,))
            self.db.log('stage.committed', {'session_id': session_id, 'digest': session['expected_digest']})
            return result

    def cancel(self, session_id, owner, reason):
        actors.require(self.db, owner)
        reason = text(reason)
        with self.db.transaction():
            session = self.status(session_id)
            if session['owner'] != owner or session['state'] != 'receiving':
                fail('stage_cancel', 'Only owner may cancel a receiving session')
            self.db.execute("UPDATE staging SET state='cancelled' WHERE session_id=?", (session_id,))
            self.db.execute('DELETE FROM stage_chunks WHERE session_id=?', (session_id,))
            self.db.log('stage.cancelled', {'session_id': session_id, 'owner': owner, 'reason': reason})
            return self.status(session_id)

    def renew(self, session_id, owner, expires_at):
        actors.require(self.db, owner)
        expires_at = timestamp(expires_at)
        with self.db.transaction():
            session = self.status(session_id)
            if session['owner'] != owner or session['state'] != 'receiving' or session['expired']:
                fail('stage_renew', 'Only an active receiving owner may renew')
            if expires_at <= session['expires_at']:
                fail('stage_expiry', 'Renewal must extend expiration')
            self.db.execute('UPDATE staging SET expires_at=? WHERE session_id=?', (expires_at, session_id))
            return self.status(session_id)
