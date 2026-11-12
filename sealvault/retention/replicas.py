from sealvault.codec import key, timestamp, text, canonical, loads, digest, fail
from sealvault.custody import actors
from sealvault.custody.seals import verify_export

DDL = '''
CREATE TABLE IF NOT EXISTS replica_retention(import_id TEXT PRIMARY KEY,revision INTEGER NOT NULL,retain_until TEXT NOT NULL,state TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS replica_holds(hold_id TEXT PRIMARY KEY,import_id TEXT NOT NULL,actor TEXT NOT NULL,reason TEXT NOT NULL,state TEXT NOT NULL);
'''


class ReplicaPolicies:
    def __init__(self, database):
        self.db = database
        if database.depth:
            fail('replica_transaction', 'Initialize replica policies outside transactions')
        database.connection.executescript(DDL)

    def retain(self, import_id, expected_revision, retain_until, actor):
        actors.require(self.db, actor, {'custodian', 'administrator'})
        retain_until = timestamp(retain_until)
        with self.db.transaction():
            replica = self.db.one('SELECT * FROM replicas WHERE import_id=?', (import_id,))
            if replica is None or replica['state'] != 'retained':
                fail('replica_state', 'Replica is absent or already released')
            prior = self.db.one('SELECT * FROM replica_retention WHERE import_id=?', (import_id,))
            revision = prior['revision'] if prior else 0
            if revision != expected_revision:
                fail('replica_retention_stale', 'Replica retention revision changed')
            if retain_until <= self.db.clock() or prior and retain_until <= prior['retain_until']:
                fail('replica_retention_date', 'Replica retention can only extend into future')
            self.db.execute("INSERT INTO replica_retention VALUES(?,?,?,'active') ON CONFLICT(import_id) DO UPDATE SET revision=excluded.revision,retain_until=excluded.retain_until", (import_id, revision + 1, retain_until))
            self.db.log('replica.retained', {'import_id': import_id, 'retain_until': retain_until, 'actor': actor})
            return self.get(import_id)

    def get(self, import_id):
        replica = self.db.one('SELECT import_id,state FROM replicas WHERE import_id=?', (import_id,))
        if replica is None:
            fail('replica_missing', 'Replica does not exist')
        policy = self.db.one('SELECT * FROM replica_retention WHERE import_id=?', (import_id,))
        holds = self.db.all("SELECT * FROM replica_holds WHERE import_id=? AND state='active' ORDER BY hold_id", (import_id,))
        return {'replica': replica, 'policy': policy, 'holds': holds, 'eligible': replica['state'] == 'retained' and policy is not None and policy['retain_until'] <= self.db.clock() and not holds}

    def hold(self, hold_id, import_id, actor, reason):
        key(hold_id)
        actors.require(self.db, actor, {'custodian', 'administrator'})
        reason = text(reason)
        with self.db.transaction():
            current = self.get(import_id)
            if current['replica']['state'] != 'retained':
                fail('replica_state', 'Released replica cannot receive a hold')
            previous = self.db.one('SELECT * FROM replica_holds WHERE hold_id=?', (hold_id,))
            if previous:
                if (previous['import_id'], previous['actor'], previous['reason']) != (import_id, actor, reason):
                    fail('replica_hold_conflict', 'Hold identity already binds another request')
                return previous
            self.db.execute("INSERT INTO replica_holds VALUES(?,?,?,?,'active')", (hold_id, import_id, actor, reason))
            self.db.log('replica.held', {'hold_id': hold_id, 'import_id': import_id, 'actor': actor})
            return self.db.one('SELECT * FROM replica_holds WHERE hold_id=?', (hold_id,))

    def release_hold(self, hold_id, administrator, reason):
        actors.require(self.db, administrator, {'administrator'})
        reason = text(reason)
        with self.db.transaction():
            row = self.db.one('SELECT * FROM replica_holds WHERE hold_id=?', (hold_id,))
            if row is None:
                fail('replica_hold_missing', 'Replica hold does not exist')
            if row['actor'] == administrator:
                fail('replica_hold_separation', 'Hold originator cannot release own hold')
            self.db.execute("UPDATE replica_holds SET state='released' WHERE hold_id=?", (hold_id,))
            self.db.log('replica.hold_released', {'hold_id': hold_id, 'actor': administrator, 'reason': reason})
            return self.get(row['import_id'])

    def release(self, import_id, administrator, reason):
        actors.require(self.db, administrator, {'administrator'})
        reason = text(reason)
        with self.db.transaction():
            current = self.get(import_id)
            if not current['eligible']:
                fail('replica_protected', 'Replica must have expired explicit retention and no active hold')
            self.db.execute("UPDATE replicas SET state='released' WHERE import_id=?", (import_id,))
            self.db.execute("UPDATE replica_retention SET state='released',revision=revision+1 WHERE import_id=?", (import_id,))
            for row in self.db.all('SELECT object_digest FROM imported_objects WHERE import_id=?', (import_id,)):
                pin_id = 'replica-' + digest([import_id, row['object_digest']])[:32]
                self.db.execute('DELETE FROM pins WHERE pin_id=?', (pin_id,))
            self.db.log('replica.released', {'import_id': import_id, 'actor': administrator, 'reason': reason})
            return self.get(import_id)


def references(db, identity):
    table = db.one("SELECT name FROM sqlite_master WHERE name='replicas'")
    if not table:
        return []
    rows = db.all("SELECT r.import_id,r.manifest_id FROM replicas r JOIN imported_objects o ON o.import_id=r.import_id WHERE o.object_digest=? AND r.state='retained' ORDER BY r.import_id", (identity,))
    return [{'kind': 'replica', **row} for row in rows]
