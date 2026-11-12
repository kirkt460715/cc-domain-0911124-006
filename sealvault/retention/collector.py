from sealvault.codec import key, integer, canonical, loads, digest, timestamp, fail, text
from sealvault.retention import policy
from sealvault.custody import actors

DDL = '''
CREATE TABLE IF NOT EXISTS gc_plans(plan_id TEXT PRIMARY KEY,created_at TEXT NOT NULL,before_at TEXT NOT NULL,body TEXT NOT NULL,digest TEXT NOT NULL,state TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS gc_results(plan_id TEXT NOT NULL,object_digest TEXT NOT NULL,result TEXT NOT NULL,PRIMARY KEY(plan_id,object_digest));
'''


class Collector:
    def __init__(self, database):
        self.db = database
        if database.depth:
            fail('gc_transaction', 'Initialize collector outside transactions')
        database.connection.executescript(DDL)

    def plan(self, plan_id, created_before, limit=1000):
        key(plan_id)
        created_before = timestamp(created_before)
        integer(limit, 'limit', 1, 10000)
        if created_before > self.db.clock():
            fail('gc_future', 'Collection cutoff cannot be in the future')
        with self.db.transaction():
            if self.db.one('SELECT plan_id FROM gc_plans WHERE plan_id=?', (plan_id,)):
                fail('gc_exists', 'Collection plan identifiers are immutable')
            candidates = []
            protected = []
            for row in self.db.all('SELECT digest,size,state,created_at FROM objects WHERE created_at<=? ORDER BY digest', (created_before,)):
                references = policy.references(self.db, row['digest'])
                if references:
                    protected.append({'digest': row['digest'], 'references': references})
                elif len(candidates) < limit:
                    candidates.append(row)
            body = {'candidates': candidates, 'protected': protected, 'candidate_bytes': sum(row['size'] for row in candidates), 'cutoff': created_before}
            self.db.execute("INSERT INTO gc_plans VALUES(?,?,?,?,?,'prepared')", (plan_id, self.db.clock(), created_before, canonical(body), digest(body)))
            self.db.log('gc.planned', {'plan_id': plan_id, 'count': len(candidates), 'bytes': body['candidate_bytes']})
            return self.get(plan_id)

    def get(self, plan_id):
        row = self.db.one('SELECT * FROM gc_plans WHERE plan_id=?', (plan_id,))
        if row is None:
            fail('gc_missing', 'Collection plan does not exist')
        row['body'] = loads(row['body'])
        if digest(row['body']) != row['digest']:
            fail('gc_corrupt', 'Collection plan checksum differs')
        row['results'] = [loads(item['result']) for item in self.db.all('SELECT result FROM gc_results WHERE plan_id=? ORDER BY object_digest', (plan_id,))]
        return row

    def advance(self, plan_id, actor, expected_digest, limit=100):
        actors.require(self.db, actor, {'administrator'})
        integer(limit, 'limit', 1, 1000)
        with self.db.transaction():
            plan = self.get(plan_id)
            if plan['digest'] != expected_digest:
                fail('gc_acknowledgement', 'Collector must acknowledge exact reviewed plan')
            if plan['state'] == 'complete':
                return plan
            done = {row['digest'] for row in plan['results']}
            pending = [row for row in plan['body']['candidates'] if row['digest'] not in done][:limit]
            for item in pending:
                identity = item['digest']
                current = self.db.one('SELECT digest,size,created_at FROM objects WHERE digest=?', (identity,))
                references = policy.references(self.db, identity)
                if current is None:
                    result = {'digest': identity, 'state': 'already_absent', 'bytes': 0}
                elif references:
                    result = {'digest': identity, 'state': 'protected_since_plan', 'references': references, 'bytes': 0}
                elif current['created_at'] != item['created_at'] or current['size'] != item['size']:
                    result = {'digest': identity, 'state': 'changed_since_plan', 'bytes': 0}
                else:
                    self.db.execute('DELETE FROM objects WHERE digest=?', (identity,))
                    result = {'digest': identity, 'state': 'deleted', 'bytes': item['size']}
                self.db.execute('INSERT INTO gc_results VALUES(?,?,?)', (plan_id, identity, canonical(result)))
            count = len(done) + len(pending)
            state = 'complete' if count == len(plan['body']['candidates']) else 'running'
            self.db.execute('UPDATE gc_plans SET state=? WHERE plan_id=?', (state, plan_id))
            self.db.log('gc.advanced', {'plan_id': plan_id, 'actor': actor, 'processed': len(pending), 'state': state})
            return self.get(plan_id)

    def report(self, plan_id):
        plan = self.get(plan_id)
        counts = {}
        for row in plan['results']:
            counts[row['state']] = counts.get(row['state'], 0) + 1
        return {'plan_id': plan_id, 'state': plan['state'], 'counts': counts, 'deleted_bytes': sum(row['bytes'] for row in plan['results']), 'remaining': len(plan['body']['candidates']) - len(plan['results'])}

    def expire_temporary(self, actor):
        actors.require(self.db, actor, {'administrator'})
        with self.db.transaction():
            now = self.db.clock()
            pins = self.db.all('SELECT pin_id FROM pins WHERE expires_at<=?', (now,))
            sessions = self.db.all("SELECT session_id FROM staging WHERE state='receiving' AND expires_at<=?", (now,))
            self.db.execute('DELETE FROM pins WHERE expires_at<=?', (now,))
            for session in sessions:
                self.db.execute("UPDATE staging SET state='expired' WHERE session_id=?", (session['session_id'],))
                self.db.execute('DELETE FROM stage_chunks WHERE session_id=?', (session['session_id'],))
            self.db.log('gc.temporary_expired', {'actor': actor, 'pins': [row['pin_id'] for row in pins], 'sessions': [row['session_id'] for row in sessions]})
            return {'pins': len(pins), 'sessions': len(sessions)}
