from sealvault.codec import key, integer, digest, canonical, loads, fail
from sealvault.objects import Objects
from sealvault.custody import actors
from sealvault.retention.policy import references

DDL = '''
CREATE TABLE IF NOT EXISTS scrub_runs(run_id TEXT PRIMARY KEY,state TEXT NOT NULL,inventory TEXT NOT NULL,inventory_hash TEXT NOT NULL,cursor INTEGER NOT NULL,quarantine INTEGER NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scrub_results(run_id TEXT NOT NULL,ordinal INTEGER NOT NULL,result TEXT NOT NULL,PRIMARY KEY(run_id,ordinal));
'''


class Scrubber:
    def __init__(self, database):
        self.db = database
        self.objects = Objects(database)
        if database.depth:
            fail('scrub_transaction', 'Initialize scrubber outside transactions')
        database.connection.executescript(DDL)

    def start(self, run_id, actor, quarantine=False):
        key(run_id)
        actors.require(self.db, actor, {'auditor', 'custodian', 'administrator'})
        if type(quarantine) is not bool:
            fail('scrub_flag', 'Quarantine must be boolean')
        if quarantine:
            actors.require(self.db, actor, {'custodian', 'administrator'})
        with self.db.transaction():
            if self.db.one('SELECT run_id FROM scrub_runs WHERE run_id=?', (run_id,)):
                fail('scrub_exists', 'Scrub run identifier is immutable')
            inventory = self.db.all('SELECT digest,size,created_at FROM objects ORDER BY digest')
            self.db.execute("INSERT INTO scrub_runs VALUES(?,'running',?,?,0,?,?)", (run_id, canonical(inventory), digest(inventory), int(quarantine), self.db.clock()))
            self.db.log('scrub.started', {'run_id': run_id, 'objects': len(inventory), 'quarantine': quarantine, 'actor': actor})
            return self.get(run_id)

    def get(self, run_id):
        row = self.db.one('SELECT * FROM scrub_runs WHERE run_id=?', (run_id,))
        if row is None:
            fail('scrub_missing', 'Scrub run does not exist')
        row['inventory'] = loads(row['inventory'])
        if digest(row['inventory']) != row['inventory_hash']:
            fail('scrub_corrupt', 'Scrub inventory checksum differs')
        row['results'] = [loads(item['result']) for item in self.db.all('SELECT result FROM scrub_results WHERE run_id=? ORDER BY ordinal', (run_id,))]
        if len(row['results']) != row['cursor']:
            fail('scrub_checkpoint', 'Scrub cursor differs from stored results')
        return row

    def advance(self, run_id, actor, limit=100):
        actors.require(self.db, actor, {'auditor', 'custodian', 'administrator'})
        integer(limit, 'limit', 1, 1000)
        with self.db.transaction():
            run = self.get(run_id)
            if run['quarantine']:
                actors.require(self.db, actor, {'custodian', 'administrator'})
            if run['state'] != 'running':
                return run
            stop = min(len(run['inventory']), run['cursor'] + limit)
            for ordinal in range(run['cursor'], stop):
                item = run['inventory'][ordinal]
                current = self.db.one('SELECT digest,size,created_at FROM objects WHERE digest=?', (item['digest'],))
                if current is None:
                    result = {'digest': item['digest'], 'status': 'absent_since_snapshot', 'valid': None}
                elif current != item:
                    result = {'digest': item['digest'], 'status': 'replaced_since_snapshot', 'valid': None}
                else:
                    verified = self.objects.verify(item['digest'], bool(run['quarantine']))
                    result = {**verified, 'status': 'verified' if verified['valid'] else 'corrupt', 'references': references(self.db, item['digest'])}
                self.db.execute('INSERT INTO scrub_results VALUES(?,?,?)', (run_id, ordinal, canonical(result)))
            state = 'complete' if stop == len(run['inventory']) else 'running'
            self.db.execute('UPDATE scrub_runs SET cursor=?,state=? WHERE run_id=?', (stop, state, run_id))
            self.db.log('scrub.advanced', {'run_id': run_id, 'cursor': stop, 'state': state})
            return self.get(run_id)

    def report(self, run_id):
        run = self.get(run_id)
        counts = {}
        affected = set()
        for row in run['results']:
            counts[row['status']] = counts.get(row['status'], 0) + 1
            if row['valid'] is False:
                for reference in row['references']:
                    if reference['kind'] == 'manifest':
                        affected.add(reference['manifest_id'])
        return {'run_id': run_id, 'state': run['state'], 'counts': counts, 'affected_manifests': sorted(affected), 'remaining': len(run['inventory']) - run['cursor'], 'fully_verified': run['state'] == 'complete' and all(row['valid'] is True for row in run['results'])}
