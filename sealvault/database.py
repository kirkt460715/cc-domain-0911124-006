import contextlib
import sqlite3
from sealvault.codec import now, canonical, digest, fail

SCHEMA = '''
CREATE TABLE IF NOT EXISTS objects(digest TEXT PRIMARY KEY,size INTEGER NOT NULL,content BLOB NOT NULL,state TEXT NOT NULL,created_at TEXT NOT NULL,verified_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS actors(actor_id TEXT PRIMARY KEY,role TEXT NOT NULL,state TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS cases(case_id TEXT PRIMARY KEY,title TEXT NOT NULL,owner TEXT NOT NULL,revision INTEGER NOT NULL,state TEXT NOT NULL,classification TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS entries(case_id TEXT NOT NULL,path TEXT NOT NULL,digest TEXT NOT NULL,size INTEGER NOT NULL,media_type TEXT NOT NULL,metadata TEXT NOT NULL,PRIMARY KEY(case_id,path));
CREATE TABLE IF NOT EXISTS manifests(manifest_id TEXT PRIMARY KEY,case_id TEXT NOT NULL,case_revision INTEGER NOT NULL,body TEXT NOT NULL,body_hash TEXT NOT NULL,merkle_root TEXT NOT NULL,state TEXT NOT NULL,parent_id TEXT,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS manifest_objects(manifest_id TEXT NOT NULL,digest TEXT NOT NULL,size INTEGER NOT NULL,PRIMARY KEY(manifest_id,digest));
CREATE TABLE IF NOT EXISTS custody(position INTEGER PRIMARY KEY AUTOINCREMENT,case_id TEXT NOT NULL,sequence INTEGER NOT NULL,action TEXT NOT NULL,actor TEXT NOT NULL,body TEXT NOT NULL,previous_hash TEXT NOT NULL,entry_hash TEXT NOT NULL,at TEXT NOT NULL,UNIQUE(case_id,sequence));
CREATE TABLE IF NOT EXISTS requests(request_id TEXT PRIMARY KEY,operation TEXT NOT NULL,input_hash TEXT NOT NULL,result TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS journal(position INTEGER PRIMARY KEY AUTOINCREMENT,action TEXT NOT NULL,body TEXT NOT NULL,previous_hash TEXT NOT NULL,entry_hash TEXT NOT NULL,at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS retention(manifest_id TEXT PRIMARY KEY,revision INTEGER NOT NULL,retain_until TEXT NOT NULL,state TEXT NOT NULL,reason TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS holds(hold_id TEXT PRIMARY KEY,manifest_id TEXT NOT NULL,state TEXT NOT NULL,reason TEXT NOT NULL,actor TEXT NOT NULL,created_at TEXT NOT NULL,released_at TEXT);
CREATE TABLE IF NOT EXISTS pins(pin_id TEXT PRIMARY KEY,digest TEXT NOT NULL,owner TEXT NOT NULL,expires_at TEXT NOT NULL,reason TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS staging(session_id TEXT PRIMARY KEY,expected_digest TEXT NOT NULL,total_size INTEGER NOT NULL,chunk_size INTEGER NOT NULL,state TEXT NOT NULL,expires_at TEXT NOT NULL,owner TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS stage_chunks(session_id TEXT NOT NULL,ordinal INTEGER NOT NULL,digest TEXT NOT NULL,content BLOB NOT NULL,PRIMARY KEY(session_id,ordinal));
CREATE INDEX IF NOT EXISTS manifest_object_digest ON manifest_objects(digest);
CREATE INDEX IF NOT EXISTS entry_digest ON entries(digest);
'''


class Database:
    def __init__(self, filename=':memory:', clock=now):
        self.clock = clock
        self.connection = sqlite3.connect(str(filename), isolation_level=None, timeout=5)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute('PRAGMA foreign_keys=ON')
        self.connection.execute('PRAGMA journal_mode=WAL')
        self.connection.execute('PRAGMA synchronous=FULL')
        version = self.connection.execute('PRAGMA user_version').fetchone()[0]
        if version not in (0, 1):
            self.connection.close()
            fail('schema_version', 'Unsupported sealvault schema')
        self.connection.executescript(SCHEMA)
        self.connection.execute('PRAGMA user_version=1')
        self.depth = 0

    def close(self):
        self.connection.close()

    def execute(self, sql, params=()):
        return self.connection.execute(sql, params)

    def one(self, sql, params=()):
        result = self.execute(sql, params).fetchone()
        return dict(result) if result else None

    def all(self, sql, params=()):
        return [dict(row) for row in self.execute(sql, params)]

    def scalar(self, sql, params=()):
        row = self.execute(sql, params).fetchone()
        return row[0] if row else None

    @contextlib.contextmanager
    def transaction(self):
        depth = self.depth
        self.execute(f'SAVEPOINT vault_{depth}' if depth else 'BEGIN IMMEDIATE')
        self.depth += 1
        try:
            yield self
        except BaseException:
            if depth:
                self.execute(f'ROLLBACK TO vault_{depth}')
                self.execute(f'RELEASE vault_{depth}')
            else:
                self.connection.rollback()
            raise
        else:
            if depth:
                self.execute(f'RELEASE vault_{depth}')
            else:
                self.connection.commit()
        finally:
            self.depth -= 1

    def log(self, action, body):
        previous = self.scalar('SELECT entry_hash FROM journal ORDER BY position DESC LIMIT 1') or '0' * 64
        at = self.clock()
        content = canonical(body)
        checksum = digest([previous, action, content, at])
        self.execute('INSERT INTO journal(action,body,previous_hash,entry_hash,at) VALUES(?,?,?,?,?)', (action, content, previous, checksum, at))
        return checksum

    def integrity(self):
        checks = [row[0] for row in self.execute('PRAGMA integrity_check')]
        foreign = self.all('PRAGMA foreign_key_check')
        return {'ok': checks == ['ok'] and not foreign, 'checks': checks, 'foreign_keys': foreign}

    def once(self, request_id, operation, value, function):
        from sealvault.codec import key, loads
        key(request_id)
        fingerprint = digest(value)
        with self.transaction():
            prior = self.one('SELECT * FROM requests WHERE request_id=?', (request_id,))
            if prior:
                if prior['operation'] != operation or prior['input_hash'] != fingerprint:
                    fail('request_conflict', 'Request identifier binds another operation or input')
                return {'duplicate': True, 'result': loads(prior['result'])}
            result = function()
            self.execute('INSERT INTO requests VALUES(?,?,?,?)', (request_id, operation, fingerprint, canonical(result)))
            return {'duplicate': False, 'result': result}
