from sealvault.codec import key, integer, timestamp, canonical, loads, digest, sha256, encode, decode, envelope, unwrap, fields, fail
from sealvault.objects import Objects
from sealvault.custody.seals import Seals, verify_export
from sealvault.custody import actors
from sealvault.retention.policy import assert_available
from sealvault.transfer.staging import Staging

DDL = '''
CREATE TABLE IF NOT EXISTS exports(export_id TEXT PRIMARY KEY,manifest_id TEXT NOT NULL,body TEXT NOT NULL,digest TEXT NOT NULL,owner TEXT NOT NULL,expires_at TEXT NOT NULL,state TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS imports(import_id TEXT PRIMARY KEY,body TEXT NOT NULL,digest TEXT NOT NULL,owner TEXT NOT NULL,expires_at TEXT NOT NULL,state TEXT NOT NULL,receipt TEXT);
CREATE TABLE IF NOT EXISTS imported_objects(import_id TEXT NOT NULL,object_digest TEXT NOT NULL,state TEXT NOT NULL,session_id TEXT,PRIMARY KEY(import_id,object_digest));
CREATE TABLE IF NOT EXISTS replicas(import_id TEXT PRIMARY KEY,manifest_id TEXT NOT NULL,body_hash TEXT NOT NULL,evidence TEXT NOT NULL,received_at TEXT NOT NULL,state TEXT NOT NULL);
'''


class Packages:
    def __init__(self, database):
        self.db = database
        self.objects = Objects(database)
        self.seals = Seals(database)
        self.staging = Staging(database)
        if database.depth:
            fail('package_transaction', 'Initialize packages outside transactions')
        database.connection.executescript(DDL)

    def prepare(self, export_id, manifest_id, owner, expires_at, chunk_size=65536):
        key(export_id)
        actors.require(self.db, owner, {'custodian'})
        integer(chunk_size, 'chunk_size', 1, 1048576)
        expires_at = timestamp(expires_at)
        if expires_at <= self.db.clock():
            fail('package_expiry', 'Export must expire in future')
        with self.db.transaction():
            if self.db.one('SELECT export_id FROM exports WHERE export_id=?', (export_id,)):
                fail('export_exists', 'Export identifier exists')
            evidence = self.seals.export(manifest_id)
            manifest = evidence['payload']['data']['manifest']
            objects = []
            unique = {row['digest']: row['size'] for row in manifest['body']['entries']}
            for identity, size in sorted(unique.items()):
                content = self.objects.read(identity)
                chunks = [sha256(content[i:i + chunk_size]) for i in range(0, len(content), chunk_size)]
                objects.append({'digest': identity, 'size': size, 'chunks': chunks})
                self.objects.pin('export-' + digest([export_id, identity])[:32], identity, owner, expires_at, 'Evidence package in flight')
            body = {'format': 'sealvault-package', 'version': 1, 'evidence': evidence, 'chunk_size': chunk_size, 'objects': objects}
            self.db.execute("INSERT INTO exports VALUES(?,?,?,?,?,?,'open')", (export_id, manifest_id, canonical(body), digest(body), owner, expires_at))
            self.db.log('package.prepared', {'export_id': export_id, 'manifest_id': manifest_id, 'digest': digest(body)})
            return envelope('sealvault-transfer', body)

    def export_status(self, export_id):
        row = self.db.one('SELECT * FROM exports WHERE export_id=?', (export_id,))
        if row is None:
            fail('export_missing', 'Export does not exist')
        row['body'] = loads(row['body'])
        if digest(row['body']) != row['digest']:
            fail('export_corrupt', 'Export package checksum differs')
        row['expired'] = row['expires_at'] <= self.db.clock()
        return row

    def chunk(self, export_id, identity, ordinal):
        integer(ordinal, 'ordinal')
        export = self.export_status(export_id)
        if export['state'] != 'open' or export['expired']:
            fail('export_state', 'Export is closed or expired')
        assert_available(self.db, export['manifest_id'])
        item = next((row for row in export['body']['objects'] if row['digest'] == identity), None)
        if item is None or ordinal >= len(item['chunks']):
            fail('export_chunk', 'Object or chunk is absent from export')
        result = self.objects.export(identity, ordinal * export['body']['chunk_size'], export['body']['chunk_size'])
        if result['range_sha256'] != item['chunks'][ordinal]:
            fail('export_chunk_corrupt', 'Chunk no longer matches frozen package')
        return {'digest': identity, 'ordinal': ordinal, 'chunk_digest': result['range_sha256'], 'content': result['base64']}

    def begin(self, import_id, package, owner, expires_at):
        key(import_id)
        actors.require(self.db, owner, {'collector', 'custodian'})
        expires_at = timestamp(expires_at)
        if expires_at <= self.db.clock():
            fail('package_expiry', 'Import must expire in future')
        body = validate_package(package)
        with self.db.transaction():
            prior = self.db.one('SELECT * FROM imports WHERE import_id=?', (import_id,))
            if prior:
                if (prior['digest'], prior['owner'], prior['expires_at']) != (digest(body), owner, expires_at):
                    fail('import_conflict', 'Import identifier binds different package or owner')
                return self.status(import_id)
            self.db.execute("INSERT INTO imports VALUES(?,?,?,?,?,'receiving',NULL)", (import_id, canonical(body), digest(body), owner, expires_at))
            for item in body['objects']:
                exists = self.db.one('SELECT digest FROM objects WHERE digest=?', (item['digest'],))
                session_id = 'import-' + digest([import_id, item['digest']])[:32]
                self.staging.begin(session_id, item['digest'], item['size'], body['chunk_size'], owner, expires_at)
                state = 'pending'
                if exists:
                    content = self.objects.read(item['digest'])
                    if len(content) != item['size']:
                        fail('import_object_size', 'Existing object length differs from package')
                    self.objects.pin('replica-' + digest([import_id, item['digest']])[:32], item['digest'], owner, expires_at, 'Replica import in flight')
                    state = 'available'
                self.db.execute('INSERT INTO imported_objects VALUES(?,?,?,?)', (import_id, item['digest'], state, session_id))
            return self.status(import_id)

    def status(self, import_id):
        row = self.db.one('SELECT * FROM imports WHERE import_id=?', (import_id,))
        if row is None:
            fail('import_missing', 'Import does not exist')
        row['body'] = loads(row['body'])
        if digest(row['body']) != row['digest']:
            fail('import_corrupt', 'Import manifest checksum differs')
        row['objects'] = self.db.all('SELECT * FROM imported_objects WHERE import_id=? ORDER BY object_digest', (import_id,))
        for item in row['objects']:
            item['missing_chunks'] = self.staging.status(item['session_id'])['missing'] if item['state'] == 'pending' else []
        row['expired'] = row['expires_at'] <= self.db.clock()
        return row

    def receive(self, import_id, owner, identity, ordinal, content):
        with self.db.transaction():
            current = self.status(import_id)
            if current['owner'] != owner or current['state'] != 'receiving' or current['expired']:
                fail('import_state', 'Import owner or state does not permit receiving')
            item = next((row for row in current['body']['objects'] if row['digest'] == identity), None)
            integer(ordinal, 'ordinal')
            if item is None or ordinal >= len(item['chunks']):
                fail('import_chunk', 'Object or chunk not declared in package')
            row = next(row for row in current['objects'] if row['object_digest'] == identity)
            if row['state'] == 'available':
                data = decode(content, 1048576)
                if sha256(data) != item['chunks'][ordinal]:
                    fail('import_chunk_digest', 'Duplicate chunk differs from package')
                return self.status(import_id)
            self.staging.receive(row['session_id'], owner, ordinal, content, item['chunks'][ordinal])
            return self.status(import_id)

    def assemble(self, import_id, owner, identity):
        with self.db.transaction():
            current = self.status(import_id)
            if current['owner'] != owner or current['state'] != 'receiving' or current['expired']:
                fail('import_state', 'Import owner or state does not permit assembly')
            row = next((row for row in current['objects'] if row['object_digest'] == identity), None)
            if row is None:
                fail('import_object', 'Object is absent from package')
            if row['state'] != 'available':
                self.staging.commit(row['session_id'], owner)
                self.objects.pin('replica-' + digest([import_id, identity])[:32], identity, owner, current['expires_at'], 'Replica import in flight')
                self.db.execute("UPDATE imported_objects SET state='available' WHERE import_id=? AND object_digest=?", (import_id, identity))
            return self.status(import_id)

    def finish(self, import_id, owner, receipt):
        key(receipt)
        actors.require(self.db, owner)
        with self.db.transaction():
            current = self.status(import_id)
            if current['owner'] != owner:
                fail('import_owner', 'Import owner differs')
            if current['state'] == 'verified':
                if current['receipt'] != receipt:
                    fail('import_receipt', 'Import already has another receipt')
                return self.replica(import_id)
            if current['state'] != 'receiving' or current['expired']:
                fail('import_state', 'Import is terminal or expired')
            if any(row['state'] != 'available' for row in current['objects']):
                fail('import_incomplete', 'Not all objects have been assembled')
            validate_package(envelope('sealvault-transfer', current['body']))
            for item in current['body']['objects']:
                if len(self.objects.read(item['digest'])) != item['size']:
                    fail('import_object_size', 'Assembled object length differs')
            evidence = current['body']['evidence']
            data = evidence['payload']['data']
            self.db.execute("INSERT INTO replicas VALUES(?,?,?,?,?,'retained')", (import_id, data['manifest_id'], data['manifest']['sha256'], canonical(evidence), self.db.clock()))
            self.db.execute("UPDATE imports SET state='verified',receipt=? WHERE import_id=?", (receipt, import_id))
            self.db.log('replica.verified', {'import_id': import_id, 'body_hash': data['manifest']['sha256'], 'receipt': receipt})
            return self.replica(import_id)

    def replica(self, import_id):
        row = self.db.one('SELECT * FROM replicas WHERE import_id=?', (import_id,))
        if row is None:
            fail('replica_missing', 'Verified replica does not exist')
        row['evidence'] = loads(row['evidence'])
        verify_export(row['evidence'])
        return row


def validate_package(package):
    body = unwrap(package, 'sealvault-transfer')
    fields(body, {'format', 'version', 'evidence', 'chunk_size', 'objects'})
    if body['format'] != 'sealvault-package' or body['version'] != 1:
        fail('package_format', 'Unsupported transfer package')
    verify_export(body['evidence'])
    chunk_size = integer(body['chunk_size'], 'chunk_size', 1, 1048576)
    entries = body['evidence']['payload']['data']['manifest']['body']['entries']
    expected = {row['digest']: row['size'] for row in entries}
    if not isinstance(body['objects'], list):
        fail('package_objects', 'Package objects must be a list')
    seen = {}
    for item in body['objects']:
        fields(item, {'digest', 'size', 'chunks'})
        from sealvault.codec import checksum
        checksum(item['digest'])
        integer(item['size'], 'size', 0, 16777216)
        if item['digest'] in seen:
            fail('package_duplicate', 'Package contains duplicate object descriptions')
        seen[item['digest']] = item['size']
        if not isinstance(item['chunks'], list) or len(item['chunks']) != (item['size'] + chunk_size - 1) // chunk_size:
            fail('package_chunks', 'Chunk geometry differs from object size')
        for value in item['chunks']:
            checksum(value)
    if seen != expected or list(seen) != sorted(seen):
        fail('package_inventory', 'Package inventory differs from sealed manifest')
    return body
