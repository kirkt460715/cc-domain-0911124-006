from sealvault.codec import key, integer, canonical, loads, digest, envelope, unwrap, fields, fail
from sealvault.custody.seals import Seals
from sealvault.retention.policy import get as retention_get

DDL = '''
CREATE TABLE IF NOT EXISTS catalog_snapshots(snapshot_id TEXT PRIMARY KEY,body TEXT NOT NULL,digest TEXT NOT NULL,created_at TEXT NOT NULL);
'''


class Catalog:
    def __init__(self, database):
        self.db = database
        if database.depth:
            fail('catalog_transaction', 'Initialize catalog outside transactions')
        database.connection.executescript(DDL)

    def capture(self, snapshot_id):
        key(snapshot_id)
        with self.db.transaction():
            if self.db.one('SELECT snapshot_id FROM catalog_snapshots WHERE snapshot_id=?', (snapshot_id,)):
                fail('catalog_exists', 'Catalog snapshot identifier exists')
            items = []
            for row in self.db.all("SELECT manifest_id FROM manifests WHERE state='sealed' ORDER BY manifest_id"):
                sealed = Seals(self.db).get(row['manifest_id'])
                retention = retention_get(self.db, row['manifest_id'])
                body = sealed['manifest']['body']
                items.append({'manifest_id': row['manifest_id'], 'case_id': sealed['case_id'], 'manifest_hash': sealed['body_hash'], 'root': sealed['merkle_root'], 'classification': body['classification'], 'entries': len(body['entries']), 'total_bytes': body['total_bytes'], 'unique_bytes': body['unique_bytes'], 'retention_state': retention['state'], 'retain_until': retention['retain_until'], 'active_holds': [hold['hold_id'] for hold in retention['holds']]})
            body = {'items': items, 'captured_at': self.db.clock(), 'journal_position': self.db.scalar('SELECT COALESCE(MAX(position),0) FROM journal')}
            self.db.execute('INSERT INTO catalog_snapshots VALUES(?,?,?,?)', (snapshot_id, canonical(body), digest(body), self.db.clock()))
            return self.get(snapshot_id)

    def get(self, snapshot_id):
        row = self.db.one('SELECT * FROM catalog_snapshots WHERE snapshot_id=?', (snapshot_id,))
        if row is None:
            fail('catalog_missing', 'Catalog snapshot does not exist')
        row['body'] = loads(row['body'])
        if digest(row['body']) != row['digest']:
            fail('catalog_corrupt', 'Catalog snapshot checksum differs')
        return row

    def page(self, snapshot_id, cursor=None, limit=100, classification=None):
        integer(limit, 'limit', 1, 1000)
        snapshot = self.get(snapshot_id)
        last = ''
        if cursor is not None:
            value = unwrap(cursor, 'sealvault-catalog-cursor')
            fields(value, {'snapshot_id', 'digest', 'after', 'classification'})
            if (value['snapshot_id'], value['digest'], value['classification']) != (snapshot_id, snapshot['digest'], classification):
                fail('catalog_cursor', 'Cursor belongs to another snapshot or filter')
            last = value['after']
        items = [row for row in snapshot['body']['items'] if row['manifest_id'] > last and (classification is None or row['classification'] == classification)]
        selected = items[:limit]
        next_cursor = None
        if len(items) > limit:
            next_cursor = envelope('sealvault-catalog-cursor', {'snapshot_id': snapshot_id, 'digest': snapshot['digest'], 'after': selected[-1]['manifest_id'], 'classification': classification})
        return {'snapshot_id': snapshot_id, 'digest': snapshot['digest'], 'items': selected, 'next_cursor': next_cursor}

    def compare(self, before_id, after_id):
        before = self.get(before_id)
        after = self.get(after_id)
        left = {row['manifest_id']: row for row in before['body']['items']}
        right = {row['manifest_id']: row for row in after['body']['items']}
        added = []
        removed = []
        changed = []
        for identity in sorted(set(left) | set(right)):
            if identity not in left:
                added.append(right[identity])
            elif identity not in right:
                removed.append(left[identity])
            elif left[identity] != right[identity]:
                changed.append({'manifest_id': identity, 'fields': [field for field in sorted(left[identity]) if left[identity][field] != right[identity][field]], 'before': left[identity], 'after': right[identity]})
        return {'before': before_id, 'after': after_id, 'added': added, 'removed': removed, 'changed': changed}

    def verify_live(self, snapshot_id):
        snapshot = self.get(snapshot_id)
        changes = []
        for item in snapshot['body']['items']:
            current = Seals(self.db).get(item['manifest_id'])
            policy = retention_get(self.db, item['manifest_id'])
            if current['body_hash'] != item['manifest_hash']:
                changes.append({'manifest_id': item['manifest_id'], 'code': 'manifest_changed'})
            if policy['state'] != item['retention_state'] or policy['retain_until'] != item['retain_until'] or [row['hold_id'] for row in policy['holds']] != item['active_holds']:
                changes.append({'manifest_id': item['manifest_id'], 'code': 'retention_changed'})
        saved = {row['manifest_id'] for row in snapshot['body']['items']}
        current_ids = {row['manifest_id'] for row in self.db.all("SELECT manifest_id FROM manifests WHERE state='sealed'")}
        return {'unchanged': not changes and saved == current_ids, 'changes': changes, 'new_manifests': sorted(current_ids - saved)}
