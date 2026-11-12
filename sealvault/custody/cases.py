from sealvault.codec import key, text, integer, canonical, loads, fail, path
from sealvault import manifests
from sealvault.custody import actors, chain
from sealvault.objects import Objects


class Cases:
    def __init__(self, database):
        self.db = database
        self.objects = Objects(database)

    def create(self, case_id, title, owner, classification='internal'):
        key(case_id)
        title = text(title, 200)
        actors.require(self.db, owner, {'collector', 'custodian'})
        if classification not in {'public', 'internal', 'restricted'}:
            fail('classification', 'Unknown classification')
        with self.db.transaction():
            if self.db.one('SELECT case_id FROM cases WHERE case_id=?', (case_id,)):
                fail('case_exists', 'Case identifier already exists')
            self.db.execute("INSERT INTO cases VALUES(?,?,?,1,'draft',?,?)", (case_id, title, owner, classification, self.db.clock()))
            chain.append(self.db, case_id, 'created', owner, {'title': title, 'classification': classification})
            return self.get(case_id)

    def get(self, case_id):
        row = self.db.one('SELECT * FROM cases WHERE case_id=?', (case_id,))
        if row is None:
            fail('case_missing', 'Evidence case does not exist')
        row['entries'] = self.db.all('SELECT path,digest,size,media_type,metadata FROM entries WHERE case_id=? ORDER BY path', (case_id,))
        for item in row['entries']:
            item['metadata'] = loads(item['metadata'])
        row['total_bytes'] = sum(item['size'] for item in row['entries'])
        row['unique_bytes'] = sum({item['digest']: item['size'] for item in row['entries']}.values())
        return row

    def editable(self, case_id, revision, actor):
        actors.require(self.db, actor, {'collector', 'custodian'})
        case = self.get(case_id)
        if case['owner'] != actor:
            fail('case_owner', 'Only current owner may edit evidence case')
        if case['revision'] != revision:
            fail('case_revision', 'Case changed since it was read')
        if case['state'] != 'draft':
            fail('case_state', 'Only draft cases may change contents')
        return case

    def attach(self, case_id, expected_revision, actor, value, replace=False):
        if type(replace) is not bool:
            fail('case_replace', 'replace must be boolean')
        item = manifests.entry(value)
        with self.db.transaction():
            case = self.editable(case_id, expected_revision, actor)
            content = self.objects.read(item['digest'])
            if len(content) != item['size']:
                fail('entry_size', 'Entry size differs from stored object')
            prior = next((entry for entry in case['entries'] if entry['path'] == item['path']), None)
            if prior and not replace:
                fail('entry_exists', 'Existing path requires explicit replacement')
            proposed = [entry for entry in case['entries'] if entry['path'] != item['path']] + [item]
            manifests.entries(proposed)
            self.db.execute('INSERT INTO entries VALUES(?,?,?,?,?,?) ON CONFLICT(case_id,path) DO UPDATE SET digest=excluded.digest,size=excluded.size,media_type=excluded.media_type,metadata=excluded.metadata', (case_id, item['path'], item['digest'], item['size'], item['media_type'], canonical(item['metadata'])))
            self.db.execute('UPDATE cases SET revision=revision+1 WHERE case_id=?', (case_id,))
            chain.append(self.db, case_id, 'entry_replaced' if prior else 'entry_attached', actor, {'before': prior, 'after': item})
            return self.get(case_id)

    def detach(self, case_id, expected_revision, actor, selected_path, reason):
        path(selected_path)
        reason = text(reason)
        with self.db.transaction():
            case = self.editable(case_id, expected_revision, actor)
            prior = next((entry for entry in case['entries'] if entry['path'] == selected_path), None)
            if prior is None:
                fail('entry_missing', 'Path is absent from case')
            self.db.execute('DELETE FROM entries WHERE case_id=? AND path=?', (case_id, selected_path))
            self.db.execute('UPDATE cases SET revision=revision+1 WHERE case_id=?', (case_id,))
            chain.append(self.db, case_id, 'entry_detached', actor, {'entry': prior, 'reason': reason})
            return self.get(case_id)

    def rename(self, case_id, expected_revision, actor, old_path, new_path):
        path(old_path)
        path(new_path)
        with self.db.transaction():
            case = self.editable(case_id, expected_revision, actor)
            source = next((entry for entry in case['entries'] if entry['path'] == old_path), None)
            if source is None:
                fail('entry_missing', 'Original evidence path is absent')
            if old_path == new_path:
                return case
            proposed = [entry for entry in case['entries'] if entry['path'] != old_path] + [{**source, 'path': new_path}]
            manifests.entries(proposed)
            self.db.execute('UPDATE entries SET path=? WHERE case_id=? AND path=?', (new_path, case_id, old_path))
            self.db.execute('UPDATE cases SET revision=revision+1 WHERE case_id=?', (case_id,))
            chain.append(self.db, case_id, 'entry_renamed', actor, {'from': old_path, 'to': new_path, 'digest': source['digest']})
            return self.get(case_id)

    def classify(self, case_id, expected_revision, actor, classification, reason):
        if classification not in {'public', 'internal', 'restricted'}:
            fail('classification', 'Unknown evidence classification')
        reason = text(reason)
        with self.db.transaction():
            case = self.editable(case_id, expected_revision, actor)
            self.db.execute('UPDATE cases SET classification=?,revision=revision+1 WHERE case_id=?', (classification, case_id))
            chain.append(self.db, case_id, 'classified', actor, {'from': case['classification'], 'to': classification, 'reason': reason})
            return self.get(case_id)

    def abandon(self, case_id, expected_revision, actor, reason):
        reason = text(reason)
        with self.db.transaction():
            self.editable(case_id, expected_revision, actor)
            self.db.execute("UPDATE cases SET state='abandoned',revision=revision+1 WHERE case_id=?", (case_id,))
            self.db.execute('DELETE FROM entries WHERE case_id=?', (case_id,))
            chain.append(self.db, case_id, 'abandoned', actor, {'reason': reason})
            return self.get(case_id)

    def list(self, state=None, owner=None):
        conditions = []
        arguments = []
        if state is not None:
            if state not in {'draft', 'sealed', 'abandoned'}:
                fail('case_state', 'Unknown case state')
            conditions.append('state=?')
            arguments.append(state)
        if owner is not None:
            conditions.append('owner=?')
            arguments.append(owner)
        query = 'SELECT case_id FROM cases'
        if conditions:
            query += ' WHERE ' + ' AND '.join(conditions)
        return [self.get(row['case_id']) for row in self.db.all(query + ' ORDER BY case_id', arguments)]
