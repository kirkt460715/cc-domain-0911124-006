from sealvault.codec import key, timestamp, canonical, loads, fail, text, envelope, unwrap, fields, digest
from sealvault import manifests
from sealvault.custody import actors, chain
from sealvault.custody.cases import Cases
from sealvault.objects import Objects


class Seals:
    def __init__(self, database):
        self.db = database
        self.cases = Cases(database)
        self.objects = Objects(database)

    def prepare(self, manifest_id, case_id, expected_revision, actor, parent_id=None):
        key(manifest_id)
        with self.db.transaction():
            case = self.cases.editable(case_id, expected_revision, actor)
            if self.db.one('SELECT manifest_id FROM manifests WHERE manifest_id=?', (manifest_id,)):
                fail('manifest_exists', 'Manifest identifier is immutable')
            if parent_id:
                parent = self.get(parent_id)
                if parent['state'] != 'sealed':
                    fail('manifest_parent', 'Parent must be a sealed manifest')
            fork_events = [row for row in chain.history(self.db, case_id, limit=10000) if row['action'] == 'forked']
            if fork_events and parent_id != fork_events[-1]['body']['parent_manifest_id']:
                fail('manifest_parent_binding', 'Forked case must preserve its explicit parent manifest')
            if not fork_events and parent_id is not None:
                fail('manifest_parent_binding', 'Parent linkage requires a recorded fork operation')
            for item in case['entries']:
                content = self.objects.read(item['digest'])
                if len(content) != item['size']:
                    fail('entry_size', 'Entry length differs from object')
            value = manifests.build(case_id, expected_revision, case['entries'], self.db.clock(), case['classification'], parent_id)
            self.db.execute("INSERT INTO manifests VALUES(?,?,?,?,?,?,'prepared',?,?)", (manifest_id, case_id, expected_revision, canonical(value['body']), value['sha256'], value['body']['merkle_root'], parent_id, self.db.clock()))
            for identity, size in {entry['digest']: entry['size'] for entry in case['entries']}.items():
                self.db.execute('INSERT INTO manifest_objects VALUES(?,?,?)', (manifest_id, identity, size))
            chain.append(self.db, case_id, 'manifest_prepared', actor, {'manifest_id': manifest_id, 'body_hash': value['sha256']})
            return self.get(manifest_id)

    def get(self, manifest_id):
        row = self.db.one('SELECT * FROM manifests WHERE manifest_id=?', (manifest_id,))
        if row is None:
            fail('manifest_missing', 'Manifest does not exist')
        row['manifest'] = {'body': loads(row.pop('body')), 'sha256': row['body_hash']}
        manifests.verify(row['manifest'])
        body = row['manifest']['body']
        if (row['case_id'], row['case_revision'], row['merkle_root'], row['parent_id']) != (body['case_id'], body['case_revision'], body['merkle_root'], body['parent_id']):
            fail('manifest_index', 'Manifest index differs from immutable body')
        actual = self.db.all('SELECT digest,size FROM manifest_objects WHERE manifest_id=? ORDER BY digest', (manifest_id,))
        expected = [{'digest': identity, 'size': size} for identity, size in sorted({item['digest']: item['size'] for item in body['entries']}.items())]
        if actual != expected:
            fail('manifest_references', 'Manifest object references differ from immutable entries')
        return row

    def seal(self, manifest_id, reviewer, retain_until):
        actors.require(self.db, reviewer, {'custodian'})
        retain_until = timestamp(retain_until)
        if retain_until <= self.db.clock():
            fail('retention_date', 'Initial retention must end after sealing time')
        with self.db.transaction():
            prepared = self.get(manifest_id)
            case = self.cases.get(prepared['case_id'])
            if prepared['state'] != 'prepared' or case['state'] != 'draft':
                fail('seal_state', 'Sealing requires a prepared manifest and draft case')
            if case['owner'] == reviewer:
                fail('seal_separation', 'Independent custodian must seal the owner submission')
            if case['revision'] != prepared['case_revision']:
                fail('seal_stale', 'Draft changed after manifest preparation')
            body = prepared['manifest']['body']
            if case['entries'] != body['entries'] or case['classification'] != body['classification']:
                fail('seal_projection', 'Draft projection differs from prepared manifest')
            for item in body['entries']:
                if len(self.objects.read(item['digest'])) != item['size']:
                    fail('seal_object', 'Manifest object size differs')
            self.db.execute("UPDATE manifests SET state='sealed' WHERE manifest_id=?", (manifest_id,))
            self.db.execute("UPDATE cases SET state='sealed',revision=revision+1 WHERE case_id=?", (case['case_id'],))
            self.db.execute("UPDATE manifests SET state='abandoned' WHERE case_id=? AND state='prepared'", (case['case_id'],))
            self.db.execute("INSERT INTO retention VALUES(?,1,?,'active',?)", (manifest_id, retain_until, 'Initial independent seal'))
            chain.append(self.db, case['case_id'], 'sealed', reviewer, {'manifest_id': manifest_id, 'body_hash': prepared['body_hash'], 'merkle_root': prepared['merkle_root'], 'retain_until': retain_until})
            self.db.execute('DELETE FROM entries WHERE case_id=?', (case['case_id'],))
            return self.get(manifest_id)

    def abandon(self, manifest_id, actor, reason):
        reason = text(reason)
        with self.db.transaction():
            row = self.get(manifest_id)
            case = self.cases.get(row['case_id'])
            actors.require(self.db, actor)
            if actor != case['owner'] or row['state'] != 'prepared':
                fail('manifest_abandon', 'Only owner may abandon a prepared manifest')
            self.db.execute("UPDATE manifests SET state='abandoned' WHERE manifest_id=?", (manifest_id,))
            chain.append(self.db, case['case_id'], 'manifest_abandoned', actor, {'manifest_id': manifest_id, 'reason': reason})
            return self.get(manifest_id)

    def fork(self, manifest_id, new_case_id, owner, title):
        with self.db.transaction():
            source = self.get(manifest_id)
            if source['state'] != 'sealed':
                fail('fork_state', 'Only retained sealed manifests can seed a new case')
            from sealvault.retention.policy import assert_available
            assert_available(self.db, manifest_id)
            self.cases.create(new_case_id, title, owner, source['manifest']['body']['classification'])
            revision = 1
            for item in source['manifest']['body']['entries']:
                self.cases.attach(new_case_id, revision, owner, item)
                revision += 1
            chain.append(self.db, new_case_id, 'forked', owner, {'parent_manifest_id': manifest_id, 'parent_body_hash': source['body_hash']})
            return self.cases.get(new_case_id)

    def export(self, manifest_id):
        row = self.get(manifest_id)
        if row['state'] != 'sealed':
            fail('manifest_export_state', 'Only sealed evidence can be exported')
        from sealvault.retention.policy import assert_available
        assert_available(self.db, manifest_id)
        custody = chain.export(self.db, row['case_id'])
        return envelope('sealvault-seal', {'manifest_id': manifest_id, 'manifest': row['manifest'], 'custody': custody})

    def proof(self, manifest_id, selected_path):
        row = self.get(manifest_id)
        if row['state'] != 'sealed':
            fail('manifest_proof_state', 'Only sealed manifests issue evidence proofs')
        return manifests.proof(row['manifest'], selected_path)


def verify_export(value):
    data = unwrap(value, 'sealvault-seal')
    fields(data, {'manifest_id', 'manifest', 'custody'})
    key(data['manifest_id'])
    verified = manifests.verify(data['manifest'])
    custody = chain.verify_export(data['custody'])
    if custody['case_id'] != data['manifest']['body']['case_id']:
        fail('seal_case', 'Custody chain belongs to another manifest case')
    events = data['custody']['payload']['data']['events']
    matches = [event for event in events if event['action'] == 'sealed' and event['body'].get('manifest_id') == data['manifest_id']]
    if len(matches) != 1 or matches[0]['body']['body_hash'] != data['manifest']['sha256'] or matches[0]['body']['merkle_root'] != verified['root']:
        fail('seal_binding', 'Custody chain does not bind exactly one matching seal')
    return {'valid': True, 'manifest_id': data['manifest_id'], 'root': verified['root'], 'custody_head': custody['head'], 'authentication': 'local_hash_chain_only'}
