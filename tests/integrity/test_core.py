import copy
from tests.support import Case
from sealvault.codec import sha256, encode, digest
from sealvault import manifests
from sealvault.custody import chain
from sealvault.custody.seals import verify_export
from sealvault.inspect import checks


class IntegrityCore(Case):
    def test_content_address_is_idempotent_and_byte_verified(self):
        stored = self.vault.objects.put(b'alpha')
        self.assertEqual(stored['digest'], sha256(b'alpha'))
        self.assertFalse(stored['duplicate'])
        self.assertTrue(self.vault.objects.put(b'alpha')['duplicate'])
        self.assertEqual(self.db.scalar('SELECT COUNT(*) FROM objects'), 1)
        self.assertEqual(self.vault.objects.read(stored['digest']), b'alpha')
        self.error('object_digest', self.vault.objects.put, b'beta', stored['digest'])
        self.assertEqual(self.vault.objects.info(stored['digest'])['size'], 5)
        self.assertTrue(self.vault.objects.verify(stored['digest'])['valid'])

    def test_object_corruption_quarantine_and_repair(self):
        identity = self.vault.objects.put(b'alpha')['digest']
        self.db.execute('UPDATE objects SET content=? WHERE digest=?', (b'xxxxx', identity))
        self.error('object_corrupt', self.vault.objects.read, identity)
        result = self.vault.objects.verify(identity, True)
        self.assertFalse(result['valid'])
        self.assertEqual(result['state'], 'quarantined')
        self.error('object_quarantined', self.vault.objects.read, identity)
        self.error('repair_content', self.vault.objects.repair, identity, b'wrong', 'bad replacement')
        self.vault.objects.repair(identity, b'alpha', 'verified local backup')
        self.assertEqual(self.vault.objects.read(identity), b'alpha')
        self.assertEqual(self.vault.objects.info(identity)['state'], 'available')

    def test_manifest_merkle_odd_width_all_proofs(self):
        self.add_case()
        sealed = self.seal()
        value = sealed['manifest']
        self.assertEqual(manifests.verify(value)['entry_count'], 3)
        for item in value['body']['entries']:
            proof = manifests.proof(value, item['path'])
            checked = manifests.verify_proof(proof, sealed['merkle_root'])
            self.assertTrue(checked['valid'])
            self.assertEqual(checked['path'], item['path'])
        last = manifests.proof(value, value['body']['entries'][-1]['path'])
        self.assertEqual(last['siblings'][0]['digest'], manifests.leaf(last['entry']))
        last['siblings'][0]['digest'] = '0' * 64
        self.error('proof_duplicate', manifests.verify_proof, last, sealed['merkle_root'])
        self.assertTrue(checks.run(self.db)['ok'])

    def test_sealed_evidence_independent_review_and_immutability(self):
        case = self.add_case()
        prepared = self.vault.seals.prepare('seal-a', 'case-a', case['revision'], 'collector')
        self.assertEqual(prepared['state'], 'prepared')
        self.error('actor_permission', self.vault.seals.seal, 'seal-a', 'collector', '2026-12-01T00:00:00Z')
        sealed = self.vault.seals.seal('seal-a', 'custodian', '2026-12-01T00:00:00Z')
        self.assertEqual(sealed['state'], 'sealed')
        self.assertEqual(self.vault.cases.get('case-a')['entries'], [])
        self.error('case_state', self.vault.cases.rename, 'case-a', case['revision'] + 1, 'collector', 'index.json', 'other.json')
        exported = self.vault.seals.export('seal-a')
        self.assertTrue(verify_export(exported)['valid'])
        self.assertTrue(chain.verify(self.db, 'case-a')['valid'])
        self.assertEqual(sealed['manifest'], prepared['manifest'])

    def test_draft_mutation_fences_prepared_manifest(self):
        case = self.add_case()
        self.vault.seals.prepare('old', 'case-a', case['revision'], 'collector')
        changed = self.vault.cases.rename('case-a', case['revision'], 'collector', 'index.json', 'new.json')
        self.error('seal_stale', self.vault.seals.seal, 'old', 'custodian', '2026-12-01T00:00:00Z')
        self.vault.seals.prepare('new', 'case-a', changed['revision'], 'collector')
        self.vault.seals.seal('new', 'custodian', '2026-12-01T00:00:00Z')
        self.assertEqual(self.vault.seals.get('old')['state'], 'abandoned')
        self.assertEqual(self.vault.seals.get('new')['state'], 'sealed')
        self.assertEqual(self.db.scalar('SELECT COUNT(*) FROM retention'), 1)

    def test_path_collisions_and_traversal_rejected(self):
        case = self.add_case(contents={'a': b'a'})
        source = case['entries'][0]
        for unsafe in ['../escape', '/absolute', 'a//b', 'a/./b', 'a/../b', 'C:drive']:
            with self.subTest(path=unsafe):
                self.error('path', self.vault.cases.attach, 'case-a', case['revision'], 'collector', {**source, 'path': unsafe})
        self.error('manifest_collision', self.vault.cases.attach, 'case-a', case['revision'], 'collector', {**source, 'path': 'A'})
        self.error('manifest_prefix', self.vault.cases.attach, 'case-a', case['revision'], 'collector', {**source, 'path': 'a/b'})
        self.assertEqual(self.vault.cases.get('case-a')['revision'], case['revision'])
        self.assertEqual(len(self.vault.cases.get('case-a')['entries']), 1)
