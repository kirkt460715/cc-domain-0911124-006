import copy
from tests.support import Case
from sealvault.codec import encode, sha256, digest, canonical
from sealvault.custody import actors, chain, checkpoints, attestations
from sealvault.inspect import semantic, compare
from sealvault.transfer import disclosure


class CustodyWorkflow(Case):
    def test_handoff_fingerprint_and_owner_change(self):
        case = self.add_case()
        proposal = self.vault.handoffs.propose('handoff', 'case-a', 'collector', 'other', case['revision'], '2026-12-01T00:00:00Z', 'transfer responsibility')
        self.assertTrue(proposal['fresh'])
        self.error('handoff_acknowledgement', self.vault.handoffs.accept, 'handoff', 'other', 'wrong', 'receipt')
        accepted = self.vault.handoffs.accept('handoff', 'other', proposal['fingerprint'], 'receipt')
        self.assertEqual(accepted['state'], 'accepted')
        self.assertEqual(self.vault.cases.get('case-a')['owner'], 'other')
        self.assertEqual(self.vault.handoffs.accept('handoff', 'other', proposal['fingerprint'], 'receipt')['state'], 'accepted')
        self.error('case_owner', self.vault.cases.rename, 'case-a', case['revision'] + 1, 'collector', 'index.json', 'new.json')
        self.vault.cases.rename('case-a', case['revision'] + 1, 'other', 'index.json', 'new.json')
        self.assertTrue(semantic.replay_case(self.db, 'case-a')['valid'])
        self.assertEqual(chain.history(self.db, 'case-a')[-1]['actor'], 'other')

    def test_handoff_stale_after_source_edit(self):
        case = self.add_case()
        proposal = self.vault.handoffs.propose('handoff', 'case-a', 'collector', 'other', case['revision'], '2026-12-01T00:00:00Z', 'transfer')
        self.vault.cases.rename('case-a', case['revision'], 'collector', 'index.json', 'new.json')
        self.assertFalse(self.vault.handoffs.get('handoff')['fresh'])
        self.error('handoff_stale', self.vault.handoffs.accept, 'handoff', 'other', proposal['fingerprint'], 'receipt')
        self.assertEqual(self.vault.cases.get('case-a')['owner'], 'collector')
        self.assertEqual(self.vault.handoffs.cancel('handoff', 'collector', 'new inventory')['state'], 'cancelled')
        self.assertTrue(chain.verify(self.db, 'case-a')['valid'])

    def test_handoff_expiration_and_rejection(self):
        case = self.add_case()
        proposal = self.vault.handoffs.propose('handoff', 'case-a', 'collector', 'other', case['revision'], '2026-11-12T00:00:00Z', 'transfer')
        self.clock.set('2026-11-12T00:00:00Z')
        self.assertTrue(self.vault.handoffs.get('handoff')['expired'])
        self.error('handoff_stale', self.vault.handoffs.accept, 'handoff', 'other', proposal['fingerprint'], 'receipt')
        rejected = self.vault.handoffs.reject('handoff', 'other', 'cannot receive')
        self.assertEqual(rejected['state'], 'rejected')
        self.error('handoff_cancel', self.vault.handoffs.cancel, 'handoff', 'collector', 'already rejected')
        self.assertEqual(self.vault.cases.get('case-a')['revision'], case['revision'])

    def test_accension_bad_rows_isolated_and_partial_explicit(self):
        self.vault.cases.create('case-a', 'Synthetic intake', 'collector')
        records = [{'path': 'a', 'content': encode(b'alpha'), 'media_type': 'text/plain'}, {'path': '../escape', 'content': encode(b'bad'), 'media_type': 'text/plain'}, {'path': 'b', 'content': encode(b'beta'), 'media_type': 'text/plain'}]
        self.vault.accessions.start('batch', 'case-a', 1, 'collector', records)
        first = self.vault.accessions.advance('batch', 'collector', 1)
        self.assertEqual(first['cursor'], 1)
        self.assertEqual(first['revision'], 2)
        last = self.vault.accessions.advance('batch', 'collector')
        self.assertEqual(last['state'], 'review')
        self.assertEqual(last['failed'], 1)
        self.assertEqual(last['results'][1]['result']['code'], 'path')
        self.error('accession_failures', self.vault.accessions.finish, 'batch', 'collector')
        self.assertEqual(self.vault.accessions.finish('batch', 'collector', True)['state'], 'partial')
        self.assertEqual(self.db.scalar('SELECT COUNT(*) FROM objects'), 2)
        self.assertEqual([row['path'] for row in self.vault.cases.get('case-a')['entries']], ['a', 'b'])
        self.assertTrue(semantic.replay_case(self.db, 'case-a')['valid'])

    def test_accession_rebase_after_external_edit(self):
        self.vault.cases.create('case-a', 'Synthetic intake', 'collector')
        records = [{'path': 'a', 'content': encode(b'a'), 'media_type': 'text/plain'}, {'path': 'b', 'content': encode(b'b'), 'media_type': 'text/plain'}]
        self.vault.accessions.start('batch', 'case-a', 1, 'collector', records)
        self.vault.accessions.advance('batch', 'collector', 1)
        self.vault.cases.rename('case-a', 2, 'collector', 'a', 'renamed')
        self.error('case_revision', self.vault.accessions.advance, 'batch', 'collector')
        self.assertEqual(self.vault.accessions.get('batch')['cursor'], 1)
        self.vault.accessions.rebase('batch', 'collector', 3, 'acknowledge path correction')
        self.vault.accessions.advance('batch', 'collector')
        self.assertEqual(self.vault.accessions.finish('batch', 'collector')['state'], 'complete')
        self.assertEqual(self.vault.cases.get('case-a')['revision'], 4)
        self.assertEqual(len(self.vault.cases.get('case-a')['entries']), 2)

    def test_attestation_requires_independent_live_recheck(self):
        self.add_case()
        self.seal()
        proposal = self.vault.attestations.inspect('attestation', 'seal-a', 'auditor', 'periodic audit')
        self.assertTrue(proposal['body']['valid'])
        self.assertEqual(len(proposal['body']['objects']), 3)
        approved = self.vault.attestations.approve('attestation', 'custodian', proposal['digest'])
        self.assertEqual(approved['state'], 'approved')
        exported = self.vault.attestations.export('attestation')
        verified = attestations.verify(exported)
        self.assertTrue(verified['valid'])
        self.assertFalse(verified['current_bytes_checked'])
        self.assertEqual(verified['objects'], 3)
        self.error('attestation_review', self.vault.attestations.approve, 'attestation', 'custodian', proposal['digest'])

    def test_attestation_stale_if_custody_changes(self):
        from sealvault.retention import policy
        self.add_case()
        self.seal()
        proposal = self.vault.attestations.inspect('attestation', 'seal-a', 'auditor', 'periodic audit')
        policy.hold(self.db, 'hold', 'seal-a', 'custodian', 'investigation')
        self.error('attestation_stale', self.vault.attestations.approve, 'attestation', 'reviewer', proposal['digest'])
        self.assertEqual(self.vault.attestations.get('attestation')['state'], 'proposed')
        self.error('attestation_state', self.vault.attestations.export, 'attestation')
        self.assertTrue(chain.verify(self.db, 'case-a')['valid'])

    def test_disclosure_selected_proofs_revoke_and_expire(self):
        self.add_case()
        seal = self.seal()
        proposed = self.vault.disclosures.propose('disclosure', 'seal-a', ['index.json'], 'recipient', '2026-11-20T00:00:00Z', 'custodian', 'share index only')
        self.error('disclosure_access', self.vault.disclosures.export, 'disclosure', 'recipient')
        self.error('disclosure_separation', self.vault.disclosures.approve, 'disclosure', 'custodian', proposed['digest'])
        self.vault.disclosures.approve('disclosure', 'reviewer', proposed['digest'])
        exported = self.vault.disclosures.export('disclosure', 'recipient')
        result = disclosure.verify(exported, seal['merkle_root'], self.clock())
        self.assertEqual(result['paths'], ['index.json'])
        self.assertFalse(result['revocation_checked'])
        self.error('disclosure_access', self.vault.disclosures.export, 'disclosure', 'wrong')
        self.vault.disclosures.acknowledge('disclosure', 'recipient', proposed['digest'], 'receipt')
        self.vault.disclosures.revoke('disclosure', 'custodian', 'recipient purpose ended')
        self.error('disclosure_access', self.vault.disclosures.export, 'disclosure', 'recipient')
        self.assertTrue(disclosure.verify(exported, seal['merkle_root'], self.clock())['valid'])
        self.clock.set('2026-11-20T00:00:00Z')
        self.error('disclosure_expired', disclosure.verify, exported, seal['merkle_root'], self.clock())

    def test_checkpoint_extension_and_independent_witness(self):
        case = self.add_case()
        checkpoint = self.vault.checkpoints.capture('checkpoint', 'case-a', 'auditor')
        self.vault.checkpoints.acknowledge('checkpoint', 'external-witness', checkpoint['digest'], 'receipt')
        self.error('checkpoint_witness', self.vault.checkpoints.acknowledge, 'checkpoint', 'auditor', checkpoint['digest'], 'self')
        self.vault.cases.rename('case-a', case['revision'], 'collector', 'index.json', 'renamed.json')
        live = self.vault.checkpoints.verify_live('checkpoint')
        self.assertEqual(live['additional_events'], 1)
        self.assertEqual(live['witnesses'], ['external-witness'])
        extension = self.vault.checkpoints.extension('checkpoint')
        verified = checkpoints.verify_extension(extension, checkpoint['digest'])
        self.assertTrue(verified['valid'])
        self.assertEqual(verified['to_sequence'] - verified['from_sequence'], 1)
        self.error('extension_anchor', checkpoints.verify_extension, extension, 'wrong')
        self.assertTrue(checkpoints.audit_all(self.db)['valid'])

    def test_semantic_replay_detects_projection_tampering(self):
        self.add_case()
        self.assertTrue(semantic.replay_case(self.db, 'case-a')['valid'])
        self.db.execute("UPDATE cases SET owner='other' WHERE case_id='case-a'")
        report = semantic.replay_case(self.db, 'case-a')
        self.assertFalse(report['valid'])
        self.assertEqual(report['problems'][-1]['code'], 'case_projection')
        self.assertEqual(report['projected']['owner'], 'collector')
        self.assertTrue(chain.verify(self.db, 'case-a')['valid'])
        self.assertFalse(semantic.verify_database(self.db)['valid'])

    def test_fork_preserves_parent_and_reports_move(self):
        self.add_case()
        original = self.seal()
        fork = self.vault.seals.fork('seal-a', 'case-b', 'collector', 'new version')
        self.vault.cases.rename('case-b', fork['revision'], 'collector', 'index.json', 'renamed.json')
        revision = self.vault.cases.get('case-b')['revision']
        self.vault.seals.prepare('seal-b', 'case-b', revision, 'collector', 'seal-a')
        self.vault.seals.seal('seal-b', 'reviewer', '2027-01-01T00:00:00Z')
        delta = compare.compare(self.db, 'seal-a', 'seal-b')
        self.assertEqual(delta['total_byte_delta'], 0)
        self.assertEqual(delta['unambiguous_moves'][0]['from'], 'index.json')
        self.assertEqual(delta['unambiguous_moves'][0]['to'], 'renamed.json')
        self.assertEqual(self.vault.seals.get('seal-a')['manifest'], original['manifest'])
        self.assertEqual(semantic.ancestry(self.db, 'seal-b')['depth'], 2)
        self.assertTrue(semantic.verify_database(self.db)['valid'])
        self.assertEqual(compare.overlap(self.db, ['seal-a', 'seal-b'])['duplicate_bytes'], 11)
