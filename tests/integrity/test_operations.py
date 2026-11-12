from tests.support import Case
from sealvault.codec import encode, sha256, digest, canonical
from sealvault.inspect import checks, compare
from sealvault import quotas
from sealvault.retention import policy


class OperationalIntegrity(Case):
    def test_scrubber_snapshot_resume_and_quarantine_impact(self):
        self.add_case()
        self.seal()
        identity = sha256(b'alpha')
        self.db.execute('UPDATE objects SET content=? WHERE digest=?', (b'xxxxx', identity))
        self.vault.scrubber.start('scrub', 'custodian', True)
        first = self.vault.scrubber.advance('scrub', 'custodian', 1)
        self.assertEqual(first['cursor'], 1)
        self.vault.objects.put(b'new-after-snapshot')
        finished = self.vault.scrubber.advance('scrub', 'custodian')
        self.assertEqual(finished['cursor'], 3)
        self.assertEqual(finished['state'], 'complete')
        report = self.vault.scrubber.report('scrub')
        self.assertFalse(report['fully_verified'])
        self.assertEqual(report['counts']['corrupt'], 1)
        self.assertEqual(report['affected_manifests'], ['seal-a'])
        self.assertEqual(self.vault.objects.info(identity)['state'], 'quarantined')
        self.assertEqual(self.db.scalar('SELECT COUNT(*) FROM objects'), 4)

    def test_repair_workflow_and_independent_review(self):
        self.add_case()
        self.seal()
        identity = sha256(b'alpha')
        self.db.execute('UPDATE objects SET content=? WHERE digest=?', (b'xxxxx', identity))
        self.vault.objects.verify(identity, True)
        proposal = self.vault.repairs.propose('repair', identity, encode(b'alpha'), 'custodian', 'verified local backup', 'recover bit corruption')
        self.assertEqual(proposal['proposal']['damaged_digest'], sha256(b'xxxxx'))
        self.error('repair_review', self.vault.repairs.apply, 'repair', 'custodian', proposal['digest'])
        self.error('repair_acknowledgement', self.vault.repairs.apply, 'repair', 'reviewer', 'wrong')
        applied = self.vault.repairs.apply('repair', 'reviewer', proposal['digest'])
        self.assertEqual(applied['state'], 'applied')
        self.assertEqual(self.vault.objects.read(identity), b'alpha')
        self.assertEqual(self.vault.repairs.pending(), [])
        self.assertTrue(checks.run(self.db)['ok'])

    def test_repair_rejects_new_damage_since_proposal(self):
        identity = self.vault.objects.put(b'alpha')['digest']
        self.db.execute('UPDATE objects SET content=? WHERE digest=?', (b'xxxxx', identity))
        self.vault.objects.verify(identity, True)
        proposal = self.vault.repairs.propose('repair', identity, encode(b'alpha'), 'custodian', 'backup', 'recover')
        self.db.execute('UPDATE objects SET content=? WHERE digest=?', (b'yyyyy', identity))
        self.error('repair_stale', self.vault.repairs.apply, 'repair', 'reviewer', proposal['digest'])
        self.assertEqual(self.vault.objects.info(identity)['state'], 'quarantined')
        self.assertEqual(self.vault.repairs.reject('repair', 'reviewer', 'changed damage')['state'], 'rejected')
        self.assertEqual(self.vault.repairs.pending(), [])

    def test_quota_counts_unique_objects_and_active_reservations(self):
        quotas.configure(self.db, 0, 6, 2, 5, 'admin', 'small test quota')
        self.vault.objects.put(b'abc')
        self.vault.objects.put(b'abc')
        self.assertEqual(quotas.usage(self.db)['bytes'], 3)
        self.assertEqual(quotas.usage(self.db)['objects'], 1)
        self.vault.objects.put(b'def')
        self.error('quota_objects', self.vault.objects.put, b'g')
        self.vault.staging.begin('stage', sha256(b'abcde'), 5, 2, 'collector', '2026-12-01T00:00:00Z')
        self.error('quota_staging', self.vault.staging.begin, 'other-stage', sha256(b'x'), 1, 1, 'collector', '2026-12-01T00:00:00Z')
        self.assertEqual(quotas.usage(self.db)['reserved_staging_bytes'], 5)
        self.vault.staging.cancel('stage', 'collector', 'no longer needed')
        self.assertEqual(quotas.usage(self.db)['reserved_staging_bytes'], 0)
        self.error('quota_below_usage', quotas.configure, self.db, 1, 5, 2, 5, 'admin', 'too small')

    def test_catalog_snapshot_pagination_stable_during_new_seal(self):
        for name in ['a', 'b', 'c']:
            self.add_case(name, {name: name.encode()})
            self.seal('seal-' + name, name)
        snapshot = self.vault.catalog.capture('catalog')
        first = self.vault.catalog.page('catalog', limit=1)
        self.assertEqual(first['items'][0]['manifest_id'], 'seal-a')
        self.assertIsNotNone(first['next_cursor'])
        self.add_case('d', {'d': b'd'})
        self.seal('seal-d', 'd')
        second = self.vault.catalog.page('catalog', first['next_cursor'], 10)
        self.assertEqual([row['manifest_id'] for row in second['items']], ['seal-b', 'seal-c'])
        self.assertIsNone(second['next_cursor'])
        self.assertEqual(self.vault.catalog.verify_live('catalog')['new_manifests'], ['seal-d'])
        self.vault.catalog.capture('new-catalog')
        self.assertEqual(len(self.vault.catalog.compare('catalog', 'new-catalog')['added']), 1)
        self.error('catalog_cursor', self.vault.catalog.page, 'new-catalog', first['next_cursor'])

    def test_catalog_retention_changes_visible(self):
        self.add_case()
        self.seal()
        self.vault.catalog.capture('before')
        self.assertTrue(self.vault.catalog.verify_live('before')['unchanged'])
        policy.hold(self.db, 'hold', 'seal-a', 'custodian', 'preservation')
        live = self.vault.catalog.verify_live('before')
        self.assertFalse(live['unchanged'])
        self.assertEqual(live['changes'][0]['code'], 'retention_changed')
        self.vault.catalog.capture('after')
        delta = self.vault.catalog.compare('before', 'after')
        self.assertEqual(delta['changed'][0]['fields'], ['active_holds'])
        self.assertEqual(delta['changed'][0]['after']['active_holds'], ['hold'])

    def test_request_id_fences_cross_operation_reuse(self):
        request = {'operation': 'case.create', 'request_id': 'request', 'arguments': {'case_id': 'case-a', 'title': 'Synthetic', 'owner': 'collector'}}
        first = self.vault.execute(request)
        second = self.vault.execute(request)
        self.assertFalse(first['duplicate'])
        self.assertTrue(second['duplicate'])
        self.assertEqual(first['result'], second['result'])
        self.assertEqual(self.db.scalar('SELECT COUNT(*) FROM cases'), 1)
        changed = {**request, 'arguments': {**request['arguments'], 'title': 'Different'}}
        self.error('request_conflict', self.vault.execute, changed)
        changed = {'operation': 'case.get', 'request_id': 'request', 'arguments': {'case_id': 'case-a'}}
        self.error('request_conflict', self.vault.execute, changed)
        self.assertEqual(self.db.scalar('SELECT COUNT(*) FROM custody'), 1)

    def test_audit_chain_tampering_detected(self):
        self.add_case()
        self.assertTrue(checks.journal(self.db)['valid'])
        self.db.execute("UPDATE journal SET body='{}' WHERE position=2")
        report = checks.journal(self.db)
        self.assertFalse(report['valid'])
        self.assertEqual(report['position'], 2)
        overall = checks.run(self.db)
        self.assertFalse(overall['ok'])
        self.assertEqual(overall['problems'][0]['code'], 'journal')

    def test_case_abandon_releases_draft_objects_only(self):
        case = self.add_case()
        self.assertEqual(len(policy.references(self.db, sha256(b'alpha'))), 1)
        abandoned = self.vault.cases.abandon('case-a', case['revision'], 'collector', 'intake cancelled')
        self.assertEqual(abandoned['state'], 'abandoned')
        self.assertEqual(abandoned['entries'], [])
        self.assertEqual(policy.references(self.db, sha256(b'alpha')), [])
        plan = self.vault.collector.plan('gc', self.clock())
        self.assertEqual(len(plan['body']['candidates']), 3)
        self.assertEqual(self.db.scalar('SELECT COUNT(*) FROM custody'), 5)
        self.assertTrue(checks.run(self.db)['ok'])
