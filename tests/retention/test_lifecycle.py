from tests.support import Case
from sealvault.retention import policy
from sealvault.codec import sha256, encode
from sealvault.custody import actors
from sealvault.inspect import checks


class RetentionLifecycle(Case):
    def test_expiration_requires_disposal_before_collection(self):
        self.add_case()
        self.seal()
        self.clock.set('2026-12-01T00:00:00Z')
        self.assertTrue(policy.get(self.db, 'seal-a')['eligible'])
        first = self.vault.collector.plan('before', self.clock())
        self.assertEqual(first['body']['candidates'], [])
        disposed = policy.dispose(self.db, 'seal-a', 1, 'admin', 'retention complete')
        self.assertEqual(disposed['state'], 'disposed')
        self.error('evidence_disposed', self.vault.seals.export, 'seal-a')
        plan = self.vault.collector.plan('after', self.clock())
        self.assertEqual(len(plan['body']['candidates']), 3)
        self.vault.collector.advance('after', 'admin', plan['digest'], 1)
        self.assertEqual(self.vault.collector.report('after')['remaining'], 2)
        self.vault.collector.advance('after', 'admin', plan['digest'])
        self.assertEqual(self.db.scalar('SELECT COUNT(*) FROM objects'), 0)
        self.assertEqual(self.vault.seals.get('seal-a')['state'], 'sealed')
        self.assertTrue(checks.run(self.db)['ok'])

    def test_hold_blocks_and_release_requires_independent_admin(self):
        self.add_case()
        self.seal()
        held = policy.hold(self.db, 'hold', 'seal-a', 'custodian', 'investigation')
        self.assertEqual(held['state'], 'active')
        self.clock.set('2026-12-02T00:00:00Z')
        self.error('retention_protected', policy.dispose, self.db, 'seal-a', 2, 'admin', 'expired')
        self.error('actor_permission', policy.release, self.db, 'hold', 'custodian', 'release')
        policy.release(self.db, 'hold', 'admin', 'case concluded')
        self.assertTrue(policy.get(self.db, 'seal-a')['eligible'])
        self.assertEqual(policy.get(self.db, 'seal-a')['revision'], 3)
        self.error('retention_stale', policy.dispose, self.db, 'seal-a', 2, 'admin', 'stale decision')
        self.assertEqual(policy.dispose(self.db, 'seal-a', 3, 'admin', 'done')['state'], 'disposed')

    def test_gc_rechecks_pin_created_after_plan(self):
        identity = self.vault.objects.put(b'orphan')['digest']
        plan = self.vault.collector.plan('plan', self.clock())
        self.assertEqual(len(plan['body']['candidates']), 1)
        self.vault.objects.pin('pin', identity, 'collector', '2026-12-01T00:00:00Z', 'needed during review')
        result = self.vault.collector.advance('plan', 'admin', plan['digest'])
        self.assertEqual(result['results'][0]['state'], 'protected_since_plan')
        self.assertEqual(self.vault.objects.read(identity), b'orphan')
        self.assertEqual(self.vault.collector.report('plan')['deleted_bytes'], 0)
        self.vault.objects.unpin('pin', 'collector')
        next_plan = self.vault.collector.plan('next', self.clock())
        self.vault.collector.advance('next', 'admin', next_plan['digest'])
        self.error('object_missing', self.vault.objects.read, identity)

    def test_shared_object_survives_one_manifest_disposal(self):
        self.add_case('first', {'a': b'shared'})
        self.seal('first-seal', 'first')
        self.add_case('second', {'b': b'shared'})
        self.seal('second-seal', 'second', '2027-01-01T00:00:00Z')
        self.assertEqual(self.db.scalar('SELECT COUNT(*) FROM objects'), 1)
        self.clock.set('2026-12-02T00:00:00Z')
        policy.dispose(self.db, 'first-seal', 1, 'admin', 'first expired')
        plan = self.vault.collector.plan('plan', self.clock())
        self.assertEqual(plan['body']['candidates'], [])
        references = policy.references(self.db, sha256(b'shared'))
        self.assertEqual([row['manifest_id'] for row in references if row['kind'] == 'manifest'], ['second-seal'])
        self.assertEqual(self.vault.objects.read(sha256(b'shared')), b'shared')

    def test_disposal_review_stale_when_hold_appears(self):
        self.add_case()
        self.seal()
        self.clock.set('2026-12-02T00:00:00Z')
        proposal = self.vault.disposal.propose('review', 'seal-a', 'custodian', 'retention complete')
        self.assertTrue(proposal['fresh'])
        self.assertEqual(proposal['body']['reclaimable_bytes'], 11)
        policy.hold(self.db, 'hold', 'seal-a', 'reviewer', 'new investigation')
        self.error('disposal_stale', self.vault.disposal.approve, 'review', 'admin', proposal['digest'])
        self.assertEqual(policy.get(self.db, 'seal-a')['state'], 'active')
        rejected = self.vault.disposal.reject('review', 'admin', 'hold now active')
        self.assertEqual(rejected['state'], 'rejected')
        self.error('disposal_certificate', self.vault.disposal.certificate, 'review')

    def test_disposal_certificate_does_not_claim_physical_erasure(self):
        self.add_case()
        self.seal()
        self.clock.set('2026-12-02T00:00:00Z')
        proposal = self.vault.disposal.propose('review', 'seal-a', 'custodian', 'expiry')
        self.vault.disposal.approve('review', 'admin', proposal['digest'])
        certificate = self.vault.disposal.certificate('review')['payload']['data']
        self.assertFalse(certificate['physical_deletion_guaranteed'])
        self.assertEqual(certificate['manifest_id'], 'seal-a')
        self.assertEqual(policy.get(self.db, 'seal-a')['state'], 'disposed')
        self.assertEqual(self.db.scalar('SELECT COUNT(*) FROM objects'), 3)
        self.assertTrue(checks.run(self.db)['ok'])

    def test_retention_extension_never_shortens_and_revisions_fence(self):
        self.add_case()
        self.seal()
        self.error('retention_shorten', policy.extend, self.db, 'seal-a', 1, '2026-11-30T00:00:00Z', 'custodian', 'shorten')
        extended = policy.extend(self.db, 'seal-a', 1, '2027-01-01T00:00:00Z', 'custodian', 'longer preservation')
        self.assertEqual(extended['revision'], 2)
        self.error('retention_stale', policy.extend, self.db, 'seal-a', 1, '2027-02-01T00:00:00Z', 'custodian', 'old view')
        self.clock.set('2026-12-10T00:00:00Z')
        self.assertFalse(policy.get(self.db, 'seal-a')['eligible'])
        self.assertEqual(policy.inventory(self.db)['eligible'], [])
        self.assertEqual(self.vault.seals.get('seal-a')['state'], 'sealed')

    def test_schedule_preview_and_apply_preserves_longer_deadline(self):
        self.add_case('internal')
        self.seal('internal-seal', 'internal')
        self.add_case('restricted', classification='restricted')
        self.seal('restricted-seal', 'restricted', '2028-01-01T00:00:00Z')
        self.vault.schedules.rule('rule', 0, {'public': 10, 'internal': 100, 'restricted': 200}, 'admin')
        plan = self.vault.schedules.preview('plan', 'rule', ['internal-seal', 'restricted-seal'], 'custodian')
        self.assertEqual([row['extend'] for row in plan['body']['rows']], [True, False])
        result = self.vault.schedules.apply('plan', 'admin', plan['digest'], 'apply retention schedule')
        self.assertEqual(result['extended'], ['internal-seal'])
        self.assertEqual(policy.get(self.db, 'restricted-seal')['retain_until'], '2028-01-01T00:00:00.000000Z')
        self.assertEqual(policy.get(self.db, 'internal-seal')['revision'], 2)
        self.assertEqual(self.vault.schedules.get_rule('rule', 1)['definition']['internal'], 100)
        self.error('schedule_review', self.vault.schedules.apply, 'plan', 'admin', plan['digest'], 'again')

    def test_schedule_atomic_stale_later_manifest(self):
        self.add_case('first')
        self.seal('first-seal', 'first')
        self.add_case('second')
        self.seal('second-seal', 'second')
        self.vault.schedules.rule('rule', 0, {'public': 100, 'internal': 200, 'restricted': 300}, 'admin')
        plan = self.vault.schedules.preview('plan', 'rule', ['first-seal', 'second-seal'], 'custodian')
        policy.hold(self.db, 'hold', 'second-seal', 'reviewer', 'protect')
        self.error('schedule_stale', self.vault.schedules.apply, 'plan', 'admin', plan['digest'], 'stale')
        self.assertEqual(policy.get(self.db, 'first-seal')['revision'], 1)
        self.assertEqual(policy.get(self.db, 'second-seal')['revision'], 2)
        self.assertEqual(self.vault.schedules.get_plan('plan')['state'], 'prepared')
