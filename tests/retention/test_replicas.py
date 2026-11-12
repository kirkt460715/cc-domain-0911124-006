import copy
from tests.support import Case
from sealvault.codec import digest, canonical, sha256
from sealvault.retention import policy
from sealvault.custody import checkpoints
from sealvault.inspect import checks


class ReplicaBoundaries(Case):
    def local_replica(self):
        self.add_case(contents={'a': b'alpha'})
        self.seal()
        package = self.vault.packages.prepare('export', 'seal-a', 'custodian', '2026-12-02T00:00:00Z')
        self.vault.packages.begin('import', package, 'collector', '2026-12-02T00:00:00Z')
        self.vault.packages.finish('import', 'collector', 'receipt')
        return package

    def test_replica_requires_explicit_retention_before_release(self):
        self.local_replica()
        self.assertFalse(self.vault.replica_policies.get('import')['eligible'])
        self.error('replica_protected', self.vault.replica_policies.release, 'import', 'admin', 'no policy')
        retained = self.vault.replica_policies.retain('import', 0, '2026-12-03T00:00:00Z', 'custodian')
        self.assertEqual(retained['policy']['revision'], 1)
        self.clock.set('2026-12-04T00:00:00Z')
        policy.dispose(self.db, 'seal-a', 1, 'admin', 'source expired')
        self.vault.collector.expire_temporary('admin')
        plan = self.vault.collector.plan('before-release', self.clock())
        self.assertEqual(plan['body']['candidates'], [])
        self.vault.replica_policies.release('import', 'admin', 'replica expired')
        after = self.vault.collector.plan('after-release', self.clock())
        self.assertEqual(len(after['body']['candidates']), 1)
        self.vault.collector.advance('after-release', 'admin', after['digest'])
        self.error('object_missing', self.vault.objects.read, sha256(b'alpha'))
        self.assertTrue(checks.replicas(self.db)['valid'])
        self.assertEqual(self.vault.packages.replica('import')['state'], 'released')

    def test_replica_hold_survives_expiration_until_independent_release(self):
        self.local_replica()
        self.vault.replica_policies.retain('import', 0, '2026-12-03T00:00:00Z', 'custodian')
        held = self.vault.replica_policies.hold('hold', 'import', 'custodian', 'preservation')
        self.assertEqual(held['state'], 'active')
        self.clock.set('2026-12-04T00:00:00Z')
        self.error('replica_protected', self.vault.replica_policies.release, 'import', 'admin', 'still held')
        self.error('actor_permission', self.vault.replica_policies.release_hold, 'hold', 'custodian', 'self')
        released = self.vault.replica_policies.release_hold('hold', 'admin', 'investigation ended')
        self.assertTrue(released['eligible'])
        self.assertEqual(released['holds'], [])
        self.vault.replica_policies.release('import', 'admin', 'expired')
        self.assertEqual(self.vault.replica_policies.get('import')['replica']['state'], 'released')
        self.assertEqual(self.vault.seals.get('seal-a')['state'], 'sealed')

    def test_replica_checker_detects_incomplete_reference_index(self):
        self.local_replica()
        self.assertTrue(checks.replicas(self.db)['valid'])
        self.db.execute("DELETE FROM imported_objects WHERE import_id='import'")
        checked = checks.replicas(self.db)
        self.assertFalse(checked['valid'])
        self.assertEqual(checked['count'], 1)
        self.assertEqual(checked['problems'][0]['code'], 'replica_references')
        self.assertFalse(checks.run(self.db)['ok'])
        self.assertEqual(self.vault.objects.read(sha256(b'alpha')), b'alpha')

    def test_checkpoint_conflicting_history_is_not_reported_as_extension(self):
        self.add_case()
        self.vault.checkpoints.capture('before', 'case-a', 'auditor')
        left = self.vault.checkpoints.export('before')
        right = copy.deepcopy(left)
        right['payload']['data']['body']['head'] = '0' * 64
        right['payload']['data']['digest'] = digest(right['payload']['data']['body'])
        right['sha256'] = digest(right['payload'])
        result = checkpoints.compare_checkpoints(left, right)
        self.assertEqual(result['state'], 'conflicting_history')
        self.assertEqual(result['sequence_delta'], 0)
        self.assertEqual(checkpoints.compare_checkpoints(left, left)['state'], 'same_history')
        self.assertTrue(self.vault.checkpoints.verify_live('before')['valid'])

    def test_checkpoint_extension_tampered_event_rejected(self):
        case = self.add_case()
        anchor = self.vault.checkpoints.capture('anchor', 'case-a', 'auditor')
        self.vault.cases.rename('case-a', case['revision'], 'collector', 'index.json', 'renamed.json')
        extension = self.vault.checkpoints.extension('anchor')
        extension['payload']['data']['events'][0]['body']['to'] = 'wrong.json'
        extension['sha256'] = digest(extension['payload'])
        self.error('extension_digest', checkpoints.verify_extension, extension, anchor['digest'])
        self.assertTrue(self.vault.checkpoints.verify_live('anchor')['valid'])
        self.assertEqual(self.vault.cases.get('case-a')['entries'][-1]['path'], 'renamed.json')
        self.assertEqual(self.db.scalar('SELECT COUNT(*) FROM custody_checkpoints'), 1)
