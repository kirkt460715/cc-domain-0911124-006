import copy
from tests.support import Case, Clock
from sealvault.service import Vault
from sealvault.custody import actors
from sealvault.codec import sha256, encode, envelope, digest
from sealvault.transfer import recovery
from sealvault.retention import policy


class Transfers(Case):
    def test_staging_out_of_order_duplicate_and_atomic_commit(self):
        data = b'abcdefghij'
        identity = sha256(data)
        session = self.vault.staging.begin('stage', identity, 10, 4, 'collector', '2026-12-01T00:00:00Z')
        self.assertEqual(session['missing'], [0, 1, 2])
        self.error('stage_incomplete', self.vault.staging.commit, 'stage', 'collector')
        self.vault.staging.receive('stage', 'collector', 2, encode(data[8:]), sha256(data[8:]))
        self.vault.staging.receive('stage', 'collector', 0, encode(data[:4]), sha256(data[:4]))
        duplicate = self.vault.staging.receive('stage', 'collector', 0, encode(data[:4]), sha256(data[:4]))
        self.assertEqual(duplicate['received'], [0, 2])
        self.assertIsNone(self.db.one('SELECT digest FROM objects WHERE digest=?', (identity,)))
        self.vault.staging.receive('stage', 'collector', 1, encode(data[4:8]), sha256(data[4:8]))
        result = self.vault.staging.commit('stage', 'collector')
        self.assertEqual(result['digest'], identity)
        self.assertEqual(self.vault.objects.read(identity), data)
        self.assertEqual(self.db.scalar('SELECT COUNT(*) FROM stage_chunks'), 0)
        self.assertEqual(self.vault.staging.commit('stage', 'collector')['digest'], identity)

    def test_stage_conflicts_and_wrong_whole_digest(self):
        identity = sha256(b'abcd')
        self.vault.staging.begin('stage', identity, 4, 2, 'collector', '2026-12-01T00:00:00Z')
        self.error('stage_owner', self.vault.staging.receive, 'stage', 'other', 0, encode(b'ab'), sha256(b'ab'))
        self.error('stage_chunk_size', self.vault.staging.receive, 'stage', 'collector', 0, encode(b'a'), sha256(b'a'))
        self.vault.staging.receive('stage', 'collector', 0, encode(b'ab'), sha256(b'ab'))
        self.error('stage_chunk_conflict', self.vault.staging.receive, 'stage', 'collector', 0, encode(b'xy'), sha256(b'xy'))
        self.vault.staging.receive('stage', 'collector', 1, encode(b'xy'), sha256(b'xy'))
        self.error('stage_object_digest', self.vault.staging.commit, 'stage', 'collector')
        self.assertIsNone(self.db.one('SELECT digest FROM objects WHERE digest=?', (identity,)))
        self.assertEqual(self.vault.staging.status('stage')['state'], 'receiving')
        self.assertEqual(self.vault.staging.cancel('stage', 'collector', 'bad source')['state'], 'cancelled')

    def test_expiration_and_renewal(self):
        self.vault.staging.begin('stage', sha256(b'a'), 1, 1, 'collector', '2026-11-12T00:00:00Z')
        renewed = self.vault.staging.renew('stage', 'collector', '2026-11-13T00:00:00Z')
        self.assertEqual(renewed['expires_at'], '2026-11-13T00:00:00.000000Z')
        self.clock.set('2026-11-13T00:00:00Z')
        self.error('stage_state', self.vault.staging.receive, 'stage', 'collector', 0, encode(b'a'), sha256(b'a'))
        self.error('stage_renew', self.vault.staging.renew, 'stage', 'collector', '2026-11-14T00:00:00Z')
        expired = self.vault.collector.expire_temporary('admin')
        self.assertEqual(expired['sessions'], 1)
        self.assertEqual(self.vault.staging.status('stage')['state'], 'expired')
        self.assertEqual(self.db.scalar('SELECT COUNT(*) FROM objects'), 0)

    def test_empty_object_has_zero_chunks(self):
        identity = sha256(b'')
        status = self.vault.staging.begin('empty', identity, 0, 4, 'collector', '2026-12-01T00:00:00Z')
        self.assertEqual(status['count'], 0)
        self.assertEqual(status['missing'], [])
        self.error('stage_ordinal', self.vault.staging.receive, 'empty', 'collector', 0, '', identity)
        result = self.vault.staging.commit('empty', 'collector')
        self.assertEqual(result['size'], 0)
        self.assertEqual(self.vault.objects.read(identity), b'')
        self.assertEqual(self.vault.objects.export(identity)['base64'], '')

    def test_cross_vault_resumable_package_and_retained_replica(self):
        self.add_case(contents={'a': b'abcdef', 'b': b'abcdef', 'empty': b''})
        sealed = self.seal()
        package = self.vault.packages.prepare('export', 'seal-a', 'custodian', '2026-12-02T00:00:00Z', 2)
        self.assertEqual(len(package['payload']['data']['objects']), 2)
        with Vault(clock=self.clock) as destination:
            actors.register(destination.db, 'collector', 'collector')
            actors.register(destination.db, 'admin', 'administrator')
            started = destination.packages.begin('import', package, 'collector', '2026-12-02T00:00:00Z')
            self.assertEqual(started['state'], 'receiving')
            request = recovery.missing_request(destination.db, 'import')
            self.assertEqual(len(request['payload']['data']['missing']), 3)
            response = recovery.serve_request(self.db, 'export', request, 1)
            recovery.receive_response(destination.db, response, 'collector')
            self.assertEqual(len(recovery.missing_request(destination.db, 'import')['payload']['data']['missing']), 2)
            recovery.receive_response(destination.db, response, 'collector')
            response = recovery.serve_request(self.db, 'export', recovery.missing_request(destination.db, 'import'))
            recovery.receive_response(destination.db, response, 'collector')
            self.error('import_incomplete', destination.packages.finish, 'import', 'collector', 'receipt')
            for item in package['payload']['data']['objects']:
                destination.packages.assemble('import', 'collector', item['digest'])
            replica = destination.packages.finish('import', 'collector', 'receipt')
            self.assertEqual(replica['body_hash'], sealed['body_hash'])
            self.assertEqual(replica['state'], 'retained')
            self.clock.set('2026-12-03T00:00:00Z')
            destination.collector.expire_temporary('admin')
            plan = destination.collector.plan('gc', self.clock())
            self.assertEqual(plan['body']['candidates'], [])
            self.assertEqual(len(plan['body']['protected']), 2)
            self.assertEqual(destination.packages.finish('import', 'collector', 'receipt')['state'], 'retained')

    def test_package_inventory_and_checksum_rejected(self):
        from sealvault.transfer.packages import validate_package
        self.add_case()
        self.seal()
        package = self.vault.packages.prepare('export', 'seal-a', 'custodian', '2026-12-02T00:00:00Z', 2)
        bad = copy.deepcopy(package)
        bad['payload']['data']['objects'].pop()
        bad['sha256'] = digest(bad['payload'])
        self.error('package_inventory', validate_package, bad)
        bad = copy.deepcopy(package)
        bad['payload']['data']['objects'][0]['chunks'].pop()
        bad['sha256'] = digest(bad['payload'])
        self.error('package_chunks', validate_package, bad)
        self.assertEqual(len(validate_package(package)['objects']), 3)
        self.assertEqual(self.db.scalar('SELECT COUNT(*) FROM imports'), 0)

    def test_existing_object_reused_but_corruption_not_ignored(self):
        self.add_case(contents={'a': b'alpha'})
        self.seal()
        package = self.vault.packages.prepare('export', 'seal-a', 'custodian', '2026-12-02T00:00:00Z', 2)
        first = self.vault.packages.begin('local', package, 'collector', '2026-12-02T00:00:00Z')
        self.assertEqual(first['objects'][0]['state'], 'available')
        self.assertEqual(self.vault.packages.finish('local', 'collector', 'receipt')['state'], 'retained')
        identity = sha256(b'alpha')
        self.db.execute('UPDATE objects SET content=? WHERE digest=?', (b'wrong', identity))
        self.error('object_corrupt', self.vault.packages.begin, 'broken', package, 'collector', '2026-12-02T00:00:00Z')
        self.assertIsNone(self.db.one("SELECT import_id FROM imports WHERE import_id='broken'"))
        self.assertEqual(self.db.scalar('SELECT COUNT(*) FROM replicas'), 1)

    def test_export_closed_and_import_cancel_release_pins(self):
        self.add_case(contents={'a': b'alpha'})
        self.seal()
        package = self.vault.packages.prepare('export', 'seal-a', 'custodian', '2026-12-02T00:00:00Z', 2)
        self.vault.packages.begin('import', package, 'collector', '2026-12-02T00:00:00Z')
        self.assertEqual(self.db.scalar('SELECT COUNT(*) FROM pins'), 2)
        cancelled = recovery.cancel(self.db, 'import', 'collector', 'do not retain duplicate')
        self.assertEqual(cancelled['state'], 'cancelled')
        self.assertEqual(self.db.scalar('SELECT COUNT(*) FROM pins'), 1)
        closed = recovery.export_close(self.db, 'export', 'custodian', 'delivered')
        self.assertEqual(closed['state'], 'closed')
        self.assertEqual(self.db.scalar('SELECT COUNT(*) FROM pins'), 0)
        self.error('export_state', self.vault.packages.chunk, 'export', sha256(b'alpha'), 0)
