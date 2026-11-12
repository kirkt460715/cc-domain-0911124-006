import os
import tempfile
from tests.support import Case
from sealvault.service import Vault
from sealvault.retention import policy
from sealvault.codec import sha256, digest
from sealvault.custody import actors
from sealvault.inspect import checks, semantic
from sealvault import quotas

SHARED = sha256(b'shared')
ALPHA = sha256(b'alpha')
BETA = sha256(b'beta')
EXTRA = sha256(b'extra')


class ForecastScenarios(Case):
    def seal_pair(self):
        self.add_case('case-a', {'a/shared.bin': b'shared', 'a/alpha.bin': b'alpha'})
        self.seal('seal-a', 'case-a', '2026-11-20T00:00:00Z')
        self.add_case('case-b', {'b/shared.bin': b'shared', 'b/beta.bin': b'beta'})
        self.seal('seal-b', 'case-b', '2026-11-25T00:00:00Z')

    def evidence_by_digest(self, body):
        return {row['digest']: row for row in body['evidence']}

    def test_shared_objects_unique_vs_logical_and_daily_release(self):
        self.seal_pair()
        days = ['2026-11-12T00:00:00Z', '2026-11-20T00:00:00Z', '2026-11-21T00:00:00Z', '2026-11-25T00:00:00Z']
        result = self.vault.forecast.scenario('f1', days)
        body = result['body']
        self.assertEqual(body['kind'], 'scenario')
        self.assertEqual(body['objects'], {'count': 3, 'unique_bytes': 15, 'quarantined_count': 0, 'quarantined_bytes': 0})
        series = body['series']
        self.assertEqual([row['protected_unique_bytes'] for row in series], [15, 10, 10, 0])
        self.assertEqual([row['protected_logical_bytes'] for row in series], [21, 10, 10, 0])
        self.assertEqual([row['releasable_bytes'] for row in series], [0, 5, 5, 15])
        self.assertEqual([row['released_delta_bytes'] for row in series], [0, 5, 0, 10])
        self.assertEqual(series[0]['protected_by_kind']['retention'], {'objects': 3, 'bytes': 15})
        self.assertEqual(series[0]['protected_by_kind']['hold'], {'objects': 0, 'bytes': 0})
        self.assertEqual(body['baseline'], body['series'])
        evidence = self.evidence_by_digest(body)
        self.assertEqual(evidence[SHARED]['releasable_from'], '2026-11-25T00:00:00.000000Z')
        self.assertEqual(evidence[ALPHA]['releasable_from'], '2026-11-20T00:00:00.000000Z')
        self.assertEqual([p['id'] for p in evidence[SHARED]['protections']], ['seal-a', 'seal-b'])
        self.assertFalse(body['evidence_truncated'])
        self.assertEqual(digest(body), result['digest'])

    def test_hold_blocks_until_explicit_release_assumption(self):
        self.add_case('case-a', {'a/shared.bin': b'shared', 'a/alpha.bin': b'alpha'})
        self.seal('seal-a', 'case-a', '2026-11-20T00:00:00Z')
        policy.hold(self.db, 'hold-1', 'seal-a', 'custodian', 'investigation')
        days = ['2026-11-21T00:00:00Z', '2026-11-25T00:00:00Z']
        result = self.vault.forecast.scenario('held', days, [{'kind': 'release_hold', 'hold_id': 'hold-1', 'at': '2026-11-25T00:00:00Z'}])
        body = result['body']
        self.assertEqual([row['protected_unique_bytes'] for row in body['series']], [11, 0])
        self.assertEqual([row['protected_unique_bytes'] for row in body['baseline']], [11, 11])
        self.assertEqual(body['series'][0]['protected_by_kind']['hold'], {'objects': 2, 'bytes': 11})
        evidence = self.evidence_by_digest(body)
        hold = next(p for p in evidence[ALPHA]['protections'] if p['kind'] == 'hold')
        self.assertEqual(hold, {'kind': 'hold', 'id': 'hold-1', 'until': '2026-11-25T00:00:00.000000Z', 'baseline_until': None, 'adjusted': True})
        self.assertEqual(evidence[ALPHA]['releasable_from'], '2026-11-25T00:00:00.000000Z')
        self.assertIsNone(evidence[ALPHA]['baseline_releasable_from'])
        self.assertEqual(len(policy.get(self.db, 'seal-a')['holds']), 1)
        self.assertEqual(policy.get(self.db, 'seal-a')['retain_until'], '2026-11-20T00:00:00.000000Z')

    def test_permanent_hold_never_releases_by_default(self):
        self.add_case()
        self.seal()
        policy.hold(self.db, 'hold-1', 'seal-a', 'custodian', 'permanent')
        result = self.vault.forecast.scenario('perm', ['2026-12-02T00:00:00Z', '2027-01-01T00:00:00Z'])
        body = result['body']
        self.assertEqual([row['protected_unique_bytes'] for row in body['series']], [11, 11])
        self.assertEqual([row['releasable_bytes'] for row in body['series']], [0, 0])
        for row in body['evidence']:
            self.assertIsNone(row['releasable_from'])
            self.assertTrue(row['protected_at_start'])

    def test_retention_shorten_and_extend_adjustments(self):
        self.add_case()
        self.seal()
        shortened = self.vault.forecast.scenario('short', ['2026-11-30T00:00:00Z'], [{'kind': 'shorten_retention', 'manifest_id': 'seal-a', 'retain_until': '2026-11-15T00:00:00Z'}])
        self.assertEqual(shortened['body']['series'][0]['protected_unique_bytes'], 0)
        self.assertEqual(shortened['body']['baseline'][0]['protected_unique_bytes'], 11)
        extended = self.vault.forecast.scenario('long', ['2026-12-02T00:00:00Z'], [{'kind': 'extend_retention', 'manifest_id': 'seal-a', 'retain_until': '2027-01-01T00:00:00Z'}])
        self.assertEqual(extended['body']['series'][0]['protected_unique_bytes'], 11)
        self.assertEqual(extended['body']['baseline'][0]['protected_unique_bytes'], 0)
        self.error('forecast_adjustment', self.vault.forecast.scenario, 'bad-1', ['2026-11-12T00:00:00Z'], [{'kind': 'extend_retention', 'manifest_id': 'seal-a', 'retain_until': '2026-11-01T00:00:00Z'}])
        self.error('forecast_adjustment', self.vault.forecast.scenario, 'bad-2', ['2026-11-12T00:00:00Z'], [{'kind': 'shorten_retention', 'manifest_id': 'seal-a', 'retain_until': '2026-12-02T00:00:00Z'}])
        self.error('forecast_adjustment', self.vault.forecast.scenario, 'bad-3', ['2026-11-12T00:00:00Z'], [{'kind': 'shorten_retention', 'manifest_id': 'missing', 'retain_until': '2026-11-01T00:00:00Z'}])
        self.error('forecast_conflict', self.vault.forecast.scenario, 'bad-4', ['2026-11-12T00:00:00Z'], [{'kind': 'shorten_retention', 'manifest_id': 'seal-a', 'retain_until': '2026-11-15T00:00:00Z'}, {'kind': 'shorten_retention', 'manifest_id': 'seal-a', 'retain_until': '2026-11-16T00:00:00Z'}])
        self.assertEqual(policy.get(self.db, 'seal-a')['retain_until'], '2026-12-01T00:00:00.000000Z')

    def test_draft_case_and_prepared_manifest_assumptions(self):
        self.add_case('case-c', {'c.bin': b'extra'})
        days = ['2026-11-12T00:00:00Z', '2026-11-20T00:00:00Z']
        drafted = self.vault.forecast.scenario('draft', days, [{'kind': 'close_case', 'case_id': 'case-c', 'at': '2026-11-20T00:00:00Z'}])
        self.assertEqual([row['protected_unique_bytes'] for row in drafted['body']['series']], [5, 0])
        self.assertEqual([row['protected_unique_bytes'] for row in drafted['body']['baseline']], [5, 5])
        self.assertEqual(drafted['body']['series'][0]['protected_by_kind']['draft'], {'objects': 1, 'bytes': 5})
        self.vault.seals.prepare('prep-1', 'case-c', 2, 'collector')
        self.vault.cases.abandon('case-c', 2, 'collector', 'discard draft')
        prepared = self.vault.forecast.scenario('prep', days, [{'kind': 'abandon_manifest', 'manifest_id': 'prep-1', 'at': '2026-11-20T00:00:00Z'}])
        self.assertEqual([row['protected_unique_bytes'] for row in prepared['body']['series']], [5, 0])
        self.assertEqual(prepared['body']['series'][0]['protected_by_kind']['prepared'], {'objects': 1, 'bytes': 5})
        self.error('forecast_adjustment', self.vault.forecast.scenario, 'bad-close', days, [{'kind': 'close_case', 'case_id': 'case-c'}])
        self.error('forecast_adjustment', self.vault.forecast.scenario, 'bad-abandon', days, [{'kind': 'abandon_manifest', 'manifest_id': 'missing'}])

    def test_pin_expiry_deterministic_and_early_release(self):
        identity = self.vault.objects.put(b'extra')['digest']
        self.vault.objects.pin('pin-1', identity, 'collector', '2026-11-20T00:00:00Z', 'temporary review')
        days = ['2026-11-19T00:00:00Z', '2026-11-21T00:00:00Z']
        deterministic = self.vault.forecast.scenario('pins', days)
        self.assertEqual([row['protected_unique_bytes'] for row in deterministic['body']['series']], [5, 0])
        self.assertEqual(deterministic['body']['series'][0]['protected_by_kind']['pin'], {'objects': 1, 'bytes': 5})
        early = self.vault.forecast.scenario('pins-early', days, [{'kind': 'release_pin', 'pin_id': 'pin-1', 'at': '2026-11-15T00:00:00Z'}])
        self.assertEqual([row['protected_unique_bytes'] for row in early['body']['series']], [0, 0])
        evidence = self.evidence_by_digest(early['body'])[EXTRA]
        self.assertEqual(evidence['baseline_releasable_from'], '2026-11-21T00:00:00.000000Z')
        self.assertEqual(self.db.scalar('SELECT COUNT(*) FROM pins'), 1)

    def test_staging_session_blocks_until_expiry(self):
        identity = self.vault.objects.put(b'extra')['digest']
        self.vault.staging.begin('session-1', identity, 5, 4, 'collector', '2026-11-20T00:00:00Z')
        result = self.vault.forecast.scenario('staged', ['2026-11-19T00:00:00Z', '2026-11-21T00:00:00Z'])
        self.assertEqual([row['protected_unique_bytes'] for row in result['body']['series']], [5, 0])
        self.assertEqual(result['body']['series'][0]['protected_by_kind']['staging'], {'objects': 1, 'bytes': 5})

    def test_replica_protections_and_assumptions(self):
        self.add_case(contents={'a': b'alpha'})
        self.seal()
        package = self.vault.packages.prepare('export', 'seal-a', 'custodian', '2026-12-02T00:00:00Z')
        self.vault.packages.begin('import', package, 'collector', '2026-12-02T00:00:00Z')
        self.vault.packages.finish('import', 'collector', 'receipt')
        days = ['2026-12-02T00:00:00Z', '2026-12-10T00:00:00Z']
        indefinite = self.vault.forecast.scenario('replica-indefinite', days)
        self.assertEqual([row['protected_unique_bytes'] for row in indefinite['body']['series']], [5, 5])
        self.assertEqual(indefinite['body']['physical']['replica'], {'count': 1, 'unique_bytes': 5, 'logical_bytes': 5})
        released = self.vault.forecast.scenario('replica-release', days, [{'kind': 'release_replica', 'import_id': 'import', 'at': '2026-12-05T00:00:00Z'}])
        self.assertEqual([row['protected_unique_bytes'] for row in released['body']['series']], [5, 0])
        self.vault.replica_policies.retain('import', 0, '2026-12-03T00:00:00Z', 'custodian')
        deterministic = self.vault.forecast.scenario('replica-policy', days)
        self.assertEqual([row['protected_unique_bytes'] for row in deterministic['body']['series']], [5, 0])
        shortened = self.vault.forecast.scenario('replica-short', days, [{'kind': 'shorten_replica', 'import_id': 'import', 'retain_until': '2026-12-02T00:00:00Z'}])
        self.assertEqual([row['protected_unique_bytes'] for row in shortened['body']['series']], [0, 0])
        self.vault.replica_policies.hold('r-hold', 'import', 'custodian', 'preservation')
        held = self.vault.forecast.scenario('replica-held', days)
        self.assertEqual([row['protected_unique_bytes'] for row in held['body']['series']], [5, 5])
        lifted = self.vault.forecast.scenario('replica-lifted', days, [{'kind': 'release_replica_hold', 'hold_id': 'r-hold', 'at': '2026-12-05T00:00:00Z'}])
        self.assertEqual([row['protected_unique_bytes'] for row in lifted['body']['series']], [5, 0])
        self.assertEqual(lifted['body']['series'][0]['protected_by_kind']['replica_hold'], {'objects': 1, 'bytes': 5})
        self.assertEqual(self.vault.replica_policies.get('import')['holds'][0]['state'], 'active')

    def test_physical_section_distinguishes_file_content_and_replica(self):
        with tempfile.TemporaryDirectory() as folder:
            filename = os.path.join(folder, 'vault.db')
            with Vault(filename, clock=self.clock) as vault:
                actors.register(vault.db, 'admin', 'administrator')
                vault.objects.put(b'alpha')
                quotas.configure(vault.db, 0, 10000, 100, 1000, 'admin', 'budget')
                result = vault.forecast.scenario('phys', ['2026-11-12T00:00:00Z'])
                physical = result['body']['physical']
                self.assertTrue(physical['database_file'].endswith('vault.db'))
                self.assertGreater(physical['sqlite_file_bytes'], 0)
                self.assertEqual(physical['local_content_bytes'], 5)
                self.assertEqual(physical['quota']['max_bytes'], 10000)
                self.assertEqual(physical['replica'], {'count': 0, 'unique_bytes': 0, 'logical_bytes': 0})
                self.assertEqual(result['body']['series'][0]['releasable_bytes'], 5)
                notes = result['body']['notes']
                self.assertTrue(any('VACUUM' in note for note in notes))
                self.assertTrue(any('freelist' in note for note in notes))
        memory = self.vault.forecast.scenario('phys-memory', ['2026-11-12T00:00:00Z'])
        self.assertEqual(memory['body']['physical']['database_file'], ':memory:')

    def test_empty_vault_scenario(self):
        result = self.vault.forecast.scenario('empty', ['2026-11-12T00:00:00Z'])
        row = result['body']['series'][0]
        self.assertEqual(row['protected_unique_bytes'], 0)
        self.assertEqual(row['releasable_bytes'], 0)
        self.assertEqual(result['body']['evidence'], [])


class ForecastSearch(Case):
    def seal_pair(self):
        self.add_case('case-a', {'a/shared.bin': b'shared', 'a/alpha.bin': b'alpha'})
        self.seal('seal-a', 'case-a', '2026-11-20T00:00:00Z')
        self.add_case('case-b', {'b/shared.bin': b'shared', 'b/beta.bin': b'beta'})
        self.seal('seal-b', 'case-b', '2026-11-25T00:00:00Z')

    def cutters(self, cost_a=3, cost_b=5):
        return [
            {'candidate_id': 'cut-a', 'cost': cost_a, 'adjustment': {'kind': 'shorten_retention', 'manifest_id': 'seal-a', 'retain_until': '2026-11-15T00:00:00Z'}},
            {'candidate_id': 'cut-b', 'cost': cost_b, 'adjustment': {'kind': 'shorten_retention', 'manifest_id': 'seal-b', 'retain_until': '2026-11-15T00:00:00Z'}},
        ]

    def test_search_finds_cheapest_joint_combination(self):
        self.seal_pair()
        result = self.vault.forecast.search('joint', ['2026-11-16T00:00:00Z'], '2026-11-16T00:00:00Z', 0, self.cutters())
        body = result['body']
        self.assertEqual(body['status'], 'optimal')
        self.assertTrue(body['proven_optimal'])
        self.assertTrue(body['search_complete'])
        self.assertEqual(body['best'], {'candidate_ids': ['cut-a', 'cut-b'], 'cost': 8, 'protected_bytes': 0, 'released_bytes': 15, 'feasible': True})
        self.assertEqual(body['gap_bytes'], 0)
        standalone = {row['candidate_id']: row['standalone_released_bytes'] for row in body['candidates']}
        self.assertEqual(standalone, {'cut-a': 5, 'cut-b': 4})
        self.assertGreater(body['best']['released_bytes'], sum(standalone.values()))
        partial = self.vault.forecast.search('partial', ['2026-11-16T00:00:00Z'], '2026-11-16T00:00:00Z', 10, self.cutters())
        self.assertEqual(partial['body']['status'], 'optimal')
        self.assertEqual(partial['body']['best']['candidate_ids'], ['cut-a'])
        self.assertEqual(partial['body']['best']['cost'], 3)

    def test_search_unreachable_with_permanent_hold(self):
        self.add_case('case-a', {'a/shared.bin': b'shared', 'a/alpha.bin': b'alpha'})
        self.seal('seal-a', 'case-a', '2026-11-20T00:00:00Z')
        policy.hold(self.db, 'hold-1', 'seal-a', 'custodian', 'permanent legal hold')
        candidates = [{'candidate_id': 'cut-a', 'cost': 1, 'adjustment': {'kind': 'shorten_retention', 'manifest_id': 'seal-a', 'retain_until': '2026-11-15T00:00:00Z'}}]
        result = self.vault.forecast.search('blocked', ['2026-11-16T00:00:00Z'], '2026-11-16T00:00:00Z', 0, candidates)
        body = result['body']
        self.assertEqual(body['status'], 'unreachable')
        self.assertFalse(body['proven_optimal'])
        self.assertTrue(body['search_complete'])
        self.assertFalse(body['best']['feasible'])
        self.assertEqual(body['best']['protected_bytes'], 11)
        self.assertEqual(body['gap_bytes'], 11)
        self.assertEqual(body['best_case_bound_bytes'], 11)

    def test_search_incomplete_when_evaluation_budget_runs_out(self):
        self.seal_pair()
        self.add_case('case-c', {'c.bin': b'extra'})
        self.seal('seal-c', 'case-c', '2026-11-20T00:00:00Z')
        candidates = self.cutters() + [{'candidate_id': 'cut-c', 'cost': 7, 'adjustment': {'kind': 'shorten_retention', 'manifest_id': 'seal-c', 'retain_until': '2026-11-15T00:00:00Z'}}]
        result = self.vault.forecast.search('limited', ['2026-11-16T00:00:00Z'], '2026-11-16T00:00:00Z', 0, candidates, 2)
        body = result['body']
        self.assertEqual(body['status'], 'incomplete')
        self.assertFalse(body['proven_optimal'])
        self.assertFalse(body['search_complete'])
        self.assertFalse(body['best']['feasible'])
        self.assertEqual(body['limits']['max_evaluations'], 2)

    def test_search_candidate_and_target_validation(self):
        self.seal_pair()
        days = ['2026-11-16T00:00:00Z']
        self.error('forecast_candidates', self.vault.forecast.search, 'v-1', days, days[0], 0, [])
        too_many = [{'candidate_id': 'c%d' % index, 'cost': 1, 'adjustment': {'kind': 'shorten_retention', 'manifest_id': 'seal-a', 'retain_until': '2026-11-15T00:00:00Z'}} for index in range(21)]
        self.error('forecast_candidates', self.vault.forecast.search, 'v-2', days, days[0], 0, too_many)
        duplicated = self.cutters() * 1
        duplicated[1] = {**duplicated[1], 'candidate_id': 'cut-a'}
        self.error('forecast_candidates', self.vault.forecast.search, 'v-3', days, days[0], 0, duplicated)
        bad_cost = [{'candidate_id': 'cut-a', 'cost': -1, 'adjustment': {'kind': 'shorten_retention', 'manifest_id': 'seal-a', 'retain_until': '2026-11-15T00:00:00Z'}}]
        self.error('integer', self.vault.forecast.search, 'v-4', days, days[0], 0, bad_cost)
        self.error('forecast_target', self.vault.forecast.search, 'v-5', days, '2026-11-17T00:00:00Z', 0, self.cutters())
        bad_adjustment = [{'candidate_id': 'cut-a', 'cost': 1, 'adjustment': {'kind': 'shorten_retention', 'manifest_id': 'missing', 'retain_until': '2026-11-15T00:00:00Z'}}]
        self.error('forecast_adjustment', self.vault.forecast.search, 'v-6', days, days[0], 0, bad_adjustment)
        self.assertEqual(self.vault.forecast.list(), [])

    def test_days_and_adjustment_validation(self):
        self.add_case()
        self.seal()
        self.error('forecast_days', self.vault.forecast.scenario, 'd-1', [])
        self.error('forecast_days', self.vault.forecast.scenario, 'd-2', ['2026-11-12T00:00:00Z'] * 2)
        self.error('forecast_days', self.vault.forecast.scenario, 'd-3', ['2026-11-13T00:00:00Z', '2026-11-12T00:00:00Z'])
        self.error('forecast_days', self.vault.forecast.scenario, 'd-4', ['2026-11-10T00:00:00Z'])
        self.error('forecast_days', self.vault.forecast.scenario, 'd-5', ['2026-11-%02dT00:00:00Z' % day for day in range(12, 12 + 32)])
        self.error('forecast_adjustment', self.vault.forecast.scenario, 'd-6', ['2026-11-12T00:00:00Z'], [{'kind': 'teleport'}])
        self.error('forecast_adjustment', self.vault.forecast.scenario, 'd-7', ['2026-11-12T00:00:00Z'], [{'kind': 'release_hold'}])
        self.error('forecast_adjustment', self.vault.forecast.scenario, 'd-8', ['2026-11-12T00:00:00Z'], [{'kind': 'release_hold', 'hold_id': 'missing'}])
        policy.hold(self.db, 'hold-1', 'seal-a', 'custodian', 'kept')
        self.error('forecast_adjustment', self.vault.forecast.scenario, 'd-9', ['2026-11-12T00:00:00Z'], [{'kind': 'release_hold', 'hold_id': 'hold-1', 'at': '2026-11-10T00:00:00Z'}])
        self.assertEqual(self.vault.forecast.list(), [])


class ForecastPersistence(Case):
    def test_saved_forecasts_compare_and_detect_tamper(self):
        self.add_case()
        self.seal()
        days = ['2026-11-30T00:00:00Z', '2026-12-02T00:00:00Z']
        first = self.vault.forecast.scenario('base', days)
        second = self.vault.forecast.scenario('whatif', days, [{'kind': 'shorten_retention', 'manifest_id': 'seal-a', 'retain_until': '2026-11-15T00:00:00Z'}])
        compared = self.vault.forecast.compare('base', 'whatif')
        self.assertEqual(compared['days']['common'][0]['protected_delta_bytes'], -11)
        self.assertEqual(compared['days']['common'][1]['protected_delta_bytes'], 0)
        self.assertEqual(compared['days']['only_before'], [])
        self.assertEqual(compared['adjustments']['only_after'], [{'kind': 'shorten_retention', 'manifest_id': 'seal-a', 'retain_until': '2026-11-15T00:00:00.000000Z'}])
        self.assertEqual([row['forecast_id'] for row in self.vault.forecast.list()], ['base', 'whatif'])
        self.assertEqual([row['forecast_id'] for row in self.vault.forecast.list('scenario')], ['base', 'whatif'])
        self.assertEqual(self.vault.forecast.list('search'), [])
        self.error('forecast_exists', self.vault.forecast.scenario, 'base', days)
        self.assertEqual(self.vault.forecast.get('base')['digest'], first['digest'])
        self.db.execute("UPDATE forecasts SET body='{}' WHERE forecast_id='base'")
        self.error('forecast_corrupt', self.vault.forecast.get, 'base')
        self.error('forecast_missing', self.vault.forecast.get, 'missing')
        self.error('forecast_kind', self.vault.forecast.list, 'unknown')
        search = self.vault.forecast.search('search-1', ['2026-11-30T00:00:00Z'], '2026-11-30T00:00:00Z', 0, [{'candidate_id': 'cut', 'cost': 1, 'adjustment': {'kind': 'shorten_retention', 'manifest_id': 'seal-a', 'retain_until': '2026-11-15T00:00:00Z'}}])
        self.assertEqual(search['body']['kind'], 'search')
        self.error('forecast_kind', self.vault.forecast.compare, 'whatif', 'search-1')

    def test_forecast_leaves_business_state_untouched(self):
        self.add_case()
        self.seal()
        policy.hold(self.db, 'hold-1', 'seal-a', 'custodian', 'kept')
        journal_before = self.db.scalar('SELECT COUNT(*) FROM journal')
        self.vault.forecast.scenario('audit', ['2026-12-02T00:00:00Z'], [{'kind': 'release_hold', 'hold_id': 'hold-1'}, {'kind': 'shorten_retention', 'manifest_id': 'seal-a', 'retain_until': '2026-11-15T00:00:00Z'}])
        self.vault.forecast.search('audit-search', ['2026-12-02T00:00:00Z'], '2026-12-02T00:00:00Z', 0, [{'candidate_id': 'lift', 'cost': 5, 'adjustment': {'kind': 'release_hold', 'hold_id': 'hold-1'}}])
        self.assertEqual(self.db.scalar('SELECT COUNT(*) FROM journal'), journal_before)
        self.assertEqual(len(policy.get(self.db, 'seal-a')['holds']), 1)
        self.assertEqual(policy.get(self.db, 'seal-a')['retain_until'], '2026-12-01T00:00:00.000000Z')
        self.assertEqual(self.db.scalar('SELECT COUNT(*) FROM objects'), 3)
        self.assertEqual(self.db.scalar("SELECT state FROM holds WHERE hold_id='hold-1'"), 'active')
        self.assertTrue(checks.run(self.db)['ok'])
        self.assertTrue(semantic.verify_database(self.db)['valid'])
