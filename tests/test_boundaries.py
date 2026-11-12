import copy
import io
import tempfile
from pathlib import Path
from contextlib import redirect_stdout, redirect_stderr
from tests.support import Case
from sealvault.codec import loads, canonical, digest, sha256, encode, decode, path, timestamp
from sealvault import manifests, quotas
from sealvault.custody import actors, chain, checkpoints
from sealvault.service import Vault
from sealvault.retention import policy
from sealvault.inspect import checks, semantic
from sealvault.cli import main, replay


class Boundaries(Case):
    def test_json_base64_and_portable_paths(self):
        self.error('duplicate_key', loads, '{"x":1,"x":2}')
        self.error('nonfinite', loads, '{"x":NaN}')
        self.error('json_decode', loads, '{')
        self.error('base64', decode, 'YQ=')
        self.error('base64', decode, 'YQ== ')
        self.assertEqual(decode('YQ=='), b'a')
        self.error('timestamp', timestamp, '2026-11-11T00:00:00')
        self.error('path_normalization', path, 'e' + chr(769))
        self.assertEqual(path('中文/数据.json'), '中文/数据.json')
        self.assertEqual(timestamp('2026-11-11T08:00:00+08:00'), self.clock())
        self.assertEqual(loads(canonical({'source': '合成'})), {'source': '合成'})

    def test_case_insensitive_prefix_collision_regardless_sort_order(self):
        self.add_case(contents={'a': b'x'})
        case = self.vault.cases.get('case-a')
        entry = {**case['entries'][0], 'path': 'A/child'}
        self.error('manifest_prefix', self.vault.cases.attach, 'case-a', case['revision'], 'collector', entry)
        self.assertEqual(len(self.vault.cases.get('case-a')['entries']), 1)
        self.assertEqual(self.vault.cases.get('case-a')['revision'], case['revision'])
        other = {**entry, 'path': 'b/child'}
        self.vault.cases.attach('case-a', case['revision'], 'collector', other)
        self.assertEqual(len(self.vault.cases.get('case-a')['entries']), 2)

    def test_merkle_proof_rejects_wrong_root_direction_and_count(self):
        self.add_case()
        sealed = self.seal()
        proof = self.vault.seals.proof('seal-a', 'records/a.txt')
        self.error('proof_root', manifests.verify_proof, proof, '0' * 64)
        changed = copy.deepcopy(proof)
        changed['siblings'][0]['side'] = 'right' if changed['siblings'][0]['side'] == 'left' else 'left'
        self.error('proof_side', manifests.verify_proof, changed, sealed['merkle_root'])
        changed = copy.deepcopy(proof)
        changed['siblings'].pop()
        self.error('proof_length', manifests.verify_proof, changed, sealed['merkle_root'])
        self.assertTrue(manifests.verify_proof(proof, sealed['merkle_root'])['valid'])
        self.assertEqual(proof['count'], 3)

    def test_manifest_reference_index_tamper_is_detected(self):
        self.add_case()
        self.seal()
        self.db.execute('DELETE FROM manifest_objects WHERE digest=?', (sha256(b'alpha'),))
        self.error('manifest_references', self.vault.seals.get, 'seal-a')
        report = checks.run(self.db)
        self.assertFalse(report['ok'])
        self.assertIn('manifest_references', [row['code'] for row in report['problems']])
        self.assertEqual(self.db.scalar('SELECT COUNT(*) FROM objects'), 3)
        self.assertEqual(self.db.scalar('SELECT COUNT(*) FROM retention'), 1)

    def test_suspended_actor_cannot_mutate_or_accept(self):
        case = self.add_case()
        actors.suspend(self.db, 'collector', 'admin', 'account paused')
        self.error('actor_permission', self.vault.cases.rename, 'case-a', case['revision'], 'collector', 'index.json', 'new.json')
        self.error('actor_self', actors.suspend, self.db, 'admin', 'admin', 'self')
        self.assertEqual(self.vault.cases.get('case-a')['revision'], case['revision'])
        actors.restore(self.db, 'collector', 'admin', 'restored')
        self.vault.cases.rename('case-a', case['revision'], 'collector', 'index.json', 'new.json')
        self.assertEqual(actors.get(self.db, 'collector')['state'], 'active')
        self.assertTrue(chain.verify(self.db, 'case-a')['valid'])

    def test_clock_regression_rolls_back_case_edit(self):
        case = self.add_case()
        before = self.db.scalar('SELECT COUNT(*) FROM custody')
        self.clock.set('2026-11-10T00:00:00Z')
        self.error('custody_clock', self.vault.cases.rename, 'case-a', case['revision'], 'collector', 'index.json', 'new.json')
        current = self.vault.cases.get('case-a')
        self.assertEqual(current['revision'], case['revision'])
        self.assertEqual(current['entries'], case['entries'])
        self.assertEqual(self.db.scalar('SELECT COUNT(*) FROM custody'), before)
        self.assertEqual(self.db.depth, 0)

    def test_concurrent_connection_revision_fence_and_reopen(self):
        with tempfile.TemporaryDirectory() as temporary:
            filename = Path(temporary) / 'vault.sqlite'
            with Vault(filename, clock=self.clock) as first:
                actors.register(first.db, 'collector', 'collector')
                first.cases.create('case-a', 'Synthetic', 'collector')
                item = first.objects.put(b'a')
                first.cases.attach('case-a', 1, 'collector', {'path': 'a', 'digest': item['digest'], 'size': 1, 'media_type': 'text/plain'})
            with Vault(filename, clock=self.clock) as first, Vault(filename, clock=self.clock) as second:
                self.assertEqual(second.cases.get('case-a')['revision'], 2)
                first.cases.rename('case-a', 2, 'collector', 'a', 'b')
                self.error('case_revision', second.cases.rename, 'case-a', 2, 'collector', 'a', 'c')
                self.assertEqual(second.cases.get('case-a')['entries'][0]['path'], 'b')
                self.assertTrue(semantic.replay_case(second.db, 'case-a')['valid'])
                self.assertTrue(checks.run(second.db)['ok'])

    def test_nested_transactions_rollback_inner_only(self):
        with self.db.transaction():
            self.vault.objects.put(b'outer')
            try:
                with self.db.transaction():
                    self.vault.objects.put(b'inner')
                    raise RuntimeError('abort inner')
            except RuntimeError:
                pass
            self.assertEqual(self.db.scalar('SELECT COUNT(*) FROM objects'), 1)
        self.assertEqual(self.vault.objects.read(sha256(b'outer')), b'outer')
        self.error('object_missing', self.vault.objects.read, sha256(b'inner'))
        self.assertEqual(self.db.depth, 0)
        self.assertTrue(checks.journal(self.db)['valid'])

    def test_cli_errors_are_structured_and_read_only_commands_work(self):
        with tempfile.TemporaryDirectory() as temporary:
            request = Path(temporary) / 'request.json'
            request.write_text(canonical({'operation': 'case.get', 'arguments': {'case_id': 'missing'}}))
            out = io.StringIO()
            error = io.StringIO()
            with redirect_stdout(out), redirect_stderr(error):
                code = main(['execute', str(request)])
            self.assertEqual(code, 2)
            self.assertEqual(out.getvalue(), '')
            self.assertEqual(loads(error.getvalue())['error']['code'], 'case_missing')
            with redirect_stdout(out):
                code = main(['commands'])
            self.assertEqual(code, 0)
            self.assertIn('seal.seal', [row['operation'] for row in loads(out.getvalue())])

    def test_fixture_assertions_fail_without_hiding_errors(self):
        self.add_case()
        fixture = {'synthetic': True, 'steps': [{'request': {'operation': 'case.get', 'arguments': {'case_id': 'case-a'}}, 'expect': {'state': 'draft', 'entries.0.path': 'index.json'}}]}
        result = replay(self.vault, fixture)
        self.assertTrue(result['ok'])
        self.assertEqual(result['steps'][0]['assertions'], 2)
        fixture['steps'][0]['expect']['state'] = 'sealed'
        self.error('fixture_assertion', replay, self.vault, fixture)
        fixture['steps'][0]['expect'] = {'nonexistent': 1}
        self.error('fixture_path', replay, self.vault, fixture)
        self.error('fixture', replay, self.vault, {'synthetic': False, 'steps': []})
        self.assertEqual(self.vault.cases.get('case-a')['state'], 'draft')

    def test_parent_binding_requires_recorded_fork(self):
        self.add_case()
        self.seal()
        other = self.add_case('other-case')
        self.error('manifest_parent_binding', self.vault.seals.prepare, 'bad-parent', 'other-case', other['revision'], 'collector', 'seal-a')
        fork = self.vault.seals.fork('seal-a', 'fork', 'collector', 'Derived evidence')
        self.error('manifest_parent_binding', self.vault.seals.prepare, 'missing-parent', 'fork', fork['revision'], 'collector')
        prepared = self.vault.seals.prepare('correct-parent', 'fork', fork['revision'], 'collector', 'seal-a')
        self.assertEqual(prepared['parent_id'], 'seal-a')
        self.assertEqual(prepared['state'], 'prepared')
        self.assertEqual(semantic.ancestry(self.db, 'correct-parent')['depth'], 2)

    def test_gc_plan_digest_and_role_are_required(self):
        self.vault.objects.put(b'orphan')
        plan = self.vault.collector.plan('plan', self.clock())
        self.error('actor_permission', self.vault.collector.advance, 'plan', 'collector', plan['digest'])
        self.error('gc_acknowledgement', self.vault.collector.advance, 'plan', 'admin', 'wrong')
        self.assertEqual(self.db.scalar('SELECT COUNT(*) FROM objects'), 1)
        self.assertEqual(self.vault.collector.get('plan')['results'], [])
        done = self.vault.collector.advance('plan', 'admin', plan['digest'])
        self.assertEqual(done['state'], 'complete')
        self.assertEqual(self.vault.collector.report('plan')['deleted_bytes'], 6)
        self.assertEqual(self.vault.collector.advance('plan', 'admin', plan['digest'])['results'], done['results'])
