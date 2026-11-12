from sealvault.codec import key, timestamp, integer, canonical, loads, digest, fail, VaultError
from sealvault import quotas

DDL = '''
CREATE TABLE IF NOT EXISTS forecasts(forecast_id TEXT PRIMARY KEY,kind TEXT NOT NULL,created_at TEXT NOT NULL,body TEXT NOT NULL,digest TEXT NOT NULL);
'''

PROTECTION_KINDS = ('draft', 'prepared', 'retention', 'hold', 'pin', 'staging', 'replica', 'replica_hold')

NOTES = [
    'unique_bytes count each stored object once while logical_bytes count every active reference, so logical bytes can exceed physical usage',
    'logical release does not shrink the SQLite file: freed pages stay on the freelist until VACUUM, which forecasts never run',
    'replica bytes belong to a separate remote-replica budget and are not part of local primary content',
    'retention and replica policies are modeled as expiring at their retain_until; actual reclamation still requires disposal review and collection',
    'hold releases, case closures and pin removals happen only through explicit assumptions; nothing is released by default',
    'a forecast never mutates cases, holds, pins, replicas, retention rules or objects',
]

SEARCH_NOTES = NOTES + [
    'best_case_bound_bytes is an optimistic lower bound collected from pruned branches; real combinations may protect more',
]

ADJUSTMENT_FIELDS = {
    'extend_retention': ({'kind', 'manifest_id', 'retain_until'}, set()),
    'shorten_retention': ({'kind', 'manifest_id', 'retain_until'}, set()),
    'extend_replica': ({'kind', 'import_id', 'retain_until'}, set()),
    'shorten_replica': ({'kind', 'import_id', 'retain_until'}, set()),
    'release_hold': ({'kind', 'hold_id'}, {'at'}),
    'release_replica_hold': ({'kind', 'hold_id'}, {'at'}),
    'release_pin': ({'kind', 'pin_id'}, {'at'}),
    'close_case': ({'kind', 'case_id'}, {'at'}),
    'abandon_manifest': ({'kind', 'manifest_id'}, {'at'}),
    'release_replica': ({'kind', 'import_id'}, {'at'}),
}


class Forecast:
    MAX_DAYS = 31
    MAX_OBJECTS = 100000
    MAX_EVIDENCE = 10000
    MAX_ADJUSTMENTS = 100
    MAX_CANDIDATES = 20
    MAX_EVALUATIONS = 200000
    MAX_SEARCH_WORK = 10000000

    def __init__(self, database):
        self.db = database
        if database.depth:
            fail('forecast_transaction', 'Initialize forecasts outside transactions')
        database.connection.executescript(DDL)

    def scenario(self, forecast_id, days, adjustments=None):
        key(forecast_id)
        days = self._days(days)
        adjustments = self._adjustment_list(adjustments)
        with self.db.transaction():
            if self.db.one('SELECT forecast_id FROM forecasts WHERE forecast_id=?', (forecast_id,)):
                fail('forecast_exists', 'Forecast identifiers are immutable')
            frozen = self._freeze()
            normalized, effects = self._normalize(frozen, adjustments, days[0])
            evidence, truncated = self._evidence(frozen, days, effects)
            body = {'kind': 'scenario', 'created_at': frozen['now'], 'days': days, 'adjustments': normalized, 'series': self._series(frozen, days, effects), 'baseline': self._series(frozen, days, {}), 'objects': frozen['totals'], 'evidence': evidence, 'evidence_truncated': truncated, 'physical': self._physical(frozen), 'notes': NOTES}
            self.db.execute('INSERT INTO forecasts VALUES(?,?,?,?,?)', (forecast_id, 'scenario', frozen['now'], canonical(body), digest(body)))
            return self.get(forecast_id)

    def search(self, search_id, days, target_day, max_protected_bytes, candidates, max_evaluations=50000):
        key(search_id)
        days = self._days(days)
        target_day = timestamp(target_day)
        if target_day not in set(days):
            fail('forecast_target', 'Target day must be one of the observation days')
        integer(max_protected_bytes, 'max_protected_bytes', 0, 10 ** 15)
        integer(max_evaluations, 'max_evaluations', 1, self.MAX_EVALUATIONS)
        if not isinstance(candidates, list) or not 1 <= len(candidates) <= self.MAX_CANDIDATES:
            fail('forecast_candidates', 'Candidate set must hold between 1 and 20 adjustments')
        with self.db.transaction():
            if self.db.one('SELECT forecast_id FROM forecasts WHERE forecast_id=?', (search_id,)):
                fail('forecast_exists', 'Forecast identifiers are immutable')
            frozen = self._freeze()
            records = sum(len(obj['records']) for obj in frozen['objects'].values())
            if max(1, records) * max_evaluations > self.MAX_SEARCH_WORK:
                fail('forecast_scale', 'Catalog size times evaluation budget exceeds the search work limit')
            parsed = self._candidates(frozen, candidates, days[0])
            result = self._optimize(frozen, target_day, max_protected_bytes, parsed, max_evaluations)
            body = {'kind': 'search', 'created_at': frozen['now'], 'days': days, 'target': {'day': target_day, 'max_protected_bytes': max_protected_bytes}, **result, 'physical': self._physical(frozen), 'notes': SEARCH_NOTES}
            self.db.execute('INSERT INTO forecasts VALUES(?,?,?,?,?)', (search_id, 'search', frozen['now'], canonical(body), digest(body)))
            return self.get(search_id)

    def get(self, forecast_id):
        row = self.db.one('SELECT * FROM forecasts WHERE forecast_id=?', (forecast_id,))
        if row is None:
            fail('forecast_missing', 'Forecast does not exist')
        row['body'] = loads(row['body'])
        if digest(row['body']) != row['digest']:
            fail('forecast_corrupt', 'Forecast checksum differs')
        return row

    def list(self, kind=None):
        if kind is not None and kind not in {'scenario', 'search'}:
            fail('forecast_kind', 'Unknown forecast kind')
        sql = 'SELECT forecast_id,kind,created_at,digest FROM forecasts'
        arguments = []
        if kind:
            sql += ' WHERE kind=?'
            arguments.append(kind)
        return self.db.all(sql + ' ORDER BY forecast_id', arguments)

    def compare(self, before_id, after_id):
        before = self.get(before_id)
        after = self.get(after_id)
        if before['kind'] != 'scenario' or after['kind'] != 'scenario':
            fail('forecast_kind', 'Only scenario forecasts can be compared')
        left = {row['day']: row for row in before['body']['series']}
        right = {row['day']: row for row in after['body']['series']}
        common = []
        for day in sorted(set(left) & set(right)):
            common.append({'day': day, 'protected_delta_bytes': right[day]['protected_unique_bytes'] - left[day]['protected_unique_bytes'], 'logical_delta_bytes': right[day]['protected_logical_bytes'] - left[day]['protected_logical_bytes'], 'releasable_delta_bytes': right[day]['releasable_bytes'] - left[day]['releasable_bytes']})
        before_adjustments = {canonical(item): item for item in before['body']['adjustments']}
        after_adjustments = {canonical(item): item for item in after['body']['adjustments']}
        return {'before': before_id, 'after': after_id, 'days': {'common': common, 'only_before': sorted(set(left) - set(right)), 'only_after': sorted(set(right) - set(left))}, 'adjustments': {'only_before': [before_adjustments[item] for item in sorted(set(before_adjustments) - set(after_adjustments))], 'only_after': [after_adjustments[item] for item in sorted(set(after_adjustments) - set(before_adjustments))]}}

    def _days(self, days):
        if not isinstance(days, list) or not 1 <= len(days) <= self.MAX_DAYS:
            fail('forecast_days', 'Provide between 1 and 31 observation days')
        normalized = [timestamp(day) for day in days]
        if len(set(normalized)) != len(normalized) or normalized != sorted(normalized):
            fail('forecast_days', 'Observation days must be distinct and strictly increasing')
        if normalized[0] < self.db.clock():
            fail('forecast_days', 'Observation days cannot precede the forecast start')
        return normalized

    def _adjustment_list(self, adjustments):
        if adjustments is None:
            return []
        if not isinstance(adjustments, list) or len(adjustments) > self.MAX_ADJUSTMENTS:
            fail('forecast_adjustment', 'Adjustments must be a bounded list', maximum=self.MAX_ADJUSTMENTS)
        return adjustments

    def _freeze(self):
        now = self.db.clock()
        objects = {}
        for row in self.db.all('SELECT digest,size,state FROM objects ORDER BY digest'):
            objects[row['digest']] = {'digest': row['digest'], 'size': row['size'], 'state': row['state'], 'records': []}
        if len(objects) > self.MAX_OBJECTS:
            fail('forecast_scale', 'Object catalog exceeds forecast capacity', objects=len(objects), maximum=self.MAX_OBJECTS)

        def attach(identity, record):
            target = objects.get(identity)
            if target is not None:
                target['records'].append(record)

        for row in self.db.all("SELECT e.case_id,e.path,e.digest FROM entries e JOIN cases c ON c.case_id=e.case_id WHERE c.state='draft' ORDER BY e.case_id,e.path"):
            attach(row['digest'], {'kind': 'draft', 'id': row['case_id'] + ':' + row['path'], 'group': row['case_id'], 'target': ('case', row['case_id']), 'end': None})
        for row in self.db.all("SELECT o.digest,o.manifest_id FROM manifest_objects o JOIN manifests m ON m.manifest_id=o.manifest_id WHERE m.state='prepared' ORDER BY o.manifest_id,o.digest"):
            attach(row['digest'], {'kind': 'prepared', 'id': row['manifest_id'], 'group': row['manifest_id'], 'target': ('prepared', row['manifest_id']), 'end': None})
        for row in self.db.all("SELECT o.digest,o.manifest_id,r.retain_until FROM manifest_objects o JOIN manifests m ON m.manifest_id=o.manifest_id JOIN retention r ON r.manifest_id=o.manifest_id WHERE m.state='sealed' AND r.state='active' ORDER BY o.manifest_id,o.digest"):
            attach(row['digest'], {'kind': 'retention', 'id': row['manifest_id'], 'group': row['manifest_id'], 'target': ('retention', row['manifest_id']), 'end': row['retain_until']})
        for row in self.db.all("SELECT h.hold_id,h.manifest_id,o.digest FROM holds h JOIN manifest_objects o ON o.manifest_id=h.manifest_id WHERE h.state='active' ORDER BY h.hold_id"):
            attach(row['digest'], {'kind': 'hold', 'id': row['hold_id'], 'group': row['manifest_id'], 'target': ('hold', row['hold_id']), 'end': None})
        for row in self.db.all('SELECT pin_id,digest,expires_at FROM pins WHERE expires_at>? ORDER BY pin_id', (now,)):
            attach(row['digest'], {'kind': 'pin', 'id': row['pin_id'], 'group': row['pin_id'], 'target': ('pin', row['pin_id']), 'end': row['expires_at']})
        for row in self.db.all("SELECT session_id,expected_digest,expires_at FROM staging WHERE state='receiving' AND expires_at>? ORDER BY session_id", (now,)):
            attach(row['expected_digest'], {'kind': 'staging', 'id': row['session_id'], 'group': row['session_id'], 'target': None, 'end': row['expires_at']})
        if self.db.one("SELECT name FROM sqlite_master WHERE name='replicas'"):
            for row in self.db.all("SELECT o.object_digest,o.import_id,p.retain_until FROM replicas r JOIN imported_objects o ON o.import_id=r.import_id LEFT JOIN replica_retention p ON p.import_id=r.import_id WHERE r.state='retained' ORDER BY o.import_id,o.object_digest"):
                attach(row['object_digest'], {'kind': 'replica', 'id': row['import_id'], 'group': row['import_id'], 'target': ('replica', row['import_id']), 'end': row['retain_until']})
            for row in self.db.all("SELECT h.hold_id,o.object_digest,o.import_id FROM replica_holds h JOIN replicas r ON r.import_id=h.import_id JOIN imported_objects o ON o.import_id=h.import_id WHERE h.state='active' AND r.state='retained' ORDER BY h.hold_id"):
                attach(row['object_digest'], {'kind': 'replica_hold', 'id': row['hold_id'], 'group': row['import_id'], 'target': ('replica_hold', row['hold_id']), 'end': None})
        for obj in objects.values():
            obj['records'].sort(key=lambda record: (record['kind'], record['id']))
        quarantined = [obj for obj in objects.values() if obj['state'] != 'available']
        totals = {'count': len(objects), 'unique_bytes': sum(obj['size'] for obj in objects.values()), 'quarantined_count': len(quarantined), 'quarantined_bytes': sum(obj['size'] for obj in quarantined)}
        return {'now': now, 'objects': objects, 'totals': totals}

    def _normalize(self, frozen, adjustments, first_day):
        normalized = []
        effects = {}
        for item in adjustments:
            if not isinstance(item, dict) or not isinstance(item.get('kind'), str) or item['kind'] not in ADJUSTMENT_FIELDS:
                fail('forecast_adjustment', 'Adjustment must be an object with a known kind')
            kind = item['kind']
            required, optional = ADJUSTMENT_FIELDS[kind]
            missing = required - set(item)
            extra = set(item) - required - optional
            if missing or extra:
                fail('forecast_adjustment', 'Adjustment fields differ from its kind', kind=kind, missing=sorted(missing), extra=sorted(extra))
            entry, target, end = self._adjustment(frozen, item, first_day)
            if target in effects:
                fail('forecast_conflict', 'Two adjustments target the same protection', kind=kind, target=list(target))
            effects[target] = end
            normalized.append(entry)
        return normalized, effects

    def _adjustment(self, frozen, item, first_day):
        kind = item['kind']
        now = frozen['now']
        if kind in {'extend_retention', 'shorten_retention'}:
            manifest_id = key(item['manifest_id'])
            row = self.db.one("SELECT m.state,r.retain_until,r.state AS retention_state FROM manifests m LEFT JOIN retention r ON r.manifest_id=m.manifest_id WHERE m.manifest_id=?", (manifest_id,))
            if row is None or row['state'] != 'sealed' or row['retention_state'] != 'active':
                fail('forecast_adjustment', 'Manifest has no active retention rule to adjust', manifest_id=manifest_id)
            retain_until = timestamp(item['retain_until'])
            if kind == 'extend_retention' and retain_until <= row['retain_until']:
                fail('forecast_adjustment', 'Extension must move the deadline later; use shorten_retention otherwise', manifest_id=manifest_id)
            if kind == 'shorten_retention' and retain_until >= row['retain_until']:
                fail('forecast_adjustment', 'Shortening must move the deadline earlier; use extend_retention otherwise', manifest_id=manifest_id)
            return {'kind': kind, 'manifest_id': manifest_id, 'retain_until': retain_until}, ('retention', manifest_id), retain_until
        if kind in {'extend_replica', 'shorten_replica'}:
            import_id = key(item['import_id'])
            self._retained_replica(import_id)
            policy = self.db.one('SELECT retain_until FROM replica_retention WHERE import_id=?', (import_id,))
            if policy is None:
                fail('forecast_adjustment', 'Replica has no explicit retention policy; model its release with release_replica', import_id=import_id)
            retain_until = timestamp(item['retain_until'])
            if kind == 'extend_replica' and retain_until <= policy['retain_until']:
                fail('forecast_adjustment', 'Extension must move the replica deadline later', import_id=import_id)
            if kind == 'shorten_replica' and retain_until >= policy['retain_until']:
                fail('forecast_adjustment', 'Shortening must move the replica deadline earlier', import_id=import_id)
            return {'kind': kind, 'import_id': import_id, 'retain_until': retain_until}, ('replica', import_id), retain_until
        at = timestamp(item['at']) if 'at' in item else first_day
        if at < now:
            fail('forecast_adjustment', 'Assumption cannot take effect before the forecast start')
        if kind == 'release_hold':
            hold_id = key(item['hold_id'])
            row = self.db.one('SELECT state FROM holds WHERE hold_id=?', (hold_id,))
            if row is None or row['state'] != 'active':
                fail('forecast_adjustment', 'Hold is absent or not active', hold_id=hold_id)
            return {'kind': kind, 'hold_id': hold_id, 'at': at}, ('hold', hold_id), at
        if kind == 'release_replica_hold':
            hold_id = key(item['hold_id'])
            if not self.db.one("SELECT name FROM sqlite_master WHERE name='replica_holds'"):
                fail('forecast_adjustment', 'Replica hold tables are absent', hold_id=hold_id)
            row = self.db.one('SELECT state FROM replica_holds WHERE hold_id=?', (hold_id,))
            if row is None or row['state'] != 'active':
                fail('forecast_adjustment', 'Replica hold is absent or not active', hold_id=hold_id)
            return {'kind': kind, 'hold_id': hold_id, 'at': at}, ('replica_hold', hold_id), at
        if kind == 'release_pin':
            pin_id = key(item['pin_id'])
            row = self.db.one('SELECT expires_at FROM pins WHERE pin_id=?', (pin_id,))
            if row is None or row['expires_at'] <= now:
                fail('forecast_adjustment', 'Pin is absent or already expired', pin_id=pin_id)
            return {'kind': kind, 'pin_id': pin_id, 'at': at}, ('pin', pin_id), at
        if kind == 'close_case':
            case_id = key(item['case_id'])
            row = self.db.one('SELECT state FROM cases WHERE case_id=?', (case_id,))
            if row is None or row['state'] != 'draft':
                fail('forecast_adjustment', 'Only a draft case can be assumed to close', case_id=case_id)
            return {'kind': kind, 'case_id': case_id, 'at': at}, ('case', case_id), at
        if kind == 'abandon_manifest':
            manifest_id = key(item['manifest_id'])
            row = self.db.one('SELECT state FROM manifests WHERE manifest_id=?', (manifest_id,))
            if row is None or row['state'] != 'prepared':
                fail('forecast_adjustment', 'Only a prepared manifest can be assumed abandoned', manifest_id=manifest_id)
            return {'kind': kind, 'manifest_id': manifest_id, 'at': at}, ('prepared', manifest_id), at
        import_id = key(item['import_id'])
        self._retained_replica(import_id)
        return {'kind': kind, 'import_id': import_id, 'at': at}, ('replica', import_id), at

    def _retained_replica(self, import_id):
        if not self.db.one("SELECT name FROM sqlite_master WHERE name='replicas'"):
            fail('forecast_adjustment', 'Replica tables are absent', import_id=import_id)
        row = self.db.one('SELECT state FROM replicas WHERE import_id=?', (import_id,))
        if row is None or row['state'] != 'retained':
            fail('forecast_adjustment', 'Replica is absent or already released', import_id=import_id)

    def _candidates(self, frozen, candidates, first_day):
        parsed = []
        seen = set()
        for item in candidates:
            if not isinstance(item, dict) or set(item) != {'candidate_id', 'cost', 'adjustment'}:
                fail('forecast_candidates', 'Candidate requires candidate_id, cost and adjustment')
            candidate_id = item['candidate_id']
            if not isinstance(candidate_id, str):
                fail('forecast_candidates', 'Candidate identifier must be a string')
            try:
                key(candidate_id)
            except VaultError:
                fail('forecast_candidates', 'Candidate identifier must be a bounded symbolic key')
            if candidate_id in seen:
                fail('forecast_candidates', 'Candidate identifiers must be distinct')
            seen.add(candidate_id)
            cost = integer(item['cost'], 'cost', 0, 10 ** 9)
            normalized, effects = self._normalize(frozen, [item['adjustment']], first_day)
            parsed.append({'candidate_id': candidate_id, 'cost': cost, 'adjustment': normalized[0], 'effects': effects})
        return parsed

    @staticmethod
    def _active(record, day, effects):
        end = record['end']
        target = record['target']
        if target is not None and target in effects:
            end = effects[target]
        return end is None or day < end

    def _evaluate_day(self, frozen, day, effects):
        protected_unique = 0
        protected_logical = 0
        releasable = 0
        protected_objects = 0
        releasable_objects = 0
        by_kind = {kind: {'objects': 0, 'bytes': 0} for kind in PROTECTION_KINDS}
        for obj in frozen['objects'].values():
            active = [record for record in obj['records'] if self._active(record, day, effects)]
            if not active:
                releasable += obj['size']
                releasable_objects += 1
                continue
            protected_unique += obj['size']
            protected_objects += 1
            for kind in {record['kind'] for record in active}:
                by_kind[kind]['objects'] += 1
                by_kind[kind]['bytes'] += obj['size']
            references = sum(1 for record in active if record['kind'] in ('draft', 'pin', 'staging', 'replica'))
            references += len({record['group'] for record in active if record['kind'] in ('retention', 'prepared', 'hold')})
            protected_logical += obj['size'] * references
        return {'day': day, 'protected_unique_bytes': protected_unique, 'protected_logical_bytes': protected_logical, 'protected_objects': protected_objects, 'releasable_bytes': releasable, 'releasable_objects': releasable_objects, 'protected_by_kind': by_kind}

    def _series(self, frozen, days, effects):
        rows = []
        previous = self._evaluate_day(frozen, frozen['now'], effects)
        for day in days:
            row = self._evaluate_day(frozen, day, effects)
            row['released_delta_bytes'] = row['releasable_bytes'] - previous['releasable_bytes']
            rows.append(row)
            previous = row
        return rows

    def _evidence(self, frozen, days, effects):
        items = []
        truncated = False
        for index, obj in enumerate(frozen['objects'].values()):
            if index >= self.MAX_EVIDENCE:
                truncated = True
                break
            records = obj['records']
            protected_at_start = any(self._active(record, frozen['now'], effects) for record in records)
            releasable_from = None
            if protected_at_start:
                for day in days:
                    if not any(self._active(record, day, effects) for record in records):
                        releasable_from = day
                        break
            baseline_releasable_from = None
            if any(self._active(record, frozen['now'], {}) for record in records):
                for day in days:
                    if not any(self._active(record, day, {}) for record in records):
                        baseline_releasable_from = day
                        break
            protections = []
            for record in records:
                adjusted = record['target'] is not None and record['target'] in effects
                until = effects[record['target']] if adjusted else record['end']
                protections.append({'kind': record['kind'], 'id': record['id'], 'until': until, 'baseline_until': record['end'], 'adjusted': adjusted})
            items.append({'digest': obj['digest'], 'size': obj['size'], 'state': obj['state'], 'protected_at_start': protected_at_start, 'releasable_from': releasable_from, 'baseline_releasable_from': baseline_releasable_from, 'protections': protections})
        return items, truncated

    def _physical(self, frozen):
        page_size = self.db.scalar('PRAGMA page_size')
        page_count = self.db.scalar('PRAGMA page_count')
        freelist = self.db.scalar('PRAGMA freelist_count')
        main = next((row['file'] for row in self.db.all('PRAGMA database_list') if row['name'] == 'main'), '')
        report = quotas.get(self.db)
        replica_imports = {}
        replica_unique = 0
        for obj in frozen['objects'].values():
            records = [record for record in obj['records'] if record['kind'] == 'replica']
            if records:
                replica_unique += obj['size']
            for record in records:
                entry = replica_imports.setdefault(record['id'], {'objects': 0, 'bytes': 0})
                entry['objects'] += 1
                entry['bytes'] += obj['size']
        return {'database_file': main or ':memory:', 'sqlite_file_bytes': page_count * page_size, 'sqlite_freelist_bytes': freelist * page_size, 'local_content_bytes': report['usage']['bytes'], 'local_object_count': report['usage']['objects'], 'reserved_staging_bytes': report['usage']['reserved_staging_bytes'], 'replica': {'count': len(replica_imports), 'unique_bytes': replica_unique, 'logical_bytes': sum(item['bytes'] for item in replica_imports.values())}, 'quota': report['limits']}

    def _optimize(self, frozen, day, target, candidates, max_evaluations):
        objects = frozen['objects']

        def protected(effects):
            total = 0
            for obj in objects.values():
                for record in obj['records']:
                    end = record['end']
                    source = record['target']
                    if source is not None and source in effects:
                        end = effects[source]
                    if end is None or day < end:
                        total += obj['size']
                        break
            return total

        stats = {'evaluated': 0, 'pruned': 0, 'exhausted': False, 'min_seen': None}

        def evaluate(effects):
            if stats['evaluated'] >= max_evaluations:
                stats['exhausted'] = True
                return None
            stats['evaluated'] += 1
            value = protected(effects)
            stats['min_seen'] = value if stats['min_seen'] is None else min(stats['min_seen'], value)
            return value

        baseline = evaluate({})
        best = {'feasible': None, 'effort': None}

        def entry_for(indices, cost, value, feasible):
            return {'candidate_ids': sorted(candidates[index]['candidate_id'] for index in indices), 'cost': cost, 'protected_bytes': value, 'released_bytes': None if baseline is None else baseline - value, 'feasible': feasible}

        def consider_feasible(indices, cost, value):
            candidate = entry_for(indices, cost, value, True)
            current = best['feasible']
            if current is None or (cost, len(indices), value, candidate['candidate_ids']) < (current['cost'], len(current['candidate_ids']), current['protected_bytes'], current['candidate_ids']):
                best['feasible'] = candidate

        def consider_effort(indices, cost, value):
            candidate = entry_for(indices, cost, value, False)
            current = best['effort']
            if current is None or (value, cost, len(indices), candidate['candidate_ids']) < (current['protected_bytes'], current['cost'], len(current['candidate_ids']), current['candidate_ids']):
                best['effort'] = candidate

        if baseline is not None:
            if baseline <= target:
                consider_feasible([], 0, baseline)
            else:
                consider_effort([], 0, baseline)

        standalone = []
        for candidate in candidates:
            value = evaluate(candidate['effects'])
            standalone.append(None if value is None else baseline - value)

        order = sorted(range(len(candidates)), key=lambda index: (candidates[index]['cost'], candidates[index]['candidate_id']))
        greedy_effects = {}
        greedy_indices = []
        greedy_cost = 0
        for index in order:
            effects = candidates[index]['effects']
            if not any(source in greedy_effects for source in effects):
                greedy_effects.update(effects)
                greedy_indices.append(index)
                greedy_cost += candidates[index]['cost']
        full = evaluate(greedy_effects)
        if full is not None:
            if full <= target:
                consider_feasible(greedy_indices, greedy_cost, full)
            else:
                consider_effort(greedy_indices, greedy_cost, full)

        current_effects = {}
        chosen = []

        def recurse(position, cost, value):
            if stats['exhausted']:
                return
            if value <= target:
                consider_feasible(chosen, cost, value)
                return
            consider_effort(chosen, cost, value)
            champion = best['feasible']
            if champion is not None and (cost > champion['cost'] or cost == champion['cost'] and len(chosen) >= len(champion['candidate_ids'])):
                stats['pruned'] += 1
                return
            optimistic = dict(current_effects)
            for index in order[position:]:
                for source, end in candidates[index]['effects'].items():
                    if source not in optimistic or end < optimistic[source]:
                        optimistic[source] = end
            bound = evaluate(optimistic)
            if bound is None:
                return
            if bound > target:
                stats['pruned'] += 1
                return
            if position >= len(order):
                return
            candidate = candidates[order[position]]
            if not any(source in current_effects for source in candidate['effects']):
                current_effects.update(candidate['effects'])
                chosen.append(order[position])
                included = evaluate(current_effects)
                if included is not None:
                    recurse(position + 1, cost + candidate['cost'], included)
                chosen.pop()
                for source in candidate['effects']:
                    del current_effects[source]
            recurse(position + 1, cost, value)

        if baseline is not None:
            recurse(0, 0, baseline)

        complete = not stats['exhausted']
        if not complete:
            status = 'incomplete'
        elif best['feasible'] is not None:
            status = 'optimal'
        else:
            status = 'unreachable'
        selected = best['feasible'] or best['effort']
        gap = 0
        if best['feasible'] is None and selected is not None:
            gap = selected['protected_bytes'] - target
        rows = []
        for candidate, alone in zip(candidates, standalone):
            rows.append({'candidate_id': candidate['candidate_id'], 'cost': candidate['cost'], 'adjustment': candidate['adjustment'], 'standalone_released_bytes': alone})
        return {'status': status, 'search_complete': complete, 'proven_optimal': status == 'optimal', 'baseline_protected_bytes': baseline, 'best': selected, 'gap_bytes': gap, 'best_case_bound_bytes': stats['min_seen'], 'evaluated': stats['evaluated'], 'pruned': stats['pruned'], 'limits': {'max_candidates': self.MAX_CANDIDATES, 'max_evaluations': max_evaluations}, 'candidates': rows}
