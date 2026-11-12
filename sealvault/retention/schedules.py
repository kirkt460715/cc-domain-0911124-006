from sealvault.codec import key, integer, canonical, loads, digest, fail, text, after
from sealvault.custody import actors
from sealvault.custody.seals import Seals
from sealvault.retention import policy

DDL = '''
CREATE TABLE IF NOT EXISTS retention_rules(rule_id TEXT PRIMARY KEY,revision INTEGER NOT NULL,definition TEXT NOT NULL,digest TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS retention_rule_history(rule_id TEXT NOT NULL,revision INTEGER NOT NULL,definition TEXT NOT NULL,digest TEXT NOT NULL,PRIMARY KEY(rule_id,revision));
CREATE TABLE IF NOT EXISTS retention_plans(plan_id TEXT PRIMARY KEY,rule_id TEXT NOT NULL,rule_revision INTEGER NOT NULL,body TEXT NOT NULL,digest TEXT NOT NULL,state TEXT NOT NULL,author TEXT NOT NULL);
'''


class Schedules:
    def __init__(self, database):
        self.db = database
        if database.depth:
            fail('schedule_transaction', 'Initialize retention schedules outside transactions')
        database.connection.executescript(DDL)

    def rule(self, rule_id, expected_revision, days_by_class, actor):
        key(rule_id)
        actors.require(self.db, actor, {'administrator'})
        if not isinstance(days_by_class, dict) or set(days_by_class) != {'public', 'internal', 'restricted'}:
            fail('schedule_classes', 'Specify retention days for all classifications')
        normalized = {name: integer(days, 'days', 1, 3650) for name, days in sorted(days_by_class.items())}
        if normalized['restricted'] < normalized['internal'] or normalized['internal'] < normalized['public']:
            fail('schedule_order', 'More restricted classifications cannot have shorter policy retention')
        with self.db.transaction():
            prior = self.db.one('SELECT revision FROM retention_rules WHERE rule_id=?', (rule_id,))
            revision = prior['revision'] if prior else 0
            if revision != expected_revision:
                fail('schedule_revision', 'Retention rule revision changed')
            self.db.execute('INSERT INTO retention_rules VALUES(?,?,?,?) ON CONFLICT(rule_id) DO UPDATE SET revision=excluded.revision,definition=excluded.definition,digest=excluded.digest', (rule_id, revision + 1, canonical(normalized), digest(normalized)))
            self.db.execute('INSERT INTO retention_rule_history VALUES(?,?,?,?)', (rule_id, revision + 1, canonical(normalized), digest(normalized)))
            self.db.log('retention.rule_saved', {'rule_id': rule_id, 'revision': revision + 1, 'actor': actor})
            return self.get_rule(rule_id)

    def get_rule(self, rule_id, revision=None):
        if revision is None:
            row = self.db.one('SELECT * FROM retention_rules WHERE rule_id=?', (rule_id,))
        else:
            row = self.db.one('SELECT * FROM retention_rule_history WHERE rule_id=? AND revision=?', (rule_id, revision))
        if row is None:
            fail('schedule_missing', 'Retention rule version does not exist')
        row['definition'] = loads(row['definition'])
        if digest(row['definition']) != row['digest']:
            fail('schedule_corrupt', 'Retention rule checksum differs')
        return row

    def preview(self, plan_id, rule_id, manifest_ids, author):
        key(plan_id)
        actors.require(self.db, author, {'custodian', 'administrator'})
        if not isinstance(manifest_ids, list) or not 1 <= len(manifest_ids) <= 1000 or len(set(manifest_ids)) != len(manifest_ids):
            fail('schedule_selection', 'Select distinct bounded manifest identifiers')
        with self.db.transaction():
            if self.db.one('SELECT plan_id FROM retention_plans WHERE plan_id=?', (plan_id,)):
                fail('schedule_plan_exists', 'Retention plan identifier exists')
            rule = self.get_rule(rule_id)
            rows = []
            for identity in sorted(manifest_ids):
                manifest = Seals(self.db).get(identity)
                current = policy.assert_available(self.db, identity)
                body = manifest['manifest']['body']
                target = after(body['created_at'], rule['definition'][body['classification']] * 86400)
                rows.append({'manifest_id': identity, 'classification': body['classification'], 'revision': current['revision'], 'before': current['retain_until'], 'target': max(target, current['retain_until']), 'extend': target > current['retain_until']})
            payload = {'rule_id': rule_id, 'rule_revision': rule['revision'], 'rule_digest': rule['digest'], 'rows': rows}
            self.db.execute("INSERT INTO retention_plans VALUES(?,?,?,?,?,'prepared',?)", (plan_id, rule_id, rule['revision'], canonical(payload), digest(payload), author))
            return self.get_plan(plan_id)

    def get_plan(self, plan_id):
        row = self.db.one('SELECT * FROM retention_plans WHERE plan_id=?', (plan_id,))
        if row is None:
            fail('schedule_plan_missing', 'Retention plan does not exist')
        row['body'] = loads(row['body'])
        if digest(row['body']) != row['digest']:
            fail('schedule_plan_corrupt', 'Retention plan checksum differs')
        return row

    def apply(self, plan_id, reviewer, expected_digest, reason):
        actors.require(self.db, reviewer, {'administrator'})
        reason = text(reason)
        with self.db.transaction():
            plan = self.get_plan(plan_id)
            if plan['state'] != 'prepared' or plan['author'] == reviewer:
                fail('schedule_review', 'Independent administrator must approve prepared plan')
            if expected_digest != plan['digest'] or self.get_rule(plan['rule_id'])['revision'] != plan['rule_revision']:
                fail('schedule_stale', 'Rule changed or reviewer acknowledged another plan')
            for row in plan['body']['rows']:
                current = policy.assert_available(self.db, row['manifest_id'])
                if current['revision'] != row['revision']:
                    fail('schedule_stale', 'Manifest retention changed after preview')
            applied = []
            for row in plan['body']['rows']:
                if row['extend']:
                    policy.extend(self.db, row['manifest_id'], row['revision'], row['target'], reviewer, reason)
                    applied.append(row['manifest_id'])
            self.db.execute("UPDATE retention_plans SET state='applied' WHERE plan_id=?", (plan_id,))
            self.db.log('retention.schedule_applied', {'plan_id': plan_id, 'reviewer': reviewer, 'manifests': applied})
            return {'plan': self.get_plan(plan_id), 'extended': applied}
