from sealvault.codec import key, timestamp, text, fail, canonical, digest
from sealvault.custody import actors, chain


def get(db, manifest_id):
    row = db.one('SELECT * FROM retention WHERE manifest_id=?', (manifest_id,))
    if row is None:
        fail('retention_missing', 'Manifest has no committed retention policy')
    row['holds'] = db.all("SELECT * FROM holds WHERE manifest_id=? AND state='active' ORDER BY hold_id", (manifest_id,))
    row['eligible'] = row['state'] == 'active' and row['retain_until'] <= db.clock() and not row['holds']
    return row


def assert_available(db, manifest_id):
    policy = get(db, manifest_id)
    if policy['state'] != 'active':
        fail('evidence_disposed', 'Evidence has been disposed; only its manifest and custody metadata remain')
    return policy


def extend(db, manifest_id, expected_revision, retain_until, actor, reason):
    actors.require(db, actor, {'custodian', 'administrator'})
    retain_until = timestamp(retain_until)
    reason = text(reason)
    with db.transaction():
        previous = get(db, manifest_id)
        if previous['revision'] != expected_revision:
            fail('retention_stale', 'Retention revision changed')
        if previous['state'] != 'active':
            fail('retention_state', 'Disposed retention cannot be changed')
        if retain_until <= previous['retain_until']:
            fail('retention_shorten', 'Retention may only be extended')
        db.execute('UPDATE retention SET retain_until=?,revision=revision+1,reason=? WHERE manifest_id=?', (retain_until, reason, manifest_id))
        case_id = db.scalar('SELECT case_id FROM manifests WHERE manifest_id=?', (manifest_id,))
        chain.append(db, case_id, 'retention_extended', actor, {'manifest_id': manifest_id, 'before': previous['retain_until'], 'after': retain_until, 'reason': reason})
        return get(db, manifest_id)


def hold(db, hold_id, manifest_id, actor, reason):
    key(hold_id)
    actors.require(db, actor, {'custodian', 'administrator'})
    reason = text(reason)
    with db.transaction():
        assert_available(db, manifest_id)
        prior = db.one('SELECT * FROM holds WHERE hold_id=?', (hold_id,))
        if prior:
            if (prior['manifest_id'], prior['actor'], prior['reason']) != (manifest_id, actor, reason):
                fail('hold_conflict', 'Hold identifier binds another request')
            return prior
        db.execute("INSERT INTO holds VALUES(?,?,'active',?,?,?,NULL)", (hold_id, manifest_id, reason, actor, db.clock()))
        db.execute('UPDATE retention SET revision=revision+1 WHERE manifest_id=?', (manifest_id,))
        case_id = db.scalar('SELECT case_id FROM manifests WHERE manifest_id=?', (manifest_id,))
        chain.append(db, case_id, 'hold_placed', actor, {'hold_id': hold_id, 'manifest_id': manifest_id, 'reason': reason})
        return db.one('SELECT * FROM holds WHERE hold_id=?', (hold_id,))


def release(db, hold_id, actor, reason):
    actors.require(db, actor, {'administrator'})
    reason = text(reason)
    with db.transaction():
        row = db.one('SELECT * FROM holds WHERE hold_id=?', (hold_id,))
        if row is None:
            fail('hold_missing', 'Retention hold does not exist')
        if row['state'] == 'released':
            return row
        if row['actor'] == actor:
            fail('hold_separation', 'Hold originator cannot release own hold')
        db.execute("UPDATE holds SET state='released',released_at=? WHERE hold_id=?", (db.clock(), hold_id))
        db.execute('UPDATE retention SET revision=revision+1 WHERE manifest_id=?', (row['manifest_id'],))
        case_id = db.scalar('SELECT case_id FROM manifests WHERE manifest_id=?', (row['manifest_id'],))
        chain.append(db, case_id, 'hold_released', actor, {'hold_id': hold_id, 'manifest_id': row['manifest_id'], 'reason': reason})
        return db.one('SELECT * FROM holds WHERE hold_id=?', (hold_id,))


def dispose(db, manifest_id, expected_revision, actor, reason):
    actors.require(db, actor, {'administrator'})
    reason = text(reason)
    with db.transaction():
        policy = get(db, manifest_id)
        if policy['revision'] != expected_revision:
            fail('retention_stale', 'Retention revision changed')
        if not policy['eligible']:
            fail('retention_protected', 'Retention deadline or active hold prevents disposal')
        db.execute("UPDATE retention SET state='disposed',revision=revision+1,reason=? WHERE manifest_id=?", (reason, manifest_id))
        case_id = db.scalar('SELECT case_id FROM manifests WHERE manifest_id=?', (manifest_id,))
        chain.append(db, case_id, 'disposed', actor, {'manifest_id': manifest_id, 'reason': reason, 'retain_until': policy['retain_until']})
        return get(db, manifest_id)


def references(db, identity):
    result = []
    for row in db.all("SELECT e.case_id,e.path FROM entries e JOIN cases c ON c.case_id=e.case_id WHERE e.digest=? AND c.state='draft' ORDER BY e.case_id,e.path", (identity,)):
        result.append({'kind': 'draft', **row})
    for row in db.all("SELECT m.manifest_id,m.state,r.state AS retention_state FROM manifest_objects o JOIN manifests m ON m.manifest_id=o.manifest_id LEFT JOIN retention r ON r.manifest_id=m.manifest_id WHERE o.digest=? ORDER BY m.manifest_id", (identity,)):
        if row['state'] == 'prepared' or row['state'] == 'sealed' and row['retention_state'] == 'active':
            result.append({'kind': 'manifest', **row})
    for row in db.all('SELECT pin_id,owner,expires_at FROM pins WHERE digest=? AND expires_at>? ORDER BY pin_id', (identity, db.clock())):
        result.append({'kind': 'pin', **row})
    for row in db.all("SELECT session_id,owner,expires_at FROM staging WHERE expected_digest=? AND state='receiving' AND expires_at>? ORDER BY session_id", (identity, db.clock())):
        result.append({'kind': 'staging', **row})
    from sealvault.retention.replicas import references as replica_references
    result.extend(replica_references(db, identity))
    return result


def inventory(db):
    result = []
    for row in db.all('SELECT manifest_id FROM retention ORDER BY manifest_id'):
        result.append(get(db, row['manifest_id']))
    return {'policies': result, 'eligible': [row['manifest_id'] for row in result if row['eligible']], 'held': [row['manifest_id'] for row in result if row['holds']]}
