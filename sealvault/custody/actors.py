from sealvault.codec import key, text, fail

ROLES = {'collector', 'custodian', 'auditor', 'administrator'}


def register(db, actor_id, role):
    key(actor_id)
    if role not in ROLES:
        fail('actor_role', 'Unknown custody role')
    with db.transaction():
        previous = db.one('SELECT * FROM actors WHERE actor_id=?', (actor_id,))
        if previous:
            if previous['role'] != role:
                fail('actor_conflict', 'Actor identifier already has another role')
            return previous
        db.execute("INSERT INTO actors VALUES(?,?,'active')", (actor_id, role))
        db.log('actor.registered', {'actor_id': actor_id, 'role': role})
        return get(db, actor_id)


def get(db, actor_id):
    row = db.one('SELECT * FROM actors WHERE actor_id=?', (actor_id,))
    if row is None:
        fail('actor_missing', 'Actor is unknown')
    return row


def require(db, actor_id, roles=None):
    row = get(db, actor_id)
    if row['state'] != 'active' or roles is not None and row['role'] not in set(roles):
        fail('actor_permission', 'Actor lacks required active role')
    return row


def suspend(db, actor_id, administrator, reason):
    require(db, administrator, {'administrator'})
    reason = text(reason)
    if actor_id == administrator:
        fail('actor_self', 'Administrator cannot suspend own identity')
    with db.transaction():
        row = get(db, actor_id)
        db.execute("UPDATE actors SET state='suspended' WHERE actor_id=?", (actor_id,))
        db.log('actor.suspended', {'actor_id': actor_id, 'administrator': administrator, 'reason': reason})
        return get(db, actor_id)


def restore(db, actor_id, administrator, reason):
    require(db, administrator, {'administrator'})
    reason = text(reason)
    with db.transaction():
        get(db, actor_id)
        db.execute("UPDATE actors SET state='active' WHERE actor_id=?", (actor_id,))
        db.log('actor.restored', {'actor_id': actor_id, 'administrator': administrator, 'reason': reason})
        return get(db, actor_id)
