from sealvault.codec import integer, fail, text
from sealvault.custody import actors


def initialize(db):
    db.execute('CREATE TABLE IF NOT EXISTS storage_limits(singleton INTEGER PRIMARY KEY CHECK(singleton=1),revision INTEGER NOT NULL,max_bytes INTEGER NOT NULL,max_objects INTEGER NOT NULL,max_staging_bytes INTEGER NOT NULL)')


def usage(db):
    objects = db.one('SELECT COUNT(*) AS objects,COALESCE(SUM(size),0) AS bytes FROM objects')
    staging = db.scalar("SELECT COALESCE(SUM(total_size),0) FROM staging WHERE state='receiving' AND expires_at>?", (db.clock(),))
    return {**objects, 'reserved_staging_bytes': staging}


def get(db):
    table = db.one("SELECT name FROM sqlite_master WHERE name='storage_limits'")
    row = db.one('SELECT * FROM storage_limits WHERE singleton=1') if table else None
    return {'limits': row, 'usage': usage(db)}


def configure(db, expected_revision, max_bytes, max_objects, max_staging_bytes, actor, reason):
    actors.require(db, actor, {'administrator'})
    integer(max_bytes, 'max_bytes', 0, 10**12)
    integer(max_objects, 'max_objects', 0, 10000000)
    integer(max_staging_bytes, 'max_staging_bytes', 0, 10**12)
    reason = text(reason)
    initialize(db)
    with db.transaction():
        prior = get(db)
        revision = prior['limits']['revision'] if prior['limits'] else 0
        if revision != expected_revision:
            fail('quota_revision', 'Storage quota revision changed')
        current = prior['usage']
        if max_bytes < current['bytes'] or max_objects < current['objects'] or max_staging_bytes < current['reserved_staging_bytes']:
            fail('quota_below_usage', 'Quota cannot be set below current usage or active reservations')
        db.execute('INSERT INTO storage_limits VALUES(1,?,?,?,?) ON CONFLICT(singleton) DO UPDATE SET revision=excluded.revision,max_bytes=excluded.max_bytes,max_objects=excluded.max_objects,max_staging_bytes=excluded.max_staging_bytes', (revision + 1, max_bytes, max_objects, max_staging_bytes))
        db.log('quota.configured', {'revision': revision + 1, 'actor': actor, 'reason': reason})
        return get(db)


def object_capacity(db, additional_bytes):
    report = get(db)
    limits = report['limits']
    if limits is None:
        return
    current = report['usage']
    if current['objects'] + 1 > limits['max_objects'] or current['bytes'] + additional_bytes > limits['max_bytes']:
        fail('quota_objects', 'New object would exceed physical storage quota')


def stage_capacity(db, additional_bytes):
    report = get(db)
    if report['limits'] is not None and report['usage']['reserved_staging_bytes'] + additional_bytes > report['limits']['max_staging_bytes']:
        fail('quota_staging', 'Staging reservation would exceed quota')
