from sealvault.codec import canonical, digest, loads, fail, integer, envelope, unwrap, fields, timestamp
from sealvault.custody import actors


def append(db, case_id, action, actor, body):
    actors.require(db, actor)
    head = db.one('SELECT sequence,entry_hash,at FROM custody WHERE case_id=? ORDER BY sequence DESC LIMIT 1', (case_id,))
    sequence = head['sequence'] + 1 if head else 1
    previous = head['entry_hash'] if head else '0' * 64
    at = timestamp(db.clock())
    if head and at < head['at']:
        fail('custody_clock', 'Custody clock moved backwards')
    content = canonical(body)
    identity = digest([case_id, sequence, previous, action, actor, content, at])
    db.execute('INSERT INTO custody(case_id,sequence,action,actor,body,previous_hash,entry_hash,at) VALUES(?,?,?,?,?,?,?,?)', (case_id, sequence, action, actor, content, previous, identity, at))
    db.log('custody.appended', {'case_id': case_id, 'sequence': sequence, 'entry_hash': identity})
    return {'case_id': case_id, 'sequence': sequence, 'entry_hash': identity}


def history(db, case_id, after=0, limit=1000):
    integer(after, 'after')
    integer(limit, 'limit', 1, 10000)
    rows = db.all('SELECT * FROM custody WHERE case_id=? AND sequence>? ORDER BY sequence LIMIT ?', (case_id, after, limit))
    for row in rows:
        row['body'] = loads(row['body'])
    return rows


def verify_rows(rows, expected_case=None, expected_head=None):
    if not isinstance(rows, list) or not rows:
        fail('custody_empty', 'Custody chain requires at least its creation event')
    previous = '0' * 64
    previous_time = ''
    identity = expected_case or rows[0]['case_id']
    for sequence, row in enumerate(rows, 1):
        fields(row, {'case_id', 'sequence', 'action', 'actor', 'body', 'previous_hash', 'entry_hash', 'at'}, {'position'})
        if row['case_id'] != identity or row['sequence'] != sequence or row['previous_hash'] != previous:
            fail('custody_sequence', 'Custody sequence or predecessor differs', sequence=sequence)
        if timestamp(row['at']) != row['at'] or row['at'] < previous_time:
            fail('custody_time', 'Custody time is noncanonical or decreasing')
        computed = digest([identity, sequence, previous, row['action'], row['actor'], canonical(row['body']), row['at']])
        if computed != row['entry_hash']:
            fail('custody_digest', 'Custody event checksum differs', sequence=sequence)
        previous = computed
        previous_time = row['at']
    if expected_head is not None and expected_head != previous:
        fail('custody_head', 'Custody chain does not reach expected head')
    return {'valid': True, 'case_id': identity, 'count': len(rows), 'head': previous, 'authentication': 'local_hash_chain_only'}


def verify(db, case_id):
    rows = history(db, case_id, limit=10000)
    count = db.scalar('SELECT COUNT(*) FROM custody WHERE case_id=?', (case_id,))
    if count > 10000:
        fail('custody_limit', 'Use a bounded archival checkpoint before exceeding chain capacity')
    return verify_rows(rows, case_id)


def export(db, case_id):
    verified = verify(db, case_id)
    return envelope('sealvault-custody', {'case_id': case_id, 'events': history(db, case_id, limit=10000), 'head': verified['head']})


def verify_export(value):
    data = unwrap(value, 'sealvault-custody')
    fields(data, {'case_id', 'events', 'head'})
    return verify_rows(data['events'], data['case_id'], data['head'])
