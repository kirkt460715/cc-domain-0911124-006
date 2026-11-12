from sealvault.codec import fail, canonical, digest
from sealvault.custody import chain
from sealvault.custody.cases import Cases
from sealvault.custody.seals import Seals


def replay_case(db, case_id):
    chain.verify(db, case_id)
    events = chain.history(db, case_id, limit=10000)
    entries = {}
    owner = None
    classification = None
    state = 'draft'
    seal_id = None
    problems = []
    for event in events:
        action = event['action']
        body = event['body']
        actor = event['actor']
        if action == 'created':
            if owner is not None:
                problems.append({'code': 'duplicate_creation', 'sequence': event['sequence']})
            owner = actor
            classification = body['classification']
        elif action in {'entry_attached', 'entry_replaced'}:
            value = body['after']
            before = body['before']
            if state != 'draft' or actor != owner or entries.get(value['path']) != before:
                problems.append({'code': 'entry_predecessor', 'sequence': event['sequence']})
            entries[value['path']] = value
        elif action == 'entry_detached':
            value = body['entry']
            if entries.get(value['path']) != value or state != 'draft' or actor != owner:
                problems.append({'code': 'detach_predecessor', 'sequence': event['sequence']})
            entries.pop(value['path'], None)
        elif action == 'entry_renamed':
            old = entries.pop(body['from'], None)
            if old is None or old['digest'] != body['digest'] or body['to'] in entries:
                problems.append({'code': 'rename_predecessor', 'sequence': event['sequence']})
            else:
                entries[body['to']] = {**old, 'path': body['to']}
        elif action == 'classified':
            if body['from'] != classification:
                problems.append({'code': 'classification_predecessor', 'sequence': event['sequence']})
            classification = body['to']
        elif action == 'handoff_accepted':
            if owner != body['source']:
                problems.append({'code': 'owner_predecessor', 'sequence': event['sequence']})
            owner = actor
        elif action == 'sealed':
            seal = Seals(db).get(body['manifest_id'])
            expected = sorted(entries.values(), key=lambda row: row['path'])
            if state != 'draft' or expected != seal['manifest']['body']['entries'] or classification != seal['manifest']['body']['classification']:
                problems.append({'code': 'seal_projection', 'sequence': event['sequence']})
            state = 'sealed'
            seal_id = body['manifest_id']
            entries = {}
        elif action == 'abandoned':
            if state != 'draft':
                problems.append({'code': 'abandon_state', 'sequence': event['sequence']})
            entries = {}
            state = 'abandoned'
    actual = Cases(db).get(case_id)
    projected = {'owner': owner, 'classification': classification, 'state': state, 'entries': sorted(entries.values(), key=lambda row: row['path'])}
    stored = {field: actual[field] for field in projected}
    if projected != stored:
        problems.append({'code': 'case_projection', 'expected_hash': digest(projected), 'actual_hash': digest(stored)})
    return {'valid': not problems, 'case_id': case_id, 'events': len(events), 'seal_id': seal_id, 'projected': projected, 'problems': problems}


def ancestry(db, manifest_id):
    seals = Seals(db)
    seen = set()
    rows = []
    current = manifest_id
    while current is not None:
        if current in seen:
            fail('ancestry_cycle', 'Manifest ancestry contains a cycle')
        seen.add(current)
        item = seals.get(current)
        rows.append({'manifest_id': current, 'case_id': item['case_id'], 'body_hash': item['body_hash'], 'state': item['state'], 'parent_id': item['parent_id']})
        current = item['parent_id']
        if len(rows) > 1000:
            fail('ancestry_depth', 'Manifest ancestry exceeds supported depth')
    rows.reverse()
    return {'manifest_id': manifest_id, 'ancestors': rows, 'depth': len(rows)}


def verify_database(db):
    results = [replay_case(db, row['case_id']) for row in db.all('SELECT case_id FROM cases ORDER BY case_id')]
    ancestry_results = []
    from sealvault.codec import VaultError
    for row in db.all('SELECT manifest_id FROM manifests ORDER BY manifest_id'):
        try:
            ancestry(db, row['manifest_id'])
        except VaultError as exc:
            ancestry_results.append({'manifest_id': row['manifest_id'], **exc.payload()})
    return {'valid': all(row['valid'] for row in results) and not ancestry_results, 'cases': results, 'ancestry_problems': ancestry_results}
