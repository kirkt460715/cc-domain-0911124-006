from sealvault import manifests
from sealvault.codec import fail, digest, envelope, unwrap, fields
from sealvault.custody.seals import Seals


def compare_values(before, after):
    manifests.verify(before)
    manifests.verify(after)
    left = {item['path']: item for item in before['body']['entries']}
    right = {item['path']: item for item in after['body']['entries']}
    added = []
    removed = []
    modified = []
    unchanged = []
    for path in sorted(set(left) | set(right)):
        old = left.get(path)
        new = right.get(path)
        if old is None:
            added.append(new)
        elif new is None:
            removed.append(old)
        elif old == new:
            unchanged.append(path)
        else:
            modified.append({'path': path, 'content_changed': old['digest'] != new['digest'], 'fields': [field for field in sorted(old) if old[field] != new[field]], 'before': old, 'after': new})
    moves = []
    unmatched_add = list(added)
    unmatched_remove = list(removed)
    for old in removed:
        matches = [new for new in unmatched_add if {k: v for k, v in old.items() if k != 'path'} == {k: v for k, v in new.items() if k != 'path'}]
        if len(matches) == 1:
            new = matches[0]
            alternatives = [candidate for candidate in unmatched_remove if candidate['digest'] == old['digest']]
            if len(alternatives) == 1:
                moves.append({'from': old['path'], 'to': new['path'], 'digest': old['digest']})
                unmatched_add.remove(new)
                unmatched_remove.remove(old)
    return {'before_hash': before['sha256'], 'after_hash': after['sha256'], 'added': added, 'removed': removed, 'modified': modified, 'unchanged': unchanged, 'unambiguous_moves': moves, 'total_byte_delta': after['body']['total_bytes'] - before['body']['total_bytes'], 'unique_byte_delta': after['body']['unique_bytes'] - before['body']['unique_bytes']}


def compare(db, before_id, after_id):
    seals = Seals(db)
    before = seals.get(before_id)
    after = seals.get(after_id)
    return {'before_id': before_id, 'after_id': after_id, **compare_values(before['manifest'], after['manifest'])}


def inventory(db, classification=None, path_prefix=None):
    if classification is not None and classification not in {'public', 'internal', 'restricted'}:
        fail('classification', 'Unknown evidence classification')
    result = []
    seals = Seals(db)
    for row in db.all("SELECT manifest_id FROM manifests WHERE state='sealed' ORDER BY manifest_id"):
        manifest = seals.get(row['manifest_id'])
        body = manifest['manifest']['body']
        if classification is not None and body['classification'] != classification:
            continue
        entries = [item for item in body['entries'] if path_prefix is None or item['path'].startswith(path_prefix)]
        if not entries:
            continue
        retained = db.scalar('SELECT state FROM retention WHERE manifest_id=?', (row['manifest_id'],))
        result.append({'manifest_id': row['manifest_id'], 'case_id': body['case_id'], 'classification': body['classification'], 'retention_state': retained, 'body_hash': manifest['body_hash'], 'matched_entries': entries})
    return result


def overlap(db, manifest_ids):
    if not isinstance(manifest_ids, list) or not 2 <= len(manifest_ids) <= 100 or len(set(manifest_ids)) != len(manifest_ids):
        fail('overlap_selection', 'Select two to one hundred distinct manifests')
    seals = Seals(db)
    objects = {}
    logical_bytes = 0
    for identity in manifest_ids:
        manifest = seals.get(identity)
        for entry in manifest['manifest']['body']['entries']:
            logical_bytes += entry['size']
            row = objects.setdefault(entry['digest'], {'digest': entry['digest'], 'size': entry['size'], 'locations': []})
            if row['size'] != entry['size']:
                fail('overlap_size', 'Shared object has inconsistent declared sizes')
            row['locations'].append({'manifest_id': identity, 'path': entry['path']})
    shared = [row for row in objects.values() if len({location['manifest_id'] for location in row['locations']}) > 1]
    unique_bytes = sum(row['size'] for row in objects.values())
    return {'manifests': manifest_ids, 'logical_bytes': logical_bytes, 'unique_bytes': unique_bytes, 'duplicate_bytes': logical_bytes - unique_bytes, 'shared': sorted(shared, key=lambda row: row['digest'])}
