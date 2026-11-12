from sealvault.codec import fields, key, path, checksum, integer, media_type, canonical, digest, sha256, timestamp, fail


def entry(value):
    fields(value, {'path', 'digest', 'size', 'media_type'}, {'metadata'})
    metadata = value.get('metadata', {})
    if not isinstance(metadata, dict) or len(metadata) > 30:
        fail('metadata', 'Entry metadata must be bounded object')
    for name, item in metadata.items():
        key(name)
        if not isinstance(item, (str, int, bool)) or isinstance(item, str) and len(item) > 500:
            fail('metadata', 'Metadata values require bounded strings or scalar integers/booleans')
    return {'path': path(value['path']), 'digest': checksum(value['digest']), 'size': integer(value['size'], 'size', 0, 16777216), 'media_type': media_type(value['media_type']), 'metadata': dict(sorted(metadata.items()))}


def entries(values):
    if not isinstance(values, list) or not 1 <= len(values) <= 10000:
        fail('manifest_entries', 'Manifest requires one to ten thousand entries')
    normalized = sorted((entry(value) for value in values), key=lambda item: item['path'])
    seen = set()
    folded = {item['path'].casefold() for item in normalized}
    if len(folded) != len(normalized):
        fail('manifest_collision', 'Evidence paths collide, including case-insensitive forms')
    for value in normalized:
        name = value['path']
        pieces = name.split('/')
        for count in range(1, len(pieces)):
            if '/'.join(pieces[:count]).casefold() in folded:
                fail('manifest_prefix', 'Evidence path is both file and directory')
        seen.add(name)
    return normalized


def leaf(value):
    return sha256(bytes([0]) + canonical(entry(value)).encode())


def parent(left, right):
    return sha256(bytes([1]) + bytes.fromhex(checksum(left)) + bytes.fromhex(checksum(right)))


def merkle(values):
    normalized = entries(values)
    level = [leaf(value) for value in normalized]
    while len(level) > 1:
        level = [parent(level[i], level[i + 1] if i + 1 < len(level) else level[i]) for i in range(0, len(level), 2)]
    return level[0]


def build(case_id, revision, values, created_at, classification, parent_id=None):
    key(case_id)
    integer(revision, 'revision', 1)
    if classification not in {'public', 'internal', 'restricted'}:
        fail('classification', 'Unknown evidence classification')
    if parent_id is not None:
        key(parent_id)
    normalized = entries(values)
    body = {'format': 'sealvault-manifest', 'version': 1, 'case_id': case_id, 'case_revision': revision, 'created_at': timestamp(created_at), 'classification': classification, 'parent_id': parent_id, 'entries': normalized, 'merkle_root': merkle(normalized), 'total_bytes': sum(value['size'] for value in normalized), 'unique_bytes': sum({value['digest']: value['size'] for value in normalized}.values())}
    return {'body': body, 'sha256': digest(body)}


def verify(value):
    fields(value, {'body', 'sha256'})
    if digest(value['body']) != value['sha256']:
        fail('manifest_digest', 'Manifest body checksum differs')
    body = value['body']
    fields(body, {'format', 'version', 'case_id', 'case_revision', 'created_at', 'classification', 'parent_id', 'entries', 'merkle_root', 'total_bytes', 'unique_bytes'})
    if body['format'] != 'sealvault-manifest' or body['version'] != 1:
        fail('manifest_format', 'Unsupported manifest format')
    rebuilt = build(body['case_id'], body['case_revision'], body['entries'], body['created_at'], body['classification'], body['parent_id'])
    if rebuilt != value:
        fail('manifest_content', 'Manifest is noncanonical or integrity fields differ')
    sizes = {}
    for item in body['entries']:
        if item['digest'] in sizes and sizes[item['digest']] != item['size']:
            fail('manifest_size', 'One content address declares multiple sizes')
        sizes[item['digest']] = item['size']
    return {'valid': True, 'entry_count': len(body['entries']), 'object_count': len(sizes), 'root': body['merkle_root'], 'authentication': 'unsigned_integrity_only'}


def proof(value, selected_path):
    verify(value)
    values = value['body']['entries']
    index = next((i for i, item in enumerate(values) if item['path'] == selected_path), None)
    if index is None:
        fail('proof_path', 'Requested path is absent from manifest')
    original_index = index
    level = [leaf(item) for item in values]
    siblings = []
    while len(level) > 1:
        neighbor = index - 1 if index % 2 else min(index + 1, len(level) - 1)
        siblings.append({'side': 'left' if index % 2 else 'right', 'digest': level[neighbor]})
        level = [parent(level[i], level[i + 1] if i + 1 < len(level) else level[i]) for i in range(0, len(level), 2)]
        index //= 2
    return {'entry': values[original_index], 'index': original_index, 'count': len(values), 'siblings': siblings, 'root': value['body']['merkle_root'], 'manifest_sha256': value['sha256']}


def verify_proof(value, expected_root):
    fields(value, {'entry', 'index', 'count', 'siblings', 'root', 'manifest_sha256'})
    checksum(expected_root)
    checksum(value['manifest_sha256'])
    count = integer(value['count'], 'count', 1, 10000)
    index = integer(value['index'], 'index', 0, count - 1)
    current = leaf(value['entry'])
    siblings = value['siblings']
    if not isinstance(siblings, list):
        fail('proof_siblings', 'Proof siblings must be a list')
    position = 0
    while count > 1:
        if position >= len(siblings):
            fail('proof_length', 'Proof has too few sibling levels')
        sibling = siblings[position]
        fields(sibling, {'side', 'digest'})
        side = 'left' if index % 2 else 'right'
        if sibling['side'] != side:
            fail('proof_side', 'Sibling direction differs from leaf index')
        if index == count - 1 and count % 2 and sibling['digest'] != current:
            fail('proof_duplicate', 'Odd-width proof must duplicate its last node')
        current = parent(sibling['digest'], current) if side == 'left' else parent(current, sibling['digest'])
        index //= 2
        count = (count + 1) // 2
        position += 1
    if position != len(siblings) or current != expected_root or value['root'] != expected_root:
        fail('proof_root', 'Proof does not reach the expected root')
    return {'valid': True, 'path': value['entry']['path'], 'root': expected_root}
