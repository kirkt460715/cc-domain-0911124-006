from sealvault.codec import sha256, checksum, fail, integer, encode, decode, key, timestamp, text

MAX_OBJECT = 16777216


class Objects:
    def __init__(self, database):
        self.db = database

    def put(self, content, expected_digest=None):
        if not isinstance(content, bytes) or len(content) > MAX_OBJECT:
            fail('object_size', 'Object must be bytes no larger than 16 MiB')
        identity = sha256(content)
        if expected_digest is not None and checksum(expected_digest) != identity:
            fail('object_digest', 'Content does not match declared digest')
        with self.db.transaction():
            existing = self.db.one('SELECT digest,size,state,content FROM objects WHERE digest=?', (identity,))
            if existing:
                if existing['content'] != content or existing['size'] != len(content):
                    fail('object_conflict', 'Existing content-addressed object is inconsistent')
                if existing['state'] != 'available':
                    fail('object_quarantined', 'Quarantined content needs explicit repair')
                return {**self.info(identity), 'duplicate': True}
            from sealvault.quotas import object_capacity
            object_capacity(self.db, len(content))
            at = self.db.clock()
            self.db.execute("INSERT INTO objects VALUES(?,?,?,'available',?,?)", (identity, len(content), content, at, at))
            self.db.log('object.stored', {'digest': identity, 'size': len(content)})
            return {**self.info(identity), 'duplicate': False}

    def put_base64(self, content, expected_digest=None):
        return self.put(decode(content), expected_digest)

    def info(self, identity):
        checksum(identity)
        row = self.db.one('SELECT digest,size,state,created_at,verified_at FROM objects WHERE digest=?', (identity,))
        if row is None:
            fail('object_missing', 'Content-addressed object is absent', digest=identity)
        return row

    def read(self, identity):
        info = self.info(identity)
        if info['state'] != 'available':
            fail('object_quarantined', 'Object is quarantined', digest=identity)
        content = self.db.scalar('SELECT content FROM objects WHERE digest=?', (identity,))
        if len(content) != info['size'] or sha256(content) != identity:
            fail('object_corrupt', 'Object bytes do not match content address', digest=identity)
        return content

    def export(self, identity, offset=0, length=None):
        integer(offset, 'offset', 0, MAX_OBJECT)
        if length is not None:
            integer(length, 'length', 0, MAX_OBJECT)
        content = self.read(identity)
        if offset > len(content):
            fail('object_range', 'Offset exceeds object size')
        end = len(content) if length is None else min(len(content), offset + length)
        selected = content[offset:end]
        return {'digest': identity, 'size': len(content), 'offset': offset, 'length': len(selected), 'range_sha256': sha256(selected), 'base64': encode(selected)}

    def verify(self, identity, quarantine=False):
        if type(quarantine) is not bool:
            fail('object_flag', 'quarantine must be boolean')
        with self.db.transaction():
            info = self.info(identity)
            content = self.db.scalar('SELECT content FROM objects WHERE digest=?', (identity,))
            actual = sha256(content)
            valid = actual == identity and len(content) == info['size']
            if not valid and quarantine:
                self.db.execute("UPDATE objects SET state='quarantined' WHERE digest=?", (identity,))
                self.db.log('object.quarantined', {'digest': identity, 'actual': actual, 'actual_size': len(content)})
            elif valid:
                self.db.execute('UPDATE objects SET verified_at=? WHERE digest=?', (self.db.clock(), identity))
            return {'digest': identity, 'valid': valid, 'actual_digest': actual, 'actual_size': len(content), 'state': self.info(identity)['state']}

    def repair(self, identity, content, reason):
        checksum(identity)
        reason = text(reason)
        if not isinstance(content, bytes) or sha256(content) != identity or len(content) > MAX_OBJECT:
            fail('repair_content', 'Replacement bytes must match original address')
        with self.db.transaction():
            info = self.info(identity)
            if info['state'] != 'quarantined':
                fail('repair_state', 'Only quarantined objects may be repaired')
            if len(content) != info['size']:
                fail('repair_size', 'Replacement length differs from original declaration')
            self.db.execute("UPDATE objects SET content=?,state='available',verified_at=? WHERE digest=?", (content, self.db.clock(), identity))
            self.db.log('object.repaired', {'digest': identity, 'reason': reason})
            return self.info(identity)

    def pin(self, pin_id, identity, owner, expires_at, reason):
        key(pin_id)
        key(owner)
        expires_at = timestamp(expires_at)
        reason = text(reason)
        if expires_at <= self.db.clock():
            fail('pin_expired', 'Pin expiration must be in future')
        with self.db.transaction():
            self.read(identity)
            prior = self.db.one('SELECT * FROM pins WHERE pin_id=?', (pin_id,))
            if prior:
                if (prior['digest'], prior['owner'], prior['expires_at'], prior['reason']) != (identity, owner, expires_at, reason):
                    fail('pin_conflict', 'Pin identifier binds different protection')
                return prior
            self.db.execute('INSERT INTO pins VALUES(?,?,?,?,?)', (pin_id, identity, owner, expires_at, reason))
            self.db.log('object.pinned', {'pin_id': pin_id, 'digest': identity, 'expires_at': expires_at})
            return self.db.one('SELECT * FROM pins WHERE pin_id=?', (pin_id,))

    def unpin(self, pin_id, owner):
        with self.db.transaction():
            pin = self.db.one('SELECT * FROM pins WHERE pin_id=?', (pin_id,))
            if pin is None:
                fail('pin_missing', 'Pin does not exist')
            if pin['owner'] != owner:
                fail('pin_owner', 'Pin owner differs')
            self.db.execute('DELETE FROM pins WHERE pin_id=?', (pin_id,))
            self.db.log('object.unpinned', {'pin_id': pin_id, 'owner': owner})
            return {'pin_id': pin_id, 'removed': True}

    def list(self, after_digest='', limit=100, state=None):
        integer(limit, 'limit', 1, 1000)
        if after_digest:
            checksum(after_digest)
        if state is not None and state not in {'available', 'quarantined'}:
            fail('object_state', 'Unknown object state')
        sql = 'SELECT digest,size,state,created_at,verified_at FROM objects WHERE digest>?'
        args = [after_digest]
        if state:
            sql += ' AND state=?'
            args.append(state)
        args.append(limit)
        return self.db.all(sql + ' ORDER BY digest LIMIT ?', args)
