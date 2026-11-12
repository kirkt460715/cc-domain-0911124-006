import unittest
from sealvault.service import Vault
from sealvault.codec import VaultError, timestamp, sha256
from sealvault.custody import actors


class Clock:
    def __init__(self):
        self.value = timestamp('2026-11-11T00:00:00Z')

    def __call__(self):
        return self.value

    def set(self, value):
        self.value = timestamp(value)


class Case(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.vault = Vault(clock=self.clock)
        self.db = self.vault.db
        for identity, role in [('collector', 'collector'), ('other', 'collector'), ('custodian', 'custodian'), ('reviewer', 'custodian'), ('admin', 'administrator'), ('auditor', 'auditor')]:
            actors.register(self.db, identity, role)

    def tearDown(self):
        self.vault.close()

    def error(self, code, function, *args, **kwargs):
        with self.assertRaises(VaultError) as result:
            function(*args, **kwargs)
        self.assertEqual(result.exception.code, code)
        return result.exception

    def add_case(self, case_id='case-a', contents=None, classification='internal'):
        if contents is None:
            contents = {'records/a.txt': b'alpha', 'records/b.txt': b'beta', 'index.json': b'{}'}
        self.vault.cases.create(case_id, 'Synthetic evidence', 'collector', classification)
        revision = 1
        for path, content in contents.items():
            stored = self.vault.objects.put(content)
            item = {'path': path, 'digest': stored['digest'], 'size': len(content), 'media_type': 'application/octet-stream', 'metadata': {'synthetic': True}}
            self.vault.cases.attach(case_id, revision, 'collector', item)
            revision += 1
        return self.vault.cases.get(case_id)

    def seal(self, manifest_id='seal-a', case_id='case-a', retain_until='2026-12-01T00:00:00Z'):
        case = self.vault.cases.get(case_id)
        self.vault.seals.prepare(manifest_id, case_id, case['revision'], case['owner'])
        return self.vault.seals.seal(manifest_id, 'custodian', retain_until)
