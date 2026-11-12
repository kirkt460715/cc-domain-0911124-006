import io
import tarfile
import tempfile
from pathlib import Path
from tests.support import Case
from sealvault.transfer import archive, directories, disclosure
from sealvault.codec import sha256, canonical, digest, encode
from sealvault.service import Vault
from sealvault.custody import actors
from sealvault.inspect import checks, semantic


class ArchiveBoundaries(Case):
    def test_deterministic_tar_and_verified_object_import(self):
        self.add_case()
        self.seal()
        first = archive.create(self.db, 'seal-a')
        second = archive.create(self.db, 'seal-a')
        self.assertEqual(first, second)
        result = archive.verify(first)
        self.assertTrue(result['valid'])
        self.assertEqual(result['objects'], 3)
        self.assertEqual(result['bytes'], 11)
        with Vault() as destination:
            actors.register(destination.db, 'collector', 'collector')
            imported = archive.import_objects(destination.db, first, 'collector')
            self.assertEqual(len(imported['created']), 3)
            self.assertFalse(imported['replica_registered'])
            repeated = archive.import_objects(destination.db, first, 'collector')
            self.assertEqual(len(repeated['duplicates']), 3)
            self.assertEqual(destination.objects.read(sha256(b'alpha')), b'alpha')

    def malicious_tar(self, name, kind=tarfile.REGTYPE, content=b'x'):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w') as target:
            item = tarfile.TarInfo(name)
            item.type = kind
            item.size = len(content) if kind == tarfile.REGTYPE else 0
            if kind == tarfile.SYMTYPE:
                item.linkname = '/outside'
            target.addfile(item, io.BytesIO(content) if item.size else None)
        return buffer.getvalue()

    def test_tar_traversal_links_and_unknown_members_rejected(self):
        self.error('archive_path', archive.inspect_bytes, self.malicious_tar('../escape'))
        self.error('archive_path', archive.inspect_bytes, self.malicious_tar('/absolute'))
        self.error('archive_member_type', archive.inspect_bytes, self.malicious_tar('objects/link', tarfile.SYMTYPE))
        self.error('archive_member_type', archive.inspect_bytes, self.malicious_tar('directory', tarfile.DIRTYPE))
        self.error('archive_path', archive.inspect_bytes, self.malicious_tar('unexpected.txt'))
        self.error('archive_decode', archive.inspect_bytes, b'not a tar')
        self.assertEqual(self.db.scalar('SELECT COUNT(*) FROM objects'), 0)
        self.assertEqual(self.db.scalar('SELECT COUNT(*) FROM replicas'), 0)

    def test_tar_duplicate_members_rejected(self):
        self.add_case()
        self.seal()
        evidence = canonical(self.vault.seals.export('seal-a')).encode()
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w') as target:
            for _ in range(2):
                info = tarfile.TarInfo('seal.json')
                info.size = len(evidence)
                target.addfile(info, io.BytesIO(evidence))
        self.error('archive_duplicate', archive.inspect_bytes, buffer.getvalue())
        self.assertEqual(self.db.scalar('SELECT COUNT(*) FROM objects'), 3)
        self.assertTrue(checks.run(self.db)['ok'])

    def test_archive_export_refuses_existing_destination(self):
        self.add_case()
        self.seal()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'evidence.tar'
            first = archive.export_file(self.db, 'seal-a', output)
            self.assertEqual(first['sha256'], sha256(output.read_bytes()))
            with self.assertRaises(FileExistsError):
                archive.export_file(self.db, 'seal-a', output)
            self.assertEqual(archive.verify(archive.read_file(output))['manifest_id'], 'seal-a')
            self.assertGreater(output.stat().st_size, 0)
            selected = archive.extract_selected(self.db, 'seal-a', 'index.json')
            self.assertEqual(selected['object']['base64'], encode(b'{}'))
            self.error('archive_selection', archive.extract_selected, self.db, 'seal-a', 'absent')

    def test_directory_intake_transaction_and_export(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / 'source'
            source.mkdir()
            (source / 'nested').mkdir()
            (source / 'nested/a').write_bytes(b'alpha')
            (source / 'b').write_bytes(b'beta')
            self.vault.cases.create('case-a', 'Directory intake', 'collector')
            result = directories.ingest(self.db, source, 'case-a', 1, 'collector')
            self.assertEqual(result['bytes'], 9)
            self.assertEqual(result['revision'], 3)
            self.assertEqual([row['path'] for row in result['entries']], ['b', 'nested/a'])
            self.seal()
            destination = Path(temporary) / 'restored'
            exported = directories.export(self.db, 'seal-a', destination)
            self.assertEqual(exported['paths'], ['b', 'nested/a'])
            self.assertEqual((destination / 'nested/a').read_bytes(), b'alpha')
            self.assertEqual((destination / 'b').read_bytes(), b'beta')
            self.error('directory_destination', directories.export, self.db, 'seal-a', destination)
            self.assertTrue(semantic.verify_database(self.db)['valid'])

    def test_directory_symlink_and_changed_file_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / 'source'
            source.mkdir()
            actual = source / 'a'
            actual.write_bytes(b'alpha')
            snapshot = directories.inventory(source)
            actual.write_bytes(b'changed')
            self.error('directory_changed', directories.read_relative, str(source), snapshot['files'][0])
            link = source / 'link'
            link.symlink_to(actual)
            self.error('directory_type', directories.inventory, source)
            link.unlink()
            folder = source / 'folder'
            folder.symlink_to(source, target_is_directory=True)
            self.error('directory_symlink', directories.inventory, source)
            self.assertEqual(self.db.scalar('SELECT COUNT(*) FROM objects'), 0)

    def test_disclosure_tampered_bytes_rejected_even_rehashed(self):
        self.add_case()
        sealed = self.seal()
        proposed = self.vault.disclosures.propose('share', 'seal-a', ['index.json'], 'recipient', '2026-12-01T00:00:00Z', 'custodian', 'share')
        self.vault.disclosures.approve('share', 'reviewer', proposed['digest'])
        content = self.vault.disclosures.export('share', 'recipient')
        content['payload']['data']['items'][0]['object']['base64'] = encode(b'xx')
        content['sha256'] = digest(content['payload'])
        self.error('disclosure_bytes', disclosure.verify, content, sealed['merkle_root'])
        proof_only = self.vault.disclosures.export('share', 'recipient', False)
        self.assertNotIn('object', proof_only['payload']['data']['items'][0])
        self.assertTrue(disclosure.verify(proof_only, sealed['merkle_root'])['valid'])
        self.assertEqual(self.vault.objects.read(sha256(b'{}')), b'{}')
