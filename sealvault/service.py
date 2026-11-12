import inspect
from sealvault.database import Database
from sealvault.codec import fields, fail, VaultError
from sealvault.objects import Objects
from sealvault.custody import actors, chain, seals
from sealvault.custody.cases import Cases
from sealvault.custody.seals import Seals
from sealvault.custody.handoffs import Handoffs
from sealvault.retention import policy
from sealvault.retention.collector import Collector
from sealvault.transfer.staging import Staging
from sealvault.transfer.packages import Packages
from sealvault.inspect import checks, compare, semantic
from sealvault.inspect.repairs import Repairs
from sealvault.retention.schedules import Schedules
from sealvault import quotas
from sealvault.custody.checkpoints import Checkpoints
from sealvault.transfer import directories
from sealvault.inspect.catalog import Catalog
from sealvault.retention.disposal import DisposalDesk
from sealvault.custody.accessions import Accessions
from sealvault.custody.attestations import Attestations
from sealvault.transfer import recovery, archive
from sealvault.inspect.scrub import Scrubber
from sealvault.retention.replicas import ReplicaPolicies
from sealvault.transfer.disclosure import Disclosures


class Vault:
    def __init__(self, filename=':memory:', clock=None):
        self.db = Database(filename, **({'clock': clock} if clock else {}))
        self.objects = Objects(self.db)
        self.cases = Cases(self.db)
        self.seals = Seals(self.db)
        self.handoffs = Handoffs(self.db)
        self.collector = Collector(self.db)
        self.staging = Staging(self.db)
        self.packages = Packages(self.db)
        self.scrubber = Scrubber(self.db)
        self.replica_policies = ReplicaPolicies(self.db)
        self.disclosures = Disclosures(self.db)
        self.catalog = Catalog(self.db)
        self.disposal = DisposalDesk(self.db)
        self.accessions = Accessions(self.db)
        self.attestations = Attestations(self.db)
        self.repairs = Repairs(self.db)
        self.schedules = Schedules(self.db)
        quotas.initialize(self.db)
        self.checkpoints = Checkpoints(self.db)
        self.routes = {}
        for prefix, service in {'object': self.objects, 'case': self.cases, 'seal': self.seals, 'handoff': self.handoffs, 'gc': self.collector, 'stage': self.staging, 'package': self.packages, 'scrub': self.scrubber, 'replica_policy': self.replica_policies, 'disclosure': self.disclosures, 'catalog': self.catalog, 'disposal': self.disposal, 'accession': self.accessions, 'attestation': self.attestations, 'repair': self.repairs, 'schedule': self.schedules, 'checkpoint': self.checkpoints}.items():
            for name, function in inspect.getmembers(service, inspect.ismethod):
                if name.startswith('_') or name in {'read', 'put', 'repair', 'editable'}:
                    continue
                self.routes[prefix + '.' + name] = (function, False)
        for prefix, module in {'actor': actors, 'custody': chain, 'retention': policy, 'check': checks, 'compare': compare, 'semantic': semantic, 'recovery': recovery, 'quota': quotas, 'directory': directories}.items():
            for name, function in inspect.getmembers(module, inspect.isfunction):
                parameters = list(inspect.signature(function).parameters)
                if function.__module__ == module.__name__ and parameters and parameters[0] == 'db' and name not in {'append', 'assert_available', 'require', 'initialize', 'object_capacity', 'stage_capacity'}:
                    self.routes[prefix + '.' + name] = (function, True)

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, kind, value, traceback):
        self.close()

    def commands(self):
        result = []
        for name, (function, needs_db) in sorted(self.routes.items()):
            parameters = list(inspect.signature(function).parameters.values())[int(needs_db):]
            result.append({'operation': name, 'required': [p.name for p in parameters if p.default is inspect.Parameter.empty], 'optional': [p.name for p in parameters if p.default is not inspect.Parameter.empty]})
        return result

    def execute(self, request):
        fields(request, {'operation'}, {'arguments', 'request_id'})
        name = request['operation']
        if not isinstance(name, str) or name not in self.routes:
            fail('operation', 'Unknown vault operation')
        function, needs_db = self.routes[name]
        args = request.get('arguments', {})
        if not isinstance(args, dict):
            fail('arguments', 'Operation arguments must be an object')
        positional = [self.db] if needs_db else []
        try:
            inspect.signature(function).bind(*positional, **args)
        except TypeError as exc:
            raise VaultError('arguments', str(exc)) from exc
        action = lambda: function(*positional, **args)
        if 'request_id' in request:
            return self.db.once(request['request_id'], name, args, action)
        return action()
