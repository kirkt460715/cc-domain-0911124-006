import base64
import datetime
import hashlib
import json
import re
import unicodedata


class VaultError(Exception):
    def __init__(self, code, message, **details):
        super().__init__(message)
        self.code = code
        self.details = details

    def payload(self):
        return {'code': self.code, 'message': str(self), 'details': self.details}


def fail(code, message, **details):
    raise VaultError(code, message, **details)


def fields(value, required, optional=()):
    if not isinstance(value, dict):
        fail('object', 'Expected an object')
    missing = set(required) - set(value)
    extra = set(value) - set(required) - set(optional)
    if missing or extra:
        fail('fields', 'Object schema differs', missing=sorted(missing), extra=sorted(extra))


def key(value):
    if not isinstance(value, str) or not re.fullmatch('[A-Za-z][A-Za-z0-9_.:-]{0,119}', value):
        fail('key', 'Expected bounded symbolic identifier')
    return value


def integer(value, name='integer', low=0, high=1000000000):
    if type(value) is not int or not low <= value <= high:
        fail('integer', 'Integer outside supported range', field=name, minimum=low, maximum=high)
    return value


def text(value, maximum=2000):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        fail('text', 'Expected bounded nonempty text')
    return value.strip()


def timestamp(value):
    if not isinstance(value, str):
        fail('timestamp', 'Timestamp must be a string')
    try:
        parsed = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        fail('timestamp', 'Malformed timestamp')
    if parsed.tzinfo is None:
        fail('timestamp', 'Timestamp requires timezone')
    return parsed.astimezone(datetime.timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def after(value, seconds):
    integer(seconds, 'seconds', 0, 315360000)
    instant = datetime.datetime.fromisoformat(timestamp(value).replace('Z', '+00:00'))
    return timestamp((instant + datetime.timedelta(seconds=seconds)).isoformat())


def canonical(value):
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)
    except (ValueError, TypeError, RecursionError) as exc:
        raise VaultError('json', 'Value cannot be encoded as canonical JSON') from exc


def loads(value):
    def pairs(items):
        result = {}
        for name, item in items:
            if name in result:
                fail('duplicate_key', 'JSON contains duplicate keys')
            result[name] = item
        return result
    try:
        return json.loads(value, object_pairs_hook=pairs, parse_constant=lambda _: fail('nonfinite', 'Nonfinite JSON is forbidden'))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise VaultError('json_decode', 'Cannot decode JSON') from exc


def sha256(content):
    return hashlib.sha256(content).hexdigest()


def digest(value):
    return sha256(canonical(value).encode('utf-8'))


def checksum(value):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value):
        fail('checksum', 'Expected lowercase SHA-256 digest')
    return value


def path(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 500:
        fail('path', 'Evidence path must be bounded nonempty text')
    if unicodedata.normalize('NFC', value) != value:
        fail('path_normalization', 'Evidence paths must use NFC normalization')
    if value.startswith('/') or chr(92) in value or any(ord(c) < 32 for c in value):
        fail('path', 'Evidence path must be relative and contain no controls')
    parts = value.split('/')
    if any(part in {'', '.', '..'} for part in parts):
        fail('path', 'Evidence path contains unsafe segments')
    if any(len(part.encode()) > 255 or ':' in part for part in parts):
        fail('path', 'Evidence path segment exceeds portable limits')
    return value


def media_type(value):
    if not isinstance(value, str) or not re.fullmatch(r'[a-z0-9][a-z0-9.+-]*/[a-z0-9][a-z0-9.+-]*', value):
        fail('media_type', 'Expected lowercase media type without parameters')
    return value


def encode(content):
    return base64.b64encode(content).decode('ascii')


def decode(value, maximum=16777216):
    if not isinstance(value, str) or len(value) > ((maximum + 2) // 3) * 4:
        fail('base64', 'Encoded object exceeds supported size')
    try:
        result = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise VaultError('base64', 'Invalid base64 content') from exc
    if len(result) > maximum or encode(result) != value:
        fail('base64', 'Base64 is oversized or noncanonical')
    return result


def envelope(format_name, payload):
    body = {'format': format_name, 'version': 1, 'data': payload}
    return {'payload': body, 'sha256': digest(body)}


def unwrap(value, format_name):
    fields(value, {'payload', 'sha256'})
    if digest(value['payload']) != value['sha256']:
        fail('envelope_digest', 'Envelope checksum differs')
    fields(value['payload'], {'format', 'version', 'data'})
    if value['payload']['format'] != format_name or value['payload']['version'] != 1:
        fail('envelope_format', 'Unsupported envelope format')
    return value['payload']['data']
