"""Small validator for exactly the schema vocabulary bundled in this package.

This is a package consistency check, not a general-purpose JSON Schema library.
Production config validation also requires the documented cross-field checks.
"""
import ipaddress
import json
import re


class SchemaError(ValueError):
    pass


def check(value, schema, root=None, path='$'):
    root = root or schema
    if '$ref' in schema:
        node = root
        ref = schema['$ref']
        if not ref.startswith('#/'):
            raise SchemaError('Only local schema references are supported.')
        for key in ref[2:].split('/'):
            node = node[key.replace('~1', '/').replace('~0', '~')]
        return check(value, node, root, path)
    kind = schema.get('type')
    good = {
        'object': lambda: isinstance(value, dict),
        'array': lambda: isinstance(value, list),
        'string': lambda: isinstance(value, str),
        'integer': lambda: isinstance(value, int) and not isinstance(value, bool),
        'boolean': lambda: isinstance(value, bool),
        'null': lambda: value is None,
    }
    if isinstance(kind, list):
        if not any(k in good and good[k]() for k in kind):
            raise SchemaError(f'{path}: expected one of {kind}')
    elif kind and (kind not in good or not good[kind]()):
        raise SchemaError(f'{path}: expected {kind}')
    if 'const' in schema and (type(value) is not type(schema['const']) or value != schema['const']):
        raise SchemaError(f'{path}: incorrect constant')
    if 'enum' in schema and value not in schema['enum']:
        raise SchemaError(f'{path}: not an allowed value')
    if isinstance(value, dict):
        properties = schema.get('properties', {})
        for required in schema.get('required', []):
            if required not in value:
                raise SchemaError(f'{path}: missing {required}')
        if schema.get('additionalProperties') is False and set(value) - set(properties):
            raise SchemaError(f'{path}: unknown property')
        for key, child in value.items():
            if key in properties:
                check(child, properties[key], root, path + '.' + key)
    if isinstance(value, list):
        if len(value) < schema.get('minItems', 0) or len(value) > schema.get('maxItems', float('inf')):
            raise SchemaError(f'{path}: incorrect item count')
        if schema.get('uniqueItems') and len({json.dumps(x, sort_keys=True) for x in value}) != len(value):
            raise SchemaError(f'{path}: duplicate item')
        for index, item in enumerate(value):
            if 'items' in schema:
                check(item, schema['items'], root, f'{path}[{index}]')
    if isinstance(value, str):
        if len(value) < schema.get('minLength', 0) or len(value) > schema.get('maxLength', float('inf')):
            raise SchemaError(f'{path}: incorrect string length')
        if 'pattern' in schema and not re.search(schema['pattern'], value):
            raise SchemaError(f'{path}: incorrect format')
        if schema.get('format') == 'ipv4':
            try:
                ipaddress.IPv4Address(value)
            except ValueError:
                raise SchemaError(f'{path}: incorrect IPv4 address') from None
    if isinstance(value, int) and not isinstance(value, bool):
        if value < schema.get('minimum', -float('inf')) or value > schema.get('maximum', float('inf')):
            raise SchemaError(f'{path}: outside allowed range')


def check_config_cross_fields(config, contract):
    tunnels = {t['id']: t for t in config['tunnels']}
    if len(tunnels) != len(config['tunnels']):
        raise SchemaError('Duplicate tunnel ID.')
    pairs = set()
    subnets = []
    for tunnel in tunnels.values():
        identity = contract.pair_identity(tunnel['local_ip'], tunnel['peer_ip'])
        if identity['pair_id'] != tunnel['pair_id'] or identity['key'] != tunnel['key']:
            raise SchemaError('Inconsistent pair identity.')
        if tunnel['pair_id'] in pairs:
            raise SchemaError('Duplicate outer pair.')
        pairs.add(tunnel['pair_id'])
        contract.inside_addresses(tunnel['inside_cidr'], tunnel['local_ip'], tunnel['peer_ip'])
        network = ipaddress.IPv4Network(tunnel['inside_cidr'])
        if any(network.overlaps(old) for old in subnets):
            raise SchemaError('Inside subnets overlap.')
        subnets.append(network)
    forward_ids, reservations = set(), set()
    for forward in config['forwards']:
        if forward['id'] in forward_ids or forward['tunnel_id'] not in tunnels:
            raise SchemaError('Invalid forward identity/reference.')
        forward_ids.add(forward['id'])
        protocols = ['tcp', 'udp'] if forward['protocol'] == 'both' else [forward['protocol']]
        for protocol in protocols:
            key = (forward['listen_ip'], protocol, forward['listen_port'])
            if key in reservations:
                raise SchemaError('Duplicate input reservation.')
            reservations.add(key)
        if any(forward['target_ip'] == t['local_ip'] for t in tunnels.values()):
            raise SchemaError('Target is a local outer address.')
    if config['next_tunnel_id'] <= max(tunnels, default=0):
        raise SchemaError('Next tunnel ID is not monotonic.')
    if config['next_forward_id'] <= max(forward_ids, default=0):
        raise SchemaError('Next forward ID is not monotonic.')
