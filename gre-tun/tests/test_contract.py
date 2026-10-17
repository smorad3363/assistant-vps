import base64
import copy
import hashlib
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'reference'))
import contract as C
from schema_check import check, check_config_cross_fields, SchemaError


def read(name):
    return json.loads((ROOT / name).read_text(encoding='utf-8'))


class PortContract(unittest.TestCase):
    def test_valid_golden_inputs(self):
        for row in read('fixtures/parser/valid.json'):
            with self.subTest(row['input']):
                self.assertEqual(C.parse_ports(row['input']), row['expected'])

    def test_invalid_golden_inputs(self):
        for row in read('fixtures/parser/invalid.json'):
            with self.subTest(row['input']):
                with self.assertRaises(C.ContractError) as caught:
                    C.parse_ports(row['input'])
                self.assertEqual(caught.exception.code, row['error'])

    def test_batch_limit(self):
        self.assertEqual(len(C.parse_ports(','.join(map(str, range(1, 257))))), 256)
        with self.assertRaises(C.ContractError) as caught:
            C.parse_ports(','.join(map(str, range(1, 258))))
        self.assertEqual(caught.exception.code, 'E_PORT_BATCH')

    def test_limits(self):
        for source, current, expected in [('20',0,20),('0',20,0),('Unlimited',20,0),('',17,17),('100000',0,100000)]:
            with self.subTest(source=source):
                self.assertEqual(C.parse_limit(source,current),expected)
        for bad in ['1.5','-1','100001','20 Mbps','۲۰','b']:
            with self.subTest(bad=bad), self.assertRaises(C.ContractError):
                C.parse_limit(bad)


class PeerContract(unittest.TestCase):
    def setUp(self):
        self.payload = read('examples/peer.payload.json')

    def test_pair_is_symmetric(self):
        self.assertEqual(C.pair_identity('192.0.2.10','198.51.100.20'),
                         C.pair_identity('198.51.100.20','192.0.2.10'))

    def test_invalid_peer_addresses(self):
        for first,second in [('192.0.2.10','192.0.2.10'),('0.0.0.0','192.0.2.10'),
                             ('127.0.0.1','192.0.2.10'),('224.1.1.1','192.0.2.10'),
                             ('255.255.255.255','192.0.2.10'),('host.example','192.0.2.10')]:
            with self.subTest(first=first), self.assertRaises(C.ContractError):
                C.pair_identity(first,second)

    def test_candidates_skip_collisions(self):
        original=C.candidate_cidrs('192.0.2.10','198.51.100.20')
        changed=C.candidate_cidrs('192.0.2.10','198.51.100.20',original[:3])
        self.assertEqual(changed[0],original[3])
        self.assertTrue(set(changed).isdisjoint(original[:3]))

    def test_default_route_is_not_address_conflict(self):
        self.assertEqual(C.candidate_cidrs('192.0.2.10','198.51.100.20',['0.0.0.0/0']),
                         C.candidate_cidrs('192.0.2.10','198.51.100.20'))

    def test_inside_assignment_is_reversed(self):
        cidr=self.payload['candidates'][0]
        first=C.inside_addresses(cidr,'192.0.2.10','198.51.100.20')
        second=C.inside_addresses(cidr,'198.51.100.20','192.0.2.10')
        self.assertEqual(first['local_inner'],second['peer_inner'])
        self.assertEqual(first['peer_inner'],second['local_inner'])

    def test_token_matches_frozen_example(self):
        token=(ROOT/'examples/peer.code.txt').read_text().strip()
        self.assertEqual(C.encode_peer(self.payload),token)
        self.assertEqual(C.decode_peer(token),self.payload)

    def test_conflict_token(self):
        payload=read('examples/peer.conflict.json')
        self.assertEqual(C.decode_peer(C.encode_peer(payload)),payload)

    def test_corrupt_or_oversized_token_rejected(self):
        token=C.encode_peer(self.payload)
        for bad in [token[:-1]+('0' if token[-1]!='0' else '1'), 'GT1.'+'A'*9000+'.'+'0'*64,
                    token.replace('GT1.','GT2.',1), '$(touch /tmp/should-not-exist)']:
            with self.subTest(length=len(bad)), self.assertRaises(C.ContractError):
                C.decode_peer(bad)

    def test_duplicate_json_keys_rejected(self):
        raw=b'{"schema_version":1,"schema_version":1}'
        encoded=base64.urlsafe_b64encode(raw).decode().rstrip('=')
        token='GT1.'+encoded+'.'+hashlib.sha256(raw).hexdigest()
        with self.assertRaises(C.ContractError): C.decode_peer(token)

    def test_semantic_token_mismatch_rejected(self):
        for key,value in [('pair_id','0'*16),('key',123),('selected_index',16),('mtu',9000)]:
            payload={**self.payload,key:value}
            with self.subTest(key=key), self.assertRaises(C.ContractError):
                C.encode_peer(payload)


class IdentityContract(unittest.TestCase):
    def test_frozen_resource_names(self):
        self.assertEqual(C.resource_ids(1,2),read('examples/resource_ids.json'))

    def test_masks_isolate_tunnels_and_classes(self):
        first=C.resource_ids(1,1)
        second=C.resource_ids(1,2)
        third=C.resource_ids(2,1)
        self.assertEqual(int(first['mark'],16)&0xfffff000,int(second['mark'],16)&0xfffff000)
        self.assertNotEqual(int(first['mark'],16)&0xfffff000,int(third['mark'],16)&0xfffff000)
        self.assertNotEqual(first['upload_leaf'],'1:')
        self.assertNotEqual(C.resource_ids(1,2)['download_leaf'],'2:')

    def test_no_id_wraparound(self):
        for bad in [0,4096,-1,True]:
            with self.subTest(bad=bad),self.assertRaises(C.ContractError): C.resource_ids(bad,1)
        self.assertLessEqual(len(C.resource_ids(4095,4095)['gre_if']),15)


class StatisticsContract(unittest.TestCase):
    def test_frozen_window_fixtures(self):
        for row in read('fixtures/stats/windows.json'):
            with self.subTest(row['name']):
                self.assertEqual(C.rolling_window(row['samples'],row['now_ms'],row['window_seconds']),row['expected'])

    def test_overlap_rejected(self):
        samples=[{'start_ms':0,'end_ms':1000,'upload_bytes':1,'download_bytes':2},
                 {'start_ms':500,'end_ms':1500,'upload_bytes':1,'download_bytes':2}]
        with self.assertRaises(C.ContractError): C.rolling_window(samples,2000,2)

    def test_bad_interval_rejected(self):
        for start,end,upload in [(1,1,0),(2,1,0),(0,1,-1)]:
            with self.subTest(start=start,end=end),self.assertRaises(C.ContractError):
                C.rolling_window([{'start_ms':start,'end_ms':end,'upload_bytes':upload,'download_bytes':0}],10,1)

    def test_reset_and_epoch_change(self):
        self.assertEqual(C.counter_delta(10,20),10)
        self.assertIsNone(C.counter_delta(20,10))
        self.assertIsNone(C.counter_delta(10,20,False))

    def test_current_speed(self):
        self.assertEqual(C.current_mbps(0,2500000,2000),'10.00')
        self.assertIsNone(C.current_mbps(0,1,500))
        self.assertIsNone(C.current_mbps(10,0,2000))

    def test_decimal_display(self):
        cases=[(None,'N/A'),(0,'0.00 MB'),(1000000,'1.00 MB'),
               (1000000000,'1.00 GB'),(1350000000,'1.35 GB'),(1235000,'1.24 MB')]
        for value,expected in cases:
            with self.subTest(value=value): self.assertEqual(C.format_volume(value),expected)

    def test_database_survives_reopen(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'stats.sqlite3'
            db=sqlite3.connect(path)
            db.executescript((ROOT/'reference/schema.sql').read_text())
            db.execute('INSERT INTO forward_history VALUES (1,1,1,0,NULL,?)',('{}',))
            db.execute('INSERT INTO samples VALUES (1,1,1,?,?,0,60000,100,200)',('epoch-1','boot-1'))
            db.commit(); db.close()
            db=sqlite3.connect(path)
            self.assertEqual(db.execute('SELECT upload_bytes,download_bytes FROM samples').fetchone(),(100,200))
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute('INSERT INTO samples VALUES (1,1,1,?,?,0,60000,100,200)',('epoch-1','boot-1'))
            db.close()


class PackageContract(unittest.TestCase):
    def test_ui_golden_menus(self):
        for name in read('contracts/menus.json'):
            with self.subTest(name=name):
                self.assertEqual(C.render_menu(name), (ROOT/f'fixtures/ui/{name}.txt').read_text())
        for name in ['tunnel','port']:
            self.assertEqual(C.render_menu(name,False),(ROOT/f'fixtures/ui/{name}_disabled.txt').read_text())

    def test_main_menu_has_exactly_four_actions(self):
        menu=read('contracts/menus.json')['main']
        self.assertEqual([row['key'] for row in menu['items']],['1','2','3','4'])
        self.assertEqual(C.render_menu('main'),
            'GRE Tunnel Manager\n\n1) Create tunnel\n2) Manage tunnels and ports\n3) Test connection\n4) Uninstall\n\n0) Exit\n\nSelect:\n')

    def test_application_strings_are_ascii(self):
        for path in [ROOT/'contracts/ui.en.json',ROOT/'contracts/error_codes.json']:
            for ch in path.read_text(): self.assertLess(ord(ch),128)
        for value in read('contracts/ui.en.json').values(): value.encode('ascii')

    def test_examples_validate_against_schemas(self):
        schema=read('schemas/config.schema.json')
        for name in ['config.entry.json','config.peer.json','config.empty.json']:
            config=read('examples/'+name)
            check(config,schema); check_config_cross_fields(config,C)
        for name in ['peer.payload.json','peer.conflict.json']:
            payload=read('examples/'+name)
            check(payload,read('schemas/peer.schema.json')); C.validate_peer(payload)

    def test_disabled_forward_still_reserves_tuple(self):
        config=read('examples/config.entry.json')
        duplicate=copy.deepcopy(config['forwards'][0])
        duplicate.update(id=4,enabled=False)
        config['forwards'].append(duplicate); config['next_forward_id']=5
        with self.assertRaises(SchemaError): check_config_cross_fields(config,C)

    def test_schema_rejects_bool_as_id(self):
        config=read('examples/config.entry.json')
        config['tunnels'][0]['id']=True
        with self.assertRaises(SchemaError): check(config,read('schemas/config.schema.json'))

    def test_unknown_config_key_rejected(self):
        config=read('examples/config.entry.json'); config['execute_shell']='anything'
        with self.assertRaises(SchemaError): check(config,read('schemas/config.schema.json'))

    def test_statistics_schema_and_windows(self):
        value=read('examples/stats.forward.json')
        check(value,read('schemas/stats.schema.json'))
        self.assertEqual(value['last_1h']['window_seconds'],3600)
        self.assertEqual(value['last_24h']['window_seconds'],86400)
        self.assertEqual(value['last_1h']['as_of_ms'],value['as_of_ms'])
        self.assertEqual(value['last_24h']['as_of_ms'],value['as_of_ms'])

    def test_statistics_schema_allows_unknown_rate(self):
        value=read('examples/stats.forward.json')
        value['current']['upload_mbps']=None
        check(value,read('schemas/stats.schema.json'))
        value['current']['upload_mbps']='fast'
        with self.assertRaises(SchemaError): check(value,read('schemas/stats.schema.json'))

    def test_reference_is_network_read_only(self):
        import ast
        tree=ast.parse((ROOT/'reference/contract.py').read_text())
        imports=[]
        for node in ast.walk(tree):
            if isinstance(node,ast.Import): imports.extend(n.name for n in node.names)
            if isinstance(node,ast.ImportFrom): imports.append(node.module)
        self.assertTrue({'subprocess','socket','os'}.isdisjoint(imports))


if __name__ == '__main__':
    unittest.main(verbosity=2)
