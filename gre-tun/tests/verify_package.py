"""Validate this handoff archive. No network, subprocess, or host mutations."""
import ast
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'reference'))
import contract as C
from schema_check import check, check_config_cross_fields


def read(path):
    return json.loads((ROOT / path).read_text(encoding='utf-8'))


def verify():
    required = ['00_START_HERE_FA.md','PROMPT_FOR_AI.txt','SPEC.md','VERSION',
                'IMPLEMENTATION_STATUS.md','PACKAGE_TEST_RESULTS.md','RUN_CONTRACT_TESTS.sh',
                'contracts/ui.en.json','contracts/menus.json','contracts/error_codes.json',
                'contracts/requirements.json','contracts/cli_contract.json',
                'schemas/config.schema.json','schemas/peer.schema.json',
                'reference/contract.py','reference/schema.sql','templates/gre-tun.service',
                'templates/gre-tun','fixtures/ui/main.txt']
    for name in required:
        assert (ROOT/name).is_file(), f'Missing: {name}'
    for path in ROOT.rglob('*.json'):
        json.loads(path.read_text(encoding='utf-8'))
    strings=read('contracts/ui.en.json')
    for value in strings.values():
        value.encode('ascii')
        assert '\r' not in value
    for menu in read('contracts/menus.json').values():
        for key in [menu['title'],menu['zero'],menu['prompt']]: assert key in strings
        for row in menu['items']:
            assert row['text'] in strings
            if 'text_disabled' in row: assert row['text_disabled'] in strings
    errors=read('contracts/error_codes.json')
    for path in (ROOT/'reference').glob('*.py'):
        ast.parse(path.read_text())
        for code in re.findall(r'"(E_[A-Z_]+)"',path.read_text()):
            assert code in errors, f'Unknown error: {code}'
    for name in ['config.entry.json','config.peer.json','config.empty.json']:
        value=read('examples/'+name)
        check(value,read('schemas/config.schema.json')); check_config_cross_fields(value,C)
    for name in ['peer.payload.json','peer.conflict.json']:
        value=read('examples/'+name)
        check(value,read('schemas/peer.schema.json')); C.validate_peer(value)
    assert C.decode_peer((ROOT/'examples/peer.code.txt').read_text().strip())==read('examples/peer.payload.json')
    check(read('examples/stats.forward.json'),read('schemas/stats.schema.json'))
    ids=[row['id'] for row in read('contracts/requirements.json')['cases']]
    assert len(ids)==len(set(ids)) and len(ids)>=30
    matrix=(ROOT/'docs/05_ROADMAP_AND_TESTS.md').read_text()
    assert all(f'| {case_id} |' in matrix for case_id in ids)
    assert all(row['implementation_result']=='NOT RUN' for row in read('contracts/requirements.json')['cases'])
    assert len(read('contracts/menus.json')['main']['items'])==4
    assert (ROOT/'VERSION').read_text().strip()==C.CONTRACT_VERSION
    # Full file integrity is checked when a distribution manifest is present.
    manifest=ROOT/'SHA256SUMS'
    if manifest.exists():
        declared=set()
        for line in manifest.read_text().splitlines():
            digest,name=line.split('  ',1)
            target=(ROOT/name).resolve()
            assert target.is_relative_to(ROOT.resolve()), 'Unsafe manifest path'
            assert target.is_file(), f'Manifest file missing: {name}'
            assert hashlib.sha256(target.read_bytes()).hexdigest()==digest, f'Hash mismatch: {name}'
            declared.add(name)
        actual={p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*') if p.is_file()
                and '__pycache__' not in p.parts and '.git' not in p.parts and p.name!='SHA256SUMS'}
        assert declared==actual, 'Manifest file inventory mismatch'
    print('PASS: schemas, examples, catalogs, fixtures, requirements and package integrity.')


if __name__=='__main__':
    verify()
