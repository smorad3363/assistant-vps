"""Persist named-nft-counter observations and rolling usage without invented gaps."""
from __future__ import annotations
from decimal import Decimal, ROUND_HALF_UP
import json
import os
from pathlib import Path
import sqlite3
import time

ROOT = Path(__file__).resolve().parents[2]
DB_PATH = Path(os.environ.get('GRE_TUN_DB_PATH', '/var/lib/gre-tun/stats.sqlite3'))


def connect(path=None):
    db_path = Path(path) if path is not None else DB_PATH
    db_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    db = sqlite3.connect(db_path, timeout=5)
    db.executescript((ROOT / 'reference' / 'schema.sql').read_text(encoding='utf-8'))
    return db


def boot_id():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def millis():
    return int(time.time_ns() // 1_000_000)


def observe(db, forwards, counters, timestamp_ms=None, mono_ns=None, boot=None, epoch='1'):
    """Store one sample per forward; missing counter is unknown, not zero.

    counters is {id: (upload_bytes, download_bytes)}; epoch must change after
    the nft named-counter collection is recreated. This routine never infers
    counter continuity across an epoch or boot change.
    """
    now = millis() if timestamp_ms is None else timestamp_ms
    mono = time.monotonic_ns() if mono_ns is None else mono_ns
    boot = boot_id() if boot is None else boot
    written = 0
    with db:
        for f in forwards:
            fid = f['id']; generation = f['generation']
            old_history = db.execute('SELECT generation FROM forward_history WHERE forward_id=? AND valid_to_ms IS NULL', (fid,)).fetchone()
            if old_history and old_history[0] != generation:
                db.execute('UPDATE forward_history SET valid_to_ms=? WHERE forward_id=? AND valid_to_ms IS NULL', (now, fid))
            db.execute('INSERT OR IGNORE INTO forward_history(forward_id,generation,tunnel_id,valid_from_ms,mapping_json) VALUES(?,?,?,?,?)',
                       (fid,generation,f['tunnel_id'],now,json.dumps(f,sort_keys=True)))
            if fid not in counters:
                continue
            upload,download = counters[fid]
            if not all(type(x) is int and x>=0 for x in (upload,download)):
                continue
            previous = db.execute('SELECT generation,epoch,boot_id,observed_ms,monotonic_ns,upload_counter,download_counter FROM baselines WHERE forward_id=?', (fid,)).fetchone()
            if previous:
                pg,pe,pb,ts,pm,pu,pd = previous
                elapsed_ms=(mono-pm)/1_000_000
                valid=(pg==generation and pe==epoch and pb==boot and
                       1000<=elapsed_ms<=90000 and
                       0<now-ts<=90000 and abs((now-ts)-elapsed_ms)<=5000 and
                       upload>=pu and download>=pd)
                if valid:
                    db.execute('INSERT OR IGNORE INTO samples(forward_id,generation,tunnel_id,epoch,boot_id,start_ms,end_ms,upload_bytes,download_bytes) VALUES(?,?,?,?,?,?,?,?,?)',
                               (fid,generation,f['tunnel_id'],epoch,boot,ts,now,upload-pu,download-pd))
                    written+=1
                else:
                    if now>=ts:
                        db.execute('INSERT OR IGNORE INTO gaps(forward_id,start_ms,end_ms,reason) VALUES(?,?,?,?)',
                                   (fid,ts,now,'epoch, reset, clock jump or observation gap'))
            db.execute('INSERT INTO baselines(forward_id,generation,epoch,boot_id,observed_ms,monotonic_ns,upload_counter,download_counter) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(forward_id) DO UPDATE SET generation=excluded.generation,epoch=excluded.epoch,boot_id=excluded.boot_id,observed_ms=excluded.observed_ms,monotonic_ns=excluded.monotonic_ns,upload_counter=excluded.upload_counter,download_counter=excluded.download_counter',
                       (fid,generation,epoch,boot,now,mono,upload,download))
        # Keep at least 25h of complete sampling intervals.
        db.execute('DELETE FROM samples WHERE end_ms<?', (now-26*3600*1000,))
        db.execute('DELETE FROM gaps WHERE end_ms<?', (now-26*3600*1000,))
    return written


def _round(x):
    return int(x.quantize(Decimal('1'),rounding=ROUND_HALF_UP))


def window(db, forward_ids, now_ms, seconds):
    start=now_ms-seconds*1000
    ids=tuple(sorted(set(forward_ids)))
    result={'window_seconds':seconds,'as_of_ms':now_ms,'upload_bytes':None,'download_bytes':None,'total_bytes':None,
            'coverage_ms':0,'avg_upload_mbps':None,'avg_download_mbps':None,'status':'unavailable'}
    if not ids:return result
    markers=','.join('?' for _ in ids)
    rows=db.execute(f'SELECT forward_id,start_ms,end_ms,upload_bytes,download_bytes FROM samples WHERE forward_id IN ({markers}) AND end_ms>? AND start_ms<? ORDER BY start_ms',ids+(start,now_ms)).fetchall()
    upload=download=Decimal(0)
    segments={fid:[] for fid in ids}
    for fid,s,e,u,d in rows:
        a=max(start,s);b=min(now_ms,e)
        if a>=b:continue
        fraction=Decimal(b-a)/Decimal(e-s)
        upload+=Decimal(u)*fraction;download+=Decimal(d)*fraction
        segments[fid].append((a,b))
    # Intersection of per-item covered time for aggregates. For a single
    # forward, this is just the union of covered sample durations.
    edges=sorted({x for intervals in segments.values() for a,b in intervals for x in (a,b)})
    covered=0
    for a,b in zip(edges,edges[1:]):
        if all(any(s<=a and b<=e for s,e in segments[fid]) for fid in ids):covered+=b-a
    if covered<=0:return result
    ub=_round(upload);dbb=_round(download)
    result.update(upload_bytes=ub,download_bytes=dbb,total_bytes=ub+dbb,coverage_ms=covered,
                  avg_upload_mbps=str((upload*Decimal(8)/Decimal(covered*1000)).quantize(Decimal('0.01'),rounding=ROUND_HALF_UP)),
                  avg_download_mbps=str((download*Decimal(8)/Decimal(covered*1000)).quantize(Decimal('0.01'),rounding=ROUND_HALF_UP)),
                  status='complete' if covered==seconds*1000 else 'partial')
    return result


def snapshot(db, cfg, item, now_ms=None):
    now=millis() if now_ms is None else now_ms
    identifier=item.upper()
    if identifier.startswith('P'):
        fid=int(identifier[1:]);f=next((x for x in cfg['forwards'] if x['id']==fid),None)
        if f is None:raise ValueError('Unknown forward ID')
        ids=[fid];limits={'upload_mbps':f['upload_mbps'],'download_mbps':f['download_mbps']}
    elif identifier.startswith('T'):
        tid=int(identifier[1:]);t=next((x for x in cfg['tunnels'] if x['id']==tid),None)
        if t is None:raise ValueError('Unknown tunnel ID')
        ids=[row[0] for row in db.execute('SELECT DISTINCT forward_id FROM forward_history WHERE tunnel_id=?',(tid,)).fetchall()]
        ids=sorted(set(ids+[f['id'] for f in cfg['forwards'] if f['tunnel_id']==tid]))
        limits=None
    else:raise ValueError('Expected Pxxxx or Txxxx')
    history=db.execute('SELECT MAX(end_ms) FROM samples WHERE forward_id IN ('+(','.join('?' for _ in ids) if ids else 'NULL')+')', ids).fetchone()[0]
    as_of=history or now
    return {'contract_version':'1.0.0','item_id':identifier,'as_of_ms':as_of,'current':{'upload_mbps':None,'download_mbps':None},
            'last_1h':window(db,ids,as_of,3600),'last_24h':window(db,ids,as_of,86400),
            'limits':limits,'includes_earlier_settings':False}
