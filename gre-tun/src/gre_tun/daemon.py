"""Bounded persistence worker. Does not autonomously rewrite host networking."""
from __future__ import annotations
import signal
import sys
import time
from . import config, firewall, network, stats

STOP=False

def stop(_signum,_frame):
    global STOP
    STOP=True


def sample():
    c=config.read()
    if c is None:return 0
    state=network.read_state()
    if state is None or not state.get('nft_owned'):return 0
    live=firewall.counters(network.run)
    known={f['id']:live[f['id']] for f in c['forwards'] if f['id'] in live}
    if not known:return 0
    with config.locked():
        with stats.connect() as db:
            return stats.observe(db,[f for f in c['forwards'] if f['id'] in known],known,epoch=str(state.get('counter_epoch',0)))


def main():
    signal.signal(signal.SIGTERM,stop)
    signal.signal(signal.SIGINT,stop)
    tick=0
    while not STOP:
        if tick%60==0:
            try:sample()
            except Exception as exc:
                print(f'[gre-tun] Stats unavailable: {type(exc).__name__}: {str(exc)[:160]}',file=sys.stderr,flush=True)
        for _ in range(10):
            if STOP:break
            time.sleep(1)
        tick+=10
    try:sample()
    except Exception:pass
    return 0
