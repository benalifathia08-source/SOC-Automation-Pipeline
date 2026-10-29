#!/usr/bin/env python3
"""Show recent n8n executions without opening the UI (read-only).

    sudo python3 executions.py [count] [--detail] [--id N]

--detail also prints, for the newest execution (or execution N with --id), each node's status, start
time and any error message, and every "text" field a Code node produced (the Telegram messages).
Reads n8n's SQLite database in read-only mode.
"""
import datetime
import json
import sqlite3
import sys

DB = '/var/lib/docker/volumes/soc-pipeline_n8n_data/_data/database.sqlite'


def unflatten(raw):
    """n8n stores execution data in the 'flatted' format: a list where strings that are numbers
    point to other list entries. Rebuild the nested object."""
    table = json.loads(raw)
    seen = {}

    def walk(v):
        if isinstance(v, str) and v.isdigit() and int(v) < len(table):
            i = int(v)
            if i in seen:
                return seen[i]
            target = table[i]
            if isinstance(target, dict):
                out = {}
                seen[i] = out
                for k, x in target.items():
                    out[k] = walk(x)
                return out
            if isinstance(target, list):
                out = []
                seen[i] = out
                out.extend(walk(x) for x in target)
                return out
            return target
        return v

    return walk('0')


def main():
    argv = sys.argv[1:]
    exec_id = None
    if '--id' in argv:
        i = argv.index('--id')
        exec_id = int(argv[i + 1])
        argv = argv[:i] + argv[i + 2:]
    args = [a for a in argv if not a.startswith('--')]
    count = int(args[0]) if args else 5
    db = sqlite3.connect(f'file:{DB}?mode=ro', uri=True)
    rows = db.execute('select id, workflowId, status, mode, startedAt, stoppedAt, waitTill from execution_entity '
                      'order by id desc limit ?', (count,)).fetchall()
    for r in rows:
        print(*r)
    target = exec_id if exec_id is not None else (rows[0][0] if rows else None)
    if ('--detail' in sys.argv or exec_id is not None) and target is not None:
        rows = [(target,)]
        raw = db.execute('select data from execution_data where executionId = ?', (target,)).fetchone()
        if not raw:
            return
        data = unflatten(raw[0])
        run = data.get('resultData', {}).get('runData', {})
        print(f'\nexecution {rows[0][0]}: nodes that ran')
        for node, runs in run.items():
            for x in runs:
                err = x.get('error')
                started = x.get('startTime')
                when = (datetime.datetime.fromtimestamp(started / 1000, datetime.timezone.utc)
                        .strftime('%H:%M:%S.%f')[:-3] + 'Z') if started else '?'
                print(f"  {node:20} {x.get('executionStatus', '?'):8} start {when}  {x.get('executionTime', '?')} ms"
                      + (f"  ERROR: {err.get('message')}" if err else ''))
        top = data.get('resultData', {}).get('error')
        if top:
            print('workflow error:', top.get('message'))
        for node, runs in run.items():
            main = (runs[-1].get('data') or {}).get('main') or [[]]
            items = main[0] or []
            if items and isinstance(items[0].get('json', {}).get('text'), str) and node != 'Telegram':
                print(f'\n--- text from "{node}" ---\n' + items[0]['json']['text'])


if __name__ == '__main__':
    main()
