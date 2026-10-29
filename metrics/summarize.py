#!/usr/bin/env python3
"""Build the before/after table from metrics/baseline-runs.csv:   python metrics/summarize.py

Counted runs only (practice runs and the lost run are listed but not counted). Times:
  T0  Wazuh alert (5712 / 100505)            T3  containment in place (651 / 60111 = event 4725)
  manual: noticed (N), decided (D) from the analyst's laptop clock (UTC+1, within 0.1 s of the servers)
  auto:   T1 alert message sent, approve click, name typed (B), from n8n's own records (in the notes)
Writes metrics/summary.md and prints it.
"""
import csv
import datetime as dt
import re
import statistics
from pathlib import Path

HERE = Path(__file__).parent
LOCAL = dt.timedelta(hours=1)          # Fathia's laptop: W. Central Africa Standard Time (UTC+1)


def utc(s):
    return dt.datetime.fromisoformat(s.replace('Z', '+00:00'))


def local(day, hms):
    h, m, s = hms.split(':')
    return dt.datetime.combine(day, dt.time(int(h), int(m), 0), dt.timezone.utc) - LOCAL + dt.timedelta(seconds=float(s))


def note_time(notes, label, day):
    m = re.search(label + r' (\d\d:\d\d:\d\d(?:\.\d+)?)Z', notes)
    return utc(f'{day}T{m.group(1)}Z') if m else None


def fmt(sec):
    sec = round(sec)
    return f'{sec // 60} min {sec % 60:02d} s' if sec >= 60 else f'{sec} s'


def stats(values):
    v = [x for x in values if x is not None]
    if not v:
        return 'n/a'
    return f'{fmt(statistics.median(v))} ({fmt(min(v))} – {fmt(max(v))}, n={len(v)})'


rows = list(csv.DictReader(open(HERE / 'baseline-runs.csv', encoding='utf-8')))
groups = {}
excluded = []
for r in rows:
    if 'practice' in r['notes'] or r['outcome'].startswith('FAILED'):
        excluded.append(f"{r['run']}: {r['outcome']}" + (' (practice)' if 'practice' in r['notes'] else ''))
        continue
    t0 = utc(r['t0_alert_utc'])
    t3 = utc(r['t3_contained_utc']) if r['t3_contained_utc'] else None
    g = groups.setdefault((r['mode'], r['playbook']), {'total': [], 'notice': [], 'human': [], 'act': [], 'decided': [], 'runs': 0, 'no_action': 0})
    g['runs'] += 1
    if t3:
        g['total'].append((t3 - t0).total_seconds())
    else:
        g['no_action'] += 1
    if r['mode'] == 'manual':
        n = local(t0.date(), r['noticed_local'])
        d = local(t0.date(), r['decided_local'])
        g['notice'].append((n - t0).total_seconds())
        g['decided'].append((d - t0).total_seconds())
        if t3 and d <= t3:
            g['human'].append((d - n).total_seconds())
            g['act'].append((t3 - d).total_seconds())
    else:
        day = t0.date()
        t1 = note_time(r['notes'], 'T1 alert message sent', day)
        approve = note_time(r['notes'], 'approve', day) or local(day, r['decided_local'])
        typed = note_time(r['notes'], 'name typed', day)
        t2 = typed or approve
        g['notice'].append((t1 - t0).total_seconds())
        g['human'].append((t2 - t1).total_seconds())
        g['act'].append((t3 - t2).total_seconds())

lines = ['# Before / after: alert to containment', '',
         'Median (range, n). Counted runs only; T0 and T3 are Wazuh timestamps in both modes.', '',
         '| Playbook | Mode | Runs | Alert → containment | Until the analyst sees it | Human decision | After the decision |',
         '|---|---|---|---|---|---|---|']
labels = {'manual': ('noticed (watching the dashboard)', 'lookups / checks + decide', 'type and run the command'),
          'auto': ('message on Telegram', 'approve (+ type the name for B)', 'pipeline acts, endpoint confirms')}
for pb in ('A', 'B'):
    for mode in ('manual', 'auto'):
        g = groups.get((mode, pb))
        if not g:
            continue
        runs = f"{g['runs']}" + (f" ({g['no_action']} no action)" if g['no_action'] else '')
        lines.append(f"| {pb} | {mode} | {runs} | **{stats(g['total'])}** | {stats(g['notice'])} | {stats(g['human'])} | {stats(g['act'])} |")
lines += ['', 'What the columns mean: manual = alert→noticed, noticed→decided, decided→containment; '
          'auto = alert→Telegram message, message→approval (B: →name typed), approval→containment.', '',
          'Not counted: ' + '; '.join(excluded) + '.']
out = '\n'.join(lines) + '\n'
(HERE / 'summary.md').write_text(out, encoding='utf-8')
print(out)
