# Before / after: alert to containment

Median (range, n). Counted runs only; T0 and T3 are Wazuh timestamps in both modes.

| Playbook | Mode | Runs | Alert → containment | Until the analyst sees it | Human decision | After the decision |
|---|---|---|---|---|---|---|
| A | manual | 6 (1 no action) | **2 min 08 s (1 min 50 s – 2 min 25 s, n=5)** | 15 s (10 s – 29 s, n=6) | 1 min 27 s (1 min 25 s – 1 min 49 s, n=5) | 24 s (9 s – 30 s, n=5) |
| A | auto | 3 | **25 s (10 s – 25 s, n=3)** | 3 s (3 s – 4 s, n=3) | 21 s (6 s – 21 s, n=3) | 1 s (1 s – 1 s, n=3) |
| B | manual | 3 | **1 min 05 s (48 s – 1 min 49 s, n=3)** | 13 s (9 s – 15 s, n=3) | 54 s (33 s – 1 min 15 s, n=2) | 19 s (18 s – 20 s, n=2) |
| B | auto | 3 | **26 s (23 s – 31 s, n=3)** | 2 s (1 s – 2 s, n=3) | 19 s (19 s – 21 s, n=3) | 3 s (3 s – 10 s, n=3) |

What the columns mean: manual = alert→noticed, noticed→decided, decided→containment; auto = alert→Telegram message, message→approval (B: →name typed), approval→containment.

Not counted: A-0: blocked (practice); B-0: disabled (practice); AUTO-B-1: FAILED: alert lost.
