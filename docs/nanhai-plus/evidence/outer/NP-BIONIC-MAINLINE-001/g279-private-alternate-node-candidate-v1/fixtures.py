#!/usr/bin/env python3
"""Credential-free selector counterexamples; no controller or network access."""
import datetime
import select_alternate as s

now = datetime.datetime(2026, 10, 4, 20, 0, tzinfo=datetime.timezone.utc)
def history(delay, age=20):
    return [{'delay': delay, 'time': (now - datetime.timedelta(seconds=age)).isoformat()}]

metrics = [s.history_metric(history(100 + i), now) for i in range(15)]
metrics[1] = s.history_metric(history(51), now)
metrics[9] = s.history_metric(history(40), now)
assert s.choose(metrics, 9) == 1

cases = {
    'alternate_is_current': (metrics, 1),
    'better_non_current_exists': ([dict(m) for m in metrics], 9),
    'missing_node': (metrics[:-1], 9),
    'no_eligible_alternate': ([None if i != 9 else metrics[9] for i in range(15)], 9),
}
cases['better_non_current_exists'][0][2]['best_delay_ms'] = 30
for label, (candidate, current) in cases.items():
    try:
        s.choose(candidate, current)
    except ValueError:
        pass
    else:
        raise AssertionError(label)

assert s.history_metric(history(0), now) is None
assert s.history_metric(history(30, 7201), now) is None
assert s.history_metric(history(30, -121), now) is None
assert s.history_metric([{'delay': 30, 'time': 'bad'}], now) is None
assert s.history_metric([{'delay': True, 'time': now.isoformat()}], now) is None
print('PASS: positive, changed-current, changed-ranking, inventory, stale/future/invalid-history negatives')
