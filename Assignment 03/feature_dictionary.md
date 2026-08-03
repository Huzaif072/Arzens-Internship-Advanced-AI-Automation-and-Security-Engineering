# Feature Dictionary

Documentation for every column produced by `feature_extractor.py`. Privacy
risk levels mirror the Task 1 Feature Engineering Brief.

## Window / bookkeeping columns

| Column | Description |
|---|---|
| `window_id` | Unique key: `{date}_{hour}_{entity_id}` (entity_id here is the pseudonymized token). |
| `entity_id` | Pseudonymized (HMAC-SHA256) identifier for the user or host/IP this row describes. |
| `entity_label` | Raw (non-pseudonymized) identifier, included in this sample output for grading/debugging transparency only. **In a production deployment this column would not leave the security team's access-controlled environment.** |
| `hour` | Bucket key as `YYYY-MM-DD_HH`. |
| `hour_of_day` | Integer hour, 0-23. |
| `privacy_risk` | Row-level overall risk flag (LOW/MEDIUM/HIGH), driven by whether `peer_deviation` is populated and by window type. |

## Count features

| Feature | Definition | Privacy Risk |
|---|---|---|
| `login_success_count` | Count of AUTH events with `status == SUCCESS` in the window. | LOW |
| `login_failure_count` | Count of AUTH events with `status == FAILURE` in the window. | LOW |
| `unique_source_ips` | Distinct count of `source_ip` values seen in the window. | MEDIUM |

## Ratio features

| Feature | Definition | Privacy Risk |
|---|---|---|
| `failure_ratio` | `login_failure_count / (login_success_count + login_failure_count)`; 0 if no logins in the window. | LOW |
| `success_rate` | `login_success_count / total_events_in_window`. | LOW |

## Temporal features

| Feature | Definition | Privacy Risk |
|---|---|---|
| `time_since_last_login_min` | Minutes since the entity's previous AUTH event, averaged over the window. Imputed with the dataset-wide mean gap for an entity's first-ever event (see "Imputation" below). | MEDIUM |
| `hour_of_day` | See above. | LOW |
| `is_business_hours` | `True` if `9 <= hour_of_day < 18`. | LOW |

## Entropy features

| Feature | Definition | Privacy Risk |
|---|---|---|
| `dns_query_entropy` | Mean Shannon entropy (base 2) of DNS query domain strings in the window. 0 if no DNS events. | LOW |
| `domain_length` | Mean character length of DNS query domains in the window. 0 if no DNS events. | LOW |

## Behavioral / aggregational features

| Feature | Definition | Privacy Risk |
|---|---|---|
| `bytes_transferred` | Sum of `bytes` across NETWORK events in the window. 0 if none. | MEDIUM |
| `unique_dest_ports` | Distinct count of `port` across NETWORK events in the window. 0 if none. | LOW |
| `peer_deviation` | Z-score of `login_failure_count` against all entities active in the same hour bucket ("peer group" — see note below). | **HIGH** |

## Rolling-window columns (added by `--rolling`)

| Feature | Definition |
|---|---|
| `login_failure_count_rolling_{1h/4h/24h}` | Trailing sum of `login_failure_count` over the last N hourly buckets for that entity. |
| `login_success_count_rolling_{1h/4h/24h}` | Same, for `login_success_count`. |
| `bytes_transferred_rolling_{1h/4h/24h}` | Same, for `bytes_transferred`. |

## Entity resolution by window type

- **user-hour**: entity is the AUTH event's `user` field. NETWORK and DNS
  events carry no username in this dataset, so they do not contribute rows
  to user-hour windows (their count/entropy/byte features will be 0 for
  every user-hour row, since no such events are attributed to a username).
- **host-hour**: entity is AUTH's `host`, or NETWORK's `source_ip`, or DNS's
  `client_ip` (treated as equivalent to `source_ip`). This lets all three
  log types populate the same feature matrix.

## Imputation policy

- Count/sum-style features (`login_success_count`, `login_failure_count`,
  `unique_source_ips`, `dns_query_entropy`, `domain_length`,
  `bytes_transferred`, `unique_dest_ports`) are imputed with **0** when a
  window has no relevant events, since "no events of this type" genuinely
  means the count is zero.
- `time_since_last_login_min` is imputed with the **column mean** for an
  entity's very first observed event, since that entity has no prior event
  to measure a gap from — 0 would be misleading (it would imply an instant
  repeat login rather than "no history available").

## Peer group definition (for `peer_deviation`)

This synthetic dataset has no org/team roster, so "peer group" is defined
as every entity active in the same hour bucket. A production deployment
should scope this to each user's actual team, since comparing, say, a
finance analyst against an engineer's typical login volume is not a
meaningful comparison.

## Privacy controls summary

- `entity_id` is pseudonymized by default (HMAC-SHA256, truncated to 16
  hex chars, prefixed `ps_`). The HMAC key (`PSEUDONYM_KEY` in
  `feature_extractor.py`) is a placeholder and must be replaced with a
  secret pulled from a secrets manager before any real deployment.
- `entity_label` (the raw value) is included in this sample output only for
  grading/debugging clarity, and is clearly marked as something that would
  not ship in a production feature store.
- `privacy_risk` flags rows where the highest-risk feature (`peer_deviation`)
  is populated as HIGH; other rows are MEDIUM (user-hour windows, since they
  describe an individual) or LOW (host-hour windows, since IPs/hosts are
  one step removed from a named person).
