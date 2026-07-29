# Goggles Internal API v1

Goggles API responses are for authenticated internal forensic workflows. They
preserve stable response version fields, evidence references, and sensitivity
metadata so analysis agents can safely traverse derived projections back to raw
JSONL evidence.

## Authentication

Most read APIs require a logged-in Goggles user session. The group index and
streaming group export additionally accept a **personal access token** bearer
credential. Send it as `Authorization: Bearer gpat_…`. On those bearer-enabled
endpoints, missing, malformed, invalid, inactive, expired, or owner-deactivated
credentials return `401` JSON — never an HTML login redirect.

Upload APIs use reusable upload bearer tokens (`goggles_…`) and are documented
separately in the app workflow notes. Upload tokens never authorize read APIs.

Personal access tokens are read-only credentials a user mints from their profile
page (or an operator mints for a service account with
`manage.py create_access_token "<name>" --user <username>`). They authorize the
group list (`GET /api/v1/groups/`) and the streaming group export
(`GET /api/v1/groups/{slug}/export/`) — not uploads or the other
session-authenticated projection APIs. A token is revoked by the owner, by an
admin, by expiry, or by deactivating the owning user. Upload tokens and
personal access tokens are distinct credentials and never interchangeable.

The current internal deployment treats authenticated Goggles users as one shared
internal tenant. Even so, endpoint implementations route through a shared
object-level readable-group scope before returning group data. If Goggles later
adds tenant or account isolation, unauthorized groups are omitted from the list
and exports for unknown slugs return `404`, indistinguishable from a missing
group, so callers cannot enumerate data outside their scope.

Responses must not expose bearer tokens, upload secrets, source IPs, or user
agents. Derived projection responses carry pointer-only evidence refs. Raw event
evidence can include sensitive forensic identifiers and is only available
through authenticated evidence endpoints.

## Common Query Parameters

Projection endpoints support these filters where the field applies:

- `engine_id`
- `account_ref`
- `audit_data_mode`
- `message_id`
- `event_type`
- `severity`: `info`, `warning`, or `error`
- `epoch`
- `from_ms`
- `to_ms`
- `limit`: defaults to `100`, capped at `500`
- `offset`: defaults to `0`

Compatibility note: releases before the memory-pressure hardening defaulted to
500 rows and allowed up to 5,000. API consumers that relied on those larger
pages must now follow `has_more` and advance `offset` in batches of at most 500.

Paginated responses include:

```json
{
  "pagination": {
    "limit": 100,
    "offset": 0,
    "returned": 10,
    "has_more": false,
    "next_offset": null
  }
}
```

Combined projection responses return one pagination object per projection list.

Action attribution endpoints also support:

- `origin`: for example `local_user`, `system`, or `observed_group_event`
- `action`: the normalized human-action name, such as `send_message`

Action pagination includes `scan_truncated` and `scan_limit`. If
`scan_truncated` is true, Goggles bounded the request to the newest safe action
window; use narrower filters rather than requesting an unbounded group history.

## Sensitivity Metadata

Derived objects that may contain decrypted content, full author identifiers, raw
wire ids, or preserved raw evidence include:

```json
{
  "sensitivity": {
    "contains_sensitive_data": true,
    "contains_full_data": true,
    "audit_data_modes": ["full_data"],
    "sensitive_field_paths": ["decoded_payload", "decoded_app_event.content"],
    "authorization": {
      "required": "authenticated_internal_user",
      "granted": true
    }
  }
}
```

The current internal-testing policy grants full-data readout to authenticated
Goggles users. If Goggles later separates analyst and administrator roles, this
metadata is the field-level hook for enforcing stricter access.

## Endpoints

### Groups

- `GET /api/v1/groups/`
- `GET /api/v1/groups/{group_slug}/`
- `GET /api/v1/accounts/{account_ref}/groups/`
- `GET /api/v1/engines/{engine_id}/groups/`

`GET /api/v1/groups/` accepts a logged-in session or a personal access token.
It returns metadata for every group the reader may export. Newly-created groups
appear on the next poll without manual slug configuration.

Query parameters:

- `limit`: defaults to `100`, capped at `500`
- `cursor`: optional opaque continuation token from a previous page's
  `pagination.next_cursor`. Omit on the first page of a poll.
- `updated_since`: optional ISO-8601 timestamp; when set, only groups with
  `updated_at` strictly after this value are returned. The response echoes the
  applied filter as `updated_since`. This is a **best-effort** change hint only:
  it does not guarantee every group that became visible since your last poll (see
  [Polling contract](#polling-contract)).

Results are ordered by `(updated_at desc, slug asc)`. The first page of each poll
fixes a server `polling_watermark` timestamp; every page in that traversal
reuses the same watermark and only includes groups with `updated_at` at or before
it. Groups that are still uncommitted, or that commit after the watermark is
captured, can require a later full index poll. The watermark is **not** a
commit-safe upper bound on `updated_at`: a group can commit after page 1 with
`updated_at` at or before the watermark and still be invisible to both the
remaining pages and a subsequent `updated_since=polling_watermark` poll.

Paginated responses include:

```json
{
  "pagination": {
    "limit": 100,
    "returned": 10,
    "has_more": true,
    "next_cursor": "…"
  },
  "polling_watermark": "2026-07-29T09:00:00+00:00"
}
```

#### Polling contract

1. Start each poll without `cursor`. Read `polling_watermark` from the first
   response and keep it for the whole traversal. Use it only to bound that
   traversal; do not treat it as a commit-safe cursor for change detection.
2. Follow `pagination.next_cursor` until `has_more` is `false`. Each cursor is
   bound to that poll's watermark and original `updated_since` filter, so only
   `cursor` and the desired `limit` need to be sent on continuation requests.
   Tampered or foreign cursors return `400` `{"error":"invalid cursor"}`.
3. After completing a traversal, you may set `updated_since` to the maximum
   `updated_at` among groups you actually received to skip unchanged groups on
   the next incremental poll. This is an optimization only: uploads assign
   `updated_at` before commit, so a group can appear after your traversal with
   `updated_at` at or before your `updated_since` bound and be omitted from
   incremental polls.
4. For **eventual completeness**, periodically run a full index poll (omit
   `updated_since` and `cursor`) and deduplicate by `slug`. A finite overlap
   window alone does not guarantee discovery of arbitrarily delayed commits.
   An empty `groups` array on an incremental poll means no group has
   `updated_at` strictly after your `updated_since` bound; it does **not** prove
   the index is unchanged.

Projection endpoints still use numeric `offset` pagination (see
[Common Query Parameters](#common-query-parameters)); only the group index uses
cursor pagination.

Group responses include `schema_version`, group summary fields, tab counts, and
classification metadata indicating whether full-data audit content may be
present.

### Group Export (streaming)

- `GET /api/v1/groups/{slug}/export/`

Streams the complete forensic aggregate for one group as a single **NDJSON**
download (`Content-Type: application/x-ndjson`) — one JSON object per line. Rows are
read from the database with server-side cursors, so the response is bounded in
server memory regardless of group size and is **not paginated**. Authenticate with a
logged-in session or a personal access token (`Authorization: Bearer gpat_…`).

The export is unconditionally the complete group: it takes **no query filters** (the
[common filters](#common-query-parameters) do not apply — applying them to only some
sections would misrepresent the payload, and filtering raw events would break the
completeness the export exists to provide). Filter client-side, or use the paginated
projection endpoints. Disabled via `GOGGLES_EXPORTS_ENABLED=0` (returns `503`).

Line schema:

```text
{"t":"manifest","schema_version":"goggles-group-export/v1","generated_at":"…","group":{…},"classification":{…},"sensitivity":{…},"sections":[…]}
{"t":"source", …}                  # one per audit file
{"t":"event", …}                   # every valid event, uncapped
{"t":"delivery_artifact", …}
{"t":"network_observation", …}
{"t":"convergence_run", …}
{"t":"state_delta", …}
{"t":"epoch_state_transition", …}
{"t":"audit_data_mode_change", …}
{"t":"eof","complete":true,"counts":{"event":N, …}}
```

`event` records use the agent-state export shape; projection records use the
projection-API shape — the export is a tagged union of the two, discriminated by the
leading `t` on every line. Derived aggregates (`timeline`, `messages`, `actions`,
`action_attribution`) are intentionally excluded; reconstruct them from the raw
records (e.g. fork resolutions are `event` records with
`event_type == "fork_resolution"`).

**Fail-closed contract.** Two distinct failure surfaces:

- *Before the first byte* (authentication, unknown group, kill-switch): a
  conventional non-`200` response (`401`/`404`/`503`). Check the HTTP status first.
- *Mid-stream*: the status is already committed at `200`, so a later error is
  reported in-band as a final `{"t":"error","complete":false}` line with **no**
  `eof`. A response whose last line is not `{"t":"eof",…}` is incomplete and must be
  discarded.

**Consistency.** The export is append-time-consistent, not a single atomic snapshot:
each section is read in its own transaction, so a record appended mid-export may be
referenced by a later section but missing from an earlier one. Re-export if a
cross-section-consistent view matters.

**Revocation is point-in-time.** Authentication is checked once, before streaming
begins. Revoking a token (or deactivating its owner) stops the *next* request; an
export already in flight continues to completion. Incident response should not assume
revoke is an immediate cut-off for a stream already underway.

### Delivery

- `GET /api/v1/groups/{group_slug}/delivery/`
- `GET /api/v1/groups/{group_slug}/delivery/{artifact_id}/`
- `GET /api/v1/messages/{message_id}/`

Delivery artifacts represent projected message-like artifacts. They include
per-engine observations, expected-recipient rows, a recipient matrix, severity,
sensitivity metadata, and evidence refs.
Each engine observation includes a state trail, with states such as transport
receipt, decode, publish outcome, and direct evidence refs for the raw lines
that produced those states.

The message endpoint returns every matching delivery artifact across groups. Use
it when automation starts from a canonical message, commit, or welcome artifact
id before it knows which group workspace contains the evidence. Each match also includes a
`related` block with same-group Network, Convergence, State, epoch-transition,
and Action Attribution projections filtered to that message id.

Recipient matrix statuses:

- `observed`
- `missing_inferred`
- `missing_count_inferred`
- `partial_count_inferred`
- `unobserved_no_uploaded_engine`
- `observed_not_expected`
- `expected_count_satisfied`
- `observed_count_exceeds_expected`

### Network

- `GET /api/v1/groups/{group_slug}/network/`

Network observations include transport receipt, publish attempt/outcome/failure,
wire id, relay, payload digest, ack, severity, sensitivity metadata, and raw
evidence refs. Welcome transport identifiers are explicit layer-specific fields,
such as `welcome_nostr_event_id`, `welcome_rumor_event_id`, and
`welcome_key_package_tag`; they are not overloaded into `message_id`.

### Convergence

- `GET /api/v1/groups/{group_slug}/convergence-runs/`
- `GET /api/v1/groups/{group_slug}/convergence-runs/{run_id}/`

Convergence runs include run lifecycle fields, selected branch, candidates,
scores, rejection reasons, decisive rule evaluations, severity, sensitivity
metadata, and evidence refs. Candidate and rule-evaluation payloads also carry
the convergence-decision evidence refs that produced those child rows.
`message_id` filters convergence runs by selected branch id, losing branch id,
candidate branch id, or candidate commit ids. `epoch` filters by run-level,
candidate-level, and evidence-level convergence epoch fields.
When MDK does not emit a stable convergence `run_id`, Goggles groups
contiguous convergence and epoch-state evidence for the same group engine into
an inferred run and sets `inferred` to `true`.
If multiple engines have the same run id, the detail endpoint returns `409` with
matching engine ids. Retry with `?engine_id=...` to fetch the intended run.

### State

- `GET /api/v1/groups/{group_slug}/state-deltas/`

State responses include group state deltas and epoch state transitions. Deltas
include origin commit links, changed fields, value metadata, severity,
sensitivity metadata, and evidence refs. `message_id` filters state deltas by
`origin_commit_id` and the source evidence row's message fields.

### Action Attribution

- `GET /api/v1/groups/{group_slug}/actions/`

Action attribution responses separate real local-user intent from system-stamped
attribution rows. The top-level sections are `user_actions`,
`system_attribution`, and `other_attribution`, each with independent pagination
metadata. Rows include operation id, action, origin, phase, affected fields,
message ids, compact event rows, severity, sensitivity metadata, and evidence
refs. Use this endpoint to answer what a person asked the client to do before
following the related delivery, network, convergence, state, or raw evidence
links.

### Combined Projections

- `GET /api/v1/groups/{group_slug}/projections/`
- `GET /api/v1/groups/{group_slug}/projections/?download=1`

The combined projection endpoint returns Delivery, Network, Convergence, State,
epoch-transition, audit-data-mode-change, and action-attribution projections in
one response. `download=1` returns the same JSON with an attachment disposition.

Audit-data-mode-change payloads expose explicit recorder boundaries, including
previous mode, new mode, reason, recorder restart status, recorder session id,
severity, sensitivity metadata, and the evidence ref for the mode-change row.

### Evidence

- `GET /api/v1/groups/{group_slug}/evidence/`
- `GET /api/v1/events/{event_id}/evidence/`

The group evidence endpoint returns a paginated, filterable evidence index with
line hashes, event summaries, source file metadata, sensitivity metadata, and
evidence refs. It does not bulk-return raw JSONL bodies.

Single-event evidence responses include the raw line, raw event object, raw
kind/context, line hash, source file metadata, and sensitivity metadata. Use
evidence refs from projection responses instead of constructing event ids when
possible. Evidence refs themselves are pointer-only: they include identifiers
such as event id, audit file id, line number, line hash, event type, and API
path, but never embed raw JSON or raw JSONL bodies.

### Group Engines

- `GET /api/v1/groups/{group_slug}/engines/`

Returns engines observed in the group with event counts, account refs, first or
last event times, sensitivity metadata, and client-provided source metadata such
as account labels, device labels, device ids, device names, platform, app
version, upload trigger, account pubkey hex, and npub.

## Human-Facing Investigation Links

These authenticated pages sit on top of the API and projection tables:

- `/investigations/accounts/{account_ref}/`
- `/investigations/engines/{engine_id}/`
- `/reports/{report_id}/`
- `/reports/{report_id}/report.json`

Saved reports store an immutable projection snapshot plus investigator notes.
The report page summarizes every saved projection section, including action
attribution and pagination `has_more` markers when a snapshot list was truncated
by the projection page size.
