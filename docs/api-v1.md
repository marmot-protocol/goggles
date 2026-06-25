# Goggles Internal API v1

Goggles API responses are for authenticated internal forensic workflows. They
preserve stable response version fields, evidence references, and sensitivity
metadata so analysis agents can safely traverse derived projections back to raw
JSONL evidence.

## Authentication

All read APIs require a logged-in Goggles user. Upload APIs use reusable bearer
tokens and are documented separately in the app workflow notes.

The current internal deployment treats authenticated Goggles users as one shared
internal tenant. Even so, endpoint implementations should route through
object-level scope checks before returning group, account, engine, message,
report, or evidence data. If Goggles later adds tenant or account isolation,
unauthorized resources should use the same not-found style behavior as unknown
resources so callers cannot enumerate data outside their scope.

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
- `limit`: defaults to `500`, capped at `5000`
- `offset`: defaults to `0`

Paginated responses include:

```json
{
  "pagination": {
    "limit": 500,
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

Group responses include `schema_version`, group summary fields, tab counts, and
classification metadata indicating whether full-data audit content may be
present.

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
When Dark Matter does not emit a stable convergence `run_id`, Goggles groups
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
