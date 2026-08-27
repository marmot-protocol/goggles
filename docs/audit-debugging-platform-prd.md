# Goggles Audit Debugging Platform PRD

Status: Draft  
Date: 2026-06-24  
Audience: MDK, Goggles, and client application engineers

## Summary

Goggles should evolve from a generic audit-log event browser into a forensic
debugging workstation for Marmot group behavior. The redesigned product should
help investigators answer three high-value questions quickly:

1. What message traffic did each engine send, publish, receive from transport,
   process, defer, or fail?
2. What did the convergence state machine see when it quiesced, which branch
   won, and why?
3. Once a branch or commit won, how did the underlying MLS-authenticated group
   state actually change?

The audit files are sensitive forensic artifacts. Goggles must continue to
preserve raw uploads, raw JSONL lines, source metadata, and line-level evidence
while adding derived views, APIs, and normalized projections that make incidents
debuggable without manually reading every row. The audit pipeline should also
support an explicit data-mode toggle so routine logs keep today's obfuscated
sensitive data while opt-in forensic sessions can include full decrypted message
content and transport wire identifiers.

## Background

MDK audit logging currently writes sensitive JSONL records using
`schema_version = "marmot-forensics-audit/v1"`. Goggles ingests those files,
preserves exact raw text, normalizes common fields into database columns, and
renders group-level dashboards.

The latest MDK audit changes add richer group and epoch breadcrumbs:

- `epoch_state_changed` records engine epoch-state transitions such as stable,
  pending publish, recovering, and unrecoverable.
- `group_state_changed` records MLS-authenticated group-state deltas such as
  membership, admin, profile, avatar, and message-retention changes.
- `convergence_decision.error_kinds` explains selector failures such as missing
  retained anchors.
- Rows without explicit user intent are now stamped with
  `context.human_action.origin = "system"` so downstream tools can keep
  attribution on every row.

These changes are necessary but not sufficient. Goggles needs new product
surfaces, derived data models, and programmatic APIs. MDK and client
libraries may also need additional audit events so Goggles can explain branch
selection, transport gaps, and client/device behavior with confidence.

## Goals

- Make message delivery and processing visible across engines.
- Make convergence decisions explainable, including branch candidates, rules,
  eligibility, rejection reasons, and selected winners.
- Make MLS group-state evolution visible as domain events, not raw JSON rows.
- Preserve chain-of-custody for every derived object by linking back to raw file,
  line number, line hash, and raw event JSON.
- Support explicit audit data modes: default obfuscated sensitive data and
  opt-in full data auditing.
- Provide stable APIs for programmatic readout by group, account, engine, message,
  convergence run, and evidence line.
- Support future Rust, Swift, Kotlin, and TypeScript clients emitting compatible
  audit logs.

## Non-Goals

- Do not turn audit logs into privacy-safe telemetry. They remain sensitive
  forensic data.
- Do not store bearer tokens, raw upload request bodies in logs, or any upload
  authorization secret in derived views.
- Do not log private keys, bearer tokens, upload tokens, authorization headers,
  or client credentials in any audit data mode.
- Do not add encrypted ciphertext or raw MLS bytes to full data auditing unless
  there is a separate product and security decision. The proposed full mode is
  for decrypted message content and transport identifiers.
- Do not require perfect certainty for inferred missing transport arrivals.
  Goggles should distinguish observed facts from cross-engine inference.
- Do not remove raw event browsing. The raw evidence path remains required even
  after higher-level views exist.
- Do not split recorder output into per-group files. Keep one append-only audit
  file per engine, and let Goggles provide group-level filtering, APIs, and
  JSON exports.
- Do not migrate or preserve the current Goggles local database contents. This
  redesign can start from a reset database and simpler migrations.
- Do not keep the all-events timeline as a primary investigation surface. It is
  too broad for the new debugging workflow.

## Audit Data Modes

The audit recorder should expose a two-option data-mode setting. The selected
mode must be stored in MDK settings, stamped into recorder or session
context, visible in Goggles, included in API responses, and auditable when it
changes.

### Obfuscated Sensitive Data

This is the default and should match the current safety posture:

- No decrypted message content.
- No encrypted ciphertext or raw MLS bytes.
- Payload length and SHA-256 digest instead of payload bytes.
- Member refs or otherwise obfuscated member public keys.
- Value length and value digest for profile, avatar, retention, and similar
  state changes.
- Transport and message identifiers only where they are already part of the
  current obfuscated audit contract, with clear marking that they remain
  sensitive forensic metadata.

This mode should be sufficient for routine debugging, convergence analysis, and
delivery tracing where payload contents are not required.

### Full Data Auditing

This mode is explicit opt-in and should be treated as a substantially more
sensitive forensic capture:

- Include decrypted application or message content after successful MLS and
  application-payload decoding.
- Include the message author's full hex public key, account id, member id, or
  other canonical author identifier when available.
- Include decoded inner application event fields where applicable, such as
  `kind`, `content`, `pubkey`, `tags`, client message id, reply/thread
  references, attachments metadata, and application-level timestamps.
- Include actual transport or on-wire identifiers for Nostr kind 445 group
  messages and other transport envelopes, such as Nostr event id, event kind,
  event pubkey, relay URL, subscription id, transport group id, gift-wrap or
  welcome ids, and publish result ids where available.
- Continue excluding bearer tokens, upload tokens, private keys, auth headers,
  cookies, and any other credential material.

Full data auditing should be off by default, require an explicit user or admin
action to enable, present prominent warnings in clients and Goggles, and produce
mode-change audit rows. Toggling full data auditing should restart or reopen the
active recorder session so the audit file has an explicit mode boundary. Goggles
should make mixed-mode evidence obvious when comparing engines, because one
engine may have plaintext evidence while another only has digests.

Full data auditing must not be enabled unless the deployment has an explicit
retention, deletion, and access-control policy in place. For the current
internal-testing deployment, that policy is: retain uploaded audit evidence until
an authenticated operator runs the documented audit-data purge command, allow
read access only to authenticated internal Goggles users, and allow uploads to be
paused during cutovers or incidents. Broader deployments must define stricter
object-level access rules before full-data capture is enabled.

## Users

- Incident investigator: needs to compare multiple devices and identify where a
  group diverged.
- Engine developer: needs to understand convergence, branch selection, pending
  publish, fork recovery, and MLS state transitions.
- Client engineer: needs to determine whether app/client behavior produced,
  omitted, delayed, or failed upload and transport events.
- Automation or analysis agent: needs structured API output suitable for scripts,
  issue comments, reports, and regression analysis.

## Core Investigation Views

### 1. Transport Message Flow

Question: What actually moved through transport, and where did it stop?

The view should organize evidence by message id, commit id, welcome id, or
application-message id. Each row is one message-like artifact. Each column is an
engine/account-device. Cells should summarize the observed lifecycle:

- user or system intent created;
- outbound message generated;
- publish attempted;
- relay or endpoint acknowledged;
- received from transport adapter;
- peeled or decrypted;
- buffered, processed, stale, retryable, or failed;
- applied to group state;
- missing from an engine where comparable logs suggest it should have appeared.

Important distinction:

- "Arrived from transport" is a fact only when the receiving engine logs an
  inbound transport event.
- "Did not arrive from transport" is usually an inference from the absence of
  a row in an engine's observation window.
- To turn non-arrival into fact, the system may need relay/server-side receipts
  or transport adapter delivery logs.

### 2. Convergence State Machine

Question: What did the convergence engine see, what did it choose, and why?

The view should organize events by convergence run. Once MDK emits a
stable `convergence_run_id`, that id should define the run. Before then, Goggles
can infer provisional runs from contiguous convergence and epoch-state events
with the same engine id and group ref. An inferred run begins when an engine
starts quiescing or evaluating stored candidates for a group, and ends when it
selects a branch, blocks, fails, returns to stable, or marks the group
unrecoverable. Inferred runs must be labeled as inferred because adjacent passes
can otherwise be merged or split incorrectly.

Each run should show:

- run id and engine id;
- group ref and wall-clock window;
- starting stable epoch and retained-anchor horizon;
- candidate branch list;
- branch fork epoch, tip epoch, commit ids, and state digest;
- eligibility result for each branch;
- rejection reasons and selector errors;
- every branch-selection rule evaluated, the rule inputs that matter for
  explainability, and the rule that actually selected or rejected a branch;
- scoring, weighting, or rule decisions where applicable;
- selected branch id and selected tip epoch;
- resulting epoch-state transition;
- raw evidence links for every row.

Current MDK data can show high-level decisions through
`convergence_decision`, `error_kinds`, and `epoch_state_changed`. It likely does
not yet expose enough candidate-level detail to fully explain branch selection.

### 3. MLS and Group State Evolution

Question: After a commit or branch won, did the MLS-authenticated group state
change correctly?

The view should organize durable state changes by epoch and origin commit:

- member added, removed, or left;
- admin added or removed;
- group renamed;
- group avatar changed;
- message retention changed;
- actor member ref when attributable;
- subject member ref when applicable;
- origin commit id when attributable;
- value digest and value length for value-bearing changes;
- previous and new engine epoch-state.

This should render as a human-readable state history while retaining hashed or
redacted identifiers. The view must make it easy to jump from a state delta to
the commit/message trace and raw JSONL evidence that produced it.

## Proposed Information Architecture

Goggles should keep the group as the primary workspace, but replace the current
event-first mental model with derived forensic objects. The all-events timeline
should be removed as a primary tab. Raw events remain available through Evidence
drilldowns, but the main workflow should be split by investigation concern.

Group workspace tabs:

- Overview: health summary, engines, audit data modes, latest activity, and
  current alerts.
- Delivery: message, commit, and welcome lifecycle matrix by artifact id.
- Network: transport receipts, publish attempts, relay acknowledgements,
  failures, and wire ids.
- Convergence: convergence runs, branch candidates, decision reasons, outcomes.
- State: MLS-authenticated group-state changes and epoch-state transitions.
- Evidence: raw files, raw lines, invalid lines, duplicates, schema versions.
- Exports: API links, downloadable JSON exports, and analysis-agent payloads.

The Evidence tab can show raw lines and raw event JSON, but should not become a
global chronological event feed. Every derived object should deep-link to the
specific evidence lines that support it.

## Derived Data Model

Goggles should retain raw `AuditFile` and `AuditEvent` records, then build
normalized relational tables for the derived projections. The product should
optimize for fast investigation workflows. Materialized JSON snapshots or cached
API responses can be added where they improve performance, but relational
derived tables should be the primary projection model.

Recommended derived objects:

- `SourceFile`: upload metadata, file hash, source labels, raw text preservation.
- `Engine`: account ref, engine id, source labels, first and last activity.
- `MessageArtifact`: canonical message, commit, welcome, or app payload carrier.
- `EngineMessageObservation`: one engine's observed lifecycle for one artifact.
- `TransportObservation`: publish attempt/outcome or inbound transport arrival.
- `RecipientExpectation`: expected recipient set for a group message, including
  welcome-message exceptions.
- `ConvergenceRun`: one canonicalization/quiescing/selection pass.
- `BranchCandidate`: candidate branch shape, eligibility, scoring, and outcome.
- `GroupStateDelta`: authenticated durable group-state change.
- `EpochStateTransition`: engine epoch-state state-machine transition.
- `EvidenceRef`: raw file id, line number, line hash, raw kind type, and an API
  path for explicit evidence retrieval. It must not embed raw JSON or raw JSONL
  bodies in every derived object.

Every derived object must carry evidence references. Raw event JSON and raw line
content should be available only through a dedicated evidence retrieval flow with
explicit authorization and auditability.

## Current Goggles Changes Needed

Near-term support should assume a greenfield database reset and a v3-current,
v2-compatible projection model:

- Accept v1, v2, and v3 raw event rows, with safe-only v3 as the current
  normalized contract and v1/v2 retained for historical evidence.
- Add a compact raw-evidence layer for files, lines, schema version, event type,
  refs, the normalized privacy posture, and evidence hashes.
- Add relational projection tables for Delivery, Network, Convergence, and
  State instead of expanding the single `AuditEvent` table indefinitely.
- Normalize historical v2 audit data modes and derive the fixed `safe_only`
  posture for v3 rows.
- Separate real app/user actions from system-stamped attribution rows.
- Remove the all-events timeline and replace it with smaller purpose-built
  group tabs.
- Add clear full-data badges, warnings, and access checks anywhere decrypted
  message content or full transport identifiers can appear.
- Keep parser/schema tests for both historical v2 and current v3.
- Include derived projections in agent export and API output.

## MDK Audit Data Gaps

The latest audit changes are a strong foundation, but Goggles probably needs
additional MDK events for complete explainability.

The current safe-only v3 event-line schema is in
[`docs/schemas/audit-log-event.v3.schema.json`](schemas/audit-log-event.v3.schema.json);
the historical v2 schema remains alongside it for compatibility.
The Goggles internal read API contract is documented in
[`docs/api-v1.md`](api-v1.md).

Message and transport gaps:

- Explicit inbound transport receipt rows before engine processing, with delivery
  plane, relay URL, subscription id, envelope kind, payload digest, and msg id.
- Clear distinction between adapter receipt, peel/decrypt, MLS processing, and
  group-state application.
- Publish attempt and outcome rows that can be correlated to expected recipients
  or delivery planes where the protocol can know that safely.
- Expected-recipient rows or fields based on group membership at send time. Group
  messages are expected to reach all other current group members. Welcome
  messages are the exception: the welcome is expected only by the added member,
  while existing members receive the commit that adds that member.
- Optional relay/server-side receipts if "did not arrive" must become factual
  rather than inferred.

Audit data mode gaps:

- Extend `AuditLogSettings` beyond `enabled` to include a stable data-mode enum,
  initially `obfuscated_sensitive_data` and `full_data`.
- Stamp the selected data mode into audit file/session context and make mode
  changes auditable.
- Add schema fields for decrypted message content, decoded application event
  fields, and full author identifiers in full data mode.
- Add schema fields for transport/on-wire ids, including Nostr kind 445 event
  ids and equivalent identifiers for other transport message types.
- Add producer tests proving obfuscated mode excludes plaintext, ciphertext, raw
  MLS bytes, and full author keys, while full mode includes only the intended
  decrypted content and transport identifiers.

Convergence gaps:

- A stable `convergence_run_id` on all rows emitted during one convergence pass.
- Quiescing lifecycle rows: started, waiting, evaluating, selected, blocked,
  applied, failed, or unrecoverable.
- Candidate branch rows with branch id, fork epoch, tip epoch, commit ids,
  commit count, state digest, retained-anchor status, and last input time.
- Per-candidate eligibility and rejection reasons.
- Rule-output rows for every decision rule the convergence engine evaluates,
  including the rule name, inputs needed for explanation, result, and whether the
  rule was decisive.
- Scoring or weighting rows when the selector compares candidates numerically.
- Selected winner row that names the selected branch and the losing branches.
- Applied branch outcome rows that link selection to `group_state_changed`.

Client and library gaps:

- TypeScript library support for the same audit-log contract.
- TypeScript, Swift, Kotlin, and Rust client controls for selecting the audit
  data mode, including warnings for full data auditing.
- Client source metadata that identifies app version, platform, upload trigger,
  stable device id, human-readable device name where available, and the logged-in
  account public key or npub without exposing raw credentials.
- Consistent upload scheduling after send, receive, convergence, startup sync,
  catch-up, and recovery operations.

## API Requirements

APIs should be optimized for forensic readout, not only raw event access.

Initial endpoints:

- `GET /api/v1/groups/`
- `GET /api/v1/groups/{group_slug}/`
- `GET /api/v1/groups/{group_slug}/delivery/`
- `GET /api/v1/groups/{group_slug}/delivery/{artifact_id}/`
- `GET /api/v1/messages/{message_id}/`
- `GET /api/v1/groups/{group_slug}/network/`
- `GET /api/v1/groups/{group_slug}/convergence-runs/`
- `GET /api/v1/groups/{group_slug}/convergence-runs/{run_id}/`
- `GET /api/v1/groups/{group_slug}/state-deltas/`
- `GET /api/v1/groups/{group_slug}/engines/`
- `GET /api/v1/events/{event_id}/evidence/`
- `GET /api/v1/accounts/{account_ref}/groups/`
- `GET /api/v1/engines/{engine_id}/groups/`

API behavior:

- Require authentication.
- Return stable JSON schemas with version fields.
- Treat this as an internal stable API rather than a public platform contract:
  version responses, keep existing fields stable where practical, and document
  intentional breaking changes.
- Support pagination and time-window filtering.
- Support filters for engine id, account ref, event type, message id, epoch, and
  severity.
- Support filters for audit data mode and a response-level classification that
  tells clients whether decrypted content may be present.
- Include evidence refs on every derived object.
- Exclude bearer tokens, upload secrets, source IPs, and user agents unless an
  explicit administrative evidence endpoint is introduced.
- Require elevated authorization for endpoints or fields that expose full data
  auditing content, including decrypted message content, full author public keys,
  and transport wire identifiers.
- Enforce object-level authorization before returning group, account, engine,
  message, convergence-run, report, or evidence data. The first internal
  deployment may map all authenticated Goggles users to one shared tenant, but
  every endpoint should still pass through a scope check so future tenant,
  account, group, and engine boundaries are explicit.
- Avoid cross-scope enumeration. Unauthorized and unknown resources should use
  the same not-found style behavior unless an administrative endpoint
  intentionally exposes existence metadata.
- Default baseline responses to least-privilege summaries. Decrypted message
  content, full author identifiers, transport wire identifiers, and raw evidence
  bodies should require the explicit full-data/evidence authorization path.

## Functional Requirements

### P0

- Reset the Goggles database model around raw evidence plus derived projections.
- Ingest V1 and V2 raw event rows while preserving raw lines and evidence refs.
- Define and store audit data-mode metadata in raw and derived views.
- Add Delivery and Network projection tables from V2 message, recipient, publish,
  receive, ingest, peel, and decode rows.
- Add Convergence projection tables from run, candidate, score, and rule-trace
  rows.
- Add State projection tables from group-state and epoch-state rows.
- Remove the all-events timeline tab from the group workspace.
- Provide API readout for group summary, delivery artifacts, network
  observations, convergence runs, state deltas, and evidence refs.
- Add tests for V1/V2 parser behavior and V2 projection building.

### P1

- Redesign the group workspace around Overview, Delivery, Network, Convergence,
  State, Evidence, and Exports.
- Add Delivery matrix with observed versus inferred-missing states.
- Add Network view with transport receipts, relay acknowledgements, publish
  failures, and wire ids.
- Add Convergence run view with branch candidates, scores, and decisive rules.
- Add State view with state-delta history and origin commit links.
- Add UI and API handling for full data auditing, including field-level
  authorization, warnings, exports, and mixed-mode comparisons.
- Add downloadable group forensic JSON exports derived from the engine-scoped
  source files.

### P2

- Add branch graph visualization.
- Add relay/server receipt integration if available.
- Add cross-group/account-level investigation views.
- Add saved investigations, annotations, and shareable internal report links.

## Success Metrics

- An investigator can answer "did this message arrive and process on each
  engine?" without opening raw JSON.
- An engine developer can answer "why did this branch win?" from the convergence
  view, with evidence links.
- A client engineer can identify missing transport receipt, publish failure,
  deferred peel, or MLS processing failure from one message trace.
- Every rendered conclusion links back to raw upload evidence.
- Programmatic API output can reproduce the same conclusions shown in the UI.

## Rollout Plan

Phase 0: Alignment

- Review this PRD with MDK, Goggles, and client owners.
- Turn P0 items into issues.
- Decide which MDK schema gaps are required before UI redesign.

Phase 1: Greenfield Storage And Ingest

- Drop/reset the current Goggles database in development and test environments.
- Replace incremental migration concerns with clean migrations for raw evidence
  and projection tables.
- Accept V1 and V2 raw rows, preserving raw evidence in both cases.
- Store schema version, audit data mode, source metadata, engine/account/group
  refs, and event type in the raw evidence layer.
- Add parser tests and fixtures for V1 and V2.

Phase 2: API and Projections

- Add Delivery, Network, Convergence, and State projection builders.
- Add read APIs with stable schemas and evidence refs.
- Add a rebuild command that can drop and recreate derived projections from raw
  evidence.

Phase 3: UI Redesign

- Remove the all-events timeline tab.
- Build Overview, Delivery, Network, Convergence, State, Evidence, and Exports
  tabs.
- Keep raw evidence drilldowns available from every derived object.

Phase 4: Producer Gaps

- Add MDK audit settings and schema support for obfuscated versus full
  data auditing.
- Add missing MDK audit events for convergence branch explainability.
- Add TypeScript/client audit-log parity.
- Validate emitted logs against the committed schema.

## Decisions From Initial Review

- Convergence runs should eventually be keyed by an MDK-emitted
  `convergence_run_id`. Until then, Goggles may infer provisional runs from
  contiguous convergence and epoch-state rows with the same engine id and group
  ref, and must label those runs as inferred.
- All convergence branch-selection rules must be visible. Goggles should show
  which rules were evaluated, what inputs mattered, what each rule returned, and
  which rule or rules were decisive.
- Expected recipients are knowable from group membership for most messages.
  Normal group messages are expected to reach all other current group members.
  Welcome messages are special: the welcome is expected only by the added member,
  while existing members receive the commit that adds that member.
- Goggles should build relational derived projection tables from raw audit
  events and optimize them for fast investigation workflows. Cached or
  materialized JSON responses can be added later where they help performance.
- Goggles does not need to migrate or preserve current local database contents.
  The redesign can start with a database reset and clean migrations.
- The all-events timeline should be removed as a primary UI surface. The new
  group workspace should use smaller tabs for Delivery, Network, Convergence,
  State, Evidence, and Exports.
- Clients should provide app version, platform, upload trigger, stable device id,
  human-readable device name where available, and the logged-in account public
  key or npub.
- Switching into or out of full data auditing should restart or reopen the
  active recorder session so audit files have an explicit mode boundary.
- During the internal-testing phase, Goggles should retain uploaded audit files,
  including full data auditing files, until an authenticated operator explicitly
  deletes forensic data with the deployment purge command. Access is limited to
  authenticated internal Goggles users, and audit uploads can be paused globally
  during cutovers or incidents.
- The read API should be a stable internal API. It does not need a public
  availability guarantee, but it should be versioned, documented, and reliable
  enough for automation and analysis agents.
- V2 `msg_id`, commit ids, and origin commit ids are canonical Marmot message
  artifact ids. For MLS content-bearing artifacts, they are 64-hex SHA-256
  digests of the MLS content bytes. Transport event ids, Nostr ids, gift-wrap
  ids, and welcome envelope ids must be recorded in explicit transport fields
  instead of overloading `msg_id`.
- Welcome transport identifiers must use explicit field names such as
  `welcome_nostr_event_id`, `welcome_rumor_event_id`, and
  `welcome_key_package_tag` so investigators know which layer produced the id.
- Membership removals must not be inferred from `change_kind` alone.
  `member_removed` with an admin actor represents an admin removal, while
  `member_removed` with `membership_change_source = "convergence"` and no actor
  represents a convergence-resolved departure and must not be rendered as an
  admin action.

## Remaining Open Questions

- What exact schema names and field shapes should MDK use for
  convergence rule outputs, expected-recipient sets, and full data auditing
  message contents?
- Which derived projection tables and indexes are required for the first fast
  Goggles implementation?
- What operator-facing deletion UI should complement the deployment purge
  command after the internal-testing phase?

## Risks

- Inferred missing transport events may be mistaken for proven non-delivery.
- System-stamped audit rows may overwhelm human-action views if not separated.
- Branch explainability will be incomplete unless MDK emits candidate
  details, not just final decisions.
- Rich APIs may accidentally expose sensitive forensic data too broadly without
  tight authentication and careful response design.
- Full data auditing materially increases sensitivity because audit files may
  contain decrypted user messages, full author public keys, and transport ids.
- Mixed-mode uploads may make cross-engine comparisons confusing unless Goggles
  clearly labels which engines have plaintext versus digest-only evidence.
