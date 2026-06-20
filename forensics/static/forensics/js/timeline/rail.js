// Right-hand rail: group state derived from audit logs at the selected
// epoch. The prototype showed ratchet-tree / key-schedule mocks; the audit
// schema has neither, so the rail shows what the logs actually prove:
// confirmation staggering across engines, forks, rollbacks, and snapshots.

import { clockOf, dateOf, fmtDelta, fmtGap, short } from "./layout.js";
import { esc, icon } from "./render.js";

const row = (label, value, { mono = true } = {}) => `
  <div class="rail-row">
    <span class="eyebrow">${esc(label)}</span>
    <span class="rail-row__value${mono ? " is-mono" : ""}">${value}</span>
  </div>`;

const engineName = (payload, idx) => {
  const engine = payload.engines[idx];
  if (!engine) return "unknown engine";
  return engine.label ? engine.label.split(" / ")[0] : engine.short;
};

const engineAvatar = (payload, idx) => {
  const engine = payload.engines[idx];
  if (!engine) return "";
  return `<span class="avatar avatar--26" style="--avatar-color: var(--viz-${engine.color_index})">${esc(engine.initials)}</span>`;
};

const labelize = (value) =>
  String(value || "")
    .replace(/_/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());

const dash = (value) => (value == null || value === "" ? "–" : esc(value));

const compactList = (values, { mono = true } = {}) => {
  const items = (values || []).filter((value) => value != null && value !== "");
  if (!items.length) return "–";
  return `<span class="rail-list${mono ? " is-mono" : ""}">${items
    .map((value) => `<span>${esc(value)}</span>`)
    .join("")}</span>`;
};

const itemBadge = (item) => {
  if (item.tone === "error") {
    return `<span class="badge badge--danger"><span class="badge__dot"></span>${esc(item.outcome || "error")}</span>`;
  }
  if (item.tone === "warning" || item.tone === "fork") {
    return `<span class="badge badge--warning"><span class="badge__dot"></span>${esc(item.outcome || item.tone)}</span>`;
  }
  if (item.tone === "send") {
    return `<span class="badge badge--info"><span class="badge__dot"></span>send</span>`;
  }
  return `<span class="badge"><span class="badge__dot"></span>${esc(item.tone || "event")}</span>`;
};

function statusBadge(ep) {
  if (ep.fork_status === "resolved") {
    return `<span class="badge badge--danger"><span class="badge__dot"></span>fork resolved</span>`;
  }
  if (ep.fork_status === "suspected") {
    return `<span class="badge badge--danger"><span class="badge__dot"></span>fork suspected</span>`;
  }
  return `<span class="badge badge--accent"><span class="badge__dot"></span>verified</span>`;
}

function confirmationList(payload, ep) {
  if (!ep.confirmations.length) {
    return `<p class="rail-note">Never confirmed in any uploaded log — known only from ${
      ep.rollbacks.length ? "a rollback" : "references by other events"
    }.</p>`;
  }
  const first = ep.confirmations.find((conf) => conf.t != null);
  const rows = ep.confirmations
    .map((conf) => {
      const delta =
        first && conf.t != null && conf.item_id !== first.item_id
          ? `<span class="rail-confirm__delta">${esc(fmtDelta(conf.t - first.t))}</span>`
          : conf.item_id === first?.item_id
            ? `<span class="rail-confirm__delta is-first">first</span>`
            : "";
      return `
        <div class="rail-confirm">
          ${conf.engine != null ? engineAvatar(payload, conf.engine) : ""}
          <span class="rail-confirm__name">${esc(conf.engine != null ? engineName(payload, conf.engine) : "?")}${conf.repeat ? " · repeat" : ""}</span>
          <span class="rail-confirm__clock">${conf.t != null ? clockOf(conf.t) : "time unknown"}</span>
          ${delta}
        </div>`;
    })
    .join("");
  const missingEngines = ep.unconfirmed_engines || [];
  const missing = missingEngines.length
    ? `<p class="rail-note rail-note--danger">${icon("alert", 12)} never confirmed by ${esc(
        missingEngines.map((idx) => engineName(payload, idx)).join(", ")
      )}</p>`
    : "";
  return `<div class="rail-confirm-list">${rows}</div>${missing}`;
}

function initiatorSummary(payload, ep) {
  const initiators = ep.initiators || [];
  if (!initiators.length) return "";
  const names = initiators
    .map((initiator) =>
      initiator.engine != null ? engineName(payload, initiator.engine) : "unknown engine"
    )
    .join(", ");
  const action = initiators.find((initiator) => initiator.action)?.action || "";
  return `${esc(names)}${action ? ` · ${esc(action)}` : ""}`;
}

function forkSection(payload, ep) {
  const parts = [];
  for (const fork of ep.forks) {
    parts.push(`
      <div class="rail-detail rail-detail--danger">
        <div class="rail-detail__title">${icon("branch", 12)} fork resolved · winner ${esc(fork.winner || "?")}</div>
        ${fork.candidate_digest ? `<div class="rail-detail__line">candidate <span class="is-mono">${esc(short(fork.candidate_digest, 12))}</span></div>` : ""}
        ${fork.incumbent_digest ? `<div class="rail-detail__line">incumbent <span class="is-mono">${esc(short(fork.incumbent_digest, 12))}</span></div>` : ""}
        ${fork.invalidated_msg_id ? `<div class="rail-detail__line">invalidated <span class="is-mono">${esc(short(fork.invalidated_msg_id, 12))}</span></div>` : ""}
        <div class="rail-detail__line">${esc(fork.engine != null ? engineName(payload, fork.engine) : "?")}${fork.t != null ? ` · ${clockOf(fork.t)}` : ""}</div>
      </div>`);
  }
  for (const conv of ep.convergences) {
    parts.push(`
      <div class="rail-detail">
        <div class="rail-detail__title">${icon("check", 12)} convergence · tip ${esc(conv.current_tip_epoch)} → ${esc(conv.selected_tip_epoch ?? "–")}</div>
        ${conv.selected_branch_id ? `<div class="rail-detail__line">branch <span class="is-mono">${esc(conv.selected_branch_id)}</span></div>` : ""}
        <div class="rail-detail__line">${esc(conv.candidate_count ?? "?")} candidate(s) · ${esc(conv.eligible_count ?? "?")} eligible</div>
      </div>`);
  }
  for (const rb of ep.rollbacks) {
    parts.push(`
      <div class="rail-detail rail-detail--danger">
        <div class="rail-detail__title">${icon("alert", 12)} ${rb.role === "abandoned" ? "rolled back" : "restored by rollback"}</div>
        <div class="rail-detail__line">E${esc(rb.pending_epoch)} → E${esc(rb.restored_epoch)}${rb.pending_kind ? ` · ${esc(rb.pending_kind)}` : ""}</div>
        <div class="rail-detail__line">${esc(rb.engine != null ? engineName(payload, rb.engine) : "?")}${rb.t != null ? ` · ${clockOf(rb.t)}` : ""}</div>
      </div>`);
  }
  for (const snap of ep.snapshots) {
    parts.push(`
      <div class="rail-detail">
        <div class="rail-detail__title">${icon("camera", 12)} snapshot · <span class="is-mono">${esc(snap.snapshot_name || "?")}</span></div>
        ${snap.reason ? `<div class="rail-detail__line">${esc(snap.reason)}</div>` : ""}
      </div>`);
  }
  return parts.join("");
}

function renderEventRail(aside, payload, itemId) {
  const item = payload.items.find((entry) => String(entry.id) === String(itemId));
  if (!item) {
    aside.innerHTML = `
      <div class="rail-head">
        <span class="eyebrow">Event detail</span>
      </div>
      <p class="rail-note">The selected timeline item is no longer present in the current payload.</p>`;
    return;
  }

  const engine = payload.engines[item.engine];
  const title =
    item.human_action_label ||
    item.summary ||
    item.snapshot_name ||
    labelize(item.type || "event");
  const engineValue = engine
    ? `${esc(engineName(payload, item.engine))}<span class="rail-inline-id is-mono">${esc(engine.engine_id)}</span>`
    : "–";
  const sourceValue = [
    item.file_id != null ? `file ${item.file_id}` : "",
    item.line != null ? `line ${item.line}` : "",
  ]
    .filter(Boolean)
    .join(" · ");

  const basics = [
    row("Type", dash(item.type), { mono: false }),
    row("Time", `${esc(dateOf(item.t))} ${clockOf(item.t)} UTC`),
    row("Wall ms", dash(item.t)),
    row("Engine", engineValue, { mono: false }),
    item.seq != null ? row("Seq", dash(item.seq)) : "",
    sourceValue ? row("Source", esc(sourceValue), { mono: false }) : "",
    item.epoch != null ? row("Epoch", `E${esc(item.epoch)}`) : "",
  ].join("");

  const messageRows = [
    item.msg_id ? row("Message", esc(item.msg_id)) : "",
    item.message_ids?.length ? row("Messages", compactList(item.message_ids)) : "",
    item.digest ? row("Digest", esc(item.digest)) : "",
    item.related_key ? row("Related key", esc(item.related_key)) : "",
  ].join("");

  const outcomeRows = [
    item.summary ? row("Summary", esc(item.summary), { mono: false }) : "",
    item.outcome ? row("Outcome", esc(item.outcome), { mono: false }) : "",
    item.outcome_summary ? row("Outcomes", esc(item.outcome_summary), { mono: false }) : "",
    item.reason ? row("Reason", esc(item.reason), { mono: false }) : "",
    item.relay_summary ? row("Relay", esc(item.relay_summary), { mono: false }) : "",
  ].join("");

  const actionRows = [
    item.operation_id ? row("Operation", esc(item.operation_id)) : "",
    item.human_action ? row("Action", esc(item.human_action), { mono: false }) : "",
    item.human_action_origin ? row("Origin", esc(item.human_action_origin), { mono: false }) : "",
    item.human_action_phase ? row("Phase", esc(item.human_action_phase), { mono: false }) : "",
    item.human_action_fields?.length
      ? row("Fields", compactList(item.human_action_fields, { mono: false }), { mono: false })
      : "",
    item.intent_kind ? row("Intent", esc(item.intent_kind), { mono: false }) : "",
    item.result_kind ? row("Result", esc(item.result_kind), { mono: false }) : "",
    item.proposal_kind ? row("Proposal", esc(item.proposal_kind), { mono: false }) : "",
    item.target_kind ? row("Target", esc(item.target_kind), { mono: false }) : "",
  ].join("");

  const burstRows = [
    item.message_count != null ? row("Message count", esc(item.message_count)) : "",
    item.event_count != null ? row("Event count", esc(item.event_count)) : "",
    item.source_event_ids?.length ? row("Source events", compactList(item.source_event_ids)) : "",
  ].join("");

  aside.innerHTML = `
    <div class="rail-head">
      <div class="rail-head__row">
        <span class="eyebrow">Event detail · from timeline</span>
        ${itemBadge(item)}
      </div>
      <h2>${esc(title)}</h2>
    </div>

    <div class="card card--flat rail-card">${basics}</div>
    ${messageRows ? `<div class="rail-section"><div class="eyebrow">Message identity</div><div class="card card--flat rail-card">${messageRows}</div></div>` : ""}
    ${outcomeRows ? `<div class="rail-section"><div class="eyebrow">Outcome</div><div class="card card--flat rail-card">${outcomeRows}</div></div>` : ""}
    ${actionRows ? `<div class="rail-section"><div class="eyebrow">Action context</div><div class="card card--flat rail-card">${actionRows}</div></div>` : ""}
    ${burstRows ? `<div class="rail-section"><div class="eyebrow">Compacted evidence</div><div class="card card--flat rail-card">${burstRows}</div></div>` : ""}

    <p class="rail-basis">${icon("clock", 11)} per-device wall-clock event detail</p>`;
}

export function renderRail(aside, payload, selection) {
  if (selection && typeof selection === "object" && selection.type === "item") {
    renderEventRail(aside, payload, selection.itemId);
    return;
  }

  const epochNumber =
    selection && typeof selection === "object" ? selection.epoch : selection;
  const ep = payload.epochs.find((entry) => entry.epoch === epochNumber);
  if (!ep) {
    aside.innerHTML = `
      <div class="rail-head">
        <span class="eyebrow">MLS state</span>
      </div>
      <p class="rail-note">No epoch structure observed yet — upload logs containing epoch confirmations.</p>`;
    return;
  }

  const first = ep.confirmations.find((conf) => conf.t != null);
  const committer = first?.engine != null ? engineName(payload, first.engine) : null;
  const initiator = initiatorSummary(payload, ep);
  const transition =
    first?.from_epoch != null ? `${first.from_epoch} → ${ep.epoch}` : `${ep.epoch}`;
  const confirmedCount = new Set(
    ep.confirmations.filter((conf) => conf.engine != null).map((conf) => conf.engine)
  ).size;

  const meta = [
    row("Epoch", esc(ep.epoch)),
    row("Transition", esc(transition)),
    first?.pending_kind ? row("Pending kind", esc(first.pending_kind)) : "",
    initiator ? row("Initiator", initiator, { mono: false }) : "",
    ep.first_confirmed_ms != null
      ? row("First confirmed", `${esc(dateOf(ep.first_confirmed_ms))} ${clockOf(ep.first_confirmed_ms)} UTC`)
      : row("First confirmed", "–"),
    committer ? row("First confirmer", esc(committer), { mono: false }) : "",
    row("Engines confirmed", `${confirmedCount} of ${payload.engines.length}`),
    ep.spread_ms != null ? row("Apply spread", esc(fmtGap(ep.spread_ms / 60000))) : "",
    row("Message events", esc(ep.message_event_count)),
  ].join("");

  const forkDetails = forkSection(payload, ep);

  aside.innerHTML = `
    <div class="rail-head">
      <div class="rail-head__row">
        <span class="eyebrow">MLS state · from audit logs</span>
        ${statusBadge(ep)}
      </div>
      <h2>Epoch ${esc(ep.epoch)}</h2>
    </div>

    <div class="card card--flat rail-card">${meta}</div>

    <div class="rail-section">
      <div class="eyebrow">Confirmed by engine</div>
      ${confirmationList(payload, ep)}
    </div>

    ${forkDetails ? `<div class="rail-section"><div class="eyebrow">Fork · rollback · snapshots</div>${forkDetails}</div>` : ""}

    <p class="rail-basis">${icon("clock", 11)} per-device wall clocks — deltas can be skewed</p>`;
}
