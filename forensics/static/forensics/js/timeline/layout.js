// Pure geometry for the epoch timeline canvas — a port of the design
// prototype's useTimelineLayout() (Timeline.jsx) adapted to the audit-log
// payload: engines instead of members, ms timestamps, sparse epoch numbers.
// JSON in, plain objects out. No DOM access, fully deterministic.

// The design prototype used COLW 170 / PPM 22 / MINSTEP 20 / GAP 8, tuned
// for sparse mock data. Real audit logs burst events sub-second, so the
// vertical constants are looser to keep dense stretches readable.
export const GUT = 96;      // left gutter width (epoch labels / clock)
export const COLW = 184;    // per-engine column width
export const PPM = 26;      // pixels per minute (vertical scale)
export const THRESH = 4;    // minutes; longer gaps are compressed
export const TOP = 34;      // top padding
export const MINSTEP = 26;  // min vertical px between adjacent timestamps
export const GAP = 14;      // min px gap between stacked items in a column

export const colX = (i) => GUT + i * COLW + COLW / 2;
export const colLeft = (i) => GUT + i * COLW + 8;
export const colInnerW = COLW - 16;

// ---- formatting (string-pure, UTC) ----

// A "—" placeholder for timestamps that cannot be rendered. A ms value can be
// non-finite (null/NaN) or out of JS Date's range (abs ms > 8.64e15), in which
// case `new Date(ms).toISOString()` throws `RangeError: Invalid time value`.
// Ingest bounds wall_time_ms to a sane epoch range, but data stored before
// that guard (or any future bug) could still reach here; one bad value must
// never throw mid-render() and blank the whole timeline + rail. Degrade to a
// placeholder instead.
const TIME_PLACEHOLDER = "—";

const safeDate = (ms) => {
  if (!Number.isFinite(ms) || Math.abs(ms) > 8.64e15) return null;
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? null : d;
};

export const clockOf = (ms) => {
  const d = safeDate(ms);
  return d ? d.toISOString().slice(11, 19) : TIME_PLACEHOLDER;
};

export const dayOf = (ms) => {
  const d = safeDate(ms);
  return d
    ? d.toLocaleDateString("en", { month: "short", day: "numeric", timeZone: "UTC" })
    : TIME_PLACEHOLDER;
};

export const dateOf = (ms) => {
  const d = safeDate(ms);
  return d ? d.toISOString().slice(0, 10) : TIME_PLACEHOLDER;
};

export function fmtGap(min) {
  if (min < 60) return `${Math.round(min)} min`;
  const h = Math.floor(min / 60);
  const m = Math.round(min % 60);
  return m ? `${h}h ${m}m` : `${h}h`;
}

export function fmtDelta(ms) {
  const sign = ms < 0 ? "−" : "+";
  const a = Math.abs(ms);
  if (a < 1000) return `${sign}${a} ms`;
  if (a < 60000) return `${sign}${Math.round(a / 1000)} s`;
  const m = Math.floor(a / 60000);
  const s = Math.round((a % 60000) / 1000);
  return s ? `${sign}${m}m ${s}s` : `${sign}${m}m`;
}

export const short = (hex, n = 8) => (hex ? String(hex).slice(0, n) : "");

// ---- per-item presentation decisions ----

const PEELER_WARNING_OUTCOMES = ["decrypt_failed", "stale_epoch"];
const DEFERRED_MESSAGE_STATES = ["peel_deferred"];
const FAILED_MESSAGE_STATES = ["failed", "epoch_invalidated"];

const failedish = (item) =>
  item.type === "rejection" ||
  (item.type === "peeler_outcome" &&
    item.outcome !== "success" &&
    !PEELER_WARNING_OUTCOMES.includes(item.outcome)) ||
  (item.type === "message_state_changed" &&
    FAILED_MESSAGE_STATES.includes(item.outcome));

const warningish = (item) =>
  item.type === "peeler_retry_burst" ||
  (item.type === "peeler_outcome" && PEELER_WARNING_OUTCOMES.includes(item.outcome)) ||
  (item.type === "message_state_changed" && DEFERRED_MESSAGE_STATES.includes(item.outcome));

const alertTone = (item, fallback) =>
  failedish(item) ? "error" : warningish(item) ? "warning" : fallback;

const plural = (count, word) => `${count} ${word}${count === 1 ? "" : "s"}`;

function detailLine(item) {
  switch (item.type) {
    case "human_action":
      return `${item.human_action_label || item.human_action || "human action"}${item.human_action_phase ? ` · ${item.human_action_phase}` : ""}`;
    case "publish_attempt":
    case "publish_outcome":
    case "publish_failure":
      return item.relay_summary || item.summary || item.type;
    case "ingest_outcome":
      return `${item.outcome || "?"}${item.epoch != null ? ` · epoch ${item.epoch}` : ""}`;
    case "peeler_outcome":
      return `peeler · ${item.outcome || "?"}${item.reason ? ` · ${item.reason}` : ""}`;
    case "peeler_retry_burst":
      return `peeler retry/defer · ${plural(item.message_count || 0, "message")} · ${plural(item.event_count || 0, "event")}`;
    case "message_state_changed":
      return `→ ${item.outcome || "?"}${item.reason ? ` · ${item.reason}` : ""}`;
    case "rejection":
      return `rejected${item.reason ? ` · ${item.reason}` : ""}`;
    default:
      return item.summary || item.type;
  }
}

// ---- the layout ----

export function computeLayout(payload) {
  const engines = payload.engines;
  const n = engines.length;
  const startMs = payload.time.start_ms;
  const epochs = payload.epochs;

  // 1) Build the per-column visual lists -----------------------------------
  // Epoch confirmations become commit nodes (first confirmer) or applied
  // ticks; everything else comes from items[]. Message follow-up events
  // (ingest_outcome, peeler outcome, state changes, rejections) merge into
  // the open card for the same msg on the same engine, so each message
  // reads as one card per column.
  const cols = engines.map(() => []);

  for (const ep of epochs) {
    for (const conf of ep.confirmations) {
      if (conf.engine == null || conf.t == null) continue;
      const isCommit = ep.commit_item_id === conf.item_id;
      cols[conf.engine].push({
        kind: isCommit ? "commit" : "applied",
        t: conf.t,
        h: isCommit ? 30 : 22,
        epoch: ep.epoch,
        fork: ep.fork_status !== "none",
        repeat: !!conf.repeat,
        id: conf.item_id,
      });
    }
  }

  for (const engine of engines) {
    if (engine.first_event_ms != null && startMs != null && engine.first_event_ms > startMs) {
      cols[engine.idx].push({
        kind: "joined",
        t: engine.first_event_ms,
        h: 22,
        id: -1, // sorts ahead of same-time events
      });
    }
  }

  const openCards = engines.map(() => new Map());
  for (const item of payload.items) {
    if (item.role === "commit" || item.role === "applied") continue; // drawn from confirmations
    const col = cols[item.engine];
    if (item.role === "rollback") {
      col.push({ kind: "rollback", t: item.t, h: 24, item, id: item.id });
      continue;
    }
    switch (item.type) {
      case "human_action":
        col.push({
          kind: "card",
          t: item.t,
          item,
          tone: item.tone || "send",
          lines: [
            detailLine(item),
            item.human_action_fields?.length ? `fields · ${item.human_action_fields.join(", ")}` : "",
          ].filter(Boolean),
          id: item.id,
        });
        break;
      case "send_entry":
        col.push({
          kind: "prop",
          t: item.t,
          h: 26,
          text: `${item.human_action_label || "intent"} · ${item.intent_kind || "?"}`,
          item,
          id: item.id,
        });
        break;
      case "auto_commit_decision":
        col.push({
          kind: "prop",
          t: item.t,
          h: 26,
          text: `${item.proposal_kind || "proposal"} · ${item.outcome || "?"}`,
          item,
          id: item.id,
        });
        break;
      case "snapshot_created":
        col.push({ kind: "snapshot", t: item.t, h: 22, item, id: item.id });
        break;
      case "peeler_retry_burst":
        col.push({
          kind: "card",
          t: item.t,
          item,
          tone: "warning",
          lines: [
            detailLine(item),
            item.outcome_summary ? `outcomes · ${item.outcome_summary}` : "",
            item.reason ? `reasons · ${item.reason}` : "",
          ].filter(Boolean),
          id: item.id,
        });
        break;
      case "ingest_entry": {
        const card = {
          kind: "card",
          t: item.t,
          item,
          tone: "receive",
          lines: [`${item.envelope_kind || "message"}${item.payload_len ? ` · ${item.payload_len} B` : ""}`],
          id: item.id,
        };
        col.push(card);
        if (item.msg_id) openCards[item.engine].set(item.msg_id, card);
        break;
      }
      case "ingest_outcome":
      case "peeler_outcome":
      case "message_state_changed":
      case "rejection": {
        const open = item.msg_id ? openCards[item.engine].get(item.msg_id) : null;
        const line = detailLine(item);
        const errorish = failedish(item);
        const warnish = warningish(item);
        if (open) {
          open.lines.push(line);
          if (errorish) open.tone = "error";
          else if (warnish && open.tone !== "error") open.tone = "warning";
          break;
        }
        col.push({
          kind: "card",
          t: item.t,
          item,
          tone: alertTone(item, item.type === "peeler_outcome" ? "receive" : item.tone),
          lines: [line],
          id: item.id,
        });
        break;
      }
      case "send_outcome":
        col.push({
          kind: "card",
          t: item.t,
          item,
          tone: "send",
          lines: [
            item.human_action_label || item.human_action || "send",
            `${item.intent_kind || "send"} → ${item.result_kind || "?"}`,
          ],
          id: item.id,
        });
        break;
      case "publish_attempt":
      case "publish_outcome":
      case "publish_failure":
        col.push({
          kind: "card",
          t: item.t,
          item,
          tone: item.type === "publish_failure" ? "error" : item.tone,
          lines: [
            item.human_action_label || item.human_action || "publish",
            detailLine(item),
          ].filter(Boolean),
          id: item.id,
        });
        break;
      case "fork_resolution":
      case "convergence_decision":
        col.push({ kind: "card", t: item.t, item, tone: "fork", lines: [item.summary], id: item.id });
        break;
      default:
        col.push({
          kind: "card",
          t: item.t,
          item,
          tone: item.tone || "receive",
          lines: [item.human_action_label || item.summary || item.type],
          id: item.id,
        });
    }
  }

  for (const col of cols) {
    for (const visual of col) {
      if (visual.kind === "card") visual.h = 36 + visual.lines.length * 16;
    }
    col.sort((a, b) => a.t - b.t || a.id - b.id);
  }

  // 2) Timestamp set -> y map with idle-gap compression ---------------------
  const tset = new Set();
  for (const col of cols) for (const visual of col) tset.add(visual.t);
  const times = [...tset].sort((a, b) => a - b);

  const ymap = new Map();
  const breaks = [];
  let y = TOP;
  if (times.length) ymap.set(times[0], y);
  for (let k = 1; k < times.length; k++) {
    const dtMin = (times[k] - times[k - 1]) / 60000;
    const prev = y;
    y += Math.max(Math.min(dtMin, THRESH) * PPM, MINSTEP);
    ymap.set(times[k], y);
    if (dtMin > THRESH) breaks.push({ y: (prev + y) / 2, dtMin });
  }
  const Y = (t) => ymap.get(t);

  // 3) Stack each column ----------------------------------------------------
  const entryY = new Map(); // "epoch:engineIdx" -> center y of the entry
  cols.forEach((col, i) => {
    let bottom = 0;
    for (const visual of col) {
      const top = Math.max(Y(visual.t), bottom + GAP);
      visual._y = top;
      bottom = top + visual.h;
      if ((visual.kind === "commit" || visual.kind === "applied") && !visual.repeat) {
        const key = `${visual.epoch}:${i}`;
        if (!entryY.has(key)) entryY.set(key, top + visual.h / 2);
      }
    }
  });

  const allVisuals = cols.flat();
  const canvasH =
    Math.max(y, ...allVisuals.map((visual) => visual._y + visual.h), TOP) + 44;
  const W = GUT + n * COLW;

  // 4) Presence lines -------------------------------------------------------
  const presence = engines
    .filter((engine) => cols[engine.idx].length)
    .map((engine) => {
      const first = cols[engine.idx][0];
      return {
        i: engine.idx,
        x: colX(engine.idx),
        y1: first._y + first.h / 2,
        y2: canvasH - 30,
      };
    });

  // 5) Epoch boundary polylines ---------------------------------------------
  const boundaries = epochs
    .map((ep) => {
      const points = ep.confirmations
        .filter((conf) => conf.engine != null && conf.t != null && !conf.repeat)
        .map((conf) => {
          const cy = entryY.get(`${ep.epoch}:${conf.engine}`);
          return cy == null ? null : [colX(conf.engine), cy];
        })
        .filter(Boolean);
      return points.length > 1 ? { epoch: ep.epoch, points } : null;
    })
    .filter(Boolean);

  // 6) Commit -> late-joiner connectors --------------------------------------
  const connectors = [];
  for (const engine of engines) {
    if (engine.first_event_ms == null || startMs == null || engine.first_event_ms <= startMs) continue;
    const firstConf = epochs
      .flatMap((ep) =>
        ep.confirmations
          .filter((conf) => conf.engine === engine.idx && conf.t != null && !conf.repeat)
          .map((conf) => ({ ep, conf }))
      )
      .sort((a, b) => a.conf.t - b.conf.t)[0];
    if (!firstConf) continue;
    const { ep } = firstConf;
    if (ep.first_confirmed_engine == null || ep.first_confirmed_engine === engine.idx) continue;
    const y1 = entryY.get(`${ep.epoch}:${ep.first_confirmed_engine}`);
    const y2 = entryY.get(`${ep.epoch}:${engine.idx}`);
    if (y1 == null || y2 == null) continue;
    connectors.push({
      x1: colX(ep.first_confirmed_engine),
      y1,
      x2: colX(engine.idx),
      y2,
    });
  }

  // 7) Gutter epoch labels ----------------------------------------------------
  let lastDay = "";
  const gutter = [];
  for (const ep of epochs) {
    if (ep.first_confirmed_ms == null || ep.first_confirmed_engine == null) continue;
    const cy = entryY.get(`${ep.epoch}:${ep.first_confirmed_engine}`);
    if (cy == null) continue;
    const day = dayOf(ep.first_confirmed_ms);
    gutter.push({
      epoch: ep.epoch,
      y: cy,
      day,
      showDay: day !== lastDay,
      clock: clockOf(ep.first_confirmed_ms),
      fork: ep.fork_status !== "none",
    });
    lastDay = day;
  }

  return { W, canvasH, cols, entryY, breaks, presence, boundaries, connectors, gutter };
}

// Last epoch with a confirmed time — the analyst lands on current state.
export function defaultEpoch(payload) {
  let pick = null;
  for (const ep of payload.epochs) {
    if (ep.first_confirmed_ms != null) pick = ep.epoch;
  }
  if (pick == null && payload.epochs.length) {
    pick = payload.epochs[payload.epochs.length - 1].epoch;
  }
  return pick;
}
