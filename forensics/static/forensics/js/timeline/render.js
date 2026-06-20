// DOM/SVG construction for the timeline canvas. Builds one innerHTML string
// (no per-node listeners — main.js delegates clicks/hover on the mount) and
// keeps selection updates to a class/aria toggle so re-render never happens.

import { GUT, COLW, colX, colLeft, colInnerW, clockOf, fmtGap, short } from "./layout.js";

export const esc = (value) =>
  String(value ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[c]);

export const icon = (name, size = 14) =>
  `<svg class="icon" width="${size}" height="${size}" aria-hidden="true"><use href="#i-${name}"/></svg>`;

const avatar = (engine, size = 26) =>
  `<span class="avatar avatar--${size}" style="--avatar-color: var(--viz-${engine.color_index})" title="${esc(engine.label || engine.short)}">${esc(engine.initials)}</span>`;

const enginePrimary = (engine) =>
  engine.label ? engine.label.split(" / ")[0] : engine.short;

function columnHeader(payload) {
  const cells = payload.engines.map((engine) => {
    const joined =
      engine.first_event_ms != null &&
      payload.time.start_ms != null &&
      engine.first_event_ms > payload.time.start_ms;
    const badge = joined
      ? `<span class="badge">joined · ${clockOf(engine.first_event_ms)}</span>`
      : `<span class="badge badge--accent">founder</span>`;
    return `
      <div class="tl-colhead__cell">
        <div class="tl-colhead__who">
          ${avatar(engine)}
          <div class="tl-colhead__names">
            <div class="tl-colhead__name">${esc(enginePrimary(engine))}</div>
            <div class="tl-colhead__sub">${esc(engine.short)}</div>
          </div>
        </div>
        ${badge}
      </div>`;
  });
  return `
    <div class="tl-colhead" style="width:${GUT + payload.engines.length * COLW}px; grid-template-columns:${GUT}px repeat(${payload.engines.length}, ${COLW}px)">
      <div class="tl-colhead__gutter">
        <span class="eyebrow">Wall clock</span>
        <span class="tl-colhead__arrow">${icon("arrow-down", 10)}</span>
      </div>
      ${cells.join("")}
    </div>`;
}

function svgOverlay(layout) {
  const presence = layout.presence
    .map(
      (p) =>
        `<line x1="${p.x}" y1="${p.y1}" x2="${p.x}" y2="${p.y2}" stroke="var(--border-default)" stroke-width="1.5" stroke-dasharray="2 6"/>`
    )
    .join("");
  const boundaries = layout.boundaries
    .map(
      (b) =>
        `<polyline points="${b.points.map((pt) => pt.join(",")).join(" ")}" fill="none" stroke="var(--accent)" stroke-width="1.5" stroke-dasharray="1 5" opacity="0.5"/>`
    )
    .join("");
  const connectors = layout.connectors
    .map((c) => {
      const my = (c.y1 + c.y2) / 2 + 8;
      return `<path d="M${c.x1} ${c.y1} C ${c.x1} ${my} ${c.x2} ${my} ${c.x2} ${c.y2 - 8}" fill="none" stroke="var(--accent)" stroke-width="2" stroke-dasharray="5 4" marker-end="url(#tl-arw)"/>`;
    })
    .join("");
  const breaks = layout.breaks
    .map(
      (b) =>
        `<line x1="${GUT - 6}" y1="${b.y}" x2="${layout.W}" y2="${b.y}" stroke="var(--border-subtle)" stroke-width="1" stroke-dasharray="2 6"/>`
    )
    .join("");
  return `
    <svg class="tl-svg" width="${layout.W}" height="${layout.canvasH}">
      <defs>
        <marker id="tl-arw" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
          <path d="M0 1 L9 5 L0 9 z" fill="var(--accent)"/>
        </marker>
      </defs>
      ${presence}${boundaries}${connectors}${breaks}
    </svg>`;
}

const TONE_BADGE = {
  error: (visual) =>
    `<span class="badge badge--danger"><span class="badge__dot"></span>${esc(visual.item.outcome || "failed")}</span>`,
  warning: (visual) =>
    `<span class="badge badge--warning"><span class="badge__dot"></span>${esc(visual.item.outcome || "attention")}</span>`,
  fork: () => `<span class="badge badge--warning">fork</span>`,
};

const itemAttrs = (item, { interactive = true } = {}) => {
  if (!item?.id) return "";
  const base = `data-item-id="${esc(item.id)}" aria-pressed="false"`;
  return interactive ? `${base} role="button" tabindex="0"` : base;
};

function cardEl(visual, x) {
  const item = visual.item;
  const badge = TONE_BADGE[visual.tone] ? TONE_BADGE[visual.tone](visual) : "";
  const ref = item.msg_id || item.digest;
  const title = item.human_action || item.type;
  const lines = visual.lines
    .map((line) => `<div class="tl-card__line">${esc(line)}</div>`)
    .join("");
  const related = item.related_key ? ` data-related="${esc(item.related_key)}"` : "";
  return `
    <div class="tl-card tl-card--${visual.tone}" ${itemAttrs(item)}${related} title="${esc(title)} · seq ${esc(item.seq)}${ref ? ` · ${esc(ref)}` : ""}"
      style="left:${x}px; top:${visual._y}px; width:${colInnerW}px; min-height:${visual.h - 6}px">
      <div class="tl-card__head"><span class="tl-card__clock">${clockOf(visual.t)}</span>${badge}</div>
      ${ref ? `<div class="tl-card__msg">${esc(short(ref, 12))}</div>` : ""}
      ${lines}
    </div>`;
}

export function render(mount, layout, payload) {
  const els = [];
  const firstEpoch = payload.epochs.find((ep) => ep.first_confirmed_ms != null);

  for (const g of layout.gutter) {
    els.push(`
      <div class="tl-gutter-label" style="top:${g.y - 15}px">
        <div class="tl-gutter-label__epoch${g.fork ? " is-fork" : ""}">E${esc(g.epoch)}</div>
        ${g.showDay ? `<div class="tl-gutter-label__day">${esc(g.day)}</div>` : ""}
        <div class="tl-gutter-label__clock">${g.clock}</div>
      </div>`);
  }

  for (const b of layout.breaks) {
    els.push(`
      <div class="tl-break-label" style="top:${b.y}px">
        <span>${esc(fmtGap(b.dtMin))} later</span>
      </div>`);
  }

  layout.cols.forEach((col, i) => {
    const x = colLeft(i);
    for (const visual of col) {
      if (visual.kind === "commit") {
        const create = firstEpoch && visual.epoch === firstEpoch.epoch;
        els.push(`
          <button type="button" class="tl-commit${visual.fork ? " tl-commit--fork" : ""}" data-epoch="${esc(visual.epoch)}" ${itemAttrs({ id: visual.id }, { interactive: false })}
            style="left:${x}px; top:${visual._y}px; width:${colInnerW}px">
            ${icon(create ? "home" : "branch", 13)}
            <span>E${esc(visual.epoch)}</span>
            <span class="tl-commit__clock">${clockOf(visual.t)}</span>
          </button>`);
        continue;
      }
      if (visual.kind === "applied") {
        els.push(`
          <div class="tl-pill tl-pill--applied" ${itemAttrs({ id: visual.id })} style="left:${x}px; top:${visual._y}px; width:${colInnerW}px" title="epoch ${esc(visual.epoch)} confirmed${visual.repeat ? " (repeat)" : ""}">
            ${icon("corner-down", 12)}<span>${visual.repeat ? "re-applied" : "applied"} E${esc(visual.epoch)}</span>
            <span class="tl-pill__clock">${clockOf(visual.t)}</span>
          </div>`);
        continue;
      }
      if (visual.kind === "joined") {
        els.push(`
          <div class="tl-pill tl-pill--joined" style="left:${x}px; top:${visual._y}px; width:${colInnerW}px">
            ${icon("user-plus", 12)}<span>first seen</span>
            <span class="tl-pill__clock">${clockOf(visual.t)}</span>
          </div>`);
        continue;
      }
      if (visual.kind === "rollback") {
        const item = visual.item;
        els.push(`
          <button type="button" class="tl-pill tl-pill--rollback" data-epoch="${esc(item.epoch)}" ${itemAttrs(item, { interactive: false })}
            style="left:${x}px; top:${visual._y}px; width:${colInnerW}px" title="${esc(item.summary)}">
            ${icon("alert", 12)}<span>${esc(item.summary || "rollback")}</span>
            <span class="tl-pill__clock">${clockOf(visual.t)}</span>
          </button>`);
        continue;
      }
      if (visual.kind === "snapshot") {
        const item = visual.item;
        els.push(`
          <div class="tl-pill tl-pill--snapshot" ${itemAttrs(item)} style="left:${x}px; top:${visual._y}px; width:${colInnerW}px" title="${esc(item.snapshot_name || "snapshot")}${item.reason ? ` · ${esc(item.reason)}` : ""}">
            ${icon("camera", 12)}<span>${esc(item.snapshot_name || "snapshot")}</span>
            <span class="tl-pill__clock">${clockOf(visual.t)}</span>
          </div>`);
        continue;
      }
      if (visual.kind === "prop") {
        els.push(`
          <div class="tl-prop" ${itemAttrs(visual.item)} style="left:${x}px; top:${visual._y}px; width:${colInnerW}px" title="${esc(visual.text)}">
            <span class="tl-prop__tag">prop</span>
            <span class="tl-prop__text">${esc(visual.text)}</span>
          </div>`);
        continue;
      }
      els.push(cardEl(visual, x));
    }
  });

  mount.innerHTML = `
    ${columnHeader(payload)}
    <div class="tl-canvas" style="width:${layout.W}px; height:${layout.canvasH}px">
      ${svgOverlay(layout)}
      ${els.join("")}
    </div>`;
}

export function updateSelection(mount, selection) {
  const epoch = typeof selection === "object" ? selection.epoch : selection;
  const itemId = typeof selection === "object" ? selection.itemId : null;
  for (const node of mount.querySelectorAll("[data-epoch]")) {
    const on = itemId == null && node.dataset.epoch === String(epoch);
    node.classList.toggle("is-selected", on);
    node.setAttribute("aria-pressed", String(on));
  }
  for (const node of mount.querySelectorAll("[data-item-id]")) {
    if (itemId == null && node.dataset.epoch != null) continue;
    const on = itemId != null && node.dataset.itemId === String(itemId);
    node.classList.toggle("is-selected", on);
    node.setAttribute("aria-pressed", String(on));
  }
}
