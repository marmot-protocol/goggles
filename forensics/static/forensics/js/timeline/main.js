// Entry point for the epoch timeline: fetch the bounded JSON payload, compute
// geometry, render the canvas + rail, and wire selection / hover.

import { computeLayout, defaultEpoch } from "./layout.js";
import { render, updateSelection } from "./render.js";
import { renderRail } from "./rail.js";

const mount = document.getElementById("timeline");
const rail = document.getElementById("mls-rail");

let activePayload = null;
let selected = null;

const showEmpty = (message) => {
  if (mount) mount.innerHTML = `<p class="empty-state">${message}</p>`;
};

const timelineUrl = (page) => {
  const baseUrl = mount?.dataset.timelineUrl;
  if (!baseUrl) return null;
  const url = new URL(baseUrl, window.location.href);
  if (page) url.searchParams.set("page", String(page));
  return url;
};

const loadPayload = async (page) => {
  const url = timelineUrl(page);
  if (url) {
    const response = await fetch(url, { headers: { Accept: "application/json" } });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return response.json();
  }

  // Backward-compatible fallback for static fixtures or cached pages that still
  // embed the old json_script payload.
  const data = document.getElementById("timeline-data");
  return data ? JSON.parse(data.textContent) : null;
};

const pageButton = (label, page) => {
  if (!page) return `<span class="pagination__link is-disabled">${label}</span>`;
  return `<button type="button" class="pagination__link" data-timeline-page="${page}">${label}</button>`;
};

const appendPaginationControls = (payload) => {
  const pagination = payload.pagination;
  if (!pagination || pagination.page_count <= 1) return;

  const nav = document.createElement("nav");
  nav.className = "pagination timeline-pagination";
  nav.setAttribute("aria-label", "Timeline pages");
  const previousPage = pagination.has_previous ? pagination.page - 1 : null;
  const nextPage = pagination.has_next ? pagination.page + 1 : null;
  nav.innerHTML = `
    ${pageButton("Previous", previousPage)}
    <span class="pagination__status">Showing ${payload.items.length} of ${pagination.event_count} timeline events · page ${pagination.page} of ${pagination.page_count}</span>
    ${pageButton("Next", nextPage)}`;
  nav.addEventListener("click", (event) => {
    const button = event.target.closest("[data-timeline-page]");
    if (!button) return;
    loadPage(Number(button.dataset.timelinePage));
  });
  mount.append(nav);
};

const selectFromNode = (target) => {
  if (!activePayload) return false;

  const itemNode = target.closest("[data-item-id]");
  if (itemNode && mount.contains(itemNode)) {
    selected = {
      type: "item",
      itemId: itemNode.dataset.itemId,
      epoch: itemNode.dataset.epoch ? Number(itemNode.dataset.epoch) : null,
    };
    updateSelection(mount, selected);
    renderRail(rail, activePayload, selected);
    return true;
  }

  const epochNode = target.closest("[data-epoch]");
  if (!epochNode || !mount.contains(epochNode)) return false;
  selected = { type: "epoch", epoch: Number(epochNode.dataset.epoch) };
  updateSelection(mount, selected);
  renderRail(rail, activePayload, selected);
  return true;
};

const bindInteractions = () => {
  mount.addEventListener("click", (e) => {
    selectFromNode(e.target);
  });

  mount.addEventListener("keydown", (e) => {
    if (e.key !== "Enter" && e.key !== " ") return;
    if (!selectFromNode(e.target)) return;
    e.preventDefault();
  });

  // Related-event highlight: hovering anything that carries a msg/digest
  // key lights up every other occurrence of that key across columns.
  mount.addEventListener("mouseover", (e) => {
    const source = e.target.closest("[data-related]");
    if (!source) return;
    const key = source.dataset.related;
    for (const node of mount.querySelectorAll("[data-related]")) {
      node.classList.toggle("is-related", node.dataset.related === key);
    }
  });
  mount.addEventListener("mouseout", (e) => {
    if (e.target.closest("[data-related]")) {
      for (const node of mount.querySelectorAll(".is-related")) {
        node.classList.remove("is-related");
      }
    }
  });
};

const boot = (payload) => {
  activePayload = payload;
  selected = null;
  if (!payload) {
    showEmpty("No timeline payload is available.");
    return;
  }

  if (!payload.engines.length) {
    showEmpty("No valid audit events yet — upload audit logs for this group to reconstruct its timeline.");
    renderRail(rail, payload, null);
    appendPaginationControls(payload);
    return;
  }

  const layout = computeLayout(payload);
  render(mount, layout, payload);

  selected = { type: "epoch", epoch: defaultEpoch(payload) };
  updateSelection(mount, selected);
  renderRail(rail, payload, selected);

  if (payload.excluded.count) {
    const note = document.createElement("p");
    note.className = "tl-excluded-note";
    note.textContent = `${payload.excluded.count} event(s) could not be placed (missing wall time or engine) — see the Messages tab.`;
    mount.append(note);
  }
  appendPaginationControls(payload);
};

const loadPage = (page) => {
  if (mount) mount.innerHTML = `<p class="empty-state">Loading timeline…</p>`;
  if (rail) rail.innerHTML = "";
  loadPayload(page).then(boot).catch((error) => {
    activePayload = null;
    selected = null;
    showEmpty(`Could not load timeline (${error.message}).`);
  });
};

if (mount && rail) {
  bindInteractions();
  loadPage();
}
