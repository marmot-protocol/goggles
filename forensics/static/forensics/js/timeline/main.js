// Entry point for the epoch timeline: fetch the bounded JSON payload, compute
// geometry, render the canvas + rail, and wire selection / hover.

import { computeLayout, defaultEpoch } from "./layout.js";
import { render, updateSelection } from "./render.js";
import { renderRail } from "./rail.js";

const mount = document.getElementById("timeline");
const rail = document.getElementById("mls-rail");

const showEmpty = (message) => {
  if (mount) mount.innerHTML = `<p class="empty-state">${message}</p>`;
};

const loadPayload = async () => {
  const url = mount?.dataset.timelineUrl;
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

const appendPaginationNote = (payload) => {
  const pagination = payload.pagination;
  if (!pagination?.has_next) return;
  const note = document.createElement("p");
  note.className = "tl-excluded-note";
  note.textContent = `Showing ${payload.items.length} of ${pagination.event_count} timeline events. Use the timeline JSON endpoint page/page_size parameters to inspect another window.`;
  mount.append(note);
};

const boot = (payload) => {
  if (!payload) {
    showEmpty("No timeline payload is available.");
    return;
  }

  if (!payload.engines.length) {
    showEmpty("No valid audit events yet — upload audit logs for this group to reconstruct its timeline.");
    renderRail(rail, payload, null);
    return;
  }

  const layout = computeLayout(payload);
  render(mount, layout, payload);

  let selected = { type: "epoch", epoch: defaultEpoch(payload) };
  updateSelection(mount, selected);
  renderRail(rail, payload, selected);

  const selectFromNode = (target) => {
    const itemNode = target.closest("[data-item-id]");
    if (itemNode && mount.contains(itemNode)) {
      selected = {
        type: "item",
        itemId: itemNode.dataset.itemId,
        epoch: itemNode.dataset.epoch ? Number(itemNode.dataset.epoch) : null,
      };
      updateSelection(mount, selected);
      renderRail(rail, payload, selected);
      return true;
    }

    const epochNode = target.closest("[data-epoch]");
    if (!epochNode || !mount.contains(epochNode)) return false;
    selected = { type: "epoch", epoch: Number(epochNode.dataset.epoch) };
    updateSelection(mount, selected);
    renderRail(rail, payload, selected);
    return true;
  };

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

  if (payload.excluded.count) {
    const note = document.createElement("p");
    note.className = "tl-excluded-note";
    note.textContent = `${payload.excluded.count} event(s) could not be placed (missing wall time or engine) — see the Messages tab.`;
    mount.append(note);
  }
  appendPaginationNote(payload);
};

if (mount && rail) {
  loadPayload().then(boot).catch((error) => {
    showEmpty(`Could not load timeline (${error.message}).`);
  });
}
