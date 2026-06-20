// Entry point for the epoch timeline: parse the embedded payload, compute
// geometry, render the canvas + rail, and wire selection / hover.

import { computeLayout, defaultEpoch } from "./layout.js";
import { render, updateSelection } from "./render.js";
import { renderRail } from "./rail.js";

const mount = document.getElementById("timeline");
const rail = document.getElementById("mls-rail");
const data = document.getElementById("timeline-data");

if (mount && rail && data) {
  const payload = JSON.parse(data.textContent);

  if (!payload.engines.length) {
    mount.innerHTML = `<p class="empty-state">No valid audit events yet — upload audit logs for this group to reconstruct its timeline.</p>`;
    renderRail(rail, payload, null);
  } else {
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
  }
}
