// Hash-driven tab bar: buttons carry role=tab + data-panel pointing at the
// panel id. Deep links (#messages) and back/forward both resolve via hash.
// Heavy panels can opt into data-lazy-url; their HTML is fetched once, only
// when the analyst selects the tab.
const tabs = Array.from(document.querySelectorAll('.tab[role="tab"][data-panel]'));

const lazyStates = new WeakMap();

const loadPanel = async (panel) => {
  const url = panel.dataset.lazyUrl;
  if (!url || lazyStates.get(panel) === "loaded" || lazyStates.get(panel) === "loading") return;

  lazyStates.set(panel, "loading");
  panel.innerHTML = `<p class="empty-state">Loading…</p>`;
  try {
    const response = await fetch(url, { headers: { "X-Requested-With": "fetch" } });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    panel.innerHTML = await response.text();
    lazyStates.set(panel, "loaded");
  } catch (error) {
    lazyStates.delete(panel);
    panel.innerHTML = `<p class="empty-state">Could not load this tab (${error.message}).</p>`;
  }
};

if (tabs.length) {
  const select = (tab, focus = false) => {
    let selectedPanel = null;
    for (const t of tabs) {
      const on = t === tab;
      t.setAttribute("aria-selected", String(on));
      t.tabIndex = on ? 0 : -1;
      const panel = document.getElementById(t.dataset.panel);
      if (panel) {
        panel.hidden = !on;
        if (on) selectedPanel = panel;
      }
    }
    if (selectedPanel) loadPanel(selectedPanel);
    if (focus) tab.focus();
  };

  const fromHash = () => {
    const id = `panel-${location.hash.slice(1)}`;
    return tabs.find((t) => t.dataset.panel === id);
  };

  for (const tab of tabs) {
    tab.addEventListener("click", () => {
      history.replaceState(null, "", `#${tab.dataset.panel.replace(/^panel-/, "")}`);
      select(tab);
    });
    tab.addEventListener("keydown", (e) => {
      if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
      e.preventDefault();
      const step = e.key === "ArrowRight" ? 1 : -1;
      const next = tabs[(tabs.indexOf(tab) + step + tabs.length) % tabs.length];
      history.replaceState(null, "", `#${next.dataset.panel.replace(/^panel-/, "")}`);
      select(next, true);
    });
  }

  window.addEventListener("hashchange", () => select(fromHash() || tabs[0]));
  select(fromHash() || tabs[0]);
}
