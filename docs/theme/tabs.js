// AI Agent Assembly — hand-rolled mdBook tabs widget (AAASM-4566).
//
// Authors write plain markup in .md files:
//
//   <div class="aaasm-tabs">
//     <div class="aaasm-tab" data-title="Python">...</div>
//     <div class="aaasm-tab" data-title="Node.js">...</div>
//   </div>
//
// This script finds each `.aaasm-tabs` container, builds a tab-button list
// from the `data-title` of its direct `.aaasm-tab` children, and toggles
// which child is visible. No preprocessor/build step — loaded via
// book.toml's `additional-js`, same mechanism as mermaid-init.js.
//
// A tab div may carry an author-supplied `id` (AAASM-4574) — e.g. to keep a
// pre-existing heading anchor working after the section was converted to a
// tab. When present it's kept as the panel id instead of being overwritten,
// and `activateHash()` below makes `#that-id` links actually switch to and
// reveal the tab, rather than just scrolling to a hidden panel.
(function () {
  'use strict';

  function initTabs(container, index) {
    var panels = Array.prototype.filter.call(container.children, function (child) {
      return child.classList.contains('aaasm-tab');
    });
    if (panels.length === 0) {
      return;
    }

    var list = document.createElement('ul');
    list.className = 'aaasm-tabs__list';
    list.setAttribute('role', 'tablist');

    panels.forEach(function (panel, panelIndex) {
      var tabId = 'aaasm-tab-' + index + '-' + panelIndex;
      var panelId = panel.id || ('aaasm-panel-' + index + '-' + panelIndex);
      var selected = panelIndex === 0;

      panel.classList.remove('aaasm-tab');
      panel.classList.add('aaasm-tabs__panel');
      panel.id = panelId;
      panel.setAttribute('role', 'tabpanel');
      panel.setAttribute('aria-labelledby', tabId);
      if (!selected) {
        panel.hidden = true;
      }

      var item = document.createElement('li');
      item.setAttribute('role', 'presentation');

      var button = document.createElement('button');
      button.type = 'button';
      button.id = tabId;
      button.className = 'aaasm-tabs__button';
      button.setAttribute('role', 'tab');
      button.setAttribute('aria-selected', String(selected));
      button.setAttribute('aria-controls', panelId);
      button.textContent = panel.getAttribute('data-title') || 'Tab ' + (panelIndex + 1);

      button.addEventListener('click', function () {
        panels.forEach(function (p) {
          p.hidden = true;
        });
        list.querySelectorAll('.aaasm-tabs__button').forEach(function (b) {
          b.setAttribute('aria-selected', 'false');
        });
        panel.hidden = false;
        button.setAttribute('aria-selected', 'true');
      });

      item.appendChild(button);
      list.appendChild(item);
    });

    container.insertBefore(list, panels[0]);
  }

  // Switches to whichever tab's panel matches `location.hash`, so a link to
  // an old heading anchor (or a same-page click on the overview table) lands
  // on visible content instead of a hidden panel. No-op if the hash doesn't
  // match a panel id.
  function activateHash() {
    var hash = window.location.hash;
    if (!hash || hash.length < 2) {
      return;
    }
    var target = document.getElementById(hash.slice(1));
    if (!target || !target.classList.contains('aaasm-tabs__panel')) {
      return;
    }
    var container = target.closest('.aaasm-tabs');
    if (!container) {
      return;
    }
    container.querySelectorAll('.aaasm-tabs__panel').forEach(function (panel) {
      panel.hidden = panel !== target;
    });
    container.querySelectorAll('.aaasm-tabs__button').forEach(function (button) {
      button.setAttribute('aria-selected', String(button.getAttribute('aria-controls') === target.id));
    });
    target.scrollIntoView();
  }

  function init() {
    var containers = document.querySelectorAll('.aaasm-tabs');
    containers.forEach(function (container, index) {
      initTabs(container, index);
    });
    activateHash();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  window.addEventListener('hashchange', activateHash);
})();
