(function () {
  function init() {
    document.querySelectorAll('.aa-dependency-pan').forEach(function (region) {
      // mdBook binds Left/Right to chapter navigation. Inside this explicitly
      // focused region, keep their native horizontal-scroll meaning instead.
      region.addEventListener('keydown', function (event) {
        if (event.key === 'ArrowLeft' || event.key === 'ArrowRight') event.stopPropagation();
      });
      function sizeDiagram() {
        var svg = region.querySelector('svg');
        if (!svg || !svg.viewBox.baseVal.width) return false;
        // One SVG unit per CSS pixel preserves Mermaid's actual16px labels.
        svg.style.width = Math.ceil(svg.viewBox.baseVal.width) + 'px';
        svg.style.height = 'auto';
        return true;
      }
      if (sizeDiagram()) return;
      var observer = new MutationObserver(function () {
        if (sizeDiagram()) observer.disconnect();
      });
      observer.observe(region, {childList: true, subtree: true, attributes: true, attributeFilter: ['viewBox']});
      window.addEventListener('pagehide', function () { observer.disconnect(); }, {once: true});
    });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init, {once: true});
  else init();
})();
