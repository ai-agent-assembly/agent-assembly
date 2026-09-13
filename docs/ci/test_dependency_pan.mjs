// Source-level DOM/event contract test. This stub does not claim browser scroll
// or rendered Mermaid coverage; those remain separate browser checks.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';
import {runInNewContext} from 'node:vm';

const script = readFileSync(new URL('../theme/dependency-pan.js', import.meta.url), 'utf8');

function target() {
  const listeners = new Map();
  return {
    addEventListener(type, callback) {
      const callbacks = listeners.get(type) ?? [];
      callbacks.push(callback);
      listeners.set(type, callbacks);
    },
    dispatch(type, event = {}) {
      for (const callback of listeners.get(type) ?? []) callback(event);
    },
    listenerCount(type) { return (listeners.get(type) ?? []).length; },
  };
}

function setup({initialSvg = null, readyState = 'complete'} = {}) {
  let svg = initialSvg;
  const region = Object.assign(target(), {querySelector: () => svg});
  const document = Object.assign(target(), {
    readyState,
    querySelectorAll(selector) {
      assert.equal(selector, '.aa-dependency-pan');
      return [region];
    },
  });
  const window = target();
  const observers = [];
  class MutationObserver {
    constructor(callback) {
      this.callback = callback;
      this.disconnected = false;
      observers.push(this);
    }
    observe(node, options) {
      assert.equal(node, region);
      assert.equal(options.childList, true);
      assert.equal(options.subtree, true);
      assert.equal(options.attributes, true);
      assert.equal(options.attributeFilter[0], 'viewBox');
      this.observing = true;
    }
    disconnect() { this.disconnected = true; }
    change() { if (!this.disconnected) this.callback(); }
  }
  runInNewContext(script, {document, window, MutationObserver}, {
    filename: 'dependency-pan.js',
  });
  return {
    document, region, window, observers,
    setSvg(nextSvg) { svg = nextSvg; },
    key(key, insideRegion) {
      const event = {
        key,
        stopped: false,
        defaultPrevented: false,
        stopPropagation() { this.stopped = true; },
        preventDefault() { this.defaultPrevented = true; },
      };
      if (insideRegion) region.dispatch('keydown', event);
      if (!event.stopped) document.dispatch('keydown', event);
      return event;
    },
  };
}

function diagram(width) {
  return {viewBox: {baseVal: {width}}, style: {}};
}

test('only Left/Right inside the region stop chapter-key propagation, without canceling native default', () => {
  const dom = setup({initialSvg: diagram(1715)});
  const documentKeys = [];
  dom.document.addEventListener('keydown', (event) => documentKeys.push(event.key));

  for (const key of ['ArrowLeft', 'ArrowRight']) {
    const inside = dom.key(key, true);
    assert.equal(inside.stopped, true);
    assert.equal(inside.defaultPrevented, false);
    const outside = dom.key(key, false);
    assert.equal(outside.stopped, false);
    assert.equal(outside.defaultPrevented, false);
  }
  assert.deepEqual(documentKeys, ['ArrowLeft', 'ArrowRight']);

  for (const key of ['Home', 'End', 'a']) {
    const event = dom.key(key, true);
    assert.equal(event.stopped, false);
    assert.equal(event.defaultPrevented, false);
  }
  assert.deepEqual(documentKeys, ['ArrowLeft', 'ArrowRight', 'Home', 'End', 'a']);
});

test('a late Mermaid SVG is sized once from viewBox, then the observer disconnects', () => {
  const dom = setup();
  assert.equal(dom.observers.length, 1);
  assert.equal(dom.observers[0].observing, true);
  const svg = diagram(1715.2);
  dom.setSvg(svg);
  dom.observers[0].change();
  assert.equal(svg.style.width, '1716px');
  assert.equal(svg.style.height, 'auto');
  assert.equal(dom.observers[0].disconnected, true);
  dom.setSvg(diagram(600));
  dom.observers[0].change();
  assert.equal(dom.region.querySelector('svg').style.width, undefined);
});

test('an unresolved SVG observer is disconnected on pagehide', () => {
  const dom = setup();
  assert.equal(dom.observers[0].disconnected, false);
  assert.equal(dom.window.listenerCount('pagehide'), 1);
  dom.window.dispatch('pagehide');
  assert.equal(dom.observers[0].disconnected, true);
});

test('initialization waits for DOMContentLoaded when document is loading', () => {
  const svg = diagram(1100);
  const dom = setup({readyState: 'loading', initialSvg: svg});
  assert.equal(dom.region.listenerCount('keydown'), 0);
  dom.document.dispatch('DOMContentLoaded');
  assert.equal(dom.region.listenerCount('keydown'), 1);
  assert.equal(svg.style.width, '1100px');
  assert.equal(dom.observers.length, 0);
});
