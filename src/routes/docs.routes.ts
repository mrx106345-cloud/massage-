import { Router } from 'express';
import { openApiDocument } from '../openapi.js';

/**
 * API documentation. The reference page is self-contained (no CDN dependency)
 * so it works under the strict CSP applied by the security middleware and in
 * air-gapped environments.
 */
export const docsRouter = Router();

docsRouter.get('/openapi.json', (_req, res) => {
  res.json(openApiDocument);
});

docsRouter.get('/', (_req, res) => {
  res.type('html').send(REFERENCE_PAGE);
});

const REFERENCE_PAGE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Aegis Chat API reference</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 15px/1.55 ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; padding: 2rem; max-width: 62rem; }
  h1 { margin: 0 0 .25rem; font-size: 1.6rem; }
  .sub { opacity: .7; margin-bottom: 1.5rem; }
  .tag { margin: 2rem 0 .6rem; font-size: 1.1rem; border-bottom: 1px solid #8884; padding-bottom: .3rem; }
  .op { border: 1px solid #8884; border-radius: 8px; padding: .6rem .8rem; margin: .5rem 0; }
  .row { display: flex; gap: .6rem; align-items: baseline; flex-wrap: wrap; }
  .method { font: 600 12px/1 ui-monospace, SFMono-Regular, Menlo, monospace; padding: .3rem .45rem; border-radius: 4px; color: #fff; text-transform: uppercase; }
  .get { background: #2b6cb0; } .post { background: #2f855a; } .put { background: #b7791f; } .delete { background: #c53030; }
  code { font: 13px/1.4 ui-monospace, SFMono-Regular, Menlo, monospace; }
  .summary { opacity: .85; }
  .secured { font-size: 12px; opacity: .7; }
  details { margin-top: .5rem; }
  pre { background: #8881; padding: .7rem; border-radius: 6px; overflow: auto; font-size: 12px; }
  a { color: inherit; }
</style>
</head>
<body>
<h1 id="title">API reference</h1>
<p class="sub">Live OpenAPI document: <a href="/api/openapi.json"><code>/api/openapi.json</code></a></p>
<div id="root">Loading…</div>
<script>
fetch('/api/openapi.json').then(function (r) { return r.json(); }).then(function (spec) {
  document.getElementById('title').textContent = spec.info.title + ' — v' + spec.info.version;
  var root = document.getElementById('root');
  root.textContent = '';
  var byTag = {};
  Object.keys(spec.paths).forEach(function (path) {
    Object.keys(spec.paths[path]).forEach(function (method) {
      var op = spec.paths[path][method];
      var tag = (op.tags && op.tags[0]) || 'Other';
      (byTag[tag] = byTag[tag] || []).push({ path: path, method: method, op: op });
    });
  });
  Object.keys(byTag).forEach(function (tag) {
    var h = document.createElement('h2');
    h.className = 'tag';
    h.textContent = tag;
    root.appendChild(h);
    byTag[tag].forEach(function (entry) {
      var box = document.createElement('div');
      box.className = 'op';
      var row = document.createElement('div');
      row.className = 'row';
      var m = document.createElement('span');
      m.className = 'method ' + entry.method;
      m.textContent = entry.method;
      var p = document.createElement('code');
      p.textContent = entry.path;
      var s = document.createElement('span');
      s.className = 'summary';
      s.textContent = entry.op.summary || '';
      row.appendChild(m); row.appendChild(p); row.appendChild(s);
      if (entry.op.security) {
        var lock = document.createElement('span');
        lock.className = 'secured';
        lock.textContent = '🔒 bearer token';
        row.appendChild(lock);
      }
      box.appendChild(row);
      if (entry.op.description) {
        var d = document.createElement('p');
        d.className = 'summary';
        d.textContent = entry.op.description;
        box.appendChild(d);
      }
      var details = document.createElement('details');
      var summary = document.createElement('summary');
      summary.textContent = 'Schema';
      details.appendChild(summary);
      var pre = document.createElement('pre');
      pre.textContent = JSON.stringify({
        parameters: entry.op.parameters || [],
        requestBody: entry.op.requestBody || null,
        responses: entry.op.responses || {}
      }, null, 2);
      details.appendChild(pre);
      box.appendChild(details);
      root.appendChild(box);
    });
  });
}).catch(function (err) {
  document.getElementById('root').textContent = 'Failed to load the specification: ' + err;
});
</script>
</body>
</html>`;
