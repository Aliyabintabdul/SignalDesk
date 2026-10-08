// SignalDesk — manual incident tracking console
const { api, esc, $, $$, toast, dialog, confirmBox, bindForm, fmtDate, fmtStamp, qs, options, route, download, loading } = Lib;
const root = $('#app');
let me = null, meta = null;
const qf = { q: '', status: 'open', severity: '', category: '', overdue: '', sort: '' };
const af = { q: '', type: '', criticality: '' };
const SEV_C = { Critical: 'var(--crit)', High: 'var(--high)', Medium: 'var(--med)', Low: 'var(--low)' };
const LOGO = '<svg viewBox="0 0 24 24" fill="none" stroke="#b8a7ff" stroke-width="2" aria-hidden="true"><path d="M12 3l8 3v6c0 4.5-3.4 8.2-8 9-4.6-.8-8-4.5-8-9V6z"/><path d="M8.5 12.5l2.3 2.3 4.7-5"/></svg>';
Lib.setUnauthorized(() => { if (me) { me = null; renderAuth('Your session expired. Sign in again.'); } });

function renderAuth(notice = '', mode = 'login') {
  const reg = mode === 'register';
  root.innerHTML = `<div class="auth"><section class="auth-l"><span class="logo">${LOGO}SignalDesk</span>
    <div><h1>From report<br>to <span>resolution.</span></h1><p>A manual incident tracker: record what happened, link affected assets, document the investigation and require a written resolution before closing. SignalDesk does not detect threats, monitor systems or connect to a SIEM.</p></div>
    <div class="mock" aria-hidden="true"><div><span class="sev High">High</span><span class="mono hint">INC-0042</span> Repeated failed sign-ins</div><div><span class="sev Medium">Medium</span><span class="mono hint">INC-0041</span> Suspicious DNS lookups</div><div><span class="sev Low">Low</span><span class="mono hint">INC-0040</span> Unpatched staging host</div></div></section>
    <section class="auth-r"><h2>${reg ? 'Create your workspace' : 'Sign in to SignalDesk'}</h2><form id="auth-form" novalidate>
    <label>Email<input type="email" name="email" autocomplete="username" required></label>
    <label>Password<input type="password" name="password" minlength="10" required autocomplete="${reg ? 'new-password' : 'current-password'}"></label>
    <p class="form-error" role="alert">${esc(notice)}</p><button class="btn primary" type="submit">${reg ? 'Create account' : 'Sign in'}</button></form>
    <button class="btn ghost" data-auth="${reg ? 'login' : 'register'}">${reg ? 'Back to sign in' : 'Create an account'}</button>
    <p class="hint">${reg ? 'Minimum 10 characters. Each account is a private, single-user workspace.' : 'Seeded demo (if enabled): demo@example.com · DemoPass123!'}</p></section></div>`;
  $('[data-auth]').onclick = e => renderAuth('', e.target.dataset.auth);
  bindForm($('#auth-form'), async data => { me = (await api(reg ? 'register' : 'login', 'POST', data)).user; location.hash = '#/'; render(); });
  $('#auth-form input').focus();
}

function shell(page) {
  root.innerHTML = `<a class="skip" href="#main">Skip to content</a><header class="hdr"><a class="logo" href="#/">${LOGO}SignalDesk</a><span class="tag-manual">Manual incident tracker</span>
    <nav aria-label="Main">${[['', 'Overview'], ['incidents', 'Incidents'], ['assets', 'Assets']].map(([k, l]) => `<a href="#/${k}" ${page === k ? 'aria-current="page"' : ''}>${l}</a>`).join('')}</nav>
    <div class="who"><span class="email">${esc(me.email)}</span><button class="btn sm" data-act="logout">Sign out</button></div></header>
    ${me.is_demo ? '<div class="demo">Demo workspace — incidents, assets and comments here are fictional sample data.</div>' : ''}<main id="main" tabindex="-1">${loading()}</main>`;
  return $('#main');
}

async function render() {
  if (!me) return renderAuth();
  const [page = '', id] = route();
  const main = shell(page);
  try {
    meta = meta || await api('meta');
    if (page === '') await viewOverview(main);
    else if (page === 'incidents') await viewIncidents(main, id && +id);
    else if (page === 'assets' && id) await viewAsset(main, +id);
    else if (page === 'assets') await viewAssets(main);
    else main.innerHTML = '<div class="empty"><h2>Not found</h2><a href="#/">Back to overview</a></div>';
  } catch (e) { if (e.status !== 401) main.innerHTML = `<div class="empty"><h2>Could not load</h2>${esc(e.message)}</div>`; }
}

const ref = n => 'INC-' + String(n).padStart(4, '0');
const sev = s => `<span class="sev ${esc(s)}">${esc(s)}</span>`;
const st = s => `<span class="st ${esc(s)}">${esc(s)}</span>`;
const review = i => i.review_date ? `<span class="${i.overdue ? 'late' : ''}">${i.overdue ? 'Review overdue · ' : 'Review '}${fmtDate(i.review_date, { day: 'numeric', month: 'short' })}</span>` : '<span class="hint">No review date</span>';
const head = (title, sub, acts = '') => `<div class="pagehead"><div><h1>${title}</h1><p>${sub}</p></div><div style="display:flex;gap:8px;flex-wrap:wrap">${acts}</div></div>`;

async function viewOverview(main) {
  const d = await api('dashboard');
  main.innerHTML = head('Security overview', 'Figures are calculated from incidents recorded in this workspace.', '<button class="btn" data-act="new-asset">+ Asset</button><button class="btn primary" data-act="new-incident">+ Log incident</button>') +
    (!d.total ? `<div class="empty"><h2>No incidents recorded</h2><p>Log an incident when something is reported, then track it through investigation to a documented resolution.</p><button class="btn primary" data-act="new-incident">Log first incident</button></div>` : `
    <section class="sevgrid" aria-label="Open incidents by severity">${meta.severities.slice().reverse().map(s => `<a class="sevcard" href="#/incidents" data-preset-sev="${s}" style="--c:${SEV_C[s]}"><span>${s} · open</span><b>${d.severity[s]}</b></a>`).join('')}
      <div class="sevcard total"><span>Open incidents</span><b>${d.open}</b><span>${d.overdue.length} overdue review${d.overdue.length === 1 ? '' : 's'} · ${d.assets} assets tracked</span></div></section>
    <div class="grid3"><div style="display:grid;gap:16px;align-content:start">
      <section class="panel"><h2>Status</h2><div class="body"><div class="statusflow">${meta.statuses.map(s => `<div><b>${d.status[s]}</b><span>${s}</span></div>`).join('')}</div>
        <div class="statline" style="margin-top:12px"><span><b>${d.resolved_30d}</b>resolved in last 30 days</span><span><b>${d.mean_hours_to_resolve == null ? '—' : d.mean_hours_to_resolve < 48 ? d.mean_hours_to_resolve + ' h' : (d.mean_hours_to_resolve / 24).toFixed(1) + ' d'}</b>mean time to resolve (${d.resolved_count} incident${d.resolved_count === 1 ? '' : 's'})</span></div></div></section>
      <section class="panel"><h2>Overdue reviews <a class="btn sm" href="#/incidents" data-preset-overdue>Open queue</a></h2><div class="body">${d.overdue.length ? `<ul class="feed">${d.overdue.map(i => `<li><span class="dot severity"></span><a href="#/incidents/${i.id}"><span class="mono hint">${ref(i.number)}</span> ${esc(i.title)} ${sev(i.severity)}</a><span class="when late">${fmtDate(i.review_date, { day: 'numeric', month: 'short' })}</span></li>`).join('')}</ul>` : '<p class="hint">No reviews are overdue.</p>'}</div></section>
      <section class="panel"><h2>Most affected assets (open)</h2><div class="body">${d.top_assets.length ? `<ul class="feed">${d.top_assets.map(a => `<li><span class="dot"></span><a href="#/assets/${a.id}">${esc(a.name)}</a><span class="when">${a.n} open · ${esc(a.criticality)}</span></li>`).join('')}</ul>` : '<p class="hint">No open incidents are linked to assets.</p>'}</div></section>
    </div><section class="panel"><h2>Recent activity</h2><div class="body"><ul class="feed">${d.recent.map(a => `<li><span class="dot ${esc(a.kind)}"></span><span>${a.incident_id ? `<a href="#/incidents/${a.incident_id}"><span class="mono hint">${ref(a.number)}</span> ${esc(a.title)}</a><br>` : ''}<span class="hint">${esc(a.message)}</span></span><span class="when">${fmtStamp(a.created)}</span></li>`).join('') || '<li class="hint">No activity yet.</li>'}</ul></div></section></div>`);
}

async function viewIncidents(main, id) {
  main.innerHTML = head('Incident queue', 'Ordered by status, severity and review date.', '<button class="btn" data-act="export">Export CSV</button><button class="btn primary" data-act="new-incident">+ Log incident</button>') + `
    <div class="console ${id ? 'has-detail' : ''}"><aside class="queue" aria-label="Incident queue"><div class="qfilters">
      <label class="full">Search<input type="search" data-q="q" value="${esc(qf.q)}" placeholder="Title, INC-0001, asset, category"></label>
      <label>Status<select data-q="status">${options([['open', 'All open'], ['', 'All'], ...meta.statuses], qf.status)}</select></label>
      <label>Severity<select data-q="severity"><option value="">Any</option>${options(meta.severities, qf.severity)}</select></label>
      <label>Category<select data-q="category"><option value="">Any</option>${options(meta.categories, qf.category)}</select></label>
      <label>Sort<select data-q="sort">${options([['', 'Priority'], ['updated', 'Recently updated'], ['review', 'Review date'], ['number', 'Newest']], qf.sort)}</select></label>
      <label class="check full"><input type="checkbox" data-q="overdue" ${qf.overdue ? 'checked' : ''}> Only overdue reviews</label></div>
      <ul class="qlist" id="qlist">${loading()}</ul><div class="qcount" id="qcount"></div></aside>
    <section class="detail" id="detail" aria-live="polite">${id ? loading() : '<div class="empty" style="border:0"><h2>Select an incident</h2>Choose an incident from the queue to review its investigation timeline.</div>'}</section></div>`;
  main.refresh = refreshQueue;
  await refreshQueue();
  if (id) await loadDetail(id);
}

async function refreshQueue() {
  const list = await api('incidents?' + qs(qf)), cur = +route()[1];
  $('#qlist').innerHTML = list.map(i => `<li><a class="qitem" href="#/incidents/${i.id}" ${i.id === cur ? 'aria-current="true"' : ''}><span class="row"><span class="ref">${ref(i.number)}</span>${sev(i.severity)}</span>
    <span class="title">${esc(i.title)}</span><span class="sub">${esc(i.asset_names || 'No linked asset')} · ${esc(i.category)}</span><span class="row">${st(i.status)}<span class="when">${review(i)}</span></span></a></li>`).join('')
    || `<li class="empty" style="border:0;margin:12px">${qf.q || qf.severity || qf.category || qf.overdue ? 'No incidents match these filters.' : 'No incidents here.'}</li>`;
  $('#qcount').innerHTML = `<span>${list.length} incident${list.length === 1 ? '' : 's'}</span><span class="hint">Export uses these filters</span>`;
}

async function loadDetail(id) {
  const box = $('#detail'); box.innerHTML = loading();
  $$('.qitem').forEach(a => a.setAttribute('aria-current', String(a.getAttribute('href') === '#/incidents/' + id)));
  $('.console').classList.add('has-detail');
  let i;
  try { i = await api('incidents/' + id); } catch (e) { box.innerHTML = `<div class="empty" style="border:0"><h2>Unavailable</h2>${esc(e.message)}</div>`; return; }
  box.incident = i;
  box.innerHTML = `<div class="dhead"><a href="#/incidents" class="hint" data-back>← Queue</a><div class="meta"><span class="mono">${ref(i.number)}</span>${sev(i.severity)}${st(i.status)}<span>${esc(i.category)}</span></div>
    <h2>${esc(i.title)}</h2><div class="meta"><span>Opened ${fmtStamp(i.created)}</span><span>Updated ${fmtStamp(i.updated)}</span>${i.resolved_at ? `<span>Resolved ${fmtStamp(i.resolved_at)}</span>` : ''}<span>${review(i)}</span></div>
    <div style="display:flex;gap:8px"><button class="btn sm" data-act="edit-incident">Edit</button><button class="btn sm danger" data-act="delete-incident">Delete</button></div></div>
    <div class="dbody"><div class="dmain">
      <div><div class="section-label">Description</div><p class="prose" style="margin:0">${esc(i.description || 'No description recorded.')}</p></div>
      ${i.resolution_notes ? `<div class="resolution"><div class="section-label">Resolution notes</div><p class="prose" style="margin:0">${esc(i.resolution_notes)}</p></div>` : ''}
      <div><div class="section-label">Investigation timeline</div>
        <form class="composer" id="comment" novalidate><label class="sr" for="cbody">Add a comment</label><textarea id="cbody" name="body" maxlength="5000" placeholder="Add a finding, action taken or next step…" required></textarea>
        <p class="form-error" role="alert"></p><div><button type="submit" class="btn primary sm">Add comment</button></div></form>
        <ol class="tl" style="margin-top:14px">${i.timeline.map(e => e.type === 'comment'
          ? `<li class="comment"><div class="h">${esc(e.author_email)} commented · ${fmtStamp(e.created)}</div><div class="c">${esc(e.body)}</div></li>`
          : `<li class="${esc(e.kind)}"><div class="h">${fmtStamp(e.created)}</div>${esc(e.message)}</li>`).join('')}</ol></div></div>
    <aside class="dside"><form class="triage" id="triage" novalidate><div class="section-label">Triage</div>
      <label>Status<select name="status">${options(meta.statuses, i.status)}</select></label><label>Severity<select name="severity">${options(meta.severities, i.severity)}</select></label>
      <label>Resolution notes <span class="hint">(required to resolve, min ${meta.min_resolution} chars)</span><textarea name="resolution_notes" maxlength="10000">${esc(i.resolution_notes)}</textarea></label>
      <p class="form-error" role="alert"></p><button type="submit" class="btn primary">Apply changes</button></form>
      <div><div class="section-label">Affected assets</div><div class="chips">${i.assets.map(a => `<a class="chip" href="#/assets/${a.id}">${esc(a.name)} · ${esc(a.criticality)}</a>`).join('') || '<span class="hint">None linked. Use Edit to link assets.</span>'}</div></div>
      <dl class="facts"><div><dt>Detected (local time, as entered)</dt><dd>${i.detected_at ? esc(i.detected_at.replace('T', ' ')) : '—'}</dd></div><div><dt>Comments</dt><dd>${i.comment_count}</dd></div></dl></aside></div>`;
  bindForm($('#comment'), async data => { await api(`incidents/${id}/comments`, 'POST', data); toast('Comment added'); await loadDetail(id); });
  bindForm($('#triage'), async data => { await api(`incidents/${id}/triage`, 'POST', data); toast('Incident updated'); await refreshQueue(); await loadDetail(id); });
}

async function viewAssets(main) {
  main.innerHTML = head('Assets', 'Systems and services you link to incidents.', '<button class="btn primary" data-act="new-asset">+ Asset</button>') + `
    <div class="filters"><label class="grow">Search<input type="search" data-a="q" value="${esc(af.q)}" placeholder="Name, identifier, owner"></label>
    <label>Type<select data-a="type"><option value="">All types</option>${options(meta.asset_types, af.type)}</select></label>
    <label>Criticality<select data-a="criticality"><option value="">Any</option>${options(meta.criticality, af.criticality)}</select></label></div><div id="results">${loading()}</div>`;
  main.refresh = async () => {
    const list = await api('assets?' + qs(af));
    $('#results').innerHTML = list.length ? `<div class="tbl"><table class="stack"><thead><tr><th>Asset</th><th>Type</th><th>Environment</th><th>Criticality</th><th>Owner</th><th class="num">Open</th><th class="num">All incidents</th></tr></thead><tbody>
      ${list.map(a => `<tr><td class="wide"><a href="#/assets/${a.id}">${esc(a.name)}</a>${a.identifier ? `<br><span class="mono hint">${esc(a.identifier)}</span>` : ''}</td><td>${esc(a.type)}</td><td class="hide-sm">${esc(a.environment)}</td>
        <td>${sev(a.criticality)}</td><td class="hide-sm">${esc(a.owner || '—')}</td><td class="num">${a.open_count || 0}</td><td class="num hide-sm">${a.incident_count}</td></tr>`).join('')}</tbody></table></div>`
      : `<div class="empty"><h2>${af.q || af.type || af.criticality ? 'No assets match' : 'No assets yet'}</h2>Add the servers, accounts and services you want to link to incidents.<br><button class="btn primary" data-act="new-asset">+ Asset</button></div>`;
  };
  await main.refresh();
}

async function viewAsset(main, id) {
  const a = await api('assets/' + id);
  main.asset = a;
  main.innerHTML = head(esc(a.name), `<a href="#/assets">Assets</a> · ${esc(a.type)} · ${esc(a.environment)}`, '<button class="btn" data-act="edit-asset">Edit</button><button class="btn danger" data-act="delete-asset">Delete</button>') + `
    <div class="grid3"><section class="panel"><h2>Linked incidents · ${a.incidents.length}</h2><div class="body">${a.incidents.length ? `<ul class="feed">${a.incidents.map(i => `<li><span class="dot ${i.status === 'Resolved' ? 'created' : 'severity'}"></span><a href="#/incidents/${i.id}"><span class="mono hint">${ref(i.number)}</span> ${esc(i.title)}</a><span>${sev(i.severity)} ${st(i.status)}</span></li>`).join('')}</ul>` : '<p class="hint">No incidents linked to this asset.</p>'}</div></section>
    <section class="panel"><h2>Details</h2><div class="body"><dl class="facts"><div><dt>Criticality</dt><dd>${sev(a.criticality)}</dd></div><div><dt>Identifier</dt><dd class="mono">${esc(a.identifier || '—')}</dd></div>
      <div><dt>Owner</dt><dd>${esc(a.owner || '—')}</dd></div><div><dt>Notes</dt><dd class="prose">${esc(a.notes || '—')}</dd></div></dl></div></section></div>`;
}

async function incidentForm(i = {}) {
  const assets = await api('assets'), linked = new Set((i.assets || []).map(a => a.id));
  const d = dialog(`<h2>${i.id ? 'Edit ' + ref(i.number) : 'Log an incident'}</h2><form novalidate><div class="grid2">
    <label class="full">Title<input name="title" required maxlength="160" value="${esc(i.title)}"></label>
    <label>Category<select name="category">${options(meta.categories, i.category || 'Other')}</select></label><label>Severity<select name="severity">${options(meta.severities, i.severity || 'Medium')}</select></label>
    <label>Status<select name="status">${options(meta.statuses, i.status || 'Open')}</select></label><label>Next review date<input name="review_date" type="date" value="${esc(i.review_date)}"></label>
    <label>Detected at (local time)<input name="detected_at" type="datetime-local" value="${esc(i.detected_at)}"></label><span></span>
    <label class="full">Description<textarea name="description" maxlength="10000" placeholder="What was reported or observed, by whom, and what is known so far.">${esc(i.description)}</textarea></label>
    <fieldset class="full" style="border:0;padding:0;margin:0"><legend class="hint" style="margin-bottom:5px">Affected assets</legend><div class="assetpick">${assets.map(a => `<label class="check"><input type="checkbox" name="asset_ids" value="${a.id}" ${linked.has(a.id) ? 'checked' : ''}> ${esc(a.name)}</label>`).join('') || '<span class="hint">No assets yet — add them on the Assets page.</span>'}</div></fieldset>
    <label class="full">Resolution notes <span class="hint">(required when status is Resolved)</span><textarea name="resolution_notes" maxlength="10000">${esc(i.resolution_notes)}</textarea></label></div>
    <p class="form-error" role="alert"></p><div class="dlg-actions"><button type="button" class="btn" data-close>Cancel</button><button type="submit" class="btn primary">Save incident</button></div></form>`);
  const form = $('form', d);
  bindForm(form, async data => {
    data.asset_ids = $$('input[name=asset_ids]:checked', form).map(x => +x.value);
    const r = await api(i.id ? 'incidents/' + i.id : 'incidents', i.id ? 'PUT' : 'POST', data);
    d.close(); toast(i.id ? 'Incident updated' : `${ref(r.number)} logged`); go('#/incidents/' + (i.id || r.id));
  });
}

function assetForm(a = {}) {
  const d = dialog(`<h2>${a.id ? 'Edit asset' : 'Add an asset'}</h2><form novalidate><div class="grid2">
    <label class="full">Name<input name="name" required maxlength="160" value="${esc(a.name)}"></label>
    <label>Type<select name="type">${options(meta.asset_types, a.type || 'Server')}</select></label><label>Environment<select name="environment">${options(meta.environments, a.environment || 'Production')}</select></label>
    <label>Criticality<select name="criticality">${options(meta.criticality, a.criticality || 'Medium')}</select></label><label>Owner (team or person)<input name="owner" maxlength="120" value="${esc(a.owner)}"></label>
    <label class="full">Identifier (hostname, IP, account, URL)<input name="identifier" maxlength="200" value="${esc(a.identifier)}"></label>
    <label class="full">Notes<textarea name="notes" maxlength="5000">${esc(a.notes)}</textarea></label></div>
    <p class="form-error" role="alert"></p><div class="dlg-actions"><button type="button" class="btn" data-close>Cancel</button><button type="submit" class="btn primary">Save asset</button></div></form>`);
  bindForm($('form', d), async data => {
    const r = await api(a.id ? 'assets/' + a.id : 'assets', a.id ? 'PUT' : 'POST', data);
    d.close(); toast('Asset saved'); go('#/assets/' + (a.id || r.id));
  });
}

const go = h => { if (location.hash === h) render(); else location.hash = h; };
const actions = {
  logout: () => api('logout', 'POST').finally(() => { me = null; location.hash = ''; renderAuth('Signed out.'); }),
  'new-incident': () => incidentForm(), 'edit-incident': () => incidentForm($('#detail').incident),
  'delete-incident': async () => { const i = $('#detail').incident; if (await confirmBox(`Delete ${ref(i.number)} “${i.title}” with its comments and history? This cannot be undone. Consider resolving it instead.`, { title: 'Delete incident' })) { try { await api('incidents/' + i.id, 'DELETE'); toast('Incident deleted'); go('#/incidents'); } catch (e) { toast(e.message, 'err'); } } },
  'new-asset': () => assetForm(), 'edit-asset': () => assetForm($('#main').asset),
  'delete-asset': async () => { const a = $('#main').asset; if (await confirmBox(`Delete ${a.name}? It will be unlinked from ${a.incidents.length} incident(s); the incidents themselves are kept and the unlink is recorded in their history.`, { title: 'Delete asset' })) { try { await api('assets/' + a.id, 'DELETE'); toast('Asset deleted'); go('#/assets'); } catch (e) { toast(e.message, 'err'); } } },
  export: () => download('export/incidents?' + qs(qf)),
};
root.addEventListener('click', e => {
  const b = e.target.closest('[data-act],[data-preset-sev],[data-preset-overdue]'); if (!b) return;
  if (b.dataset.presetSev) Object.assign(qf, { severity: b.dataset.presetSev, status: 'open', overdue: '', q: '', category: '' });
  else if ('presetOverdue' in b.dataset) Object.assign(qf, { overdue: '1', status: 'open', severity: '', q: '', category: '' });
  else if (actions[b.dataset.act]) { e.preventDefault(); actions[b.dataset.act](); }
});
let timer;
root.addEventListener('input', e => {
  const t = e.target, k = t.dataset.q || t.dataset.a; if (!k) return;
  (t.dataset.q ? qf : af)[k] = t.type === 'checkbox' ? (t.checked ? '1' : '') : t.value;
  clearTimeout(timer); timer = setTimeout(() => { const m = $('#main'); m && m.refresh && m.refresh().catch(err => toast(err.message, 'err')); }, 200);
});
window.addEventListener('hashchange', () => {
  if (!me) return;
  const [p, id] = route();
  if (p === 'incidents' && $('.console')) { if (id) loadDetail(+id); else { $('.console').classList.remove('has-detail'); $('#detail').innerHTML = '<div class="empty" style="border:0"><h2>Select an incident</h2></div>'; } }
  else render();
});

(async () => {
  try { me = (await api('session')).user; render(); }
  catch (e) { e.status === 401 ? renderAuth() : (root.innerHTML = `<div class="loading">${esc(e.message)}</div>`); }
})();
