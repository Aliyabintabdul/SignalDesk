"""SignalDesk — manual security incident tracker (Python standard library + SQLite).

Incidents are entered and updated by people. SignalDesk does not detect threats,
monitor systems, ingest logs or integrate with a SIEM.
"""
from pathlib import Path
from core import App, ApiError, Csv, Form, now_iso, one, rows, today

SEVERITIES = ['Low', 'Medium', 'High', 'Critical']
STATUSES = ['Open', 'Investigating', 'Contained', 'Resolved']
CATEGORIES = ['Phishing', 'Malware', 'Unauthorized access', 'Account compromise', 'Data exposure', 'Vulnerability', 'Policy violation', 'Availability', 'Other']
ASSET_TYPES = ['Server', 'Workstation', 'Network device', 'Cloud service', 'Application', 'Identity system', 'Database', 'Other']
ENVIRONMENTS = ['Production', 'Staging', 'Development', 'Corporate', 'Unspecified']
CRITICALITY = ['Low', 'Medium', 'High', 'Critical']
MIN_RESOLUTION = 10

SCHEMA = """
CREATE TABLE assets(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL, type TEXT NOT NULL, environment TEXT NOT NULL, criticality TEXT NOT NULL, owner TEXT NOT NULL DEFAULT '',
  identifier TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '', created TEXT NOT NULL, updated TEXT NOT NULL);
CREATE INDEX assets_user ON assets(user_id, name);
CREATE TABLE incidents(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, number INTEGER NOT NULL,
  title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', category TEXT NOT NULL, severity TEXT NOT NULL CHECK(severity IN ('Low','Medium','High','Critical')),
  status TEXT NOT NULL CHECK(status IN ('Open','Investigating','Contained','Resolved')), review_date TEXT, detected_at TEXT,
  resolution_notes TEXT NOT NULL DEFAULT '', resolved_at TEXT, created TEXT NOT NULL, updated TEXT NOT NULL,
  CHECK(status<>'Resolved' OR length(trim(resolution_notes))>=10), UNIQUE(user_id, number));
CREATE INDEX incidents_user ON incidents(user_id, status, severity);
CREATE TABLE incident_assets(incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY(incident_id, asset_id));
CREATE INDEX incident_assets_asset ON incident_assets(asset_id);
CREATE TABLE comments(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE, body TEXT NOT NULL, author_email TEXT NOT NULL, created TEXT NOT NULL);
CREATE INDEX comments_incident ON comments(incident_id, id);
CREATE TABLE activity(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  incident_id INTEGER REFERENCES incidents(id) ON DELETE CASCADE, kind TEXT NOT NULL, from_value TEXT, to_value TEXT, message TEXT NOT NULL, created TEXT NOT NULL);
CREATE INDEX activity_user ON activity(user_id, id);
CREATE INDEX activity_incident ON activity(incident_id, id)
"""


def migrate_v1(c):
    for stmt in SCHEMA.split(';'):
        c.execute(stmt)
    if c.execute("SELECT 1 FROM sqlite_master WHERE name='records'").fetchone():
        sev = {1: 'Low', 2: 'Low', 3: 'Medium', 4: 'High', 5: 'Critical'}
        for r in c.execute('SELECT * FROM records ORDER BY user_id, id').fetchall():
            ts, uid = now_iso(), r['user_id']
            number = c.execute('SELECT COALESCE(MAX(number),0)+1 FROM incidents WHERE user_id=?', (uid,)).fetchone()[0]
            status = r['status'] if r['status'] in STATUSES else 'Open'
            resolution = 'Resolved before migration; no resolution notes were recorded.' if status == 'Resolved' else ''
            iid = c.execute("""INSERT INTO incidents(user_id,number,title,description,category,severity,status,review_date,resolution_notes,resolved_at,created,updated)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""", (uid, number, r['title'] or 'Untitled incident', r['notes'] or '', 'Other',
                                                 sev.get(int(r['amount'] or 3), 'Medium'), status, r['due'], resolution, ts if status == 'Resolved' else None, ts, ts)).lastrowid
            if (r['category'] or '').strip():
                a = c.execute('SELECT id FROM assets WHERE user_id=? AND name=?', (uid, r['category'].strip())).fetchone()
                aid = a[0] if a else c.execute("""INSERT INTO assets(user_id,name,type,environment,criticality,notes,created,updated)
                    VALUES(?,?,'Other','Unspecified','Medium','Created from an earlier version of SignalDesk.',?,?)""", (uid, r['category'].strip(), ts, ts)).lastrowid
                c.execute('INSERT OR IGNORE INTO incident_assets VALUES(?,?,?)', (iid, aid, uid))
            c.execute('INSERT INTO activity(user_id,incident_id,kind,message,created) VALUES(?,?,?,?,?)', (uid, iid, 'created', 'Imported from earlier version', ts))
        c.execute('ALTER TABLE records RENAME TO legacy_records')
        if c.execute("SELECT 1 FROM sqlite_master WHERE name='events'").fetchone():
            c.execute('ALTER TABLE events RENAME TO legacy_events')


def seed(c, uid):
    from datetime import date, timedelta
    d = lambda n: (date.today() + timedelta(days=n)).isoformat()
    ts = now_iso()
    assets = [('Identity gateway', 'Identity system', 'Production', 'Critical', 'IT operations', 'sso.internal.example'),
              ('Workstation LAB-07', 'Workstation', 'Corporate', 'Medium', 'Research team', 'LAB-07'),
              ('Staging web server', 'Server', 'Staging', 'Low', 'Platform team', '10.0.4.12'),
              ('Customer database', 'Database', 'Production', 'Critical', 'Data team', 'db-prod-1')]
    aids = [c.execute("""INSERT INTO assets(user_id,name,type,environment,criticality,owner,identifier,notes,created,updated) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                      (uid, *a, 'Fictional demo asset.', ts, ts)).lastrowid for a in assets]
    incidents = [('Repeated failed sign-ins on SSO', 'Unauthorized access', 'High', 'Investigating', d(-1), [0], 'Burst of failed logins reported by the help desk for three accounts.'),
                 ('Suspicious DNS lookups from lab machine', 'Malware', 'Medium', 'Open', d(2), [1], 'User reported pop-ups; DNS lookups to an unfamiliar domain were noticed in router logs.'),
                 ('Unpatched staging server', 'Vulnerability', 'Low', 'Contained', d(6), [2], 'Staging host missed the last patch cycle. Isolated from the public network.'),
                 ('Phishing email reported by finance', 'Phishing', 'Medium', 'Resolved', d(-3), [], 'Invoice-themed email with credential-harvesting link.')]
    for n, (title, cat, sev, status, review, links, desc) in enumerate(incidents, 1):
        res = 'Sender blocked, message purged from mailboxes, no credentials were entered.' if status == 'Resolved' else ''
        iid = c.execute("""INSERT INTO incidents(user_id,number,title,description,category,severity,status,review_date,resolution_notes,resolved_at,created,updated)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""", (uid, n, title, desc, cat, sev, status, review, res, ts if status == 'Resolved' else None, ts, ts)).lastrowid
        for i in links:
            c.execute('INSERT INTO incident_assets VALUES(?,?,?)', (iid, aids[i], uid))
        log(c, uid, iid, 'created', None, status, f'Incident opened at {sev} severity (demo data)')
        if status != 'Open':
            log(c, uid, iid, 'status', 'Open', status, f'Status changed from Open to {status}')
        if n == 1:
            c.execute('INSERT INTO comments(user_id,incident_id,body,author_email,created) VALUES(?,?,?,?,?)',
                      (uid, iid, 'Reset passwords for the three affected accounts and enabled MFA prompts. Watching for further attempts.', 'demo@example.com', ts))
            log(c, uid, iid, 'comment', None, None, 'Comment added')


app = App('SignalDesk', 'signaldesk', Path(__file__).parent, [migrate_v1], seed)


def log(c, uid, iid, kind, old, new, message):
    c.execute('INSERT INTO activity(user_id,incident_id,kind,from_value,to_value,message,created) VALUES(?,?,?,?,?,?,?)', (uid, iid, kind, old, new, message, now_iso()))


def resolution_check(f, status, notes):
    f.check(status != 'Resolved' or len((notes or '').strip()) >= MIN_RESOLUTION, 'resolution_notes',
            f'Describe how the incident was resolved (at least {MIN_RESOLUTION} characters) before marking it Resolved.')


def incident_form(ctx, body):
    f = Form(body)
    f.text('title', True, 160); f.text('description', False, 10000); f.choice('category', CATEGORIES, 'Other')
    f.choice('severity', SEVERITIES, 'Medium'); f.choice('status', STATUSES, 'Open'); f.date('review_date'); f.datetime('detected_at')
    f.text('resolution_notes', False, 10000)
    resolution_check(f, f.values['status'], f.values['resolution_notes'])
    ids = body.get('asset_ids') or []
    f.check(isinstance(ids, list) and len(ids) <= 50 and all(isinstance(x, int) or (isinstance(x, str) and x.isdigit()) for x in ids), 'asset_ids', 'Choose assets from the list.')
    v = f.done()
    v['asset_ids'] = sorted({int(x) for x in ids})
    if v['asset_ids']:
        found = ctx.db.execute(f'SELECT COUNT(*) FROM assets WHERE user_id=? AND id IN ({",".join("?" * len(v["asset_ids"]))})', (ctx.uid, *v['asset_ids'])).fetchone()[0]
        if found != len(v['asset_ids']):
            raise ApiError(400, 'One or more selected assets were not found.', 'validation_error', {'asset_ids': 'Choose assets from your inventory.'})
    return v


def asset_form(body):
    f = Form(body)
    f.text('name', True, 160); f.choice('type', ASSET_TYPES, 'Other'); f.choice('environment', ENVIRONMENTS, 'Production')
    f.choice('criticality', CRITICALITY, 'Medium'); f.text('owner', False, 120); f.text('identifier', False, 200); f.text('notes', False, 5000)
    return f.done()


def own_incident(ctx, iid=None):
    return one(ctx.db, 'SELECT * FROM incidents WHERE id=? AND user_id=?', (iid or ctx.params['id'], ctx.uid), 'Incident')


INCIDENT_SELECT = """SELECT i.*, CASE WHEN i.review_date < :today AND i.status<>'Resolved' THEN 1 ELSE 0 END AS overdue,
  (SELECT group_concat(a.name, ', ') FROM incident_assets ia JOIN assets a ON a.id=ia.asset_id WHERE ia.incident_id=i.id) AS asset_names,
  (SELECT COUNT(*) FROM comments c WHERE c.incident_id=i.id) AS comment_count
  FROM incidents i WHERE i.user_id=:uid"""
SEV_ORDER = "CASE i.severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END"


def incident_query(ctx):
    sql, args = INCIDENT_SELECT, {'uid': ctx.uid, 'today': today()}
    if ctx.q('q'):
        sql += """ AND (i.title LIKE :q OR i.description LIKE :q OR i.category LIKE :q OR ('INC-' || printf('%04d', i.number)) LIKE :q
                 OR EXISTS(SELECT 1 FROM incident_assets ia JOIN assets a ON a.id=ia.asset_id WHERE ia.incident_id=i.id AND a.name LIKE :q))"""
        args['q'] = f"%{ctx.q('q')}%"
    status = ctx.q('status')
    if status == 'open':
        sql += " AND i.status<>'Resolved'"
    elif status in STATUSES:
        sql += ' AND i.status=:status'; args['status'] = status
    if ctx.q('severity') in SEVERITIES:
        sql += ' AND i.severity=:sev'; args['sev'] = ctx.q('severity')
    if ctx.q('category') in CATEGORIES:
        sql += ' AND i.category=:cat'; args['cat'] = ctx.q('category')
    if ctx.q('asset_id').isdigit():
        sql += ' AND EXISTS(SELECT 1 FROM incident_assets ia WHERE ia.incident_id=i.id AND ia.asset_id=:aid)'; args['aid'] = int(ctx.q('asset_id'))
    if ctx.q('overdue') == '1':
        sql += " AND i.review_date < :today AND i.status<>'Resolved'"
    order = {'updated': 'i.updated DESC', 'review': 'i.review_date IS NULL, i.review_date', 'number': 'i.number DESC'}.get(ctx.q('sort'), f"i.status='Resolved', {SEV_ORDER}, i.review_date IS NULL, i.review_date")
    return rows(ctx.db.execute(f'{sql} ORDER BY {order}', args))


def set_assets(ctx, iid, asset_ids):
    ctx.db.execute('DELETE FROM incident_assets WHERE incident_id=?', (iid,))
    for aid in asset_ids:
        ctx.db.execute('INSERT INTO incident_assets VALUES(?,?,?)', (iid, aid, ctx.uid))


@app.route('GET', '/api/meta')
def meta(ctx):
    return {'severities': SEVERITIES, 'statuses': STATUSES, 'categories': CATEGORIES, 'asset_types': ASSET_TYPES, 'environments': ENVIRONMENTS,
            'criticality': CRITICALITY, 'min_resolution': MIN_RESOLUTION}


@app.route('GET', '/api/dashboard')
def dashboard(ctx):
    c, uid, t = ctx.db, ctx.uid, today()
    sev = {s: 0 for s in SEVERITIES}
    for r in c.execute("SELECT severity, COUNT(*) n FROM incidents WHERE user_id=? AND status<>'Resolved' GROUP BY severity", (uid,)):
        sev[r['severity']] = r['n']
    status = {s: 0 for s in STATUSES}
    for r in c.execute('SELECT status, COUNT(*) n FROM incidents WHERE user_id=? GROUP BY status', (uid,)):
        status[r['status']] = r['n']
    mttr = c.execute("""SELECT AVG((julianday(resolved_at)-julianday(created))*24), COUNT(*) FROM incidents WHERE user_id=? AND status='Resolved' AND resolved_at IS NOT NULL""", (uid,)).fetchone()
    ctx.query = {'overdue': ['1'], 'sort': ['review']}
    return {'open': sum(sev.values()), 'severity': sev, 'status': status, 'total': sum(status.values()),
            'overdue': incident_query(ctx),
            'resolved_30d': c.execute("SELECT COUNT(*) FROM incidents WHERE user_id=? AND status='Resolved' AND resolved_at>=strftime('%Y-%m-%dT%H:%M:%SZ','now','-30 days')", (uid,)).fetchone()[0],
            'mean_hours_to_resolve': round(mttr[0], 1) if mttr[0] is not None else None, 'resolved_count': mttr[1],
            'assets': c.execute('SELECT COUNT(*) FROM assets WHERE user_id=?', (uid,)).fetchone()[0],
            'top_assets': rows(c.execute("""SELECT a.id, a.name, a.criticality, COUNT(*) n FROM incident_assets ia JOIN assets a ON a.id=ia.asset_id JOIN incidents i ON i.id=ia.incident_id
                WHERE a.user_id=? AND i.status<>'Resolved' GROUP BY a.id ORDER BY n DESC, a.name LIMIT 5""", (uid,))),
            'recent': rows(c.execute("""SELECT a.*, i.number, i.title FROM activity a LEFT JOIN incidents i ON i.id=a.incident_id WHERE a.user_id=? ORDER BY a.id DESC LIMIT 12""", (uid,)))}


@app.route('GET', '/api/incidents')
def list_incidents(ctx):
    return incident_query(ctx)


@app.route('POST', '/api/incidents')
def create_incident(ctx):
    v, ts = incident_form(ctx, ctx.body), now_iso()
    number = ctx.db.execute('SELECT COALESCE(MAX(number),0)+1 FROM incidents WHERE user_id=?', (ctx.uid,)).fetchone()[0]
    iid = ctx.db.execute("""INSERT INTO incidents(user_id,number,title,description,category,severity,status,review_date,detected_at,resolution_notes,resolved_at,created,updated)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""", (ctx.uid, number, v['title'], v['description'], v['category'], v['severity'], v['status'], v['review_date'], v['detected_at'],
                                            v['resolution_notes'], ts if v['status'] == 'Resolved' else None, ts, ts)).lastrowid
    set_assets(ctx, iid, v['asset_ids'])
    log(ctx.db, ctx.uid, iid, 'created', None, v['status'], f'Incident opened at {v["severity"]} severity')
    return 201, {'id': iid, 'number': number}


@app.route('GET', '/api/incidents/{id}')
def get_incident(ctx):
    inc = own_incident(ctx)
    ctx.query = {}
    inc = next(x for x in incident_query(ctx) if x['id'] == inc['id'])
    inc['assets'] = rows(ctx.db.execute('SELECT a.* FROM assets a JOIN incident_assets ia ON ia.asset_id=a.id WHERE ia.incident_id=? ORDER BY a.name', (inc['id'],)))
    comments = [{**r, 'type': 'comment'} for r in ctx.db.execute('SELECT id, body, author_email, created FROM comments WHERE incident_id=? AND user_id=?', (inc['id'], ctx.uid))]
    events = [{**r, 'type': 'event'} for r in ctx.db.execute('SELECT id, kind, from_value, to_value, message, created FROM activity WHERE incident_id=? AND user_id=? AND kind<>?', (inc['id'], ctx.uid, 'comment'))]
    inc['timeline'] = sorted(comments + events, key=lambda e: (e['created'], e['type'] == 'comment', e['id']), reverse=True)
    return inc


def apply_change(ctx, old, status, severity):
    """Log status/severity transitions and maintain resolved_at."""
    if old['status'] != status:
        log(ctx.db, ctx.uid, old['id'], 'status', old['status'], status, f'Status changed from {old["status"]} to {status}')
    if old['severity'] != severity:
        log(ctx.db, ctx.uid, old['id'], 'severity', old['severity'], severity, f'Severity changed from {old["severity"]} to {severity}')
    if status == 'Resolved':
        return old['resolved_at'] if old['status'] == 'Resolved' else now_iso()
    return None


@app.route('PUT', '/api/incidents/{id}')
def update_incident(ctx):
    old = own_incident(ctx)
    v = incident_form(ctx, ctx.body)
    resolved_at = apply_change(ctx, old, v['status'], v['severity'])
    ctx.db.execute("""UPDATE incidents SET title=?,description=?,category=?,severity=?,status=?,review_date=?,detected_at=?,resolution_notes=?,resolved_at=?,updated=?
        WHERE id=? AND user_id=?""", (v['title'], v['description'], v['category'], v['severity'], v['status'], v['review_date'], v['detected_at'],
                                      v['resolution_notes'], resolved_at, now_iso(), old['id'], ctx.uid))
    before = {r[0] for r in ctx.db.execute('SELECT asset_id FROM incident_assets WHERE incident_id=?', (old['id'],))}
    if before != set(v['asset_ids']):
        set_assets(ctx, old['id'], v['asset_ids'])
        log(ctx.db, ctx.uid, old['id'], 'assets', None, None, f'Affected assets updated ({len(v["asset_ids"])} linked)')
    if old['title'] != v['title'] or old['description'] != v['description'] or old['category'] != v['category']:
        log(ctx.db, ctx.uid, old['id'], 'edit', None, None, 'Incident details edited')
    return {'ok': True}


@app.route('POST', '/api/incidents/{id}/triage')
def triage(ctx):
    """Quick status/severity change from the console, with resolution notes when resolving."""
    old = own_incident(ctx)
    f = Form(ctx.body)
    status = f.choice('status', STATUSES, old['status']); severity = f.choice('severity', SEVERITIES, old['severity'])
    notes = f.text('resolution_notes', False, 10000) or old['resolution_notes']
    resolution_check(f, status, notes)
    f.done()
    resolved_at = apply_change(ctx, old, status, severity)
    ctx.db.execute('UPDATE incidents SET status=?, severity=?, resolution_notes=?, resolved_at=?, updated=? WHERE id=?', (status, severity, notes, resolved_at, now_iso(), old['id']))
    return {'ok': True}


@app.route('DELETE', '/api/incidents/{id}')
def delete_incident(ctx):
    own_incident(ctx)
    ctx.db.execute('DELETE FROM incidents WHERE id=? AND user_id=?', (ctx.params['id'], ctx.uid))
    return {'ok': True}


@app.route('POST', '/api/incidents/{id}/comments')
def add_comment(ctx):
    inc = own_incident(ctx)
    f = Form(ctx.body); body = f.text('body', True, 5000); f.done()
    cid = ctx.db.execute('INSERT INTO comments(user_id,incident_id,body,author_email,created) VALUES(?,?,?,?,?)', (ctx.uid, inc['id'], body, ctx.user['email'], now_iso())).lastrowid
    ctx.db.execute('UPDATE incidents SET updated=? WHERE id=?', (now_iso(), inc['id']))
    log(ctx.db, ctx.uid, inc['id'], 'comment', None, None, 'Comment added')
    return 201, {'id': cid}


@app.route('GET', '/api/assets')
def list_assets(ctx):
    sql = """SELECT a.*, COUNT(i.id) AS incident_count, SUM(CASE WHEN i.status<>'Resolved' THEN 1 ELSE 0 END) AS open_count
             FROM assets a LEFT JOIN incident_assets ia ON ia.asset_id=a.id LEFT JOIN incidents i ON i.id=ia.incident_id WHERE a.user_id=?"""
    args = [ctx.uid]
    if ctx.q('q'):
        sql += ' AND (a.name LIKE ? OR a.identifier LIKE ? OR a.owner LIKE ?)'; args += [f"%{ctx.q('q')}%"] * 3
    if ctx.q('type') in ASSET_TYPES:
        sql += ' AND a.type=?'; args.append(ctx.q('type'))
    if ctx.q('criticality') in CRITICALITY:
        sql += ' AND a.criticality=?'; args.append(ctx.q('criticality'))
    return rows(ctx.db.execute(sql + ' GROUP BY a.id ORDER BY a.name COLLATE NOCASE', args))


@app.route('POST', '/api/assets')
def create_asset(ctx):
    v, ts = asset_form(ctx.body), now_iso()
    aid = ctx.db.execute("""INSERT INTO assets(user_id,name,type,environment,criticality,owner,identifier,notes,created,updated) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                         (ctx.uid, v['name'], v['type'], v['environment'], v['criticality'], v['owner'], v['identifier'], v['notes'], ts, ts)).lastrowid
    return 201, {'id': aid}


@app.route('GET', '/api/assets/{id}')
def get_asset(ctx):
    a = one(ctx.db, 'SELECT * FROM assets WHERE id=? AND user_id=?', (ctx.params['id'], ctx.uid), 'Asset')
    ctx.query = {'asset_id': [str(a['id'])], 'sort': ['number']}
    a['incidents'] = incident_query(ctx)
    return a


@app.route('PUT', '/api/assets/{id}')
def update_asset(ctx):
    one(ctx.db, 'SELECT id FROM assets WHERE id=? AND user_id=?', (ctx.params['id'], ctx.uid), 'Asset')
    v = asset_form(ctx.body)
    ctx.db.execute('UPDATE assets SET name=?,type=?,environment=?,criticality=?,owner=?,identifier=?,notes=?,updated=? WHERE id=? AND user_id=?',
                   (v['name'], v['type'], v['environment'], v['criticality'], v['owner'], v['identifier'], v['notes'], now_iso(), ctx.params['id'], ctx.uid))
    return {'ok': True}


@app.route('DELETE', '/api/assets/{id}')
def delete_asset(ctx):
    a = one(ctx.db, 'SELECT * FROM assets WHERE id=? AND user_id=?', (ctx.params['id'], ctx.uid), 'Asset')
    for (iid,) in ctx.db.execute('SELECT incident_id FROM incident_assets WHERE asset_id=?', (a['id'],)).fetchall():
        log(ctx.db, ctx.uid, iid, 'assets', None, None, f'Asset “{a["name"]}” was deleted and unlinked')
    ctx.db.execute('DELETE FROM assets WHERE id=? AND user_id=?', (a['id'], ctx.uid))
    return {'ok': True}


@app.route('GET', '/api/export/incidents')
def export_incidents(ctx):
    data = [[f"INC-{i['number']:04d}", i['title'], i['category'], i['severity'], i['status'], i['asset_names'], i['review_date'], i['detected_at'],
             i['created'], i['updated'], i['resolved_at'], i['description'], i['resolution_notes']] for i in incident_query(ctx)]
    return Csv(f'signaldesk-incidents-{today()}.csv', ['Reference', 'Title', 'Category', 'Severity', 'Status', 'Affected assets', 'Review date', 'Detected at (local)',
                                                       'Created (UTC)', 'Updated (UTC)', 'Resolved (UTC)', 'Description', 'Resolution notes'], data)


if __name__ == '__main__':
    app.main(8005)
