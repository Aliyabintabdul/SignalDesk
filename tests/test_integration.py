import shutil, tempfile, unittest
from pathlib import Path
import harness
from harness import Client, Server, ROOT


class SignalDeskTests(harness.AppTestCase):
    def incident(self, c, **kw):
        return self.assertStatus(c.post('/api/incidents', {'title': 'Odd login', 'category': 'Unauthorized access', 'severity': 'High', 'status': 'Open', **kw}), 201)

    def test_resolution_requires_notes(self):
        c = self.client('r@example.com')
        e = self.assertStatus(c.post('/api/incidents', {'title': 'x', 'status': 'Resolved'}), 400)
        self.assertIn('resolution_notes', e['fields'])
        iid = self.incident(c)['id']
        self.assertStatus(c.post(f'/api/incidents/{iid}/triage', {'status': 'Resolved'}), 400)
        self.assertStatus(c.post(f'/api/incidents/{iid}/triage', {'status': 'Resolved', 'resolution_notes': 'too short'}), 400)
        self.assertStatus(c.put(f'/api/incidents/{iid}', {'title': 'Odd login', 'status': 'Resolved', 'resolution_notes': '   '}), 400)
        self.assertStatus(c.post(f'/api/incidents/{iid}/triage', {'status': 'Resolved', 'resolution_notes': 'Password reset, MFA enforced.'}), 200)
        inc = c.get(f'/api/incidents/{iid}')[1]
        self.assertEqual(inc['status'], 'Resolved'); self.assertIsNotNone(inc['resolved_at'])
        self.assertStatus(c.post(f'/api/incidents/{iid}/triage', {'status': 'Investigating'}), 200)  # reopen
        self.assertIsNone(c.get(f'/api/incidents/{iid}')[1]['resolved_at'])

    def test_comments_activity_assets_and_metrics(self):
        c = self.client('w@example.com')
        a1 = self.assertStatus(c.post('/api/assets', {'name': 'SSO', 'type': 'Identity system', 'environment': 'Production', 'criticality': 'Critical'}), 201)['id']
        a2 = self.assertStatus(c.post('/api/assets', {'name': 'Laptop 7', 'type': 'Workstation'}), 201)['id']
        self.assertStatus(c.post('/api/assets', {'name': 'x', 'type': 'Toaster'}), 400)
        r = self.incident(c, asset_ids=[a1, a2], review_date='2020-01-01')
        iid = r['id']; self.assertEqual(r['number'], 1)
        self.assertEqual(self.incident(c, severity='Low', title='Second')['number'], 2)
        self.assertStatus(c.post('/api/incidents', {'title': 'bad', 'asset_ids': [9999]}), 400)
        self.assertStatus(c.post(f'/api/incidents/{iid}/comments', {'body': ''}), 400)
        self.assertStatus(c.post(f'/api/incidents/{iid}/comments', {'body': 'Checked gateway logs.'}), 201)
        self.assertStatus(c.post(f'/api/incidents/{iid}/triage', {'status': 'Investigating', 'severity': 'Critical'}), 200)
        inc = c.get(f'/api/incidents/{iid}')[1]
        self.assertEqual(sorted(a['name'] for a in inc['assets']), ['Laptop 7', 'SSO'])
        kinds = [e.get('kind', 'comment') if e['type'] == 'event' else 'comment' for e in inc['timeline']]
        self.assertTrue({'created', 'status', 'severity', 'comment'} <= set(kinds))
        self.assertTrue(any(e.get('from_value') == 'High' and e.get('to_value') == 'Critical' for e in inc['timeline']))
        d = c.get('/api/dashboard')[1]
        self.assertEqual((d['open'], d['severity']['Critical'], d['severity']['Low'], len(d['overdue'])), (2, 1, 1, 1))
        self.assertEqual(len(c.get('/api/incidents?severity=Critical')[1]), 1)
        self.assertEqual(len(c.get(f'/api/incidents?asset_id={a2}')[1]), 1)
        self.assertEqual(len(c.get('/api/incidents?q=INC-0002')[1]), 1)
        self.assertEqual(c.get(f'/api/assets/{a1}')[1]['incidents'][0]['id'], iid)
        self.assertStatus(c.delete(f'/api/assets/{a2}'), 200)  # unlinks, keeps the incident, logs it
        inc = c.get(f'/api/incidents/{iid}')[1]
        self.assertEqual([a['name'] for a in inc['assets']], ['SSO'])
        self.assertTrue(any('Laptop 7' in e.get('message', '') for e in inc['timeline']))
        self.assertStatus(c.delete(f'/api/incidents/{iid}'), 200)
        self.assertEqual(c.get('/api/dashboard')[1]['open'], 1)

    def test_account_isolation(self):
        a, b = self.client('xa@example.com'), self.client('xb@example.com')
        aid = a.post('/api/assets', {'name': 'Mine'})[1]['id']
        iid = self.incident(a, asset_ids=[aid])['id']
        self.assertEqual(b.get('/api/incidents')[1], []); self.assertEqual(b.get('/api/assets')[1], [])
        self.assertStatus(b.get(f'/api/incidents/{iid}'), 404)
        self.assertStatus(b.post(f'/api/incidents/{iid}/comments', {'body': 'hi'}), 404)
        self.assertStatus(b.post(f'/api/incidents/{iid}/triage', {'status': 'Contained'}), 404)
        self.assertStatus(b.post('/api/incidents', {'title': 'x', 'asset_ids': [aid]}), 400)
        self.assertStatus(b.delete(f'/api/assets/{aid}'), 404)
        self.assertEqual(self.incident(b)['number'], 1)  # numbering is per account
        self.assertEqual(b.get('/api/dashboard')[1]['open'], 1)

    def test_csv_export(self):
        c = self.client('csv@example.com')
        self.incident(c, title='=HYPERLINK("x")', description='+danger')
        s, text = c.get('/api/export/incidents?status=open', raw=True)
        self.assertEqual(s, 200); self.assertIn("'=HYPERLINK", text); self.assertIn("'+danger", text); self.assertIn('INC-0001', text)


class PersistenceAndMigration(unittest.TestCase):
    def test_restart_keeps_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            srv = Server(Path(tmp) / 'p.sqlite3').start()
            c = Client(srv.port); c.register('p@example.com')
            c.post('/api/incidents', {'title': 'Kept'})
            srv.stop(); srv.start()
            c2 = Client(srv.port); c2.login('p@example.com')
            self.assertEqual(c2.get('/api/incidents')[1][0]['title'], 'Kept')
            srv.stop()

    @unittest.skipUnless((ROOT / 'data.pre-saas.sqlite3').exists(), 'legacy database not present')
    def test_existing_legacy_database_migrates(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / 'legacy.sqlite3'
            shutil.copy(ROOT / 'data.pre-saas.sqlite3', db)
            srv = Server(db).start()
            c = Client(srv.port)
            self.assertEqual(c.login('demo@example.com', 'DemoPass123!')[0], 200)
            incs = c.get('/api/incidents')[1]
            self.assertEqual(len(incs), 3)
            first = next(i for i in incs if i['title'] == 'Repeated failed sign-ins')
            self.assertEqual((first['severity'], first['status'], first['asset_names']), ('High', 'Investigating', 'Identity gateway'))
            srv.stop()


if __name__ == '__main__':
    unittest.main()
