from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs
import sqlite3, json, secrets, hashlib, hmac, os, argparse, mimetypes, math
from datetime import date
BASE=Path(__file__).resolve().parent
CONFIG=json.loads((BASE/'config.json').read_text())
DB=BASE/'data.sqlite3'
def connect():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; c.execute('PRAGMA foreign_keys=ON'); return c
def password(p,s): return hashlib.pbkdf2_hmac('sha256',p.encode(),bytes.fromhex(s),200000).hex()
def initialize():
    with connect() as c:
        c.executescript('CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,email TEXT UNIQUE,password TEXT,salt TEXT); CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id INTEGER REFERENCES users(id),expires INTEGER); CREATE TABLE IF NOT EXISTS records(id INTEGER PRIMARY KEY,user_id INTEGER REFERENCES users(id),title TEXT,category TEXT,amount REAL,due TEXT,status TEXT,notes TEXT); CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,user_id INTEGER REFERENCES users(id),message TEXT,created TEXT DEFAULT CURRENT_TIMESTAMP);')
        if not c.execute('SELECT id FROM users WHERE email=?',('demo@example.com',)).fetchone():
            s=secrets.token_hex(16); uid=c.execute('INSERT INTO users(email,password,salt) VALUES(?,?,?)',('demo@example.com',password('DemoPass123!',s),s)).lastrowid
            for t,k,a,d,st in CONFIG['rows']: c.execute('INSERT INTO records(user_id,title,category,amount,due,status,notes) VALUES(?,?,?,?,?,?,?)',(uid,t,k,a,d,st,'Sample record — edit me to explore the workflow.'))
def validate(b):
    t=str(b.get('title','')).strip(); cat=str(b.get('category','')).strip(); due=str(b.get('due','')); st=b.get('status')
    try: a=float(b.get('amount',0)); date.fromisoformat(due)
    except (ValueError,TypeError): raise ValueError('Enter a valid number and date.')
    if not t or len(t)>160 or len(cat)>160 or not math.isfinite(a) or a<0 or a>1e9 or st not in CONFIG['statuses']: raise ValueError('Check title, category, amount and status.')
    if CONFIG['name']=='SignalDesk' and (a<1 or a>5 or not a.is_integer()): raise ValueError('Severity must be a whole number from 1 to 5.')
    if CONFIG['name']=='Stockroom' and not a.is_integer(): raise ValueError('Quantity must be a whole number.')
    return t,cat,a,due,st,str(b.get('notes',''))[:5000]
class Handler(BaseHTTPRequestHandler):
    def reply(self,obj,status=200,cookie=None):
        data=json.dumps(obj,allow_nan=False).encode(); self.send_response(status); self.send_header('Content-Type','application/json'); self.send_header('Cache-Control','no-store')
        if cookie: self.send_header('Set-Cookie',cookie)
        self.end_headers(); self.wfile.write(data)
    def dispatch(self):
        p=urlparse(self.path).path
        if not p.startswith('/api/'):
            if self.command!='GET': return self.reply({'error':'Method not allowed'},405)
            target=(BASE/'frontend'/('index.html' if p=='/' else p.lstrip('/'))).resolve()
            if not target.is_relative_to((BASE/'frontend').resolve()) or not target.is_file(): return self.reply({'error':'Not found'},404)
            self.send_response(200); self.send_header('Content-Type',mimetypes.guess_type(target)[0] or 'application/octet-stream'); self.end_headers(); self.wfile.write(target.read_bytes()); return
        b={}
        if self.command in ('POST','PUT'):
            if self.headers.get('Sec-Fetch-Site')=='cross-site': return self.reply({'error':'Cross-site request blocked'},403)
            origin=self.headers.get('Origin')
            if origin and urlparse(origin).netloc!=self.headers.get('Host'): return self.reply({'error':'Origin rejected'},403)
            n=int(self.headers.get('Content-Length',0))
            if n>20000: return self.reply({'error':'Request too large'},413)
            b=json.loads(self.rfile.read(n) or b'{}')
            if not isinstance(b,dict): raise ValueError('JSON object required')
        if p=='/api/config' and self.command=='GET': return self.reply({k:v for k,v in CONFIG.items() if k!='rows'})
        with connect() as c:
            if p in ('/api/login','/api/register') and self.command=='POST':
                email=str(b.get('email','')).strip().lower(); pw=str(b.get('password',''))
                if '@' not in email or len(email)>254 or len(pw)<10 or len(pw)>128: raise ValueError('Use a valid email and a password of 10–128 characters.')
                u=c.execute('SELECT * FROM users WHERE email=?',(email,)).fetchone()
                if p.endswith('register'):
                    if u: raise ValueError('Email already registered.')
                    s=secrets.token_hex(16); uid=c.execute('INSERT INTO users(email,password,salt) VALUES(?,?,?)',(email,password(pw,s),s)).lastrowid
                else:
                    if not u or not hmac.compare_digest(u['password'],password(pw,u['salt'])): return self.reply({'error':'Invalid credentials'},401)
                    uid=u['id']
                token=secrets.token_urlsafe(32); c.execute("INSERT INTO sessions VALUES(?,?,strftime('%s','now')+86400)",(token,uid)); return self.reply({'ok':True},cookie=f'session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400')
            cookies=dict(x.strip().split('=',1) for x in self.headers.get('Cookie','').split(';') if '=' in x)
            token=cookies.get('session',''); session=c.execute("SELECT user_id FROM sessions WHERE token=? AND expires>strftime('%s','now')",(token,)).fetchone()
            if not session: return self.reply({'error':'Please sign in'},401)
            uid=session['user_id']
            if p=='/api/logout' and self.command=='POST':
                c.execute('DELETE FROM sessions WHERE token=?',(token,)); return self.reply({'ok':True},cookie='session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0')
            if p=='/api/me' and self.command=='GET': return self.reply(dict(c.execute('SELECT email FROM users WHERE id=?',(uid,)).fetchone()))
            if p=='/api/events' and self.command=='GET': return self.reply([dict(x) for x in c.execute('SELECT message,created FROM events WHERE user_id=? ORDER BY id DESC LIMIT 20',(uid,))])
            if p=='/api/records' and self.command=='GET': return self.reply([dict(x) for x in c.execute('SELECT * FROM records WHERE user_id=? ORDER BY due,id',(uid,))])
            if p=='/api/records' and self.command=='POST':
                v=validate(b); rid=c.execute('INSERT INTO records(user_id,title,category,amount,due,status,notes) VALUES(?,?,?,?,?,?,?)',(uid,*v)).lastrowid; c.execute('INSERT INTO events(user_id,message) VALUES(?,?)',(uid,'Created: '+v[0])); return self.reply({'id':rid},201)
            parts=p.strip('/').split('/')
            if len(parts) in (3,4) and parts[:2]==['api','records']:
                rid=int(parts[2]); r=c.execute('SELECT * FROM records WHERE id=? AND user_id=?',(rid,uid)).fetchone()
                if not r: return self.reply({'error':'Record not found'},404)
                if len(parts)==4 and parts[3]=='action' and self.command=='POST':
                    if CONFIG['name']=='Stockroom':
                        delta=int(b.get('delta',0)); a=r['amount']+delta
                        if a<0 or abs(delta)>100000: raise ValueError('Adjustment would create invalid stock.')
                        st='Low stock' if a<5 else 'In stock'; c.execute('UPDATE records SET amount=?,status=? WHERE id=?',(a,st,rid)); msg=f"Stock adjusted by {delta}: {r['title']}"
                    else:
                        ix=CONFIG['statuses'].index(r['status']); st=CONFIG['statuses'][min(ix+1,len(CONFIG['statuses'])-1)]; c.execute('UPDATE records SET status=? WHERE id=?',(st,rid)); msg=f"{r['title']} → {st}"
                    c.execute('INSERT INTO events(user_id,message) VALUES(?,?)',(uid,msg)); return self.reply({'ok':True})
                if len(parts)==3 and self.command=='PUT':
                    v=validate(b); c.execute('UPDATE records SET title=?,category=?,amount=?,due=?,status=?,notes=? WHERE id=?',(*v,rid)); c.execute('INSERT INTO events(user_id,message) VALUES(?,?)',(uid,'Updated: '+v[0])); return self.reply({'ok':True})
                if len(parts)==3 and self.command=='DELETE':
                    if self.headers.get('Sec-Fetch-Site')=='cross-site': return self.reply({'error':'Cross-site request blocked'},403)
                    c.execute('DELETE FROM records WHERE id=?',(rid,)); c.execute('INSERT INTO events(user_id,message) VALUES(?,?)',(uid,'Deleted: '+r['title'])); return self.reply({'ok':True})
            return self.reply({'error':'Route not found'},404)
    def safe(self):
        try: self.dispatch()
        except (ValueError,TypeError,KeyError,OverflowError): self.reply({'error':'Invalid input. Check all fields.'},400)
        except sqlite3.Error: self.reply({'error':'Database operation failed'},500)
    do_GET=safe; do_POST=safe; do_PUT=safe; do_DELETE=safe
if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--port',type=int,default=8000); args=parser.parse_args(); initialize(); print(f"{CONFIG['name']} running at http://localhost:{args.port}",flush=True); ThreadingHTTPServer(('127.0.0.1',args.port),Handler).serve_forever()
