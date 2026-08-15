const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const PORT = Number(process.env.PORT || 10000);
const ROOT = __dirname;
const SESSION_SECRET = process.env.APP_SESSION_SECRET;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!SESSION_SECRET || !SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error('Missing required environment variables: APP_SESSION_SECRET, SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY');
  process.exit(1);
}

const db = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false }
});

const rate = new Map();

function json(res, status, data, headers = {}) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'SAMEORIGIN',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(self "https://meet.jit.si"), microphone=(self "https://meet.jit.si"), geolocation=()',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' https://meet.jit.si; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https://meet.jit.si wss://meet.jit.si; frame-src 'self' https://meet.jit.si; object-src 'none'; base-uri 'self'; form-action 'self'",
    ...headers
  });
  res.end(body);
}

function clean(value, max) {
  return String(value ?? '').trim().slice(0, max);
}

function base64url(input) {
  return Buffer.from(input).toString('base64url');
}
function sign(payload) {
  const head = base64url(JSON.stringify({ alg:'HS256', typ:'JWT' }));
  const body = base64url(JSON.stringify(payload));
  const unsigned = `${head}.${body}`;
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(unsigned).digest('base64url');
  return `${unsigned}.${sig}`;
}
function verify(token) {
  if (!token) throw new Error('Unauthorized');
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Unauthorized');
  const unsigned = `${parts[0]}.${parts[1]}`;
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(unsigned).digest();
  const actual = Buffer.from(parts[2], 'base64url');
  if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) throw new Error('Unauthorized');
  const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
  if (!payload.exp || payload.exp < Math.floor(Date.now()/1000)) throw new Error('Session expired');
  return payload;
}
function bearer(req) {
  const h = req.headers.authorization || '';
  return h.startsWith('Bearer ') ? h.slice(7) : null;
}
async function currentUser(req) {
  const payload = verify(bearer(req));
  const { data, error } = await db.from('users')
    .select('id,auth_user_id,full_name,email,reg_no,role,is_password_changed,created_at')
    .eq('auth_user_id', payload.sub).maybeSingle();
  if (error || !data) throw new Error('User account not found');
  return data;
}

function hashPassword(password) {
  return new Promise((resolve,reject) => {
    const salt = crypto.randomBytes(16).toString('base64url');
    crypto.scrypt(password, salt, 64, { N:16384, r:8, p:1, maxmem:64*1024*1024 }, (err, derived) => {
      if (err) return reject(err);
      resolve(`scrypt$16384$8$1$${salt}$${derived.toString('base64url')}`);
    });
  });
}
function verifyPassword(password, stored) {
  return new Promise((resolve,reject) => {
    const p = String(stored || '').split('$');
    if (p.length !== 6 || p[0] !== 'scrypt') return resolve(false);
    const [,n,r,pp,salt,encoded] = p;
    const expected = Buffer.from(encoded,'base64url');
    crypto.scrypt(password, salt, expected.length, { N:Number(n), r:Number(r), p:Number(pp), maxmem:64*1024*1024 }, (err, derived) => {
      if (err) return reject(err);
      resolve(expected.length === derived.length && crypto.timingSafeEqual(expected, derived));
    });
  });
}
function randomPassword() {
  return crypto.randomBytes(12).toString('base64url').replace(/[-_]/g,'').slice(0,14);
}
function clientIp(req) {
  return (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
}
function limited(req, bucket, max, windowMs) {
  const key = `${bucket}:${clientIp(req)}`;
  const now = Date.now();
  const hit = rate.get(key);
  if (!hit || now - hit.start > windowMs) {
    rate.set(key,{start:now,count:1});
    return false;
  }
  hit.count++;
  return hit.count > max;
}
async function body(req) {
  let raw = '';
  for await (const chunk of req) {
    raw += chunk;
    if (Buffer.byteLength(raw) > 1024*1024) throw new Error('Request too large');
  }
  try { return JSON.parse(raw || '{}'); } catch { throw new Error('Invalid JSON'); }
}

async function route(req,res,url) {
  if (req.method === 'GET' && url.pathname === '/health') return json(res,200,{ok:true,service:'TCC ProjectHub'});
  if (url.pathname === '/api/login' && req.method === 'POST') {
    if (limited(req,'login',10,15*60*1000)) return json(res,429,{error:'Majaribio mengi ya login. Subiri dakika chache.'});
    const b = await body(req);
    const identifier = clean(b.identifier,254);
    const password = String(b.password || '');
    if (!identifier || !password || password.length > 256) return json(res,400,{error:'Email/Reg No na password vinahitajika.'});
    let {data:user,error} = await db.from('users').select('id,auth_user_id,full_name,email,reg_no,role,password,password_hash,is_password_changed,created_at').ilike('email',identifier).maybeSingle();
    if (error) throw error;
    if (!user) {
      const r = await db.from('users').select('id,auth_user_id,full_name,email,reg_no,role,password,password_hash,is_password_changed,created_at').ilike('reg_no',identifier).maybeSingle();
      if (r.error) throw r.error; user=r.data;
    }
    let valid=false;
    if (user) valid = user.password_hash ? await verifyPassword(password,user.password_hash) : String(user.password ?? '') === password;
    if (!user || !valid) return json(res,401,{error:'Taarifa za kuingia si sahihi.'});
    if (!user.password_hash) {
      const hash = await hashPassword(password);
      const up = await db.from('users').update({password_hash:hash,password:null}).eq('id',user.id);
      if (up.error) throw up.error;
    }
    if (!user.auth_user_id) {
      user.auth_user_id=crypto.randomUUID();
      const up=await db.from('users').update({auth_user_id:user.auth_user_id}).eq('id',user.id);
      if(up.error) throw up.error;
    }
    const now=Math.floor(Date.now()/1000);
    const accessToken=sign({sub:user.auth_user_id,role:user.role,iat:now,exp:now+12*60*60});
    delete user.password; delete user.password_hash;
    return json(res,200,{accessToken,user});
  }

  if (url.pathname === '/api/me' && req.method === 'GET') {
    const user=await currentUser(req); return json(res,200,{user});
  }

  if (url.pathname === '/api/change-password' && req.method === 'POST') {
    const user=await currentUser(req), b=await body(req), pass=String(b.newPassword||'');
    if(pass.length<8 || pass.length>128) return json(res,400,{error:'Password mpya iwe na characters 8 hadi 128.'});
    const password_hash=await hashPassword(pass);
    const {error}=await db.from('users').update({password_hash,password:null,is_password_changed:true}).eq('id',user.id);
    if(error) throw error;
    return json(res,200,{ok:true});
  }

  if (url.pathname === '/api/members' && req.method === 'GET') {
    const user=await currentUser(req);
    if(user.role!=='admin') return json(res,403,{error:'Admin permission required.'});
    const {data,error}=await db.from('users').select('id,auth_user_id,full_name,email,reg_no,role,is_password_changed,created_at').order('created_at',{ascending:false});
    if(error) throw error; return json(res,200,{members:data||[]});
  }

  if (url.pathname === '/api/members' && req.method === 'POST') {
    const admin=await currentUser(req);
    if(admin.role!=='admin') return json(res,403,{error:'Admin permission required.'});
    if(limited(req,'create',30,60*60*1000)) return json(res,429,{error:'Jaribu tena baadaye.'});
    const b=await body(req);
    const full_name=clean(b.full_name,120), email=clean(b.email,254).toLowerCase(), reg_no=clean(b.reg_no,80);
    if(!full_name || !email || !reg_no) return json(res,400,{error:'Jina, email na Reg No vinahitajika.'});
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json(res,400,{error:'Email si sahihi.'});
    const tempPassword=randomPassword(), password_hash=await hashPassword(tempPassword);
    const row={auth_user_id:crypto.randomUUID(),full_name,email,reg_no,role:'member',password_hash,password:null,is_password_changed:false};
    const {data,error}=await db.from('users').insert(row).select('id,auth_user_id,full_name,email,reg_no,role,is_password_changed,created_at').single();
    if(error) return json(res,error.code==='23505'?409:500,{error:error.code==='23505'?'Email au Reg No tayari ipo.':error.message});
    return json(res,201,{user:data,temporaryPassword:tempPassword});
  }

  if (url.pathname === '/api/members/delete' && req.method === 'POST') {
    const admin=await currentUser(req);
    if(admin.role!=='admin') return json(res,403,{error:'Admin permission required.'});
    const b=await body(req), userId=Number(b.userId);
    if(!Number.isInteger(userId)) return json(res,400,{error:'User id si sahihi.'});
    const {data:target,error:lookup}=await db.from('users').select('id,role').eq('id',userId).maybeSingle();
    if(lookup) throw lookup;
    if(!target) return json(res,404,{error:'User not found.'});
    if(target.role==='admin') return json(res,403,{error:'Admin account haiwezi kufutwa hapa.'});
    const {error}=await db.from('users').delete().eq('id',userId);
    if(error) throw error;
    return json(res,200,{ok:true});
  }

  if (url.pathname === '/api/saved-code/latest' && req.method === 'GET') {
    const user=await currentUser(req);
    const {data,error}=await db.from('saved_codes').select('code_content,updated_at').eq('owner_auth_id',user.auth_user_id).order('updated_at',{ascending:false}).limit(1).maybeSingle();
    if(error) throw error; return json(res,200,{code:data?.code_content||null,updatedAt:data?.updated_at||null});
  }

  if (url.pathname === '/api/saved-code' && req.method === 'POST') {
    const user=await currentUser(req), b=await body(req), code=String(b.code||'');
    if(!code.trim()) return json(res,400,{error:'Kodi iko tupu.'});
    if(code.length>500000) return json(res,413,{error:'Kodi ni kubwa sana.'});
    const {error}=await db.from('saved_codes').insert({owner_id:user.id,owner_auth_id:user.auth_user_id,code_content:code});
    if(error) throw error; return json(res,201,{ok:true});
  }

  if (url.pathname === '/api/messages' && req.method === 'GET') {
    await currentUser(req);
    const {data,error}=await db.from('messages').select('id,sender_name,sender_auth_id,message_text,created_at').order('created_at',{ascending:true}).limit(200);
    if(error) throw error; return json(res,200,{messages:data||[]});
  }

  if (url.pathname === '/api/messages' && req.method === 'POST') {
    const user=await currentUser(req), b=await body(req), message=clean(b.message,2000);
    if(!message) return json(res,400,{error:'Ujumbe hauwezi kuwa tupu.'});
    if(limited(req,'chat',60,60*1000)) return json(res,429,{error:'Umetuma ujumbe mwingi. Subiri kidogo.'});
    const {data,error}=await db.from('messages').insert({sender_name:user.full_name,sender_auth_id:user.auth_user_id,message_text:message}).select('id,sender_name,sender_auth_id,message_text,created_at').single();
    if(error) throw error; return json(res,201,{message:data});
  }

  if (url.pathname === '/api/messages/clear' && req.method === 'POST') {
    const user=await currentUser(req);
    if(user.role!=='admin') return json(res,403,{error:'Admin permission required.'});
    const {error}=await db.from('messages').delete().not('id','is',null);
    if(error) throw error; return json(res,200,{ok:true});
  }

  return null;
}

const MIME={'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'application/javascript; charset=utf-8','.json':'application/json; charset=utf-8','.ico':'image/x-icon','.png':'image/png','.jpg':'image/jpeg','.svg':'image/svg+xml','.txt':'text/plain; charset=utf-8'};

function serveStatic(req,res,url) {
  let pathname=decodeURIComponent(url.pathname);
  if(pathname==='/' || pathname==='/index.html') pathname='/login.html';
  const file=path.normalize(path.join(ROOT,pathname));
  if(!file.startsWith(ROOT)) return json(res,403,{error:'Forbidden'});
  let target=file;
  if(!path.extname(target)) target=path.join(ROOT,'404.html');
  if(!fs.existsSync(target) || fs.statSync(target).isDirectory()) target=path.join(ROOT,'404.html');
  const ext=path.extname(target);
  res.writeHead(200,{
    'Content-Type':MIME[ext]||'application/octet-stream',
    'Cache-Control':ext==='.html'?'no-store':'public, max-age=300',
    'X-Content-Type-Options':'nosniff','X-Frame-Options':'SAMEORIGIN',
    'Referrer-Policy':'strict-origin-when-cross-origin',
    'Content-Security-Policy':"default-src 'self'; script-src 'self' 'unsafe-inline' https://meet.jit.si; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https://meet.jit.si wss://meet.jit.si; frame-src 'self' https://meet.jit.si; object-src 'none'; base-uri 'self'; form-action 'self'",
    'Permissions-Policy':'camera=(self "https://meet.jit.si"), microphone=(self "https://meet.jit.si"), geolocation=()'
  });
  fs.createReadStream(target).pipe(res);
}

const server=http.createServer(async(req,res)=>{
  try{
    const url=new URL(req.url,`http://${req.headers.host||'localhost'}`);
    if(req.method==='OPTIONS'){res.writeHead(204,{'Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'Authorization, Content-Type','Access-Control-Allow-Methods':'GET, POST, OPTIONS'});return res.end();}
    const handled=await route(req,res,url);
    if(handled!==null) return;
    if(url.pathname.startsWith('/api/')) return json(res,404,{error:'Endpoint not found'});
    return serveStatic(req,res,url);
  }catch(error){
    console.error(error);
    const status=/Unauthorized|expired|not found/i.test(error.message||'')?401:500;
    return json(res,status,{error:status===401?'Session imekwisha au haipo.':'Server error. Angalia Render logs.'});
  }
});

server.listen(PORT,'0.0.0.0',()=>console.log(`TCC ProjectHub running on port ${PORT}`));
