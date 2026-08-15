const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

function env(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Missing environment variable: ${name}`);
  return value;
}

function adminClient() {
  return createClient(env('SUPABASE_URL'), env('SUPABASE_SERVICE_ROLE_KEY'), {
    auth: { persistSession: false, autoRefreshToken: false }
  });
}

function json(statusCode, body, extraHeaders = {}) {
  return {
    statusCode,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...extraHeaders },
    body: JSON.stringify(body)
  };
}

function getBearer(event) {
  const header = event.headers?.authorization || event.headers?.Authorization || '';
  return header.startsWith('Bearer ') ? header.slice(7) : null;
}

function base64url(input) {
  return Buffer.from(input).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function signToken(payload) {
  const header = base64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = base64url(JSON.stringify(payload));
  const unsigned = `${header}.${body}`;
  const signature = crypto.createHmac('sha256', env('SUPABASE_JWT_SECRET')).update(unsigned).digest('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  return `${unsigned}.${signature}`;
}

function verifyToken(token) {
  if (!token) throw new Error('Unauthorized');
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Unauthorized');
  const unsigned = `${parts[0]}.${parts[1]}`;
  const expected = crypto.createHmac('sha256', env('SUPABASE_JWT_SECRET')).update(unsigned).digest();
  const actual = Buffer.from(parts[2].replace(/-/g, '+').replace(/_/g, '/') + '==', 'base64');
  if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) throw new Error('Unauthorized');
  const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  if (!payload.exp || payload.exp <= Math.floor(Date.now() / 1000)) throw new Error('Session expired');
  return payload;
}

function passwordHash(password) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16).toString('base64url');
    crypto.scrypt(password, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }, (err, derived) => {
      if (err) return reject(err);
      resolve(`scrypt$16384$8$1$${salt}$${derived.toString('base64url')}`);
    });
  });
}

function passwordVerify(password, stored) {
  return new Promise((resolve, reject) => {
    const parts = String(stored || '').split('$');
    if (parts.length !== 6 || parts[0] !== 'scrypt') return resolve(false);
    const [, n, r, p, salt, encoded] = parts;
    const expected = Buffer.from(encoded, 'base64url');
    crypto.scrypt(password, salt, expected.length, { N: Number(n), r: Number(r), p: Number(p), maxmem: 64 * 1024 * 1024 }, (err, derived) => {
      if (err) return reject(err);
      resolve(expected.length === derived.length && crypto.timingSafeEqual(expected, derived));
    });
  });
}

function randomPassword() {
  return crypto.randomBytes(9).toString('base64url').replace(/[-_]/g, '').slice(0, 12);
}

async function currentUser(event) {
  const payload = verifyToken(getBearer(event));
  const supabase = adminClient();
  const { data, error } = await supabase.from('users').select('id,auth_user_id,full_name,email,reg_no,role,is_password_changed,created_at').eq('auth_user_id', payload.sub).maybeSingle();
  if (error || !data) throw new Error('User account not found');
  return data;
}

module.exports = { env, adminClient, json, getBearer, signToken, verifyToken, passwordHash, passwordVerify, randomPassword, currentUser };
