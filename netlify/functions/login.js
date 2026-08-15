const crypto = require('crypto');
const { adminClient, json, passwordHash, passwordVerify, signToken } = require('./_shared');

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return json(405, { error: 'Method not allowed' });
  try {
    const { identifier, password } = JSON.parse(event.body || '{}');
    const id = String(identifier || '').trim();
    const pass = String(password || '');
    if (!id || !pass || pass.length > 256) return json(400, { error: 'Email/Reg No na password vinahitajika.' });

    const supabase = adminClient();
    const fields = 'id,auth_user_id,full_name,email,reg_no,role,password,password_hash,is_password_changed,created_at';
    let { data: user, error } = await supabase.from('users').select(fields).eq('email', id).maybeSingle();
    if (error) throw error;
    if (!user) {
      const result = await supabase.from('users').select(fields).eq('reg_no', id).maybeSingle();
      if (result.error) throw result.error;
      user = result.data;
    }
    if (!user) return json(401, { error: 'Taarifa za kuingia si sahihi.' });
    let valid = false;
    if (user.password_hash) valid = await passwordVerify(pass, user.password_hash);
    else if (user.password != null) valid = String(user.password) === pass;
    if (!valid) return json(401, { error: 'Taarifa za kuingia si sahihi.' });

    if (!user.auth_user_id) {
      const authUserId = crypto.randomUUID();
      await supabase.from('users').update({ auth_user_id: authUserId }).eq('id', user.id);
      user.auth_user_id = authUserId;
    }
    if (!user.password_hash) {
      const hash = await passwordHash(pass);
      await supabase.from('users').update({ password_hash: hash, password: null }).eq('id', user.id);
    }

    const now = Math.floor(Date.now() / 1000);
    const accessToken = signToken({ iss: 'supabase', sub: user.auth_user_id, aud: 'authenticated', role: 'authenticated', iat: now, exp: now + 12 * 60 * 60, email: user.email });
    delete user.password;
    delete user.password_hash;
    return json(200, { accessToken, user: { ...user, is_password_changed: Boolean(user.is_password_changed) } });
  } catch (error) {
    return json(500, { error: error.message || 'Login failed' });
  }
};
