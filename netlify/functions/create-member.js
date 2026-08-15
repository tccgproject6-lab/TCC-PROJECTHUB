const { adminClient, json, currentUser, passwordHash, randomPassword } = require('./_shared');
const crypto = require('crypto');

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return json(405, { error: 'Method not allowed' });
  try {
    const admin = await currentUser(event);
    if (admin.role !== 'admin') return json(403, { error: 'Admin permission required.' });
    const body = JSON.parse(event.body || '{}');
    const full_name = String(body.full_name || '').trim();
    const email = String(body.email || '').trim().toLowerCase();
    const reg_no = String(body.reg_no || '').trim();
    if (!full_name || !email || !reg_no) return json(400, { error: 'Jina, email na Reg No vinahitajika.' });
    if (full_name.length > 120 || email.length > 254 || reg_no.length > 80) return json(400, { error: 'Taarifa ni ndefu sana.' });

    const supabase = adminClient();
    const tempPassword = randomPassword();
    const hash = await passwordHash(tempPassword);
    const row = { auth_user_id: crypto.randomUUID(), full_name, email, reg_no, role: 'member', password_hash: hash, password: null, is_password_changed: false };
    const { data, error } = await supabase.from('users').insert(row).select('id,auth_user_id,full_name,email,reg_no,role,is_password_changed,created_at').single();
    if (error) throw error;
    return json(201, { user: data, temporaryPassword: tempPassword });
  } catch (error) {
    const code = error.code === '23505' ? 409 : (error.message === 'Unauthorized' || error.message === 'Session expired' ? 401 : 500);
    return json(code, { error: error.code === '23505' ? 'Email au Reg No tayari ipo.' : error.message });
  }
};
