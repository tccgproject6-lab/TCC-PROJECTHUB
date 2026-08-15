const { adminClient, json, currentUser, passwordHash } = require('./_shared');

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return json(405, { error: 'Method not allowed' });
  try {
    const user = await currentUser(event);
    const { newPassword } = JSON.parse(event.body || '{}');
    const pass = String(newPassword || '');
    if (pass.length < 8 || pass.length > 128) return json(400, { error: 'Password mpya iwe na angalau characters 8.' });
    const hash = await passwordHash(pass);
    const supabase = adminClient();
    const { error } = await supabase.from('users').update({ password_hash: hash, password: null, is_password_changed: true }).eq('auth_user_id', user.auth_user_id);
    if (error) throw error;
    return json(200, { ok: true });
  } catch (error) {
    return json(error.message === 'Unauthorized' || error.message === 'Session expired' ? 401 : 500, { error: error.message });
  }
};
