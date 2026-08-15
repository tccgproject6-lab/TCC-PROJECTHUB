const { adminClient, json, currentUser } = require('./_shared');

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') return json(405, { error: 'Method not allowed' });
  try {
    const admin = await currentUser(event);
    if (admin.role !== 'admin') return json(403, { error: 'Admin permission required.' });
    const { userId } = JSON.parse(event.body || '{}');
    if (!userId) return json(400, { error: 'User id missing.' });
    const supabase = adminClient();
    const { data: target, error: lookupError } = await supabase.from('users').select('id,role').eq('id', userId).maybeSingle();
    if (lookupError) throw lookupError;
    if (!target) return json(404, { error: 'User not found.' });
    if (target.role === 'admin') return json(403, { error: 'Admin account cannot be deleted here.' });
    const { error } = await supabase.from('users').delete().eq('id', userId);
    if (error) throw error;
    return json(200, { ok: true });
  } catch (error) {
    return json(error.message === 'Unauthorized' || error.message === 'Session expired' ? 401 : 500, { error: error.message });
  }
};
