(function () {
  if (!window.supabase || !window.APP_CONFIG) {
    throw new Error('Supabase SDK/config haijapakia.');
  }

  const token = sessionStorage.getItem('gsms_access_token');
  const headers = token ? { Authorization: `Bearer ${token}` } : {};
  const client = window.supabase.createClient(window.APP_CONFIG.supabaseUrl, window.APP_CONFIG.supabaseAnonKey, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
    global: { headers }
  });

  window.supabaseClient = client;
  if (token && client.realtime && typeof client.realtime.setAuth === 'function') client.realtime.setAuth(token);

  async function api(path, options = {}) {
    const response = await fetch(path, {
      ...options,
      headers: { 'Content-Type': 'application/json', ...(options.headers || {}) }
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || 'Request failed');
    return body;
  }

  async function loginUser(identifier, password) {
    const result = await api('/api/login', {
      method: 'POST',
      body: JSON.stringify({ identifier, password })
    });
    sessionStorage.setItem('gsms_access_token', result.accessToken);
    sessionStorage.setItem('gsms_user', JSON.stringify(result.user));
    return result.user;
  }

  async function updatePassword(newPassword) {
    const result = await api('/api/change-password', {
      method: 'POST',
      body: JSON.stringify({ newPassword })
    });
    const user = getCurrentUser();
    if (user) {
      user.is_password_changed = true;
      sessionStorage.setItem('gsms_user', JSON.stringify(user));
    }
    return result;
  }

  function getCurrentUser() {
    try { return JSON.parse(sessionStorage.getItem('gsms_user') || 'null'); } catch { return null; }
  }

  async function getVerifiedCurrentUser() {
    const user = getCurrentUser();
    if (!user || !sessionStorage.getItem('gsms_access_token')) return null;
    const { data, error } = await client.from('users').select('id,auth_user_id,full_name,email,reg_no,role,is_password_changed,created_at').eq('auth_user_id', user.auth_user_id).maybeSingle();
    if (error || !data) return null;
    sessionStorage.setItem('gsms_user', JSON.stringify(data));
    return data;
  }

  async function registerUser(userData) {
    return api('/api/create-member', { method: 'POST', body: JSON.stringify(userData) });
  }

  async function getAllMembers() {
    const { data, error } = await client.from('users').select('id,auth_user_id,full_name,email,reg_no,role,is_password_changed,created_at').order('created_at', { ascending: false });
    if (error) throw error;
    return data || [];
  }

  async function deleteUser(userId) {
    return api('/api/delete-member', { method: 'POST', body: JSON.stringify({ userId }) });
  }

  async function checkAdminExists() {
    const { data, error } = await client.from('users').select('id').eq('role', 'admin').limit(1);
    if (error) throw error;
    return Boolean(data && data.length);
  }

  window.loginUser = loginUser;
  window.updatePassword = updatePassword;
  window.getCurrentUser = getCurrentUser;
  window.getVerifiedCurrentUser = getVerifiedCurrentUser;
  window.registerUser = registerUser;
  window.getAllMembers = getAllMembers;
  window.deleteUser = deleteUser;
  window.checkAdminExists = checkAdminExists;
})();
