(function () {
  const API = window.APP_CONFIG?.apiBase || '';

  async function api(path, options = {}) {
    const token = sessionStorage.getItem('tcc_access_token');
    const headers = {
      'Content-Type': 'application/json',
      ...(options.headers || {})
    };
    if (token) headers.Authorization = `Bearer ${token}`;

    const response = await fetch(`${API}${path}`, {
      ...options,
      headers,
      cache: 'no-store'
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      if (response.status === 401) {
        sessionStorage.removeItem('tcc_access_token');
        sessionStorage.removeItem('tcc_user');
      }
      throw new Error(body.error || 'Request failed');
    }
    return body;
  }

  async function loginUser(identifier, password) {
    const result = await api('/api/login', {
      method: 'POST',
      body: JSON.stringify({ identifier, password })
    });
    sessionStorage.setItem('tcc_access_token', result.accessToken);
    sessionStorage.setItem('tcc_user', JSON.stringify(result.user));
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
      sessionStorage.setItem('tcc_user', JSON.stringify(user));
    }
    return result;
  }

  function getCurrentUser() {
    try { return JSON.parse(sessionStorage.getItem('tcc_user') || 'null'); }
    catch { return null; }
  }

  async function getVerifiedCurrentUser() {
    if (!sessionStorage.getItem('tcc_access_token')) return null;
    try {
      const result = await api('/api/me');
      sessionStorage.setItem('tcc_user', JSON.stringify(result.user));
      return result.user;
    } catch {
      return null;
    }
  }

  async function registerUser(userData) {
    return api('/api/members', {
      method: 'POST',
      body: JSON.stringify(userData)
    });
  }

  async function getAllMembers() {
    const result = await api('/api/members');
    return result.members || [];
  }

  async function deleteUser(userId) {
    return api('/api/members/delete', {
      method: 'POST',
      body: JSON.stringify({ userId })
    });
  }

  async function saveCode(code) {
    return api('/api/saved-code', {
      method: 'POST',
      body: JSON.stringify({ code })
    });
  }

  async function loadLatestCode() {
    return api('/api/saved-code/latest');
  }

  async function getMessages() {
    const result = await api('/api/messages');
    return result.messages || [];
  }

  async function sendMessage(message) {
    return api('/api/messages', {
      method: 'POST',
      body: JSON.stringify({ message })
    });
  }

  async function clearMessages() {
    return api('/api/messages/clear', { method: 'POST' });
  }
  async function updateUser(userData) {
    return api('/api/members/update', {
        method: 'POST',
        body: JSON.stringify(userData)
    });
}

window.loginUser = loginUser;
window.updatePassword = updatePassword;
window.getCurrentUser = getCurrentUser;
window.getVerifiedCurrentUser = getVerifiedCurrentUser;
window.registerUser = registerUser;
window.getAllMembers = getAllMembers;
window.deleteUser = deleteUser;
window.updateUser = updateUser;
window.saveCode = saveCode;
window.loadLatestCode = loadLatestCode;
window.getMessages = getMessages;
window.sendMessage = sendMessage;
window.clearMessages = clearMessages;
})();
