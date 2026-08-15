function clearSession() {
  sessionStorage.removeItem('tcc_access_token');
  sessionStorage.removeItem('tcc_user');
}

function getCurrentUser() {
  try { return JSON.parse(sessionStorage.getItem('tcc_user') || 'null'); } catch { return null; }
}

function logout() {
  clearSession();
  window.location.replace('login.html');
}

function redirectBasedOnRole(user) {
  window.location.replace(user && user.role === 'admin' ? 'admin.html' : 'index.html');
}

async function requireAuth(requiredRole) {
  const user = await window.getVerifiedCurrentUser();
  if (!user) {
    clearSession();
    window.location.replace('login.html');
    return null;
  }
  if (requiredRole && user.role !== requiredRole) {
    window.location.replace('index.html');
    return null;
  }
  return user;
}

window.clearSession = clearSession;
window.getCurrentUser = getCurrentUser;
window.logout = logout;
window.redirectBasedOnRole = redirectBasedOnRole;
window.requireAuth = requireAuth;
