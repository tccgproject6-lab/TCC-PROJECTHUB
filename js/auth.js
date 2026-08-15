// js/auth.js

// 1. Check kama session ipo
function getCurrentUser() {
    const user = localStorage.getItem('currentUser');
    return user ? JSON.parse(user) : null;
}

// 2. Redirect Guard
function requireAuth() {
    const user = getCurrentUser();
    if (!user) {
        window.location.href = 'login.html';
        return null;
    }
    return user;
}

// 3. Logout Function
function logout() {
    localStorage.removeItem('currentUser');
    window.location.href = 'login.html';
}

// 4. Redirect kulingana na Role
function redirectBasedOnRole(user) {
    if (user.role === 'admin') {
        window.location.href = 'admin.html';
    } else {
        window.location.href = 'index.html';
    }
}

// 5. Domestic Event Listeners
document.addEventListener('DOMContentLoaded', async () => {
    
    // Check ikiwa tayari amelogin akiwa kwenye login.html
    const path = window.location.pathname;
    const currentUser = getCurrentUser();
    
    if (path.endsWith('login.html') && currentUser) {
        redirectBasedOnRole(currentUser);
        return;
    }

    // Login Form Handling
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const identifier = document.getElementById('identifier').value.trim();
            const password = document.getElementById('password').value.trim();

            try {
                let user = null;

                // Tumia loginUser() iliyotengenezwa kwenye db.js
                if (typeof window.loginUser === 'function') {
                    user = await window.loginUser(identifier, password);
                } else if (window.supabaseClient && typeof window.supabaseClient.from === 'function') {
                    // Fallback kwa supabaseClient badala ya supabase
                    const { data, error } = await window.supabaseClient
                        .from('users')
                        .select('*')
                        .or(`reg_no.eq.${identifier},email.eq.${identifier}`)
                        .eq('password', password);

                    if (error) throw error;
                    user = (data && data.length > 0) ? data[0] : null;
                } else {
                    throw new Error("Database integration connection failed!");
                }

                if (!user) {
                    alert('Taarifa ulizoingiza (Reg No/Email au Password) si sahihi!');
                    return;
                }

                // Hifadhi session
                localStorage.setItem('currentUser', JSON.stringify(user));

                // Angalia kama anapaswa kubadilisha password ya default
                if (!user.is_password_changed) {
                    const loginSec = document.getElementById('loginSection');
                    const resetSec = document.getElementById('resetPasswordSection');
                    
                    if (loginSec && resetSec) {
                        loginSec.style.display = 'none';
                        resetSec.style.display = 'block';
                    } else {
                        redirectBasedOnRole(user);
                    }
                } else {
                    redirectBasedOnRole(user);
                }
            } catch (err) {
                alert('Imefeli kuingia: ' + err.message);
            }
        });
    }

    // Password Reset Form
    const resetForm = document.getElementById('resetPasswordForm');
    if (resetForm) {
        resetForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const newPassword = document.getElementById('newPassword').value.trim();
            const confirmPassword = document.getElementById('confirmPassword').value.trim();

            if (newPassword.length < 6) {
                alert('Password lazima iwe na angalau herufi au tarakimu 6!');
                return;
            }

            if (newPassword !== confirmPassword) {
                alert('Password mpya na ya kuthibitisha hazifanani!');
                return;
            }

            const activeUser = getCurrentUser();
            if (!activeUser) {
                alert('Session imeisha, tafadhali ingia tena.');
                window.location.href = 'login.html';
                return;
            }

            try {
                if (typeof window.updatePassword === 'function') {
                    await window.updatePassword(activeUser.id, newPassword);
                } else if (window.supabaseClient) {
                    const { error } = await window.supabaseClient
                        .from('users')
                        .update({ password: newPassword, is_password_changed: true })
                        .eq('id', activeUser.id);

                    if (error) throw error;
                }

                activeUser.is_password_changed = true;
                activeUser.password = newPassword;
                localStorage.setItem('currentUser', JSON.stringify(activeUser));

                alert('Password imebadilishwa kikamilifu!');
                redirectBasedOnRole(activeUser);
            } catch (err) {
                alert('Imefeli kureset password: ' + err.message);
            }
        });
    }
});

// Global Exports
window.getCurrentUser = getCurrentUser;
window.requireAuth = requireAuth;
window.logout = logout;
window.redirectBasedOnRole = redirectBasedOnRole;
