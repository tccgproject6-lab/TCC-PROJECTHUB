// js/auth.js

// 1. Check kama session ipo
function getCurrentUser() {
    const user = localStorage.getItem('currentUser');
    return user ? JSON.parse(user) : null;
}

// 2. Redirect Guard kwa ajili ya kurasa zote
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

// 4. Function ya ku-redirect kulingana na Role ya mtumiaji
function redirectBasedOnRole(user) {
    if (user.role === 'admin') {
        window.location.href = 'admin.html';
    } else {
        window.location.href = 'index.html';
    }
}

// 5. Domestic event listeners za Login & Password Reset
document.addEventListener('DOMContentLoaded', async () => {
    
    // Check ikiwa tayari amelogin tuko kwenye login.html
    const path = window.location.pathname;
    const currentUser = getCurrentUser();
    
    if (path.includes('login.html') && currentUser) {
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

                // Tumia loginUser kutoka db.js ikipatikana
                if (typeof loginUser === 'function') {
                    user = await loginUser(identifier, password);
                } else if (typeof supabase !== 'undefined') {
                    // Fallback Direct Supabase Query kama db.js haina loginUser
                    const { data, error } = await supabase
                        .from('users')
                        .select('*')
                        .or(`reg_no.eq.${identifier},email.eq.${identifier}`)
                        .eq('password', password)
                        .single();

                    if (error || !data) {
                        alert('Taarifa ulizoingiza (Reg No/Email au Password) si sahihi!');
                        return;
                    }
                    user = data;
                } else {
                    throw new Error("Supabase Client haijapatikana!");
                }

                if (!user) {
                    alert('Taarifa ulizoingiza si sahihi!');
                    return;
                }

                // Hifadhi session kwa kutumia key iliyo-align na index/admin ('currentUser')
                localStorage.setItem('currentUser', JSON.stringify(user));

                // Angalia kama anatakiwa kubadilisha password ya default (123456)
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

    // Password Reset Form Logic
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
                if (typeof updatePassword === 'function') {
                    await updatePassword(activeUser.id, newPassword);
                } else if (typeof supabase !== 'undefined') {
                    const { error } = await supabase
                        .from('users')
                        .update({ password: newPassword, is_password_changed: true })
                        .eq('id', activeUser.id);

                    if (error) throw error;
                }

                // Update session ya sasa
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

// Zifanye zitambulike Global Scope kwenye HTML zote
window.getCurrentUser = getCurrentUser;
window.requireAuth = requireAuth;
window.logout = logout;
window.redirectBasedOnRole = redirectBasedOnRole;
