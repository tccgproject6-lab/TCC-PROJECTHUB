// js/auth.js
import { checkAdminExists, loginUser, updatePassword } from './db.js';

// Check kama session ipo
export function getCurrentUser() {
    const user = localStorage.getItem('gsms_user');
    return user ? JSON.parse(user) : null;
}

// Redirect Guard
export function requireAuth() {
    const user = getCurrentUser();
    if (!user) {
        window.location.href = 'login.html';
        return null;
    }
    return user;
}

export function logout() {
    localStorage.removeItem('gsms_user');
    window.location.href = 'login.html';
}

// Global initialization
document.addEventListener('DOMContentLoaded', async () => {
    // Handling login logic kama kipo kwenye login.html
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const identifier = document.getElementById('identifier').value;
            const password = document.getElementById('password').value;

            try {
                const user = await loginUser(identifier, password);
                if (!user) {
                    alert('Taarifa ulizoingiza si sahihi!');
                    return;
                }

                // Hifadhi session
                localStorage.setItem('gsms_user', JSON.stringify(user));

                // Angalia kama anatakiwa kubadilisha password ya default (123456)
                if (!user.is_password_changed) {
                    document.getElementById('loginSection').style.display = 'none';
                    document.getElementById('resetPasswordSection').style.display = 'block';
                } else {
                    redirectBasedOnRole(user);
                }
            } catch (err) {
                alert('Imefeli kuingia: ' + err.message);
            }
        });
    }

    // Password reset form logic
    const resetForm = document.getElementById('resetPasswordForm');
    if (resetForm) {
        resetForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const newPassword = document.getElementById('newPassword').value;
            const confirmPassword = document.getElementById('confirmPassword').value;

            if (newPassword !== confirmPassword) {
                alert('Password hazifanani!');
                return;
            }

            const currentUser = getCurrentUser();
            try {
                await updatePassword(currentUser.id, newPassword);
                currentUser.is_password_changed = true;
                localStorage.setItem('gsms_user', JSON.stringify(currentUser));
                alert('Password imebadilishwa kikamilifu!');
                redirectBasedOnRole(currentUser);
            } catch (err) {
                alert('Imefeli kureset password: ' + err.message);
            }
        });
    }
});

function redirectBasedOnRole(user) {
    if (user.role === 'admin') {
        window.location.href = 'admin.html';
    } else {
        window.location.href = 'index.html';
    }
}