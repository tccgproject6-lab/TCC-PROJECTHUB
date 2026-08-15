// js/db.js

// 1. Kutengeneza Supabase Client na kuzuia Overwriting
const url = window.SUPABASE_URL || 'https://exejmvckurtbdtcpjvxn.supabase.co';
const key = window.SUPABASE_KEY || 'EyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImV4ZWptdmNrdXJ0YmR0Y3BqdnhuIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODY3MjY0ODksImV4cCI6MjEwMjMwMjQ4OX0.nY1Xmb6gTi_MkVU8MSEd-tiz_hzuO8gPeOyapXGhsD8';

// Tumia createClient kikamilifu
const client = window.supabase.createClient(url, key);

// Hifadhi kwenye window kama dbClient au supabaseClient
window.supabaseClient = client;

// 2. Query Functions
async function checkAdminExists() {
    const { data, error } = await client
        .from('users')
        .select('*')
        .eq('role', 'admin');
    if (error) throw error;
    return data && data.length > 0;
}

async function registerUser(userData) {
    const { data, error } = await client
        .from('users')
        .insert([userData])
        .select();
    if (error) throw error;
    return data[0];
}

async function loginUser(emailOrReg, password) {
    const { data, error } = await client
        .from('users')
        .select('*')
        .or(`email.eq.${emailOrReg},reg_no.eq.${emailOrReg}`)
        .eq('password', password);
        
    if (error) throw error;
    return (data && data.length > 0) ? data[0] : null;
}

async function updatePassword(userId, newPassword) {
    const { error } = await client
        .from('users')
        .update({ password: newPassword, is_password_changed: true })
        .eq('id', userId);
    if (error) throw error;
    return true;
}

async function getAllMembers() {
    const { data, error } = await client
        .from('users')
        .select('*')
        .order('created_at', { ascending: false });
    if (error) throw error;
    return data || [];
}

async function deleteUser(userId) {
    const { error } = await client
        .from('users')
        .delete()
        .eq('id', userId);
    if (error) throw error;
    return true;
}

// Global Exports
window.checkAdminExists = checkAdminExists;
window.registerUser = registerUser;
window.loginUser = loginUser;
window.updatePassword = updatePassword;
window.getAllMembers = getAllMembers;
window.deleteUser = deleteUser;
