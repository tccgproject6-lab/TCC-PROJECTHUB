// js/db.js

// 1. Kuhakikisha Supabase Client imeundwa na ipo tayari
let supabase = null;

if (typeof window.supabaseClient !== 'undefined') {
    supabase = window.supabaseClient;
} else if (typeof window.supabase !== 'undefined' && typeof window.supabase.createClient === 'function') {
    const url = window.SUPABASE_URL || 'YOUR_SUPABASE_URL';
    const key = window.SUPABASE_KEY || 'YOUR_SUPABASE_KEY';
    supabase = window.supabase.createClient(url, key);
    window.supabase = supabase; // Hifadhi global instance
}

// 2. Angalia kama Admin yupo
async function checkAdminExists() {
    const { data, error } = await supabase
        .from('users')
        .select('*')
        .eq('role', 'admin');
    if (error) throw error;
    return data && data.length > 0;
}

// 3. Sajili User Mpya
async function registerUser(userData) {
    const { data, error } = await supabase
        .from('users')
        .insert([userData])
        .select();
    if (error) throw error;
    return data[0];
}

// 4. Ingingia Mfumo (Login)
async function loginUser(emailOrReg, password) {
    const { data, error } = await supabase
        .from('users')
        .select('*')
        .or(`email.eq.${emailOrReg},reg_no.eq.${emailOrReg}`)
        .eq('password', password);
        
    if (error) throw error;
    return (data && data.length > 0) ? data[0] : null;
}

// 5. Badilisha Password
async function updatePassword(userId, newPassword) {
    const { error } = await supabase
        .from('users')
        .update({ password: newPassword, is_password_changed: true })
        .eq('id', userId);
    if (error) throw error;
    return true;
}

// 6. Leta Wanachama Wote
async function getAllMembers() {
    const { data, error } = await supabase
        .from('users')
        .select('*')
        .order('created_at', { ascending: false });
    if (error) throw error;
    return data || [];
}

// 7. Futa User
async function deleteUser(userId) {
    const { error } = await supabase
        .from('users')
        .delete()
        .eq('id', userId);
    if (error) throw error;
    return true;
}

// Attach kila function kwenye Window Object kwa ajili ya Global Access
window.supabase = supabase;
window.checkAdminExists = checkAdminExists;
window.registerUser = registerUser;
window.loginUser = loginUser;
window.updatePassword = updatePassword;
window.getAllMembers = getAllMembers;
window.deleteUser = deleteUser;
