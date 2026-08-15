// js/db.js
import { SUPABASE_URL, SUPABASE_KEY } from './config.js';

// Initialize Supabase Client
export const supabase = window.supabase.createClient(SUPABASE_URL, SUPABASE_KEY);

// User Queries
export async function checkAdminExists() {
    const { data, error } = await supabase
        .from('users')
        .select('*')
        .eq('role', 'admin');
    if (error) throw error;
    return data.length > 0;
}

export async function registerUser(userData) {
    const { data, error } = await supabase
        .from('users')
        .insert([userData])
        .select();
    if (error) throw error;
    return data[0];
}

export async function loginUser(emailOrReg, password) {
    const { data, error } = await supabase
        .from('users')
        .select('*')
        .or(`email.eq.${emailOrReg},reg_no.eq.${emailOrReg}`)
        .eq('password', password);
        
    if (error) throw error;
    return data[0] || null;
}

export async function updatePassword(userId, newPassword) {
    const { data, error } = await supabase
        .from('users')
        .update({ password: newPassword, is_password_changed: true })
        .eq('id', userId);
    if (error) throw error;
    return true;
}

export async function getAllMembers() {
    const { data, error } = await supabase
        .from('users')
        .select('*')
        .order('created_at', { ascending: false });
    if (error) throw error;
    return data;
}

export async function deleteUser(userId) {
    const { error } = await supabase
        .from('users')
        .delete()
        .eq('id', userId);
    if (error) throw error;
    return true;
}