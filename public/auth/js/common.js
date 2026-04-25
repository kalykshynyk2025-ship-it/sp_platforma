const API_BASE = '/api';
const setToken = (token) => localStorage.setItem('token', token);
const getToken = () => localStorage.getItem('token');
const clearToken = () => localStorage.removeItem('token');
