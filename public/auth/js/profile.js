(async () => {
  const token = getToken();
  if (!token) return window.location.href = '/login';
  const res = await fetch(`${API_BASE}/profile`, {headers:{Authorization:`Bearer ${token}`}});
  const data = await res.json();
  if (!res.ok) { clearToken(); return window.location.href = '/login'; }
  document.getElementById('email').textContent = `Email: ${data.user.email}`;
})();
document.getElementById('logout')?.addEventListener('click', () => { clearToken(); window.location.href='/login'; });
