document.getElementById('login-form')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = document.getElementById('email').value;
  const password = document.getElementById('password').value;
  const res = await fetch(`${API_BASE}/login`, {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email,password})});
  const data = await res.json();
  if (!res.ok) return document.getElementById('msg').textContent = data.error || 'Ошибка';
  setToken(data.token); window.location.href = '/profile';
});
