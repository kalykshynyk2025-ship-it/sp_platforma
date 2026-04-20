document.getElementById('register-form')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = document.getElementById('email').value;
  const password = document.getElementById('password').value;
  const res = await fetch(`${API_BASE}/register`, {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email,password})});
  const data = await res.json();
  document.getElementById('msg').textContent = res.ok ? 'Успешно! Теперь войдите.' : (data.error || 'Ошибка');
});
