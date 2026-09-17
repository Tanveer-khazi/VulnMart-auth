const API = {
  token() {
    return localStorage.getItem('vm_token');
  },
  setToken(token) {
    if (token) localStorage.setItem('vm_token', token);
  },
  clearToken() {
    localStorage.removeItem('vm_token');
  },
  async request(path, options = {}) {
    const headers = Object.assign({ 'Content-Type': 'application/json' }, options.headers || {});
    const token = API.token();
    if (token) headers.Authorization = `Bearer ${token}`;

    const res = await fetch(path, {
      credentials: 'include',
      ...options,
      headers,
    });

    let body = null;
    try { body = await res.json(); } catch (e) { /* no body */ }

    if (!res.ok) {
      const error = new Error((body && body.error) || `Request failed (${res.status})`);
      error.status = res.status;
      error.body = body;
      throw error;
    }
    return body;
  },
};

function showMessage(el, text, kind) {
  el.textContent = text;
  el.className = `msg ${kind || ''}`;
}

function renderHeaderNav() {
  const nav = document.getElementById('site-nav');
  if (!nav) return;
  const loggedIn = !!API.token();
  nav.innerHTML = loggedIn
    ? '<a href="/profile.html">Profile</a><a href="/admin.html">Admin</a><a href="/oauth-demo.html">OAuth demo</a><a href="#" id="logout-link">Logout</a>'
    : '<a href="/login.html">Login</a><a href="/register.html">Register</a>';

  const logoutLink = document.getElementById('logout-link');
  if (logoutLink) {
    logoutLink.addEventListener('click', async (e) => {
      e.preventDefault();
      await API.request('/api/auth/logout', { method: 'POST' }).catch(() => {});
      API.clearToken();
      window.location.href = '/login.html';
    });
  }
}

document.addEventListener('DOMContentLoaded', renderHeaderNav);
