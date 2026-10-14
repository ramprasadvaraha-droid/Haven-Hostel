(() => {
  const $ = (selector, root = document) => root.querySelector(selector);
  const loginScreen = $('#login-screen');
  const hostelApp = $('#hostel-app');
  const loginForm = $('#login-form');
  const signupForm = $('#signup-form');
  const joinForm = $('#join-form');
  const joinModal = $('#join-modal');
  const roomSelect = $('#room-select');
  const bedSelect = $('#bed-select');
  const joiningDate = $('#checkin-input');
  const paymentDate = $('#payment-date');
  const state = { user: null, summary: null, rooms: [], residents: [], activity: [] };
  let csrfToken = '';
  let toastTimer;

  const bedIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M3 18v-8M3 15h18v5M7 15v-5a3 3 0 0 1 3-3h7a4 4 0 0 1 4 4v4M3 20v-2m18 2v-2" stroke-linecap="round" stroke-linejoin="round"/></svg>';

  function escapeHTML(value) {
    return String(value ?? '').replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
  }

  async function apiRequest(path, options = {}) {
    const method = (options.method || 'GET').toUpperCase();
    const headers = new Headers(options.headers || {});
    if (!['GET', 'HEAD', 'OPTIONS'].includes(method) && csrfToken) headers.set('X-CSRF-Token', csrfToken);
    if (options.body && !(options.body instanceof FormData) && !headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json');
    }
    const response = await fetch(path, { ...options, method, headers, credentials: 'same-origin' });
    const payload = response.status === 204 ? null : await response.json().catch(() => null);
    if (!response.ok) throw new Error(payload?.detail || 'The request could not be completed.');
    return payload;
  }

  function showToast(message) {
    const toast = $('#toast');
    toast.textContent = message;
    toast.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { toast.hidden = true; }, 3500);
  }

  function showLogin(message = '', setupRequired = false) {
    csrfToken = '';
    hostelApp.hidden = true;
    loginScreen.hidden = false;
    loginForm.hidden = setupRequired;
    signupForm.hidden = !setupRequired;
    $('#credentials-note').hidden = setupRequired;
    $('.login-kicker').textContent = setupRequired ? 'First-time setup' : 'Staff access';
    $('#login-title').textContent = setupRequired ? 'Create your admin account.' : 'Welcome back.';
    $('.login-copy').textContent = setupRequired
      ? 'Set up the administrator account to secure this hostel workspace.'
      : 'Sign in to manage residents, rooms, and payments.';
    $('#login-error').textContent = message;
    $('#login-error').hidden = !message;
    $('#signup-error').hidden = true;
    if (setupRequired) $('#signup-username').focus(); else $('#login-username').focus();
  }

  function showDashboard(user) {
    state.user = user;
    $('#staff-identity').textContent = `${user.username} · ${user.role}`;
    hostelApp.hidden = false;
    loginScreen.hidden = true;
  }

  function formatDate(value) {
    if (!value) return '—';
    return new Intl.DateTimeFormat('en-IN', { day: 'numeric', month: 'short', year: 'numeric' })
      .format(new Date(`${value}T00:00:00`));
  }

  function formatCurrency(paise) {
    return new Intl.NumberFormat('en-IN', { style: 'currency', currency: 'INR' }).format((paise || 0) / 100);
  }

  function availableBeds(room) {
    return room.beds.filter(bed => !bed.occupied).map(bed => bed.number);
  }

  function floorLabel(number) {
    const suffix = number % 100 >= 11 && number % 100 <= 13
      ? 'th'
      : ({ 1: 'st', 2: 'nd', 3: 'rd' }[number % 10] || 'th');
    return `${number}${suffix} Floor`;
  }

  function renderBeds(room) {
    return room.beds.map(bed => `<span class="bed ${bed.occupied ? 'filled' : ''}" title="Bed ${bed.number} ${bed.occupied ? 'occupied' : 'available'}" aria-label="Bed ${bed.number} ${bed.occupied ? 'occupied' : 'available'}">${bedIcon}<span class="bed-number">${bed.number}</span></span>`).join('');
  }

  function renderBedOptions() {
    const room = state.rooms.find(item => item.id === roomSelect.value);
    const bedNumbers = room ? availableBeds(room) : [];
    bedSelect.innerHTML = bedNumbers.length
      ? bedNumbers.map(number => `<option value="${number}">Bed ${number}</option>`).join('')
      : '<option value="" disabled selected>No beds available</option>';
    bedSelect.disabled = !bedNumbers.length;
  }

  function renderRooms() {
    const availableRooms = state.rooms.filter(room => room.occupied < room.share_count);
    $('#room-list').innerHTML = availableRooms.length
      ? availableRooms.map(room => {
        const openBeds = room.share_count - room.occupied;
        return `<div class="room-row"><div><div class="room-id">${escapeHTML(room.hostel_name)} · ${floorLabel(room.floor_number)}</div><div class="room-type">Room ${escapeHTML(room.room_number)} · ${room.share_count}-share</div></div><div class="beds" aria-label="${room.occupied} occupied, ${openBeds} available">${renderBeds(room)}</div><div class="room-capacity">${openBeds} <span>open</span></div></div>`;
      }).join('')
      : '<div class="table-empty">No beds are configured yet, or all beds are occupied.</div>';

    const previousRoom = roomSelect.value;
    roomSelect.innerHTML = availableRooms.length
      ? availableRooms.map(room => `<option value="${escapeHTML(room.id)}">${escapeHTML(room.hostel_name)} · ${floorLabel(room.floor_number)} · Room ${escapeHTML(room.room_number)} · ${room.share_count - room.occupied} open</option>`).join('')
      : '<option value="" disabled selected>No beds available</option>';
    if (availableRooms.some(room => room.id === previousRoom)) roomSelect.value = previousRoom;
    roomSelect.disabled = availableRooms.length === 0;
    renderBedOptions();
    renderHostelStructure();

    $('#stat-capacity').textContent = String(state.summary.capacity);
    $('#stat-occupied').textContent = String(state.summary.occupied);
    $('#stat-available').textContent = String(state.summary.available);
    $('#stat-rooms-open').textContent = String(state.summary.rooms_open);
    $('#stat-outstanding').textContent = formatCurrency(state.summary.outstanding_paise);
    $('#stat-unpaid-count').textContent = state.summary.unpaid_count
      ? `${state.summary.unpaid_count} unpaid resident${state.summary.unpaid_count === 1 ? '' : 's'}`
      : 'No unpaid balances';
  }

  function renderRoomTile(room, canManage) {
    const deleteButton = canManage
      ? `<div class="room-structure-actions"><button class="delete-room-button" type="button" data-delete-room="${escapeHTML(room.id)}" ${room.occupied ? 'disabled title="Check residents out before deleting this room."' : ''}>Delete room</button></div>`
      : '';
    return `<article class="room-structure-tile"><div class="room-tile-top"><div><div class="room-id">Room ${escapeHTML(room.room_number)}</div><div class="room-type">${room.share_count}-share · ${room.occupied}/${room.share_count} occupied</div></div><span class="room-pill">${room.share_count - room.occupied} open</span></div><div class="beds" aria-label="${room.occupied} occupied, ${room.share_count - room.occupied} available">${renderBeds(room)}</div>${deleteButton}</article>`;
  }

  function renderHostelStructure() {
    const canManage = state.user?.role === 'admin';
    $('#hostel-create-wrap').hidden = !canManage;
    $('#hostel-structure').innerHTML = state.hostels.length
      ? state.hostels.map(hostel => {
        const hostelRooms = hostel.floors.reduce((total, floor) => total + floor.rooms.length, 0);
        const floorMarkup = hostel.floors.length
          ? hostel.floors.map(floor => {
            const roomsMarkup = floor.rooms.length
              ? `<div class="room-structure-grid">${floor.rooms.map(room => renderRoomTile(room, canManage)).join('')}</div>`
              : '<div class="floor-empty">No rooms on this floor yet.</div>';
            const addRoomForm = canManage
              ? `<form class="structure-form" data-room-form data-floor-id="${escapeHTML(floor.id)}"><div class="field room-number-field"><label>Room number</label><input name="room_number" required maxlength="20" placeholder="e.g. 105"></div><div class="field share-field"><label>Sharing capacity</label><input name="share_count" type="number" min="1" max="20" value="4" required></div><button class="primary-button" type="submit">Add room</button></form>`
              : '';
            return `<section class="floor-group"><div class="floor-head"><div><h3 class="floor-title">${floorLabel(floor.floor_number)}</h3><div class="section-subtitle">${floor.rooms.length} room${floor.rooms.length === 1 ? '' : 's'}</div></div></div>${roomsMarkup}${addRoomForm}</section>`;
          }).join('')
          : '<div class="floor-group floor-empty">No floors yet. Add the first floor to start configuring rooms.</div>';
        const addFloorForm = canManage && hostel.floors.length < 99
          ? `<form class="structure-form" data-floor-form data-hostel-id="${escapeHTML(hostel.id)}"><div class="field"><label>Add floor number</label><input name="floor_number" type="number" min="1" max="99" required placeholder="e.g. 1"></div><button class="primary-button" type="submit">Add floor</button></form>`
          : '';
        const deleteHostelButton = canManage
          ? `<button class="delete-room-button" type="button" data-delete-hostel="${escapeHTML(hostel.id)}" ${hostel.occupied ? 'disabled title="Check out or move current residents before deleting this hostel."' : ''}>Delete hostel</button>`
          : '';
        return `<article class="hostel-card"><header class="hostel-card-head"><div><h2 class="hostel-card-title">${escapeHTML(hostel.name)}</h2><div class="hostel-card-meta">${hostel.floors.length} floor${hostel.floors.length === 1 ? '' : 's'} · ${hostelRooms} room${hostelRooms === 1 ? '' : 's'}</div></div><div class="hostel-head-actions">${deleteHostelButton}${addFloorForm}</div></header>${floorMarkup}</article>`;
      }).join('')
      : '<div class="table-empty">No hostels configured yet. Add your first hostel to set up floors and rooms.</div>';
  }

  function residentDocuments(resident) {
    if (!resident.documents.length) return 'No photos';
    return resident.documents.map(document => {
      const label = document.kind === 'person_photo' ? 'Person photo' : 'Aadhaar photo';
      return `<a class="document-link" href="${escapeHTML(document.url)}" target="_blank" rel="noopener">${label}</a>`;
    }).join(' · ');
  }

  function residentRows(searchValue = '') {
    const query = searchValue.trim().toLowerCase();
    const filtered = state.residents.filter(resident =>
      resident.name.toLowerCase().includes(query) || resident.mobile.includes(query) || resident.room.includes(query)
    );
    if (!filtered.length) {
      return `<div class="table-empty">${state.residents.length ? 'No residents match your search.' : 'No active residents yet. Register a joiner to get started.'}</div>`;
    }
    return `<div class="table-scroll"><table><thead><tr><th>Resident</th><th>Hostel / Floor / Room</th><th>Joining date</th><th>Next payment date</th><th>Payment</th><th>Documents</th><th>Actions</th></tr></thead><tbody>${filtered.map(resident => `<tr><td><div class="resident-name">${escapeHTML(resident.name)}</div><div class="resident-contact">${escapeHTML(resident.mobile)}${resident.aadhaar_last4 ? ` · Aadhaar ending ${escapeHTML(resident.aadhaar_last4)}` : ''}</div></td><td><span class="room-pill">${escapeHTML(resident.room)} · Bed ${resident.bed_number}</span><div class="resident-contact">${escapeHTML(resident.hostel_name)} · ${floorLabel(resident.floor_number)}</div></td><td>${escapeHTML(formatDate(resident.joining_date))}</td><td>${escapeHTML(formatDate(resident.payment_due_date))}</td><td>${resident.payment_status === 'unpaid' ? `<span class="payment-unpaid">${escapeHTML(formatCurrency(resident.amount_due_paise))} due</span>` : '<span class="payment-paid">Paid</span>'}</td><td>${residentDocuments(resident)}</td><td><div class="payment-actions">${resident.payment_status === 'unpaid' ? `<button class="whatsapp-button" type="button" data-whatsapp="${escapeHTML(resident.id)}">Send reminder</button><button class="mark-paid-button" type="button" data-mark-paid="${escapeHTML(resident.id)}">Mark paid</button>` : ''}<button class="exit-button" type="button" data-checkout="${escapeHTML(resident.id)}">Check out</button></div></td></tr>`).join('')}</tbody></table></div>`;
  }

  function renderResidents() {
    const countText = `${state.residents.length} active resident${state.residents.length === 1 ? '' : 's'}`;
    $('#resident-count').textContent = state.residents.length ? countText : 'No active residents';
    $('#resident-count-all').textContent = state.residents.length ? countText : 'No active residents';
    $('#resident-table').innerHTML = residentRows($('#resident-search').value);
    $('#resident-table-all').innerHTML = residentRows($('#resident-search-all').value);
  }

  function renderActivity() {
    const icon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 5v14M5 12h14" stroke-linecap="round"/></svg>';
    $('#activity-list').innerHTML = state.activity.length
      ? state.activity.map(item => `<div class="activity"><div class="activity-icon ${item.type === 'exit' ? 'exit' : ''}">${item.type === 'exit' ? icon.replace('M12 5v14M5 12h14', 'M5 12h14') : icon}</div><div><div class="activity-text"><strong>${escapeHTML(item.name)}</strong> ${item.type === 'exit' ? 'checked out of' : 'checked in to'} <strong>${escapeHTML(item.hostel_name ? `${item.hostel_name} · ${floorLabel(item.floor_number)} · ` : '')}Room ${escapeHTML(item.room)}${item.bed_number ? ` · Bed ${item.bed_number}` : ''}</strong></div><div class="activity-time">${escapeHTML(new Intl.DateTimeFormat('en-IN', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(item.time)))}</div></div></div>`).join('')
      : '<div class="empty-activity">Check-ins and check-outs will appear here.</div>';
  }

  async function refreshDashboard() {
    const dashboard = await apiRequest('/api/dashboard');
    state.summary = dashboard.summary;
    state.hostels = dashboard.hostels;
    state.rooms = dashboard.rooms;
    state.residents = dashboard.residents;
    state.activity = dashboard.activity;
    showDashboard(dashboard.user);
    renderRooms();
    renderResidents();
    renderActivity();
  }

  function updatePaymentDate() {
    if (!joiningDate.value) {
      paymentDate.value = '';
      return;
    }
    const [year, month, day] = joiningDate.value.split('-').map(Number);
    const nextMonth = month % 12;
    const nextYear = year + (month === 12 ? 1 : 0);
    const lastDay = new Date(nextYear, nextMonth + 1, 0).getDate();
    paymentDate.value = `${nextYear}-${String(nextMonth + 1).padStart(2, '0')}-${String(Math.min(day, lastDay)).padStart(2, '0')}`;
  }

  function openJoinModal() {
    if (!state.rooms.some(room => room.occupied < room.share_count)) {
      showToast(state.rooms.length ? 'All beds are occupied. Check out a resident to free a bed.' : 'Add a hostel, floor, and room before registering a joiner.');
      return;
    }
    $('#form-error').hidden = true;
    const now = new Date();
    joiningDate.value = new Date(now.getTime() - now.getTimezoneOffset() * 60000).toISOString().slice(0, 10);
    updatePaymentDate();
    joinModal.hidden = false;
    $('#resident-name-input').focus();
  }

  function closeJoinModal() {
    joinModal.hidden = true;
    joinForm.reset();
    $('#amount-due-field').hidden = true;
    $('#amount-due').required = false;
  }

  function openWhatsAppReminder(resident) {
    const digits = resident.mobile.replace(/\D/g, '');
    const phone = digits.length === 10 ? `91${digits}` : digits.startsWith('0') ? `91${digits.slice(1)}` : digits;
    const amount = formatCurrency(resident.amount_due_paise);
    const dueDate = formatDate(resident.payment_due_date);
    const message = `Hello ${resident.name}, our records show an outstanding hostel payment of ${amount}, due on ${dueDate}. Please complete payment at your earliest convenience. If you have already paid, please disregard this reminder. Thank you, Haven Hostel.`;
    window.open(`https://wa.me/${phone}?text=${encodeURIComponent(message)}`, '_blank', 'noopener,noreferrer');
  }

  loginForm.addEventListener('submit', async event => {
    event.preventDefault();
    const submit = loginForm.querySelector('button[type="submit"]');
    submit.disabled = true;
    $('#login-error').hidden = true;
    try {
      const payload = await apiRequest('/api/session', {
        method: 'POST',
        body: JSON.stringify({ username: $('#login-username').value.trim(), password: $('#login-password').value }),
      });
      csrfToken = payload.csrf_token;
      loginForm.reset();
      await refreshDashboard();
    } catch (error) {
      $('#login-error').textContent = error.message;
      $('#login-error').hidden = false;
    } finally {
      submit.disabled = false;
    }
  });

  signupForm.addEventListener('submit', async event => {
    event.preventDefault();
    const submit = signupForm.querySelector('button[type="submit"]');
    const password = $('#signup-password').value;
    const confirmPassword = $('#signup-confirm-password').value;
    $('#signup-error').hidden = true;
    if (password !== confirmPassword) {
      $('#signup-error').textContent = 'The passwords do not match.';
      $('#signup-error').hidden = false;
      return;
    }
    submit.disabled = true;
    try {
      const payload = await apiRequest('/api/setup-admin', {
        method: 'POST',
        body: JSON.stringify({ username: $('#signup-username').value.trim(), password }),
      });
      csrfToken = payload.csrf_token;
      signupForm.reset();
      await refreshDashboard();
      showToast('Administrator account created. Sign-up is now closed.');
    } catch (error) {
      $('#signup-error').textContent = error.message;
      $('#signup-error').hidden = false;
    } finally {
      submit.disabled = false;
    }
  });

  joinForm.addEventListener('submit', async event => {
    event.preventDefault();
    const submit = joinForm.querySelector('button[type="submit"]');
    submit.disabled = true;
    $('#form-error').hidden = true;
    const payload = new FormData(joinForm);
    payload.delete('payment_due_date');
    try {
      await apiRequest('/api/residents', { method: 'POST', body: payload });
      closeJoinModal();
      await refreshDashboard();
      showToast('Resident checked in and bed assigned.');
    } catch (error) {
      $('#form-error').textContent = error.message;
      $('#form-error').hidden = false;
    } finally {
      submit.disabled = false;
    }
  });

  document.addEventListener('submit', async event => {
    const form = event.target;
    if (form.id === 'hostel-form') {
      event.preventDefault();
      const submit = form.querySelector('button[type="submit"]');
      submit.disabled = true;
      try {
        const payload = new FormData(form);
        await apiRequest('/api/hostels', {
          method: 'POST',
          body: JSON.stringify({ name: payload.get('name') }),
        });
        form.reset();
        await refreshDashboard();
        showToast('Hostel added. Add floors and rooms to configure beds.');
      } catch (error) {
        showToast(error.message);
      } finally {
        submit.disabled = false;
      }
      return;
    }

    if (form.matches('[data-floor-form]')) {
      event.preventDefault();
      const submit = form.querySelector('button[type="submit"]');
      submit.disabled = true;
      try {
        const payload = new FormData(form);
        await apiRequest(`/api/hostels/${encodeURIComponent(form.dataset.hostelId)}/floors`, {
          method: 'POST',
          body: JSON.stringify({ floor_number: Number(payload.get('floor_number')) }),
        });
        await refreshDashboard();
        showToast('Floor added. Configure the rooms on this floor.');
      } catch (error) {
        showToast(error.message);
      } finally {
        submit.disabled = false;
      }
      return;
    }

    if (form.matches('[data-room-form]')) {
      event.preventDefault();
      const submit = form.querySelector('button[type="submit"]');
      submit.disabled = true;
      try {
        const payload = new FormData(form);
        await apiRequest(`/api/floors/${encodeURIComponent(form.dataset.floorId)}/rooms`, {
          method: 'POST',
          body: JSON.stringify({
            room_number: payload.get('room_number'),
            share_count: Number(payload.get('share_count')),
          }),
        });
        await refreshDashboard();
        showToast('Room added with its sharing capacity.');
      } catch (error) {
        showToast(error.message);
      } finally {
        submit.disabled = false;
      }
    }
  });

  $('#payment-status').addEventListener('change', event => {
    const unpaid = event.target.value === 'unpaid';
    $('#amount-due-field').hidden = !unpaid;
    $('#amount-due').required = unpaid;
    if (!unpaid) $('#amount-due').value = '';
  });
  roomSelect.addEventListener('change', renderBedOptions);
  joiningDate.addEventListener('input', updatePaymentDate);
  $('#resident-search').addEventListener('input', () => renderResidents());
  $('#resident-search-all').addEventListener('input', () => renderResidents());

  document.addEventListener('click', async event => {
    const joinButton = event.target.closest('.open-join');
    if (joinButton) openJoinModal();

    if (event.target === joinModal || event.target.closest('[data-close]')) closeJoinModal();

    const navButton = event.target.closest('[data-view]');
    const gotoButton = event.target.closest('[data-goto]');
    const destination = navButton?.dataset.view || gotoButton?.dataset.goto;
    if (destination) {
      document.querySelectorAll('.page-view').forEach(view => { view.hidden = view.id !== `${destination}-view`; });
      document.querySelectorAll('.nav-button').forEach(button => {
        const active = button.dataset.view === destination;
        button.classList.toggle('active', active);
        if (active) button.setAttribute('aria-current', 'page'); else button.removeAttribute('aria-current');
      });
      $('#crumb-view').textContent = destination.charAt(0).toUpperCase() + destination.slice(1);
    }

    const deleteRoomButton = event.target.closest('[data-delete-room]');
    if (deleteRoomButton) {
      const room = state.rooms.find(item => item.id === deleteRoomButton.dataset.deleteRoom);
      if (!room || !window.confirm(`Delete Room ${room.room_number} from ${room.hostel_name}, ${floorLabel(room.floor_number)}? It will be removed from active availability; past resident and audit history will be retained.`)) return;
      try {
        await apiRequest(`/api/rooms/${encodeURIComponent(room.id)}`, { method: 'DELETE' });
        await refreshDashboard();
        showToast(`Room ${room.room_number} deleted from active availability.`);
      } catch (error) {
        showToast(error.message);
      }
    }

    const deleteHostelButton = event.target.closest('[data-delete-hostel]');
    if (deleteHostelButton) {
      const hostel = state.hostels.find(item => item.id === deleteHostelButton.dataset.deleteHostel);
      if (!hostel || !window.confirm(`Delete ${hostel.name} from active availability? Its rooms will be archived and past resident/audit history retained.`)) return;
      try {
        await apiRequest(`/api/hostels/${encodeURIComponent(hostel.id)}`, { method: 'DELETE' });
        await refreshDashboard();
        showToast(`${hostel.name} deleted from active availability.`);
      } catch (error) {
        showToast(error.message);
      }
    }

    const checkoutButton = event.target.closest('[data-checkout]');
    if (checkoutButton) {
      const resident = state.residents.find(item => item.id === checkoutButton.dataset.checkout);
      if (!resident || !window.confirm(`Check out ${resident.name} from ${resident.hostel_name}, ${floorLabel(resident.floor_number)}, Room ${resident.room}, Bed ${resident.bed_number}? This will free the bed.`)) return;
      try {
        await apiRequest(`/api/residents/${encodeURIComponent(resident.id)}`, { method: 'DELETE' });
        await refreshDashboard();
        showToast(`${resident.name} checked out. Bed ${resident.bed_number} is available.`);
      } catch (error) {
        showToast(error.message);
      }
    }

    const reminderButton = event.target.closest('[data-whatsapp]');
    if (reminderButton) {
      const resident = state.residents.find(item => item.id === reminderButton.dataset.whatsapp);
      if (resident?.payment_status === 'unpaid') openWhatsAppReminder(resident);
    }

    const paidButton = event.target.closest('[data-mark-paid]');
    if (paidButton) {
      const resident = state.residents.find(item => item.id === paidButton.dataset.markPaid);
      if (!resident || resident.payment_status !== 'unpaid') return;
      try {
        await apiRequest(`/api/residents/${encodeURIComponent(resident.id)}/payment`, { method: 'POST' });
        await refreshDashboard();
        showToast(`Payment marked as paid for ${resident.name}.`);
      } catch (error) {
        showToast(error.message);
      }
    }

    if (event.target.closest('#logout-button')) {
      try {
        await apiRequest('/api/session/logout', { method: 'POST' });
      } catch (error) {
        showToast(error.message);
      }
      showLogin();
    }
  });

  document.addEventListener('keydown', event => {
    if (event.key === 'Escape' && !joinModal.hidden) closeJoinModal();
  });

  async function initialize() {
    try {
      const session = await apiRequest('/api/session');
      csrfToken = session.csrf_token;
      await refreshDashboard();
    } catch {
      try {
        const setup = await apiRequest('/api/setup-status');
        showLogin('', setup.setup_required);
      } catch {
        showLogin();
      }
    }
  }

  $('#today-date').textContent = new Intl.DateTimeFormat('en-IN', {
    weekday: 'long', day: 'numeric', month: 'long', year: 'numeric',
  }).format(new Date());
  initialize();
})();