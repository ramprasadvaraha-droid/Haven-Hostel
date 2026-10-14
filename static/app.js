(() => {
  const $ = (selector, root = document) => root.querySelector(selector);
  const landingScreen = $('#landing-screen');
  const loginScreen = $('#login-screen');
  const developerLoginScreen = $('#developer-login-screen');
  const hostelApp = $('#hostel-app');
  const platformApp = $('#platform-app');
  const loginForm = $('#login-form');
  const signupForm = $('#signup-form');
  const developerLoginForm = $('#developer-login-form');
  const joinForm = $('#join-form');
  const joinModal = $('#join-modal');
  const roomChargesModal = $('#room-charges-modal');
  const roomSelect = $('#room-select');
  const bedSelect = $('#bed-select');
  const joiningDate = $('#checkin-input');
  const paymentDate = $('#payment-date');
  const state = { user: null, summary: null, rooms: [], residents: [], activity: [], bookings: null, newBookingIds: new Set(), platform: null, roomTypeCharges: [] };
  let csrfToken = '';
  let platformCsrfToken = '';
  let selectedPlatformHostelId = '';
  let toastTimer;

  const bedIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M3 18v-8M3 15h18v5M7 15v-5a3 3 0 0 1 3-3h7a4 4 0 0 1 4 4v4M3 20v-2m18 2v-2" stroke-linecap="round" stroke-linejoin="round"/></svg>';

  function escapeHTML(value) {
    return String(value ?? '').replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
  }

  async function apiRequest(path, options = {}) {
    const method = (options.method || 'GET').toUpperCase();
    const headers = new Headers(options.headers || {});
    const token = path.startsWith('/api/platform/') ? platformCsrfToken : csrfToken;
    if (!['GET', 'HEAD', 'OPTIONS'].includes(method) && token) headers.set('X-CSRF-Token', token);
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
    landingScreen.hidden = true;
    developerLoginScreen.hidden = true;
    hostelApp.hidden = true;
    platformApp.hidden = true;
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

  function showLanding() {
    csrfToken = '';
    platformCsrfToken = '';
    state.user = null;
    state.platform = null;
    landingScreen.hidden = false;
    loginScreen.hidden = true;
    developerLoginScreen.hidden = true;
    hostelApp.hidden = true;
    platformApp.hidden = true;
  }

  function showDeveloperLogin() {
    landingScreen.hidden = true;
    loginScreen.hidden = true;
    developerLoginScreen.hidden = false;
    hostelApp.hidden = true;
    platformApp.hidden = true;
    $('#developer-login-error').hidden = true;
    $('#developer-username').focus();
  }

  function showDashboard(user) {
    state.user = user;
    landingScreen.hidden = true;
    developerLoginScreen.hidden = true;
    $('#staff-identity').textContent = `${user.username} · ${user.role}`;
    $('#qr-nav').hidden = user.role !== 'admin';
    platformApp.hidden = true;
    hostelApp.hidden = false;
    loginScreen.hidden = true;
  }

  function showPlatformDashboard(user) {
    state.user = user;
    landingScreen.hidden = true;
    loginScreen.hidden = true;
    developerLoginScreen.hidden = true;
    hostelApp.hidden = true;
    platformApp.hidden = false;
    $('#platform-identity').textContent = user.username;
  }

  function showPlatformStep(step) {
    document.querySelectorAll('.platform-step-panel').forEach(panel => {
      panel.hidden = panel.id !== `platform-${step}-step`;
    });
    document.querySelectorAll('.platform-steps [data-platform-step]').forEach(button => {
      if (button.dataset.platformStep === step) button.setAttribute('aria-current', 'step');
      else button.removeAttribute('aria-current');
    });
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
    return room.beds.map(bed => {
      const status = bed.occupied ? 'occupied' : bed.reserved ? 'reserved' : 'available';
      return `<span class="bed ${bed.occupied ? 'filled' : bed.reserved ? 'reserved' : ''}" title="Bed ${bed.number} ${status}" aria-label="Bed ${bed.number} ${status}">${bedIcon}<span class="bed-number">${bed.number}</span></span>`;
    }).join('');
  }

  function renderBedOptions() {
    const room = state.rooms.find(item => item.id === roomSelect.value);
    const bedNumbers = room ? availableBeds(room) : [];
    bedSelect.innerHTML = bedNumbers.length
      ? bedNumbers.map(number => `<option value="${number}">Bed ${number}</option>`).join('')
      : '<option value="" disabled selected>No beds available</option>';
    bedSelect.disabled = !bedNumbers.length;
    updateAmountDueFromRoom(room);
  }

  function updateAmountDueFromRoom(room) {
    const amountDue = $('#amount-due');
    if ($('#payment-status').value !== 'unpaid') return;
    if (amountDue.dataset.rateDefault !== 'true' && amountDue.value) return;
    amountDue.value = room?.monthly_rent_paise ? (room.monthly_rent_paise / 100).toFixed(2) : '';
    amountDue.dataset.rateDefault = room?.monthly_rent_paise ? 'true' : 'false';
  }

  function renderRooms() {
    const availableRooms = state.rooms.filter(room => room.available_beds > 0 && !room.reserved);

    const previousRoom = roomSelect.value;
    roomSelect.innerHTML = availableRooms.length
      ? availableRooms.map(room => `<option value="${escapeHTML(room.id)}">${escapeHTML(room.hostel_name)} · ${floorLabel(room.floor_number)} · Room ${escapeHTML(room.room_number)} · ${room.available_beds} open${room.monthly_rent_paise ? ` · ${escapeHTML(formatCurrency(room.monthly_rent_paise))}/month` : ''}</option>`).join('')
      : '<option value="" disabled selected>No beds available</option>';
    if (availableRooms.some(room => room.id === previousRoom)) roomSelect.value = previousRoom;
    roomSelect.disabled = availableRooms.length === 0;
    renderBedOptions();
    renderHostelStructure();
    renderRoomTypeCharges();

    $('#stat-capacity').textContent = String(state.summary.capacity);
    $('#stat-total-hostels').textContent = String(state.summary.total_hostels);
    $('#stat-occupied').textContent = String(state.summary.occupied);
    $('#stat-available').textContent = String(state.summary.available);
    $('#stat-rooms-open').textContent = String(state.summary.rooms_open);
    $('#stat-total-rooms').textContent = String(state.summary.total_rooms);
    $('#stat-paid-count').textContent = String(state.summary.paid_count);
    $('#stat-pending-count').textContent = String(state.summary.unpaid_count);
    $('#stat-outstanding-text').textContent = `${formatCurrency(state.summary.outstanding_paise)} outstanding`;
  }

  function renderRoomTile(room, canManage) {
    const deleteButton = canManage
      ? `<div class="room-structure-actions"><button class="delete-room-button" type="button" data-delete-room="${escapeHTML(room.id)}" ${room.occupied || room.reserved ? 'disabled title="Check residents out or cancel the visit before deleting this room."' : ''}>Delete room</button></div>`
      : '';
    const rentForm = canManage
      ? `<form class="rent-form" data-rent-form data-room-id="${escapeHTML(room.id)}"><label for="rent-${escapeHTML(room.id)}">Monthly rent</label><input id="rent-${escapeHTML(room.id)}" name="monthly_rent" type="number" min="0" max="1000000" step="0.01" value="${(room.monthly_rent_paise / 100).toFixed(2)}" required><button type="submit">Save</button></form>`
      : '';
    const badge = room.reserved
      ? `<span class="room-pill reserved">Reserved by ${escapeHTML(room.reservation_name)} · ${escapeHTML(room.reservation_visit_time)}</span>`
      : `<span class="room-pill">${room.available_beds} open</span>`;
    const monthlyCharge = room.monthly_rent_paise > 0 ? ` · ${formatCurrency(room.monthly_rent_paise)}/month` : '';
    return `<article class="room-structure-tile ${room.reserved ? 'reserved' : ''}"><div class="room-tile-top"><div><div class="room-id">Room ${escapeHTML(room.room_number)}</div><div class="room-type">${room.share_count}-share · ${room.occupied}/${room.share_count} occupied${monthlyCharge}</div></div>${badge}</div><div class="beds" aria-label="${room.occupied} occupied, ${room.available_beds} available">${renderBeds(room)}</div>${rentForm}${deleteButton}</article>`;
  }

  function renderRoomTypeCharges() {
    const container = $('#room-charges-list');
    if (!container) return;
    const placeholders = { 2: '10000', 3: '8500', 4: '7500' };
    container.innerHTML = state.hostels.length
      ? state.hostels.map(hostel => {
        const hostelRooms = hostel.floors.flatMap(floor => floor.rooms);
        const shareCounts = [...new Set(hostelRooms.map(room => room.share_count))].sort((first, second) => first - second);
        if (!shareCounts.length) {
          return `<div class="room-charge-form"><h3 class="room-charge-form-title">${escapeHTML(hostel.name)}</h3><div class="empty-activity">Add rooms in the Employer layout before setting charges.</div></div>`;
        }
        const fields = shareCounts.map(shareCount => {
          const savedCharge = state.roomTypeCharges.find(charge => charge.hostel_id === hostel.id && charge.share_count === shareCount);
          const roomRates = hostelRooms.filter(room => room.share_count === shareCount).map(room => room.monthly_rent_paise);
          const uniqueRates = [...new Set(roomRates)];
          const inheritedRate = uniqueRates.length === 1 && uniqueRates[0] > 0 ? uniqueRates[0] : null;
          const value = savedCharge
            ? (savedCharge.monthly_rent_paise / 100).toFixed(2)
            : inheritedRate === null ? '' : (inheritedRate / 100).toFixed(2);
          return `<div class="room-charge-field"><label for="room-charge-${escapeHTML(hostel.id)}-${shareCount}">${shareCount} sharing · INR/month</label><input id="room-charge-${escapeHTML(hostel.id)}-${shareCount}" name="monthly_rent_${shareCount}" data-share-count="${shareCount}" type="number" min="0" max="1000000" step="0.01" value="${value}" placeholder="${placeholders[shareCount] || 'Enter amount'}"></div>`;
        }).join('');
        return `<form class="room-charge-form" data-room-charges-form data-hostel-id="${escapeHTML(hostel.id)}"><div class="room-charge-form-head"><div><h3 class="room-charge-form-title">${escapeHTML(hostel.name)}</h3><div class="section-subtitle">Updates matching rooms and prices for future bookings.</div></div><button class="primary-button" type="submit">Save prices</button></div><div class="room-charge-fields">${fields}</div></form>`;
      }).join('')
      : '<div class="table-empty">Register a hostel client before setting room charges.</div>';
  }

  function renderHostelStructure() {
    const canManage = false;
    $('#hostel-create-wrap').hidden = true;
    $('#hostel-structure').innerHTML = state.hostels.length
      ? state.hostels.map(hostel => {
        const hostelRooms = hostel.floors.reduce((total, floor) => total + floor.rooms.length, 0);
        const floorMarkup = hostel.floors.length
          ? hostel.floors.map(floor => {
            const roomsMarkup = floor.rooms.length
              ? `<div class="room-structure-grid">${floor.rooms.map(room => renderRoomTile(room, canManage)).join('')}</div>`
              : '<div class="floor-empty">No rooms on this floor yet.</div>';
            const addRoomForm = canManage
              ? `<form class="structure-form" data-room-form data-floor-id="${escapeHTML(floor.id)}"><div class="field room-number-field"><label>Room number</label><input name="room_number" required maxlength="20" placeholder="e.g. 105"></div><div class="field share-field"><label>Sharing capacity</label><input name="share_count" type="number" min="1" max="20" value="4" required></div><div class="field rent-field"><label>Monthly rent (INR)</label><input name="monthly_rent" type="number" min="0" max="1000000" step="0.01" value="0" required></div><button class="primary-button" type="submit">Add room</button></form>`
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
    const activityMarkup = (items, type) => items.length
      ? items.map(item => `<div class="activity"><div class="activity-icon ${type === 'exit' ? 'exit' : ''}">${type === 'exit' ? icon.replace('M12 5v14M5 12h14', 'M5 12h14') : icon}</div><div><div class="activity-text"><strong>${escapeHTML(item.name)}</strong> ${type === 'exit' ? 'checked out of' : 'checked in to'} <strong>${escapeHTML(item.hostel_name ? `${item.hostel_name} · ${floorLabel(item.floor_number)} · ` : '')}Room ${escapeHTML(item.room)}${item.bed_number ? ` · Bed ${item.bed_number}` : ''}</strong></div><div class="activity-time">${escapeHTML(new Intl.DateTimeFormat('en-IN', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(item.time)))}</div></div></div>`).join('')
      : `<div class="empty-activity">No ${type === 'exit' ? 'check-outs' : 'check-ins'} yet.</div>`;
    $('#checkin-activity-list').innerHTML = activityMarkup(state.activity.filter(item => item.type === 'join').slice(0, 5), 'join');
    $('#checkout-activity-list').innerHTML = activityMarkup(state.activity.filter(item => item.type === 'exit').slice(0, 5), 'exit');
  }

  function renderBookings() {
    const bookings = state.bookings || [];
    $('#pending-visits-label').textContent = `Pending Visits (${bookings.length})`;
    $('#booking-count').textContent = bookings.length
      ? `${bookings.length} visit${bookings.length === 1 ? '' : 's'} awaiting confirmation`
      : 'No pending visits';
    $('#booking-list').innerHTML = bookings.length
      ? bookings.map(booking => `<article class="booking-card ${state.newBookingIds.has(booking.id) ? 'booking-card-new' : ''}"><div><div class="booking-name">${escapeHTML(booking.student_name)}</div><div class="booking-meta">${escapeHTML(booking.phone)} · ${escapeHTML(booking.hostel_name)} · ${floorLabel(booking.floor_number)}<br>Room ${escapeHTML(booking.room_number)} · ${booking.sharing_needed || 'Any'} sharing · Visit ${escapeHTML(booking.visit_time)}${booking.monthly_rent_paise ? ` · ${escapeHTML(formatCurrency(booking.monthly_rent_paise))}/month` : ''}</div></div><div class="booking-actions"><button class="booking-confirm" type="button" data-confirm-booking="${escapeHTML(booking.id)}">Confirm</button><button class="booking-cancel" type="button" data-cancel-booking="${escapeHTML(booking.id)}">Cancel</button></div></article>`).join('')
      : '<div class="table-empty">No pending visits.</div>';
  }

  function renderQrHostels() {
    const select = $('#qr-hostel-select');
    const previous = select.value;
    select.innerHTML = state.hostels.length
      ? state.hostels.map(hostel => `<option value="${escapeHTML(hostel.id)}">${escapeHTML(hostel.name)}</option>`).join('')
      : '<option value="">No active hostels</option>';
    if (state.hostels.some(hostel => hostel.id === previous)) select.value = previous;
    $('#generate-qr').disabled = !state.hostels.length;
  }

  function renderPlatformLayout(hostelId = selectedPlatformHostelId) {
    const hostel = state.platform?.hostels.find(item => item.id === hostelId);
    if (!hostel) {
      $('#platform-hostel-structure').innerHTML = '<div class="table-empty">Register a client to set up its hostel layout.</div>';
      return;
    }
    selectedPlatformHostelId = hostel.id;
    const floorMarkup = hostel.floors.length
      ? hostel.floors.map(floor => {
        const rooms = floor.rooms.length
          ? `<div class="room-structure-grid">${floor.rooms.map(room => `<article class="room-structure-tile"><div class="room-tile-top"><div><div class="room-id">Room ${escapeHTML(room.room_number)}</div><div class="room-type">${room.share_count}-bed room${room.monthly_rent_paise ? ` · ${escapeHTML(formatCurrency(room.monthly_rent_paise))}/month` : ''}</div></div><span class="room-pill">${room.share_count} beds</span></div></article>`).join('')}</div>`
          : '<div class="floor-empty">No rooms on this floor yet.</div>';
        return `<section class="floor-group"><div class="floor-head"><div><h3 class="floor-title">${floorLabel(floor.floor_number)}</h3><div class="section-subtitle">${floor.rooms.length} room${floor.rooms.length === 1 ? '' : 's'}</div></div></div>${rooms}<form class="structure-form" data-platform-room-form data-floor-id="${escapeHTML(floor.id)}"><div class="field room-number-field"><label>Room number</label><input name="room_number" required maxlength="20" placeholder="e.g. 105"></div><div class="field share-field"><label>Beds per room</label><select name="share_count" required><option value="1">1 bed</option><option value="2">2 beds</option><option value="3">3 beds</option><option value="4" selected>4 beds</option></select></div><button class="primary-button" type="submit">Add room</button></form></section>`;
      }).join('')
      : '<div class="floor-group floor-empty">No floors yet. Add the first floor to define this hostel layout.</div>';
    const addFloor = hostel.floors.length < 99
      ? `<form class="structure-form" data-platform-floor-form data-hostel-id="${escapeHTML(hostel.id)}"><div class="field"><label>Floor number</label><input name="floor_number" type="number" min="1" max="99" required placeholder="e.g. 1"></div><button class="primary-button" type="submit">Add floor</button></form>`
      : '';
    $('#platform-hostel-structure').innerHTML = `<article class="hostel-card"><header class="hostel-card-head"><div><h2 class="hostel-card-title">Hostel setup</h2><div class="hostel-card-meta">${hostel.floors.length} floor${hostel.floors.length === 1 ? '' : 's'} · ${hostel.floors.reduce((total, floor) => total + floor.rooms.length, 0)} rooms</div></div></header>${floorMarkup}<section class="floor-group">${addFloor}</section></article>`;
  }

  function renderPlatformDashboard() {
    const { summary, clients, hostels } = state.platform;
    $('#platform-clients-count').textContent = String(summary.total_clients);
    $('#platform-subscription-received').textContent = formatCurrency(summary.subscription_received_paise);
    $('#platform-subscription-received-count').textContent = `${summary.subscription_received_count} received`;
    $('#platform-subscription-pending').textContent = formatCurrency(summary.subscription_pending_paise);
    $('#platform-subscription-pending-count').textContent = `${summary.subscription_pending_count} pending`;
    $('#platform-client-count').textContent = `${summary.total_clients} registered client${summary.total_clients === 1 ? '' : 's'} · ${clients.length} active hostel${clients.length === 1 ? '' : 's'}`;
    document.querySelectorAll('[data-platform-step="layout"], [data-platform-step="dashboard"]').forEach(button => {
      button.disabled = clients.length === 0;
    });
    $('#platform-client-list').innerHTML = clients.length
      ? `<table><thead><tr><th>Client</th><th>Hostel</th></tr></thead><tbody>${clients.map(client => `<tr><td><button class="text-button" type="button" data-select-platform-hostel="${escapeHTML(client.hostel_id)}" aria-label="Open ${escapeHTML(client.owner_username)} hostel layout">${escapeHTML(client.owner_username)}</button></td><td>${escapeHTML(client.hostel_name)}</td></tr>`).join('')}</tbody></table>`
      : '<div class="table-empty">No clients registered yet.</div>';
    $('#subscription-count').textContent = `${state.platform.subscriptions.length} subscription payment${state.platform.subscriptions.length === 1 ? '' : 's'}`;
    $('#platform-subscription-list').innerHTML = state.platform.subscriptions.length
      ? `<table><thead><tr><th>Client</th><th>Period</th><th>Amount</th><th>Due</th><th>Status</th><th></th></tr></thead><tbody>${state.platform.subscriptions.map(subscription => `<tr><td class="resident-name">${escapeHTML(subscription.owner_username)}</td><td>${escapeHTML(subscription.billing_period)}</td><td>${escapeHTML(formatCurrency(subscription.amount_paise))}</td><td>${escapeHTML(formatDate(subscription.due_date))}</td><td><span class="${subscription.status === 'received' ? 'payment-paid' : 'payment-unpaid'}">${subscription.status === 'received' ? 'Received' : 'Pending'}</span></td><td>${subscription.status === 'pending' ? `<button class="mark-paid-button" type="button" data-subscription-received="${escapeHTML(subscription.id)}">Mark received</button>` : ''}</td></tr>`).join('')}</tbody></table>`
      : '<div class="table-empty">No subscription payments recorded yet.</div>';
    const ownerSelect = $('#subscription-owner');
    const previousOwner = ownerSelect.value;
    ownerSelect.innerHTML = state.platform.owners.length
      ? state.platform.owners.map(owner => `<option value="${escapeHTML(owner.owner_id)}">${escapeHTML(owner.owner_username)}</option>`).join('')
      : '<option value="">No active clients</option>';
    if (state.platform.owners.some(owner => owner.owner_id === previousOwner)) ownerSelect.value = previousOwner;
    $('#platform-subscription-form').querySelector('button[type="submit"]').disabled = !state.platform.owners.length;
    if (selectedPlatformHostelId && !hostels.some(hostel => hostel.id === selectedPlatformHostelId)) selectedPlatformHostelId = '';
    renderPlatformLayout(selectedPlatformHostelId);
  }

  async function refreshPlatformDashboard() {
    const payload = await apiRequest('/api/platform/dashboard');
    state.platform = payload;
    showPlatformDashboard(payload.user);
    renderPlatformDashboard();
  }

  async function refreshDashboard() {
    const [dashboard, bookings] = await Promise.all([
      apiRequest('/api/dashboard'),
      apiRequest('/api/bookings'),
    ]);
    state.summary = dashboard.summary;
    state.hostels = dashboard.hostels;
    state.roomTypeCharges = dashboard.room_type_charges || [];
    state.rooms = dashboard.rooms;
    state.residents = dashboard.residents;
    state.activity = dashboard.activity;
    const priorBookingIds = new Set((state.bookings || []).map(booking => booking.id));
    state.newBookingIds = new Set(bookings.filter(booking => !priorBookingIds.has(booking.id)).map(booking => booking.id));
    state.bookings = bookings;
    showDashboard(dashboard.user);
    renderRooms();
    renderResidents();
    renderActivity();
    renderBookings();
    renderQrHostels();
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
    if (!state.rooms.some(room => room.available_beds > 0 && !room.reserved)) {
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
    $('#amount-due').dataset.rateDefault = 'false';
  }

  function openRoomChargesModal() {
    renderRoomTypeCharges();
    roomChargesModal.hidden = false;
    roomChargesModal.querySelector('input')?.focus();
  }

  function closeRoomChargesModal() {
    roomChargesModal.hidden = true;
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

  developerLoginForm.addEventListener('submit', async event => {
    event.preventDefault();
    const submit = developerLoginForm.querySelector('button[type="submit"]');
    submit.disabled = true;
    $('#developer-login-error').hidden = true;
    try {
      const payload = await apiRequest('/api/platform/session', {
        method: 'POST',
        body: JSON.stringify({
          username: $('#developer-username').value.trim(),
          password: $('#developer-password').value,
        }),
      });
      platformCsrfToken = payload.csrf_token;
      developerLoginForm.reset();
      await refreshPlatformDashboard();
    } catch (error) {
      $('#developer-login-error').textContent = error.message;
      $('#developer-login-error').hidden = false;
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
    if (form.matches('[data-room-charges-form]')) {
      event.preventDefault();
      const submit = form.querySelector('button[type="submit"]');
      const payload = new FormData(form);
      const charges = [...form.querySelectorAll('[data-share-count]')]
        .filter(input => String(payload.get(input.name)).trim() !== '')
        .map(input => ({ share_count: Number(input.dataset.shareCount), monthly_rent: Number(payload.get(input.name)) }));
      if (!charges.length) {
        showToast('Enter a price for at least one sharing type.');
        return;
      }
      submit.disabled = true;
      try {
        await apiRequest(`/api/hostels/${encodeURIComponent(form.dataset.hostelId)}/room-charges`, {
          method: 'PUT',
          body: JSON.stringify({ charges }),
        });
        await refreshDashboard();
        showToast('Room type charges saved and applied to matching rooms.');
      } catch (error) {
        showToast(error.message);
      } finally {
        submit.disabled = false;
      }
      return;
    }

    if (form.id === 'platform-subscription-form') {
      event.preventDefault();
      const submit = form.querySelector('button[type="submit"]');
      submit.disabled = true;
      try {
        const payload = new FormData(form);
        await apiRequest('/api/platform/subscriptions', {
          method: 'POST',
          body: JSON.stringify({
            owner_id: payload.get('owner_id'),
            billing_period: payload.get('billing_period'),
            amount: Number(payload.get('amount')),
            due_date: payload.get('due_date'),
          }),
        });
        form.reset();
        await refreshPlatformDashboard();
        showToast('Subscription payment recorded as pending.');
      } catch (error) {
        showToast(error.message);
      } finally {
        submit.disabled = !state.platform?.owners.length;
      }
      return;
    }

    if (form.id === 'platform-client-form') {
      event.preventDefault();
      const submit = form.querySelector('button[type="submit"]');
      submit.disabled = true;
      try {
        const payload = new FormData(form);
        const created = await apiRequest('/api/platform/clients', {
          method: 'POST',
          body: JSON.stringify({
            owner_username: payload.get('owner_username'),
            password: payload.get('password'),
            hostel_name: payload.get('hostel_name'),
          }),
        });
        form.reset();
        await refreshPlatformDashboard();
        selectedPlatformHostelId = created.hostel_id;
        renderPlatformLayout(created.hostel_id);
        showPlatformStep('layout');
        showToast('Hostel owner and first hostel registered.');
      } catch (error) {
        showToast(error.message);
      } finally {
        submit.disabled = false;
      }
      return;
    }

    if (form.matches('[data-platform-floor-form]')) {
      event.preventDefault();
      const submit = form.querySelector('button[type="submit"]');
      submit.disabled = true;
      try {
        const payload = new FormData(form);
        await apiRequest(`/api/platform/hostels/${encodeURIComponent(form.dataset.hostelId)}/floors`, {
          method: 'POST',
          body: JSON.stringify({ floor_number: Number(payload.get('floor_number')) }),
        });
        await refreshPlatformDashboard();
        showToast('Floor added to the hostel layout.');
      } catch (error) {
        showToast(error.message);
      } finally {
        submit.disabled = false;
      }
      return;
    }

    if (form.matches('[data-platform-room-form]')) {
      event.preventDefault();
      const submit = form.querySelector('button[type="submit"]');
      submit.disabled = true;
      try {
        const payload = new FormData(form);
        await apiRequest(`/api/platform/floors/${encodeURIComponent(form.dataset.floorId)}/rooms`, {
          method: 'POST',
          body: JSON.stringify({
            room_number: payload.get('room_number'),
            share_count: Number(payload.get('share_count')),
          }),
        });
        await refreshPlatformDashboard();
        showToast('Room added to the hostel layout.');
      } catch (error) {
        showToast(error.message);
      } finally {
        submit.disabled = false;
      }
      return;
    }

    if (form.matches('[data-rent-form]')) {
      event.preventDefault();
      const submit = form.querySelector('button[type="submit"]');
      submit.disabled = true;
      try {
        const payload = new FormData(form);
        await apiRequest(`/api/rooms/${encodeURIComponent(form.dataset.roomId)}/rent`, {
          method: 'PATCH',
          body: JSON.stringify({ monthly_rent: Number(payload.get('monthly_rent')) }),
        });
        await refreshDashboard();
        showToast('Monthly room rent updated.');
      } catch (error) {
        showToast(error.message);
      } finally {
        submit.disabled = false;
      }
      return;
    }

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
            monthly_rent: Number(payload.get('monthly_rent') || 0),
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
    if (unpaid) updateAmountDueFromRoom(state.rooms.find(room => room.id === roomSelect.value));
    else {
      $('#amount-due').value = '';
      $('#amount-due').dataset.rateDefault = 'false';
    }
  });
  $('#amount-due').addEventListener('input', () => { $('#amount-due').dataset.rateDefault = 'false'; });
  roomSelect.addEventListener('change', renderBedOptions);
  joiningDate.addEventListener('input', updatePaymentDate);
  $('#resident-search').addEventListener('input', () => renderResidents());
  $('#resident-search-all').addEventListener('input', () => renderResidents());
  document.addEventListener('click', async event => {
    const portalButton = event.target.closest('[data-open-portal]');
    if (portalButton?.dataset.openPortal === 'owner') {
      try {
        const setup = await apiRequest('/api/setup-status');
        showLogin('', setup.setup_required);
      } catch {
        showLogin();
      }
    }
    if (portalButton?.dataset.openPortal === 'developer') showDeveloperLogin();
    if (event.target.closest('[data-back-to-landing]')) showLanding();

    const platformHostelButton = event.target.closest('[data-select-platform-hostel]');
    if (platformHostelButton) {
      selectedPlatformHostelId = platformHostelButton.dataset.selectPlatformHostel;
      renderPlatformLayout(platformHostelButton.dataset.selectPlatformHostel);
      showPlatformStep('layout');
      $('#platform-layout-step').scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    const platformStepButton = event.target.closest('[data-platform-step]');
    if (platformStepButton && !platformStepButton.disabled) showPlatformStep(platformStepButton.dataset.platformStep);

    if (event.target.closest('[data-finish-platform-layout]')) {
      selectedPlatformHostelId = '';
      renderPlatformLayout('');
      $('#platform-client-form').reset();
      showPlatformStep('client');
      $('#client-owner-username').focus();
      showToast('Layout complete. Ready to register the next client.');
    }

    const subscriptionReceivedButton = event.target.closest('[data-subscription-received]');
    if (subscriptionReceivedButton) {
      const subscriptionId = subscriptionReceivedButton.dataset.subscriptionReceived;
      try {
        await apiRequest(`/api/platform/subscriptions/${encodeURIComponent(subscriptionId)}/received`, {
          method: 'PATCH',
          body: JSON.stringify({}),
        });
        await refreshPlatformDashboard();
        showToast('Subscription payment marked as received.');
      } catch (error) {
        showToast(error.message);
      }
    }

    const joinButton = event.target.closest('.open-join');
    if (joinButton) openJoinModal();

    if (event.target === joinModal || event.target.closest('[data-close]')) closeJoinModal();
    if (event.target.closest('.open-room-charges')) openRoomChargesModal();
    if (event.target === roomChargesModal || event.target.closest('[data-close-room-charges]')) closeRoomChargesModal();

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

    const confirmBookingButton = event.target.closest('[data-confirm-booking]');
    if (confirmBookingButton) {
      const booking = state.bookings?.find(item => item.id === confirmBookingButton.dataset.confirmBooking);
      if (!booking || !window.confirm(`Confirm ${booking.student_name} for Room ${booking.room_number}? This creates a resident record and marks the room occupied.`)) return;
      try {
        await apiRequest(`/api/bookings/confirm/${encodeURIComponent(booking.id)}`, {
          method: 'POST',
          body: JSON.stringify({}),
        });
        await refreshDashboard();
        showToast(`${booking.student_name} checked in to Room ${booking.room_number}.`);
      } catch (error) {
        showToast(error.message);
      }
    }

    const cancelBookingButton = event.target.closest('[data-cancel-booking]');
    if (cancelBookingButton) {
      const booking = state.bookings?.find(item => item.id === cancelBookingButton.dataset.cancelBooking);
      if (!booking || !window.confirm(`Cancel ${booking.student_name}'s visit? Room ${booking.room_number} will be released.`)) return;
      try {
        await apiRequest(`/api/bookings/${encodeURIComponent(booking.id)}`, { method: 'DELETE' });
        await refreshDashboard();
        showToast('Visit cancelled and room released.');
      } catch (error) {
        showToast(error.message);
      }
    }

    if (event.target.closest('#generate-qr')) {
      const hostelId = $('#qr-hostel-select').value;
      const hostel = state.hostels.find(item => item.id === hostelId);
      if (!hostel) return;
      const imageUrl = `/api/qr/${encodeURIComponent(hostelId)}`;
      try {
        const response = await fetch(imageUrl, { credentials: 'same-origin' });
        if (!response.ok) {
          const payload = await response.json().catch(() => null);
          throw new Error(payload?.detail || 'Could not generate the QR code.');
        }
        const imageBlob = await response.blob();
        const image = $('#qr-image');
        if (image.dataset.objectUrl) URL.revokeObjectURL(image.dataset.objectUrl);
        image.dataset.objectUrl = URL.createObjectURL(imageBlob);
        image.src = image.dataset.objectUrl;
        $('#qr-hostel-name').textContent = hostel.name;
        $('#qr-download').href = `${imageUrl}?download=true`;
        $('#qr-empty').hidden = true;
        const card = $('#qr-card');
        card.hidden = false;
        card.classList.remove('qr-visible');
        requestAnimationFrame(() => card.classList.add('qr-visible'));
      } catch (error) {
        showToast(error.message);
      }
    }

    if (event.target.closest('#qr-print')) {
      document.body.classList.add('print-qr');
      window.addEventListener('afterprint', () => document.body.classList.remove('print-qr'), { once: true });
      window.print();
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
      showLanding();
    }

    if (event.target.closest('#platform-logout-button')) {
      try {
        await apiRequest('/api/platform/session/logout', { method: 'POST' });
      } catch (error) {
        showToast(error.message);
      }
      showLanding();
    }
  });

  document.addEventListener('keydown', event => {
    if (event.key !== 'Escape') return;
    if (!roomChargesModal.hidden) closeRoomChargesModal();
    else if (!joinModal.hidden) closeJoinModal();
  });

  async function initialize() {
    try {
      const platformSession = await apiRequest('/api/platform/session');
      platformCsrfToken = platformSession.csrf_token;
      await refreshPlatformDashboard();
      return;
    } catch {
      platformCsrfToken = '';
    }
    try {
      const session = await apiRequest('/api/session');
      csrfToken = session.csrf_token;
      await refreshDashboard();
    } catch {
      showLanding();
    }
  }

  setInterval(() => {
    if (!state.user || document.hidden) return;
    if (state.user.role !== 'developer') refreshDashboard().catch(() => {});
  }, 15000);

  $('#today-date').textContent = new Intl.DateTimeFormat('en-IN', {
    weekday: 'long', day: 'numeric', month: 'long', year: 'numeric',
  }).format(new Date());
  initialize();
})();