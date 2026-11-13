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
  const platformResetRequestForm = $('#platform-reset-request-form');
  const platformResetConfirmForm = $('#platform-reset-confirm-form');
  const platformPasswordChangeForm = $('#platform-password-change-form');
  const joinForm = $('#join-form');
  const joinModal = $('#join-modal');
  const roomChargesModal = $('#room-charges-modal');
  const platformPasswordChangeModal = $('#platform-password-change-modal');
  const roomSelect = $('#room-select');
  const bedSelect = $('#bed-select');
  const joiningDate = $('#checkin-input');
  const paymentDate = $('#payment-date');
  const state = { user: null, summary: null, rooms: [], residents: [], activity: [], bookings: null, newBookingIds: new Set(), platform: null, roomTypeCharges: [], roomChargeExtraShareCounts: {}, registrations: null, whatsappBroadcastStatus: null };
  let csrfToken = '';
  let platformCsrfToken = '';
  let selectedPlatformHostelId = '';
  let layoutEditHostelId = '';
  let platformSetupDraft = { hostelId: '', step: 1, rooms: [] };
  let toastTimer;

  const bedIcon = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M3 18v-8M3 15h18v5M7 15v-5a3 3 0 0 1 3-3h7a4 4 0 0 1 4 4v4M3 20v-2m18 2v-2" stroke-linecap="round" stroke-linejoin="round"/></svg>';

  function escapeHTML(value) {
    return String(value ?? '').replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
  }

  async function apiRequest(path, options = {}, csrfRetried = false) {
    const method = (options.method || 'GET').toUpperCase();
    const headers = new Headers(options.headers || {});
    const isPlatformRequest = path.startsWith('/api/platform/');
    const token = isPlatformRequest ? platformCsrfToken : csrfToken;
    if (!['GET', 'HEAD', 'OPTIONS'].includes(method) && token) headers.set('X-CSRF-Token', token);
    if (options.body && !(options.body instanceof FormData) && !headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json');
    }
    const response = await fetch(path, { ...options, method, headers, credentials: 'same-origin' });
    const payload = response.status === 204 ? null : await response.json().catch(() => null);
    if (!response.ok) {
      if (!csrfRetried && response.status === 403 && payload?.detail === 'Refresh your session before making changes.') {
        const sessionPath = isPlatformRequest ? '/api/platform/session' : '/api/session';
        const sessionResponse = await fetch(sessionPath, { credentials: 'same-origin', cache: 'no-store' });
        const sessionPayload = await sessionResponse.json().catch(() => null);
        if (!sessionResponse.ok) {
          throw new Error(sessionPayload?.detail || 'Your session expired. Sign in again.');
        }
        if (isPlatformRequest) platformCsrfToken = sessionPayload.csrf_token;
        else csrfToken = sessionPayload.csrf_token;
        return apiRequest(path, options, true);
      }
      throw new Error(payload?.detail || 'The request could not be completed.');
    }
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
    $('.login-kicker').textContent = setupRequired ? 'First-time setup' : 'Owner and staff access';
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
    developerLoginForm.hidden = false;
    $('#show-platform-reset').hidden = false;
    $('#platform-reset-view').hidden = true;
    platformResetRequestForm.reset();
    platformResetRequestForm.hidden = false;
    platformResetConfirmForm.reset();
    platformResetConfirmForm.hidden = true;
    $('#developer-login-error').hidden = true;
    $('#developer-username').focus();
  }

  function showPlatformPasswordReset() {
    developerLoginForm.hidden = true;
    $('#show-platform-reset').hidden = true;
    $('#developer-login-error').hidden = true;
    $('#platform-reset-view').hidden = false;
    platformResetRequestForm.reset();
    platformResetRequestForm.hidden = false;
    platformResetConfirmForm.reset();
    platformResetConfirmForm.hidden = true;
    $('#platform-reset-request-error').hidden = true;
    $('#platform-reset-request-message').hidden = true;
    $('#reset-request-username').focus();
  }

  function returnToPlatformSignIn(message = '') {
    $('#platform-reset-view').hidden = true;
    developerLoginForm.hidden = false;
    $('#show-platform-reset').hidden = false;
    $('#developer-login-error').textContent = message;
    $('#developer-login-error').hidden = !message;
    $('#developer-password').value = '';
    $('#developer-username').focus();
  }

  function ownerLayoutNeedsSetup() {
    return state.user?.role === 'admin' && (state.hostels || []).some(hostel =>
      !hostel.floors?.some(floor => floor.rooms?.length));
  }

  function setActiveView(destination) {
    document.querySelectorAll('.page-view').forEach(view => { view.hidden = view.id !== `${destination}-view`; });
    document.querySelectorAll('.nav-button').forEach(button => {
      const active = button.dataset.view === destination;
      button.classList.toggle('active', active);
      if (active) button.setAttribute('aria-current', 'page'); else button.removeAttribute('aria-current');
    });
    const toolsMenu = $('#nav-tools');
    toolsMenu.open = ['qr', 'room-charges'].includes(destination);
    const viewLabels = { whatsapp: 'Announcements', registrations: 'Registration', bookings: 'Visit requests', qr: 'Vacancy QR' };
    $('#crumb-view').textContent = viewLabels[destination] || destination.charAt(0).toUpperCase() + destination.slice(1);
  }

  function showDashboard(user) {
    state.user = user;
    landingScreen.hidden = true;
    developerLoginScreen.hidden = true;
    $('#staff-identity').textContent = `${user.username} · ${user.role}`;
    const layoutLocked = ownerLayoutNeedsSetup();
    document.querySelectorAll('.nav-button').forEach(button => {
      const ownerOnly = button.dataset.view === 'qr' || button.hasAttribute('data-admin-only');
      button.hidden = layoutLocked
        ? button.dataset.view !== 'rooms'
        : ownerOnly && user.role !== 'admin';
    });
    document.querySelectorAll('.open-join, .pending-visits, [data-goto]').forEach(element => {
      element.hidden = layoutLocked;
    });
    $('#nav-tools').hidden = layoutLocked;
    $('#whatsapp-broadcast-section').hidden = user.role !== 'admin';
    $('#registration-admin-section').hidden = user.role !== 'admin';
    $('#registration-applications-section').hidden = user.role !== 'admin';
    $('.side-note').hidden = layoutLocked;
    if (layoutLocked) setActiveView('rooms');
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

  function platformFloorLabel(floor, floors = []) {
    const labels = { basement: 'Basement', ground: 'Ground floor', penthouse: 'Pent house' };
    if (labels[floor.floor_type]) return labels[floor.floor_type];
    const groundFloor = floors.find(item => item.floor_type === 'ground');
    const basementFloor = floors.find(item => item.floor_type === 'basement');
    const referenceFloor = groundFloor || basementFloor;
    const ordinal = referenceFloor ? floor.floor_number - referenceFloor.floor_number : floor.floor_number;
    return floorLabel(ordinal);
  }

  function hostelDetailsMarkup(hostel) {
    const details = [
      hostel.address && `Address: ${hostel.address}`,
      hostel.owner_mobile && `Owner mobile: ${hostel.owner_mobile}`,
      hostel.location && `Location: ${hostel.location}`,
    ].filter(Boolean);
    return details.length ? `<div class="hostel-details">${details.map(escapeHTML).join(' · ')}</div>` : '';
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

    $('#stat-occupied').textContent = String(state.summary.occupied);
    $('#stat-available').textContent = String(state.summary.available);
    $('#stat-pending-count').textContent = String(state.summary.unpaid_count);
    $('#stat-outstanding-text').textContent = `${formatCurrency(state.summary.outstanding_paise)} outstanding`;
  }

  function roomTypeControl(hostel, id = 'room-ac-type') {
    if (hostel.ac_type === 'ac') {
      return `<div class="field room-ac-type-field"><label>Room type</label><div class="room-type-static">AC</div><input type="hidden" name="ac_type" value="ac"></div>`;
    }
    return `<div class="field room-ac-type-field"><label for="${escapeHTML(id)}">Room type</label><select id="${escapeHTML(id)}" name="ac_type" required><option value="" selected disabled>Select AC type</option><option value="ac">AC</option><option value="non_ac">Non-AC</option></select></div>`;
  }

  function renderRoomTile(room, canManage) {
    const deleteButton = canManage
      ? `<div class="room-structure-actions"><button class="delete-room-button" type="button" data-delete-room="${escapeHTML(room.id)}" ${room.occupied || room.reserved ? 'disabled title="Check residents out or cancel the visit before deleting this room."' : ''}>Delete room</button></div>`
      : '';
    const badge = room.reserved
      ? `<span class="room-pill reserved">Reserved by ${escapeHTML(room.reservation_name)} · ${escapeHTML(room.reservation_visit_time)}</span>`
      : `<span class="room-pill">${room.available_beds} open</span>`;
    const monthlyCharge = room.monthly_rent_paise > 0 ? ` · ${formatCurrency(room.monthly_rent_paise)}/month` : '';
    const roomType = room.ac_type === 'ac' ? 'AC' : 'Non-AC';
    return `<article class="room-structure-tile ${room.reserved ? 'reserved' : ''}"><div class="room-tile-top"><div><div class="room-id">Room ${escapeHTML(room.room_number)}</div><div class="room-type">${room.share_count}-share · ${roomType} · ${room.occupied}/${room.share_count} occupied${monthlyCharge}</div></div>${badge}</div><div class="beds" aria-label="${room.occupied} occupied, ${room.available_beds} available">${renderBeds(room)}</div>${deleteButton}</article>`;
  }

  function roomTypeChargeRowMarkup(hostel, hostelRooms, rateTypes, shareCount) {
    const placeholders = { 2: '10000', 3: '8500', 4: '7500' };
    const rates = rateTypes.map(([acType, label]) => {
      const savedCharge = state.roomTypeCharges.find(charge => charge.hostel_id === hostel.id && charge.share_count === shareCount && (charge.ac_type || 'non_ac') === acType);
      const roomRates = hostelRooms.filter(room => room.share_count === shareCount && (room.ac_type || 'non_ac') === acType).map(room => room.monthly_rent_paise);
      const uniqueRates = [...new Set(roomRates)];
      const inheritedRate = uniqueRates.length === 1 && uniqueRates[0] > 0 ? uniqueRates[0] : null;
      const value = savedCharge
        ? (savedCharge.monthly_rent_paise / 100).toFixed(2)
        : inheritedRate === null ? '' : (inheritedRate / 100).toFixed(2);
      const name = `monthly_rent_${shareCount}_${acType}`;
      return `<div class="room-charge-field"><label for="room-charge-${escapeHTML(hostel.id)}-${shareCount}-${acType}">${label} · INR/month</label><input id="room-charge-${escapeHTML(hostel.id)}-${shareCount}-${acType}" name="${name}" data-share-count="${shareCount}" data-ac-type="${acType}" type="number" min="0" max="1000000" step="0.01" value="${value}" placeholder="${placeholders[shareCount] || 'Enter amount'}"></div>`;
    }).join('');
    return `<div class="room-charge-row" data-share-count="${shareCount}"><strong>${shareCount} sharing</strong><div class="room-charge-variants">${rates}</div></div>`;
  }

  function renderRoomTypeCharges() {
    const container = $('#room-charges-list');
    if (!container) return;
    container.innerHTML = state.hostels.length
      ? state.hostels.map(hostel => {
        const hostelRooms = hostel.floors.flatMap(floor => floor.rooms);
        const rateTypes = hostel.ac_type === 'ac' ? [['ac', 'AC']] : [['ac', 'AC'], ['non_ac', 'Non-AC']];
        const visibleShareCounts = [...new Set([
          ...Array.from({ length: 6 }, (_, index) => index + 1),
          ...(state.roomChargeExtraShareCounts[hostel.id] || []),
        ])].filter(shareCount => Number.isInteger(shareCount) && shareCount >= 1 && shareCount <= 20).sort((a, b) => a - b);
        const availableShareCounts = Array.from({ length: 14 }, (_, index) => index + 7)
          .filter(shareCount => !visibleShareCounts.includes(shareCount));
        const fields = visibleShareCounts
          .map(shareCount => roomTypeChargeRowMarkup(hostel, hostelRooms, rateTypes, shareCount))
          .join('');
        const addControl = availableShareCounts.length
          ? `<div class="room-charge-add-controls"><label for="room-charge-add-${escapeHTML(hostel.id)}">Add sharing type</label><select id="room-charge-add-${escapeHTML(hostel.id)}" data-room-charge-share-selection><option value="">Choose capacity</option>${availableShareCounts.map(shareCount => `<option value="${shareCount}">${shareCount} sharing</option>`).join('')}</select><button class="room-charge-add" type="button" data-add-room-charge-sharing data-hostel-id="${escapeHTML(hostel.id)}" disabled>Add</button></div>`
          : '';
        return `<form class="room-charge-form" data-room-charges-form data-hostel-id="${escapeHTML(hostel.id)}"><div class="room-charge-form-head"><div><h3 class="room-charge-form-title">${escapeHTML(hostel.name)}</h3><div class="section-subtitle">Updates matching rooms and prices for future bookings.</div></div><button class="primary-button" type="submit">Save prices</button></div><div class="room-charge-fields">${fields}</div>${addControl}</form>`;
      }).join('')
      : '<div class="table-empty">Register a hostel client before setting room charges.</div>';
  }

  function renderHostelStructure() {
    const canManage = state.user?.role === 'admin';
    $('#room-layout-description').textContent = canManage
      ? layoutEditHostelId
        ? 'Edit mode is on. Add or remove floors and rooms, then choose Done editing.'
        : 'Choose Edit layout to add or remove floors and rooms.'
      : 'The structure is read-only here. Add or move residents with check-in and check-out actions.';
    $('#hostel-create-wrap').hidden = true;
    const ownerDraftHostel = canManage
      ? state.hostels.find(hostel => hostel.id === platformSetupDraft.hostelId && platformSetupDraft.ownerMode)
      : null;
    if (ownerDraftHostel && platformSetupDraft.step >= 1 && platformSetupDraft.step <= 4) {
      renderPlatformSetupWizard(ownerDraftHostel, true);
      return;
    }
    const setupHostel = canManage
      ? state.hostels.find(hostel => !hostel.floors?.some(floor => floor.rooms?.length))
      : null;
    if (setupHostel && (platformSetupDraft.hostelId !== setupHostel.id || !platformSetupDraft.ownerMode || platformSetupDraft.step < 1 || platformSetupDraft.step > 4)) {
      platformSetupDraft = { hostelId: setupHostel.id, step: 1, rooms: [], ownerMode: true };
      renderPlatformSetupWizard(setupHostel, true);
      return;
    }
    $('#hostel-structure').innerHTML = state.hostels.length
      ? state.hostels.map(hostel => {
        const hostelRooms = hostel.floors.reduce((total, floor) => total + floor.rooms.length, 0);
        const editingLayout = canManage && layoutEditHostelId === hostel.id;
        const editLayoutButton = canManage
          ? `<button class="secondary-button" type="button" data-toggle-layout-edit="${escapeHTML(hostel.id)}">${editingLayout ? 'Done editing' : 'Edit layout'}</button>`
          : '';
        const floorMarkup = hostel.floors.length
          ? hostel.floors.map(floor => {
            const roomsMarkup = floor.rooms.length
              ? `<div class="room-structure-grid">${floor.rooms.map(room => renderRoomTile(room, editingLayout)).join('')}</div>`
              : '<div class="floor-empty">No rooms on this floor yet.</div>';
            const addRoomForm = editingLayout
              ? `<form class="structure-form" data-room-form data-floor-id="${escapeHTML(floor.id)}"><div class="field room-number-field"><label>Room number</label><input name="room_number" required maxlength="20" placeholder="e.g. 105"></div><div class="field share-field"><label>Sharing capacity</label><input name="share_count" type="number" min="1" max="20" value="4" required></div>${roomTypeControl(hostel, `owner-room-type-${floor.id}`)}<button class="primary-button" type="submit">Add room</button></form>`
              : '';
            const deleteFloor = editingLayout
              ? `<button class="delete-room-button" type="button" data-owner-delete-floor="${escapeHTML(floor.id)}">Delete floor</button>`
              : '';
            return `<section class="floor-group"><div class="floor-head"><div><h3 class="floor-title">${escapeHTML(platformFloorLabel(floor, hostel.floors))}</h3><div class="section-subtitle">${floor.rooms.length} room${floor.rooms.length === 1 ? '' : 's'}</div></div>${deleteFloor}</div>${roomsMarkup}${addRoomForm}</section>`;
          }).join('')
          : `<div class="layout-empty-state">${canManage ? '<button class="primary-button" type="button" data-owner-start-layout>Set up floors and rooms</button>' : '<div>No floors configured yet.</div>'}</div>`;
        const addFloorForm = editingLayout && hostel.floors.length < 99
          ? `<form class="structure-form" data-floor-form data-hostel-id="${escapeHTML(hostel.id)}"><div class="field"><label>Floor number</label><input name="floor_number" type="number" min="1" max="99" required placeholder="e.g. 1"></div><div class="field"><label>Floor type</label><select name="floor_type"><option value="standard">Standard floor</option><option value="basement">Basement</option><option value="ground">Ground floor</option><option value="penthouse">Pent house</option></select></div><button class="primary-button" type="submit">Add floor</button></form>`
          : '';
        const deleteHostelButton = '';
        return `<article class="hostel-card"><header class="hostel-card-head"><div><h2 class="hostel-card-title">${escapeHTML(hostel.name)}</h2><div class="hostel-card-meta">${hostel.floors.length} floor${hostel.floors.length === 1 ? '' : 's'} · ${hostelRooms} room${hostelRooms === 1 ? '' : 's'} · ${hostel.ac_type === 'ac' ? 'AC' : 'AC + Non AC'}</div>${hostelDetailsMarkup(hostel)}</div><div class="hostel-head-actions">${editLayoutButton}${deleteHostelButton}${addFloorForm}</div></header>${floorMarkup}</article>`;
      }).join('')
      : '<div class="table-empty">No hostels configured yet. Add your first hostel to set up floors and rooms.</div>';
  }

  function residentDocuments(resident) {
    if (!resident.documents.length) return 'No photos';
    return resident.documents.map(document => {
      const label = document.kind === 'person_photo' ? 'Person photo' : 'Aadhaar photo';
      return `<a class="document-link" href="${escapeHTML(document.preview_url)}" target="_blank" rel="noopener">View ${label}</a> · <a class="document-link" href="${escapeHTML(document.url)}" download>Download</a>`;
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
    return `<div class="table-scroll"><table><thead><tr><th>Resident</th><th>Hostel / Floor / Room</th><th>Joining date</th><th>Next payment date</th><th>Payment</th><th>Documents</th><th>WhatsApp</th><th>Actions</th></tr></thead><tbody>${filtered.map(resident => `<tr><td><div class="resident-name">${escapeHTML(resident.name)}</div><div class="resident-contact">${escapeHTML(resident.mobile)}${resident.aadhaar_last4 ? ` · Aadhaar ending ${escapeHTML(resident.aadhaar_last4)}` : ''}</div></td><td><span class="room-pill">${escapeHTML(resident.room)} · Bed ${resident.bed_number}</span><div class="resident-contact">${escapeHTML(resident.hostel_name)} · ${floorLabel(resident.floor_number)}</div></td><td>${escapeHTML(formatDate(resident.joining_date))}</td><td>${escapeHTML(formatDate(resident.payment_due_date))}</td><td>${resident.payment_status === 'unpaid' ? `<span class="payment-unpaid">${escapeHTML(formatCurrency(resident.amount_due_paise))} due</span>` : '<span class="payment-paid">Paid</span>'}</td><td>${residentDocuments(resident)}</td><td><span class="resident-contact">${resident.whatsapp_opt_in ? 'Opted in' : 'Not opted in'}</span><button class="consent-toggle" type="button" data-whatsapp-consent="${escapeHTML(resident.id)}">${resident.whatsapp_opt_in ? 'Opt out' : 'Record opt-in'}</button></td><td><div class="payment-actions">${resident.payment_status === 'unpaid' ? `<button class="whatsapp-button" type="button" data-whatsapp="${escapeHTML(resident.id)}">Send reminder</button><button class="mark-paid-button" type="button" data-mark-paid="${escapeHTML(resident.id)}">Mark paid</button>` : ''}<button class="exit-button" type="button" data-checkout="${escapeHTML(resident.id)}">Check out</button></div></td></tr>`).join('')}</tbody></table></div>`;
  }

  function renderResidents() {
    const countText = `${state.residents.length} active resident${state.residents.length === 1 ? '' : 's'}`;
    $('#resident-count').textContent = state.residents.length ? countText : 'No active residents';
    $('#resident-count-all').textContent = state.residents.length ? countText : 'No active residents';
    $('#resident-table').innerHTML = residentRows($('#resident-search').value);
    $('#resident-table-all').innerHTML = residentRows($('#resident-search-all').value);
  }

  function renderWhatsAppBroadcast() {
    const hostelSelect = $('#whatsapp-broadcast-hostel');
    const previousHostel = hostelSelect.value;
    hostelSelect.innerHTML = state.hostels.length
      ? state.hostels.map(hostel => `<option value="${escapeHTML(hostel.id)}">${escapeHTML(hostel.name)}</option>`).join('')
      : '<option value="">No active hostels</option>';
    if (state.hostels.some(hostel => hostel.id === previousHostel)) hostelSelect.value = previousHostel;

    const eligibleCount = state.residents.filter(resident =>
      resident.hostel_id === hostelSelect.value && resident.whatsapp_opt_in).length;
    $('#whatsapp-broadcast-count').textContent = `${eligibleCount} opted-in guest${eligibleCount === 1 ? '' : 's'}`;
    $('#whatsapp-broadcast-status').textContent = state.whatsappBroadcastStatus?.reason
      || 'Could not verify WhatsApp broadcast setup.';
    $('#send-whatsapp-broadcast').disabled = !state.whatsappBroadcastStatus?.ready
      || !hostelSelect.value
      || eligibleCount === 0
      || !$('#whatsapp-broadcast-message').value.trim();
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
    $('#pending-visits-label').textContent = `Visit requests (${bookings.length})`;
    $('#booking-count').textContent = bookings.length
      ? `${bookings.length} visit${bookings.length === 1 ? '' : 's'} awaiting confirmation`
      : 'No pending visits';
    $('#booking-list').innerHTML = bookings.length
      ? bookings.map(booking => `<article class="booking-card ${state.newBookingIds.has(booking.id) ? 'booking-card-new' : ''}"><div><div class="booking-name">${escapeHTML(booking.student_name)}</div><div class="booking-meta">${escapeHTML(booking.phone)} · ${escapeHTML(booking.hostel_name)} · ${floorLabel(booking.floor_number)}<br>Room ${escapeHTML(booking.room_number)} · ${booking.sharing_needed || 'Any'} sharing · Visit ${escapeHTML(booking.visit_time)}${booking.monthly_rent_paise ? ` · ${escapeHTML(formatCurrency(booking.monthly_rent_paise))}/month` : ''}</div></div><div class="booking-actions"><button class="booking-confirm" type="button" data-confirm-booking="${escapeHTML(booking.id)}">Confirm</button><button class="booking-cancel" type="button" data-cancel-booking="${escapeHTML(booking.id)}">Cancel</button></div></article>`).join('')
      : '<div class="table-empty">No pending visits.</div>';
  }

  function renderRegistrationWorkspace() {
    const workspace = state.registrations;
    const hostelSelect = $('#registration-hostel-select');
    const previousHostel = hostelSelect.value;
    hostelSelect.innerHTML = state.hostels.length
      ? state.hostels.map(hostel => `<option value="${escapeHTML(hostel.id)}">${escapeHTML(hostel.name)}</option>`).join('')
      : '<option value="">No active hostels</option>';
    if (state.hostels.some(hostel => hostel.id === previousHostel)) hostelSelect.value = previousHostel;
    $('#create-registration-invite').disabled = !state.hostels.length;
    if (!workspace) return;

    const now = Date.now();
    $('#registration-invite-list').innerHTML = workspace.invites.length
      ? workspace.invites.map(invite => {
        const active = !invite.used_at && !invite.revoked_at && Date.parse(invite.expires_at) > now;
        const status = invite.revoked_at ? 'Revoked' : invite.used_at ? 'Application submitted' : active ? 'Active' : 'Expired';
        return `<article class="registration-card"><div class="registration-card-head"><div><h3 class="registration-card-title">${escapeHTML(invite.hostel_name)}</h3><div class="registration-card-meta">Expires ${escapeHTML(formatDate(invite.expires_at.slice(0, 10)))} · ${status}</div></div>${active ? `<button class="booking-cancel" type="button" data-revoke-registration-invite="${escapeHTML(invite.id)}">Revoke</button>` : ''}</div></article>`;
      }).join('')
      : '<div class="table-empty">No registration links created yet.</div>';

    const pending = workspace.applications;
    const nowDate = new Date();
    const today = new Date(nowDate.getTime() - nowDate.getTimezoneOffset() * 60000).toISOString().slice(0, 10);
    $('#registration-application-count').textContent = pending.length
      ? `${pending.length} application${pending.length === 1 ? '' : 's'} awaiting approval`
      : 'No applications awaiting approval';
    $('#registration-application-list').innerHTML = pending.length
      ? pending.map(application => {
        const availableRooms = state.rooms.filter(room => room.hostel_id === application.hostel_id && room.available_beds > 0 && !room.reserved);
        const documents = application.documents.length
          ? application.documents.filter(document => document.kind !== 'person_photo').map(document => `<a class="document-link" href="${escapeHTML(document.url)}" target="_blank" rel="noopener">Download Aadhaar photo</a>`).join(' · ')
          : 'No photos provided';
        const personPhoto = application.documents.find(document => document.kind === 'person_photo');
        const photoPreview = personPhoto
          ? `<a class="registration-photo-preview" href="${escapeHTML(personPhoto.preview_url)}" target="_blank" rel="noopener"><img src="${escapeHTML(personPhoto.preview_url)}" alt="Person photo uploaded by ${escapeHTML(application.name)}" loading="lazy"><span>Open full photo</span></a>`
          : '';
        const roomOptions = availableRooms.map(room => `<option value="${escapeHTML(room.id)}">${escapeHTML(room.hostel_name)} · Room ${escapeHTML(room.room_number)} · ${room.available_beds} bed${room.available_beds === 1 ? '' : 's'} available</option>`).join('');
        const firstRoom = availableRooms[0];
        const availableBeds = firstRoom ? firstRoom.beds.filter(bed => !bed.occupied && !bed.reserved) : [];
        const submitted = formatDate(application.submitted_at.slice(0, 10));
        const approveForm = availableRooms.length
          ? `<form data-registration-approval="${escapeHTML(application.id)}"><div class="registration-approval-grid"><div class="field"><label>Room</label><select name="room_id" data-registration-room required>${roomOptions}</select></div><div class="field"><label>Bed</label><select name="bed_number" data-registration-bed required>${availableBeds.map(bed => `<option value="${bed.number}">Bed ${bed.number}</option>`).join('')}</select></div><div class="field"><label>Joining date</label><input name="joining_date" type="date" value="${today}" required></div><div class="field"><label>Payment status</label><select name="payment_status" data-registration-payment required><option value="" selected disabled>Choose</option><option value="paid">Paid</option><option value="unpaid">Unpaid</option></select></div><div class="field" data-registration-amount-field hidden><label>Balance due (INR)</label><input name="amount_due" type="number" min="0.01" max="1000000" step="0.01"></div></div><div class="registration-actions"><button class="primary-button" type="submit">Approve and check in</button></div></form>`
          : '<div class="registration-status">Add an available bed in this hostel before approving and assigning a room.</div>';
        return `<article class="registration-card"><div class="registration-card-head"><div><h3 class="registration-card-title">${escapeHTML(application.name)}</h3><div class="registration-card-meta">${escapeHTML(application.mobile)}${application.aadhaar_last4 ? ` · Aadhaar ending ${escapeHTML(application.aadhaar_last4)}` : ''}<br>${escapeHTML(application.hostel_name)} · Submitted ${escapeHTML(submitted)} · WhatsApp updates ${application.whatsapp_opt_in ? 'opted in' : 'not opted in'}<br>${documents}</div></div>${photoPreview}</div>${approveForm}</article>`;
      }).join('')
      : '<div class="table-empty">No pending applications.</div>';
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
    if (platformSetupDraft.hostelId !== hostel.id && !hostel.floors.length) {
      platformSetupDraft = { hostelId: hostel.id, step: 1, rooms: [] };
    }
    if (platformSetupDraft.hostelId === hostel.id && platformSetupDraft.step >= 1 && platformSetupDraft.step <= 4) {
      renderPlatformSetupWizard(hostel);
      return;
    }
    const floorMarkup = hostel.floors.length
      ? hostel.floors.map(floor => {
        const rooms = floor.rooms.length
          ? `<div class="room-structure-grid">${floor.rooms.map(room => `<article class="room-structure-tile"><div class="room-tile-top"><div><div class="room-id">Room ${escapeHTML(room.room_number)}</div><div class="room-type">${room.share_count}-bed room${room.monthly_rent_paise ? ` · ${escapeHTML(formatCurrency(room.monthly_rent_paise))}/month` : ''}</div></div><span class="room-pill">${room.share_count} beds</span></div><div class="room-structure-actions"><button class="delete-room-button" type="button" data-platform-delete-room="${escapeHTML(room.id)}">Delete room</button></div></article>`).join('')}</div>`
          : '<div class="floor-empty">No rooms on this floor yet.</div>';
        return `<section class="floor-group"><div class="floor-head"><div><h3 class="floor-title">${escapeHTML(platformFloorLabel(floor, hostel.floors))}</h3><div class="section-subtitle">${floor.rooms.length} room${floor.rooms.length === 1 ? '' : 's'}</div></div><button class="delete-room-button" type="button" data-platform-delete-floor="${escapeHTML(floor.id)}">Delete floor</button></div>${rooms}<form class="structure-form" data-platform-room-form data-floor-id="${escapeHTML(floor.id)}"><div class="field room-number-field"><label>Room number</label><input name="room_number" required maxlength="20" placeholder="e.g. 105"></div><div class="field share-field"><label>Beds per room</label><select name="share_count" required><option value="1">1 bed</option><option value="2">2 beds</option><option value="3">3 beds</option><option value="4" selected>4 beds</option></select></div>${roomTypeControl(hostel, `platform-room-type-${floor.id}`)}<button class="primary-button" type="submit">Add room</button></form></section>`;
      }).join('')
      : '<div class="floor-group floor-empty">No floors yet. Add the first floor to define this hostel layout.</div>';
    const addFloor = hostel.floors.length < 99
      ? `<form class="structure-form" data-platform-floor-form data-hostel-id="${escapeHTML(hostel.id)}"><div class="field"><label>Floor number</label><input name="floor_number" type="number" min="1" max="99" required placeholder="e.g. 1"></div><button class="primary-button" type="submit">Add floor</button></form>`
      : '';
    $('#platform-hostel-structure').innerHTML = `<article class="hostel-card"><header class="hostel-card-head"><div><h2 class="hostel-card-title">Hostel setup</h2><div class="hostel-card-meta">${hostel.floors.length} floor${hostel.floors.length === 1 ? '' : 's'} · ${hostel.floors.reduce((total, floor) => total + floor.rooms.length, 0)} rooms · ${hostel.ac_type === 'ac' ? 'AC' : 'AC + Non AC'}</div>${hostelDetailsMarkup(hostel)}</div></header>${floorMarkup}<section class="floor-group">${addFloor}</section></article>`;
  }

  function renderPlatformSetupWizard(hostel, ownerMode = false) {
    const steps = ['Add floor', 'Add room', 'Add sharing', 'Review rates'];
    const sharingCounts = Array.from({ length: ownerMode ? 20 : 4 }, (_, index) => index + 1);
    const stepNavigation = `<ol class="layout-wizard-steps" aria-label="Hostel setup progress">${steps.map((label, index) => `<li class="layout-wizard-step ${platformSetupDraft.step === index + 1 ? 'active' : platformSetupDraft.step > index + 1 ? 'complete' : ''}" ${platformSetupDraft.step === index + 1 ? 'aria-current="step"' : ''}><span>${index + 1}</span>${label}</li>`).join('')}</ol>`;
    const floorOptions = [
      ['basement', 'Basement'],
      ['ground', 'Ground floor'],
      ['penthouse', 'Pent house'],
    ];
    let stepContent = '';

    if (platformSetupDraft.step === 1) {
      stepContent = `<form class="layout-wizard-form" ${ownerMode ? 'data-owner-setup-form' : 'data-platform-setup-form'}><fieldset class="layout-choice-group"><legend>Select the type of floors in your building</legend><div class="floor-type-grid">${floorOptions.map(([value, label]) => `<label class="floor-choice"><input type="checkbox" name="floor_types" value="${value}" ${value === 'ground' ? 'checked' : ''}><span>${label}</span></label>`).join('')}</div></fieldset><div class="layout-step-fields"><div class="field"><label for="layout-floor-count">Floors above Ground floor</label><div class="floor-count-stepper"><button type="button" data-floor-count-change="-1" aria-label="Decrease upper floor count">-</button><input id="layout-floor-count" name="upper_floor_count" type="number" min="0" max="99" value="0" required><button type="button" data-floor-count-change="1" aria-label="Increase upper floor count">+</button></div></div><fieldset class="layout-choice-group"><legend>Select the available AC type</legend><div class="ac-choice-grid"><label class="ac-choice"><input type="radio" name="ac_type" value="ac"><span>AC</span></label><label class="ac-choice"><input type="radio" name="ac_type" value="mixed" checked><span>AC + Non AC</span></label></div></fieldset></div><div class="layout-wizard-actions"><button class="secondary-button" type="button" data-layout-wizard-back>Back</button><button class="primary-button" type="submit">Next</button></div></form>`;
    } else if (platformSetupDraft.step === 2) {
      const queuedRooms = platformSetupDraft.rooms.length
        ? `<ul class="room-draft-list">${platformSetupDraft.rooms.map((room, index) => {
          const floor = hostel.floors.find(item => item.id === room.floorId);
          return `<li><span>Room ${escapeHTML(room.roomNumber)} · ${escapeHTML(floor ? platformFloorLabel(floor, hostel.floors) : '')} · ${room.acType === 'ac' ? 'AC' : 'Non-AC'}</span><button type="button" data-remove-room-draft="${index}" aria-label="Remove room ${escapeHTML(room.roomNumber)}">Remove</button></li>`;
        }).join('')}</ul>`
        : '<div class="floor-empty">No rooms added yet.</div>';
      stepContent = `<form class="layout-wizard-form" ${ownerMode ? 'data-owner-room-draft-form' : 'data-platform-room-draft-form'}><div class="layout-step-fields"><div class="field"><label for="layout-room-floor">Floor</label><select id="layout-room-floor" name="floor_id" required>${hostel.floors.map(floor => `<option value="${escapeHTML(floor.id)}">${escapeHTML(platformFloorLabel(floor, hostel.floors))}</option>`).join('')}</select></div><div class="field"><label for="layout-room-number">Room number</label><input id="layout-room-number" name="room_number" required maxlength="20" placeholder="e.g. 105"></div>${roomTypeControl(hostel, 'layout-room-ac-type')}</div><button class="secondary-button" type="submit">Add room</button></form><div class="room-draft-wrap"><div class="section-subtitle">Rooms to configure (${platformSetupDraft.rooms.length})</div>${queuedRooms}</div><div class="layout-wizard-actions"><button class="secondary-button" type="button" data-layout-wizard-back>Back</button><button class="primary-button" type="button" data-layout-wizard-next ${platformSetupDraft.rooms.length ? '' : 'disabled'}>Next</button></div>`;
    } else if (platformSetupDraft.step === 3) {
      const sharingFields = platformSetupDraft.rooms.map((room, index) => {
        const floor = hostel.floors.find(item => item.id === room.floorId);
        return `<div class="field"><label for="layout-share-${index}">Room ${escapeHTML(room.roomNumber)} · ${escapeHTML(floor ? platformFloorLabel(floor, hostel.floors) : '')}</label><select class="platform-layout-select" id="layout-share-${index}" name="share_${index}" required><option value="" disabled ${room.shareCount ? '' : 'selected'}>Sharing Types</option>${sharingCounts.map(count => `<option value="${count}" ${room.shareCount === count ? 'selected' : ''}>${count} sharing</option>`).join('')}</select></div>`;
      }).join('');
      stepContent = `<form class="layout-wizard-form" ${ownerMode ? 'data-owner-sharing-form' : 'data-platform-sharing-form'}><div class="room-draft-list">${sharingFields}</div><div class="layout-wizard-actions"><button class="secondary-button" type="button" data-layout-wizard-back>Back</button><button class="primary-button" type="submit">Next</button></div></form>`;
    } else {
      const rentFields = platformSetupDraft.rooms.map(room => {
        const floor = hostel.floors.find(item => item.id === room.floorId);
        const charge = state.roomTypeCharges.find(item => item.hostel_id === hostel.id && item.share_count === room.shareCount && (item.ac_type || 'non_ac') === room.acType);
        const rate = charge ? formatCurrency(charge.monthly_rent_paise) : 'Not configured';
        return `<div class="room-rate-review"><strong>Room ${escapeHTML(room.roomNumber)}</strong><span>${room.shareCount}-sharing · ${room.acType === 'ac' ? 'AC' : 'Non-AC'} · ${escapeHTML(floor ? platformFloorLabel(floor, hostel.floors) : '')}</span><b>${rate}${charge ? '/month' : ''}</b></div>`;
      }).join('');
      stepContent = `<form class="layout-wizard-form" ${ownerMode ? 'data-owner-rent-form' : 'data-platform-rent-form'}><p class="section-subtitle">Rent comes from Room type charges. Rooms without a saved rate will be added at ₹0 until you configure one.</p><div class="room-rate-review-list">${rentFields}</div><div class="layout-wizard-actions"><button class="secondary-button" type="button" data-layout-wizard-back>Back</button><button class="primary-button" type="submit">Create rooms</button></div></form>`;
    }

    const target = ownerMode ? '#hostel-structure' : '#platform-hostel-structure';
    $(target).innerHTML = `<article class="hostel-card"><header class="hostel-card-head"><div><h2 class="hostel-card-title">Hostel setup</h2><div class="hostel-card-meta">${escapeHTML(hostel.name)}</div>${hostelDetailsMarkup(hostel)}</div></header><div class="layout-wizard">${stepNavigation}<section class="layout-wizard-panel"><h3>${steps[platformSetupDraft.step - 1]}</h3>${stepContent}</section></div></article>`;
  }

  function renderPlatformDashboard() {
    const { summary, clients, hostels } = state.platform;
    $('#platform-clients-count').textContent = String(summary.total_clients);
    $('#platform-subscription-received').textContent = formatCurrency(summary.subscription_received_paise);
    $('#platform-subscription-received-count').textContent = `${summary.subscription_received_count} received`;
    $('#platform-subscription-pending').textContent = formatCurrency(summary.subscription_pending_paise);
    $('#platform-subscription-pending-count').textContent = `${summary.subscription_pending_count} pending`;
    $('#platform-client-count').textContent = `${summary.total_clients} registered client${summary.total_clients === 1 ? '' : 's'} · ${clients.length} active hostel${clients.length === 1 ? '' : 's'}`;
    document.querySelectorAll('[data-platform-step="dashboard"]').forEach(button => {
      button.disabled = clients.length === 0;
    });
    $('#platform-client-list').innerHTML = clients.length
      ? `<table><thead><tr><th>Client</th><th>Hostel</th><th>Owner mobile</th><th>Location</th></tr></thead><tbody>${clients.map(client => `<tr><td class="resident-name" data-label="Client">${escapeHTML(client.owner_username)}</td><td data-label="Hostel">${escapeHTML(client.hostel_name)}</td><td data-label="Mobile">${escapeHTML(client.owner_mobile || '—')}</td><td data-label="Location">${escapeHTML(client.location || '—')}</td></tr>`).join('')}</tbody></table>`
      : '<div class="table-empty">No clients registered yet.</div>';
    $('#subscription-count').textContent = `${state.platform.subscriptions.length} subscription payment${state.platform.subscriptions.length === 1 ? '' : 's'}`;
    $('#platform-subscription-list').innerHTML = state.platform.subscriptions.length
      ? `<table><thead><tr><th>Client</th><th>Period</th><th>Amount</th><th>Due</th><th>Status</th><th></th></tr></thead><tbody>${state.platform.subscriptions.map(subscription => `<tr><td class="resident-name" data-label="Client">${escapeHTML(subscription.owner_username)}</td><td data-label="Period">${escapeHTML(subscription.billing_period)}</td><td data-label="Amount">${escapeHTML(formatCurrency(subscription.amount_paise))}</td><td data-label="Due">${escapeHTML(formatDate(subscription.due_date))}</td><td data-label="Status"><span class="${subscription.status === 'received' ? 'payment-paid' : 'payment-unpaid'}">${subscription.status === 'received' ? 'Received' : 'Pending'}</span></td><td data-label="Action">${subscription.status === 'pending' ? `<button class="mark-paid-button" type="button" data-subscription-received="${escapeHTML(subscription.id)}">Mark received</button>` : ''}</td></tr>`).join('')}</tbody></table>`
      : '<div class="table-empty">No subscription payments recorded yet.</div>';
    const ownerSelect = $('#subscription-owner');
    const previousOwner = ownerSelect.value;
    ownerSelect.innerHTML = state.platform.owners.length
      ? state.platform.owners.map(owner => `<option value="${escapeHTML(owner.owner_id)}">${escapeHTML(owner.owner_username)}</option>`).join('')
      : '<option value="">No active clients</option>';
    if (state.platform.owners.some(owner => owner.owner_id === previousOwner)) ownerSelect.value = previousOwner;
    $('#platform-subscription-form').querySelector('button[type="submit"]').disabled = !state.platform.owners.length;
    if (selectedPlatformHostelId && !hostels.some(hostel => hostel.id === selectedPlatformHostelId)) selectedPlatformHostelId = '';
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
    const [registrations, whatsappBroadcastStatus] = dashboard.user.role === 'admin'
      ? await Promise.all([
        apiRequest('/api/registration-workspace'),
        apiRequest('/api/whatsapp/broadcast-status'),
      ])
      : [null, null];
    state.summary = dashboard.summary;
    state.hostels = dashboard.hostels;
    state.roomTypeCharges = dashboard.room_type_charges || [];
    state.rooms = dashboard.rooms;
    state.residents = dashboard.residents;
    state.activity = dashboard.activity;
    const priorBookingIds = new Set((state.bookings || []).map(booking => booking.id));
    state.newBookingIds = new Set(bookings.filter(booking => !priorBookingIds.has(booking.id)).map(booking => booking.id));
    state.bookings = bookings;
    state.registrations = registrations;
    state.whatsappBroadcastStatus = whatsappBroadcastStatus;
    showDashboard(dashboard.user);
    renderRooms();
    renderResidents();
    renderWhatsAppBroadcast();
    renderActivity();
    renderBookings();
    renderRegistrationWorkspace();
    renderQrHostels();
  }

  function renderLayoutDraft() {
    if (platformSetupDraft.ownerMode) renderHostelStructure();
    else renderPlatformLayout(platformSetupDraft.hostelId);
  }

  async function refreshLayoutDashboard() {
    if (platformSetupDraft.ownerMode) await refreshDashboard();
    else await refreshPlatformDashboard();
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

  function openPlatformPasswordChangeModal() {
    platformPasswordChangeForm.reset();
    $('#platform-password-change-error').hidden = true;
    platformPasswordChangeModal.hidden = false;
    $('#platform-current-password').focus();
  }

  function closePlatformPasswordChangeModal() {
    platformPasswordChangeModal.hidden = true;
    platformPasswordChangeForm.reset();
    $('#platform-password-change-error').hidden = true;
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

  platformResetRequestForm.addEventListener('submit', async event => {
    event.preventDefault();
    const submit = platformResetRequestForm.querySelector('button[type="submit"]');
    const username = $('#reset-request-username').value.trim();
    $('#platform-reset-request-error').hidden = true;
    submit.disabled = true;
    try {
      const result = await apiRequest('/api/platform/password/forgot', {
        method: 'POST',
        body: JSON.stringify({ username }),
      });
      $('#reset-confirm-username').value = username;
      $('#platform-reset-request-message').textContent = result.message;
      $('#platform-reset-request-message').hidden = false;
      platformResetRequestForm.hidden = true;
      platformResetConfirmForm.hidden = false;
      $('#platform-reset-code').focus();
    } catch (error) {
      $('#platform-reset-request-error').textContent = error.message;
      $('#platform-reset-request-error').hidden = false;
    } finally {
      submit.disabled = false;
    }
  });

  platformResetConfirmForm.addEventListener('submit', async event => {
    event.preventDefault();
    const submit = platformResetConfirmForm.querySelector('button[type="submit"]');
    const password = $('#platform-reset-password').value;
    $('#platform-reset-confirm-error').hidden = true;
    if (password !== $('#platform-reset-confirm-password').value) {
      $('#platform-reset-confirm-error').textContent = 'The passwords do not match.';
      $('#platform-reset-confirm-error').hidden = false;
      return;
    }
    submit.disabled = true;
    try {
      await apiRequest('/api/platform/password/reset', {
        method: 'POST',
        body: JSON.stringify({
          username: $('#reset-confirm-username').value,
          code: $('#platform-reset-code').value,
          password,
        }),
      });
      const username = $('#reset-confirm-username').value;
      returnToPlatformSignIn('Password reset. Sign in with your new password.');
      $('#developer-username').value = username;
    } catch (error) {
      $('#platform-reset-confirm-error').textContent = error.message;
      $('#platform-reset-confirm-error').hidden = false;
    } finally {
      submit.disabled = false;
    }
  });

  platformPasswordChangeForm.addEventListener('submit', async event => {
    event.preventDefault();
    const submit = platformPasswordChangeForm.querySelector('button[type="submit"]');
    const password = $('#platform-new-password').value;
    $('#platform-password-change-error').hidden = true;
    if (password !== $('#platform-confirm-new-password').value) {
      $('#platform-password-change-error').textContent = 'The passwords do not match.';
      $('#platform-password-change-error').hidden = false;
      return;
    }
    submit.disabled = true;
    try {
      await apiRequest('/api/platform/session/password', {
        method: 'POST',
        body: JSON.stringify({ current_password: $('#platform-current-password').value, password }),
      });
      closePlatformPasswordChangeModal();
      showToast('Employer password updated.');
    } catch (error) {
      $('#platform-password-change-error').textContent = error.message;
      $('#platform-password-change-error').hidden = false;
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
    if (form.id === 'whatsapp-broadcast-form') {
      event.preventDefault();
      const hostelId = $('#whatsapp-broadcast-hostel').value;
      const hostel = state.hostels.find(item => item.id === hostelId);
      const eligibleCount = state.residents.filter(resident =>
        resident.hostel_id === hostelId && resident.whatsapp_opt_in).length;
      if (!hostel || !eligibleCount) {
        renderWhatsAppBroadcast();
        return;
      }
      if (!window.confirm(`Send this WhatsApp announcement individually to ${eligibleCount} opted-in active guest${eligibleCount === 1 ? '' : 's'} at ${hostel.name}? Check the approved template before sending; do not retry if some deliveries fail.`)) return;

      const submit = $('#send-whatsapp-broadcast');
      submit.disabled = true;
      let outcome = '';
      try {
        const result = await apiRequest('/api/whatsapp/broadcast', {
          method: 'POST',
          body: JSON.stringify({
            hostel_id: hostelId,
            message: $('#whatsapp-broadcast-message').value.trim(),
          }),
        });
        try {
          await refreshDashboard();
        } catch (error) {
          showToast(`Broadcast request completed, but the dashboard did not refresh: ${error.message}`);
        }
        const failures = result.failed_residents || [];
        outcome = failures.length
          ? `Sent ${result.sent_count} of ${result.recipient_count}; failed for ${failures.map(resident => resident.name).join(', ')}. Check delivery status before retrying.`
          : `Sent to ${result.sent_count} opted-in guest${result.sent_count === 1 ? '' : 's'}.`;
        $('#whatsapp-broadcast-status').textContent = outcome;
        showToast(failures.length ? `Broadcast completed with ${failures.length} delivery failure${failures.length === 1 ? '' : 's'}.` : 'WhatsApp announcement sent.');
      } catch (error) {
        showToast(error.message);
      } finally {
        renderWhatsAppBroadcast();
        if (outcome) $('#whatsapp-broadcast-status').textContent = outcome;
      }
      return;
    }

    if (form.matches('[data-registration-approval]')) {
      event.preventDefault();
      const submit = form.querySelector('button[type="submit"]');
      const payload = new FormData(form);
      submit.disabled = true;
      try {
        await apiRequest(`/api/registration-applications/${encodeURIComponent(form.dataset.registrationApproval)}/approve`, {
          method: 'POST',
          body: JSON.stringify({
            room_id: payload.get('room_id'),
            bed_number: Number(payload.get('bed_number')),
            joining_date: payload.get('joining_date'),
            payment_status: payload.get('payment_status'),
            amount_due: payload.get('payment_status') === 'unpaid' ? Number(payload.get('amount_due')) : 0,
          }),
        });
        await refreshDashboard();
        showToast('Application approved and resident checked in.');
      } catch (error) {
        showToast(error.message);
      } finally {
        submit.disabled = false;
      }
      return;
    }

    if (form.matches('[data-platform-setup-form], [data-owner-setup-form]')) {
      event.preventDefault();
      const ownerMode = form.matches('[data-owner-setup-form]');
      const submit = form.querySelector('button[type="submit"]');
      const payload = new FormData(form);
      const floorTypes = payload.getAll('floor_types');
      const upperFloorCount = Number(payload.get('upper_floor_count'));
      if (!floorTypes.length && upperFloorCount === 0) {
        showToast('Add at least one floor or upper level.');
        return;
      }
      submit.disabled = true;
      try {
        const setupPath = ownerMode
          ? `/api/hostels/${encodeURIComponent(platformSetupDraft.hostelId)}/setup`
          : `/api/platform/hostels/${encodeURIComponent(platformSetupDraft.hostelId)}/setup`;
        await apiRequest(setupPath, {
          method: 'PUT',
          body: JSON.stringify({
            floor_types: floorTypes,
            upper_floor_count: upperFloorCount,
            ac_type: payload.get('ac_type'),
          }),
        });
        platformSetupDraft.step = 2;
        await refreshLayoutDashboard();
        showToast('Floors added. Add the rooms for this hostel.');
      } catch (error) {
        showToast(error.message);
      } finally {
        submit.disabled = false;
      }
      return;
    }

    if (form.matches('[data-platform-room-draft-form], [data-owner-room-draft-form]')) {
      event.preventDefault();
      const payload = new FormData(form);
      const roomNumber = String(payload.get('room_number')).trim();
      const duplicate = platformSetupDraft.rooms.some(room =>
        room.floorId === payload.get('floor_id') && room.roomNumber.toLocaleLowerCase() === roomNumber.toLocaleLowerCase());
      if (duplicate) {
        showToast('That room number is already in the setup list for this floor.');
        return;
      }
      platformSetupDraft.rooms.push({
        floorId: payload.get('floor_id'),
        roomNumber,
        acType: payload.get('ac_type'),
        shareCount: null,
      });
      renderLayoutDraft();
      $('#layout-room-number').focus();
      return;
    }

    if (form.matches('[data-platform-sharing-form], [data-owner-sharing-form]')) {
      event.preventDefault();
      const payload = new FormData(form);
      platformSetupDraft.rooms.forEach((room, index) => {
        room.shareCount = Number(payload.get(`share_${index}`));
      });
      platformSetupDraft.step = 4;
      renderLayoutDraft();
      return;
    }

    if (form.matches('[data-platform-rent-form], [data-owner-rent-form]')) {
      event.preventDefault();
      const ownerMode = form.matches('[data-owner-rent-form]');
      const submit = form.querySelector('button[type="submit"]');
      submit.disabled = true;
      try {
        for (const room of [...platformSetupDraft.rooms]) {
          const roomPath = ownerMode
            ? `/api/floors/${encodeURIComponent(room.floorId)}/rooms`
            : `/api/platform/floors/${encodeURIComponent(room.floorId)}/rooms`;
          await apiRequest(roomPath, {
            method: 'POST',
            body: JSON.stringify({
              room_number: room.roomNumber,
              share_count: room.shareCount,
              ac_type: room.acType,
            }),
          });
          platformSetupDraft.rooms.shift();
        }
        platformSetupDraft.step = 5;
        if (ownerMode) layoutEditHostelId = '';
        await refreshLayoutDashboard();
        showToast('Rooms saved with rates from Room type charges.');
      } catch (error) {
        await refreshLayoutDashboard();
        showToast(error.message);
      } finally {
        submit.disabled = false;
      }
      return;
    }

    if (form.matches('[data-room-charges-form]')) {
      event.preventDefault();
      const submit = form.querySelector('button[type="submit"]');
      const payload = new FormData(form);
      const charges = [...form.querySelectorAll('[data-share-count]')]
        .filter(input => String(payload.get(input.name)).trim() !== '')
        .map(input => ({
          share_count: Number(input.dataset.shareCount),
          ac_type: input.dataset.acType,
          monthly_rent: Number(payload.get(input.name)),
        }));
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
            hostel_address: payload.get('hostel_address'),
            location: payload.get('location'),
            owner_mobile: payload.get('owner_mobile'),
          }),
        });
        form.reset();
        platformSetupDraft = { hostelId: created.hostel_id, step: 1, rooms: [] };
        await refreshPlatformDashboard();
        showPlatformStep('dashboard');
        showToast('Hostel owner and first hostel registered. The owner can now configure their layout.');
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
            ac_type: payload.get('ac_type'),
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
          body: JSON.stringify({
            floor_number: Number(payload.get('floor_number')),
            floor_type: payload.get('floor_type'),
          }),
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
            ac_type: payload.get('ac_type'),
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
  $('#registration-whatsapp').addEventListener('input', event => event.target.setCustomValidity(''));
  $('#amount-due').addEventListener('input', () => { $('#amount-due').dataset.rateDefault = 'false'; });
  roomSelect.addEventListener('change', renderBedOptions);
  joiningDate.addEventListener('input', updatePaymentDate);
  $('#resident-search').addEventListener('input', () => renderResidents());
  $('#resident-search-all').addEventListener('input', () => renderResidents());
  $('#whatsapp-broadcast-hostel').addEventListener('change', renderWhatsAppBroadcast);
  $('#whatsapp-broadcast-message').addEventListener('input', renderWhatsAppBroadcast);
  document.addEventListener('change', event => {
    if (event.target.matches('[data-room-charge-share-selection]')) {
      const form = event.target.closest('[data-room-charges-form]');
      const addButton = form?.querySelector('[data-add-room-charge-sharing]');
      if (addButton) addButton.disabled = !event.target.value;
    }
    if (event.target.matches('[data-registration-room]')) {
      const form = event.target.closest('[data-registration-approval]');
      const room = state.rooms.find(item => item.id === event.target.value);
      const bedSelect = form.querySelector('[data-registration-bed]');
      const beds = room ? room.beds.filter(bed => !bed.occupied && !bed.reserved) : [];
      bedSelect.innerHTML = beds.length
        ? beds.map(bed => `<option value="${bed.number}">Bed ${bed.number}</option>`).join('')
        : '<option value="">No beds available</option>';
      bedSelect.disabled = !beds.length;
    }
    if (event.target.matches('[data-registration-payment]')) {
      const form = event.target.closest('[data-registration-approval]');
      const amountField = form.querySelector('[data-registration-amount-field]');
      const amountInput = amountField.querySelector('input');
      const unpaid = event.target.value === 'unpaid';
      amountField.hidden = !unpaid;
      amountInput.required = unpaid;
      if (!unpaid) amountInput.value = '';
    }
  });
  document.addEventListener('click', async event => {
    const floorCountButton = event.target.closest('[data-floor-count-change]');
    if (floorCountButton) {
      const floorCountInput = $('#layout-floor-count');
      floorCountInput.value = Math.max(0, Math.min(99, Number(floorCountInput.value) + Number(floorCountButton.dataset.floorCountChange)));
    }

    const removeRoomDraft = event.target.closest('[data-remove-room-draft]');
    if (removeRoomDraft) {
      platformSetupDraft.rooms.splice(Number(removeRoomDraft.dataset.removeRoomDraft), 1);
      renderLayoutDraft();
    }

    if (event.target.closest('[data-layout-wizard-back]')) {
      if (platformSetupDraft.step > 1) {
        platformSetupDraft.step -= 1;
        renderLayoutDraft();
      } else if (platformSetupDraft.ownerMode) {
        platformSetupDraft.step = 0;
        renderHostelStructure();
      } else {
        showPlatformStep('dashboard');
      }
    }

    if (event.target.closest('[data-layout-wizard-next]')) {
      platformSetupDraft.step = Math.min(4, platformSetupDraft.step + 1);
      renderLayoutDraft();
    }

    const layoutEditButton = event.target.closest('[data-toggle-layout-edit]');
    if (layoutEditButton) {
      const hostelId = layoutEditButton.dataset.toggleLayoutEdit;
      layoutEditHostelId = layoutEditHostelId === hostelId ? '' : hostelId;
      renderHostelStructure();
    }

    if (event.target.closest('[data-owner-start-layout]')) {
      const hostel = state.hostels.find(item => !item.floors.length);
      if (hostel) {
        platformSetupDraft = { hostelId: hostel.id, step: 1, rooms: [], ownerMode: true };
        renderPlatformSetupWizard(hostel, true);
      }
    }

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
    if (event.target.closest('#show-platform-reset')) showPlatformPasswordReset();
    if (event.target.closest('#back-to-employer-signin')) returnToPlatformSignIn();
    if (event.target.closest('#change-platform-password-button')) openPlatformPasswordChangeModal();
    if (event.target === platformPasswordChangeModal || event.target.closest('[data-close-platform-password]')) {
      closePlatformPasswordChangeModal();
    }

    const platformHostelButton = event.target.closest('[data-select-platform-hostel]');
    if (platformHostelButton) {
      selectedPlatformHostelId = platformHostelButton.dataset.selectPlatformHostel;
      renderPlatformLayout(platformHostelButton.dataset.selectPlatformHostel);
      showPlatformStep('layout');
      $('#platform-layout-step').scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    const platformStepButton = event.target.closest('[data-platform-step]');
    if (platformStepButton && !platformStepButton.disabled) showPlatformStep(platformStepButton.dataset.platformStep);
    if (event.target.closest('[data-platform-back-to-dashboard]')) showPlatformStep('dashboard');

    if (event.target.closest('[data-finish-platform-layout]')) {
      selectedPlatformHostelId = '';
      platformSetupDraft = { hostelId: '', step: 5, rooms: [] };
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
    if (joinButton && !ownerLayoutNeedsSetup()) openJoinModal();

    if (event.target.closest('#create-registration-invite')) {
      const submit = $('#create-registration-invite');
      const whatsappInput = $('#registration-whatsapp');
      whatsappInput.setCustomValidity('');
      if (!whatsappInput.reportValidity()) return;
      let recipient = whatsappInput.value.replace(/\D/g, '');
      if (recipient.startsWith('00')) recipient = recipient.slice(2);
      if (recipient.length === 10) recipient = `91${recipient}`;
      else if (recipient.startsWith('0') && recipient.length === 11) recipient = `91${recipient.slice(1)}`;
      if (recipient.length < 10 || recipient.length > 15) {
        whatsappInput.setCustomValidity('Enter a WhatsApp number with 10 to 15 digits.');
        whatsappInput.reportValidity();
        return;
      }
      submit.disabled = true;
      try {
        const invite = await apiRequest('/api/registration-invites', {
          method: 'POST',
          body: JSON.stringify({ hostel_id: $('#registration-hostel-select').value, expires_in_days: 7 }),
        });
        const link = new URL(invite.path, window.location.origin).toString();
        $('#registration-invite-url').value = link;
        $('#registration-invite-whatsapp').href = `https://wa.me/${recipient}?text=${encodeURIComponent(`Please complete your Haven Hostel registration: ${link}`)}`;
        $('#registration-invite-result').hidden = false;
        await refreshDashboard();
        showToast('Single-use registration link created. Share it with the new joiner.');
      } catch (error) {
        showToast(error.message);
      } finally {
        submit.disabled = false;
      }
    }

    if (event.target.closest('[data-copy-registration-link]')) {
      const linkInput = $('#registration-invite-url');
      try {
        await navigator.clipboard.writeText(linkInput.value);
        showToast('Registration link copied.');
      } catch {
        linkInput.focus();
        linkInput.select();
        showToast('Select the link and copy it.');
      }
    }

    const revokeInviteButton = event.target.closest('[data-revoke-registration-invite]');
    if (revokeInviteButton) {
      if (!window.confirm('Revoke this registration link? The joiner will no longer be able to submit it.')) return;
      try {
        await apiRequest(`/api/registration-invites/${encodeURIComponent(revokeInviteButton.dataset.revokeRegistrationInvite)}/revoke`, {
          method: 'POST',
          body: JSON.stringify({}),
        });
        await refreshDashboard();
        showToast('Registration link revoked.');
      } catch (error) {
        showToast(error.message);
      }
    }

    if (event.target === joinModal || event.target.closest('[data-close]')) closeJoinModal();
    if (event.target.closest('.open-room-charges') && !ownerLayoutNeedsSetup()) openRoomChargesModal();
    if (event.target === roomChargesModal || event.target.closest('[data-close-room-charges]')) closeRoomChargesModal();

    const addRoomChargeSharingButton = event.target.closest('[data-add-room-charge-sharing]');
    if (addRoomChargeSharingButton) {
      const hostelId = addRoomChargeSharingButton.dataset.hostelId;
      const hostel = state.hostels.find(item => item.id === hostelId);
      const form = addRoomChargeSharingButton.closest('[data-room-charges-form]');
      const fields = form?.querySelector('.room-charge-fields');
      const shareSelection = form?.querySelector('[data-room-charge-share-selection]');
      const shareCount = Number(shareSelection?.value);
      const extraShareCounts = state.roomChargeExtraShareCounts[hostelId] || [];
      if (!hostel || !fields || !shareSelection || !Number.isInteger(shareCount) || shareCount < 7 || shareCount > 20 || extraShareCounts.includes(shareCount)) {
        showToast('Choose an available sharing capacity between 7 and 20.');
        return;
      }
      const hostelRooms = hostel.floors.flatMap(floor => floor.rooms);
      const rateTypes = hostel.ac_type === 'ac' ? [['ac', 'AC']] : [['ac', 'AC'], ['non_ac', 'Non-AC']];
      state.roomChargeExtraShareCounts[hostelId] = [...extraShareCounts, shareCount];
      const rowMarkup = roomTypeChargeRowMarkup(hostel, hostelRooms, rateTypes, shareCount);
      const nextRow = [...fields.querySelectorAll('.room-charge-row')]
        .find(row => Number(row.dataset.shareCount) > shareCount);
      if (nextRow) nextRow.insertAdjacentHTML('beforebegin', rowMarkup);
      else fields.insertAdjacentHTML('beforeend', rowMarkup);
      shareSelection.querySelector(`option[value="${shareCount}"]`)?.remove();
      shareSelection.value = '';
      addRoomChargeSharingButton.disabled = true;
      if (![...shareSelection.options].some(option => option.value)) {
        shareSelection.innerHTML = '<option value="">All capacities added</option>';
        shareSelection.disabled = true;
      }
    }

    const navButton = event.target.closest('[data-view]');
    const gotoButton = event.target.closest('[data-goto]');
    const destination = navButton?.dataset.view || gotoButton?.dataset.goto;
    if (destination) {
      if (!ownerLayoutNeedsSetup() || destination === 'rooms') setActiveView(destination);
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

    const platformDeleteRoomButton = event.target.closest('[data-platform-delete-room]');
    if (platformDeleteRoomButton) {
      const roomId = platformDeleteRoomButton.dataset.platformDeleteRoom;
      const hostel = state.platform?.hostels.find(item => item.floors.some(floor => floor.rooms.some(room => room.id === roomId)));
      const floor = hostel?.floors.find(item => item.rooms.some(room => room.id === roomId));
      const room = floor?.rooms.find(item => item.id === roomId);
      if (!room || !window.confirm(`Delete Room ${room.room_number} from ${hostel.name}, ${platformFloorLabel(floor, hostel.floors)}? Past resident and audit history will be retained.`)) return;
      try {
        await apiRequest(`/api/rooms/${encodeURIComponent(room.id)}`, { method: 'DELETE' });
        await refreshPlatformDashboard();
        showToast(`Room ${room.room_number} deleted from active availability.`);
      } catch (error) {
        showToast(error.message);
      }
    }

    const platformDeleteFloorButton = event.target.closest('[data-platform-delete-floor]');
    if (platformDeleteFloorButton) {
      const floorId = platformDeleteFloorButton.dataset.platformDeleteFloor;
      const hostel = state.platform?.hostels.find(item => item.floors.some(floor => floor.id === floorId));
      const floor = hostel?.floors.find(item => item.id === floorId);
      if (!floor || !window.confirm(`Delete ${platformFloorLabel(floor, hostel.floors)} from ${hostel.name}? Its rooms will be archived; resident and audit history will be retained.`)) return;
      try {
        const deleted = await apiRequest(`/api/platform/floors/${encodeURIComponent(floor.id)}`, { method: 'DELETE' });
        await refreshPlatformDashboard();
        showToast(`${platformFloorLabel(floor, hostel.floors)} deleted; ${deleted.rooms_archived} room(s) archived.`);
      } catch (error) {
        showToast(error.message);
      }
    }

    const ownerDeleteFloorButton = event.target.closest('[data-owner-delete-floor]');
    if (ownerDeleteFloorButton) {
      const floorId = ownerDeleteFloorButton.dataset.ownerDeleteFloor;
      const hostel = state.hostels.find(item => item.floors.some(floor => floor.id === floorId));
      const floor = hostel?.floors.find(item => item.id === floorId);
      if (!floor || !window.confirm(`Delete ${platformFloorLabel(floor, hostel.floors)} from ${hostel.name}? Its rooms will be archived and resident history retained.`)) return;
      try {
        const deleted = await apiRequest(`/api/floors/${encodeURIComponent(floor.id)}`, { method: 'DELETE' });
        await refreshDashboard();
        showToast(`${platformFloorLabel(floor, hostel.floors)} deleted; ${deleted.rooms_archived} room(s) archived.`);
      } catch (error) {
        showToast(error.message);
      }
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

    const consentButton = event.target.closest('[data-whatsapp-consent]');
    if (consentButton) {
      const resident = state.residents.find(item => item.id === consentButton.dataset.whatsappConsent);
      if (!resident) return;
      const enabled = !resident.whatsapp_opt_in;
      if (enabled && !window.confirm(`Confirm that ${resident.name} explicitly agreed to receive WhatsApp updates from the hostel? Only record opt-in if you have their permission.`)) return;
      consentButton.disabled = true;
      try {
        await apiRequest(`/api/residents/${encodeURIComponent(resident.id)}/whatsapp-consent`, {
          method: 'PATCH',
          body: JSON.stringify({ enabled }),
        });
        resident.whatsapp_opt_in = enabled;
        renderResidents();
        renderWhatsAppBroadcast();
        showToast(enabled ? `${resident.name} opted in to WhatsApp updates.` : `${resident.name} opted out of WhatsApp updates.`);
      } catch (error) {
        consentButton.disabled = false;
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
    if (!platformPasswordChangeModal.hidden) closePlatformPasswordChangeModal();
    else if (!roomChargesModal.hidden) closeRoomChargesModal();
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

  $('#today-date').textContent = new Intl.DateTimeFormat('en-IN', {
    weekday: 'long', day: 'numeric', month: 'long', year: 'numeric',
  }).format(new Date());
  initialize();
})();