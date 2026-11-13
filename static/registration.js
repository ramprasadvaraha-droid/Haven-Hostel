(() => {
  const form = document.querySelector('#registration-form');
  const message = document.querySelector('#registration-message');
  const submit = form.querySelector('button[type="submit"]');
  const token = window.location.pathname.split('/').pop();

  function showMessage(text, isError = false) {
    message.textContent = text;
    message.classList.toggle('error', isError);
    message.hidden = false;
  }

  async function responseError(response) {
    const payload = await response.json().catch(() => null);
    return payload?.detail || 'The request could not be completed.';
  }

  async function loadInvitation() {
    try {
      const response = await fetch(`/api/join/${encodeURIComponent(token)}`, { cache: 'no-store' });
      if (!response.ok) throw new Error(await responseError(response));
      const invitation = await response.json();
      document.querySelector('#hostel-name').textContent = invitation.hostel_name;
      form.hidden = false;
    } catch (error) {
      showMessage(error.message, true);
    }
  }

  form.addEventListener('submit', async event => {
    event.preventDefault();
    for (const input of form.querySelectorAll('input[type="file"]')) {
      if (input.files[0]?.size > 5 * 1024 * 1024) {
        showMessage(`${input.labels[0].textContent} must be 5 MB or smaller.`, true);
        return;
      }
    }
    submit.disabled = true;
    message.hidden = true;
    const body = new FormData(form);
    body.set('consent', 'true');
    try {
      const response = await fetch(`/api/join/${encodeURIComponent(token)}`, { method: 'POST', body });
      if (!response.ok) throw new Error(await responseError(response));
      form.reset();
      form.hidden = true;
      showMessage('Your registration was submitted. The hostel owner will review it and arrange your room and check-in if approved.');
    } catch (error) {
      showMessage(error.message, true);
    } finally {
      submit.disabled = false;
    }
  });

  loadInvitation();
})();
