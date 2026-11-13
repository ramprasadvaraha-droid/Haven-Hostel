(() => {
  const form = document.querySelector('#registration-form');
  const message = document.querySelector('#registration-message');
  const submit = form.querySelector('button[type="submit"]');
  const token = window.location.pathname.split('/').pop();
  const previewUrls = new Map();

  function clearPhotoPreview(input, preview) {
    const previousUrl = previewUrls.get(input.id);
    if (previousUrl) URL.revokeObjectURL(previousUrl);
    previewUrls.delete(input.id);
    preview.querySelector('img').removeAttribute('src');
    preview.hidden = true;
  }

  for (const input of form.querySelectorAll('input[type="file"]')) {
    const preview = form.querySelector(`[data-photo-preview-for="${input.id}"]`);
    input.addEventListener('change', () => {
      clearPhotoPreview(input, preview);
      const file = input.files[0];
      if (!file || !['image/jpeg', 'image/png', 'image/webp'].includes(file.type)) return;
      const previewUrl = URL.createObjectURL(file);
      previewUrls.set(input.id, previewUrl);
      preview.querySelector('img').src = previewUrl;
      preview.hidden = false;
    });
  }

  function clearPhotoPreviews() {
    for (const input of form.querySelectorAll('input[type="file"]')) {
      clearPhotoPreview(input, form.querySelector(`[data-photo-preview-for="${input.id}"]`));
    }
  }

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
      clearPhotoPreviews();
      form.hidden = true;
      showMessage('Your registration was submitted. The hostel owner will review it and arrange your room and check-in if approved.');
    } catch (error) {
      showMessage(error.message, true);
    } finally {
      submit.disabled = false;
    }
  });

  window.addEventListener('beforeunload', clearPhotoPreviews);
  loadInvitation();
})();
