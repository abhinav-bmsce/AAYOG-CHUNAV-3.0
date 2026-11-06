/**
 * ============================================================================
 * Title:       AAYOG_CHUNAV 3.0 - Administrator Portal Controller
 * File:        public/admin.js
 * Description: Client-side logic for multi-election administration, candidate &
 *              voter management, booth tracking, cryptographic audits, and backups.
 * ============================================================================
 */

let adminToken = localStorage.getItem('aayog_admin_token') || null;
let currentTab = 'overview';
let adminRefreshTimer = null;
let adminSelectedElectionId = 1;
let cachedElections = [];

document.addEventListener('DOMContentLoaded', async () => {
  try {
    const headers = {};
    if (adminToken) headers['Authorization'] = `Bearer ${adminToken}`;
    const res = await fetch('/api/admin/check_session', { headers });
    const data = await res.json();

    const ipBadge = document.getElementById('adminIpBadge');
    if (ipBadge && data.client_ip) {
      ipBadge.textContent = `IP: ${data.client_ip} (${data.ip_allowed ? 'Allowlisted' : 'Blocked'})`;
    }

    if (!data.ip_allowed && !data.mtls) {
      showLoginModal();
      const alertBox = document.getElementById('loginAlert');
      if (alertBox) {
        alertBox.className = 'alert alert-error';
        alertBox.textContent = `🚫 Access Denied: Your IP address (${data.client_ip}) is not on the administrative allowlist. Only allowlisted addresses or verified mTLS administrative clients may access this portal.`;
        alertBox.classList.remove('hidden');
      }
      const loginBtn = document.getElementById('loginBtn');
      if (loginBtn) loginBtn.disabled = true;
      return;
    }

    if (data.authenticated) {
      showDashboard();
    } else {
      adminToken = null;
      localStorage.removeItem('aayog_admin_token');
      showLoginModal();
    }
  } catch (e) {
    if (adminToken) showDashboard();
    else showLoginModal();
  }
});

function showLoginModal() {
  const modal = document.getElementById('adminLoginModal');
  const dash = document.getElementById('adminDashboard');
  if (modal) modal.style.display = 'flex';
  if (dash) dash.style.display = 'none';
}

function showDashboard() {
  const modal = document.getElementById('adminLoginModal');
  const dash = document.getElementById('adminDashboard');
  if (modal) modal.style.display = 'none';
  if (dash) dash.style.display = 'block';

  loadAllData();
  if (adminRefreshTimer) clearInterval(adminRefreshTimer);
  adminRefreshTimer = setInterval(refreshActiveTabData, 3500);
}

function getAuthHeaders() {
  const headers = { 'Content-Type': 'application/json' };
  if (adminToken) headers['Authorization'] = `Bearer ${adminToken}`;
  return headers;
}

/**
 * Administrator Login
 */
async function handleAdminLogin(event) {
  event.preventDefault();
  const user = document.getElementById('adminUsername').value.trim();
  const pass = document.getElementById('adminPassword').value;
  const otp = document.getElementById('adminOtp').value.trim();
  const alertBox = document.getElementById('loginAlert');
  const btn = document.getElementById('loginBtn');

  alertBox.className = 'alert hidden';
  btn.disabled = true;
  btn.textContent = 'Authenticating...';

  try {
    const res = await fetch('/api/admin/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: user, password: pass, otp: otp })
    });

    const data = await res.json();
    if (res.ok && data.success) {
      adminToken = data.token;
      localStorage.setItem('aayog_admin_token', adminToken);
      showDashboard();
    } else {
      alertBox.className = 'alert alert-error';
      alertBox.textContent = `❌ ${data.message || 'Authentication failed. Check credentials/2FA code.'}`;
      alertBox.classList.remove('hidden');
    }
  } catch (err) {
    alertBox.className = 'alert alert-error';
    alertBox.textContent = '❌ Failed to reach server. Check HTTPS connection.';
    alertBox.classList.remove('hidden');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Authenticate & Enter Portal';
  }
}

/**
 * Administrator Logout
 */
async function handleAdminLogout() {
  try {
    await fetch('/api/admin/logout', {
      method: 'POST',
      headers: getAuthHeaders()
    });
  } catch (e) {}
  adminToken = null;
  localStorage.removeItem('aayog_admin_token');
  showLoginModal();
}

/**
 * Tab Navigation
 */
function switchTab(tabName) {
  currentTab = tabName;
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
  document.querySelectorAll('.tab-pane').forEach(pane => pane.classList.remove('active'));

  const btn = Array.from(document.querySelectorAll('.tab-btn')).find(b => b.getAttribute('onclick')?.includes(`'${tabName}'`));
  if (btn) btn.classList.add('active');

  const pane = document.getElementById(`pane-${tabName}`);
  if (pane) pane.classList.add('active');

  refreshActiveTabData();
}

/**
 * Handle Global Scope Dropdown Change
 */
function onAdminScopeChange(val) {
  adminSelectedElectionId = parseInt(val, 10) || 1;
  const candLabel = document.getElementById('candScopeLabel');
  if (candLabel) candLabel.textContent = `Election #${adminSelectedElectionId}`;
  refreshActiveTabData();
}

/**
 * Load Initial Dashboard Data
 */
async function loadAllData() {
  await loadAllElections();
  refreshActiveTabData();
}

/**
 * Periodically Refresh Active Tab Data
 */
function refreshActiveTabData() {
  switch (currentTab) {
    case 'overview':
      loadOverview();
      break;
    case 'elections':
      loadAllElections();
      break;
    case 'candidates':
      loadAdminCandidates();
      break;
    case 'voters':
      loadAdminVoters();
      break;
    case 'booths':
      loadAdminBooths();
      break;
    case 'analytics':
      loadAdminAnalytics();
      break;
    case 'security':
      loadSecurityAlerts();
      loadAllowlist();
      break;
    case 'audit':
      loadAuditLogs();
      break;
    case 'backups':
      loadBackups();
      break;
  }
}

/* =============================================================================
 * TAB 1: OVERVIEW
 * ============================================================================= */
async function loadOverview() {
  try {
    const res = await fetch(`/api/results?election_id=${adminSelectedElectionId}`, { headers: getAuthHeaders() });
    if (!res.ok) return;
    const data = await res.json();

    const reg = data.total_registered || 0;
    const votes = data.total_votes || 0;
    const remaining = Math.max(0, reg - votes);
    const turnout = reg > 0 ? ((votes / reg) * 100).toFixed(1) : 0;

    const regEl = document.getElementById('ovTotalReg');
    const votesEl = document.getElementById('ovTotalVotes');
    const remEl = document.getElementById('ovRemaining');
    const turnEl = document.getElementById('ovTurnout');
    const stateEl = document.getElementById('ovElectionState');
    const titleEl = document.getElementById('ovElectionTitle');

    if (regEl) regEl.textContent = reg;
    if (votesEl) votesEl.textContent = votes;
    if (remEl) remEl.textContent = remaining;
    if (turnEl) turnEl.textContent = `${turnout}%`;
    if (titleEl) titleEl.textContent = data.election_title || `Election #${adminSelectedElectionId}`;
    if (stateEl) {
      stateEl.textContent = data.status_str || 'ACTIVE';
      stateEl.className = `badge state-${(data.status_str || 'ACTIVE').toLowerCase()}`;
    }

    // Candidate standings table
    const tbody = document.getElementById('ovCandidatesTableBody');
    if (tbody && Array.isArray(data.candidates)) {
      tbody.innerHTML = '';
      data.candidates.forEach(c => {
        const pct = votes > 0 ? ((c.votes / votes) * 100).toFixed(1) : 0;
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td><strong>#${c.id}</strong></td>
          <td>${c.name}</td>
          <td><span class="party-tag">${c.party}</span></td>
          <td><strong>${c.votes}</strong></td>
          <td>${pct}%</td>
        `;
        tbody.appendChild(tr);
      });
    }
  } catch (err) {
    console.error('Error loading overview:', err);
  }
}

async function setElectionState(newState) {
  try {
    const res = await fetch('/api/admin/election/state', {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ election_id: adminSelectedElectionId, state: newState })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      alert(`Election #${adminSelectedElectionId} state updated to: ${data.new_state}`);
      loadOverview();
      loadAllElections();
    } else {
      alert(`Error updating state: ${data.message || 'Operation failed'}`);
    }
  } catch (err) {
    alert('Network error communicating with server.');
  }
}

/* =============================================================================
 * TAB 2: ALL ELECTIONS HUB
 * ============================================================================= */
async function loadAllElections() {
  try {
    const res = await fetch('/api/admin/elections', { headers: getAuthHeaders() });
    if (!res.ok) return;
    const data = await res.json();
    cachedElections = data.elections || [];

    // Update Scope Selector in Navbar
    const scopeSelect = document.getElementById('adminElectionScope');
    if (scopeSelect && Array.isArray(cachedElections)) {
      scopeSelect.innerHTML = '';
      cachedElections.forEach(el => {
        const opt = document.createElement('option');
        opt.value = el.id;
        opt.textContent = `#${el.id}: ${el.title} (${el.status_str})`;
        if (el.id === adminSelectedElectionId) opt.selected = true;
        scopeSelect.appendChild(opt);
      });
    }

    // Populate Elections Table
    const tbody = document.getElementById('allElectionsTableBody');
    if (!tbody) return;
    tbody.innerHTML = '';

    cachedElections.forEach(el => {
      const tr = document.createElement('tr');
      const isSel = (el.id === adminSelectedElectionId);
      tr.innerHTML = `
        <td><strong>#${el.id}</strong> ${isSel ? '<span class="badge">ACTIVE CONTEXT</span>' : ''}</td>
        <td><strong>${el.title}</strong><br><small class="text-muted">${el.description || ''}</small></td>
        <td><span class="meta-type-tag">${el.election_type}</span></td>
        <td><span class="badge state-${el.status_str.toLowerCase()}">${el.status_str}</span></td>
        <td>${el.total_voters}</td>
        <td>${el.total_votes}</td>
        <td class="action-cell">
          <button type="button" class="btn-sm btn-secondary" onclick="selectActiveContext(${el.id})">Select</button>
          ${el.status_str === 'DRAFT' ? `<button type="button" class="btn-sm btn-danger" onclick="deleteDraftElection(${el.id})">Delete</button>` : ''}
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error('Failed to load elections:', err);
  }
}

function selectActiveContext(id) {
  adminSelectedElectionId = id;
  const scopeSelect = document.getElementById('adminElectionScope');
  if (scopeSelect) scopeSelect.value = id;
  onAdminScopeChange(id);
  alert(`Switched administrative context to Election #${id}`);
}

async function handleCreateElection(event) {
  event.preventDefault();
  const title = document.getElementById('newElTitle').value.trim();
  const elType = document.getElementById('newElType').value;
  const desc = document.getElementById('newElDesc').value.trim();
  const requireOtp = document.getElementById('newElOtp').checked ? 1 : 0;

  try {
    const res = await fetch('/api/admin/elections', {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({
        title: title,
        election_type: elType,
        description: desc,
        require_otp: requireOtp
      })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      alert(`Election created successfully! Assigned Election ID #${data.election_id}`);
      document.getElementById('createElectionForm').reset();
      await loadAllElections();
      selectActiveContext(data.election_id);
    } else {
      alert(`Error creating election: ${data.message || 'Operation failed'}`);
    }
  } catch (err) {
    alert('Network error creating election.');
  }
}

async function deleteDraftElection(id) {
  if (!confirm(`Are you sure you want to delete Draft Election #${id}?`)) return;
  try {
    const res = await fetch('/api/admin/election/delete', {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ id: id })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      alert('Draft election deleted.');
      loadAllElections();
    } else {
      alert(`Cannot delete election: ${data.message}`);
    }
  } catch (err) {
    alert('Network error.');
  }
}

/* =============================================================================
 * TAB 3: CANDIDATE MANAGEMENT
 * ============================================================================= */
async function loadAdminCandidates() {
  const tbody = document.getElementById('adminCandidatesTableBody');
  if (!tbody) return;

  try {
    const res = await fetch(`/api/admin/candidates?election_id=${adminSelectedElectionId}`, { headers: getAuthHeaders() });
    if (!res.ok) return;
    const data = await res.json();
    const candidates = data.candidates || [];

    tbody.innerHTML = '';
    if (candidates.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="text-muted" style="text-align:center;">No candidates registered for this election yet.</td></tr>';
      return;
    }

    candidates.forEach(c => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><strong>#${c.id}</strong></td>
        <td><img src="${c.photo || c.photo_url || '/images/others.png'}" style="width:36px;height:36px;border-radius:50%;object-fit:cover;" onerror="this.onerror=null; this.src='/images/others.png';"></td>
        <td><strong>${c.name}</strong></td>
        <td><span class="party-tag">${c.party}</span></td>
        <td><strong>${c.votes}</strong></td>
        <td class="action-cell">
          <button type="button" class="btn-sm btn-danger" onclick="deleteCandidateAction(${c.id})">Delete</button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error('Error loading candidates:', err);
  }
}

function previewCandidateImage(event) {
  const file = event.target.files && event.target.files[0];
  const previewWrap = document.getElementById('candPhotoPreviewWrap');
  const previewImg = document.getElementById('candPhotoPreview');
  const statusSpan = document.getElementById('candPhotoStatus');
  if (!file) {
    if (previewWrap) previewWrap.style.display = 'none';
    return;
  }

  // Validate file type
  const validTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp'];
  const validExts = ['.jpg', '.jpeg', '.png', '.webp'];
  const ext = '.' + file.name.split('.').pop().toLowerCase();
  if (!validTypes.includes(file.type) && !validExts.includes(ext)) {
    alert('Invalid file format. Only JPG, JPEG, PNG, and WebP images are permitted.');
    event.target.value = '';
    if (previewWrap) previewWrap.style.display = 'none';
    return;
  }

  // Validate file size (max 5MB)
  if (file.size > 5 * 1024 * 1024) {
    alert('File is too large. Maximum allowed image size is 5MB.');
    event.target.value = '';
    if (previewWrap) previewWrap.style.display = 'none';
    return;
  }

  const reader = new FileReader();
  reader.onload = (e) => {
    if (previewImg) previewImg.src = e.target.result;
    if (statusSpan) statusSpan.textContent = `✓ Selected: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
    if (previewWrap) previewWrap.style.display = 'flex';
  };
  reader.readAsDataURL(file);
}

async function handleAddCandidate(event) {
  event.preventDefault();
  const name = document.getElementById('candName').value.trim();
  const party = document.getElementById('candParty').value.trim();
  let photo = document.getElementById('candPhoto').value.trim();
  const fileInput = document.getElementById('candPhotoFile');
  const addBtn = document.getElementById('addCandBtn');

  if (addBtn) addBtn.disabled = true;

  try {
    // If an image file was selected, upload it first
    if (fileInput && fileInput.files && fileInput.files[0]) {
      const file = fileInput.files[0];
      const dataUrl = await new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.onerror = reject;
        reader.readAsDataURL(file);
      });

      const uploadRes = await fetch('/api/admin/candidate/upload_photo', {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({
          election_id: adminSelectedElectionId,
          filename: file.name,
          image_data: dataUrl
        })
      });
      const uploadData = await uploadRes.json();
      if (uploadRes.ok && uploadData.success) {
        photo = uploadData.photo_url;
      } else {
        alert(`Image upload error: ${uploadData.message || 'Failed to upload photograph.'}`);
        if (addBtn) addBtn.disabled = false;
        return;
      }
    }

    if (!photo) photo = '/images/others.png';

    const res = await fetch('/api/admin/candidates', {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({
        election_id: adminSelectedElectionId,
        name: name,
        party: party,
        photo: photo
      })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      alert('Candidate registered successfully!');
      document.getElementById('addCandidateForm').reset();
      const previewWrap = document.getElementById('candPhotoPreviewWrap');
      if (previewWrap) previewWrap.style.display = 'none';
      loadAdminCandidates();
    } else {
      alert(`Error: ${data.message || 'Cannot add candidate once election has started.'}`);
    }
  } catch (err) {
    alert('Network error adding candidate.');
  } finally {
    if (addBtn) addBtn.disabled = false;
  }
}

async function deleteCandidateAction(id) {
  if (!confirm(`Remove candidate #${id}?`)) return;
  try {
    const res = await fetch('/api/admin/candidates/delete', {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ election_id: adminSelectedElectionId, id: id })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      alert('Candidate removed.');
      loadAdminCandidates();
    } else {
      alert(`Cannot remove candidate: ${data.message}`);
    }
  } catch (err) {
    alert('Network error.');
  }
}

/* =============================================================================
 * TAB 4: VOTER MANAGEMENT
 * ============================================================================= */
async function loadAdminVoters(searchQuery = '') {
  const tbody = document.getElementById('votersTableBody');
  const countEl = document.getElementById('voterScopeCount');
  if (!tbody) return;

  try {
    const url = `/api/admin/voters?election_id=${adminSelectedElectionId}${searchQuery ? '&q=' + encodeURIComponent(searchQuery) : ''}`;
    const res = await fetch(url, { headers: getAuthHeaders() });
    if (!res.ok) return;
    const data = await res.json();

    if (countEl) countEl.textContent = data.total_count || 0;
    tbody.innerHTML = '';

    const voters = data.voters || [];
    if (voters.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="text-muted" style="text-align:center;">No voters registered matching criteria.</td></tr>';
      return;
    }

    voters.forEach(v => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><code>${v.id}</code></td>
        <td><strong>${v.name}</strong></td>
        <td>Booth #${v.booth_id}</td>
        <td>
          <span class="badge ${v.has_voted ? 'state-closed' : 'state-active'}">
            ${v.has_voted ? 'Voted ✔' : 'Eligible'}
          </span>
        </td>
        <td>${v.has_voted ? v.voted_at : '—'}</td>
        <td class="action-cell">
          ${!v.has_voted ? `<button type="button" class="btn-sm btn-danger" onclick="deleteVoterAction('${v.id}')">Remove</button>` : '<span class="text-muted">Ballot Cast</span>'}
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {
    console.error('Error loading voters:', err);
  }
}

function handleVoterSearch() {
  const q = document.getElementById('voterSearchInput').value.trim();
  loadAdminVoters(q);
}

async function handleAddVoter(event) {
  event.preventDefault();
  const id = document.getElementById('addVoterId').value.trim().toUpperCase();
  const name = document.getElementById('addVoterName').value.trim();
  const booth = parseInt(document.getElementById('addVoterBooth').value, 10) || 1;

  try {
    const res = await fetch('/api/admin/voters', {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ election_id: adminSelectedElectionId, id: id, name: name, booth_id: booth })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      alert(`Voter ${id} registered successfully!`);
      document.getElementById('addVoterForm').reset();
      loadAdminVoters();
    } else {
      alert(`Error registering voter: ${data.message || 'Duplicate ID or capacity limit reached.'}`);
    }
  } catch (err) {
    alert('Network error registering voter.');
  }
}

function loadSampleCsv() {
  const input = document.getElementById('bulkCsvText');
  if (input) {
    input.value = "V160,Vikram Malhotra,1\nV161,Pooja Sharma,2\nV162,Karan Patel,1\nV163,Neha Gupta,2\nV164,Ananya Rao,1";
  }
}

function clearCsvInput() {
  const input = document.getElementById('bulkCsvText');
  if (input) input.value = '';
  const resultEl = document.getElementById('bulkImportResult');
  if (resultEl) {
    resultEl.textContent = '';
    resultEl.className = 'status-msg';
  }
}

async function handleBulkImport() {
  const bulkInput = document.getElementById('bulkCsvText');
  let csv = bulkInput ? bulkInput.value.trim() : '';
  if (!csv && bulkInput && bulkInput.placeholder) {
    csv = bulkInput.placeholder.trim();
    bulkInput.value = csv;
  }
  const resultEl = document.getElementById('bulkImportResult');
  if (!csv) {
    alert('Please enter CSV data to import.');
    return;
  }

  if (resultEl) {
    resultEl.textContent = 'Importing voter roll...';
    resultEl.className = 'status-msg';
  }

  try {
    const res = await fetch(`/api/admin/voters/import?election_id=${adminSelectedElectionId}`, {
      method: 'POST',
      headers: { ...getAuthHeaders(), 'Content-Type': 'text/plain' },
      body: csv
    });
    const data = await res.json();
    if (res.ok && data.success) {
      let msg = `✅ Import successful: ${data.added} voter(s) added, ${data.skipped} duplicates/invalid skipped.`;
      if (data.details) {
        msg += ` (${data.details})`;
      }
      if (resultEl) {
        resultEl.textContent = msg;
        resultEl.className = 'status-msg success';
      }
      loadAdminVoters();
    } else {
      const errMsg = `❌ Import failed: ${data.message || 'Error processing CSV'}`;
      if (resultEl) {
        resultEl.textContent = errMsg;
        resultEl.className = 'status-msg error';
      }
    }
  } catch (err) {
    if (resultEl) {
      resultEl.textContent = 'Network error importing CSV.';
      resultEl.className = 'status-msg error';
    }
  }
}

async function deleteVoterAction(id) {
  if (!confirm(`Remove voter ${id} from roll?`)) return;
  try {
    const res = await fetch('/api/admin/voters/delete', {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ election_id: adminSelectedElectionId, id: id })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      loadAdminVoters();
    } else {
      alert(`Cannot delete voter: ${data.message}`);
    }
  } catch (err) {
    alert('Network error.');
  }
}

/* =============================================================================
 * TAB 5: POLLING BOOTHS
 * ============================================================================= */
async function loadAdminBooths() {
  const tbody = document.getElementById('adminBoothsTableBody');
  const addSelect = document.getElementById('addVoterBooth');
  if (!tbody) return;

  try {
    const res = await fetch(`/api/admin/booths?election_id=${adminSelectedElectionId}`, { headers: getAuthHeaders() });
    if (!res.ok) return;
    const data = await res.json();
    const booths = data.booths || [];

    tbody.innerHTML = '';
    if (addSelect) addSelect.innerHTML = '';

    if (booths.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" class="text-muted" style="text-align:center;">No polling booths configured yet.</td></tr>';
      return;
    }

    booths.forEach(b => {
      const turnout = b.total_registered > 0 ? ((b.votes_cast / b.total_registered) * 100).toFixed(1) : 0;
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><strong>Station #${b.id}</strong></td>
        <td><strong>${b.name}</strong></td>
        <td>${b.location || '—'}</td>
        <td>${b.total_registered}</td>
        <td><strong>${b.votes_cast}</strong></td>
        <td>${turnout}%</td>
        <td class="action-cell">
          <button type="button" class="btn-sm btn-danger" onclick="deleteBoothAction(${b.id})">Delete</button>
        </td>
      `;
      tbody.appendChild(tr);

      if (addSelect) {
        const opt = document.createElement('option');
        opt.value = b.id;
        opt.textContent = `Station #${b.id}: ${b.name}`;
        addSelect.appendChild(opt);
      }
    });
  } catch (err) {
    console.error('Error loading booths:', err);
  }
}

async function handleAddBooth(event) {
  event.preventDefault();
  const id = parseInt(document.getElementById('boothIdInput').value, 10);
  const name = document.getElementById('boothNameInput').value.trim();
  const loc = document.getElementById('boothLocInput').value.trim();

  try {
    const res = await fetch('/api/admin/booths', {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ election_id: adminSelectedElectionId, id: id, name: name, location: loc })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      alert('Polling booth created!');
      document.getElementById('addBoothForm').reset();
      loadAdminBooths();
    } else {
      alert(`Error creating booth: ${data.message || 'Duplicate ID'}`);
    }
  } catch (err) {
    alert('Network error adding booth.');
  }
}

async function deleteBoothAction(id) {
  if (!confirm(`Delete Polling Booth #${id}?`)) return;
  try {
    const res = await fetch('/api/admin/booths/delete', {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ election_id: adminSelectedElectionId, id: id })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      loadAdminBooths();
    } else {
      alert(`Cannot delete booth: ${data.message}`);
    }
  } catch (err) {
    alert('Network error.');
  }
}

/* =============================================================================
 * TAB 6: LIVE ANALYTICS & RESULTS
 * ============================================================================= */
async function loadAdminAnalytics() {
  try {
    const res = await fetch(`/api/admin/analytics?election_id=${adminSelectedElectionId}`, { headers: getAuthHeaders() });
    if (!res.ok) return;
    const data = await res.json();

    const leaderEl = document.getElementById('anLeaderName');
    const marginEl = document.getElementById('anLeadMargin');
    const tieEl = document.getElementById('anTieStatus');
    const stateEl = document.getElementById('anResultsState');

    if (leaderEl) leaderEl.textContent = data.leader_name || '—';
    if (marginEl) marginEl.textContent = `${data.margin_of_victory || 0} votes`;
    if (tieEl) tieEl.textContent = data.is_tie ? '⚠️ Contested Tie' : 'Clear Advantage';
    if (stateEl) stateEl.textContent = data.results_declared ? 'Officially Declared' : 'Sealed';

    const tbody = document.getElementById('anCandidatesTableBody');
    if (tbody && Array.isArray(data.candidates)) {
      tbody.innerHTML = '';
      const total = data.total_ballots || 0;
      data.candidates.forEach(c => {
        const pct = total > 0 ? ((c.votes / total) * 100).toFixed(1) : 0;
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td><strong>#${c.id}</strong></td>
          <td><strong>${c.name}</strong></td>
          <td><span class="party-tag">${c.party}</span></td>
          <td><strong>${c.votes}</strong></td>
          <td>${pct}%</td>
        `;
        tbody.appendChild(tr);
      });
    }
  } catch (err) {
    console.error('Error loading analytics:', err);
  }
}

async function declareOfficialResults() {
  if (!confirm(`Are you sure you want to officially declare results for Election #${adminSelectedElectionId}?\nThis will make results visible to all voters.`)) return;
  setElectionState('DECLARED');
}

/* =============================================================================
 * TAB 7: SECURITY ALERTS & IP ALLOWLIST
 * ============================================================================= */
async function loadAllowlist() {
  const ul = document.getElementById('allowlistUl');
  if (!ul) return;
  try {
    const res = await fetch('/api/admin/allowlist', { headers: getAuthHeaders() });
    const data = await res.json();
    ul.innerHTML = '';
    (data.allowed_ips || []).forEach(ip => {
      const li = document.createElement('li');
      li.innerHTML = `<span>🔒 ${ip}</span> <span class="badge">Allowlisted</span>`;
      ul.appendChild(li);
    });
  } catch (err) {}
}

async function handleAddIp(event) {
  event.preventDefault();
  const ipInput = document.getElementById('newIpAddress');
  const ip = ipInput.value.trim();
  const msgEl = document.getElementById('ipActionMsg');

  try {
    const res = await fetch('/api/admin/allowlist', {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ ip: ip })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      msgEl.textContent = `✅ IP ${ip} allowlisted.`;
      msgEl.className = 'status-msg success';
      ipInput.value = '';
      loadAllowlist();
    } else {
      msgEl.textContent = `❌ ${data.message || 'Failed to add IP'}`;
      msgEl.className = 'status-msg error';
    }
  } catch (err) {
    msgEl.textContent = 'Network error.';
    msgEl.className = 'status-msg error';
  }
}

async function loadSecurityAlerts() {
  const tbody = document.getElementById('alertsTableBody');
  if (!tbody) return;
  try {
    const res = await fetch('/api/admin/alerts', { headers: getAuthHeaders() });
    const alerts = await res.json();
    tbody.innerHTML = '';
    if (!Array.isArray(alerts) || alerts.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" class="text-muted" style="text-align:center;">No intrusion or security alerts detected.</td></tr>';
      return;
    }
    alerts.forEach(a => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${a.timestamp}</td>
        <td><span class="badge state-${(a.severity || 'low').toLowerCase()}">${a.severity}</span></td>
        <td><strong>${a.type}</strong></td>
        <td><code>${a.ip}</code></td>
        <td>${a.details}</td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {}
}

async function runFileIntegrityCheck() {
  const out = document.getElementById('fileIntegrityOutput');
  if (out) out.textContent = 'Running SHA-256 baseline verification...';
  try {
    const res = await fetch('/api/admin/integrity', { headers: getAuthHeaders() });
    const txt = await res.text();
    if (out) out.textContent = txt;
  } catch (err) {
    if (out) out.textContent = 'Integrity check error.';
  }
}

/* =============================================================================
 * TAB 8: AUDIT LEDGER
 * ============================================================================= */
async function loadAuditLogs() {
  const tbody = document.getElementById('auditTableBody');
  if (!tbody) return;
  try {
    const res = await fetch('/api/admin/audit', { headers: getAuthHeaders() });
    const logs = await res.json();
    tbody.innerHTML = '';
    if (!Array.isArray(logs) || logs.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" class="text-muted" style="text-align:center;">No audit records found.</td></tr>';
      return;
    }
    logs.forEach(l => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><strong>#${l.seq}</strong></td>
        <td>${l.timestamp}</td>
        <td><strong>${l.event}</strong></td>
        <td>${l.actor}</td>
        <td><span class="badge state-${(l.severity || 'low').toLowerCase()}">${l.severity}</span></td>
        <td>${l.details}</td>
        <td><code>${(l.hmac_signature || '').substring(0, 16)}...</code></td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {}
}

async function runLedgerVerification() {
  const resBox = document.getElementById('ledgerVerifyResult');
  const ovBadge = document.getElementById('ovLedgerStatus');
  if (resBox) {
    resBox.className = 'alert';
    resBox.textContent = 'Verifying HMAC chain...';
    resBox.classList.remove('hidden');
  }

  try {
    const res = await fetch('/api/admin/audit/verify', {
      method: 'POST',
      headers: getAuthHeaders()
    });
    const data = await res.json();

    if (data.chain_valid) {
      if (resBox) {
        resBox.className = 'alert alert-success';
        resBox.textContent = `✅ HMAC Audit Chain Valid: All ${data.total_records} cryptographic audit records verified without tampering.`;
      }
      if (ovBadge) {
        ovBadge.className = 'badge-verified';
        ovBadge.textContent = 'Ledger Intact';
      }
    } else {
      if (resBox) {
        resBox.className = 'alert alert-error';
        resBox.textContent = `❌ AUDIT CHAIN CORRUPTED: Tampering detected at record sequence #${data.tampered_record_seq}!`;
      }
      if (ovBadge) {
        ovBadge.className = 'badge state-closed';
        ovBadge.textContent = 'Tamper Alert';
      }
    }
  } catch (err) {
    if (resBox) resBox.textContent = 'Verification error.';
  }
}

/* =============================================================================
 * TAB 9: BACKUP & RECOVERY
 * ============================================================================= */
async function loadBackups() {
  const tbody = document.getElementById('backupsTableBody');
  if (!tbody) return;
  try {
    const res = await fetch('/api/admin/backups', { headers: getAuthHeaders() });
    const data = await res.json();
    tbody.innerHTML = '';
    const backups = data.backups || [];
    if (backups.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" class="text-muted" style="text-align:center;">No backups created yet.</td></tr>';
      return;
    }
    backups.forEach(b => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><strong>📁 ${b.filename}</strong></td>
        <td>${b.created_at || 'Confirmed'}</td>
        <td>${b.size_kb || 0} KB</td>
        <td><code>${b.sha256 ? b.sha256.substring(0, 16) + '...' : 'Verified'}</code></td>
        <td class="action-cell">
          <button type="button" class="btn-sm btn-warning" onclick="handleRestoreBackup('${b.filename}')">Restore</button>
        </td>
      `;
      tbody.appendChild(tr);
    });
  } catch (err) {}
}

async function handleCreateBackup() {
  const resBox = document.getElementById('backupActionResult');
  if (resBox) {
    resBox.className = 'alert';
    resBox.textContent = 'Creating cryptographic backup archive...';
    resBox.classList.remove('hidden');
  }

  try {
    const res = await fetch('/api/admin/backup/create', {
      method: 'POST',
      headers: getAuthHeaders()
    });
    const data = await res.json();
    if (res.ok && data.success) {
      if (resBox) {
        resBox.className = 'alert alert-success';
        resBox.textContent = `✅ Backup created: ${data.archive}`;
      }
      loadBackups();
    } else {
      if (resBox) {
        resBox.className = 'alert alert-error';
        resBox.textContent = `❌ Backup failed: ${data.message || 'Operation error'}`;
      }
    }
  } catch (err) {
    if (resBox) resBox.textContent = 'Network error.';
  }
}

async function handleRestoreBackup(archiveName) {
  if (!confirm(`Are you SURE you want to restore backup '${archiveName}'?\nAll current active state will be reverted to this snapshot after SHA-256 verification.`)) return;

  try {
    const res = await fetch('/api/admin/backup/restore', {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ archive: archiveName })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      alert('Backup verified and restored successfully! Reloading data...');
      loadAllData();
    } else {
      alert(`Restore rejected: ${data.message || 'Checksum verification failed.'}`);
    }
  } catch (err) {
    alert('Network error restoring backup.');
  }
}

/* =============================================================================
 * TAB 10: REPORTS
 * ============================================================================= */
function exportPdfReport() {
  window.open(`/api/admin/report/pdf?election_id=${adminSelectedElectionId}`, '_blank');
}

function exportCsvReport() {
  window.open(`/api/admin/report/csv?election_id=${adminSelectedElectionId}`, '_blank');
}
