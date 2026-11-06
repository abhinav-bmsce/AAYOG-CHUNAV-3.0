/**
 * ============================================================================
 * Title:       AAYOG_CHUNAV 3.0 - Multi-Election Frontend Controller
 * File:        public/app.js
 * Description: Client-side logic for the dynamic multi-election voting interface,
 *              anonymous 2FA voting, ballot receipt verification, and real-time
 *              analytics polling.
 * ============================================================================
 */

let activeElectionId = 1;
let currentElectionInfo = null;
let selectedCandidateId = null;
let selectedCandidateName = null;
let autoRefreshTimer = null;
let isOtpVerified = false;
let currentSimulatedOtp = '';
let currentVoterBoothId = 1;

document.addEventListener('DOMContentLoaded', async () => {
  await loadElectionsList();
  await loadElectionData();
  /* Poll every 3 seconds for live multi-client updates */
  autoRefreshTimer = setInterval(loadResults, 3000);
});

/**
 * Fetch list of all elections from backend and populate dropdown
 */
async function loadElectionsList() {
  try {
    const res = await fetch('/api/elections');
    if (!res.ok) return;
    const elections = await res.json();
    const select = document.getElementById('electionSelect');
    if (!select || !Array.isArray(elections) || elections.length === 0) return;

    select.innerHTML = '';
    elections.forEach(el => {
      const opt = document.createElement('option');
      opt.value = el.id;
      opt.textContent = `#${el.id}: ${el.title} [${el.status_str}]`;
      if (el.id === activeElectionId) opt.selected = true;
      select.appendChild(opt);
    });

    if (elections.some(e => e.id === activeElectionId)) {
      // keep current active
    } else if (elections.length > 0) {
      activeElectionId = elections[0].id;
    }
  } catch (err) {
    console.error('Failed to load elections list:', err);
  }
}

/**
 * Handle user changing active election from dropdown
 */
async function changeElection(newId) {
  activeElectionId = parseInt(newId, 10) || 1;
  selectedCandidateId = null;
  selectedCandidateName = null;
  isOtpVerified = false;
  currentSimulatedOtp = '';
  onVoterIdChange();
  clearAlert();
  document.getElementById('receiptBox').classList.add('hidden');
  document.getElementById('verifyResultBox').classList.add('hidden');

  // Update footer links
  const pdfLink = document.getElementById('footerPdfLink');
  const csvLink = document.getElementById('footerCsvLink');
  if (pdfLink) pdfLink.href = `/api/admin/report/pdf?election_id=${activeElectionId}`;
  if (csvLink) csvLink.href = `/api/admin/report/csv?election_id=${activeElectionId}`;

  await loadElectionData();
}

/**
 * Load complete election details, candidates, and live results
 */
async function loadElectionData() {
  try {
    // 1. Fetch Election Info
    const infoRes = await fetch(`/api/election/info?id=${activeElectionId}`);
    if (infoRes.ok) {
      currentElectionInfo = await infoRes.json();
      updateElectionMetaCard(currentElectionInfo);
    }

    // 2. Fetch Candidates
    await loadCandidates();

    // 3. Fetch Live Results
    await loadResults();
  } catch (err) {
    console.error('Error loading election data:', err);
  }
}

/**
 * Update active election metadata cards and badges
 */
function updateElectionMetaCard(info) {
  if (!info) return;

  const titleEl = document.getElementById('metaElectionTitle');
  const descEl = document.getElementById('metaElectionDesc');
  const typeEl = document.getElementById('metaElectionType');
  const statusEl = document.getElementById('metaElectionStatus');
  const votersEl = document.getElementById('metaTotalVoters');
  const votesEl = document.getElementById('metaTotalVotes');
  const otpEl = document.getElementById('metaRequireOtp');
  const badgeText = document.getElementById('electionStatusText');
  const badgeBox = document.getElementById('electionStatusBadge');

  if (titleEl) titleEl.textContent = info.title || 'Election';
  if (descEl) descEl.textContent = info.description || 'Secure digital voting session.';
  if (typeEl) typeEl.textContent = (info.election_type || 'GENERAL').toUpperCase();
  if (statusEl) statusEl.textContent = info.status_str || 'ACTIVE';
  if (votersEl) votersEl.textContent = `${info.total_voters || 0} Registered`;
  if (votesEl) votesEl.textContent = `${info.total_votes || 0} Ballots`;
  if (otpEl) otpEl.textContent = info.require_otp ? 'Required (2FA OTP)' : 'Disabled (Direct)';

  if (badgeText) badgeText.textContent = info.status_str || 'ACTIVE';
  if (badgeBox) {
    if (info.status_str === 'ACTIVE') {
      badgeBox.className = 'server-badge active';
    } else if (info.status_str === 'PAUSED') {
      badgeBox.className = 'server-badge paused';
    } else {
      badgeBox.className = 'server-badge closed';
    }
  }

  // Cast vote button lock if inactive
  const castBtn = document.getElementById('castVoteBtn');
  if (castBtn) {
    if (info.status_str !== 'ACTIVE') {
      castBtn.disabled = true;
      castBtn.textContent = `Voting ${info.status_str || 'Unavailable'}`;
    } else {
      castBtn.disabled = false;
      castBtn.innerHTML = '<span class="btn-icon">🗳️</span> Submit Official Secret Ballot';
    }
  }
}

/**
 * Fetch candidates and render dynamic cards
 */
async function loadCandidates() {
  const container = document.getElementById('candidateCards');
  if (!container) return;

  try {
    const res = await fetch(`/api/candidates?election_id=${activeElectionId}`);
    if (!res.ok) {
      container.innerHTML = '<p class="text-muted">Unable to load candidates.</p>';
      return;
    }
    const candidates = await res.json();
    if (!Array.isArray(candidates) || candidates.length === 0) {
      container.innerHTML = '<div class="no-data-card"><p>No candidates registered for this election yet.</p></div>';
      return;
    }

    container.innerHTML = '';
    candidates.forEach((cand, idx) => {
      const card = document.createElement('div');
      card.className = `candidate-card ${selectedCandidateId === cand.id ? 'selected' : ''}`;
      card.id = `card-${cand.id}`;
      card.onclick = () => selectCandidate(cand.id, cand.name);

      let partyClass = 'party-others';
      if (cand.party.includes('BJP')) partyClass = 'party-bjp';
      else if (cand.party.includes('INC') || cand.party.includes('Congress')) partyClass = 'party-inc';

      // Fallback photo or avatar
      const photoSrc = cand.photo || cand.photo_url || '/images/others.png';
      const photoHtml = `<img src="${photoSrc}" alt="${cand.name}" class="candidate-photo" onerror="this.onerror=null; this.src='/images/others.png';">`;

      card.innerHTML = `
        <div class="card-radio">
          <input type="radio" name="candidate" id="cand-${cand.id}" value="${cand.id}" ${selectedCandidateId === cand.id ? 'checked' : ''}>
          <label for="cand-${cand.id}"></label>
        </div>
        <div class="avatar-wrapper">
          ${photoHtml}
        </div>
        <h3 class="candidate-name">${cand.name.toUpperCase()}</h3>
        <span class="party-tag ${partyClass}">${cand.party}</span>
        <div class="card-footer">
          <span class="ballot-no">Ballot #${cand.id}</span>
          <span class="select-hint">${selectedCandidateId === cand.id ? 'Selected ✔' : 'Click to Select'}</span>
        </div>
      `;
      container.appendChild(card);
    });
  } catch (err) {
    console.error('Error rendering candidates:', err);
    container.innerHTML = '<p class="text-muted">Failed to load candidate list.</p>';
  }
}

/**
 * Handle candidate card selection
 */
function selectCandidate(id, name) {
  selectedCandidateId = id;
  selectedCandidateName = name;

  const radio = document.getElementById(`cand-${id}`);
  if (radio) radio.checked = true;

  document.querySelectorAll('.candidate-card').forEach(card => card.classList.remove('selected'));
  const activeCard = document.getElementById(`card-${id}`);
  if (activeCard) activeCard.classList.add('selected');

  const preview = document.getElementById('selectedPreview');
  preview.innerHTML = `<span class="selected-name-badge">Ballot #${id}: ${name}</span>`;

  clearAlert();
}

/**
 * Populates ID input from quick helper tags
 */
function selectQuickId(id) {
  const input = document.getElementById('voterIdInput');
  input.value = id;
  onVoterIdChange();
  verifyVoterId();
}

/**
 * Reset status message on manual input typing
 */
function onVoterIdChange() {
  const statusEl = document.getElementById('idStatusText');
  if (statusEl) {
    statusEl.textContent = '';
    statusEl.className = 'status-msg';
  }

  /* Hide OTP and booth on ID change */
  const otpGroup = document.getElementById('otpGroup');
  if (otpGroup) otpGroup.style.display = 'none';

  const simBox = document.getElementById('otpSimulatedBox');
  if (simBox) simBox.style.display = 'none';
  currentSimulatedOtp = '';

  const boothContainer = document.getElementById('boothBadgeContainer');
  if (boothContainer) boothContainer.classList.add('hidden');

  isOtpVerified = false;
  const otpInp = document.getElementById('otpInput');
  if (otpInp) { otpInp.value = ''; otpInp.disabled = false; }

  const vBtn = document.getElementById('verifyOtpBtn');
  if (vBtn) { vBtn.textContent = 'Verify OTP'; vBtn.className = 'btn-accent'; }
}

/**
 * Verifies voter eligibility and requests Two-Factor Authentication OTP
 */
async function verifyVoterId() {
  const input = document.getElementById('voterIdInput');
  const voterId = input.value.trim().toUpperCase();
  const statusEl = document.getElementById('idStatusText');
  const boothContainer = document.getElementById('boothBadgeContainer');
  const boothText = document.getElementById('assignedBoothText');
  const checkBtn = document.getElementById('checkIdBtn');
  const otpGroup = document.getElementById('otpGroup');
  const otpStatus = document.getElementById('otpStatusText');
  const simBox = document.getElementById('otpSimulatedBox');
  const simDisplay = document.getElementById('simulatedOtpDisplay');

  if (!voterId) {
    statusEl.textContent = 'Please enter a Voter ID to verify (e.g. V101).';
    statusEl.className = 'status-msg error';
    return;
  }

  statusEl.textContent = 'Verifying voter ID and requesting OTP...';
  statusEl.className = 'status-msg';
  checkBtn.disabled = true;

  try {
    const res = await fetch('/api/otp/request', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ voter_id: voterId, election_id: activeElectionId })
    });

    let data;
    try {
      data = await res.json();
    } catch (parseErr) {
      statusEl.textContent = `❌ Server returned HTTP ${res.status}: Invalid response format.`;
      statusEl.className = 'status-msg error';
      otpGroup.style.display = 'none';
      if (simBox) simBox.style.display = 'none';
      return;
    }

    if (data.success) {
      statusEl.textContent = `✅ Voter ID '${voterId}' (${data.name || 'Eligible Voter'}) is verified!`;
      statusEl.className = 'status-msg success';

      if (data.booth_name) {
        currentVoterBoothId = data.booth_id || 1;
        boothText.textContent = `${data.booth_name} (Station #${currentVoterBoothId})`;
        boothContainer.classList.remove('hidden');
      }

      otpGroup.style.display = 'block';
      if (data.development_mode && (data.simulated_otp || data.demo_otp)) {
        currentSimulatedOtp = data.simulated_otp || data.demo_otp;
        if (simDisplay) simDisplay.textContent = currentSimulatedOtp;
        if (simBox) simBox.style.display = 'flex';
        otpStatus.textContent = 'Demo passcode generated. Enter 6-digit OTP code below:';
      } else {
        currentSimulatedOtp = '';
        if (simBox) simBox.style.display = 'none';
        otpStatus.textContent = data.message || 'Passcode dispatched to your registered SMS/Email. Enter code below:';
      }
      otpStatus.className = 'status-msg';
    } else if (data.error === 'ALREADY_VOTED') {
      statusEl.textContent = `⚠️ Voter ID '${voterId}' has ALREADY VOTED in this election at ${data.voted_at || 'an earlier session'}. Duplicate voting blocked.`;
      statusEl.className = 'status-msg warning';
      otpGroup.style.display = 'none';
      if (simBox) simBox.style.display = 'none';
    } else if (data.error === 'NOT_FOUND') {
      statusEl.textContent = `❌ Voter ID '${voterId}' was not found in the authorized voter roll for this election.`;
      statusEl.className = 'status-msg error';
      otpGroup.style.display = 'none';
      if (simBox) simBox.style.display = 'none';
    } else {
      statusEl.textContent = `❌ ${data.message || data.error || 'Failed to dispatch OTP passcode.'}`;
      statusEl.className = 'status-msg error';
      otpGroup.style.display = 'none';
      if (simBox) simBox.style.display = 'none';
    }
  } catch (err) {
    console.error('OTP request error:', err);
    statusEl.textContent = '❌ Failed to reach election server for OTP dispatch. Check connection.';
    statusEl.className = 'status-msg error';
    otpGroup.style.display = 'none';
    if (simBox) simBox.style.display = 'none';
  } finally {
    checkBtn.disabled = false;
  }
}

/**
 * Autofills simulated OTP for convenient demonstration
 */
function autofillOtp() {
  if (currentSimulatedOtp) {
    document.getElementById('otpInput').value = currentSimulatedOtp;
    verifyOtpCode();
  }
}

/**
 * Verifies 2FA OTP code with server
 */
async function verifyOtpCode() {
  const voterId = document.getElementById('voterIdInput').value.trim().toUpperCase();
  const otpInput = document.getElementById('otpInput');
  const otpCode = otpInput.value.trim();
  const statusEl = document.getElementById('otpStatusText');
  const btn = document.getElementById('verifyOtpBtn');

  if (!otpCode || otpCode.length < 4) {
    statusEl.textContent = 'Please enter a valid 6-digit OTP.';
    statusEl.className = 'status-msg error';
    return;
  }

  btn.disabled = true;
  btn.textContent = 'Verifying...';

  try {
    const res = await fetch('/api/otp/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ voter_id: voterId, otp: otpCode, election_id: activeElectionId })
    });
    const data = await res.json();

    if (data.success) {
      isOtpVerified = true;
      statusEl.textContent = '✅ Two-Factor Authentication Verified! You may now cast your secret ballot.';
      statusEl.className = 'status-msg success';
      btn.textContent = 'Verified ✔';
      btn.className = 'btn-accent verified';
      otpInput.disabled = true;
    } else {
      isOtpVerified = false;
      statusEl.textContent = `❌ ${data.message || 'Invalid OTP code.'}`;
      statusEl.className = 'status-msg error';
      btn.textContent = 'Verify OTP';
    }
  } catch (err) {
    statusEl.textContent = 'Network error verifying OTP.';
    statusEl.className = 'status-msg error';
    btn.textContent = 'Verify OTP';
  } finally {
    btn.disabled = false;
  }
}

/**
 * Submits the ballot with Ballot Secrecy Guarantee
 */
async function submitVote(event) {
  event.preventDefault();
  clearAlert();

  const voterId = document.getElementById('voterIdInput').value.trim().toUpperCase();
  const submitBtn = document.getElementById('castVoteBtn');
  const otpInput = document.getElementById('otpInput');
  const otpVal = otpInput ? otpInput.value.trim() : '';

  if (!voterId) {
    showAlert('error', 'Please enter your registered Voter ID.');
    document.getElementById('voterIdInput').focus();
    return;
  }

  if (!selectedCandidateId) {
    showAlert('error', 'Please select a candidate by clicking one of the cards above.');
    return;
  }

  if (currentElectionInfo && currentElectionInfo.require_otp && !isOtpVerified) {
    showAlert('error', 'Please complete Two-Factor Authentication (OTP) verification before casting your ballot.');
    if (document.getElementById('otpGroup').style.display === 'none') {
      verifyVoterId();
    } else {
      document.getElementById('otpInput').focus();
    }
    return;
  }

  submitBtn.disabled = true;
  submitBtn.innerHTML = '<span class="spinner"></span> Securing Ballot Transmission...';

  try {
    const res = await fetch('/api/vote', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        voter_id: voterId,
        candidate_id: selectedCandidateId,
        booth_id: currentVoterBoothId,
        election_id: activeElectionId,
        otp: otpVal
      })
    });

    const data = await res.json();

    if (res.ok && data.success) {
      showAlert('success', `🎉 Ballot recorded successfully! Your vote has been officially registered.`);
      
      // Display Cryptographic Receipt
      const receiptBox = document.getElementById('receiptBox');
      const tokenCode = document.getElementById('receiptTokenCode');
      const timestampEl = document.getElementById('receiptTimestamp');

      if (tokenCode) tokenCode.textContent = data.receipt_token || 'BLT-VERIFIED';
      if (timestampEl) timestampEl.textContent = new Date().toLocaleString();
      if (receiptBox) {
        receiptBox.classList.remove('hidden');
        receiptBox.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }

      // Reset form controls
      document.getElementById('voterIdInput').value = '';
      onVoterIdChange();
      await loadResults();
      await loadElectionData();
    } else if (res.status === 409) {
      showAlert('warning', `⚠️ DUPLICATE VOTE BLOCKED: ${data.message || 'This voter ID has already participated in this election.'}`);
    } else {
      showAlert('error', `❌ ${data.message || 'Ballot submission rejected.'}`);
    }
  } catch (err) {
    console.error('Vote submission error:', err);
    showAlert('error', '❌ Network error submitting ballot. Check your HTTPS connection.');
  } finally {
    submitBtn.disabled = false;
    submitBtn.innerHTML = '<span class="btn-icon">🗳️</span> Submit Official Secret Ballot';
  }
}

/**
 * Copies the receipt token to clipboard
 */
function copyReceiptToken() {
  const token = document.getElementById('receiptTokenCode').textContent;
  navigator.clipboard.writeText(token).then(() => {
    alert('Cryptographic Receipt Token copied to clipboard!\nKeep it safe to verify ballot integrity.');
  });
}

/**
 * Anonymous Ballot Receipt Verification
 */
async function verifyReceiptTokenAction() {
  const tokenInput = document.getElementById('verifyTokenInput');
  const token = tokenInput.value.trim();
  const resultBox = document.getElementById('verifyResultBox');

  if (!token) {
    alert('Please enter or paste a valid Ballot Receipt Token (BLT-...).');
    tokenInput.focus();
    return;
  }

  resultBox.className = 'verifier-result-card';
  resultBox.innerHTML = '<p class="text-muted">Querying official cryptographic ballot ledger...</p>';
  resultBox.classList.remove('hidden');

  try {
    const res = await fetch(`/api/receipt/verify?token=${encodeURIComponent(token)}&election_id=${activeElectionId}`);
    const data = await res.json();

    if (res.ok && data.recorded) {
      resultBox.className = 'verifier-result-card success';
      resultBox.innerHTML = `
        <div class="result-headline">
          <span class="icon">✅</span>
          <strong>OFFICIALLY RECORDED IN BALLOT BOX</strong>
        </div>
        <p class="result-detail">
          Token <code>${data.receipt_token}</code> exists in the tamper-evident ballot box for <strong>${data.election_title || 'Election'}</strong>.
        </p>
        <div class="result-meta-grid">
          <div><span>Recorded At:</span> <strong>${data.recorded_at || 'Confirmed'}</strong></div>
          <div><span>Station / Booth:</span> <strong>Booth #${data.booth_id || 1}</strong></div>
          <div><span>Ballot Secrecy:</span> <strong>Candidate Selection Encrypted & Decoupled</strong></div>
        </div>
      `;
    } else {
      resultBox.className = 'verifier-result-card error';
      resultBox.innerHTML = `
        <div class="result-headline">
          <span class="icon">❌</span>
          <strong>RECEIPT TOKEN NOT FOUND</strong>
        </div>
        <p class="result-detail">
          No ballot matching token <code>${token}</code> was found in Election #${activeElectionId}. Please verify the token format and selected election.
        </p>
      `;
    }
  } catch (err) {
    resultBox.className = 'verifier-result-card error';
    resultBox.innerHTML = `<p>Network error connecting to verification engine.</p>`;
  }
}

let lastDeclaredResults = {};
let dismissedWinnerModals = {};

/**
 * Requests and renders live election results & real-time percentage shares
 */
async function loadResults() {
  try {
    const res = await fetch(`/api/results?election_id=${activeElectionId}`);
    if (!res.ok) return;

    const data = await res.json();
    const totalVotes = data.total_votes || 0;
    const totalReg = data.total_registered || 0;
    const turnoutPct = (data.turnout_pct !== undefined) ? data.turnout_pct : (totalReg > 0 ? ((totalVotes / totalReg) * 100).toFixed(1) : 0);

    // Stat card updates
    const votesEl = document.getElementById('totalVotesCount');
    const leaderEl = document.getElementById('leadingCandidateName');
    const regEl = document.getElementById('totalRegisteredCount');
    const turnoutEl = document.getElementById('turnoutPercentage');
    const winnerBanner = document.getElementById('winnerBanner');
    const winnerBannerName = document.getElementById('winnerBannerName');
    const legendEl = document.getElementById('resultsSealedLegend');
    const barsContainer = document.getElementById('resultsBars');

    if (votesEl) votesEl.textContent = totalVotes;
    if (regEl) regEl.textContent = `${totalReg} Voters`;
    if (turnoutEl) turnoutEl.textContent = `${turnoutPct}%`;

    if (!data.results_declared) {
      // =========================================================================
      // SEALED STATE: While active or closed, prior to official declaration
      // Voters must NOT see candidate-wise counts or leading candidate
      // =========================================================================
      if (leaderEl) {
        leaderEl.textContent = '🔒 Sealed by Commission';
        leaderEl.className = 'stat-value sealed';
      }
      if (legendEl) {
        legendEl.textContent = 'Ballot tallies strictly sealed until official declaration';
      }
      if (winnerBanner) {
        winnerBanner.classList.add('hidden');
      }

      if (barsContainer) {
        barsContainer.innerHTML = `
          <div class="results-sealed-card">
            <div class="sealed-lock-icon">🔒</div>
            <h3 class="sealed-heading">BALLOT TALLIES STRICTLY SEALED</h3>
            <p class="sealed-desc">Candidate-wise vote counts and leader standings are held in the cryptographic vault to guarantee ballot secrecy and prevent voter bias during polling.</p>
            <div class="sealed-badge">Total Ballots Cast: <strong>${totalVotes}</strong> &bull; Turnout: <strong>${turnoutPct}%</strong></div>
          </div>
        `;
      }
      return;
    }

    // =========================================================================
    // DECLARED STATE: Admin has declared official election results
    // Results published: Candidates, photos, votes, percentages, winner announcement
    // =========================================================================
    lastDeclaredResults[activeElectionId] = data;

    if (legendEl) {
      legendEl.textContent = 'Official certified results published by Election Commission';
    }

    // Leader / Tie text
    if (leaderEl) {
      if (data.is_tie && totalVotes > 0) {
        leaderEl.textContent = `🤝 ${data.leader || 'Contested Tie'}`;
        leaderEl.className = 'stat-value tie';
      } else if (totalVotes > 0 && data.leader) {
        leaderEl.textContent = `🏆 ${data.leader}`;
        leaderEl.className = 'stat-value leader';
      } else {
        leaderEl.textContent = '—';
        leaderEl.className = 'stat-value';
      }
    }

    // Winner Announcement Banner
    if (winnerBanner) {
      winnerBanner.classList.remove('hidden');
      if (winnerBannerName) {
        winnerBannerName.textContent = data.is_tie ? `🤝 Historic Tie: ${data.leader}` : `🏆 ${data.leader}`;
      }
    }

    // Automatically trigger Winner Announcement Modal once per election session
    if (!dismissedWinnerModals[activeElectionId] && totalVotes > 0) {
      showWinnerModal(data);
    }

    // Candidate distribution bars with photo thumbnails and percentages
    if (!barsContainer) return;

    if (!Array.isArray(data.candidates) || data.candidates.length === 0) {
      barsContainer.innerHTML = '<p class="text-muted" style="padding:20px;text-align:center;">No ballots recorded in this election.</p>';
      return;
    }

    barsContainer.innerHTML = '';
    data.candidates.forEach(cand => {
      const votes = cand.votes || 0;
      const pct = (cand.percentage !== undefined) ? cand.percentage : (totalVotes > 0 ? ((votes / totalVotes) * 100).toFixed(1) : 0);

      let barColor = '#4f46e5';
      if (cand.party && cand.party.includes('BJP')) barColor = '#ff9933';
      else if (cand.party && (cand.party.includes('INC') || cand.party.includes('Congress'))) barColor = '#10b981';
      else if (cand.party && cand.party.includes('Independent')) barColor = '#8b5cf6';

      const row = document.createElement('div');
      row.className = 'bar-row';
      const photoSrc = cand.photo_url || cand.photo || '/images/others.png';
      row.innerHTML = `
        <div class="bar-info">
          <div class="cand-info-group">
            <img src="${photoSrc}" class="result-cand-thumb" onerror="this.onerror=null; this.src='/images/others.png';" alt="${cand.name}">
            <span class="cand-label">${cand.name} <small class="text-muted">(${cand.party})</small></span>
          </div>
          <span class="cand-votes"><strong>${votes}</strong> votes (${pct}%)</span>
        </div>
        <div class="bar-track">
          <div class="bar-fill" style="width: ${pct}%; background-color: ${barColor};"></div>
        </div>
      `;
      barsContainer.appendChild(row);
    });
  } catch (err) {
    console.error('Failed to load live results:', err);
  }
}

/**
 * Display professional winner announcement modal
 */
function showWinnerModal(data) {
  const modal = document.getElementById('winnerModal');
  const modalTitle = document.getElementById('winnerModalTitle');
  const electionSub = document.getElementById('winnerElectionTitle');
  const modalBody = document.getElementById('winnerModalBody');
  if (!modal || !modalBody) return;

  const totalVotes = data.total_votes || 0;
  const turnout = data.turnout_pct || 0;
  if (electionSub) {
    electionSub.textContent = `${data.election_title || 'Election #' + activeElectionId} • Official Results`;
  }

  if (data.is_tie) {
    if (modalTitle) modalTitle.textContent = '⚖️ ELECTION RESULT: HISTORIC TIE DECLARED';
    modalBody.innerHTML = `
      <div class="tie-announcement-card">
        <div class="tie-badge">🤝 EQUAL HIGHEST VOTES</div>
        <h3 class="tie-headline">${data.leader || 'Multiple Candidates Tied'}</h3>
        <p class="tie-sub">Candidates have secured an exact tie in official counted ballots. Under election commission protocols, a contested runoff or tie-break procedure may be initiated.</p>
        <div class="winner-stats-grid">
          <div class="w-stat"><span>Tied Votes:</span> <strong>${data.winner_votes || 0}</strong></div>
          <div class="w-stat"><span>Total Votes Cast:</span> <strong>${totalVotes}</strong></div>
          <div class="w-stat"><span>Voter Turnout:</span> <strong>${turnout}%</strong></div>
          <div class="w-stat"><span>Secrecy Audit:</span> <strong style="color:#10b981;">100% Verified</strong></div>
        </div>
      </div>
    `;
  } else {
    if (modalTitle) modalTitle.textContent = '🏆 OFFICIAL ELECTION RESULTS DECLARED';
    const photo = data.winner_photo || '/images/others.png';
    const winnerName = data.leader || 'Candidate';
    const winnerParty = data.leader_party || 'Affiliated';
    const winnerVotes = data.winner_votes || 0;
    const winnerPct = totalVotes > 0 ? ((winnerVotes / totalVotes) * 100).toFixed(1) : 0;
    const margin = data.margin || 0;

    modalBody.innerHTML = `
      <div class="winner-profile-card">
        <div class="winner-photo-wrapper">
          <img src="${photo}" class="winner-modal-photo" onerror="this.onerror=null; this.src='/images/others.png';" alt="${winnerName}">
          <span class="winner-ribbon">WINNER 🏆</span>
        </div>
        <h3 class="winner-modal-name">${winnerName}</h3>
        <span class="party-tag winner-party">${winnerParty}</span>
        <div class="winner-vote-pill">
          <span>Secured: <strong>${winnerVotes} Votes</strong> (${winnerPct}%)</span>
          <span>•</span>
          <span>Lead Margin: <strong>+${margin} votes</strong></span>
        </div>
        <div class="winner-stats-grid">
          <div class="w-stat"><span>Total Ballots:</span> <strong>${totalVotes}</strong></div>
          <div class="w-stat"><span>Voter Turnout:</span> <strong>${turnout}%</strong></div>
          <div class="w-stat"><span>Runner Up:</span> <strong>${data.runner_up || 'None'} (${data.runner_up_votes || 0})</strong></div>
          <div class="w-stat"><span>Official Status:</span> <strong style="color:#10b981;">Certified Winner</strong></div>
        </div>
      </div>
    `;
  }

  modal.classList.remove('hidden');
}

/**
 * Closes the winner announcement modal
 */
function closeWinnerModal() {
  const modal = document.getElementById('winnerModal');
  if (modal) modal.classList.add('hidden');
  dismissedWinnerModals[activeElectionId] = true;
}

/**
 * Re-opens the winner announcement modal from the banner
 */
function openWinnerModal() {
  if (lastDeclaredResults[activeElectionId]) {
    showWinnerModal(lastDeclaredResults[activeElectionId]);
  } else {
    loadResults().then(() => {
      if (lastDeclaredResults[activeElectionId]) {
        showWinnerModal(lastDeclaredResults[activeElectionId]);
      }
    });
  }
}

/**
 * Display alert banner
 */
function showAlert(type, message) {
  const box = document.getElementById('alertBox');
  if (!box) return;
  box.className = `alert alert-${type}`;
  box.innerHTML = message;
  box.classList.remove('hidden');
}

/**
 * Clear alert banner
 */
function clearAlert() {
  const box = document.getElementById('alertBox');
  if (box) {
    box.className = 'alert hidden';
    box.innerHTML = '';
  }
}
