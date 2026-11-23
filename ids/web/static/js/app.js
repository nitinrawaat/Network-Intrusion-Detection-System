/**
 * AEGIS // Cyber Defense SOC Console v2.0
 * Real-time event streaming, Attack Topology Graph, Telemetry Timeline,
 * MITRE ATT&CK Framework Triage, Active IPS Quarantine & Multi-Vector Scenarios.
 */

(() => {
  'use strict';

  // Application State
  const state = {
    events: [],
    summary: {
      total_events: 0,
      by_severity: {},
      by_type: {},
      top_sources: [],
      mitre_matrix: {},
      quarantine_count: 0,
      active_quarantine_list: [],
      threat_level: 'NORMAL'
    },
    filter: {
      search: '',
      severity: '',
      type: ''
    },
    telemetryHistory: [], // Rolling history for time-series chart
    topologyNodes: [],    // Dynamic graph nodes for canvas topology
    topologyBeams: [],    // Active animated laser pulses
    audioEnabled: true,
    isStreamPaused: false,
    sseConnection: null,
    audioCtx: null,
    targetUrl: localStorage.getItem('ids_target_url') || ''
  };

  // Helper for remote backend URL routing
  function apiUrl(path) {
    if (!state.targetUrl) return path;
    const base = state.targetUrl.replace(/\/+$/, '');
    return `${base}${path}`;
  }

  // DOM Elements
  const el = {
    clock: document.getElementById('live-clock'),
    sseStatus: document.getElementById('sse-status-pill'),
    btnChangeTarget: document.getElementById('btn-change-target'),
    hudTargetUrl: document.getElementById('hud-target-url'),
    defconPill: document.getElementById('hud-threat-defcon'),
    defconText: document.getElementById('defcon-status-text'),
    totalCount: document.getElementById('stat-total-count'),
    criticalCount: document.getElementById('stat-critical-count'),
    highCount: document.getElementById('stat-high-count'),
    quarantineCount: document.getElementById('stat-quarantine-count'),
    barCritical: document.getElementById('bar-critical'),
    barHigh: document.getElementById('bar-high'),
    barQuarantine: document.getElementById('bar-quarantine'),
    tbody: document.getElementById('incident-tbody'),
    streamBadge: document.getElementById('incident-stream-badge'),
    quarantineContainer: document.getElementById('quarantine-container'),
    canvasTopology: document.getElementById('canvas-topology'),
    canvasTelemetry: document.getElementById('canvas-telemetry'),
    canvasVectors: document.getElementById('canvas-vectors'),
    canvasSeverity: document.getElementById('canvas-severity'),
    filterSearch: document.getElementById('filter-search'),
    filterSeverity: document.getElementById('filter-severity'),
    filterType: document.getElementById('filter-type'),
    btnOpenScenarios: document.getElementById('btn-open-scenarios'),
    btnExportCsv: document.getElementById('btn-export-csv'),
    btnConfig: document.getElementById('btn-config'),
    btnClear: document.getElementById('btn-clear-db'),
    btnPause: document.getElementById('btn-pause-stream'),
    btnAudio: document.getElementById('btn-audio-toggle'),
    iconSoundOn: document.getElementById('icon-sound-on'),
    iconSoundOff: document.getElementById('icon-sound-off'),
    toastContainer: document.getElementById('toast-container'),
    btnRefreshQuarantine: document.getElementById('btn-refresh-quarantine'),
    // Modals
    scenarioModal: document.getElementById('scenario-modal'),
    btnCloseScenario: document.getElementById('btn-close-scenario'),
    forensicsModal: document.getElementById('forensics-modal'),
    forensicBody: document.getElementById('forensic-body'),
    btnCloseForensic: document.getElementById('btn-close-forensic'),
    configModal: document.getElementById('config-modal'),
    btnCloseConfig: document.getElementById('btn-close-config'),
    btnCancelConfig: document.getElementById('btn-cancel-config'),
    btnSaveConfig: document.getElementById('btn-save-config'),
    // Config fields
    cfgPsPorts: document.getElementById('cfg-ps-ports'),
    cfgPsWindow: document.getElementById('cfg-ps-window'),
    cfgUdpPorts: document.getElementById('cfg-udp-ports'),
    cfgUdpWindow: document.getElementById('cfg-udp-window'),
    cfgSynThresh: document.getElementById('cfg-syn-thresh'),
    cfgSynWindow: document.getElementById('cfg-syn-window'),
    cfgAlertMin: document.getElementById('cfg-alert-min'),
    cfgAlertDedup: document.getElementById('cfg-alert-dedup'),
    cfgAlertRate: document.getElementById('cfg-alert-rate')
  };

  // ---------------------------------------------------------------------------
  // Audio Synthesizer (Zero External Audio Files)
  // ---------------------------------------------------------------------------
  function playAlertChime(severity) {
    if (!state.audioEnabled) return;
    try {
      if (!state.audioCtx) {
        state.audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      }
      if (state.audioCtx.state === 'suspended') {
        state.audioCtx.resume();
      }

      const ctx = state.audioCtx;
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.connect(gain);
      gain.connect(ctx.destination);

      const now = ctx.currentTime;

      if (severity === 'CRITICAL') {
        osc.type = 'sawtooth';
        osc.frequency.setValueAtTime(880, now);
        osc.frequency.setValueAtTime(1174.66, now + 0.1);
        gain.gain.setValueAtTime(0.2, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.35);
        osc.start(now);
        osc.stop(now + 0.35);
      } else if (severity === 'HIGH') {
        osc.type = 'sine';
        osc.frequency.setValueAtTime(659.25, now);
        gain.gain.setValueAtTime(0.15, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.25);
        osc.start(now);
        osc.stop(now + 0.25);
      } else {
        osc.type = 'triangle';
        osc.frequency.setValueAtTime(440, now);
        gain.gain.setValueAtTime(0.08, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.15);
        osc.start(now);
        osc.stop(now + 0.15);
      }
    } catch (e) {
      console.warn('Audio chime warning:', e);
    }
  }

  // ---------------------------------------------------------------------------
  // Clock HUD
  // ---------------------------------------------------------------------------
  function initClock() {
    function update() {
      const now = new Date();
      el.clock.textContent = now.toTimeString().split(' ')[0] + ' UTC';
    }
    update();
    setInterval(update, 1000);
  }

  // ---------------------------------------------------------------------------
  // Toast Notifications
  // ---------------------------------------------------------------------------
  function showToast(title, msg, severity = 'LOW') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${severity}`;
    toast.innerHTML = `
      <div>
        <div class="toast-title">${escapeHtml(title)}</div>
        <div class="toast-msg">${escapeHtml(msg)}</div>
      </div>
      <button class="modal-close" style="font-size:1.2rem;">&times;</button>
    `;

    toast.querySelector('button').addEventListener('click', () => toast.remove());
    el.toastContainer.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(100%)';
      setTimeout(() => toast.remove(), 300);
    }, 4500);
  }

  // ---------------------------------------------------------------------------
  // Data Fetching & Rendering
  // ---------------------------------------------------------------------------
  async function fetchSummary() {
    try {
      const res = await fetch(apiUrl('/api/summary'));
      if (!res.ok) return;
      const data = await res.json();
      state.summary = data;
      renderKPIs();
      renderDefcon();
      renderMitreMatrix();
      renderQuarantineTable();
      renderVectorChart();
      renderSeverityDonut();
      updateTopologyNodes();
    } catch (e) {
      console.error('Failed to fetch summary:', e);
    }
  }

  async function fetchEvents() {
    try {
      const res = await fetch(apiUrl('/api/events?limit=100'));
      if (!res.ok) return;
      const data = await res.json();
      state.events = data.events || [];
      renderTable();
    } catch (e) {
      console.error('Failed to fetch events:', e);
    }
  }

  function renderDefcon() {
    const level = state.summary.threat_level || 'NORMAL';
    el.defconText.textContent = level;
    el.defconPill.className = `hud-item defcon-pill defcon-${level}`;
  }

  function renderKPIs() {
    const total = state.summary.total_events || 0;
    const sev = state.summary.by_severity || {};
    const crit = sev['CRITICAL'] || 0;
    const high = sev['HIGH'] || 0;
    const quarantine = state.summary.quarantine_count || 0;

    animateCounter(el.totalCount, total);
    animateCounter(el.criticalCount, crit);
    animateCounter(el.highCount, high);
    if (el.quarantineCount) animateCounter(el.quarantineCount, quarantine);

    const critPct = total > 0 ? Math.min(100, (crit / total) * 100) : 0;
    const highPct = total > 0 ? Math.min(100, (high / total) * 100) : 0;

    el.barCritical.style.width = `${critPct}%`;
    el.barHigh.style.width = `${highPct}%`;
  }

  function animateCounter(elem, target) {
    if (!elem) return;
    const start = parseInt(elem.textContent) || 0;
    if (start === target) return;
    const duration = 400;
    const startTime = performance.now();

    function step(currentTime) {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const val = Math.floor(start + (target - start) * progress);
      elem.textContent = val.toLocaleString();
      if (progress < 1) {
        requestAnimationFrame(step);
      } else {
        elem.textContent = target.toLocaleString();
      }
    }
    requestAnimationFrame(step);
  }

  // ---------------------------------------------------------------------------
  // MITRE ATT&CK Matrix Rendering
  // ---------------------------------------------------------------------------
  function renderMitreMatrix() {
    const matrix = state.summary.mitre_matrix || {};
    const techniques = [
      { id: 'T1046', hitEl: document.getElementById('hit-T1046'), cardEl: document.getElementById('mitre-T1046') },
      { id: 'T1498.001', hitEl: document.getElementById('hit-T1498'), cardEl: document.getElementById('mitre-T1498') },
      { id: 'T1557.002', hitEl: document.getElementById('hit-T1557'), cardEl: document.getElementById('mitre-T1557') },
      { id: 'T1071.004', hitEl: document.getElementById('hit-T1071'), cardEl: document.getElementById('mitre-T1071') },
      { id: 'T1568.002', hitEl: document.getElementById('hit-T1568'), cardEl: document.getElementById('mitre-T1568') }
    ];

    techniques.forEach(t => {
      const count = matrix[t.id]?.count || 0;
      if (t.hitEl) t.hitEl.textContent = `${count} HITS`;
      if (t.cardEl) {
        if (count > 0) {
          t.cardEl.classList.add('has-hits');
        } else {
          t.cardEl.classList.remove('has-hits');
        }
      }
    });
  }

  // ---------------------------------------------------------------------------
  // Active Defense / IPS Quarantine Rendering
  // ---------------------------------------------------------------------------
  function renderQuarantineTable() {
    if (!el.quarantineContainer) return;
    const list = state.summary.active_quarantine_list || [];

    if (!list.length) {
      el.quarantineContainer.innerHTML = `
        <div class="empty-state" style="padding: 24px; text-align: center; color: var(--text-muted); font-size: 0.82rem;">
          🛡️ No attacker IP addresses currently under IPS quarantine.
        </div>
      `;
      return;
    }

    el.quarantineContainer.innerHTML = `
      <table class="quarantine-table">
        <thead>
          <tr>
            <th>BANNED IP</th>
            <th>SEVERITY</th>
            <th>REASON / MITIGATION</th>
            <th>ACTION</th>
          </tr>
        </thead>
        <tbody>
          ${list.map(item => `
            <tr>
              <td class="font-mono text-purple" style="font-weight:700;">${escapeHtml(item.ip)}</td>
              <td><span class="badge badge-${item.severity || 'HIGH'}">${item.severity || 'HIGH'}</span></td>
              <td style="color:var(--text-secondary); max-width:180px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${escapeHtml(item.reason)}">
                ${escapeHtml(item.reason)}
              </td>
              <td>
                <button class="btn-unblock" onclick="window.unblockIp('${escapeHtml(item.ip)}')">
                  Unblock
                </button>
              </td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    `;
  }

  window.unblockIp = async function(ip) {
    try {
      const res = await fetch(apiUrl('/api/quarantine/unblock'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
      });
      if (res.ok) {
        showToast('Firewall Rule Lifted', `IP address ${ip} released from quarantine`, 'LOW');
        fetchSummary();
      }
    } catch (e) {
      showToast('Error', 'Failed to unblock IP', 'HIGH');
    }
  };

  window.quarantineIp = async function(ip, reason = 'Manual SOC Quarantine') {
    if (!ip || ip.includes('Distributed') || ip.includes('Broadcast')) return;
    try {
      const res = await fetch(apiUrl('/api/quarantine'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, reason, severity: 'HIGH' })
      });
      if (res.ok) {
        showToast('IPS Quarantine Enforced', `Attacker IP ${ip} blocked at firewall`, 'HIGH');
        fetchSummary();
      }
    } catch (e) {
      showToast('Error', 'Failed to quarantine IP', 'HIGH');
    }
  };

  // ---------------------------------------------------------------------------
  // Interactive Network Attack Topology Visualizer (Canvas)
  // ---------------------------------------------------------------------------
  function initTopology() {
    const canvas = el.canvasTopology;
    if (!canvas) return;

    function renderTopology() {
      const ctx = canvas.getContext('2d');
      const w = canvas.width;
      const h = canvas.height;
      const centerX = w / 2;
      const centerY = h / 2;

      ctx.clearRect(0, 0, w, h);

      // Target Sensor Node (Center)
      ctx.save();
      ctx.beginPath();
      ctx.arc(centerX, centerY, 24, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(0, 242, 254, 0.15)';
      ctx.fill();
      ctx.lineWidth = 2;
      ctx.strokeStyle = '#00f2fe';
      ctx.shadowColor = '#00f2fe';
      ctx.shadowBlur = 15;
      ctx.stroke();

      // Pulsing radar ring
      const pulseTime = (Date.now() % 2000) / 2000;
      ctx.beginPath();
      ctx.arc(centerX, centerY, 24 + pulseTime * 20, 0, Math.PI * 2);
      ctx.strokeStyle = `rgba(0, 242, 254, ${1 - pulseTime})`;
      ctx.stroke();
      ctx.restore();

      // Target Label
      ctx.fillStyle = '#f8fafc';
      ctx.font = 'bold 10px JetBrains Mono';
      ctx.textAlign = 'center';
      ctx.fillText('SENSOR (192.168.1.50)', centerX, centerY + 38);

      // Attacker Nodes Orbiting
      const nodes = state.topologyNodes;
      const count = Math.max(nodes.length, 3);
      const orbitR = 90;

      nodes.forEach((node, idx) => {
        const angle = (idx / count) * Math.PI * 2 - Math.PI / 2;
        const nx = centerX + Math.cos(angle) * orbitR;
        const ny = centerY + Math.sin(angle) * orbitR;

        // Connection link
        ctx.beginPath();
        ctx.moveTo(nx, ny);
        ctx.lineTo(centerX, centerY);
        ctx.strokeStyle = node.isAttacking ? 'rgba(255, 0, 85, 0.35)' : 'rgba(255, 255, 255, 0.08)';
        ctx.lineWidth = node.isAttacking ? 2 : 1;
        ctx.stroke();

        // Attacker Node circle
        ctx.save();
        ctx.beginPath();
        ctx.arc(nx, ny, 12, 0, Math.PI * 2);
        ctx.fillStyle = node.isAttacking ? '#ff0055' : '#334155';
        ctx.shadowColor = node.isAttacking ? '#ff0055' : 'transparent';
        ctx.shadowBlur = node.isAttacking ? 12 : 0;
        ctx.fill();
        ctx.restore();

        // Node IP Label
        ctx.fillStyle = node.isAttacking ? '#ff0055' : '#94a3b8';
        ctx.font = '9px JetBrains Mono';
        ctx.textAlign = 'center';
        ctx.fillText(node.ip, nx, ny + (Math.sin(angle) > 0 ? 20 : -14));
      });

      // Animated Laser Beams
      const now = Date.now();
      state.topologyBeams = state.topologyBeams.filter(b => now - b.startTime < b.duration);

      state.topologyBeams.forEach(beam => {
        const progress = (now - beam.startTime) / beam.duration;
        const bx = beam.fromX + (centerX - beam.fromX) * progress;
        const by = beam.fromY + (centerY - beam.fromY) * progress;

        ctx.save();
        ctx.beginPath();
        ctx.arc(bx, by, 4, 0, Math.PI * 2);
        ctx.fillStyle = '#ff0055';
        ctx.shadowColor = '#ff0055';
        ctx.shadowBlur = 10;
        ctx.fill();
        ctx.restore();
      });

      requestAnimationFrame(renderTopology);
    }

    renderTopology();
  }

  function updateTopologyNodes() {
    const sources = state.summary.top_sources || [];
    const centerX = el.canvasTopology ? el.canvasTopology.width / 2 : 280;
    const centerY = el.canvasTopology ? el.canvasTopology.height / 2 : 130;
    const orbitR = 90;

    state.topologyNodes = sources.slice(0, 5).map((s, idx) => {
      const angle = (idx / Math.max(sources.length, 3)) * Math.PI * 2 - Math.PI / 2;
      return {
        ip: s.source_ip,
        count: s.count,
        isAttacking: true,
        x: centerX + Math.cos(angle) * orbitR,
        y: centerY + Math.sin(angle) * orbitR
      };
    });
  }

  function spawnAttackBeam(sourceIp) {
    const node = state.topologyNodes.find(n => n.ip === sourceIp);
    const canvas = el.canvasTopology;
    if (!canvas) return;

    const fromX = node ? node.x : Math.random() * canvas.width;
    const fromY = node ? node.y : 20;

    state.topologyBeams.push({
      fromX,
      fromY,
      startTime: Date.now(),
      duration: 500
    });
  }

  // ---------------------------------------------------------------------------
  // Real-Time Telemetry & Throughput Timeline (Canvas)
  // ---------------------------------------------------------------------------
  function initTelemetryTimeline() {
    const canvas = el.canvasTelemetry;
    if (!canvas) return;

    // Fill initial 30 seconds of rolling history
    const maxPoints = 30;
    for (let i = 0; i < maxPoints; i++) {
      state.telemetryHistory.push({ pps: 20 + Math.random() * 15, alerts: 0 });
    }

    // Polling / Tick update every second
    setInterval(async () => {
      try {
        const res = await fetch(apiUrl('/api/telemetry'));
        if (res.ok) {
          const tel = await res.json();
          // Add data point
          state.telemetryHistory.push({
            pps: tel.packets_per_second || 30,
            alerts: state.events.filter(e => e._isNew).length
          });
          if (state.telemetryHistory.length > maxPoints) {
            state.telemetryHistory.shift();
          }
          // Clear _isNew flag gradually
          state.events.forEach(e => { e._isNew = false; });
        }
      } catch (e) {
        // Fallback smooth oscillation
        state.telemetryHistory.push({ pps: 25 + Math.random() * 10, alerts: 0 });
        if (state.telemetryHistory.length > maxPoints) state.telemetryHistory.shift();
      }
    }, 1000);

    function renderTimeline() {
      const ctx = canvas.getContext('2d');
      const w = canvas.width;
      const h = canvas.height;
      const paddingX = 40;
      const paddingBottom = 30;
      const paddingTop = 20;
      const chartH = h - paddingBottom - paddingTop;
      const pts = state.telemetryHistory;

      ctx.clearRect(0, 0, w, h);

      // Gridlines
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
      ctx.lineWidth = 1;
      for (let i = 0; i <= 3; i++) {
        const y = h - paddingBottom - (chartH / 3) * i;
        ctx.beginPath();
        ctx.moveTo(paddingX, y);
        ctx.lineTo(w - 10, y);
        ctx.stroke();

        ctx.fillStyle = '#64748b';
        ctx.font = '10px JetBrains Mono';
        ctx.textAlign = 'right';
        ctx.fillText(Math.round(i * 50), paddingX - 8, y + 3);
      }

      if (pts.length < 2) {
        requestAnimationFrame(renderTimeline);
        return;
      }

      const stepX = (w - paddingX - 10) / (pts.length - 1);

      // Packet Rate Line (Cyan)
      ctx.beginPath();
      pts.forEach((p, idx) => {
        const x = paddingX + idx * stepX;
        const y = h - paddingBottom - (Math.min(p.pps, 150) / 150) * chartH;
        if (idx === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      ctx.strokeStyle = '#00f2fe';
      ctx.lineWidth = 2;
      ctx.shadowColor = 'rgba(0, 242, 254, 0.4)';
      ctx.shadowBlur = 8;
      ctx.stroke();
      ctx.shadowBlur = 0;

      // Incident Spikes Line (Crimson)
      ctx.beginPath();
      pts.forEach((p, idx) => {
        const x = paddingX + idx * stepX;
        const val = p.alerts * 25; // amplify for visibility
        const y = h - paddingBottom - (Math.min(val, 150) / 150) * chartH;
        if (idx === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      ctx.strokeStyle = '#ff0055';
      ctx.lineWidth = 2.5;
      ctx.shadowColor = 'rgba(255, 0, 85, 0.6)';
      ctx.shadowBlur = 10;
      ctx.stroke();
      ctx.shadowBlur = 0;

      // Legend
      ctx.fillStyle = '#00f2fe';
      ctx.font = '10px JetBrains Mono';
      ctx.textAlign = 'left';
      ctx.fillText('— Throughput (pkts/s)', paddingX + 10, 16);

      ctx.fillStyle = '#ff0055';
      ctx.fillText('— Threat Spikes', paddingX + 170, 16);

      requestAnimationFrame(renderTimeline);
    }

    renderTimeline();
  }

  // ---------------------------------------------------------------------------
  // Canvas Charts (Bar & Donut)
  // ---------------------------------------------------------------------------
  function renderVectorChart() {
    const canvas = el.canvasVectors;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const width = canvas.width;
    const height = canvas.height;

    ctx.clearRect(0, 0, width, height);

    const counts = state.summary.by_type || {};
    const getCount = (keys) => keys.reduce((sum, k) => sum + (counts[k] || 0), 0);
    const types = [
      { keys: ['TCP_PORT_SCAN', 'PORT_SCAN'], label: 'Port', color: '#00f2fe' },
      { keys: ['UDP_PORT_SCAN', 'UDP_SCAN'], label: 'UDP', color: '#38bdf8' },
      { keys: ['TCP_SYN_FLOOD', 'SYN_FLOOD'], label: 'SYN', color: '#ff0055' },
      { keys: ['ARP_SPOOFING', 'ARP_SPOOF'], label: 'ARP', color: '#f59e0b' },
      { keys: ['DNS_TUNNELING', 'DNS_NXDOMAIN_BURST', 'DNS_ANOMALY'], label: 'DNS', color: '#a855f7' }
    ];

    const maxVal = Math.max(...types.map(t => getCount(t.keys)), 10);
    const paddingX = 35;
    const paddingBottom = 30;
    const chartHeight = height - paddingBottom - 20;
    const barWidth = 32;
    const spacing = (width - paddingX * 2) / types.length;

    // Draw gridlines
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
    ctx.lineWidth = 1;
    for (let i = 0; i <= 3; i++) {
      const y = height - paddingBottom - (chartHeight / 3) * i;
      ctx.beginPath();
      ctx.moveTo(paddingX, y);
      ctx.lineTo(width - 10, y);
      ctx.stroke();

      ctx.fillStyle = '#64748b';
      ctx.font = '10px JetBrains Mono';
      ctx.textAlign = 'right';
      ctx.fillText(Math.round((maxVal / 3) * i), paddingX - 8, y + 3);
    }

    // Draw Bars
    types.forEach((t, idx) => {
      const val = getCount(t.keys);
      const barH = (val / maxVal) * chartHeight;
      const x = paddingX + idx * spacing + (spacing - barWidth) / 2;
      const y = height - paddingBottom - barH;

      ctx.shadowColor = t.color;
      ctx.shadowBlur = val > 0 ? 8 : 0;

      const grad = ctx.createLinearGradient(0, y, 0, y + barH);
      grad.addColorStop(0, t.color);
      grad.addColorStop(1, 'rgba(10, 20, 40, 0.3)');
      ctx.fillStyle = grad;

      ctx.beginPath();
      const r = Math.min(6, barH);
      ctx.roundRect ? ctx.roundRect(x, y, barWidth, barH, [r, r, 0, 0]) : ctx.rect(x, y, barWidth, barH);
      ctx.fill();
      ctx.shadowBlur = 0;

      if (val > 0) {
        ctx.fillStyle = '#f8fafc';
        ctx.font = 'bold 10px JetBrains Mono';
        ctx.textAlign = 'center';
        ctx.fillText(val, x + barWidth / 2, y - 4);
      }

      ctx.fillStyle = '#94a3b8';
      ctx.font = '10px Outfit';
      ctx.textAlign = 'center';
      ctx.fillText(t.label, x + barWidth / 2, height - paddingBottom + 16);
    });
  }

  function renderSeverityDonut() {
    const canvas = el.canvasSeverity;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const width = canvas.width;
    const height = canvas.height;

    ctx.clearRect(0, 0, width, height);

    const counts = state.summary.by_severity || {};
    const segments = [
      { label: 'Critical', val: counts['CRITICAL'] || 0, color: '#ff0055' },
      { label: 'High', val: counts['HIGH'] || 0, color: '#f59e0b' },
      { label: 'Medium', val: counts['MEDIUM'] || 0, color: '#eab308' },
      { label: 'Low', val: counts['LOW'] || 0, color: '#00f2fe' }
    ];

    const total = segments.reduce((sum, s) => sum + s.val, 0);
    const cx = width / 2;
    const cy = height / 2;
    const radius = 70;
    const innerRadius = 48;

    if (total === 0) {
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.08)';
      ctx.lineWidth = radius - innerRadius;
      ctx.beginPath();
      ctx.arc(cx, cy, (radius + innerRadius) / 2, 0, Math.PI * 2);
      ctx.stroke();

      ctx.fillStyle = '#64748b';
      ctx.font = '11px Outfit';
      ctx.textAlign = 'center';
      ctx.fillText('No alerts', cx, cy + 4);
      return;
    }

    let startAngle = -Math.PI / 2;
    segments.forEach(s => {
      if (s.val === 0) return;
      const sliceAngle = (s.val / total) * Math.PI * 2;
      const endAngle = startAngle + sliceAngle;

      ctx.save();
      ctx.shadowColor = s.color;
      ctx.shadowBlur = 8;

      ctx.beginPath();
      ctx.arc(cx, cy, radius, startAngle, endAngle);
      ctx.arc(cx, cy, innerRadius, endAngle, startAngle, true);
      ctx.closePath();
      ctx.fillStyle = s.color;
      ctx.fill();
      ctx.restore();

      startAngle = endAngle;
    });

    ctx.fillStyle = '#f8fafc';
    ctx.font = 'bold 20px JetBrains Mono';
    ctx.textAlign = 'center';
    ctx.fillText(total, cx, cy + 3);

    ctx.fillStyle = '#64748b';
    ctx.font = '9px Outfit';
    ctx.fillText('TOTAL', cx, cy + 16);
  }

  // ---------------------------------------------------------------------------
  // Incident Table & Filters
  // ---------------------------------------------------------------------------
  function renderTable() {
    const query = state.filter.search.toLowerCase();
    const filterSev = state.filter.severity;
    const filterType = state.filter.type;

    const filtered = state.events.filter(ev => {
      if (filterSev && ev.severity !== filterSev) return false;
      if (filterType && ev.event_type !== filterType) return false;
      if (query) {
        const text = `${ev.source_ip || ''} ${ev.destination_ip || ''} ${ev.event_type || ''} ${ev.description || ''} ${ev.detector || ''}`.toLowerCase();
        if (!text.includes(query)) return false;
      }
      return true;
    });

    el.streamBadge.textContent = `${filtered.length} / ${state.events.length} EVENTS`;

    if (!filtered.length) {
      el.tbody.innerHTML = `
        <tr class="empty-row">
          <td colspan="8">
            <div class="table-empty">
              <div class="pulse-radar-loader"></div>
              <div class="empty-text">No matching security events found.</div>
              <div class="empty-hint">Try adjusting search filters or launch attack simulation.</div>
            </div>
          </td>
        </tr>
      `;
      return;
    }

    el.tbody.innerHTML = filtered.map(ev => {
      const timeStr = formatTimestamp(ev.timestamp);
      const mitreId = ev.mitre?.technique_id || 'T1000';
      return `
        <tr class="${ev._isNew ? 'row-new' : ''}">
          <td class="font-mono" style="color: #94a3b8;">${timeStr}</td>
          <td><span class="badge badge-${ev.severity}">${ev.severity}</span></td>
          <td style="font-weight: 600;">${formatThreatType(ev.event_type)}</td>
          <td><span class="mitre-pill font-mono">${mitreId}</span></td>
          <td class="font-mono text-cyan" style="color: var(--accent-cyan); font-weight:600;">${escapeHtml(ev.source_ip || 'N/A')}</td>
          <td class="font-mono" style="color: #cbd5e1;">${escapeHtml(ev.destination_ip || 'Broadcast')}</td>
          <td style="max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(ev.description || '')}">
            ${escapeHtml(ev.description || 'Threat detected')}
          </td>
          <td style="text-align: center; white-space: nowrap;">
            <button class="btn btn-secondary btn-sm" onclick="window.inspectForensics('${ev.id || ev.timestamp}')" title="Inspect raw packet forensics">
              🔬 Inspect
            </button>
            <button class="btn-quarantine" onclick="window.quarantineIp('${escapeHtml(ev.source_ip)}', '${escapeHtml(ev.event_type)}')" title="Quarantine IP with IPS firewall rule">
              🛑 Block
            </button>
          </td>
        </tr>
      `;
    }).join('');
  }

  function formatTimestamp(ts) {
    if (!ts) return 'N/A';
    try {
      const d = new Date(ts);
      return d.toLocaleTimeString() + '.' + String(d.getMilliseconds()).padStart(3, '0');
    } catch {
      return String(ts).slice(11, 23);
    }
  }

  function formatThreatType(type) {
    const map = {
      'TCP_PORT_SCAN': 'TCP Port Scan',
      'PORT_SCAN': 'TCP Port Scan',
      'UDP_SCAN': 'UDP Port Probe',
      'UDP_PORT_SCAN': 'UDP Port Probe',
      'SYN_FLOOD': 'TCP SYN Flood',
      'TCP_SYN_FLOOD': 'TCP SYN Flood',
      'ARP_SPOOF': 'ARP Cache Poison',
      'ARP_SPOOFING': 'ARP Cache Poison',
      'DNS_ANOMALY': 'DNS Anomaly',
      'DNS_TUNNELING': 'DNS Tunneling C2',
      'DNS_NXDOMAIN_BURST': 'DNS NXDOMAIN Burst'
    };
    return map[type] || type;
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/[&<>"']/g, m => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    })[m]);
  }

  // ---------------------------------------------------------------------------
  // Server-Sent Events (SSE) Live Feed
  // ---------------------------------------------------------------------------
  function initSSE() {
    if (state.sseConnection) {
      state.sseConnection.close();
    }

    el.sseStatus.textContent = 'CONNECTING...';
    el.sseStatus.style.color = '#f59e0b';

    const source = new EventSource(apiUrl('/api/events/stream'));
    state.sseConnection = source;

    source.onopen = () => {
      el.sseStatus.textContent = 'CONNECTED';
      el.sseStatus.style.color = '#10b981';
    };

    source.onmessage = (e) => {
      if (!e.data || e.data.startsWith(':')) return;
      try {
        const event = JSON.parse(e.data);
        handleIncomingEvent(event);
      } catch (err) {
        console.warn('Error parsing incoming SSE:', err);
      }
    };

    source.onerror = () => {
      el.sseStatus.textContent = 'RECONNECTING';
      el.sseStatus.style.color = '#ff0055';
    };
  }

  function handleIncomingEvent(event) {
    event._isNew = true;
    if (!state.isStreamPaused) {
      state.events.unshift(event);
      if (state.events.length > 300) {
        state.events.pop();
      }
      renderTable();
    }

    // Trigger visual laser beam in topology graph
    spawnAttackBeam(event.source_ip);

    // Refresh summary metrics
    fetchSummary();

    // Trigger audio chime
    playAlertChime(event.severity);

    // Toast notification for critical/high threats
    if (event.severity === 'CRITICAL' || event.severity === 'HIGH') {
      showToast(
        `🚨 ${event.event_type} (${event.severity})`,
        `Source: ${event.source_ip || 'Unknown'} -> ${event.description || ''}`,
        event.severity
      );
    }
  }

  // ---------------------------------------------------------------------------
  // Forensics Inspector Modal (Required for test_web_api.py)
  // ---------------------------------------------------------------------------
  window.inspectForensics = function(identifier) {
    const ev = state.events.find(e => (e.id && String(e.id) === String(identifier)) || String(e.timestamp) === String(identifier));
    if (!ev) return;

    const evidenceJson = JSON.stringify(ev.evidence || {}, null, 2);
    const mitre = ev.mitre || {};

    el.forensicBody.innerHTML = `
      <div class="forensic-metric-grid">
        <div class="forensic-metric">
          <div class="forensic-label">THREAT VECTOR</div>
          <div class="forensic-val" style="color:var(--accent-cyan);">${formatThreatType(ev.event_type)}</div>
        </div>
        <div class="forensic-metric">
          <div class="forensic-label">SEVERITY LEVEL</div>
          <div class="forensic-val"><span class="badge badge-${ev.severity}">${ev.severity}</span></div>
        </div>
        <div class="forensic-metric">
          <div class="forensic-label">ATTACKER IP (SOURCE)</div>
          <div class="forensic-val font-mono" style="color:#38bdf8;">${escapeHtml(ev.source_ip || 'Unknown')}</div>
        </div>
        <div class="forensic-metric">
          <div class="forensic-label">TARGET IP (DESTINATION)</div>
          <div class="forensic-val font-mono">${escapeHtml(ev.destination_ip || 'Broadcast')}</div>
        </div>
      </div>

      <div class="forensic-metric-grid" style="margin-top:12px;">
        <div class="forensic-metric">
          <div class="forensic-label">MITRE TECHNIQUE ID</div>
          <div class="forensic-val font-mono text-cyan">${escapeHtml(mitre.technique_id || 'N/A')}</div>
        </div>
        <div class="forensic-metric">
          <div class="forensic-label">MITRE TACTIC</div>
          <div class="forensic-val">${escapeHtml(mitre.tactic || 'Discovery / Impact')}</div>
        </div>
      </div>

      <div class="forensic-metric" style="margin-top:12px;">
        <div class="forensic-label">DETECTOR ENGINE MODULE</div>
        <div class="forensic-val">${escapeHtml(ev.detector)}</div>
      </div>

      <div class="forensic-metric" style="margin-top:12px;">
        <div class="forensic-label">INCIDENT SUMMARY</div>
        <div class="forensic-val">${escapeHtml(ev.description)}</div>
      </div>

      <div style="margin-top:12px;">
        <div class="forensic-label" style="margin-bottom:6px;">RAW PACKET EVIDENCE & PROTOCOL TELEMETRY (JSON)</div>
        <div class="forensic-json-box">${escapeHtml(evidenceJson)}</div>
      </div>
    `;

    el.forensicsModal.classList.remove('hidden');
  };

  function closeForensics() {
    el.forensicsModal.classList.add('hidden');
  }

  // ---------------------------------------------------------------------------
  // Attack Scenario Launcher Modal
  // ---------------------------------------------------------------------------
  function openScenarioModal() {
    el.scenarioModal.classList.remove('hidden');
  }

  function closeScenarioModal() {
    el.scenarioModal.classList.add('hidden');
  }

  async function launchScenario(scenarioName) {
    closeScenarioModal();
    showToast('Attack Injected', `Launching scenario: ${scenarioName}...`, 'LOW');

    try {
      const res = await fetch(apiUrl('/api/simulate'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario: scenarioName })
      });
      const data = await res.json();
      if (!res.ok) {
        showToast('Error', data.error || 'Failed to launch scenario', 'HIGH');
      } else {
        showToast('Scenario Running', data.message || 'Adversarial traffic propagating', 'LOW');
      }
    } catch (e) {
      showToast('Error', 'Failed to reach simulator engine', 'HIGH');
    }
  }

  // ---------------------------------------------------------------------------
  // CSV Export Handler
  // ---------------------------------------------------------------------------
  function exportCsvReport() {
    window.location.href = apiUrl('/api/export/csv');
    showToast('Report Generated', 'Downloading SOC Incident Forensics CSV...', 'LOW');
  }

  // ---------------------------------------------------------------------------
  // Rule Configuration Modal
  // ---------------------------------------------------------------------------
  async function openConfigModal() {
    try {
      const res = await fetch(apiUrl('/api/config'));
      if (!res.ok) return;
      const cfg = await res.json();

      if (cfg.port_scan) {
        el.cfgPsPorts.value = cfg.port_scan.unique_ports || 10;
        el.cfgPsWindow.value = cfg.port_scan.window_seconds || 5;
      }
      if (cfg.udp_scan) {
        el.cfgUdpPorts.value = cfg.udp_scan.unique_ports || 10;
        el.cfgUdpWindow.value = cfg.udp_scan.window_seconds || 5;
      }
      if (cfg.syn_flood) {
        el.cfgSynThresh.value = cfg.syn_flood.syn_threshold || 200;
        el.cfgSynWindow.value = cfg.syn_flood.window_seconds || 5;
      }
      if (cfg.alerts) {
        el.cfgAlertMin.value = cfg.alerts.min_severity || 'LOW';
        el.cfgAlertDedup.value = cfg.alerts.dedup_window_seconds || 2.0;
        el.cfgAlertRate.value = cfg.alerts.max_rate_per_minute || 120;
      }

      el.configModal.classList.remove('hidden');
    } catch (e) {
      showToast('Error', 'Failed to load configuration rules.', 'HIGH');
    }
  }

  function closeConfigModal() {
    el.configModal.classList.add('hidden');
  }

  async function saveConfig() {
    try {
      const currentRes = await fetch(apiUrl('/api/config'));
      const cfg = currentRes.ok ? await currentRes.json() : {};

      cfg.port_scan = {
        enabled: true,
        unique_ports: parseInt(el.cfgPsPorts.value) || 10,
        window_seconds: parseFloat(el.cfgPsWindow.value) || 5
      };
      cfg.udp_scan = {
        enabled: true,
        unique_ports: parseInt(el.cfgUdpPorts.value) || 10,
        window_seconds: parseFloat(el.cfgUdpWindow.value) || 5
      };
      cfg.syn_flood = {
        enabled: true,
        syn_threshold: parseInt(el.cfgSynThresh.value) || 200,
        window_seconds: parseFloat(el.cfgSynWindow.value) || 5
      };
      cfg.alerts = {
        min_severity: el.cfgAlertMin.value,
        dedup_window_seconds: parseFloat(el.cfgAlertDedup.value) || 2.0,
        max_rate_per_minute: parseInt(el.cfgAlertRate.value) || 120
      };

      const saveRes = await fetch(apiUrl('/api/config'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(cfg)
      });

      if (saveRes.ok) {
        showToast('Success', 'IDS detection rules updated and saved!', 'LOW');
        closeConfigModal();
      } else {
        showToast('Error', 'Failed to save detection rules.', 'HIGH');
      }
    } catch (e) {
      showToast('Error', 'Network error while saving rules.', 'HIGH');
    }
  }

  // ---------------------------------------------------------------------------
  // Action Handlers (Clear DB, Sound Toggle, Pause)
  // ---------------------------------------------------------------------------
  async function clearDatabase() {
    if (!confirm('Are you sure you want to purge all historical security events from the database?')) {
      return;
    }
    try {
      const res = await fetch(apiUrl('/api/clear'), { method: 'POST' });
      if (res.ok) {
        state.events = [];
        showToast('Database Purged', 'All security events cleared.', 'LOW');
        fetchSummary();
        renderTable();
      }
    } catch (e) {
      showToast('Error', 'Failed to clear database.', 'HIGH');
    }
  }

  function toggleAudio() {
    state.audioEnabled = !state.audioEnabled;
    el.iconSoundOn.classList.toggle('hidden', !state.audioEnabled);
    el.iconSoundOff.classList.toggle('hidden', state.audioEnabled);
    showToast('Audio Alert', state.audioEnabled ? 'Sound notifications enabled' : 'Sound notifications muted', 'LOW');
  }

  function togglePauseStream() {
    state.isStreamPaused = !state.isStreamPaused;
    el.btnPause.innerHTML = state.isStreamPaused ? '<span>▶️ Resume</span>' : '<span>⏸️ Pause</span>';
  }

  function changeTarget() {
    const next = prompt('Enter remote Linux IDS Sensor address (e.g. http://192.168.1.50:8080) or leave empty for LOCAL:', state.targetUrl || '');
    if (next !== null) {
      const trimmed = next.trim().replace(/\/+$/, '');
      if (!trimmed || trimmed === window.location.origin) {
        state.targetUrl = '';
        localStorage.removeItem('ids_target_url');
        if (el.hudTargetUrl) el.hudTargetUrl.textContent = 'LOCAL SENSOR';
      } else {
        state.targetUrl = trimmed;
        localStorage.setItem('ids_target_url', trimmed);
        if (el.hudTargetUrl) el.hudTargetUrl.textContent = trimmed.replace(/^https?:\/\//, '');
      }
      showToast('Sensor Target Changed', `Connecting to: ${state.targetUrl || 'LOCAL'}`, 'LOW');
      fetchSummary();
      fetchEvents();
      initSSE();
    }
  }

  // ---------------------------------------------------------------------------
  // Event Listeners Initialization
  // ---------------------------------------------------------------------------
  function initListeners() {
    if (el.btnChangeTarget) el.btnChangeTarget.addEventListener('click', changeTarget);

    el.filterSearch.addEventListener('input', (e) => {
      state.filter.search = e.target.value;
      renderTable();
    });

    el.filterSeverity.addEventListener('change', (e) => {
      state.filter.severity = e.target.value;
      renderTable();
    });

    el.filterType.addEventListener('change', (e) => {
      state.filter.type = e.target.value;
      renderTable();
    });

    // Scenario modal triggers
    if (el.btnOpenScenarios) el.btnOpenScenarios.addEventListener('click', openScenarioModal);
    if (el.btnCloseScenario) el.btnCloseScenario.addEventListener('click', closeScenarioModal);
    if (el.scenarioModal) {
      el.scenarioModal.addEventListener('click', (e) => {
        if (e.target === el.scenarioModal) closeScenarioModal();
      });
    }

    // Launch buttons inside scenario modal
    document.querySelectorAll('.btn-launch-scenario').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const scenario = e.currentTarget.getAttribute('data-scenario') || 'all';
        launchScenario(scenario);
      });
    });

    // Export CSV
    if (el.btnExportCsv) el.btnExportCsv.addEventListener('click', exportCsvReport);

    // Quarantine Refresh
    if (el.btnRefreshQuarantine) el.btnRefreshQuarantine.addEventListener('click', fetchSummary);

    el.btnConfig.addEventListener('click', openConfigModal);
    el.btnClear.addEventListener('click', clearDatabase);
    el.btnAudio.addEventListener('click', toggleAudio);
    el.btnPause.addEventListener('click', togglePauseStream);

    el.btnCloseForensic.addEventListener('click', closeForensics);
    el.forensicsModal.addEventListener('click', (e) => {
      if (e.target === el.forensicsModal) closeForensics();
    });

    el.btnCloseConfig.addEventListener('click', closeConfigModal);
    el.btnCancelConfig.addEventListener('click', closeConfigModal);
    el.btnSaveConfig.addEventListener('click', saveConfig);
    el.configModal.addEventListener('click', (e) => {
      if (e.target === el.configModal) closeConfigModal();
    });

    // Resize listener to re-draw canvas charts
    window.addEventListener('resize', () => {
      renderVectorChart();
      renderSeverityDonut();
    });
  }

  // ---------------------------------------------------------------------------
  // App Bootstrapper
  // ---------------------------------------------------------------------------
  function init() {
    if (state.targetUrl && el.hudTargetUrl) {
      el.hudTargetUrl.textContent = state.targetUrl.replace(/^https?:\/\//, '');
    }
    initClock();
    initTopology();
    initTelemetryTimeline();
    initListeners();
    fetchSummary();
    fetchEvents();
    initSSE();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
