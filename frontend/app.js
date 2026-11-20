(() => {
  'use strict';
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const state = { incidents: [], iocs: [], recentBatch: [], pendingCsvFlows: null, ws: null, canvas: null, angle: 0.35, zoom: 1, dragging: false, pointer: null, incidentRefreshTimer: null, iocRefreshTimer: null, sceneMode: 'live', scenario: null, selectedDemoType: null, replay: { playing: false, elapsed: 0, lastFrame: 0, frameId: null, sceneKey: null, speed: 1, duration: 12000, attemptEvery: 500, attempts: 24 } };
  const modalOpeners = new Map();
  const batchTableState = { rows: [], sortKey: 'row_number', sortDirection: 'asc' };
  const scenarios = [
    { keys: ['brute', 'credential', 'password', 'ssh'], id: 'bruteforce', name: 'Password guessing', source: 'Remote computer', middle: 'Login gateway', target: 'Account server', packet: 'LOGIN TRY', count: 24, metric: 'LOGIN ATTEMPTS', title: 'Repeated password guesses', explain: 'One source keeps trying different passwords against the same login service. The server rejects the repeated attempts; this replay does not prove an account was accessed.', subtitle: 'Repeated login attempts aimed at an authentication service', color: '#f3787e' },
    { keys: ['ddos'], id: 'ddos', name: 'Traffic flood (DDoS)', source: 'Many remote devices', middle: 'Network edge', target: 'Public service', packet: 'REQUEST', count: 36, metric: 'ILLUSTRATIVE REQUESTS', title: 'Many devices overwhelm one service', explain: 'A distributed denial-of-service pattern sends a large volume of requests toward one service. The many animated sources explain the pattern; they are not measured attacker counts.', subtitle: 'High-volume traffic pattern targeting a service', color: '#ff8a62' },
    { keys: ['dos', 'denial of service'], id: 'dos', name: 'Service traffic flood (DoS)', source: 'Remote computer', middle: 'Network edge', target: 'Public service', packet: 'REQUEST', count: 24, metric: 'ILLUSTRATIVE REQUESTS', title: 'One source sends disruptive traffic', explain: 'A denial-of-service pattern can overload or disrupt a service with repeated traffic. This scene is illustrative and does not measure service impact or prove an outage.', subtitle: 'Repeated traffic pattern aimed at one service', color: '#ff8a62' },
    { keys: ['infiltrat', 'lateral', 'privilege', 'backdoor', 'remote access'], id: 'infiltration', name: 'Suspicious internal access', source: 'Suspicious source device', middle: 'Internal network', target: 'Protected server', packet: 'ACCESS', count: 12, metric: 'SUSPICIOUS CONNECTIONS', title: 'Access moves into a protected system', explain: 'The illustration shows suspicious access progressing from a device into an internal network and toward a server. Flow data alone may not reveal the exact host or prove compromise.', subtitle: 'Suspicious access pattern toward an internal system', color: '#f1b95f' },
    { keys: ['heartbleed', 'heartbeat', 'data leak', 'exfiltrat'], id: 'data-leak', name: 'Possible data exposure', source: 'Remote requester', middle: 'Vulnerable service', target: 'Sensitive data', packet: 'REQUEST', count: 16, metric: 'ILLUSTRATIVE REQUEST / RESPONSE', title: 'Heartbleed label · possible data exposure', explain: 'This is a conceptual request-and-response explanation for the Heartbleed model label, not a replay of the Heartbleed exploit. Flow features cannot confirm that vulnerable software was present or that data was disclosed.', subtitle: 'Heartbleed-labeled traffic · conceptual request and response', color: '#c58aff' },
    { keys: ['portscan', 'port scan', 'scan', 'recon'], id: 'portscan', name: 'Service probing', source: 'Remote computer', middle: 'Network edge', target: 'Multiple services', packet: 'PROBE', count: 20, metric: 'ILLUSTRATIVE PROBES', title: 'One source checks many doors', explain: 'A probing pattern checks multiple ports or services to discover what is reachable. Each marker is an explanatory probe, not a reconstructed packet.', subtitle: 'Repeated probes across network services', color: '#59c9dc' },
    { keys: ['web attack', 'web', 'sql', 'xss', 'injection'], id: 'web', name: 'Web application attack', source: 'Remote browser', middle: 'Web gateway', target: 'Web application', packet: 'WEB REQUEST', count: 18, metric: 'ILLUSTRATIVE REQUESTS', title: 'Suspicious requests target a web application', explain: 'Requests are shown passing through a gateway toward an application. This explains the detected traffic family; it does not show the exact request contents or confirm exploitation.', subtitle: 'Suspicious request pattern toward a web service', color: '#f3787e' },
    { keys: ['botnet', 'bot'], id: 'botnet', name: 'Coordinated device activity', source: 'Multiple devices', middle: 'Network edge', target: 'Target service', packet: 'BEACON', count: 24, metric: 'ILLUSTRATIVE SIGNALS', title: 'Several devices show coordinated activity', explain: 'Multiple devices are drawn to explain a possible coordinated pattern. The model family label is not proof that those devices are infected or controlled by an attacker.', subtitle: 'Coordinated traffic pattern across devices', color: '#f1b95f' }
  ];
  const pickScenario = label => {
    const text = String(label || '').toLowerCase();
    const webScenario = scenarios.find(s => s.id === 'web');
    if (text.includes('sql')) return { ...webScenario, id: 'web-sql', name: 'SQL injection', source: 'Remote client', middle: 'Web application', target: 'Database', packet: 'SQL QUERY', metric: 'ILLUSTRATIVE SQL REQUESTS', title: 'SQL-like input targets a web application and database', explain: 'The illustration shows suspicious SQL-like input sent to a web application and onward toward its database. It is a conceptual explanation of the selected label, not captured request content and not proof that a database was accessed.', subtitle: 'SQL injection pattern · client → web app → database' };
    if (text.includes('xss')) return { ...webScenario, id: 'web-xss', name: 'Cross-site scripting', source: 'Remote browser', middle: 'Web application', target: 'User browser', packet: 'SCRIPT INPUT', metric: 'ILLUSTRATIVE WEB INPUTS', title: 'Script-like input targets a web application', explain: 'The illustration explains an XSS-labeled flow pattern between a client, application, and browser. Flow features do not show the exact request body or prove that a script executed.', subtitle: 'XSS pattern · client → web app → browser' };
    if (text.includes('web') && text.includes('brute')) return { ...scenarios[0], id: 'web-brute', name: 'Web login brute force', source: 'Remote client', middle: 'Web login', target: 'User account', packet: 'LOGIN TRY', metric: 'ILLUSTRATIVE LOGIN ATTEMPTS', title: 'Repeated login attempts target a web account', explain: 'The illustration shows repeated login attempts toward a web authentication service. It does not show actual credentials or prove that an account was accessed.', subtitle: 'Web brute-force pattern · client → login service → account' };
    if (text.includes('web')) return webScenario;
    return scenarios.find(s => s.keys.some(key => text.includes(key))) || { keys: [], id: 'generic', name: String(label || 'Suspicious activity'), source: 'Originating system', middle: 'Network gateway', target: 'Destination service', packet: 'FLOW', count: 16, metric: 'ILLUSTRATIVE FLOW EVENTS', title: 'Suspicious activity moves toward a service', explain: 'The model flagged this traffic pattern. The scene shows a simplified path from source to destination; it is an explanation, not a packet-by-packet recording or proof of compromise.', subtitle: 'Illustrative path for the detected traffic family', color: '#f3787e' };
  };
  const colors = { ATTACK: '#f3787e', REVIEW: '#f1b95f', BENIGN: '#53d69a', FAILED: '#8ba0b0' };
  const esc = value => String(value ?? '').replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[ch]);
  const shortId = id => String(id || '—').slice(0, 8).toUpperCase();
  const payloadOf = item => item?.payload || item || {};
  const unseenFamilyInfo = label => {
    const raw = String(label || 'Unclassified');
    const normalized = raw.toLowerCase().replace(/[_-]+/g, ' ');
    if (/\b(benign|normal)\b/.test(normalized)) return { name: 'Benign', recall: null };
    if (/\b(ddos|dos)\b/.test(normalized)) return { name: 'DoS/DDoS family', recall: '36.8%' };
    if (/\b(brute|patator|ssh)\b/.test(normalized)) return { name: 'Brute-force family', recall: '24.4%' };
    if (/\b(web|sql|xss|injection)\b/.test(normalized)) return { name: 'Web-attack family', recall: '36.0%' };
    if (/\bbotnet\b/.test(normalized)) return { name: 'Botnet family', recall: '0%' };
    if (/\binfiltration\b/.test(normalized)) return { name: 'Infiltration family', recall: '0.6%' };
    return { name: raw, recall: null };
  };
  const safeDate = value => { if (!value) return '—'; const date = new Date(value); return Number.isNaN(date.valueOf()) ? '—' : date.toLocaleString([], { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' }); };
  const ago = value => { if (!value) return '—'; const delta = Date.now() - new Date(value).valueOf(); if (!Number.isFinite(delta)) return '—'; const m = Math.max(0, Math.floor(delta / 60000)); return m < 1 ? 'just now' : m < 60 ? `${m}m ago` : m < 1440 ? `${Math.floor(m / 60)}h ago` : `${Math.floor(m / 1440)}d ago`; };
  const normalize = value => String(value || '').toLowerCase().replaceAll('_', ' ');
  const decisionClass = value => `decision-${String(value || '').toLowerCase()}`;
  const decisionGuidance = decision => ({
    BENIGN: ['No known attack pattern was flagged in these flows.', 'Keep monitoring; this result cannot confirm traffic is safe.'],
    REVIEW: ['The signals are mixed, so this flow needs a closer look.', 'Check the flow details and compare with other activity.'],
    ATTACK: ['The flow matches a pattern the model treats as an attack.', 'Review the evidence and affected endpoints before acting.'],
  })[String(decision || '').toUpperCase()] || ['No decision is available for this flow.', 'Check the input and try again.'];
  const rawScoreTip = 'Raw, uncalibrated model output; not a real-world likelihood.';
  const shapFeatureLabels = {
    'Flow Duration': 'Connection length', 'Flow Bytes/s': 'Data sent per second', 'Flow Packets/s': 'Packets per second',
    'Total Fwd Packets': 'Packets sent out', 'Total Backward Packets': 'Packets sent back',
    'Fwd Packets Length Total': 'Bytes sent out', 'Bwd Packets Length Total': 'Bytes sent back',
    'Fwd Packet Length Max': 'Largest outgoing packet', 'Fwd Packet Length Min': 'Smallest outgoing packet',
    'Fwd Packet Length Mean': 'Average outgoing packet size', 'Fwd Packet Length Std': 'Variation in outgoing packet sizes',
    'Bwd Packet Length Max': 'Largest returning packet', 'Bwd Packet Length Min': 'Smallest returning packet',
    'Bwd Packet Length Mean': 'Average returning packet size', 'Bwd Packet Length Std': 'Variation in returning packet sizes',
    'Fwd Header Length': 'Outgoing packet-header size', 'Bwd Header Length': 'Returning packet-header size',
    'Fwd Packets/s': 'Outgoing packets per second', 'Bwd Packets/s': 'Returning packets per second',
    'Avg Fwd Segment Size': 'Average outgoing segment size', 'Avg Bwd Segment Size': 'Average returning segment size',
    'Fwd Avg Bytes/Bulk': 'Average outgoing bytes per data burst', 'Fwd Avg Packets/Bulk': 'Average outgoing packets per data burst',
    'Bwd Avg Bytes/Bulk': 'Average returning bytes per data burst', 'Bwd Avg Packets/Bulk': 'Average returning packets per data burst',
    'Fwd Avg Bulk Rate': 'Outgoing data-burst rate', 'Bwd Avg Bulk Rate': 'Returning data-burst rate',
    'Subflow Fwd Packets': 'Outgoing packets per connection segment', 'Subflow Fwd Bytes': 'Outgoing bytes per connection segment',
    'Subflow Bwd Packets': 'Returning packets per connection segment', 'Subflow Bwd Bytes': 'Returning bytes per connection segment',
    'Init Fwd Win Bytes': 'Initial outgoing window size', 'Init Bwd Win Bytes': 'Initial returning window size',
    'Fwd Act Data Packets': 'Outgoing packets carrying data', 'Fwd Seg Size Min': 'Smallest outgoing segment',
    'Fwd PSH Flags': 'Outgoing data-push flags', 'Bwd PSH Flags': 'Returning data-push flags',
    'Fwd URG Flags': 'Outgoing urgent-data flags', 'Bwd URG Flags': 'Returning urgent-data flags',
    'Avg Packet Size': 'Average packet size across the flow', 'Packet Length Max': 'Largest packet size',
    'Packet Length Min': 'Smallest packet size', 'Packet Length Mean': 'Average size of each packet',
    'Packet Length Std': 'Variation in packet sizes', 'Packet Length Variance': 'Spread in packet sizes',
    'Down/Up Ratio': 'Download-to-upload balance', 'SYN Flag Count': 'Connection-start flags',
    'FIN Flag Count': 'Connection-close flags', 'RST Flag Count': 'Connection-reset flags',
    'ACK Flag Count': 'Acknowledgment flags', 'PSH Flag Count': 'Data-push flags',
    'URG Flag Count': 'Urgent-data flags', 'Flow IAT Mean': 'Average gap between packets',
    'CWE Flag Count': 'Congestion-window flags', 'ECE Flag Count': 'Congestion-signal flags',
    'Flow IAT Std': 'Variation in gaps between packets',
    'Flow IAT Max': 'Longest gap between packets', 'Flow IAT Min': 'Shortest gap between packets',
    'Fwd IAT Mean': 'Average gap between outgoing packets', 'Bwd IAT Mean': 'Average gap between returning packets',
    'Fwd IAT Total': 'Total gaps between outgoing packets', 'Bwd IAT Total': 'Total gaps between returning packets',
    'Active Mean': 'Average busy period', 'Idle Mean': 'Average quiet period',
  };
  function plainShapFeatureName(feature) {
    const name = String(feature || '');
    if (shapFeatureLabels[name]) return shapFeatureLabels[name];
    return name.replace(/\bFwd\b/g, 'outgoing').replace(/\bBwd\b/g, 'returning')
      .replace(/\bIAT\b/g, 'time between packets').replace(/\bAvg\b/g, 'average')
      .replace(/\bMean\b/g, 'average').replace(/\bStd\b/g, 'variation')
      .replace(/\bMin\b/g, 'smallest').replace(/\bMax\b/g, 'largest')
      .replace(/\bPackets Length\b/g, 'packet size').replace(/\bPacket Length\b/g, 'packet size')
      .replace(/\bFlag Count\b/g, 'flags').replace(/\bBulk\b/g, 'data burst')
      .replace(/\bSubflow\b/g, 'connection segment').replace(/\bWin Bytes\b/g, 'window size in bytes')
      .replace(/\bFlow\b/g, 'connection').replace(/\/s\b/g, ' per second').replace(/\s+/g, ' ').trim();
  }
  function uniqueShapFeatureLabels(features) {
    const seen = new Map(); const used = new Set();
    return features.map((item, index) => {
      const name = String(item?.feature || '');
      const base = plainShapFeatureName(name);
      const count = (seen.get(base) || 0) + 1;
      seen.set(base, count);
      let label = count === 1 ? base : `${base} (another feature ${index + 1})`;
      while (used.has(label)) label += ' again';
      used.add(label);
      return label;
    });
  }
  const featureNames = ['Protocol', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Fwd Packets Length Total', 'Bwd Packets Length Total', 'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s', 'Packet Length Min', 'Packet Length Max', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio', 'Avg Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init Fwd Win Bytes', 'Init Bwd Win Bytes', 'Fwd Act Data Packets', 'Fwd Seg Size Min', 'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'];
  const cliHint = '.\\recovery_venv\\Scripts\\python.exe cyber.py "path\\to\\flows.csv" --all --output results.jsonl';
  const statusClass = value => `status-${String(value || 'New').toLowerCase().replace(/[_\s]+/g, '-')}`;
  const lifecycleLabel = value => ({ new: 'New', triaged: 'Triaged', contained: 'Contained', resolved: 'Resolved', 'false positive': 'False positive' })[String(value || '').replaceAll('_', ' ').toLowerCase()] || normalize(value);
  const getRisk = item => Number(item?.risk_score ?? payloadOf(item)?.risk?.score ?? 0);
  const getSeverity = item => item?.severity || payloadOf(item)?.risk?.severity || payloadOf(item)?.investigation?.severity || '—';

  let apiToken = '';
  let tokenPrompt = null;
  function sendWebSocketAuth(socket = state.ws) {
    if (apiToken && socket?.readyState === WebSocket.OPEN && !socket.authSent) {
      socket.authSent = true;
      socket.send(JSON.stringify({ type: 'auth', token: apiToken }));
    }
  }
  async function requestApiToken() {
    if (!tokenPrompt) tokenPrompt = Promise.resolve().then(() => window.prompt('This local API requires a token. Enter CYBER_API_TOKEN:'));
    const pending = tokenPrompt;
    const value = await pending;
    if (tokenPrompt === pending) {
      tokenPrompt = null;
      apiToken = String(value || '');
      sendWebSocketAuth();
    }
    if (!apiToken) throw new Error('An API token is required to use this dashboard.');
    return apiToken;
  }
  async function api(path, options = {}) {
    const send = token => {
      const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
      if (token) headers.Authorization = `Bearer ${token}`;
      return fetch(path, { ...options, headers });
    };
    const firstToken = apiToken;
    let response = await send(firstToken);
    if (response.status === 401 && response.headers.get('www-authenticate')?.includes('Bearer')) {
      if (firstToken) apiToken = '';
      const token = await requestApiToken();
      response = await send(token);
      if (response.status === 401) {
        apiToken = '';
        throw new Error('Authentication failed. Check CYBER_API_TOKEN and reload the dashboard.');
      }
    }
    const type = response.headers.get('content-type') || '';
    const body = type.includes('json') ? await response.json() : await response.text();
    if (!response.ok) throw new Error(typeof body === 'object' ? (body.detail || body.error || JSON.stringify(body)) : body);
    return body;
  }
  function toast(title, detail = '', kind = '') {
    const node = document.createElement('div'); node.className = `toast ${kind}`;
    node.innerHTML = `<b>${esc(title)}</b><span>${esc(detail)}</span>`; $('#toastRegion').append(node);
    setTimeout(() => node.remove(), 4800);
  }
  function setConnection(online, message) {
    $('#connectionDot').classList.toggle('muted', !online); $('#connectionText').textContent = message || (online ? 'API connected' : 'API offline');
  }
  function nav(view) {
    $$('.modal-backdrop.open').forEach(modal => closeModal(modal.id));
    $$('.view').forEach(el => el.classList.toggle('active', el.id === `${view}View`));
    $$('.nav-item').forEach(el => el.classList.toggle('active', el.dataset.view === view));
    $('#pageCrumb').textContent = ({ overview: 'Overview', incidents: 'Incidents', intel: 'Threat intelligence', evidence: 'Evidence search' })[view] || 'Overview';
    if (view === 'incidents') loadIncidents(); if (view === 'intel') loadIocs();
  }
  async function refreshAll() {
    try {
      const health = await api('/api/health'); setConnection(true, health.local_llm?.status === 'ready' ? 'Local API · LLM ready' : 'Local API · connected');
      $('#pipelineBuildInfo').textContent = `Pipeline ${health.pipeline_version || 'unknown'} · Git ${health.git_commit_hash || 'unknown'}`;
      const intelStatus = health.threat_intelligence?.configured ? 'ThreatFox is configured. Sync pulls indicators from the last 1–7 days; review matches before acting.' : 'ThreatFox sync is not configured. Set THREATFOX_AUTH_KEY locally to enable it; never paste the key into this page.';
      if ($('#threatFoxStatus')) $('#threatFoxStatus').textContent = intelStatus;
      $('#lastUpdated').textContent = `Updated ${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;
      await Promise.all([loadIncidents(), loadIocs()]);
    } catch (error) { setConnection(false, 'API unavailable'); $('#lastUpdated').textContent = 'Start the local API to load activity'; }
  }
  async function loadIncidents() {
    try {
      state.incidents = await api('/api/incidents?limit=500');
      renderIncidents(); renderStats(); renderChart();
    } catch (error) { $('#recentIncidentRows').innerHTML = `<tr><td colspan="6" class="empty-cell">${esc(error.message)}</td></tr>`; $('#allIncidentRows').innerHTML = `<tr><td colspan="7" class="empty-cell">${esc(error.message)}</td></tr>`; }
  }
  async function loadIocs() {
    try { state.iocs = await api('/api/threat-intel?limit=1000'); renderIocs(); renderStats(); }
    catch (error) { $('#iocRows').innerHTML = `<tr><td colspan="7" class="empty-cell">${esc(error.message)}</td></tr>`; }
  }
  function scheduleIncidentRefresh() { clearTimeout(state.incidentRefreshTimer); state.incidentRefreshTimer = setTimeout(loadIncidents, 250); }
  function scheduleIocRefresh() { clearTimeout(state.iocRefreshTimer); state.iocRefreshTimer = setTimeout(loadIocs, 250); }
  function renderStats() {
    const closedStates = ['Resolved', 'False positive'];
    const open = state.incidents.filter(item => !closedStates.includes(item.status)).length;
    const high = state.incidents.filter(item => ['HIGH', 'CRITICAL'].includes(String(getSeverity(item)).toUpperCase()) && !closedStates.includes(item.status)).length;
    const resolved = state.incidents.filter(item => item.status === 'Resolved').length;
    $('#statOpen').textContent = open; $('#statHigh').textContent = high; $('#statResolved').textContent = resolved; $('#statIocs').textContent = state.iocs.length; $('#intelTotal').textContent = state.iocs.length; $('#navIncidentCount').textContent = open;
  }
  function incidentRow(item, full = false) {
    const payload = payloadOf(item); const decision = payload.final_decision || 'REVIEW'; const rawLabel = payload.final_attack || payload.investigation?.suspected_attack || 'Unclassified'; const family = unseenFamilyInfo(rawLabel).name;
    const risk = getRisk(item); const severity = getSeverity(item); const date = item.updated_at || item.created_at;
    const riskMarkup = `<span class="risk-value">${Math.round(risk)}</span><span class="risk-track"><i class="${risk >= 70 ? 'high' : ''}" style="width:${Math.min(100, Math.max(0, risk))}%"></i></span>`;
    return `<tr data-incident="${esc(item.id)}"><td><button type="button" class="id-cell incident-open-link" data-open="${esc(item.id)}" aria-label="Open incident INC-${esc(shortId(item.id))}">INC-${shortId(item.id)}</button></td><td><span class="family-cell"><i class="family-icon">${decision === 'ATTACK' ? '⌁' : decision === 'REVIEW' ? '◉' : '✓'}</i><span class="decision-pill ${decisionClass(decision)}">${esc(decision)}</span><span title="Classifier label: ${esc(rawLabel)}">${esc(family)}</span></span></td>${full ? `<td>${riskMarkup}</td><td><span class="severity-pill severity-${normalize(severity)}">${esc(severity)}</span></td>` : `<td>${riskMarkup}</td>`}<td><span class="status-pill ${statusClass(item.status)}">${esc(lifecycleLabel(item.status))}</span></td><td title="${esc(safeDate(date))}">${esc(full ? safeDate(item.created_at) : ago(date))}</td><td><button type="button" class="row-open" data-open="${esc(item.id)}" aria-label="Open incident INC-${esc(shortId(item.id))}">›</button></td></tr>`;
  }
  function renderIncidents() {
    $('#recentCount').textContent = state.incidents.length;
    const recentQuery = ($('#incidentSearch')?.value || '').toLowerCase();
    const recent = state.incidents.filter(item => incidentSearchMatch(item, recentQuery)).slice(0, 7);
    $('#recentIncidentRows').innerHTML = recent.length ? recent.map(item => incidentRow(item)).join('') : `<tr><td colspan="6" class="empty-cell">No matching incidents. Run an analysis to create investigation records.</td></tr>`;
    const allQuery = ($('#allIncidentSearch')?.value || '').trim().toLowerCase(); const status = $('#statusFilter')?.value || '';
    const decisionFilter = $('#decisionFilter')?.value || ''; const sort = $('#incidentSort')?.value || 'time_desc';
    const filtered = state.incidents.filter(item => {
      const decision = String(payloadOf(item).final_decision || 'REVIEW').toUpperCase();
      return (!status || String(item.status || 'New').toLowerCase() === status.toLowerCase()) && (!decisionFilter || decision === decisionFilter) && incidentSearchMatch(item, allQuery);
    }).sort((a, b) => {
      if (sort.startsWith('risk_')) return (getRisk(a) - getRisk(b)) * (sort === 'risk_desc' ? -1 : 1);
      const timeA = Date.parse(a.created_at || '') || 0;
      const timeB = Date.parse(b.created_at || '') || 0;
      return (timeA - timeB) * (sort === 'time_desc' ? -1 : 1);
    });
    $('#allIncidentRows').innerHTML = filtered.length ? filtered.map(item => incidentRow(item, true)).join('') : `<tr><td colspan="7" class="empty-cell">No incidents match these filters.</td></tr>`;
    if (!state.recentBatch.length) {
      drawThreatField(state.incidents.slice(0, 40).map(item => ({ ...payloadOf(item), pipeline_completed: true, final_decision: payloadOf(item).final_decision || 'REVIEW', final_attack: payloadOf(item).final_attack || 'Unclassified', flow_metrics: {} })));
    }
  }
  function incidentSearchMatch(item, query) {
    if (!query) return true; const payload = payloadOf(item);
    const context = payload.flow_context || {};
    return [item.id, item.status, getSeverity(item), payload.final_attack, payload.final_decision, payload.investigation?.finding,
      context.source_host, context.source_ip, context.source_port, context.destination_host, context.destination_ip, context.destination_port]
      .some(value => String(value || '').toLowerCase().includes(query));
  }
  function renderIncidentHistory(id, audit) {
    if (!Array.isArray(audit)) return `<div class="detail-section"><h3>Analyst history</h3><p class="muted-copy">History is temporarily unavailable.</p></div>`;
    const events = audit.filter(event => event.incident_id === id && ['incident.validated', 'response.approved', 'response.simulation_logged'].includes(event.event_type))
      .sort((a, b) => (Date.parse(a.created_at) || 0) - (Date.parse(b.created_at) || 0));
    if (!events.length) return `<div class="detail-section"><h3>Analyst history</h3><p class="muted-copy">No analyst notes or state changes recorded yet.</p></div>`;
    const rows = events.map(event => {
      const details = event.details || {};
      const title = event.event_type === 'incident.validated'
        ? `State changed: ${lifecycleLabel(details.previous_state || 'unknown')} → ${lifecycleLabel(details.state || 'unknown')}`
        : event.event_type === 'response.simulation_logged'
          ? `SIMULATION dry-run logged · ${Number(details.steps_count || 0)} proposed steps`
          : 'Response approved · simulation only';
      const note = details.note ? `<p><b>Note:</b> ${esc(details.note)}</p>` : '';
      const action = details.action_taken ? `<p><b>Action taken:</b> ${esc(details.action_taken)}</p>` : '';
      const approver = details.approved_by ? `<p><b>Approved by:</b> ${esc(details.approved_by)}</p>` : '';
      return `<li><time datetime="${esc(event.created_at || '')}">${esc(safeDate(event.created_at))}</time><b>${esc(title)}</b>${note}${action}${approver}</li>`;
    }).join('');
    const limitNote = audit.length >= 500 ? 'The audit endpoint is capped at 500 recent events, so older entries may not be shown.' : 'Showing recorded notes, state validations, and approvals in time order.';
    return `<div class="detail-section"><h3>Analyst history</h3><ol class="incident-history">${rows}</ol><p class="muted-copy">${limitNote}</p></div>`;
  }
  function renderChart() {
    const results = state.recentBatch.length ? state.recentBatch : state.incidents.slice(0, 40).map(payloadOf);
    const bins = Array.from({ length: 12 }, (_, i) => results.slice(Math.floor(i * results.length / 12), Math.floor((i + 1) * results.length / 12)));
    $('#chartBars').innerHTML = bins.map(bin => {
      const count = key => bin.filter(row => row.final_decision === key).length;
      const max = Math.max(1, ...bins.map(b => b.length));
      return `<div class="chart-group" title="${bin.length} analyzed"><i style="height:${count('ATTACK') / max * 100}%;background:${colors.ATTACK}"></i><i style="height:${count('REVIEW') / max * 100}%;background:${colors.REVIEW}"></i><i style="height:${count('BENIGN') / max * 100}%;background:${colors.BENIGN}"></i></div>`;
    }).join('');
    $('#chartLabels').innerHTML = `<span>${results.length ? `${results.length} recent flow${results.length === 1 ? '' : 's'}` : 'No analysis yet'}</span><span>${state.recentBatch.length ? 'LATEST BATCH' : 'SAVED INCIDENTS'}</span>`;
  }
  function renderIocs() {
    const query = ($('#iocSearch')?.value || '').toLowerCase(); const items = state.iocs.filter(item => [item.indicator_type, item.indicator_value, item.family, item.source, item.severity].some(v => String(v || '').toLowerCase().includes(query)));
    $('#iocRows').innerHTML = items.length ? items.map(item => `<tr><td><span class="summary-chip">${esc(item.indicator_type)}</span></td><td><span class="id-cell">${esc(item.indicator_value)}</span></td><td>${esc(item.family || '—')}</td><td>${Math.round(Number(item.confidence || 0) * 100)}%</td><td>${esc(item.severity || '—')}</td><td>${esc(item.source)}</td><td>${esc(safeDate(item.created_at))}</td></tr>`).join('') : `<tr><td colspan="7" class="empty-cell">${query ? 'No matching indicators.' : 'No indicators imported yet.'}</td></tr>`;
  }
  function modalFocusableElements(modal) {
    return [...modal.querySelectorAll('a[href],button:not([disabled]),input:not([disabled]):not([type="hidden"]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])')]
      .filter(element => !element.closest('[hidden],[inert]') && element.getAttribute('aria-hidden') !== 'true' && element.getClientRects().length > 0);
  }
  function openModal(id) {
    const el = document.getElementById(id); if (!el) return;
    if (!el.classList.contains('open')) {
      const opener = document.activeElement;
      modalOpeners.set(id, opener && opener !== document.body ? opener : null);
    }
    el.classList.add('open'); el.setAttribute('aria-hidden', 'false');
    const dialog = el.querySelector('[role="dialog"]') || el;
    if (!dialog.hasAttribute('tabindex')) dialog.setAttribute('tabindex', '-1');
    (modalFocusableElements(el)[0] || dialog).focus();
  }
  function closeModal(id) {
    const el = document.getElementById(id); if (!el) return;
    el.classList.remove('open'); el.setAttribute('aria-hidden', 'true');
    const opener = modalOpeners.get(id); modalOpeners.delete(id);
    if (opener?.isConnected && typeof opener.focus === 'function') opener.focus();
  }
  function openAnalyze() { $('#batchResult').classList.remove('visible'); $('#analysisProgress').classList.remove('visible'); $('#fileName').textContent = ''; $('#flowFile').value = ''; state.pendingCsvFlows = null; $('#uploadFeedback').textContent = ''; $('#csvPreview').hidden = true; $('#analyzeUploadedCsv').disabled = true; openModal('analyzeModal'); }
  async function openIncident(id) {
    try {
      const item = await api(`/api/incidents/${encodeURIComponent(id)}`); const p = payloadOf(item); const decision = p.final_decision || 'REVIEW';
      let incidentHistory = null;
      try { incidentHistory = await api('/api/audit?limit=500'); } catch { incidentHistory = null; }
      const historyHtml = renderIncidentHistory(id, incidentHistory);
      const rawModelLabel = p.final_attack || p.detection?.predicted_attack || p.investigation?.suspected_attack || 'Unclassified';
      $('#detailTitle').textContent = `${decision} · ${unseenFamilyInfo(rawModelLabel).name}`; $('#detailSubtitle').textContent = `INC-${shortId(id)} · Created ${safeDate(item.created_at)} · ${lifecycleLabel(item.status)}`;
      const probability = Number(p.investigation?.average_attack_probability ?? p.decision?.average_attack_probability ?? 0);
      const metrics = [['RISK SCORE', Math.round(getRisk(item)), 'Priority score for sorting and review. Classifier outputs are raw and uncalibrated.'], ['SEVERITY', getSeverity(item)], ['RF ATTACK SCORE', `${(Number(p.investigation?.random_forest_attack_probability || 0) * 100).toFixed(1)}%`, rawScoreTip], ['XGBOOST ATTACK SCORE', `${(Number(p.investigation?.xgboost_attack_probability || 0) * 100).toFixed(1)}%`, rawScoreTip], ['AVERAGE ATTACK SCORE', `${(probability * 100).toFixed(1)}%`, rawScoreTip], ['MODEL AGREEMENT', p.decision?.model_agreement ? 'Agree' : 'Disagree'], ['SOURCE', item.source || '—'], ['RESPONSE STATE', p.response_workflow?.state || '—']];
      const metricHtml = metrics.map(([label, value, tip]) => `<div class="detail-metric"><span${tip ? ` title="${esc(tip)}"` : ''}>${esc(label)}</span><b${tip ? ` title="${esc(tip)}"` : ''}>${esc(value)}</b></div>`).join('');
      const [decisionExplanation, nextHint] = decisionGuidance(decision);
      const modelFamilyInfo = unseenFamilyInfo(rawModelLabel);
      const modelFamily = modelFamilyInfo.name;
      const subtypeNote = decision === 'BENIGN' || String(modelFamily).toLowerCase() === 'benign'
        ? 'No attack subtype was reported.'
        : 'Not estimated by the active family-level classifier.';
      const familyRecall = modelFamilyInfo.recall ? ` Separate five-family research-pilot recall: ${esc(modelFamilyInfo.recall)} for this family.` : ' This label was not included in the five-family research pilot.';
      const rawLabelNote = rawModelLabel !== modelFamily ? `<p><b>Classifier label:</b> ${esc(rawModelLabel)} (shown under the broader research family).</p>` : '';
      const generalizationNoteHtml = `<section class="detail-section generalization-note" role="note"><h3>Model label and validation limits</h3><p><b>Flag:</b> ${esc(decision)} · <b>Research family:</b> ${esc(modelFamily)}.</p>${rawLabelNote}<p><b>Likely type:</b> ${esc(subtypeNote)}</p><p><b>Unseen-capture status:</b> Experimental. A separate reduced-sample research pilot averaged 23% recall overall across held-out captures.${familyRecall} These aggregate results are not this flow's confidence or proof of reliable detection. No evaluated family met the reliability rule.</p></section>`;
      const explanation = p.investigation?.explanation || p.decision?.explanation || p.rag?.summary || 'No investigation explanation is available.';
      const analystNote = p.rag?.analyst_note;
      const analystNoteHtml = analystNote ? `<div class="detail-section"><h3>Analyst note</h3><p style="white-space:pre-line">${esc(analystNote)}</p><p class="muted-copy">Note validation: ${esc(p.rag?.note_validation || 'not recorded')}${p.rag?.note_validation_reason ? ` · ${esc(p.rag.note_validation_reason)}` : ''}</p></div>` : '';
      const reasons = p.decision?.correlation_reasons || [];
      const evidenceTrail = Array.isArray(p.evidence_trail) ? p.evidence_trail : [];
      const evidenceTrailHtml = evidenceTrail.length ? `<div class="detail-section"><h3>Evidence trail</h3><div class="table-scroll" role="region" aria-label="Evidence trail table" tabindex="0"><table><caption class="sr-only">Pipeline signals cited by decision reasons.</caption><thead><tr><th scope="col">ID</th><th scope="col">Type</th><th scope="col">Source</th><th scope="col">Value</th><th scope="col">Direction</th><th scope="col">Weight</th></tr></thead><tbody>${evidenceTrail.map(entry => `<tr><td>${esc(entry.id || '')}</td><td>${esc(entry.type || '')}</td><td>${esc(entry.source || '')}</td><td>${esc(typeof entry.value === 'string' ? entry.value : JSON.stringify(entry.value ?? ''))}</td><td>${esc(entry.direction || 'neutral')}</td><td>${entry.weight == null ? '—' : esc(Number(entry.weight).toFixed(3))}</td></tr>`).join('')}</tbody></table></div></div>` : '';
      const agentTrace = Array.isArray(p.agent_trace) ? p.agent_trace : [];
      const unavailableAgents = agentTrace.filter(entry => entry.status === 'unavailable');
      const agentTraceHtml = agentTrace.length ? `<div class="detail-section agent-trace-section"><h3>Agent trace</h3>${unavailableAgents.length ? `<div class="agent-trace-warning" role="alert"><b>Warning: ${unavailableAgents.length} stage${unavailableAgents.length === 1 ? '' : 's'} unavailable.</b> Review the partial results before acting.</div>` : ''}<div class="table-scroll" role="region" aria-label="Agent trace table" tabindex="0"><table class="agent-trace-table"><caption class="sr-only">Analysis stages, their status, timing, and input and output summaries.</caption><thead><tr><th scope="col">Agent</th><th scope="col">Role</th><th scope="col">Status</th><th scope="col">Duration</th><th scope="col">Input summary</th><th scope="col">Output summary</th></tr></thead><tbody>${agentTrace.map(entry => `<tr><th scope="row">${esc(entry.agent || 'Unknown')}</th><td>${esc(entry.role || '')}</td><td><span class="agent-trace-status ${entry.status === 'unavailable' ? 'unavailable' : 'complete'}">${esc(entry.status || 'unknown')}</span></td><td>${esc(entry.duration_ms ?? '—')} ms</td><td>${esc(entry.input_summary || '')}</td><td>${esc(entry.output_summary || '')}</td></tr>`).join('')}</tbody></table></div></div>` : '';
      const tasks = p.response_workflow?.tasks || [];
      const evidence = p.evidence?.flow_indicators || p.decision?.flow_indicators || [];
      const threatIntel = p.threat_intel || {};
      const threatMatches = Array.isArray(threatIntel.matches) ? threatIntel.matches : [];
      const threatIntelHtml = threatIntel.available ? `<div class="detail-section"><h3>Threat-intelligence check</h3>${threatMatches.length ? `<p>This flow matched ${threatMatches.length} stored indicator${threatMatches.length === 1 ? '' : 's'}:</p><ul>${threatMatches.map(match => `<li><b>${esc(match.indicator_type || 'indicator')} ${esc(match.indicator_value)}</b>${match.family ? ` · tagged ${esc(match.family)}` : ''}${match.source ? ` · source ${esc(match.source)}` : ''}${match.severity ? ` · ${esc(match.severity)} severity` : ''}${match.confidence != null ? ` · ${Math.round(Number(match.confidence) * 100)}% confidence` : ''}</li>`).join('')}</ul><span class="muted-copy">An indicator match links this flow to a stored reference; it does not by itself prove that the host is compromised.</span>` : `<p>No stored threat indicator matched the IP, domain, URL, or hash fields available in this flow. This does not establish that the endpoint is safe.</p>`}</div>` : '';
      const shap = p.detection?.random_forest?.attack_probability_explanation || {};
      const shapFeatures = shap.status === 'available' && Array.isArray(shap.top_features)
        ? shap.top_features.filter(item => item?.feature && item.contribution != null && Number.isFinite(Number(item.contribution))).slice(0, 5)
        : [];
      const maxShapContribution = Math.max(0, ...shapFeatures.map(item => Math.abs(Number(item.contribution))));
      const shapLabels = uniqueShapFeatureLabels(shapFeatures);
      const explainHtml = shapFeatures.length ? `<div class="detail-section shap-section"><h3>Top 5 features</h3><p>These features help explain this model result; they do not prove what happened.</p><div class="shap-legend" aria-label="Chart legend"><span class="shap-legend-decrease"><i aria-hidden="true"></i>Decreases suspicion</span><span class="shap-legend-increase"><i aria-hidden="true"></i>Increases suspicion</span></div><div class="shap-chart" role="list">${shapFeatures.map((item, index) => {
        const contribution = Number(item.contribution); const label = shapLabels[index];
        const width = maxShapContribution ? Math.abs(contribution) / maxShapContribution * 100 : 0;
        const value = `${contribution > 0 ? '+' : ''}${contribution.toFixed(4)}`;
        const direction = contribution > 0 ? 'increases suspicion' : contribution < 0 ? 'decreases suspicion' : 'does not shift suspicion';
        return `<div class="shap-chart-row" role="listitem"><span class="shap-chart-label">${esc(label)}</span><span class="shap-chart-track" role="img" aria-label="${esc(label)} ${direction} by ${esc(value)}"><span class="shap-chart-half shap-chart-negative">${contribution < 0 ? `<i style="width:${width}%"></i>` : ''}</span><span class="shap-chart-axis" aria-hidden="true"></span><span class="shap-chart-half shap-chart-positive">${contribution > 0 ? `<i style="width:${width}%"></i>` : ''}</span></span><span class="shap-chart-value">${esc(value)}</span></div>`;
      }).join('')}</div></div>` : '';
      const context = p.flow_context || {};
      const endpointPairs = [['Source host', context.source_host], ['Source IP', context.source_ip], ['Source port', context.source_port], ['Destination host', context.destination_host], ['Destination IP', context.destination_ip], ['Destination port', context.destination_port], ['Protocol', context.protocol], ['Observed time', context.timestamp]];
      const endpointHtml = endpointPairs.some(([, value]) => value != null) ? `<div class="detail-section"><h3>Observed flow endpoints</h3><div class="detail-grid">${endpointPairs.filter(([, value]) => value != null).map(([label, value]) => `<div class="detail-metric"><span>${esc(label)}</span><b>${esc(value)}</b></div>`).join('')}</div></div>` : '';
      const playbook = p.playbook || {};
      const playbookPhases = Array.isArray(playbook.phases) ? playbook.phases : [];
      const playbookHtml = playbookPhases.length ? `<div class="detail-section playbook-section"><h3>Incident playbook · ${esc(playbook.playbook_label || 'generic playbook')}</h3><p>${esc(playbook.execution_notice || 'Recommendations only. Nothing is executed by this playbook.')}</p>${playbook.knowledge_base_note ? `<p class="muted-copy">${esc(playbook.knowledge_base_note)}</p>` : ''}<div class="playbook-technique">ATT&CK: ${esc(playbook.technique_id || playbook.knowledge_base_reference || 'No technique recorded in the local knowledge base')}${playbook.technique_name ? ` · ${esc(playbook.technique_name)}` : ''}</div>${playbookPhases.map(phase => `<section class="playbook-phase"><h4>${esc(normalize(phase.name))}</h4>${phase.steps?.length ? `<ol>${phase.steps.map(step => `<li><span>${esc(step.action || '')}</span><small>${step.technique_id ? `Technique ${esc(step.technique_id)} · ` : 'Generic guidance · '}Evidence: ${esc((step.evidence_ids || []).join(', '))}</small></li>`).join('')}</ol>` : `<p class="muted-copy">No step has supporting evidence in this incident.</p><p class="muted-copy">${esc(phase.empty_reason || 'Left empty on purpose: steps must be justified by evidence.')}</p>`}</section>`).join('')}</div>` : '';
      const simulationLogs = Array.isArray(p.response_workflow?.simulation_logs) ? p.response_workflow.simulation_logs : [];
      const simulationLogHtml = simulationLogs.length ? `<div class="detail-section simulation-section"><h3>SIMULATION · dry-run log</h3><p role="status">No commands were executed and no real systems were changed.</p>${simulationLogs.map(log => `<div class="simulation-log"><b>${esc(safeDate(log.created_at))} · ${esc(log.mode || 'dry-run')} · executed: ${log.executed ? 'yes' : 'no'}</b><ol>${(log.steps || []).map(step => `<li><span>${esc(step.phase || 'response')}: ${esc(step.action || '')}</span><small>Would run · Evidence: ${esc((step.evidence_ids || []).join(', ') || 'none')}</small></li>`).join('')}</ol></div>`).join('')}</div>` : '';
      const currentState = item.status || 'New';
      const allowedTransitions = Array.isArray(item.allowed_transitions) ? item.allowed_transitions : [];
      const transitionOptions = allowedTransitions.length ? allowedTransitions.map(value => `<option value="${esc(value)}">${esc(value)}</option>`).join('') : '<option value="" disabled>No transitions available</option>';
      $('#detailBody').innerHTML = `<div class="detail-topline"><span class="decision-pill ${decisionClass(decision)}">${esc(decision)}</span><span class="status-pill ${statusClass(item.status)}">${esc(lifecycleLabel(item.status))}</span></div><div class="decision-guidance"><p>${esc(decisionExplanation)}</p><p><b>Next:</b> ${esc(nextHint)}</p></div>${generalizationNoteHtml}<div class="detail-grid">${metricHtml}</div>${endpointHtml}${threatIntelHtml}<div class="muted-copy">Model scores are raw and uncalibrated; they are not real-world likelihoods.</div>${explainHtml}${agentTraceHtml}<div class="detail-section"><h3>Investigation summary</h3><p>${esc(explanation)}</p></div>${analystNoteHtml}${reasons.length ? `<div class="detail-section"><h3>Decision factors</h3><ul>${reasons.map(x => `<li>${esc(x)}</li>`).join('')}</ul></div>` : ''}${evidenceTrailHtml}${evidence.length ? `<div class="detail-section"><h3>Flow evidence signals</h3><ul>${evidence.map(x => `<li>${esc(typeof x === 'string' ? x : JSON.stringify(x))}</li>`).join('')}</ul></div>` : ''}${tasks.length ? `<div class="detail-section"><h3>Suggested response actions</h3><ul>${tasks.map(x => `<li>${esc(x.action || x.description || JSON.stringify(x))} <span class="muted-copy">(${esc(x.status || 'proposed')})</span></li>`).join('')}</ul></div>` : ''}${historyHtml}<div class="detail-section"><h3>Resolution validation</h3><label class="field-label" for="validationState">Incident state</label><select class="select-control" id="validationState"><option value="in_progress">In progress</option><option value="resolved">Resolved</option><option value="not_resolved">Not resolved</option></select><label class="field-label" for="validationNote">Analyst note</label><input id="validationNote" class="text-input" placeholder="What did you verify?" maxlength="500"><label class="field-label" for="validationAction">Action taken</label><input id="validationAction" class="text-input" placeholder="Optional; this records work already performed" maxlength="300"></div><div class="muted-copy" style="margin-top:14px">Response approval records authorization for manual execution. It does not change firewall, host, or network controls.</div>`;
      $('#detailActions').innerHTML = `<button class="button outline" data-report="${esc(id)}">Open report</button>${tasks.length ? `<button class="button outline" data-approve="${esc(id)}">Approve &amp; log simulation</button>` : ''}<button class="button primary" data-validate="${esc(id)}">Save lifecycle update</button>`;
      const timelineHeading = [...$('#detailBody').querySelectorAll('.detail-section h3')].find(node => node.textContent === 'Analyst history');
      if (timelineHeading) timelineHeading.closest('.detail-section').insertAdjacentHTML('beforebegin', `${playbookHtml}${simulationLogHtml}`);
      else $('#detailBody').insertAdjacentHTML('beforeend', `${playbookHtml}${simulationLogHtml}`);
      const stateLabel = $('#detailBody').querySelector('label[for="validationState"]');
      if (stateLabel) stateLabel.textContent = 'Next incident state';
      const stateSelect = $('#validationState');
      stateSelect.innerHTML = `<option value="" selected disabled>Current: ${esc(currentState)}</option>${transitionOptions}`;
      stateSelect.required = true;
      const validationHeading = stateLabel?.closest('.detail-section')?.querySelector('h3');
      if (validationHeading) validationHeading.textContent = 'Incident lifecycle';
      const saveValidation = $('#detailActions').querySelector('[data-validate]');
      if (saveValidation) saveValidation.textContent = 'Save lifecycle update';
      const approveButton = $('#detailActions').querySelector('[data-approve]');
      if (approveButton) approveButton.textContent = 'Approve & log simulation';
      const executionCopy = [...$('#detailBody').querySelectorAll('.muted-copy')].find(node => node.textContent.includes('Response approval records authorization'));
      if (executionCopy) executionCopy.textContent = 'Approval writes a SIMULATION dry-run log only. No real systems are changed.';
      openModal('detailModal');
    } catch (error) { toast('Could not open incident', error.message, 'error'); }
  }
  async function validateIncident(id) {
    try { const body = { state: $('#validationState').value, note: $('#validationNote').value, action_taken: $('#validationAction').value }; if (!body.state) throw new Error('Choose an allowed next state.'); await api(`/api/incidents/${encodeURIComponent(id)}/validation`, { method: 'POST', body: JSON.stringify(body) }); toast('Lifecycle updated', `Incident moved to ${body.state}.`, 'success'); closeModal('detailModal'); await loadIncidents(); }
    catch (error) { toast('Validation failed', error.message, 'error'); }
  }
  async function approveIncident(id) {
    try { await api(`/api/incidents/${encodeURIComponent(id)}/response/approve`, { method: 'POST', body: JSON.stringify({ approved_by: 'local analyst' }) }); toast('Simulation log saved', 'SIMULATION only. No commands ran and no real systems changed.', 'success'); await openIncident(id); await loadIncidents(); }
    catch (error) { toast('Approval failed', error.message, 'error'); }
  }
  function openReport(id) { window.open(`/api/incidents/${encodeURIComponent(id)}/report/download`, '_blank', 'noopener'); }
  function parseCsv(text) {
    const rows = []; let row = [], field = '', quoted = false;
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (quoted) { if (c === '"' && text[i + 1] === '"') { field += '"'; i++; } else if (c === '"') quoted = false; else field += c; }
      else if (c === '"') quoted = true;
      else if (c === ',') { row.push(field); field = ''; }
      else if (c === '\n') { row.push(field.replace(/\r$/, '')); rows.push(row); row = []; field = ''; }
      else field += c;
    }
    if (quoted) throw new Error('CSV has an unclosed quoted field.');
    if (field.length || row.length) { row.push(field.replace(/\r$/, '')); rows.push(row); }
    const headers = (rows.shift() || []).map((v, i) => (i === 0 ? v.replace(/^\uFEFF/, '') : v).trim());
    if (!headers.length || headers.every(h => !h)) throw new Error('CSV does not contain a header row.');
    const flows = rows.filter(values => values.some(v => v.trim() !== '')).map(values => {
      const flow = {}; headers.forEach((header, index) => { if (!header || /^label$/i.test(header)) return; const raw = (values[index] || '').trim(); if (raw === '') { flow[header] = null; return; } const number = Number(raw); flow[header] = Number.isFinite(number) ? number : raw; }); return flow;
    });
    return { headers, flows };
  }
  async function startBatch(flows, sourceName) {
    if (!flows.length) throw new Error('No flow rows were found.');
    if (flows.length > 100) throw new Error('The dashboard accepts up to 100 rows per analysis.');
    $('#analysisProgress').classList.add('visible'); $('#batchResult').classList.remove('visible'); $('#progressTitle').textContent = `Analyzing ${flows.length} flow${flows.length === 1 ? '' : 's'}…`; $('#progressText').textContent = 'The local detector and investigation pipeline are processing this batch.';
    $('#runDemo').disabled = true; $('#flowFile').disabled = true;
    try {
      const data = await api('/api/analyze-batch', { method: 'POST', body: JSON.stringify({ flows }) });
      state.recentBatch = data.results; renderBatch(data, sourceName); renderChart();
      toast('Analysis complete', `${data.rows} flows analyzed · ${data.pipeline_failures} pipeline failures.`, data.pipeline_failures ? 'error' : 'success');
      await loadIncidents();
    } finally { $('#analysisProgress').classList.remove('visible'); $('#runDemo').disabled = false; $('#flowFile').disabled = false; }
  }
  function driftBanner(drift) {
    if (!drift || drift.status === 'ok') return '';
    const palette = { warning: ['#ff5d5d', 'rgba(255,93,93,.12)'], caution: ['#ffb020', 'rgba(255,176,32,.12)'], unavailable: ['#8a94a6', 'rgba(138,148,166,.12)'] };
    const [edge, fill] = palette[drift.status] || palette.unavailable;
    const message = drift.status === 'unavailable'
      ? 'Training data could not be compared. Review these results with care.'
      : 'This data looks different from training data. Review these results with care.';
    return `<div class="drift-banner" role="alert" style="border-left:4px solid ${edge};background:${fill};padding:10px 14px;margin-bottom:10px;border-radius:6px;font-size:13px;line-height:1.4"><b>${esc(message)}</b></div>`;
  }
  function batchTopReason(item) {
    const decision = item.final_decision || 'FAILED';
    const reasons = item.decision?.correlation_reasons;
    const reason = (Array.isArray(reasons) ? reasons[0] : '') || item.decision?.explanation || item.investigation?.finding || item.investigation?.explanation || item.error || decisionGuidance(decision)[0];
    const text = typeof reason === 'string' ? reason : JSON.stringify(reason);
    return String(text || '').replace(/\s+/g, ' ').trim();
  }
  function batchRiskScore(item) {
    const score = item?.risk?.score;
    return score == null || !Number.isFinite(Number(score)) ? null : Number(score);
  }
  function visibleBatchRows() {
    const decision = $('#batchDecisionFilter')?.value || 'ALL';
    const query = ($('#batchSearch')?.value || '').trim().toLowerCase();
    const rows = batchTableState.rows.filter(item => {
      const rowDecision = String(item.final_decision || 'FAILED').toUpperCase();
      if (decision !== 'ALL' && rowDecision !== decision) return false;
      if (!query) return true;
      return [item.row_number, rowDecision, item.risk?.score, batchTopReason(item), item.incident_id]
        .some(value => String(value ?? '').toLowerCase().includes(query));
    });
    const direction = batchTableState.sortDirection === 'asc' ? 1 : -1;
    rows.sort((a, b) => {
      const key = batchTableState.sortKey;
      const left = key === 'risk_score' ? batchRiskScore(a) : key === 'top_reason' ? batchTopReason(a).toLowerCase() : key === 'incident_id' ? String(a.incident_id || '').toLowerCase() : key === 'decision' ? String(a.final_decision || 'FAILED').toLowerCase() : Number(a.row_number || 0);
      const right = key === 'risk_score' ? batchRiskScore(b) : key === 'top_reason' ? batchTopReason(b).toLowerCase() : key === 'incident_id' ? String(b.incident_id || '').toLowerCase() : key === 'decision' ? String(b.final_decision || 'FAILED').toLowerCase() : Number(b.row_number || 0);
      if (typeof left === 'number' || typeof right === 'number') {
        const l = Number.isFinite(left) ? left : -Infinity; const r = Number.isFinite(right) ? right : -Infinity;
        return (l - r) * direction;
      }
      return String(left).localeCompare(String(right)) * direction;
    });
    return rows;
  }
  function renderBatchTable() {
    const rows = visibleBatchRows(); const tbody = $('#batchResultsBody');
    if (!tbody) return;
    tbody.innerHTML = rows.length ? rows.map(item => {
      const decision = item.final_decision || 'FAILED'; const rawScore = batchRiskScore(item);
      const score = rawScore == null ? '—' : String(Math.round(rawScore));
      const incident = item.incident_id ? `<button type="button" class="text-button" data-open="${esc(item.incident_id)}" aria-label="Open incident INC-${esc(shortId(item.incident_id))}">INC-${esc(shortId(item.incident_id))}</button>` : '<span aria-label="No incident linked">—</span>';
      return `<tr><td>${esc(item.row_number ?? '—')}</td><td><span class="decision-pill ${decisionClass(decision)}">${esc(decision)}</span></td><td title="Priority score for sorting and review. Classifier outputs are raw and uncalibrated.">${esc(score)}</td><td class="batch-reason">${esc(batchTopReason(item))}</td><td>${incident}</td></tr>`;
    }).join('') : `<tr><td colspan="5" class="empty-cell">${batchTableState.rows.length ? 'No results match these filters.' : 'No batch results are available.'}</td></tr>`;
    const count = $('#batchResultCount');
    if (count) count.textContent = `Showing ${rows.length} of ${batchTableState.rows.length} result${batchTableState.rows.length === 1 ? '' : 's'}.`;
    $$('[data-batch-sort]').forEach(button => {
      const active = button.dataset.batchSort === batchTableState.sortKey;
      const th = button.closest('th');
      if (th) th.setAttribute('aria-sort', active ? (batchTableState.sortDirection === 'asc' ? 'ascending' : 'descending') : 'none');
      button.setAttribute('aria-label', `Sort by ${button.textContent.trim()}${active ? (batchTableState.sortDirection === 'asc' ? ', ascending' : ', descending') : ''}`);
    });
    const disabled = rows.length === 0;
    $('#exportBatchCsv').disabled = disabled; $('#exportBatchJson').disabled = disabled;
  }
  function exportBatchResults(format) {
    const rows = visibleBatchRows().map(item => ({
      row: item.row_number ?? '', decision: item.final_decision || 'FAILED',
      risk_score: batchRiskScore(item),
      top_reason: batchTopReason(item), incident_id: item.incident_id || '',
    }));
    if (!rows.length) return;
    let contents; let type; let extension;
    if (format === 'json') {
      contents = JSON.stringify(rows, null, 2); type = 'application/json;charset=utf-8'; extension = 'json';
    } else {
      const columns = ['row', 'decision', 'risk_score', 'top_reason', 'incident_id'];
      const quote = value => `"${String(value ?? '').replace(/"/g, '""')}"`;
      contents = [columns.map(quote).join(','), ...rows.map(row => columns.map(column => quote(row[column])).join(','))].join('\r\n');
      type = 'text/csv;charset=utf-8'; extension = 'csv';
    }
    const url = URL.createObjectURL(new Blob([contents], { type })); const link = document.createElement('a');
    link.href = url; link.download = `batch-results-${new Date().toISOString().slice(0, 10)}.${extension}`; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  function renderBatch(data, sourceName) {
    const holder = $('#batchResult'); const dec = data.decisions || {}; const resultRows = data.results || [];
    batchTableState.rows = resultRows; batchTableState.sortKey = 'row_number'; batchTableState.sortDirection = 'asc';
    const chips = [`<span class="summary-chip">SOURCE <b>${esc(sourceName)}</b></span>`, `<span class="summary-chip">ROWS <b>${data.rows}</b></span>`, `<span class="summary-chip">FAILURES <b>${data.pipeline_failures}</b></span>`, ...['ATTACK', 'REVIEW', 'BENIGN', 'FAILED'].filter(k => dec[k]).map(k => `<span class="summary-chip" style="color:${colors[k]}">${k} <b>${dec[k]}</b></span>` )];
    const failedStages = [...new Set(resultRows.flatMap(row => (row.agent_trace || []).filter(entry => entry.status === 'unavailable').map(entry => entry.agent || 'Unknown stage')))];
    const stageWarning = failedStages.length ? `<div class="agent-trace-warning" role="alert"><b>Warning:</b> unavailable analysis stage${failedStages.length === 1 ? '' : 's'}: ${esc(failedStages.join(', '))}. Review partial results before acting.</div>` : '';
    holder.innerHTML = driftBanner(data.input_drift) + stageWarning + `<div class="batch-summary">${chips.join('')}</div><section class="batch-results-panel" aria-label="Batch analysis results"><div class="batch-result-tools"><label class="batch-control">Decision type<select id="batchDecisionFilter" class="select-control"><option value="ALL">All decisions</option><option value="ATTACK">ATTACK</option><option value="REVIEW">REVIEW</option><option value="BENIGN">BENIGN</option><option value="FAILED">FAILED</option></select></label><label class="batch-control batch-search-control">Search<input id="batchSearch" type="search" class="text-input" placeholder="Row, decision, reason, or incident"></label><div class="batch-export-tools"><button type="button" class="button outline" id="exportBatchCsv">Export CSV</button><button type="button" class="button outline" id="exportBatchJson">Export JSON</button></div></div><p class="batch-result-count" id="batchResultCount" role="status" aria-live="polite"></p><div class="batch-results-scroll" role="region" aria-label="Batch results table" tabindex="0"><table class="batch-results-table"><caption class="sr-only">Sortable and filterable results for this flow analysis batch.</caption><thead><tr><th scope="col" aria-sort="ascending"><button type="button" data-batch-sort="row_number">Row</button></th><th scope="col" aria-sort="none"><button type="button" data-batch-sort="decision">Decision</button></th><th scope="col" aria-sort="none" title="Priority score for sorting and review. Classifier outputs are raw and uncalibrated."><button type="button" data-batch-sort="risk_score">Risk score</button></th><th scope="col" aria-sort="none"><button type="button" data-batch-sort="top_reason">Top reason</button></th><th scope="col" aria-sort="none"><button type="button" data-batch-sort="incident_id">Incident link</button></th></tr></thead><tbody id="batchResultsBody"></tbody></table></div></section>`;
    holder.classList.add('visible'); renderBatchTable(); drawThreatField(resultRows);
  }
  async function runDemo(options = {}) {
    const quick = options.quick === true;
    try {
      if (quick) {
        openAnalyze();
        $('#runQuickDemo').disabled = true;
        $('#analysisProgress').classList.add('visible');
        $('#progressTitle').textContent = 'Loading 10 mixed sample flows…';
        $('#progressText').textContent = 'Getting a ready-to-run sample from this machine.';
      }
      const limit = quick ? '10' : $('#demoLimit').value;
      const attackType = quick ? 'all' : $('#demoAttackType').value;
      const demo = await api(`/api/sample-flows?limit=${limit}&attack_type=${encodeURIComponent(attackType)}`);
      if (quick) {
        $('#progressTitle').textContent = 'Analyzing 10 mixed sample flows…';
        $('#progressText').textContent = 'The local detector is checking the sample.';
      }
      state.selectedDemoType = attackType === 'all' ? null : demo.attack_type;
      if (state.selectedDemoType) sessionStorage.setItem('cyber.selectedDemoAttackType', state.selectedDemoType);
      else sessionStorage.removeItem('cyber.selectedDemoAttackType');
      await startBatch(demo.flows, demo.source);
      if (quick) {
        if (!state.recentBatch.some(item => item.final_decision === 'ATTACK')) {
          const note = document.createElement('div');
          note.className = 'quick-demo-note';
          note.setAttribute('role', 'status');
          note.textContent = 'No ATTACK verdict appeared in these 10 mixed sample flows. That does not mean traffic is safe; the detector did not flag an attack in this sample.';
          $('#batchResult').prepend(note);
        }
        $('#batchResult').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }
      if (attackType !== 'all') {
        const detected = state.recentBatch.filter(item => item.final_decision === 'ATTACK')
          .sort((a, b) => Number(b.risk?.score || 0) - Number(a.risk?.score || 0))[0];
        if (detected) startScenarioReplay({ ...pickScenario(detected.final_attack), detectedFamily: detected.final_attack }, detected.flow_context || null);
        else {
          showLiveFlowScene();
          $('#attackExplainerTitle').textContent = 'No ATTACK verdict in this batch';
          $('#attackExplainerText').textContent = 'The selected sample contains this attack type, but the detector did not classify any analyzed flow as ATTACK. The dashboard will not show that attack simulation as if it were detected.';
        }
      }
    }
    catch (error) { toast('Demo analysis failed', error.message, 'error'); $('#analysisProgress').classList.remove('visible'); $('#runDemo').disabled = false; }
    finally { if (quick) $('#runQuickDemo').disabled = false; }
  }  function showUploadMessage(message, kind = 'error') {
    $('#uploadFeedback').innerHTML = `<div class="upload-message ${kind}">${esc(message)}</div>`;
  }
  function ignoredColumnMessage(columns) {
    return columns.length ? `Extra columns not used as model inputs: ${columns.join(', ')}.` : '';
  }
  function renderCsvPreview(headers, flows, canAnalyze = true) {
    const sample = flows.slice(0, 5);
    const head = `<thead><tr>${headers.map(header => `<th>${esc(header)}</th>`).join('')}</tr></thead>`;
    const body = `<tbody>${sample.map(flow => `<tr>${headers.map(header => `<td>${esc(flow[header] ?? '')}</td>`).join('')}</tr>`).join('')}</tbody>`;
    $('#csvPreviewTable').innerHTML = `<table>${head}${body}</table>`;
    $('#csvPreview').hidden = false;
    $('#analyzeUploadedCsv').disabled = !canAnalyze;
  }
  async function uploadCsv(file) {
    if (!file) return;
    state.pendingCsvFlows = null;
    $('#csvPreview').hidden = true;
    $('#analyzeUploadedCsv').disabled = true;
    $('#uploadFeedback').textContent = '';
    $('#fileName').textContent = file.name;
    if (file.size > 25 * 1024 * 1024) {
      showUploadMessage(`This file is larger than 25 MB. The dashboard limit is 25 MB. For larger files, use the CLI: ${cliHint}`);
      return;
    }
    try {
      const { headers, flows } = parseCsv(await file.text());
      if (!flows.length) throw new Error('This CSV has no data rows. Add at least one flow and try again.');
      if (flows.length > 100) {
        showUploadMessage(`This file has ${flows.length} rows. The dashboard limit is 100 rows. For larger files, use the CLI: ${cliHint}`);
        return;
      }
      const missing = featureNames.filter(name => !headers.includes(name));
      const extras = headers.filter(name => name && !featureNames.includes(name));
      const messages = [];
      if (missing.length) {
        const shown = missing.slice(0, 10);
        messages.push(`Missing columns (${missing.length}): ${shown.join(', ')}${missing.length > 10 ? `, +${missing.length - 10} more` : ''}.`);
      }
      const extraMessage = ignoredColumnMessage(extras);
      if (extraMessage) messages.push(extraMessage);
      const invalidValues = featureNames.filter(name => headers.includes(name) && flows.some(flow => typeof flow[name] !== 'number' || !Number.isFinite(flow[name])));
      if (invalidValues.length) messages.push(`Use numbers in these columns: ${invalidValues.slice(0, 10).join(', ')}${invalidValues.length > 10 ? `, +${invalidValues.length - 10} more` : ''}.`);
      renderCsvPreview(headers, flows, !missing.length && !invalidValues.length);
      if (messages.length) {
        showUploadMessage(messages.join(' '), missing.length || invalidValues.length ? 'error' : 'info');
      }
      if (missing.length || invalidValues.length) return;
      state.pendingCsvFlows = flows;
      if (!messages.length) showUploadMessage(`${flows.length} rows ready to preview and analyze.`, 'success');
    } catch (error) {
      showUploadMessage(error.message || 'Could not read this CSV. Check the file and try again.');
    }
  }
  async function analyzeUploadedCsv() {
    if (!state.pendingCsvFlows) return;
    const flows = state.pendingCsvFlows;
    $('#analyzeUploadedCsv').disabled = true;
    state.selectedDemoType = null;
    sessionStorage.removeItem('cyber.selectedDemoAttackType');
    $('#demoAttackType').value = 'all';
    try { await startBatch(flows, $('#fileName').textContent); state.pendingCsvFlows = null; }
    catch (error) { toast('CSV analysis failed', error.message, 'error'); }
    finally { $('#analyzeUploadedCsv').disabled = !state.pendingCsvFlows; }
  }
  async function searchEvidence(query) {
    if (!query.trim()) return; const holder = $('#evidenceResults'); holder.innerHTML = `<div class="empty-state"><span class="spinner"></span><span>Searching local references…</span></div>`;
    try {
      const data = await api(`/api/evidence/search?q=${encodeURIComponent(query)}&limit=6`); const items = data.results || [];
      holder.innerHTML = items.length ? items.map(item => `<article class="panel evidence-card"><h3>${esc(item.title || item.family || 'Reference')}</h3><div class="evidence-meta">${esc(item.family || 'General')} · ${esc(item.source_name || 'Local evidence library')}${item.technique_id ? ` · ${esc(item.technique_id)}` : ''}${item.source_url ? ` · <a class="evidence-ref" href="${esc(item.source_url)}" target="_blank" rel="noreferrer">Source ↗</a>` : ''}</div><div class="evidence-body">${esc(item.body || item.text || '')}</div></article>`).join('') : `<div class="empty-state"><b>No references found</b><span>Try an attack family or investigation keyword.</span></div>`;
    } catch (error) { holder.innerHTML = `<div class="empty-state"><b>Search failed</b><span>${esc(error.message)}</span></div>`; }
  }
  async function importIocs(event) {
    event.preventDefault(); $('#iocError').textContent = '';
    try {
      const indicators = JSON.parse($('#iocJson').value); if (!Array.isArray(indicators)) throw new Error('The input must be a JSON array.');
      const result = await api('/api/threat-intel/import', { method: 'POST', body: JSON.stringify({ indicators, source: $('#iocSource').value.trim() || 'manual' }) });
      closeModal('iocModal'); toast('Indicators imported', `${result.stored} indicators stored.`, 'success'); await loadIocs();
    } catch (error) { $('#iocError').textContent = error.message; }
  }
  async function findRelatedIncidents() {
    const button = $('#correlateIncidentsBtn'); const holder = $('#correlationResults');
    button.disabled = true; holder.textContent = 'Checking stored incidents…';
    try {
      const minutes = Number($('#correlationWindow').value);
      const result = await api(`/api/incidents/correlated?window_minutes=${minutes}&limit=500`);
      const groups = result.groups || [];
      holder.innerHTML = groups.length
        ? `<div class="table-scroll"><table><thead><tr><th>SHARED IP</th><th>INCIDENTS</th><th>FAMILIES</th><th>FIRST SEEN</th><th>LAST SEEN</th></tr></thead><tbody>${groups.map(group => `<tr><td>${esc(group.shared_endpoint)}</td><td>${group.incident_ids.map(id => `<button class="text-button" data-open="${esc(id)}">${esc(id.slice(0, 8))}</button>`).join(', ')}</td><td>${group.families.map(esc).join(', ')}</td><td>${esc(new Date(group.first_seen).toLocaleString())}</td><td>${esc(new Date(group.last_seen).toLocaleString())}</td></tr>`).join('')}</tbody></table></div><p class="muted-copy">Candidate links use a shared IP and ingestion time. They do not confirm a common campaign.</p>`
        : '<div class="empty-state"><b>No candidate groups found</b><span>Incidents need source or destination IP metadata to be correlated.</span></div>';
    } catch (error) { holder.textContent = `Correlation failed: ${error.message}`; }
    finally { button.disabled = false; }
  }
  async function syncThreatFox() {
    const button = $('#syncThreatFoxBtn'); button.disabled = true;
    try {
      const result = await api('/api/threat-intel/sync?days=3', { method: 'POST' });
      toast('ThreatFox sync complete', `${result.stored} indicators stored; ${result.skipped} unsupported or expired entries skipped.`, 'success');
      await loadIocs();
    } catch (error) { toast('ThreatFox sync failed', error.message, 'error'); }
    finally { button.disabled = false; }
  }
  function attachEvents() {
    const banner = $('#prototypeBanner');
    if (localStorage.getItem('cyber.prototypeBannerDismissed') === 'true') banner.hidden = true;
    $('#dismissPrototypeBanner').addEventListener('click', () => { banner.hidden = true; localStorage.setItem('cyber.prototypeBannerDismissed', 'true'); });
    $$('.nav-item').forEach(button => button.addEventListener('click', () => nav(button.dataset.view)));
    $$('[data-go]').forEach(button => button.addEventListener('click', () => nav(button.dataset.go)));
    $('#analyzeBtn').addEventListener('click', openAnalyze); $('#analyzeBtn2').addEventListener('click', openAnalyze);
    $('#refreshBtn').addEventListener('click', refreshAll); $('#runDemo').addEventListener('click', () => runDemo()); $('#runQuickDemo').addEventListener('click', () => runDemo({ quick: true }));
    $('#analyzeUploadedCsv').addEventListener('click', analyzeUploadedCsv);
    $('#demoAttackType').addEventListener('change', event => {
      const choice = event.target.selectedOptions[0];
      if (event.target.value === 'all') {
        state.selectedDemoType = null;
        sessionStorage.removeItem('cyber.selectedDemoAttackType');
        showLiveFlowScene();
        return;
      }
      const selectedSampleType = choice?.textContent?.trim() || event.target.value;
      state.selectedDemoType = selectedSampleType;
      sessionStorage.setItem('cyber.selectedDemoAttackType', selectedSampleType);
      showLiveFlowScene();
      state.scenario = null; $('#playAttack').disabled = true;
      $('#attackExplainerTitle').textContent = 'Run analysis to see a detected attack';
      $('#attackExplainerText').textContent = `The ${selectedSampleType} sample is not treated as a detection. Run the demo first; an attack simulation appears only if the detector returns an ATTACK verdict.`;
    });
    $('#flowFile').addEventListener('change', event => { const file = event.target.files[0]; if (file) uploadCsv(file); });
    const drop = $('#dropZone'); drop.addEventListener('dragover', event => { event.preventDefault(); drop.classList.add('dragover'); }); drop.addEventListener('dragleave', () => drop.classList.remove('dragover')); drop.addEventListener('drop', event => { event.preventDefault(); drop.classList.remove('dragover'); uploadCsv(event.dataTransfer.files[0]); });
    $$('[data-close]').forEach(button => button.addEventListener('click', () => closeModal(button.dataset.close)));
    $$('.modal-backdrop').forEach(backdrop => backdrop.addEventListener('click', event => { if (event.target === backdrop) closeModal(backdrop.id); }));
    document.addEventListener('keydown', event => {
      const modal = $$('.modal-backdrop.open').at(-1);
      if (!modal) return;
      if (event.key === 'Escape') { event.preventDefault(); closeModal(modal.id); return; }
      if (event.key !== 'Tab') return;
      const focusables = modalFocusableElements(modal);
      if (!focusables.length) {
        event.preventDefault(); (modal.querySelector('[role="dialog"]') || modal).focus(); return;
      }
      const first = focusables[0], last = focusables[focusables.length - 1];
      if (event.shiftKey && (document.activeElement === first || !modal.contains(document.activeElement))) {
        event.preventDefault(); last.focus();
      } else if (!event.shiftKey && (document.activeElement === last || !modal.contains(document.activeElement))) {
        event.preventDefault(); first.focus();
      }
    });
    document.addEventListener('click', event => {
      const open = event.target.closest('[data-open]'); if (open) openIncident(open.dataset.open);
      const approve = event.target.closest('[data-approve]'); if (approve) approveIncident(approve.dataset.approve);
      const validate = event.target.closest('[data-validate]'); if (validate) validateIncident(validate.dataset.validate);
      const report = event.target.closest('[data-report]'); if (report) openReport(report.dataset.report);
    });
    $('#incidentSearch').addEventListener('input', renderIncidents); $('#allIncidentSearch').addEventListener('input', renderIncidents); $('#statusFilter').addEventListener('change', renderIncidents); $('#decisionFilter').addEventListener('change', renderIncidents); $('#incidentSort').addEventListener('change', renderIncidents); $('#iocSearch').addEventListener('input', renderIocs);
    $('#importIocBtn').addEventListener('click', () => openModal('iocModal')); $('#iocForm').addEventListener('submit', importIocs);
    $('#syncThreatFoxBtn').addEventListener('click', syncThreatFox);
    $('#correlateIncidentsBtn').addEventListener('click', findRelatedIncidents);
    const batchResults = $('#batchResult');
    batchResults.addEventListener('input', event => { if (event.target.id === 'batchSearch') renderBatchTable(); });
    batchResults.addEventListener('change', event => { if (event.target.id === 'batchDecisionFilter') renderBatchTable(); });
    batchResults.addEventListener('click', event => {
      const sort = event.target.closest('[data-batch-sort]');
      if (sort) {
        const key = sort.dataset.batchSort;
        if (batchTableState.sortKey === key) batchTableState.sortDirection = batchTableState.sortDirection === 'asc' ? 'desc' : 'asc';
        else { batchTableState.sortKey = key; batchTableState.sortDirection = key === 'risk_score' ? 'desc' : 'asc'; }
        renderBatchTable();
      }
      if (event.target.closest('#exportBatchCsv')) exportBatchResults('csv');
      if (event.target.closest('#exportBatchJson')) exportBatchResults('json');
    });
    $('#evidenceForm').addEventListener('submit', event => { event.preventDefault(); searchEvidence($('#evidenceQuery').value); });
    $$('.quick-searches button').forEach(button => button.addEventListener('click', () => { $('#evidenceQuery').value = button.dataset.query; searchEvidence(button.dataset.query); }));
  }
  function initCanvas() {
    const canvas = $('#threatCanvas'); const ctx = canvas.getContext('2d'); state.canvas = { canvas, ctx, nodes: [], edges: [], hitTargets: [], graphTime: 0, animationFrame: null };
    const attachThree = () => { if (!window.CyberThreeScene || !state.canvas) return; state.canvas.three = window.CyberThreeScene; render3d(); };
    const showCanvasFallback = () => {
      document.documentElement.classList.remove('three-ready');
      $('#threatCanvas3d')?.remove();
      $('#sceneFallbackNotice').hidden = false;
      $('#sceneCanvasLabel').innerHTML = 'CANVAS FLOW GRAPH <span>2D FALLBACK</span>';
      if (state.canvas) { state.canvas.three = null; render3d(); }
    };
    window.addEventListener('cyber3dready', attachThree);
    window.addEventListener('cyber3dunavailable', showCanvasFallback);
    if (window.CyberThreeSceneUnavailable) showCanvasFallback();
    window.addEventListener('cyber3dselect', event => {
      const node = state.canvas?.nodes?.find(item => item.key === event.detail?.key);
      if (!node) return;
      state.canvas.selectedNodeKey = node.key; setEndpointDetails(node.context, false); render3d();
      $('#attackExplainerTitle').textContent = `${node.role === 'source' ? 'Source' : 'Destination'} · ${node.label}`;
      $('#attackExplainerText').textContent = `${node.flows} analyzed connection${node.flows === 1 ? '' : 's'} touch this endpoint; ${node.attacks} were classified ATTACK and ${node.reviews} REVIEW. These are model decisions, not proof of compromise.`;
    });
    attachThree();
    const resize = () => { const rect = canvas.getBoundingClientRect(); const dpr = Math.min(1.5, window.devicePixelRatio || 1); canvas.width = Math.max(1, Math.floor(rect.width * dpr)); canvas.height = Math.max(1, Math.floor(rect.height * dpr)); ctx.setTransform(dpr, 0, 0, dpr, 0, 0); render3d(); };
    new ResizeObserver(resize).observe(canvas); resize();
    canvas.addEventListener('pointerdown', event => { state.dragging = true; state.dragMoved = false; state.pointer = { x: event.clientX, y: event.clientY }; canvas.setPointerCapture(event.pointerId); });
    canvas.addEventListener('pointermove', event => { if (!state.dragging) return; const dx = event.clientX - state.pointer.x, dy = event.clientY - state.pointer.y; if (Math.abs(dx) + Math.abs(dy) > 3) state.dragMoved = true; state.angle += dx * .009; state.pointer = { x: event.clientX, y: event.clientY }; render3d(); });
    canvas.addEventListener('pointerup', event => { state.dragging = false; if (!state.dragMoved) selectGraphNodeAt(event.offsetX, event.offsetY); }); canvas.addEventListener('pointercancel', () => { state.dragging = false; });
    canvas.addEventListener('wheel', event => { event.preventDefault(); state.zoom = Math.min(1.7, Math.max(.7, state.zoom + (event.deltaY < 0 ? .08 : -.08))); render3d(); }, { passive: false });
    $('#reset3d').addEventListener('click', () => { state.angle = .35; state.zoom = 1; state.canvas?.three?.reset(); render3d(); });
    $('#playAttack').addEventListener('click', toggleAttackReplay);
    $('#restartAttack').addEventListener('click', restartAttackReplay);
    $('#showLiveFlows').addEventListener('click', toggleFlowDataView);
    $('#replaySpeed').addEventListener('change', event => { state.replay.speed = Number(event.target.value) === 2 ? 2 : 1; });
  }
  function drawThreatField(results) {
    const rows = (results || []).filter(item => item.pipeline_completed).slice(0, 100);
    const nodes = new Map(), edges = [];
    const hash = value => { let n = 2166136261; for (const ch of String(value)) n = Math.imul(n ^ ch.charCodeAt(0), 16777619); return n >>> 0; };
    const endpoint = (context, side, index) => {
      const host = context[`${side}_host`], ip = context[`${side}_ip`];
      if (!host && !ip) return { id: `unknown-${side}`, display: side === 'source' ? 'Unknown sources' : 'Unknown destinations' };
      const id = String(ip || host || `${side === 'source' ? 'Source' : 'Destination'} flow ${index + 1}`).trim();
      const display = String(host || ip || `${side === 'source' ? 'Source' : 'Destination'} ${index + 1}`);
      return { id, display };
    };
    const ensureNode = (role, endpointInfo, context) => {
      let key = `${role}:${endpointInfo.id}`;
      if (!nodes.has(key) && nodes.size >= 30) key = `overflow:${role}`;
      if (!nodes.has(key)) {
        const seed = hash(key);
        const slot = [...nodes.values()].filter(node => node.role === role).length;
        const column = slot % 5, row = Math.floor(slot / 5);
        const side = role === 'source' ? -1 : 1;
        nodes.set(key, {
          key, role, label: key.startsWith('overflow:') ? (role === 'source' ? 'More sources' : 'More targets') : endpointInfo.display,
          x: side * (.68 + ((seed % 100) / 1000)),
          y: endpointInfo.id.startsWith('unknown-') ? 0 : .2 - row * .2,
          z: endpointInfo.id.startsWith('unknown-') ? 0 : (column - 2) * .28,
          context, flows: 0, attacks: 0, reviews: 0, risk: 0, color: colors.BENIGN,
        });
      }
      return nodes.get(key);
    };
    rows.forEach((item, index) => {
      const context = item.flow_context || {};
      const source = ensureNode('source', endpoint(context, 'source', index), context);
      const target = ensureNode('destination', endpoint(context, 'destination', index), context);
      const decision = String(item.final_decision || 'FAILED').toUpperCase();
      const risk = Math.max(0, Math.min(100, Number(item.risk?.score || 0)));
      const color = colors[decision] || colors.FAILED;
      for (const node of [source, target]) {
        node.flows++;
        if (decision === 'ATTACK') node.attacks++;
        if (decision === 'REVIEW') node.reviews++;
        node.risk = Math.max(node.risk, risk);
        if (decision === 'ATTACK' || (decision === 'REVIEW' && !node.attacks)) node.color = color;
      }
      edges.push({ source, target, decision, color, label: item.final_attack || 'Unclassified', risk, index, context, rowNumber: item.row_number, incidentId: item.incident_id });
    });
    state.canvas.nodes = [...nodes.values()];
    state.canvas.edges = edges;
    renderFlowDataTable(edges);
    state.canvas.hitTargets = [];
    state.canvas.selectedNodeKey = [...nodes.values()].sort((a, b) => (b.attacks * 100 + b.risk) - (a.attacks * 100 + a.risk))[0]?.key || null;
    state.sceneMode = 'live'; state.replay.playing = false;
    if (state.replay.frameId != null) cancelAnimationFrame(state.replay.frameId);
    state.replay.frameId = null; state.replay.sceneKey = null;
    const lead = [...rows].filter(item => item.final_decision === 'ATTACK').sort((a, b) => Number(b.risk?.score || 0) - Number(a.risk?.score || 0))[0];
    state.scenario = lead ? { ...pickScenario(lead.final_attack || 'Suspicious activity'), detectedFamily: lead.final_attack } : null;
    state.sceneContext = lead?.flow_context || null;
    $('#playAttack').disabled = !lead;
    $('#threatPanel').classList.remove('demo-active'); $('#sceneWrap').classList.remove('demo-mode');
    $('#sceneModeBadge').innerHTML = `<i></i> FLOW GRAPH`;
    $('#sceneSubtitle').textContent = `${edges.length} analyzed flow${edges.length === 1 ? '' : 's'} · ${nodes.size} endpoint${nodes.size === 1 ? '' : 's'}`;
    $('#sceneCanvasLabel').innerHTML = '3D FLOW TOPOLOGY <span>ANALYZED DATA</span>';
    $('.scene-hint').textContent = 'DRAG TO ROTATE · CLICK A NODE · SCROLL TO ZOOM';
    $('#sceneLegend').style.display = '';
    $('#attackExplainerTitle').textContent = 'Observed flow topology';
    const hasEndpoints = rows.some(item => item.flow_context && (item.flow_context.source_ip || item.flow_context.source_host || item.flow_context.destination_ip || item.flow_context.destination_host));
    $('#attackExplainerText').textContent = hasEndpoints
      ? 'Each connection represents one analyzed flow between supplied endpoints. Node and line colors show the system decision. Select a node for its associated endpoint details.'
      : 'No host or IP identifiers were supplied. The graph groups these flows into clearly labeled unknown-endpoint nodes; they do not represent real devices. Add endpoint metadata to see the actual systems.';
    if (!lead && edges.length) {
      $('#attackExplainerTitle').textContent = 'No ATTACK verdict in these flows';
      $('#attackExplainerText').textContent = 'The displayed connections are colored by the pipeline decisions. No attack-specific simulation is available because no flow was classified as ATTACK.';
    }
    const withEndpoints = [...rows].reverse().find(item => item.flow_context && Object.keys(item.flow_context).length);
    setEndpointDetails(withEndpoints?.flow_context || null, false);
    $('#sceneEmpty').classList.toggle('hidden', edges.length > 0);
    render3d(); animateFlowGraph();
  }
  function animateFlowGraph() {
    const graph = state.canvas;
    if (!graph?.edges?.length || matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    if (graph.animationFrame != null) cancelAnimationFrame(graph.animationFrame);
    graph.animationUntil = performance.now() + 5200;
    const frame = now => {
      if (state.sceneMode !== 'live' || document.visibilityState === 'hidden' || now >= graph.animationUntil) {
        graph.animationFrame = null; graph.graphTime = 0; render3d(); return;
      }
      graph.graphTime = now; render3d(); graph.animationFrame = requestAnimationFrame(frame);
    };
    graph.animationFrame = requestAnimationFrame(frame);
  }
  function selectGraphNodeAt(x, y) {
    if (state.sceneMode !== 'live' || !state.canvas?.hitTargets) return;
    const hit = [...state.canvas.hitTargets].reverse().find(target => Math.hypot(target.x - x, target.y - y) <= target.radius + 6);
    if (!hit) return;
    state.canvas.selectedNodeKey = hit.node.key; setEndpointDetails(hit.node.context, false); render3d();
    $('#attackExplainerTitle').textContent = `${hit.node.role === 'source' ? 'Source' : 'Destination'} · ${hit.node.label}`;
    $('#attackExplainerText').textContent = `${hit.node.flows} analyzed connection${hit.node.flows === 1 ? '' : 's'} touch this endpoint; ${hit.node.attacks} were classified ATTACK and ${hit.node.reviews} REVIEW. These are model decisions, not proof of compromise.`;
  }
  function render3d() {
    if (!state.canvas) return; const { canvas, ctx, nodes = [], edges = [] } = state.canvas; const rect = canvas.getBoundingClientRect(); const w = rect.width, h = rect.height; if (!w || !h) return;
    ctx.clearRect(0, 0, w, h);
    if (state.canvas.three) {
      state.canvas.three.setState({ mode: state.sceneMode, nodes, edges, scenario: state.scenario, elapsed: state.replay.elapsed, duration: state.replay.duration, graphTime: state.canvas.graphTime, selected: state.canvas.selectedNodeKey });
      return;
    }
    if (state.sceneMode === 'demo') {
      const ratio = Math.min(1, state.replay.elapsed / Math.max(1, state.replay.duration));
      if (!window.AttackScenes?.draw(ctx, w, h, state.scenario, state.replay.elapsed, ratio)) renderAttackScene(ctx, w, h);
      return;
    }
    const cx = w * .5, cy = h * .5; const scale = Math.min(w, h) * .7 * state.zoom; const ca = Math.cos(state.angle), sa = Math.sin(state.angle); const tilt = .55;
    const project = (x, y, z) => { const rx = x * ca - z * sa; const rz = x * sa + z * ca; const depth = 2.5 + rz; const perspective = 2.5 / depth; return { x: cx + rx * scale * perspective, y: cy + (y * Math.cos(tilt) - rz * Math.sin(tilt)) * scale * perspective, scale: perspective, z: rz }; };
    ctx.lineWidth = 1; for (let i = -4; i <= 4; i++) { const k = i / 4; const a = project(k, 0, -.62), b = project(k, 0, .62), c = project(-.62, 0, k), d = project(.62, 0, k); ctx.strokeStyle = i === 0 ? '#2f6671aa' : '#28445564'; ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.moveTo(c.x, c.y); ctx.lineTo(d.x, d.y); ctx.stroke(); }
    ctx.fillStyle = '#7390a1'; ctx.font = '8px Consolas,monospace'; ctx.textAlign = 'center'; ctx.fillText('SOURCE SYSTEMS', cx - scale * .66, 18); ctx.fillText('DESTINATION SYSTEMS', cx + scale * .66, 18);
    let visibleEdges = edges;
    if (nodes.length === 2 && nodes.every(node => node.key.startsWith('unknown-'))) {
      const grouped = new Map();
      edges.forEach(edge => {
        const group = grouped.get(edge.decision) || { ...edge, count: 0, risk: 0 };
        group.count++; group.risk = Math.max(group.risk, edge.risk); grouped.set(edge.decision, group);
      });
      const lanes = [...grouped.values()];
      visibleEdges = lanes.map((edge, index) => ({ ...edge, offset: (index - (lanes.length - 1) / 2) * 12 }));
    }
    const sortedEdges = [...visibleEdges].sort((a, b) => (a.source.z + a.target.z) - (b.source.z + b.target.z));
    sortedEdges.forEach(edge => {
      const a = project(edge.source.x, edge.source.y, edge.source.z), b = project(edge.target.x, edge.target.y, edge.target.z);
      const offset = edge.offset || 0;
      ctx.save(); ctx.globalAlpha = edge.decision === 'BENIGN' ? .48 : .78; ctx.strokeStyle = edge.color; ctx.lineWidth = (edge.decision === 'ATTACK' ? 2.4 : 1.8) + edge.risk / 140; ctx.beginPath(); ctx.moveTo(a.x, a.y + offset); ctx.lineTo(b.x, b.y + offset); ctx.stroke(); ctx.restore();
      if (edge.count > 1) { ctx.fillStyle = edge.color; ctx.font = '600 10px Segoe UI,sans-serif'; ctx.textAlign = 'center'; ctx.textBaseline = 'bottom'; ctx.fillText(`${edge.decision} · ${edge.count} FLOWS`, (a.x + b.x) / 2, (a.y + b.y) / 2 + offset - 7); }
      if (state.canvas.graphTime) {
        const progress = ((state.canvas.graphTime / (1900 + (edge.index % 4) * 150)) + edge.index * .31) % 1;
        const x = a.x + (b.x - a.x) * progress, y = a.y + (b.y - a.y) * progress + offset;
        ctx.globalAlpha = .2; ctx.fillStyle = edge.color; ctx.beginPath(); ctx.arc(x, y, 8, 0, Math.PI * 2); ctx.fill(); ctx.globalAlpha = .95; ctx.beginPath(); ctx.arc(x, y, 2.5, 0, Math.PI * 2); ctx.fill(); ctx.globalAlpha = 1;
      }
    });
    state.canvas.hitTargets = [];
    [...nodes].sort((a, b) => project(a.x, a.y, a.z).z - project(b.x, b.y, b.z).z).forEach((node, nodeIndex) => {
      const p = project(node.x, node.y, node.z); const radius = Math.min(12, 5.2 + Math.log2(node.flows + 1) * 1.5) * p.scale;
      ctx.globalAlpha = .08 + Math.min(.2, node.risk / 500); ctx.fillStyle = node.color; ctx.beginPath(); ctx.arc(p.x, p.y, radius * (2.7 + node.risk / 100), 0, Math.PI * 2); ctx.fill(); ctx.globalAlpha = 1;
      ctx.fillStyle = '#0c1b2a'; ctx.strokeStyle = node.color; ctx.lineWidth = state.canvas.selectedNodeKey === node.key ? 2.5 : 1.5; ctx.beginPath(); ctx.arc(p.x, p.y, radius, 0, Math.PI * 2); ctx.fill(); ctx.stroke();
      ctx.fillStyle = node.color; ctx.beginPath(); ctx.arc(p.x, p.y, Math.max(1.8, radius * .38), 0, Math.PI * 2); ctx.fill();
      const showLabel = nodes.length <= 18 || nodeIndex % 4 === 0 || state.canvas.selectedNodeKey === node.key;
      if (showLabel) {
        ctx.fillStyle = '#e0edf3'; ctx.font = `${Math.max(10, Math.min(13, w / 100))}px Segoe UI,sans-serif`; ctx.textAlign = 'center'; ctx.textBaseline = 'top';
        const label = node.label.length > 22 ? `${node.label.slice(0, 20)}…` : node.label;
        ctx.fillText(label, p.x, p.y + radius + 4);
      }
      ctx.fillStyle = '#9bb0bf'; ctx.font = '9px Consolas,monospace'; ctx.textAlign = 'center'; ctx.textBaseline = 'top'; ctx.fillText(`${node.flows} FLOW${node.flows === 1 ? '' : 'S'}`, p.x, p.y + radius + (showLabel ? 19 : 4));
      state.canvas.hitTargets.push({ x: p.x, y: p.y, radius: radius + 10, node });
    });
    ctx.textBaseline = 'alphabetic';
  }
  function setEndpointDetails(context, simulated, scenario = state.scenario) {
    const sourceHost = context?.source_host || (simulated ? `EXAMPLE · ${scenario?.source || 'SOURCE SYSTEM'}` : null);
    const sourceIp = context?.source_ip || null;
    const targetHost = context?.destination_host || (simulated ? `EXAMPLE · ${scenario?.target || 'DESTINATION'}` : null);
    const targetIp = context?.destination_ip || null;
    const targetPort = context?.destination_port || null;
    $('#sourceKicker').textContent = context?.source_ip || context?.source_host ? 'OBSERVED FLOW SOURCE' : simulated ? 'ILLUSTRATIVE SOURCE' : 'FLOW SOURCE';
    $('#targetKicker').textContent = context?.destination_ip || context?.destination_host ? 'OBSERVED DESTINATION' : simulated ? 'ILLUSTRATIVE TARGET' : 'FLOW DESTINATION';
    $('#sourceSystem').textContent = sourceHost || 'Source system not provided';
    $('#sourceAddress').textContent = sourceIp || (simulated ? 'No real source IP supplied' : 'Source IP not included in flow data');
    $('#targetSystem').textContent = targetHost || 'Target server not provided';
    $('#targetAddress').textContent = [targetIp, targetPort].filter(Boolean).join(' · ') || (simulated ? 'No real destination IP supplied' : 'Target IP / port not included in flow data');
    $('#sceneDisclaimer').textContent = simulated
      ? 'ILLUSTRATIVE REPLAY · Not a packet recording; no traffic is sent. Real endpoints appear only when present in the flow.'
      : 'TOPOLOGY FROM ANALYZED FLOWS · Particle motion is a visual cue, not packet timing or live traffic.';
  }
  function formatClock(ms) { return `00:${String(Math.max(0, Math.floor(ms / 1000))).padStart(2, '0')}`; }
  function updateReplayUi() {
    const replay = state.replay, ratio = Math.min(1, replay.elapsed / replay.duration);
    const attempts = Math.min(replay.attempts, replay.elapsed <= 0 ? 0 : Math.floor(replay.elapsed / replay.attemptEvery) + 1);
    if (state.sceneMode === 'demo' && state.scenario) {
      const stages = {
        botnet: ['1 · Attacker sends commands to infected devices', '2 · Infected devices receive the command', '3 · The devices contact the target together'],
        ddos: ['1 · Many devices send requests', '2 · Requests converge on one service', '3 · The target is flooded by traffic'],
        dos: ['1 · One source starts repeated requests', '2 · The requests reach the service', '3 · One source keeps the service busy'],
        bruteforce: ['1 · A client tries a password', '2 · The login service checks the attempt', '3 · The service rejects repeated guesses'],
        'web-brute': ['1 · A client tries to sign in', '2 · The web login checks the attempt', '3 · Repeated guesses are rejected'],
        infiltration: ['1 · Activity starts outside the network', '2 · It crosses into an internal system', '3 · It moves toward a protected server'],
        'web-sql': ['1 · SQL-like input leaves the client', '2 · The web app receives the request', '3 · The request targets the database'],
        'web-xss': ['1 · Script-like input is sent', '2 · The web app processes the request', '3 · The pattern may reach a browser'],
        web: ['1 · A client sends a web request', '2 · The web app receives it', '3 · The request targets the application'],
        portscan: ['1 · A scanner checks a service', '2 · It moves to the next port', '3 · Several services have been probed'],
        'data-leak': ['1 · A heartbeat request is sent', '2 · The request reaches a TLS service', '3 · A possible memory response returns'],
      };
      const stagesForAttack = stages[state.scenario.id];
      const stage = stagesForAttack
        ? stagesForAttack[ratio < .34 ? 0 : ratio < .68 ? 1 : 2]
        : ratio < .34 ? `1 · Starts at ${state.scenario.source}` : ratio < .68 ? `2 · Passes through ${state.scenario.middle}` : `3 · Targets ${state.scenario.target}`;
      $('#attackExplainerText').textContent = `${stage}. ${state.scenario.explain}`;
    }
    $('#attemptCount').textContent = `${attempts} / ${replay.attempts}`;
    $('#timelineProgress').style.width = `${ratio * 100}%`;
    $('#replayClock').textContent = `${formatClock(replay.elapsed)} / ${formatClock(replay.duration)}`;
    $('#replayState').textContent = replay.playing ? 'PLAYING' : ratio >= 1 ? 'COMPLETE' : replay.elapsed ? 'PAUSED' : 'READY';
    $('#attemptStatus').textContent = state.scenario?.metric || 'ILLUSTRATIVE EVENTS';
    $('#playAttack').innerHTML = replay.playing ? '<span>Ⅱ</span> Pause simulation' : ratio >= 1 ? '<span>↻</span> Replay attack' : '<span>▶</span> Play attack simulation';
  }
  function setDemoScene(scenario = pickScenario('SSH Brute Force'), context = null) {
    if (state.canvas?.animationFrame != null) cancelAnimationFrame(state.canvas.animationFrame);
    if (state.canvas) { state.canvas.animationFrame = null; state.canvas.graphTime = 0; }
    state.scenario = scenario;
    $('#playAttack').disabled = false;
    state.sceneMode = 'demo'; $('#threatPanel').classList.add('demo-active'); $('#sceneWrap').classList.add('demo-mode'); $('#sceneModeBadge').innerHTML = '<i></i> SIMULATION';
    $('#sceneSubtitle').textContent = scenario.detectedFamily ? `DETECTED: ${scenario.detectedFamily} · ${scenario.subtitle}` : scenario.selectedSampleType ? `SELECTED SAMPLE: ${scenario.selectedSampleType} · ${scenario.subtitle}` : scenario.subtitle;
    $('#sceneCanvasLabel').textContent = (scenario.detectedFamily ? `${scenario.detectedFamily} · EXPLANATION` : scenario.selectedSampleType ? `${scenario.selectedSampleType} · SAMPLE EXPLANATION` : scenario.name).toUpperCase(); $('#sceneLegend').style.display = 'none';
    $('.scene-hint').textContent = 'ATTACK-SPECIFIC EXPLANATION · USE PLAYBACK CONTROLS';
    $('#attackExplainerTitle').textContent = scenario.detectedFamily ? `Detected label: ${scenario.detectedFamily}` : scenario.selectedSampleType ? `Selected flow type: ${scenario.selectedSampleType}` : scenario.title; $('#attackExplainerText').textContent = scenario.explain;
    $('#sceneEmpty').classList.add('hidden'); setEndpointDetails(context, true, scenario); updateReplayUi(); render3d();
  }
  function showLiveFlowScene() {
    state.replay.playing = false; if (state.replay.frameId != null) cancelAnimationFrame(state.replay.frameId); state.replay.frameId = null; state.replay.sceneKey = null; state.sceneMode = 'live'; $('#threatPanel').classList.remove('demo-active'); $('#sceneWrap').classList.remove('demo-mode');
    const items = state.recentBatch.length ? state.recentBatch : state.incidents.slice(0, 40).map(item => ({ ...payloadOf(item), incident_id: payloadOf(item).incident_id || item.id, pipeline_completed: true, final_decision: payloadOf(item).final_decision || 'REVIEW', final_attack: payloadOf(item).final_attack || 'Unclassified' }));
    drawThreatField(items);
  }
  function flowEndpointText(context, side) {
    const host = String(context?.[`${side}_host`] || '').trim();
    const ip = String(context?.[`${side}_ip`] || '').trim();
    const port = context?.[`${side}_port`];
    const name = host || ip || `Unknown ${side}`;
    const address = host && ip && host.toLowerCase() !== ip.toLowerCase() ? ` (${ip})` : '';
    return `${name}${address}${port != null && port !== '' ? ` · port ${port}` : ''}`;
  }
  function renderFlowDataTable(edges = []) {
    const body = $('#flowDataRows'); if (!body) return;
    body.innerHTML = edges.length ? edges.map(edge => {
      const incident = edge.incidentId
        ? `<button type="button" class="text-button" data-open="${esc(edge.incidentId)}" aria-label="Open incident INC-${esc(shortId(edge.incidentId))}">Open INC-${esc(shortId(edge.incidentId))}</button>`
        : '<span>No incident saved</span>';
      return `<tr><th scope="row">${esc(edge.rowNumber ?? edge.index + 1)}</th><td>${esc(flowEndpointText(edge.context, 'source'))}</td><td>${esc(flowEndpointText(edge.context, 'destination'))}</td><td><span class="decision-pill ${decisionClass(edge.decision)}">${esc(edge.decision)}</span></td><td>${incident}</td></tr>`;
    }).join('') : '<tr><td colspan="5" class="empty-cell">No analyzed flow connections are available.</td></tr>';
  }
  function toggleFlowDataView() {
    showLiveFlowScene();
    const view = $('#flowDataView'); const button = $('#showLiveFlows');
    view.hidden = !view.hidden; button.setAttribute('aria-expanded', String(!view.hidden));
    if (!view.hidden) view.focus({ preventScroll: true });
  }
  function toggleAttackReplay() {
    if (state.sceneMode !== 'demo') { startScenarioReplay(state.scenario || pickScenario('SSH Brute Force'), state.sceneContext || null); return; }
    if (state.replay.playing) { state.replay.playing = false; if (state.replay.frameId != null) cancelAnimationFrame(state.replay.frameId); state.replay.frameId = null; updateReplayUi(); return; }
    if (state.replay.elapsed >= state.replay.duration) { startScenarioReplay(state.scenario || pickScenario('SSH Brute Force'), state.sceneContext || null); return; }
    state.replay.playing = true; state.replay.lastFrame = performance.now(); updateReplayUi(); state.replay.frameId = requestAnimationFrame(animateReplay);
  }
  function startScenarioReplay(scenario, context = null) {
    const replay = state.replay;
    if (replay.frameId != null) cancelAnimationFrame(replay.frameId);
    if (state.canvas?.animationFrame != null) cancelAnimationFrame(state.canvas.animationFrame);
    if (state.canvas) { state.canvas.animationFrame = null; state.canvas.graphTime = 0; }
    replay.attempts = scenario.count || 16;
    replay.duration = Math.max(8000, replay.attempts * replay.attemptEvery);
    replay.elapsed = 0; replay.playing = true; replay.lastFrame = performance.now();
    replay.sceneKey = `${scenario.id}|${scenario.selectedSampleType || scenario.detectedFamily || ''}`;
    setDemoScene(scenario, context);
    replay.frameId = requestAnimationFrame(animateReplay);
  }
  function restartAttackReplay() { startScenarioReplay(state.scenario || pickScenario('SSH Brute Force'), state.sceneContext || null); }
  function animateReplay(now) {
    const replay = state.replay; if (!replay.playing || state.sceneMode !== 'demo') { replay.frameId = null; return; }
    if (document.visibilityState !== 'hidden') replay.elapsed = Math.min(replay.duration, replay.elapsed + Math.max(0, now - replay.lastFrame) * replay.speed);
    replay.lastFrame = now; updateReplayUi(); render3d();
    if (replay.elapsed >= replay.duration) { replay.playing = false; replay.frameId = null; updateReplayUi(); return; }
    replay.frameId = requestAnimationFrame(animateReplay);
  }
  function startAttackExplanation(item) {
    const detectedFamily = item.final_attack || item.investigation?.suspected_attack || 'Unclassified attack';
    const scenario = { ...pickScenario(detectedFamily), detectedFamily };
    const context = item.flow_context || null;
    startScenarioReplay(scenario, context);
  }
  function renderAttackScene(ctx, w, h) {
    const scenario = state.scenario || pickScenario('SSH Brute Force');
    const cx = w / 2, cy = h * .57, scale = Math.min(w, h) * .82 * state.zoom;
    const ca = Math.cos(state.angle), sa = Math.sin(state.angle), tilt = .42;
    const project = (x, y = -.08, z = 0) => {
      const rx = x * ca - z * sa, rz = x * sa + z * ca, depth = 2.7 + rz, p = 2.7 / depth;
      return { x: cx + rx * scale * p, y: cy + (y * Math.cos(tilt) - rz * Math.sin(tilt)) * scale * p, p };
    };
    for (let i = -4; i <= 4; i++) {
      const k = i / 4, a = project(k, -.25, -.65), b = project(k, -.25, .65), c = project(-.65, -.25, k), d = project(.65, -.25, k);
      ctx.strokeStyle = '#28445565'; ctx.lineWidth = 1; ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.moveTo(c.x, c.y); ctx.lineTo(d.x, d.y); ctx.stroke();
    }
    const drawNode = (x, z, label, icon, color = '#62c6d3', size = 14) => {
      const point = project(x, -.08, z), r = size * point.p;
      ctx.globalAlpha = .12; ctx.fillStyle = color; ctx.beginPath(); ctx.arc(point.x, point.y, r * 2.4, 0, Math.PI * 2); ctx.fill(); ctx.globalAlpha = 1;
      ctx.save(); ctx.translate(point.x, point.y); ctx.fillStyle = '#102538'; ctx.strokeStyle = color; ctx.lineWidth = 1.5;
      ctx.beginPath(); ctx.moveTo(-r, -r * .5); ctx.lineTo(0, -r); ctx.lineTo(r, -r * .5); ctx.lineTo(r, r * .5); ctx.lineTo(0, r); ctx.lineTo(-r, r * .5); ctx.closePath(); ctx.fill(); ctx.stroke();
      ctx.beginPath(); ctx.moveTo(0, -r); ctx.lineTo(0, r); ctx.moveTo(-r, -r * .5); ctx.lineTo(0, 0); ctx.lineTo(r, -r * .5); ctx.moveTo(0, 0); ctx.lineTo(-r, r * .5); ctx.moveTo(0, 0); ctx.lineTo(r, r * .5); ctx.stroke();
      ctx.fillStyle = '#eff8fb'; ctx.font = `bold ${Math.max(6, r * .52)}px Segoe UI`; ctx.textAlign = 'center'; ctx.textBaseline = 'middle'; ctx.fillText(icon, 0, 0); ctx.restore();
      ctx.fillStyle = '#bfd0da'; ctx.font = '7px Segoe UI'; ctx.textAlign = 'center'; ctx.fillText(label, point.x, point.y + r + 11);
      return point;
    };
    const link = (a, b, color = '#57788a', dashed = true) => {
      ctx.save(); ctx.strokeStyle = color; ctx.lineWidth = 1.6; ctx.setLineDash(dashed ? [4, 4] : []); ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke(); ctx.restore();
    };
    const pulse = (a, b, progress, color, tag) => {
      if (progress < 0 || progress > 1) return;
      const x = a.x + (b.x - a.x) * progress, y = a.y + (b.y - a.y) * progress;
      ctx.globalAlpha = .24; ctx.fillStyle = color; ctx.beginPath(); ctx.arc(x, y, 10, 0, Math.PI * 2); ctx.fill(); ctx.globalAlpha = 1;
      ctx.fillStyle = color; ctx.beginPath(); ctx.arc(x, y, 3.4, 0, Math.PI * 2); ctx.fill();
      if (progress > .28 && progress < .78) { ctx.fillStyle = '#f2f7fa'; ctx.font = 'bold 8px Consolas, monospace'; ctx.textAlign = 'center'; ctx.fillText(tag, x, y - 10); }
    };
    const tick = state.replay.elapsed, index = Math.floor(tick / state.replay.attemptEvery), flight = 1500;
    const traffic = (paths, tag, color = scenario.color, count = 5, parallel = false) => {
      const visible = Math.min(count, Math.max(1, index + 1));
      for (let n = Math.max(0, index - visible + 1); n <= index; n++) {
        const progress = (tick - n * state.replay.attemptEvery) / flight;
        if (parallel) {
          const path = paths[n % paths.length]; pulse(path[0], path[1], progress, color, tag);
        } else {
          const scaled = progress * paths.length, segment = Math.floor(scaled), path = paths[Math.min(segment, paths.length - 1)];
          pulse(path[0], path[1], segment >= paths.length ? -1 : scaled - segment, color, tag);
        }
      }
    };
    const id = scenario.id;
    if (id === 'botnet') {
      const hub = drawNode(-.05, 0, 'ATTACKER CONTROL', 'C2', '#efb65e', 15);
      const target = drawNode(.78, 0, 'TARGET SERVICE', 'SV', '#f3787e', 16);
      const bots = [-.38, -.13, .13, .38].map((z, i) => drawNode(-.72, z, `INFECTED DEVICE ${i + 1}`, 'PC', '#ef8e70', 11));
      bots.forEach(bot => { link(hub, bot, '#efb65e'); link(bot, target, '#e46e72'); });
      const routes = [];
      bots.forEach(bot => { routes.push([hub, bot, '#efb65e', 'COMMAND']); routes.push([bot, target, '#f3787e', 'BEACON']); });
      const recent = routes.filter((_, routeIndex) => routeIndex % 2 === 1);
      const visible = Math.min(6, Math.max(1, index + 1));
      for (let n = Math.max(0, index - visible + 1); n <= index; n++) {
        const progress = (tick - n * state.replay.attemptEvery) / flight, route = recent[n % recent.length];
        pulse(route[0], route[1], progress, route[2], route[3]);
      }
      if (index % 4 === 0) traffic(routes.filter((_, routeIndex) => routeIndex % 2 === 0), 'COMMAND', '#efb65e', 1);
    } else if (id === 'ddos') {
      const sources = [-.42, -.14, .14, .42].map((z, i) => drawNode(-.76, z, `DEVICE ${i + 1}`, 'PC', '#ef8e70', 11));
      const target = drawNode(.76, 0, 'OVERLOADED SERVICE', 'SV', '#f3787e', 17);
      const paths = sources.map(source => { link(source, target, '#e46e72'); return [source, target]; });
      traffic(paths, 'REQUEST', '#ff7968', 7, true);
      const glow = .5 + .5 * Math.sin(tick / 160); ctx.globalAlpha = .12 + glow * .15; ctx.fillStyle = '#ff625e'; ctx.beginPath(); ctx.arc(target.x, target.y, 22 + glow * 10, 0, Math.PI * 2); ctx.fill(); ctx.globalAlpha = 1;
    } else if (id === 'dos') {
      const source = drawNode(-.72, 0, 'ONE ATTACKER', 'PC', '#f3787e', 15), target = drawNode(.72, 0, 'BUSY SERVICE', 'SV', '#efb65e', 17);
      link(source, target, '#ef6e70'); traffic([[source, target]], 'REQUEST', '#ff766b', 5);
      const glow = .5 + .5 * Math.sin(tick / 130); ctx.globalAlpha = .1 + glow * .12; ctx.fillStyle = '#ff766b'; ctx.beginPath(); ctx.arc(target.x, target.y, 20 + glow * 8, 0, Math.PI * 2); ctx.fill(); ctx.globalAlpha = 1;
    } else if (id === 'bruteforce' || id === 'web-brute') {
      const source = drawNode(-.72, 0, id === 'web-brute' ? 'REMOTE CLIENT' : 'ONE ATTACKER', 'PC', '#f3787e', 14);
      const login = drawNode(.05, 0, id === 'web-brute' ? 'WEB LOGIN' : 'LOGIN SERVICE', 'ID', '#efb65e', 15);
      const account = drawNode(.73, 0, 'LOCKED ACCOUNT', 'LK', '#62c6d3', 15);
      link(source, login, '#ed7472'); link(login, account, '#466274');
      traffic([[source, login]], 'GUESS', '#f3787e', 4);
      const replyIndex = index - 1, replyProgress = (tick - replyIndex * state.replay.attemptEvery - 700) / 900;
      if (replyIndex >= 0) pulse(login, source, replyProgress, '#62c6d3', 'DENIED');
      const lock = project(.42, -.08, 0); ctx.fillStyle = '#efb65e'; ctx.font = 'bold 9px Segoe UI'; ctx.textAlign = 'center'; ctx.fillText('ACCESS BLOCKED', lock.x, lock.y - 24);
    } else if (id === 'infiltration') {
      const attacker = drawNode(-.78, 0, 'OUTSIDE DEVICE', 'PC', '#f3787e', 13);
      const gate = drawNode(-.25, 0, 'NETWORK GATE', 'FW', '#efb65e', 14);
      const host = drawNode(.28, 0, 'INTERNAL HOST', 'PC', '#ef8e70', 14);
      const server = drawNode(.78, 0, 'PROTECTED SERVER', 'SV', '#c58aff', 15);
      link(attacker, gate, '#e46e72'); link(gate, host, '#efb65e'); link(host, server, '#c58aff');
      const p = (tick % 3000) / 3000;
      if (p < .34) pulse(attacker, gate, p / .34, '#f3787e', 'ENTRY');
      else if (p < .67) pulse(gate, host, (p - .34) / .33, '#efb65e', 'ACCESS');
      else pulse(host, server, (p - .67) / .33, '#c58aff', 'MOVE');
      const zone = project(.48, -.34, .36); ctx.fillStyle = '#c58aff'; ctx.font = '8px Segoe UI'; ctx.textAlign = 'center'; ctx.fillText('INTERNAL NETWORK', zone.x, zone.y);
    } else if (id === 'web-sql') {
      const client = drawNode(-.72, 0, 'REMOTE CLIENT', 'PC', '#f3787e', 14);
      const app = drawNode(0, 0, 'WEB APPLICATION', 'WEB', '#efb65e', 16);
      const db = drawNode(.72, 0, 'DATABASE', 'DB', '#c58aff', 17);
      link(client, app, '#f3787e'); link(app, db, '#c58aff'); traffic([[client, app], [app, db]], 'SQL INPUT', '#ff806f', 3);
      const badge = project(.52, -.32, .12); ctx.fillStyle = '#ff9b76'; ctx.font = 'bold 8px Consolas, monospace'; ctx.textAlign = 'center'; ctx.fillText('QUERY', badge.x, badge.y);
    } else if (id === 'web-xss') {
      const attacker = drawNode(-.72, 0, 'SENDER', 'PC', '#f3787e', 14);
      const app = drawNode(0, 0, 'WEB APPLICATION', 'WEB', '#efb65e', 16);
      const browser = drawNode(.72, 0, 'VISITOR BROWSER', 'BR', '#c58aff', 15);
      link(attacker, app, '#f3787e'); link(app, browser, '#c58aff'); traffic([[attacker, app], [app, browser]], 'SCRIPT', '#d38aff', 3);
    } else if (id === 'web') {
      const client = drawNode(-.72, 0, 'REMOTE CLIENT', 'PC', '#f3787e', 14);
      const gateway = drawNode(0, 0, 'WEB GATEWAY', 'FW', '#efb65e', 15);
      const app = drawNode(.72, 0, 'WEB APPLICATION', 'WEB', '#62c6d3', 16);
      link(client, gateway, '#f3787e'); link(gateway, app, '#62c6d3'); traffic([[client, gateway], [gateway, app]], 'REQUEST', scenario.color, 3);
    } else if (id === 'portscan') {
      const scanner = drawNode(-.76, 0, 'ONE SCANNER', 'PC', '#f3787e', 14);
      const services = [-.42, -.14, .14, .42].map((z, i) => drawNode(.65, z, ['WEB · 443', 'SSH · 22', 'MAIL · 25', 'DB · 3306'][i], 'PT', i === index % 4 ? '#efb65e' : '#62c6d3', 12));
      services.forEach(service => link(scanner, service, '#58788a'));
      traffic(services.map(service => [scanner, service]), 'PROBE', '#62c6d3', 1, true);
      const active = services[index % services.length], glow = .5 + .5 * Math.sin(tick / 120); ctx.globalAlpha = .1 + glow * .17; ctx.fillStyle = '#efb65e'; ctx.beginPath(); ctx.arc(active.x, active.y, 20 + glow * 7, 0, Math.PI * 2); ctx.fill(); ctx.globalAlpha = 1;
    } else if (id === 'data-leak') {
      const client = drawNode(-.72, 0, 'REQUESTER', 'PC', '#62c6d3', 14);
      const tls = drawNode(0, 0, 'TLS SERVICE', 'TLS', '#efb65e', 16);
      const memory = drawNode(.72, 0, 'SERVER MEMORY', 'RAM', '#c58aff', 17);
      link(client, tls, '#62c6d3'); link(tls, memory, '#c58aff');
      const p = (tick % 3000) / 3000;
      if (p < .45) pulse(client, tls, p / .45, '#62c6d3', 'HEARTBEAT');
      else if (p < .7) pulse(tls, memory, (p - .45) / .25, '#efb65e', 'REQUEST');
      else pulse(memory, client, (p - .7) / .3, '#c58aff', 'POSSIBLE DATA');
      const badge = project(.52, -.32, .12); ctx.fillStyle = '#c58aff'; ctx.font = 'bold 8px Consolas, monospace'; ctx.textAlign = 'center'; ctx.fillText('MEMORY DATA', badge.x, badge.y);
    } else {
      const source = drawNode(-.72, 0, scenario.source.toUpperCase(), 'PC', scenario.color, 14);
      const middle = drawNode(0, 0, scenario.middle.toUpperCase(), 'FW', '#efb65e', 15);
      const target = drawNode(.72, 0, scenario.target.toUpperCase(), 'SV', '#62c6d3', 15);
      link(source, middle, scenario.color); link(middle, target, '#62c6d3'); traffic([[source, middle], [middle, target]], scenario.packet, scenario.color, 3);
    }
    ctx.textAlign = 'left'; ctx.textBaseline = 'alphabetic';
  }
  function connectEvents() {
    const scheme = location.protocol === 'https:' ? 'wss' : 'ws'; const ws = new WebSocket(`${scheme}://${location.host}/ws/events`); state.ws = ws;
    ws.onopen = () => { sendWebSocketAuth(ws); setConnection(true, 'API connected · live events'); };
    ws.onmessage = event => { let message; try { message = JSON.parse(event.data); } catch { return; } if (['incident.created', 'incident.validated', 'response.approved', 'analysis.completed'].includes(message.event_type)) scheduleIncidentRefresh(); if (message.event_type === 'threat_intel.imported') scheduleIocRefresh(); };
    ws.onclose = () => { setTimeout(() => { if (document.visibilityState !== 'hidden') connectEvents(); }, 4000); };
    ws.onerror = () => { setConnection(false, 'API reconnecting'); ws.close(); };
  }
  document.addEventListener('DOMContentLoaded', () => {
    attachEvents(); initCanvas();
    const savedSampleType = sessionStorage.getItem('cyber.selectedDemoAttackType');
    const savedOption = [...$('#demoAttackType').options].find(option => option.textContent.trim() === savedSampleType);
    if (savedOption) {
      $('#demoAttackType').value = savedOption.value;
      state.selectedDemoType = savedSampleType;
    }
    refreshAll(); connectEvents();
  });
})();
