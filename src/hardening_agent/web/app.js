const token = document.querySelector('meta[name="lha-token"]').content;
const state = { targets: [], guidelineSources: [], guidelineCandidates: [], discoveryPlatform: null, discoveryRecommendations: new Map(), editingSourceCategories: [], vms: [], selectedPolicyRuleIds: new Set(), selectedAuditRuleIds: new Set(), policyProfiles: [], editingTargetName: null, sourceReviewJobId: null, hardeningReviewJobId: null, aiHardeningReview: null, generalBaseline: null, generalBaselineLevel: 'basic', generalBaselineCategories: null, generalBaselineStatusFilter: 'all', baselineBusy: false, baselineSetups: new Map(), baselineSetupJobs: new Map(), baselineRole: 'general-server', selectedBaselineControlIds: new Set(), baselinePlan: null, baselinePlanBusy: false, fullScanJobId: null, reportPlatform: '', lastGuideline: null, scapResults: [], vulnerabilityResults: [] };
const categoryNames = { accounts: 'Benutzer, Passwörter und PAM', audit: 'Audit-Protokollierung', filesystem: 'Dateisysteme und Mount-Optionen', kernel: 'Kernel und sysctl', logging: 'Systemprotokollierung', lsm: 'AppArmor oder SELinux', network: 'Netzwerk und Firewall', services: 'Dienste und minimale Pakete', ssh: 'SSH-Zugriff', sudo: 'Privilegien und sudo', system: 'Updates und Systempflege' };

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}), 'X-LHA-CSRF': token };
  if (options.body) headers['Content-Type'] = 'application/json';
  const response = await fetch(path, { ...options, headers });
  const type = response.headers.get('content-type') || '';
  if (!response.ok) {
    const payload = type.includes('json') ? await response.json() : { error: response.statusText };
    throw new Error(payload.error || response.statusText);
  }
  return type.includes('json') ? response.json() : response.blob();
}

function toast(message) {
  const element = document.getElementById('toast');
  element.textContent = message;
  element.classList.add('show');
  window.setTimeout(() => element.classList.remove('show'), 3200);
}

function values(id) {
  return document.getElementById(id).value.split(',').map(item => item.trim()).filter(Boolean);
}

function activity(message, kind = '') {
  const panel = document.getElementById('activity');
  const line = document.createElement('p');
  line.className = kind;
  line.textContent = `${new Date().toLocaleTimeString()} – ${message}`;
  panel.prepend(line);
}

function setBusy(form, busy) {
  form.querySelectorAll('button, input, select').forEach(element => element.disabled = busy);
}

async function loadStatus() {
  const payload = await api('/api/status');
  const installedNames = payload.ollama.models.map(model => model.name);
  const preferredModel = window.localStorage.getItem('lha-active-model');
  if (preferredModel && preferredModel !== payload.ollama.model && installedNames.includes(preferredModel) && payload.ollama.state !== 'working') {
    try {
      await api('/api/ollama/select', { method: 'POST', body: JSON.stringify({ model: preferredModel }) });
      payload.ollama.model = preferredModel; payload.ollama.state = 'ready'; payload.ollama.message = `${preferredModel} ist ausgewählt`;
    } catch (error) { window.localStorage.removeItem('lha-active-model'); }
  }
  document.getElementById('app-version').textContent = `Version ${payload.version}`;
  const aiStateNames = { ready: 'Bereit', working: 'Analysiert', error: 'Fehler', unavailable: 'Fehlt' };
  document.getElementById('ollama-state').textContent = aiStateNames[payload.ollama.state] || payload.ollama.state;
  const statusDot = document.querySelector('.status-dot'); statusDot.className = `status-dot ${payload.ollama.state}`;
  document.getElementById('ollama-model').textContent = payload.ollama.model;
  const runtimeState = document.getElementById('ai-runtime-state'); runtimeState.textContent = aiStateNames[payload.ollama.state] || payload.ollama.state;
  runtimeState.className = `badge ai-${payload.ollama.state}`;
  document.getElementById('ai-runtime-detail').textContent = payload.ollama.message;
  document.getElementById('vm-count').textContent = payload.counts.vms;
  document.getElementById('target-count').textContent = payload.counts.targets;
  const badge = document.getElementById('root-badge');
  badge.textContent = payload.running_as_root ? 'ROOT-MODUS' : 'Benutzerbetrieb';
  badge.classList.toggle('danger', payload.running_as_root);
  document.getElementById('tool-status').replaceChildren(...Object.entries(payload.tools).map(([name, path]) => {
    const item = document.createElement('div'); item.className = `check${path ? '' : ' missing'}`;
    const label = document.createElement('strong'); label.textContent = name;
    const value = document.createElement('span'); value.textContent = path || 'nicht gefunden';
    item.append(label, value); return item;
  }));
  document.getElementById('status-warnings').textContent = [...payload.vm_warnings, payload.ollama.error].filter(Boolean).join('\n');
  const modelSelect = document.getElementById('active-model'); modelSelect.replaceChildren();
  const modelList = document.getElementById('model-list'); modelList.replaceChildren();
  payload.ollama.models.forEach(model => {
    const option = document.createElement('option'); option.value = model.name; option.textContent = `${model.name} · ${(model.size / 1e9).toFixed(1)} GB`;
    option.selected = model.name === payload.ollama.model; modelSelect.append(option);
    const item = document.createElement('div'); item.className = 'list-item';
    const info = document.createElement('div');
    const name = document.createElement('strong'); name.textContent = model.name;
    const size = document.createElement('p'); size.textContent = `${(model.size / 1e9).toFixed(1)} GB`;
    info.append(name, size); item.append(info);
    if (model.name === payload.ollama.model) { const active = document.createElement('span'); active.className = 'badge'; active.textContent = 'Aktiv'; item.append(active); }
    modelList.append(item);
  });
  modelSelect.disabled = payload.ollama.state === 'working' || !payload.ollama.models.length;
  document.getElementById('select-model').disabled = modelSelect.disabled;
}

async function loadVMs() {
  const payload = await api('/api/vms'); state.vms = payload.vms;
  const body = document.getElementById('vm-table'); body.replaceChildren();
  const stateLabels = { running: 'Läuft', 'shut off': 'Ausgeschaltet', paused: 'Pausiert', blocked: 'Blockiert', crashed: 'Abgestürzt', pmsuspended: 'Energiesparmodus', idle: 'Inaktiv', unknown: 'Unbekannt' };
  payload.vms.forEach(vm => {
    const row = document.createElement('tr');
    const nameCell = document.createElement('td'); const vmName = document.createElement('strong'); vmName.textContent = vm.name;
    nameCell.append(vmName);
    if (vm.vagrant) { const tag = document.createElement('span'); tag.className = 'vagrant-tag'; tag.textContent = 'Vagrant'; nameCell.append(tag); }
    row.append(nameCell);
    const stateCell = document.createElement('td'); const stateBadge = document.createElement('span'); const canonicalState = String(vm.state || 'unknown').toLowerCase(); stateBadge.className = `vm-state ${canonicalState.replace(/[^a-z]+/g, '-')}`; stateBadge.textContent = stateLabels[canonicalState] || vm.state || 'Unbekannt'; stateCell.append(stateBadge); row.append(stateCell);
    const addressCell = document.createElement('td'); addressCell.textContent = vm.addresses.join(', ') || (canonicalState === 'running' ? 'Nicht erkannt' : '–'); if (canonicalState === 'running' && !vm.addresses.length) addressCell.className = 'vm-address-missing'; row.append(addressCell);
    const cpuCell = document.createElement('td'); cpuCell.textContent = vm.vcpus || '–'; row.append(cpuCell);
    const action = document.createElement('td'); const button = document.createElement('button');
    button.className = 'secondary'; button.textContent = vm.vagrant ? 'Vagrant-Ziel einrichten' : 'Ins Formular übernehmen';
    button.addEventListener('click', () => useVM(vm, button)); action.append(button); row.append(action); body.append(row);
  });
  if (!payload.vms.length) {
    const row = document.createElement('tr'); const cell = document.createElement('td');
    cell.colSpan = 5; cell.className = 'empty-table'; cell.textContent = 'Keine KVM-Domains erkannt – diese Funktion ist optional.';
    row.append(cell); body.append(row);
  }
  document.getElementById('vm-warnings').textContent = payload.warnings.join('\n');
}

async function useVM(vm, button) {
  button.disabled = true;
  let connection = { host: vm.addresses[0] || '', user: 'admin', port: 22, identity_file: '' };
  try {
    if (vm.vagrant) {
      const payload = await api('/api/vagrant/config', { method: 'POST', body: JSON.stringify({ vm_name: vm.name }) });
      connection = payload.config;
      const targetPayload = { name: vm.name, local: false, host: connection.host, user: connection.user,
        port: connection.port, identity_file: connection.identity_file, vm_name: vm.name,
        vagrant_directory: connection.directory, vagrant_machine: connection.machine,
        vagrant_home: connection.vagrant_home || '' };
      const existing = state.targets.find(target => target.name === vm.name);
      if (existing) targetPayload.original_name = existing.name;
      await api('/api/targets', { method: 'POST', body: JSON.stringify(targetPayload) });
      state.selectedPolicyRuleIds.clear();
      await Promise.all([loadTargets(), loadStatus()]);
      document.querySelector('[data-view="targets"]').click();
      activity(`Vagrant-Ziel ${vm.name} vollständig eingerichtet`, 'success');
      toast(`Vagrant-Ziel ${vm.name} ist bereit`);
      button.disabled = false;
      return;
    }
  } catch (error) { toast(error.message); button.disabled = false; return; }
  document.querySelector('[data-view="targets"]').click();
  cancelTargetEdit();
  document.getElementById('target-mode-ssh').checked = true;
  updateTargetMode();
  document.getElementById('target-name').value = vm.name;
  document.getElementById('target-host').value = connection.host;
  document.getElementById('target-user').value = connection.user;
  document.getElementById('target-port').value = connection.port;
  document.getElementById('target-key').value = connection.identity_file;
  document.getElementById('target-vm').value = vm.name;
  document.getElementById('target-host').focus();
  button.disabled = false;
}

async function loadTargets() {
  const payload = await api('/api/targets'); state.targets = payload.targets;
  const list = document.getElementById('target-list'); list.replaceChildren();
  const select = document.getElementById('build-target'); select.replaceChildren();
  payload.targets.forEach(target => {
    const item = document.createElement('div'); item.className = 'list-item';
    const info = document.createElement('div'); const name = document.createElement('strong'); name.textContent = target.name;
    const detail = document.createElement('p');
    const keyState = target.local ? '' : ` · ${target.identity_file ? 'SSH-Key gesetzt' : 'ohne SSH-Key'}`;
    const transport = target.vagrant_directory ? ' · Vagrant CLI' : '';
    detail.textContent = `${target.local ? 'Lokal' : `${target.user || ''}@${target.host}:${target.port}`}${keyState}${transport}${target.vm_name ? ` · KVM ${target.vm_name}` : ''}`;
    info.append(name, detail);
    const actions = document.createElement('div'); actions.className = 'item-actions';
    const editButton = document.createElement('button'); editButton.className = 'secondary'; editButton.textContent = 'Bearbeiten';
    editButton.addEventListener('click', () => editTarget(target));
    const auditButton = document.createElement('button'); auditButton.className = 'secondary'; auditButton.textContent = 'Audit';
    auditButton.addEventListener('click', () => auditTarget(target.name, auditButton));
    const deleteButton = document.createElement('button'); deleteButton.className = 'danger'; deleteButton.textContent = 'Löschen';
    deleteButton.addEventListener('click', () => deleteTarget(target.name, deleteButton));
    actions.append(editButton, auditButton, deleteButton); item.append(info, actions); list.append(item);
    const option = document.createElement('option'); option.value = target.name; option.textContent = target.name; select.append(option);
  });
}

async function deleteTarget(name, button) {
  if (!window.confirm(`Zielsystem „${name}“ wirklich löschen?\n\nAudit-Dateien und erzeugte Pakete bleiben erhalten.`)) return;
  button.disabled = true;
  try {
    await api(`/api/targets/${encodeURIComponent(name)}`, { method: 'DELETE' });
    state.selectedPolicyRuleIds.clear();
    if (state.editingTargetName === name) cancelTargetEdit();
    await Promise.all([loadTargets(), loadStatus()]);
    activity(`Zielsystem ${name} gelöscht`, 'success');
    toast('Zielsystem gelöscht');
  } catch (error) {
    button.disabled = false;
    toast(error.message);
  }
}

function editTarget(target) {
  state.editingTargetName = target.name;
  document.querySelector('[data-view="targets"]').click();
  document.getElementById(target.local ? 'target-mode-local' : 'target-mode-ssh').checked = true;
  document.getElementById('target-name').value = target.name;
  document.getElementById('target-host').value = target.local ? '' : target.host;
  document.getElementById('target-user').value = target.user || '';
  document.getElementById('target-port').value = target.port || 22;
  document.getElementById('target-key').value = target.identity_file || '';
  document.getElementById('target-vm').value = target.vm_name || '';
  document.getElementById('edit-target-name').textContent = target.name;
  document.getElementById('edit-target-banner').hidden = false;
  document.getElementById('target-submit').textContent = 'Änderungen speichern';
  updateTargetMode();
  document.getElementById('target-name').focus();
}

function cancelTargetEdit() {
  state.editingTargetName = null;
  const form = document.getElementById('target-form'); form.reset();
  document.getElementById('target-mode-local').checked = true;
  document.getElementById('target-user').value = 'admin';
  document.getElementById('target-port').value = 22;
  document.getElementById('edit-target-banner').hidden = true;
  document.getElementById('edit-target-name').textContent = '';
  document.getElementById('target-submit').textContent = 'Zielsystem speichern';
  updateTargetMode();
}

async function auditTarget(target, button) {
  const selected = state.targets.find(item => item.name === target);
  const transport = selected && selected.vagrant_directory ? ' über Vagrant CLI' : '';
  button.disabled = true; activity(`Audit für ${target}${transport} gestartet`);
  try {
    const result = await api('/api/audit', { method: 'POST', body: JSON.stringify({ target }) });
    if (result.connection_refreshed) { await loadTargets(); activity('Vagrant-SSH-Zugang automatisch aktualisiert', 'success'); }
    activity(`${result.platform.pretty_name} erkannt; Inventar gespeichert`, 'success');
    result.warnings.forEach(warning => activity(warning, warning.includes('used QEMU Guest Agent') ? 'success' : 'error'));
    toast('Audit abgeschlossen');
  } catch (error) { activity(error.message, 'error'); toast(error.message); }
  finally { button.disabled = false; }
}

async function loadGuidelineSources() {
  const payload = await api('/api/guideline-sources'); state.guidelineSources = payload.sources; renderGuidelineSources();
}

async function loadPolicyProfiles() {
  const payload = await api('/api/policy-profiles'); state.policyProfiles = payload.profiles || [];
}

function resetGuidelineSourceForm() {
  const form = document.getElementById('guideline-source-form'); form.reset();
  state.editingSourceCategories = [];
  document.getElementById('source-original-id').value = '';
  document.getElementById('source-version').value = '*';
  document.getElementById('source-reviewed').value = new Date().toISOString().slice(0, 10);
  document.getElementById('source-enabled').checked = true;
}

function editGuidelineSource(source) {
  document.getElementById('source-original-id').value = source.custom ? source.id : '';
  document.getElementById('source-id').value = source.id;
  document.getElementById('source-publisher').value = source.publisher;
  document.getElementById('source-title').value = source.title;
  document.getElementById('source-url').value = source.url;
  document.getElementById('source-distribution').value = source.distribution;
  document.getElementById('source-version').value = source.version_pattern;
  document.getElementById('source-reviewed').value = source.reviewed;
  document.getElementById('source-enabled').checked = source.enabled;
  document.getElementById('source-scope').value = source.scope;
  state.editingSourceCategories = Array.isArray(source.categories) ? [...source.categories] : [];
  document.getElementById('source-editor').open = true;
  document.querySelector('.guideline-manager').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function renderGuidelineSources() {
  const list = document.getElementById('guideline-source-list'); list.replaceChildren();
  document.getElementById('source-count').textContent = `${state.guidelineSources.length} Quellen`;
  state.guidelineSources.forEach(source => {
    const item = document.createElement('article'); item.className = `guideline-source-card${source.enabled ? '' : ' disabled'}`;
    const head = document.createElement('div'); const title = document.createElement('strong'); title.textContent = `${source.publisher}: ${source.title}`; const badge = document.createElement('span'); badge.className = 'badge'; badge.textContent = source.enabled ? 'Aktiv' : 'Deaktiviert'; head.append(title, badge);
    const mapping = document.createElement('div'); mapping.className = 'source-mapping';
    const addMapping = (label, value) => { const cell = document.createElement('span'); const key = document.createElement('b'); key.textContent = label; cell.append(key, document.createTextNode(value)); mapping.append(cell); };
    addMapping('Distribution', source.distribution); addMapping('Version', source.version_pattern); addMapping('Geprüft', source.reviewed); addMapping('Herkunft', source.custom ? 'Eigene Zuordnung' : 'Mitgelieferte Zuordnung');
    const scope = document.createElement('p'); scope.textContent = source.scope;
    const actions = document.createElement('div'); actions.className = 'source-card-actions'; const link = document.createElement('a'); link.href = source.url; link.target = '_blank'; link.rel = 'noopener noreferrer'; link.textContent = 'Quelle öffnen'; actions.append(link);
    const edit = document.createElement('button'); edit.type = 'button'; edit.className = 'secondary'; edit.textContent = source.custom ? 'Bearbeiten' : 'Anpassen'; edit.addEventListener('click', () => editGuidelineSource(source)); actions.append(edit);
    if (source.custom) { const remove = document.createElement('button'); remove.type = 'button'; remove.className = 'danger'; remove.textContent = 'Löschen'; remove.addEventListener('click', async () => { if (!window.confirm(`Eigene Zuordnung für „${source.title}“ löschen?`)) return; await api(`/api/guideline-sources/${encodeURIComponent(source.id)}`, { method: 'DELETE' }); await loadGuidelineSources(); toast('Eigene Quellenzuordnung gelöscht'); }); actions.append(remove); }
    item.append(head, mapping, scope, actions); list.append(item);
  });
}

function renderSourceReview(payload) {
  const container = document.getElementById('source-review-result'); container.replaceChildren();
  const summary = document.createElement('p'); summary.className = 'source-review-summary'; summary.textContent = payload.summary || 'Keine Zusammenfassung zurückgegeben.'; container.append(summary);
  if (payload.suggestions.length) { const list = document.createElement('div'); list.className = 'source-review-suggestions'; payload.suggestions.forEach(item => { const row = document.createElement('div'); const title = document.createElement('strong'); title.textContent = item.title; const terms = document.createElement('code'); terms.textContent = item.search_terms; const reason = document.createElement('p'); reason.textContent = item.reason; row.append(title, terms, reason); list.append(row); }); container.append(list); }
  else { const complete = document.createElement('p'); complete.textContent = payload.missing_categories.length ? 'Qwen hat keine zusätzlichen sicheren Herstellerquellen vorgeschlagen.' : 'Die gespeicherten Quellen passen zur erkannten Distribution und Version.'; container.append(complete); }
}

async function reviewGuidelineSources() {
  const button = document.getElementById('review-guideline-sources'); const target = document.getElementById('build-target').value;
  if (!target) { toast('Zuerst ein Zielsystem auswählen'); return; }
  button.disabled = true; document.getElementById('source-review-result').textContent = 'Qwen analysiert Quellenmetadaten und Versionszuordnung …';
  try {
    const started = await api('/api/guidelines/review', { method: 'POST', body: JSON.stringify({ target }) }); state.sourceReviewJobId = started.job_id;
    while (state.sourceReviewJobId === started.job_id) { await new Promise(resolve => window.setTimeout(resolve, 2000)); const payload = await api(`/api/recommendations/${encodeURIComponent(started.job_id)}`); if (payload.status === 'running') continue; state.sourceReviewJobId = null; if (payload.status === 'completed') { renderSourceReview(payload); activity(`Quellenabdeckung mit ${payload.model} geprüft`, 'success'); } else { throw new Error(payload.error || 'Quellenprüfung fehlgeschlagen'); } }
  } catch (error) { document.getElementById('source-review-result').textContent = error.message; activity(error.message, 'error'); toast(error.message); }
  finally { button.disabled = false; await loadStatus(); }
}

function sourceIdFromCandidate(candidate) {
  const distribution = candidate.distribution || state.discoveryPlatform?.distribution || 'linux';
  const slug = candidate.title.toLowerCase().normalize('NFKD').replace(/[^a-z0-9]+/g, '.').replace(/^\.|\.$/g, '').slice(0, 70) || 'guideline';
  return `${distribution}.${slug}`.slice(0, 127);
}

function useGuidelineCandidate(candidate, recommendation) {
  resetGuidelineSourceForm();
  document.getElementById('source-id').value = sourceIdFromCandidate(candidate);
  document.getElementById('source-publisher').value = candidate.domain;
  document.getElementById('source-title').value = candidate.title;
  document.getElementById('source-url').value = candidate.url;
  document.getElementById('source-distribution').value = candidate.distribution || state.discoveryPlatform?.distribution || '';
  document.getElementById('source-version').value = ['all', '*'].includes(candidate.version) ? '' : (candidate.version || state.discoveryPlatform?.version || '');
  document.getElementById('source-scope').value = 'Online gefundener Kandidat; Inhalt und Versionspassung vor Freigabe manuell prüfen.';
  state.editingSourceCategories = Array.isArray(recommendation?.categories) ? [...recommendation.categories] : [];
  document.getElementById('source-editor').open = true;
  document.querySelector('.guideline-manager').scrollIntoView({ behavior: 'smooth', block: 'start' });
  document.getElementById('source-title').focus(); toast('Kandidat übernommen – bitte Quelle und Versionszuordnung prüfen');
}

function renderGuidelineCandidates(summary = '') {
  const container = document.getElementById('source-discovery-result'); container.replaceChildren();
  if (summary) { const text = document.createElement('p'); text.className = 'source-review-summary'; text.textContent = summary; container.append(text); }
  if (!state.guidelineCandidates.length) { const empty = document.createElement('p'); empty.textContent = 'Keine neuen Treffer auf den erlaubten Herstellerdomains gefunden.'; container.append(empty); return; }
  const list = document.createElement('div'); list.className = 'guideline-candidate-list';
  state.guidelineCandidates.forEach((candidate, index) => { const recommendation = state.discoveryRecommendations.get(index); const item = document.createElement('article'); const title = document.createElement('a'); title.href = candidate.url; title.target = '_blank'; title.rel = 'noopener noreferrer'; title.textContent = candidate.title; const domain = document.createElement('small'); domain.textContent = `${candidate.distribution || state.discoveryPlatform?.distribution || 'Linux'} ${candidate.version || state.discoveryPlatform?.version || ''} · ${candidate.domain}`; item.append(title, domain); if (recommendation) { const reason = document.createElement('p'); reason.textContent = `Qwen: ${recommendation.reason}`; item.append(reason); } const use = document.createElement('button'); use.type = 'button'; use.className = 'secondary'; use.textContent = 'Als Quellenkandidat übernehmen'; use.addEventListener('click', () => useGuidelineCandidate(candidate, recommendation)); item.append(use); list.append(item); });
  container.append(list);
}

async function discoverGuidelineSources() {
  const button = document.getElementById('discover-guideline-sources'); const target = document.getElementById('build-target').value; const scope = document.getElementById('guideline-discovery-scope').value;
  if (scope === 'target' && !target) { toast('Zuerst ein Zielsystem auswählen'); return; }
  const scopeNames = { target: `Zielsystem „${target}“`, manual: 'Distribution und Version aus dem Quellenformular', inventories: 'alle bereits geprüften Linux-Versionen', supported: 'alle unterstützten Hersteller und Versionen' };
  if (!window.confirm(`Jetzt ausdrücklich online suchen: ${scopeNames[scope]}?\n\nEs werden nur HTTPS-Treffer erlaubter Herstellerdomains angezeigt.`)) return;
  button.disabled = true; document.getElementById('source-discovery-result').textContent = 'Offizielle Herstellerdomains werden durchsucht …';
  try {
    const payload = await api('/api/guidelines/discover', { method: 'POST', body: JSON.stringify({ target, scope, distribution: document.getElementById('source-distribution').value, version: document.getElementById('source-version').value }) });
    state.guidelineCandidates = payload.search.candidates; state.discoveryPlatform = payload.guideline.platform; state.discoveryRecommendations = new Map(); renderGuidelineCandidates(payload.search.warnings.length ? `Suche teilweise eingeschränkt: ${payload.search.warnings.join(' · ')}` : `${payload.search.candidates.length} offizielle Kandidaten gefunden.`);
    if (payload.job_id) { let result; do { await new Promise(resolve => window.setTimeout(resolve, 2000)); result = await api(`/api/recommendations/${encodeURIComponent(payload.job_id)}`); } while (result.status === 'running'); if (result.status === 'completed') { state.discoveryRecommendations = new Map(result.recommendations.map(item => [item.candidate_index, item])); renderGuidelineCandidates(result.summary); activity(`Neue Richtlinien mit ${result.model} bewertet`, 'success'); } else { activity(`Online-Treffer gefunden; Qwen-Bewertung fehlgeschlagen: ${result.error}`, 'error'); } }
    else { activity(`${payload.search.candidates.length} offizielle Richtlinienkandidaten gefunden; Qwen ist nicht verfügbar`, 'success'); }
  } catch (error) { document.getElementById('source-discovery-result').textContent = error.message; activity(error.message, 'error'); toast(error.message); }
  finally { button.disabled = false; await loadStatus(); }
}

function renderGuidelineSummary(guideline, checkSummary) {
  state.lastGuideline = guideline;
  renderPolicyOverview();
  const container = document.getElementById('guideline-summary'); container.replaceChildren();
  const generalContainer = document.getElementById('general-hardening-summary'); generalContainer.replaceChildren();
  const cards = document.createElement('div'); cards.className = 'guideline-cards';
  const addCard = (label, title, detail, status = '') => {
    const card = document.createElement('div'); card.className = `guideline-card ${status}`;
    const small = document.createElement('small'); small.textContent = label;
    const strong = document.createElement('strong'); strong.textContent = title;
    const text = document.createElement('p'); text.textContent = detail;
    card.append(small, strong, text); cards.append(card);
  };
  addCard('ERKANNTES SYSTEM', guideline.platform.pretty_name, `${guideline.vendor} · ${guideline.platform.distribution} ${guideline.platform.version}`, guideline.compatibility);
  addCard('OFFIZIELLE BASIS', guideline.framework, guideline.compatibility_message, guideline.compatibility);
  const scanner = guideline.native_scanner;
  const nativeRuleCount = scanner.data_streams.reduce((sum, stream) => sum + (stream.rules || 0), 0);
  const scannerTitle = scanner.ready ? 'Scanner und Inhalte vorhanden' : (scanner.tool_ready ? 'Regelinhalte fehlen' : 'Scanner fehlt');
  addCard('NATIVE PRÜFUNG', scannerTitle, scanner.ready ? `${Object.keys(scanner.tools).join(', ')} · ${scanner.data_streams.length} Datenquellen · ${nativeRuleCount || '?'} SCAP-Regeln` : guideline.install_hint, scanner.ready ? 'covered' : 'gap');
  container.append(cards);
  const relationship = document.createElement('div'); relationship.className = 'policy-relationship';
  const stages = [
    ['1', 'Herstellerquellen', `${guideline.documents.length} versionspassende Dokumente`, 'Beschreiben die Richtlinie, führen aber selbst keine Prüfung aus.'],
    ['2', 'Maschinenlesbarer Benchmark', scanner.ready ? `${nativeRuleCount || '?'} Regeln insgesamt` : 'OpenSCAP-Inhalt fehlt', 'Der Full Scan erstellt unabhängig von Herstellerprofilen ein eigenes Vollprofil mit allen Regeln.'],
    ['3', 'Ausgeführter Policy-Audit', guideline.scap_scan ? `${guideline.scap_scan.results} SCAP-Regeln geprüft` : 'Noch kein vollständiger Profil-Audit', 'Danach können die fehlgeschlagenen Regeln ausgewählt, gespeichert und gehärtet werden.']
  ];
  stages.forEach(([number, titleText, value, explanation]) => { const stage = document.createElement('div'); const numberNode = document.createElement('span'); numberNode.textContent = number; const body = document.createElement('div'); const title = document.createElement('strong'); title.textContent = titleText; const count = document.createElement('b'); count.textContent = value; const note = document.createElement('small'); note.textContent = explanation; body.append(title, count, note); stage.append(numberNode, body); relationship.append(stage); }); container.append(relationship);
  if (!scanner.ready && guideline.install_plan) {
    const install = document.createElement('div'); install.className = 'scanner-install';
    const info = document.createElement('div'); const title = document.createElement('strong'); const needsDebian13Content = guideline.platform.distribution === 'debian' && String(guideline.platform.version).split('.')[0] === '13' && !scanner.exact_stream_match; title.textContent = needsDebian13Content ? 'Passender Debian-13-SCAP-Inhalt fehlt' : scanner.tool_ready ? 'OpenSCAP-Regelinhalte fehlen' : 'OpenSCAP fehlt auf diesem Zielsystem';
    const detail = document.createElement('p'); detail.textContent = needsDebian13Content ? 'Das Debian-Paket enthält nur ältere Datenströme. Der Agent installiert OpenSCAP aus APT und ergänzt den offiziellen, SHA-512-geprüften ComplianceAsCode-0.1.81-Datenstrom für Debian 13. Es wird noch kein Hardening ausgeführt.' : `Benötigte Pakete: ${guideline.install_plan.packages.join(', ')}. Die Installation verändert nur diese Pakete und startet noch kein Hardening.`;
    info.append(title, detail);
    const button = document.createElement('button'); button.type = 'button'; button.textContent = needsDebian13Content ? 'Debian-13-Inhalt installieren' : 'OpenSCAP installieren'; button.addEventListener('click', () => installComplianceScanner(button, guideline.install_plan));
    install.append(info, button); container.append(install);
  }
  if (scanner.ready && scanner.data_streams.length) {
    const scan = document.createElement('div'); scan.className = 'scanner-scan';
    const info = document.createElement('div'); const title = document.createElement('strong'); title.textContent = 'Vollständigen SCAP-Benchmark prüfen';
    const detail = document.createElement('p'); detail.textContent = `Alle ${nativeRuleCount || ''} Regeln werden in ein unabhängiges temporäres Vollprofil aufgenommen. Das Herstellerprofil standard wird nicht verwendet.`; info.append(title, detail);
    const controls = document.createElement('div'); controls.className = 'scanner-scan-controls';
    const stream = document.createElement('select'); stream.id = 'scap-stream-select';
    scanner.data_streams.forEach(item => { const option = document.createElement('option'); option.value = item.path; option.textContent = item.path.split('/').pop(); stream.append(option); });
    const hint = document.createElement('span'); hint.className = 'badge'; hint.textContent = 'Full Scan bereit';
    controls.append(stream, hint); scan.append(info, controls); container.append(scan);
  } else if (scanner.ready) {
    const warning = document.createElement('div'); warning.className = 'scanner-command'; const title = document.createElement('strong'); title.textContent = 'Keine auswertbaren SCAP-Profile erkannt'; const detail = document.createElement('p'); detail.textContent = 'Der Scanner ist vorhanden, aber aus dem Datenstrom konnten keine Profile gelesen werden. Paketinhalt oder Datenstrom bitte prüfen.'; warning.append(title, detail); container.append(warning);
  }

  const lower = document.createElement('div'); lower.className = 'guideline-detail-grid';
  const sources = document.createElement('div'); const sourceTitle = document.createElement('strong'); sourceTitle.textContent = 'Zugeordnete Herstellerquellen'; sources.append(sourceTitle);
  guideline.documents.forEach(documentInfo => {
    const item = document.createElement('div'); item.className = 'guideline-source';
    const link = document.createElement('a'); link.href = documentInfo.url; link.target = '_blank'; link.rel = 'noopener noreferrer'; link.textContent = documentInfo.title;
    const scope = document.createElement('span'); scope.textContent = `${documentInfo.distribution} ${documentInfo.version_pattern} · ${documentInfo.scope}`;
    item.append(link, scope); sources.append(item);
  });
  if (!guideline.documents.length) { const warning = document.createElement('p'); warning.textContent = 'Für diese Distribution und Version ist keine aktive Herstellerquelle definiert.'; sources.append(warning); }
  const policy = document.createElement('div'); const policyTitle = document.createElement('strong'); policyTitle.textContent = 'Verfügbarer SCAP-Benchmark'; policy.append(policyTitle);
  const policyText = document.createElement('p'); policyText.textContent = scanner.ready ? `${nativeRuleCount || '?'} maschinenlesbare SCAP-Regeln erkannt. Der Full Scan wählt alle Regeln direkt aus dem Datenstrom aus.` : 'OpenSCAP oder der passende Hersteller-Datenstrom fehlt noch.'; policy.append(policyText);
  if (scanner.profiles.length) { const profiles = document.createElement('details'); profiles.className = 'native-profiles'; const summary = document.createElement('summary'); summary.textContent = `${scanner.profiles.length} erkannte Herstellerprofile anzeigen`; const list = document.createElement('ul'); scanner.profiles.forEach(profile => { const item = document.createElement('li'); item.textContent = profile; list.append(item); }); profiles.append(summary, list); policy.append(profiles); }
  if (scanner.sample_rules.length) { const rules = document.createElement('details'); rules.className = 'native-profiles'; const summary = document.createElement('summary'); summary.textContent = `${scanner.sample_rules.length} Regeln als technische Stichprobe anzeigen`; const note = document.createElement('p'); note.textContent = 'Nach dem Scan wird die vollständige Ergebnisliste mit echten Titeln und Auswahlfeldern angezeigt.'; const list = document.createElement('ul'); scanner.sample_rules.forEach(ruleId => { const item = document.createElement('li'); item.textContent = ruleId.replace('xccdf_org.ssgproject.content_rule_', ''); list.append(item); }); rules.append(summary, note, list); policy.append(rules); }
  lower.append(sources, policy); container.append(lower);
  if (guideline.scap_scan && state.scapResults.length) renderScapResults(container, guideline.scap_scan);
  renderGeneralLinuxBaseline(generalContainer, state.scapResults.filter(item => item.status === 'fail'));
}

function renderPolicyOverview() {
  const container = document.getElementById('policy-overview');
  if (!container || !state.lastGuideline) return;
  container.replaceChildren(); const guideline = state.lastGuideline; const scanner = guideline.native_scanner; const nativeRules = scanner.data_streams.reduce((sum, stream) => sum + (stream.rules || 0), 0);
  const addLayer = (number, titleText, count, description, status) => { const item = document.createElement('article'); item.className = `policy-layer ${status}`; const index = document.createElement('span'); index.textContent = number; const body = document.createElement('div'); const title = document.createElement('strong'); title.textContent = titleText; const value = document.createElement('b'); value.textContent = count; const note = document.createElement('p'); note.textContent = description; body.append(title, value, note); item.append(index, body); container.append(item); };
  const streams = scanner.data_streams.map(item => item.path.split('/').pop()).join(', ');
  addLayer('1', 'Vollständiger SCAP-Benchmark', scanner.ready ? `${nativeRules || '?'} Regeln` : 'Noch nicht verfügbar', scanner.ready ? `${guideline.platform.pretty_name} · Datenstrom: ${streams}. Der Agent erzeugt ein eigenes Vollprofil mit allen Regeln; standard wird nicht als Basis verwendet.` : guideline.install_hint, scanner.ready ? 'primary' : 'missing');
  const distro = guideline.platform.distribution; const version = guideline.platform.version; const ovalSupported = distro === 'opensuse-leap' || distro === 'debian' || distro === 'ubuntu';
  addLayer('2', 'Schwachstellen und Patches', ovalSupported ? `Offizieller Feed für ${distro} ${version}` : 'Noch kein eindeutiger Feed', ovalSupported ? 'OVAL bewertet installierte Pakete und fehlende Herstellerupdates. Das ist keine Konfigurationsregel.' : 'Es wird niemals stillschweigend der Feed einer anderen Distribution verwendet.', ovalSupported ? 'secondary' : 'missing');
  const categories = new Set(guideline.documents.flatMap(item => item.categories || []));
  addLayer('3', 'Herstellerdokumentation', `${guideline.documents.length} versionspassende Quellen`, guideline.documents.length ? `${categories.size} Kategorien dokumentiert. Diese Quellen erklären die Policy; die ausführbaren Regeln bleiben Bestandteil des OpenSCAP-Profils.` : 'Für diese Distribution und Version ist noch keine aktive Herstellerquelle zugeordnet.', guideline.documents.length ? 'reference' : 'missing');
}

function renderScapResults(container, scan) {
  const results = state.scapResults;
  const failed = results.filter(item => item.status === 'fail');
  const pending = results.filter(item => ['notselected', 'notchecked'].includes(item.status));
  const evaluated = results.length - pending.length;
  const section = document.createElement('div'); section.className = 'scap-results';
  let advancedSelection = null;
  const head = document.createElement('div'); head.className = 'scap-results-head';
  const identity = document.createElement('div');
  const title = document.createElement('strong'); title.textContent = 'Ergebnis des vollständigen SCAP-Benchmarks';
  const detail = document.createElement('p'); detail.textContent = `${results.length} Regeln im Vollprofil · ${evaluated} technisch bewertet · ${pending.length} technisch nicht auswertbar.`;
  identity.append(title, detail);
  const counts = document.createElement('div'); counts.className = 'scap-counts';
  [['pass', 'Bestanden'], ['fail', 'Nicht bestanden'], ['error', 'Fehler'], ['notapplicable', 'Nicht anwendbar'], ['notselected', 'Nicht im Profil'], ['notchecked', 'Nicht geprüft']].forEach(([key, label]) => {
    const badge = document.createElement('span');
    badge.className = `check-result ${key === 'pass' ? 'passed' : key === 'fail' ? 'failed' : key === 'error' ? 'error' : 'manual'}`;
    badge.textContent = `${label}: ${scan.counts[key] || 0}`; counts.append(badge);
  });
  head.append(identity, counts); section.append(head);
  if (scan.applicability_status === 'incompatible') {
    const explanation = document.createElement('div'); explanation.className = 'scan-explanation error';
    explanation.textContent = scan.applicability_message || 'Der gewählte SCAP-Datenstrom passt nicht zu diesem System. Es wird kein Hardening freigegeben.';
    section.append(explanation);
  } else if ((scan.counts.notapplicable || 0) > 0) {
    const explanation = document.createElement('div'); explanation.className = 'scan-explanation';
    explanation.textContent = `${scan.counts.notapplicable} Regeln wurden nicht übersprungen: OpenSCAP hat ihre Voraussetzungen ausgewertet und festgestellt, dass sie auf diesem System nicht anwendbar sind. Nur „nicht ausgewählt“ und „nicht geprüft“ sind echte technische Abdeckungslücken.`;
    section.append(explanation);
  }

  if (failed.length) {
    const selection = document.createElement('details'); selection.className = 'policy-selection advanced-policy'; const advancedSummary = document.createElement('summary'); advancedSummary.textContent = 'Erweiterte OpenSCAP-Auswahl und Qwen-Priorisierung'; selection.append(advancedSummary); advancedSelection = selection;
    const selectionTop = document.createElement('div'); selectionTop.className = 'policy-selection-top';
    const selectionTitle = document.createElement('div'); const selectionStrong = document.createElement('strong'); selectionStrong.textContent = 'Wichtige Fehlschläge als Hardening-Profil speichern';
    const selectionHint = document.createElement('p'); selectionHint.textContent = 'Gewünschte Regeln unten auswählen, einen Profilnamen eingeben und speichern.'; selectionTitle.append(selectionStrong, selectionHint);
    const selectionActions = document.createElement('div'); const selectionCount = document.createElement('span'); selectionCount.id = 'policy-selection-count'; selectionCount.className = 'badge'; selectionCount.textContent = `${state.selectedPolicyRuleIds.size} ausgewählt`;
    const all = document.createElement('button'); all.type = 'button'; all.className = 'secondary'; all.textContent = 'Alle fehlgeschlagenen'; all.addEventListener('click', () => { state.selectedPolicyRuleIds = new Set(failed.map(item => item.id)); renderGuidelineSummary(state.lastGuideline, null); });
    const none = document.createElement('button'); none.type = 'button'; none.className = 'secondary'; none.textContent = 'Keine'; none.addEventListener('click', () => { state.selectedPolicyRuleIds.clear(); renderGuidelineSummary(state.lastGuideline, null); });
    selectionActions.append(selectionCount, all, none); selectionTop.append(selectionTitle, selectionActions); selection.append(selectionTop);

    const profileTools = document.createElement('div'); profileTools.className = 'policy-profile-tools';
    const saved = document.createElement('select'); saved.setAttribute('aria-label', 'Gespeichertes Auswahlprofil'); const empty = document.createElement('option'); empty.value = ''; empty.textContent = 'Gespeichertes Profil wählen'; saved.append(empty);
    state.policyProfiles.filter(item => item.base_profile === scan.profile && item.data_stream === scan.data_stream).forEach(item => { const option = document.createElement('option'); option.value = item.id; option.textContent = `${item.name} · ${item.rule_ids.length} Regeln`; saved.append(option); });
    const load = document.createElement('button'); load.type = 'button'; load.className = 'secondary'; load.textContent = 'Profil laden'; load.addEventListener('click', () => { const profile = state.policyProfiles.find(item => item.id === saved.value); if (!profile) return; const available = new Set(failed.map(item => item.id)); state.selectedPolicyRuleIds = new Set(profile.rule_ids.filter(id => available.has(id))); renderGuidelineSummary(state.lastGuideline, null); toast(`${profile.name} geladen`); });
    const name = document.createElement('input'); name.placeholder = 'Name für neues Auswahlprofil'; name.setAttribute('aria-label', 'Profilname');
    const save = document.createElement('button'); save.type = 'button'; save.textContent = 'Hardening-Profil speichern'; save.addEventListener('click', async () => { if (!name.value.trim()) { toast('Profilname eingeben'); return; } if (!state.selectedPolicyRuleIds.size) { toast('Mindestens eine fehlgeschlagene Regel auswählen'); return; } save.disabled = true; try { await api('/api/policy-profiles', { method: 'POST', body: JSON.stringify({ target: document.getElementById('build-target').value, name: name.value.trim(), profile: scan.profile, data_stream: scan.data_stream, rule_ids: Array.from(state.selectedPolicyRuleIds) }) }); await loadPolicyProfiles(); renderGuidelineSummary(state.lastGuideline, null); toast('Hardening-Profil gespeichert'); } catch (error) { toast(error.message); } finally { save.disabled = false; } });
    profileTools.append(saved, load, name, save); selection.append(profileTools);
    const ai = document.createElement('div'); ai.className = 'ai-hardening-review';
    const aiHead = document.createElement('div'); aiHead.className = 'ai-hardening-head';
    const aiTitle = document.createElement('div'); const aiStrong = document.createElement('strong'); aiStrong.textContent = 'KI-Hardening-Analyse'; const aiHint = document.createElement('p'); aiHint.textContent = 'Qwen priorisiert ausschliesslich die echten OpenSCAP-Fehlschläge. Die Auswahl bleibt unter deiner Kontrolle.'; aiTitle.append(aiStrong, aiHint);
    const aiRun = document.createElement('button'); aiRun.type = 'button'; aiRun.className = 'secondary'; aiRun.textContent = state.hardeningReviewJobId ? 'Qwen analysiert …' : state.aiHardeningReview?.status === 'completed' ? 'Analyse erneut ausführen' : 'Mit Qwen priorisieren'; aiRun.disabled = Boolean(state.hardeningReviewJobId); aiRun.addEventListener('click', () => startHardeningReview());
    aiHead.append(aiTitle, aiRun); ai.append(aiHead);
    if (state.aiHardeningReview?.status === 'running') { const working = document.createElement('p'); working.className = 'ai-working'; working.textContent = `${state.aiHardeningReview.model || 'Qwen'} bewertet Risiko, Betriebswirkung und Prüfweg im Hintergrund …`; ai.append(working); }
    if (state.aiHardeningReview?.status === 'failed') { const error = document.createElement('p'); error.className = 'ai-review-error'; error.textContent = state.aiHardeningReview.error; ai.append(error); }
    if (state.aiHardeningReview?.status === 'completed') {
      const review = state.aiHardeningReview; const summary = document.createElement('p'); summary.className = 'ai-review-summary'; summary.textContent = review.summary || 'Analyse abgeschlossen.'; ai.append(summary);
      const controls = document.createElement('div'); controls.className = 'ai-review-controls'; const guardrail = document.createElement('span'); guardrail.textContent = `${review.model} · ${review.guardrail}`; const use = document.createElement('button'); use.type = 'button'; use.textContent = `KI-Vorschlag auswählen (${review.selected_rule_ids.length})`; use.disabled = !review.selected_rule_ids.length; use.addEventListener('click', () => { const available = new Set(failed.map(item => item.id)); state.selectedPolicyRuleIds = new Set(review.selected_rule_ids.filter(id => available.has(id))); renderGuidelineSummary(state.lastGuideline, null); toast('KI-Vorschlag übernommen – bitte vor dem Speichern prüfen'); }); controls.append(guardrail, use); ai.append(controls);
      const recommendations = document.createElement('div'); recommendations.className = 'ai-recommendation-list'; review.recommendations.forEach(item => { const card = document.createElement('article'); card.className = `ai-recommendation ${item.priority}`; const header = document.createElement('div'); const label = document.createElement('strong'); label.textContent = item.title; const badge = document.createElement('span'); badge.textContent = `${item.priority} · ${item.disposition}`; header.append(label, badge); const reason = document.createElement('p'); reason.textContent = item.reason; const impact = document.createElement('small'); impact.textContent = `Betriebswirkung: ${item.operational_impact || 'manuell prüfen'} · Kontrolle danach: ${item.validation || 'OpenSCAP erneut ausführen'}`; card.append(header, reason, impact); recommendations.append(card); }); ai.append(recommendations);
    }
    selection.append(ai); section.append(selection);
  } else {
    const clean = document.createElement('div'); clean.className = `scan-explanation${scan.applicability_status === 'incompatible' ? ' error' : ''}`; clean.textContent = scan.applicability_status === 'incompatible' ? 'Kein gültiges Härtungsergebnis: Bitte den exakt passenden SCAP-Datenstrom installieren und den Full Scan wiederholen.' : 'Im vollständigen Benchmark ist keine Regel fehlgeschlagen. Deshalb gibt es aktuell keine Hardening-Massnahme.'; section.append(clean);
  }

  const important = failed;
  const details = document.createElement('details'); details.open = Boolean(failed.length);
  const summary = document.createElement('summary'); summary.textContent = failed.length ? `${failed.length} fehlgeschlagene Regeln auswählen` : 'Technische SCAP-Ergebnisse anzeigen'; details.append(summary);
  const list = document.createElement('div'); list.className = 'scap-result-list';
  const grouped = new Map(); (important.length ? important : results).forEach(result => { const category = result.topic || 'other'; if (!grouped.has(category)) grouped.set(category, []); grouped.get(category).push(result); });
  grouped.forEach((groupResults, category) => {
    const categoryTitle = document.createElement('div'); categoryTitle.className = 'scap-category-title'; categoryTitle.textContent = `${categoryNames[category] || 'Weitere Herstellerregeln'} · ${groupResults.length}`; list.append(categoryTitle);
    groupResults.forEach(result => {
      const row = document.createElement('div'); row.className = ['fail', 'notselected', 'notchecked'].includes(result.status) ? 'selectable-policy-rule' : '';
      if (result.status === 'fail') {
        const checkbox = document.createElement('input'); checkbox.type = 'checkbox'; checkbox.checked = state.selectedPolicyRuleIds.has(result.id); checkbox.setAttribute('aria-label', `${result.title} auswählen`);
        checkbox.addEventListener('change', () => { if (checkbox.checked) state.selectedPolicyRuleIds.add(result.id); else state.selectedPolicyRuleIds.delete(result.id); const counter = document.querySelector('#policy-selection-count'); if (counter) counter.textContent = `${state.selectedPolicyRuleIds.size} ausgewählt`; }); row.append(checkbox);
      }
      const ruleInfo = document.createElement('div'); const name = document.createElement('strong'); name.textContent = result.title; const id = document.createElement('code'); id.textContent = result.short_id; ruleInfo.append(name, id);
      const status = document.createElement('span'); status.className = `check-result ${result.status === 'pass' ? 'passed' : result.status === 'fail' ? 'failed' : result.status === 'error' ? 'error' : 'manual'}`; status.textContent = result.status; row.append(ruleInfo, status); list.append(row);
    });
  });
  details.append(list); section.append(details);

  if (failed.length) {
    const remediation = document.createElement('div'); remediation.className = 'native-remediation'; const info = document.createElement('div'); const remediationTitle = document.createElement('strong'); remediationTitle.textContent = 'Hardening aus ausgewählten Fehlschlägen'; const note = document.createElement('p'); note.textContent = 'Der Agent prüft die Auswahl nochmals und erzeugt ein Apply-, Verify- und Tailoring-Skript. Du kannst das Paket herunterladen oder sicher nach /tmp des Zielsystems übertragen.'; info.append(remediationTitle, note);
    const actions = document.createElement('div'); actions.className = 'remediation-actions';
    const download = document.createElement('button'); download.type = 'button'; download.textContent = 'Skripte herunterladen'; download.addEventListener('click', () => buildSelectedPolicyPackage(download, scan.profile, scan.data_stream, 'download'));
    const stage = document.createElement('button'); stage.type = 'button'; stage.className = 'secondary'; stage.textContent = 'Nach /tmp übertragen'; stage.addEventListener('click', () => buildSelectedPolicyPackage(stage, scan.profile, scan.data_stream, 'stage'));
    actions.append(download, stage); remediation.append(info, actions); (advancedSelection || section).append(remediation);
  }
  container.append(section);
}

function renderGeneralLinuxBaseline(container, failedRules) {
  const panel = document.createElement('section'); panel.className = 'general-baseline';
  const head = document.createElement('div'); head.className = 'general-baseline-head';
  const identity = document.createElement('div'); const title = document.createElement('strong'); title.textContent = 'Baseline-Auswertung'; const description = document.createElement('p'); description.textContent = 'Ordnet die echten Ergebnisse des Hersteller-Benchmarks nach allgemeinen Empfehlungen von ANSSI, BSI und NIST ein.'; identity.append(title, description);
  const tools = document.createElement('div'); tools.className = 'general-baseline-tools';
  const level = document.createElement('select'); level.setAttribute('aria-label', 'Baseline-Niveau'); [['basic', 'Basis'], ['elevated', 'Erhöht'], ['critical', 'Kritisch']].forEach(([value, label]) => { const option = document.createElement('option'); option.value = value; option.textContent = label; option.selected = state.generalBaselineLevel === value; level.append(option); }); level.addEventListener('change', () => { state.generalBaselineLevel = level.value; evaluateGeneralBaseline(); });
  const run = document.createElement('button'); run.type = 'button'; run.className = 'secondary'; run.textContent = state.baselineBusy ? 'Wird ausgewertet …' : 'Baseline auswerten'; run.disabled = state.baselineBusy; run.addEventListener('click', () => evaluateGeneralBaseline()); tools.append(level, run); head.append(identity, tools); panel.append(head);
  if (!state.generalBaseline) { const note = document.createElement('p'); note.className = 'baseline-placeholder'; note.textContent = 'Nach dem Full Scan wird die allgemeine Linux-Baseline automatisch ausgewertet.'; panel.append(note); container.append(panel); return; }
  const baseline = state.generalBaseline;
  const summary = document.createElement('div'); summary.className = 'baseline-summary'; const labels = { pass: 'Bestanden', fail: 'Nicht bestanden', manual: 'Manuell', not_covered: 'Nicht abgedeckt', technical_gap: 'Technische Lücke', not_applicable: 'Nicht anwendbar' }; ['pass', 'fail', 'manual', 'not_covered', 'technical_gap', 'not_applicable'].forEach(key => { const badge = document.createElement('span'); badge.className = `baseline-status ${key}`; badge.textContent = `${labels[key]}: ${baseline.counts[key] || 0}`; summary.append(badge); }); panel.append(summary);
  const categoryBox = document.createElement('details'); categoryBox.className = 'baseline-category-filter'; const categorySummary = document.createElement('summary'); categorySummary.textContent = `${baseline.enabled_categories.length} von ${baseline.categories.length} Kategorien aktiviert`; const categoryGrid = document.createElement('div'); categoryGrid.className = 'baseline-category-grid'; baseline.categories.forEach(category => { const label = document.createElement('label'); const checkbox = document.createElement('input'); checkbox.type = 'checkbox'; checkbox.checked = state.generalBaselineCategories === null ? category.enabled : state.generalBaselineCategories.has(category.id); checkbox.addEventListener('change', () => { if (state.generalBaselineCategories === null) state.generalBaselineCategories = new Set(baseline.enabled_categories); if (checkbox.checked) state.generalBaselineCategories.add(category.id); else state.generalBaselineCategories.delete(category.id); }); const text = document.createElement('span'); text.textContent = category.title; label.append(checkbox, text); categoryGrid.append(label); }); const applyCategories = document.createElement('button'); applyCategories.type = 'button'; applyCategories.textContent = 'Kategorien anwenden'; applyCategories.addEventListener('click', () => evaluateGeneralBaseline()); categoryGrid.append(applyCategories); categoryBox.append(categorySummary, categoryGrid); panel.append(categoryBox);
  renderBaselineWorkflow(panel, baseline, failedRules);
  const actions = document.createElement('div'); actions.className = 'baseline-actions'; const filter = document.createElement('select'); filter.setAttribute('aria-label', 'Baseline-Statusfilter'); [['all', 'Alle Einträge'], ['fail', 'Nur offen'], ['manual', 'Nur manuell'], ['not_covered', 'Nicht abgedeckt'], ['pass', 'Bestanden']].forEach(([value, label]) => { const option = document.createElement('option'); option.value = value; option.textContent = label; option.selected = state.generalBaselineStatusFilter === value; filter.append(option); }); filter.addEventListener('change', () => { state.generalBaselineStatusFilter = filter.value; renderGuidelineSummary(state.lastGuideline, null); }); const hint = document.createElement('span'); hint.textContent = 'Gewünschte Einträge unten markieren'; actions.append(hint, filter); panel.append(actions);
  const grouped = new Map(); baseline.controls.filter(control => state.generalBaselineStatusFilter === 'all' || control.status === state.generalBaselineStatusFilter).forEach(control => { if (!grouped.has(control.category)) grouped.set(control.category, []); grouped.get(control.category).push(control); });
  const list = document.createElement('div'); list.className = 'baseline-control-groups'; grouped.forEach((controls, category) => { const details = document.createElement('details'); details.open = controls.some(control => ['fail', 'technical_gap'].includes(control.status)); const groupSummary = document.createElement('summary'); groupSummary.textContent = `${controls[0].category_title} · ${controls.length}`; const controlsList = document.createElement('div'); controlsList.className = 'baseline-control-list'; controls.forEach(control => { const card = document.createElement('article'); card.className = `baseline-control ${control.status}`; const top = document.createElement('div'); const selectLabel = document.createElement('label'); selectLabel.className = 'baseline-control-select'; const checkbox = document.createElement('input'); checkbox.type = 'checkbox'; checkbox.disabled = ['pass', 'not_applicable'].includes(control.status); checkbox.checked = state.selectedBaselineControlIds.has(control.id); checkbox.addEventListener('change', () => { if (checkbox.checked) state.selectedBaselineControlIds.add(control.id); else state.selectedBaselineControlIds.delete(control.id); state.baselinePlan = null; renderGuidelineSummary(state.lastGuideline, null); }); const controlTitle = document.createElement('strong'); controlTitle.textContent = control.title; selectLabel.append(checkbox, controlTitle); const status = document.createElement('span'); status.className = `baseline-status ${control.status}`; status.textContent = labels[control.status] || control.status; top.append(selectLabel, status); const rationale = document.createElement('p'); rationale.textContent = control.rationale; card.append(top, rationale); if (control.matched_rules.length) { const matching = document.createElement('small'); matching.textContent = `Technisch zugeordnet: ${control.matched_rules.map(item => item.short_id || item.id).join(', ')}`; card.append(matching); } if (control.manual) { const manual = document.createElement('small'); manual.className = 'baseline-manual'; manual.textContent = `Manuelle Ergänzung: ${control.manual}`; card.append(manual); } const sourceDetails = document.createElement('details'); const sourceSummary = document.createElement('summary'); sourceSummary.textContent = `${control.sources.length} offizielle Referenzen anzeigen`; const sourceList = document.createElement('div'); sourceList.className = 'baseline-sources'; control.sources.forEach(source => { const link = document.createElement('a'); link.href = source.url; link.target = '_blank'; link.rel = 'noopener noreferrer'; link.textContent = `${source.id} · ${source.title}`; sourceList.append(link); }); sourceDetails.append(sourceSummary, sourceList); card.append(sourceDetails); renderBaselineSetup(card, control, failedRules); controlsList.append(card); }); details.append(groupSummary, controlsList); list.append(details); }); if (!grouped.size) { const empty = document.createElement('p'); empty.className = 'baseline-placeholder'; empty.textContent = 'Für diesen Filter sind keine Empfehlungen vorhanden.'; list.append(empty); } panel.append(list);
  const method = document.createElement('p'); method.className = 'baseline-method'; method.textContent = `${baseline.method} Bericht: ${baseline.report_path || 'lokal gespeichert'}`; panel.append(method); container.append(panel);
}

function renderBaselineWorkflow(panel, baseline, failedRules) {
  const workflow = document.createElement('section'); workflow.className = 'baseline-workflow';
  const heading = document.createElement('div'); heading.className = 'baseline-workflow-heading'; const title = document.createElement('strong'); title.textContent = 'Hardening-Paket in 3 Schritten'; const note = document.createElement('span'); note.textContent = 'Nur echte OpenSCAP-Fehlschläge werden ausführbar'; heading.append(title, note); workflow.append(heading);
  const steps = document.createElement('div'); steps.className = 'baseline-workflow-steps';
  const roleStep = document.createElement('div'); const roleNumber = document.createElement('b'); roleNumber.textContent = '1'; const roleBody = document.createElement('div'); const roleTitle = document.createElement('strong'); roleTitle.textContent = 'Systemrolle'; const role = document.createElement('select'); role.setAttribute('aria-label', 'Systemrolle'); (baseline.system_roles || []).forEach(item => { const option = document.createElement('option'); option.value = item.id; option.textContent = item.title; option.selected = state.baselineRole === item.id; role.append(option); }); role.addEventListener('change', () => { state.baselineRole = role.value; state.baselinePlan = null; renderGuidelineSummary(state.lastGuideline, null); }); const activeRole = (baseline.system_roles || []).find(item => item.id === state.baselineRole); const roleHint = document.createElement('small'); roleHint.textContent = activeRole?.description || 'Passende Betriebsrolle auswählen'; roleBody.append(roleTitle, role, roleHint); roleStep.append(roleNumber, roleBody);
  const selectStep = document.createElement('div'); const selectNumber = document.createElement('b'); selectNumber.textContent = '2'; const selectBody = document.createElement('div'); const selectTitle = document.createElement('strong'); selectTitle.textContent = 'Einträge auswählen'; const selected = document.createElement('span'); selected.className = 'baseline-selected-count'; selected.textContent = `${state.selectedBaselineControlIds.size} ausgewählt`; const selectActions = document.createElement('div'); const open = document.createElement('button'); open.type = 'button'; open.className = 'secondary'; open.textContent = 'Alle offenen'; open.addEventListener('click', () => { state.selectedBaselineControlIds = new Set(baseline.controls.filter(item => ['fail', 'manual', 'not_covered', 'technical_gap'].includes(item.status)).map(item => item.id)); state.baselinePlan = null; renderGuidelineSummary(state.lastGuideline, null); }); const none = document.createElement('button'); none.type = 'button'; none.className = 'secondary'; none.textContent = 'Keine'; none.addEventListener('click', () => { state.selectedBaselineControlIds.clear(); state.baselinePlan = null; renderGuidelineSummary(state.lastGuideline, null); }); selectActions.append(open, none); selectBody.append(selectTitle, selected, selectActions); selectStep.append(selectNumber, selectBody);
  const planStep = document.createElement('div'); const planNumber = document.createElement('b'); planNumber.textContent = '3'; const planBody = document.createElement('div'); const planTitle = document.createElement('strong'); planTitle.textContent = 'Prüfen und Paket'; const planButton = document.createElement('button'); planButton.type = 'button'; planButton.disabled = state.baselinePlanBusy || !state.selectedBaselineControlIds.size; planButton.textContent = state.baselinePlanBusy ? 'Konflikte werden geprüft …' : 'Auswahl prüfen'; planButton.addEventListener('click', checkBaselinePlan); const planHint = document.createElement('small'); planHint.textContent = 'Konflikte, Betriebsrisiken und automatisierbare Regeln'; planBody.append(planTitle, planButton, planHint); planStep.append(planNumber, planBody);
  steps.append(roleStep, selectStep, planStep); workflow.append(steps);
  if (state.baselinePlan) {
    const plan = state.baselinePlan; const result = document.createElement('div'); result.className = `baseline-plan-result ${plan.status}`; const resultHead = document.createElement('div'); const resultTitle = document.createElement('strong'); resultTitle.textContent = plan.status === 'blocked' ? 'Konflikt erkannt' : plan.status === 'review_required' ? 'Prüfung erforderlich' : 'Paket ist bereit'; const counts = document.createElement('span'); counts.textContent = `${plan.counts.controls} Einträge · ${plan.counts.actionable_rules} Regeln · ${plan.counts.manual} manuell`; resultHead.append(resultTitle, counts); const message = document.createElement('p'); message.textContent = plan.message; result.append(resultHead, message);
    const issues = [...plan.conflicts, ...plan.reviews, ...plan.manual_controls.map(item => ({ message: `${item.title}: ${item.reason}` }))]; if (issues.length) { const details = document.createElement('details'); const summary = document.createElement('summary'); summary.textContent = `${issues.length} Hinweise anzeigen`; const list = document.createElement('ul'); issues.forEach(item => { const row = document.createElement('li'); row.textContent = item.message; list.append(row); }); details.append(summary, list); result.append(details); }
    const packageActions = document.createElement('div'); packageActions.className = 'baseline-package-actions'; const confirmation = document.createElement('label'); const confirm = document.createElement('input'); confirm.type = 'checkbox'; confirm.disabled = !plan.reviews.length; confirm.checked = !plan.reviews.length; const confirmText = document.createElement('span'); confirmText.textContent = plan.reviews.length ? 'Rollenabhängige Hinweise geprüft' : 'Keine zusätzliche Bestätigung nötig'; confirmation.append(confirm, confirmText); const download = document.createElement('button'); download.type = 'button'; download.disabled = plan.status === 'blocked' || !plan.counts.actionable_rules; download.textContent = 'Paket herunterladen'; download.addEventListener('click', () => createBaselinePackage(download, 'download', confirm.checked)); const stage = document.createElement('button'); stage.type = 'button'; stage.className = 'secondary'; stage.disabled = download.disabled; stage.textContent = 'Nach /tmp übertragen'; stage.addEventListener('click', () => createBaselinePackage(stage, 'stage', confirm.checked)); packageActions.append(confirmation, download, stage); result.append(packageActions); workflow.append(result);
  }
  panel.append(workflow);
}

async function checkBaselinePlan() {
  if (state.baselinePlanBusy || !state.selectedBaselineControlIds.size) return;
  state.baselinePlanBusy = true; state.baselinePlan = null; renderGuidelineSummary(state.lastGuideline, null);
  try { state.baselinePlan = await api('/api/general-baseline/plan', { method: 'POST', body: JSON.stringify({ target: document.getElementById('build-target').value, role: state.baselineRole, control_ids: Array.from(state.selectedBaselineControlIds) }) }); activity(`Baseline-Plan geprüft: ${state.baselinePlan.counts.actionable_rules} ausführbare Regeln`, state.baselinePlan.status === 'blocked' ? 'error' : 'success'); }
  catch (error) { activity(error.message, 'error'); toast(error.message); }
  finally { state.baselinePlanBusy = false; renderGuidelineSummary(state.lastGuideline, null); }
}

async function createBaselinePackage(button, delivery, confirmReviews) {
  const plan = state.baselinePlan; if (!plan) return;
  if (plan.reviews.length && !confirmReviews) { toast('Rollenabhängige Hinweise zuerst bestätigen'); return; }
  if (!window.confirm(`Gemeinsames Hardening-Paket für ${plan.counts.actionable_rules} geprüfte Regeln erstellen?\n\nApply erstellt zuerst eine Dateisicherung. Für produktive Systeme bleibt ein Snapshot erforderlich.`)) return;
  button.disabled = true; activity('Ausgewählte Regeln werden erneut geprüft und das Paket wird erstellt');
  try {
    const result = await api('/api/general-baseline/package', { method: 'POST', body: JSON.stringify({ target: document.getElementById('build-target').value, role: state.baselineRole, control_ids: Array.from(state.selectedBaselineControlIds), confirm_generation: true, confirm_reviews: confirmReviews, delivery }) });
    if (result.status === 'privilege_required') { activity('Für die erneute OpenSCAP-Prüfung sind Root-Rechte erforderlich', 'error'); toast('Root-Berechtigung erforderlich'); return; }
    result.warnings.forEach(warning => activity(warning, 'error'));
    if (result.status === 'staged') { activity(`Paket bereit: ${result.directory}`, 'success'); activity(`Apply: ${result.apply_command}`, 'success'); activity(`Verify: ${result.verify_command}`, 'success'); activity(`Restore: ${result.restore_command}`, 'success'); window.prompt('Paket wurde noch nicht ausgeführt. Apply-Befehl:', result.apply_command); toast('Paket nach /tmp übertragen'); return; }
    const blob = await api(`/api/download/${result.download_id}`); const url = URL.createObjectURL(blob); const link = document.createElement('a'); link.href = url; link.download = result.filename; link.click(); URL.revokeObjectURL(url); activity(`Hardening-Paket für ${result.controls} Einträge erstellt`, 'success'); toast('Apply-, Verify- und Restore-Paket heruntergeladen');
  } catch (error) { activity(error.message, 'error'); toast(error.message); }
  finally { button.disabled = false; }
}

function appendSetupList(container, titleText, values) {
  if (!values?.length) return;
  const block = document.createElement('div'); block.className = 'baseline-setup-block';
  const title = document.createElement('strong'); title.textContent = titleText;
  const list = document.createElement('ul'); values.forEach(value => { const item = document.createElement('li'); item.textContent = value; list.append(item); });
  block.append(title, list); container.append(block);
}

function renderBaselineSetup(card, control, failedRules) {
  const running = state.baselineSetupJobs.has(control.id);
  const setup = state.baselineSetups.get(control.id);
  const actions = document.createElement('div'); actions.className = 'baseline-control-actions';
  const mode = document.createElement('span'); mode.textContent = control.failed_rule_ids.length ? `${control.failed_rule_ids.length} OpenSCAP-Regeln verfügbar` : 'Planungs- und Prüfentwurf';
  const button = document.createElement('button'); button.type = 'button'; button.className = 'secondary'; button.disabled = running; button.textContent = running ? 'Qwen erstellt Setup …' : setup?.status === 'completed' ? 'KI-Setup neu erstellen' : 'KI-Setup erstellen'; button.addEventListener('click', () => startBaselineSetup(control.id));
  actions.append(mode, button); card.append(actions);
  if (!setup) return;
  if (setup.status === 'failed') { const error = document.createElement('p'); error.className = 'baseline-setup-error'; error.textContent = setup.error; card.append(error); return; }
  const panel = document.createElement('details'); panel.className = 'baseline-ai-setup'; panel.open = true;
  const summary = document.createElement('summary'); const labels = { apply: 'Anwenden empfohlen', review: 'Betreiberprüfung', keep: 'Beibehalten', not_recommended: 'Nicht empfohlen' }; summary.textContent = `KI-Setup · ${labels[setup.recommendation] || setup.recommendation}`; panel.append(summary);
  const intro = document.createElement('p'); intro.textContent = setup.summary; panel.append(intro);
  if (setup.settings.length) { const settings = document.createElement('div'); settings.className = 'baseline-setup-settings'; setup.settings.forEach(item => { const row = document.createElement('div'); const name = document.createElement('strong'); name.textContent = item.name; const value = document.createElement('code'); value.textContent = item.value; const reason = document.createElement('span'); reason.textContent = item.reason; row.append(name, value, reason); settings.append(row); }); panel.append(settings); }
  appendSetupList(panel, 'Voraussetzungen', setup.prerequisites);
  if (setup.operational_impact) { const impact = document.createElement('p'); impact.className = 'baseline-setup-impact'; impact.textContent = `Betriebswirkung: ${setup.operational_impact}`; panel.append(impact); }
  appendSetupList(panel, 'Prüfung danach', setup.validation_steps);
  appendSetupList(panel, 'Rücknahme', setup.rollback_steps);
  appendSetupList(panel, 'Warnungen', setup.warnings);
  const guardrail = document.createElement('small'); guardrail.textContent = `${setup.model} · ${setup.guardrail}`; panel.append(guardrail);
  if (setup.implementation_mode === 'openscap' && setup.rule_ids.length) { const select = document.createElement('button'); select.type = 'button'; select.textContent = 'Geprüfte Regeln in Hardening-Auswahl übernehmen'; select.addEventListener('click', () => { const available = new Set(failedRules.map(item => item.id)); setup.rule_ids.filter(id => available.has(id)).forEach(id => state.selectedPolicyRuleIds.add(id)); renderGuidelineSummary(state.lastGuideline, null); toast('OpenSCAP-Regeln übernommen – Auswahl vor dem Export prüfen'); }); panel.append(select); }
  card.append(panel);
}

async function startBaselineSetup(controlId) {
  if (state.baselineSetupJobs.has(controlId)) return;
  try {
    const started = await api('/api/general-baseline/setup', { method: 'POST', body: JSON.stringify({ target: document.getElementById('build-target').value, control_id: controlId }) });
    state.baselineSetupJobs.set(controlId, started.job_id); renderGuidelineSummary(state.lastGuideline, null); activity(`${started.model} erstellt das Setup für ${controlId}`);
    while (state.baselineSetupJobs.get(controlId) === started.job_id) { await new Promise(resolve => window.setTimeout(resolve, 2000)); const payload = await api(`/api/recommendations/${encodeURIComponent(started.job_id)}`); if (payload.status === 'running') continue; state.baselineSetupJobs.delete(controlId); state.baselineSetups.set(controlId, payload); renderGuidelineSummary(state.lastGuideline, null); if (payload.status === 'completed') { activity(`KI-Setup für ${controlId} abgeschlossen`, 'success'); toast('KI-Setup ist bereit'); } else { throw new Error(payload.error || 'KI-Setup fehlgeschlagen'); } }
  } catch (error) { state.baselineSetupJobs.delete(controlId); state.baselineSetups.set(controlId, { status: 'failed', error: error.message }); renderGuidelineSummary(state.lastGuideline, null); activity(error.message, 'error'); toast(error.message); }
}

async function evaluateGeneralBaseline(automatic = false) {
  if (state.baselineBusy || !state.scapResults.length) return;
  state.baselineBusy = true; renderGuidelineSummary(state.lastGuideline, null);
  try { const categories = state.generalBaselineCategories === null ? undefined : Array.from(state.generalBaselineCategories); const body = { target: document.getElementById('build-target').value, level: state.generalBaselineLevel }; if (categories !== undefined) body.categories = categories; state.generalBaseline = await api('/api/general-baseline', { method: 'POST', body: JSON.stringify(body) }); const available = new Set(state.generalBaseline.controls.map(item => item.id)); state.selectedBaselineControlIds = new Set(Array.from(state.selectedBaselineControlIds).filter(id => available.has(id))); state.baselinePlan = null; activity(`Allgemeine Linux-Baseline ${state.generalBaseline.level_info.title}: ${state.generalBaseline.controls.length} Empfehlungen ausgewertet`, 'success'); if (!automatic) toast('Allgemeine Linux-Baseline aktualisiert'); }
  catch (error) { activity(error.message, 'error'); if (!automatic) toast(error.message); }
  finally { state.baselineBusy = false; renderGuidelineSummary(state.lastGuideline, null); }
}

async function startHardeningReview(automatic = false) {
  if (state.hardeningReviewJobId || !state.scapResults.some(item => item.status === 'fail')) return;
  const target = document.getElementById('build-target').value;
  try {
    const started = await api('/api/compliance/ai-prioritize', { method: 'POST', body: JSON.stringify({ target }) });
    state.hardeningReviewJobId = started.job_id; state.aiHardeningReview = { status: 'running', model: started.model }; renderGuidelineSummary(state.lastGuideline, null); activity(`${started.model} priorisiert die fehlgeschlagenen OpenSCAP-Regeln`);
    while (state.hardeningReviewJobId === started.job_id) { await new Promise(resolve => window.setTimeout(resolve, 2000)); const payload = await api(`/api/recommendations/${encodeURIComponent(started.job_id)}`); if (payload.status === 'running') continue; state.hardeningReviewJobId = null; state.aiHardeningReview = payload; renderGuidelineSummary(state.lastGuideline, null); if (payload.status === 'completed') { activity(`KI-Priorisierung abgeschlossen; ${payload.selected_rule_ids.length} Regeln empfohlen`, 'success'); toast('Qwen-Analyse ist bereit'); } else { throw new Error(payload.error || 'KI-Hardening-Analyse fehlgeschlagen'); } }
  } catch (error) { state.hardeningReviewJobId = null; state.aiHardeningReview = { status: 'failed', error: error.message }; renderGuidelineSummary(state.lastGuideline, null); activity(error.message, 'error'); if (!automatic) toast(error.message); }
}

async function buildSelectedPolicyPackage(button, profile, dataStream, delivery = 'download') {
  const rules = Array.from(state.selectedPolicyRuleIds); if (!rules.length) { toast('Zuerst offene Regeln auswählen'); return; }
  const destination = delivery === 'stage' ? 'direkt nach /tmp des Zielsystems übertragen' : 'als ZIP herunterladen';
  if (!window.confirm(`Massnahmenpaket für ${rules.length} ausgewählte Herstellerregeln erzeugen und ${destination}?\n\nDie Regeln werden vorher nochmals geprüft. Es wird noch kein Hardening ausgeführt.`)) return;
  button.disabled = true; activity(`${rules.length} ausgewählte Herstellerregeln werden erneut geprüft`);
  try {
    const result = await api('/api/compliance/selected-remediation', { method: 'POST', body: JSON.stringify({ target: document.getElementById('build-target').value, profile, data_stream: dataStream, rule_ids: rules, confirm_generation: true, delivery }) });
    if (result.status === 'privilege_required') { activity('Für die erneute Prüfung sind Root-Leserechte erforderlich', 'error'); toast('Root-Berechtigung auf dem Ziel erforderlich'); return; }
    result.warnings.forEach(warning => activity(warning, 'error'));
    if (result.status === 'staged') {
      activity(`Hardening-Paket mit ${result.rules} Regeln bereitgestellt: ${result.directory}`, 'success');
      activity(`Ausführen: ${result.apply_command}`, 'success');
      activity(`Danach prüfen: ${result.verify_command}`, 'success');
      window.prompt('Paket wurde noch nicht ausgeführt. Diesen Befehl auf dem Ziel starten:', result.apply_command);
      toast('Paket sicher nach /tmp übertragen');
      return;
    }
    const blob = await api(`/api/download/${result.download_id}`); const url = URL.createObjectURL(blob); const link = document.createElement('a'); link.href = url; link.download = result.filename; link.click(); URL.revokeObjectURL(url);
    activity(`Auswahlpaket mit ${result.rules} Regeln erstellt`, 'success'); toast('Ausgewähltes Hardening-Paket heruntergeladen');
  }
  catch (error) { activity(error.message, 'error'); toast(error.message); }
  finally { button.disabled = false; }
}

async function buildNativePolicyPackage(button, profile, dataStream) {
  const target = document.getElementById('build-target').value; const shortProfile = profile.replace('xccdf_org.ssgproject.content_profile_', '');
  if (!window.confirm(`Vollständiges OpenSCAP-Massnahmenpaket für „${shortProfile}“ erzeugen?\n\nDas Paket kann Anmeldung, Netzwerk, Boot, Dienste und Dateisysteme ändern. Es wird nur erzeugt und heruntergeladen, noch nicht ausgeführt.`)) return;
  button.disabled = true; activity(`Vollständiges Policy-Paket ${shortProfile} wird erzeugt`);
  try { const result = await api('/api/compliance/remediation', { method: 'POST', body: JSON.stringify({ target, profile, data_stream: dataStream, confirm_generation: true }) }); const blob = await api(`/api/download/${result.download_id}`); const url = URL.createObjectURL(blob); const link = document.createElement('a'); link.href = url; link.download = result.filename; link.click(); URL.revokeObjectURL(url); result.warnings.forEach(warning => activity(warning, 'error')); activity(`Vollständiges OpenSCAP-Paket ${result.filename} erstellt`, 'success'); toast('Policy-Paket heruntergeladen – vor Anwendung vollständig prüfen'); }
  catch (error) { activity(error.message, 'error'); toast(error.message); }
  finally { button.disabled = false; }
}

async function installComplianceScanner(button, plan) {
  const target = document.getElementById('build-target').value;
  const packages = plan.packages.join(', ');
  if (!window.confirm(`OpenSCAP auf „${target}“ installieren?\n\nPakete: ${packages}\n\nEs wird noch kein Hardening ausgeführt.`)) return;
  button.disabled = true; activity(`OpenSCAP-Installation auf ${target} gestartet`);
  try {
    const payload = await api('/api/compliance/install', { method: 'POST', body: JSON.stringify({ target, confirm_install: true }) });
    if (payload.status === 'privilege_required') {
      const container = document.getElementById('guideline-summary');
      const notice = document.createElement('div'); notice.className = 'scanner-command';
      const text = document.createElement('strong'); text.textContent = 'Interaktive Root-Berechtigung erforderlich';
      const hint = document.createElement('p'); hint.textContent = 'Diesen Befehl direkt auf dem Zielsystem ausführen und danach die Prüfung erneut starten:';
      const command = document.createElement('code'); command.textContent = payload.command;
      const copy = document.createElement('button'); copy.type = 'button'; copy.className = 'secondary'; copy.textContent = 'Befehl kopieren'; copy.addEventListener('click', async () => { await navigator.clipboard.writeText(payload.command); toast('Installationsbefehl kopiert'); });
      notice.append(text, hint, command, copy); container.prepend(notice);
      activity('Automatische Installation benötigt sudo ohne Passwort; Befehl wird angezeigt', 'error'); toast('Root-Berechtigung auf dem Ziel erforderlich');
      return;
    }
    const alreadyAvailable = payload.status === 'already_available';
    activity(alreadyAvailable ? `OpenSCAP ist auf ${target} bereits verfügbar` : `OpenSCAP auf ${target} erfolgreich installiert`, 'success');
    toast(alreadyAvailable ? 'OpenSCAP ist bereits verfügbar' : 'OpenSCAP wurde erfolgreich installiert');
    if (payload.guideline) renderGuidelineSummary(payload.guideline, null);
    if (payload.refresh_required) {
      activity('Installation abgeschlossen; SCAP-Datenströme werden jetzt neu eingelesen');
      window.setTimeout(() => loadApplicableControls(), 0);
    }
  } catch (error) { activity(error.message, 'error'); toast(error.message); }
  finally { button.disabled = false; }
}

async function runComplianceScan(button, profile, dataStream) {
  const target = document.getElementById('build-target').value;
  button.disabled = true; activity(`OpenSCAP-Profil ${profile.replace('xccdf_org.ssgproject.content_profile_', '')} auf ${target} gestartet`);
  try {
    const payload = await api('/api/compliance/scan', { method: 'POST', body: JSON.stringify({ target, profile, data_stream: dataStream }) });
    if (payload.status === 'privilege_required') {
      const notice = document.createElement('div'); notice.className = 'scanner-command'; const title = document.createElement('strong'); title.textContent = 'OpenSCAP benötigt Root-Leserechte'; const hint = document.createElement('p'); hint.textContent = 'Befehl auf dem Ziel ausführen oder passwortloses sudo für den Scan bereitstellen:'; const command = document.createElement('code'); command.textContent = payload.command; notice.append(title, hint, command); document.getElementById('guideline-summary').prepend(notice); activity('OpenSCAP benötigt Root-Leserechte auf dem Ziel', 'error'); return;
    }
    state.scapResults = payload.results; state.selectedPolicyRuleIds.clear(); state.selectedAuditRuleIds.clear(); renderGuidelineSummary(payload.guideline, null); renderReport(document.getElementById('report-filter').value);
    const failed = payload.counts.fail || 0; activity(`OpenSCAP abgeschlossen: ${payload.results.length} Regeln, ${failed} nicht bestanden`, failed ? 'error' : 'success'); toast('OpenSCAP-Ergebnisse wurden in den Bericht integriert');
  } catch (error) { activity(error.message, 'error'); toast(error.message); button.disabled = false; }
}

function addTextBlock(parent, title, text) {
  const block = document.createElement('div'); block.className = 'detail-block';
  const heading = document.createElement('h4'); heading.textContent = title;
  const content = document.createElement('pre'); content.textContent = text || 'Nicht angegeben';
  block.append(heading, content); parent.append(block);
}

function renderReport() {
  const container = document.getElementById('report-list'); container.replaceChildren();
  const documents = state.lastGuideline?.documents || [];
  const baselineControls = state.generalBaseline?.controls || [];
  const normalizeStatus = status => status === 'notapplicable' ? 'not_applicable' : status;
  const entries = [
    ...state.scapResults.map(rule => ({
      kind: 'scap', status: normalizeStatus(rule.status), category: rule.topic || 'other',
      categoryTitle: categoryNames[rule.topic] || rule.topic || 'Weitere Herstellerregeln',
      selected: state.selectedPolicyRuleIds.has(rule.id), rule,
      sources: documents,
      sourceText: documents.length ? `manufacturer ${documents.map(source => `${source.id || ''} ${source.publisher || ''} ${source.title || ''}`).join(' ')}`.toLowerCase() : '',
      searchText: `${rule.short_id || ''} ${rule.id || ''} ${rule.title || ''} ${rule.topic || ''} ${documents.map(source => `${source.title || ''} ${source.scope || ''}`).join(' ')}`.toLowerCase()
    })),
    ...baselineControls.map(control => ({
      kind: 'baseline', status: control.status, category: control.category,
      categoryTitle: control.category_title, control,
      selected: (control.matched_rule_ids || []).some(id => state.selectedPolicyRuleIds.has(id)),
      sources: control.sources || [],
      sourceText: (control.sources || []).map(source => `${source.id || ''} ${source.publisher || ''} ${source.title || ''}`).join(' ').toLowerCase(),
      searchText: `${control.id || ''} ${control.title || ''} ${control.rationale || ''} ${control.category_title || ''} ${(control.sources || []).map(source => `${source.id || ''} ${source.title || ''}`).join(' ')} ${(control.matched_rules || []).map(rule => `${rule.short_id || ''} ${rule.title || ''}`).join(' ')}`.toLowerCase()
    }))
  ];
  const categorySelect = document.getElementById('report-category'); const previousCategory = categorySelect.value || 'all'; categorySelect.replaceChildren(); const allCategories = document.createElement('option'); allCategories.value = 'all'; allCategories.textContent = 'Alle Kategorien'; categorySelect.append(allCategories); const categories = new Map(); entries.forEach(entry => categories.set(entry.category, entry.categoryTitle)); [...categories.entries()].sort((left, right) => left[1].localeCompare(right[1], 'de')).forEach(([value, label]) => { const option = document.createElement('option'); option.value = value; option.textContent = label; categorySelect.append(option); }); categorySelect.value = categories.has(previousCategory) ? previousCategory : 'all';
  const filters = {
    needle: document.getElementById('report-filter').value.trim().toLowerCase(),
    kind: document.getElementById('report-kind').value,
    status: document.getElementById('report-status').value,
    category: categorySelect.value,
    source: document.getElementById('report-source').value,
    selection: document.getElementById('report-selection').value
  };
  const visible = entries.filter(entry => {
    if (filters.needle && !entry.searchText.includes(filters.needle)) return false;
    if (filters.kind !== 'all' && entry.kind !== filters.kind) return false;
    if (filters.status !== 'all' && entry.status !== filters.status) return false;
    if (filters.category !== 'all' && entry.category !== filters.category) return false;
    if (filters.source !== 'all' && !entry.sourceText.includes(filters.source)) return false;
    if (filters.selection === 'selected' && !entry.selected) return false;
    if (filters.selection === 'unselected' && entry.selected) return false;
    return true;
  });
  document.getElementById('report-visible-count').textContent = `${visible.length} von ${entries.length} Einträgen`;
  document.getElementById('report-context').textContent = entries.length
    ? `${state.reportPlatform || 'Linux'}: ${state.scapResults.length} OpenSCAP-Regeln und ${baselineControls.length} allgemeine Baseline-Empfehlungen.`
    : 'Nach einem vollständigen OpenSCAP-Scan erscheinen hier alle Ergebnisse und offiziellen Referenzen.';
  renderReportSummary();
  if (!entries.length) { const empty = document.createElement('div'); empty.className = 'control-placeholder'; empty.textContent = 'Noch kein Prüfbericht vorhanden. Zuerst den Full Scan starten.'; container.append(empty); return; }
  const overview = document.createElement('div'); overview.className = 'report-overview'; const overviewText = document.createElement('strong'); overviewText.textContent = `${visible.length} sichtbare von ${entries.length} Berichtseinträgen`; const download = document.createElement('button'); download.type = 'button'; download.className = 'secondary'; download.textContent = 'Prüfbericht herunterladen'; download.addEventListener('click', () => downloadPolicyReport(download)); overview.append(overviewText, download); container.append(overview);
  const statusLabels = { pass: 'Bestanden', fail: 'Nicht bestanden', not_applicable: 'Nicht anwendbar', manual: 'Manuell', not_covered: 'Nicht abgedeckt', technical_gap: 'Technische Lücke', notchecked: 'Nicht geprüft', notselected: 'Nicht ausgewählt', error: 'Fehler' };
  const scapEntries = visible.filter(entry => entry.kind === 'scap');
  if (scapEntries.length) {
    const heading = document.createElement('div'); heading.className = 'report-section-heading'; const title = document.createElement('strong'); title.textContent = 'Vollständiger OpenSCAP-Benchmark'; const detail = document.createElement('span'); detail.textContent = `${scapEntries.length} Regeln`; heading.append(title, detail); container.append(heading);
    scapEntries.forEach(entry => { const rule = entry.rule; const item = document.createElement('article'); item.className = 'report-item scap-report-item'; const head = document.createElement('div'); head.className = 'report-head'; const identity = document.createElement('div'); const id = document.createElement('code'); id.textContent = rule.short_id; const titleNode = document.createElement('h3'); titleNode.textContent = rule.title; identity.append(id, titleNode); const status = document.createElement('span'); status.className = `check-result ${entry.status === 'pass' ? 'passed' : entry.status === 'fail' ? 'failed' : entry.status === 'not_applicable' ? 'manual' : 'error'}`; status.textContent = statusLabels[entry.status] || entry.status; head.append(identity, status); item.append(head); const config = document.createElement('div'); config.className = 'report-config'; addTextBlock(config, 'Prüfergebnis', statusLabels[entry.status] || entry.status); addTextBlock(config, 'Kategorie', entry.categoryTitle); addTextBlock(config, 'Maßnahme ausgewählt', entry.selected ? 'Ja' : 'Nein'); item.append(config); if (documents.length) { const sources = document.createElement('div'); sources.className = 'report-sources'; documents.forEach(source => { const sourceEntry = document.createElement('div'); const link = document.createElement('a'); link.href = source.url; link.target = '_blank'; link.rel = 'noopener noreferrer'; link.textContent = source.title; const scope = document.createElement('span'); scope.textContent = source.scope; sourceEntry.append(link, scope); sources.append(sourceEntry); }); item.append(sources); } container.append(item); });
  }
  const baselineEntries = visible.filter(entry => entry.kind === 'baseline');
  if (baselineEntries.length) {
    const heading = document.createElement('div'); heading.className = 'report-section-heading baseline-heading'; const title = document.createElement('strong'); title.textContent = 'Allgemeines Linux-Hardening'; const detail = document.createElement('span'); detail.textContent = `${baselineEntries.length} Empfehlungen · ${state.generalBaseline.level_info?.title || state.generalBaseline.level}`; heading.append(title, detail); container.append(heading);
    baselineEntries.forEach(entry => { const control = entry.control; const item = document.createElement('article'); item.className = `report-item baseline-report-item ${entry.status}`; const head = document.createElement('div'); head.className = 'report-head'; const identity = document.createElement('div'); const id = document.createElement('code'); id.textContent = control.id; const titleNode = document.createElement('h3'); titleNode.textContent = control.title; identity.append(id, titleNode); const status = document.createElement('span'); status.className = `baseline-status ${entry.status}`; status.textContent = statusLabels[entry.status] || entry.status; head.append(identity, status); item.append(head); const rationale = document.createElement('p'); rationale.className = 'baseline-report-rationale'; rationale.textContent = control.rationale; item.append(rationale); const config = document.createElement('div'); config.className = 'report-config'; addTextBlock(config, 'Kategorie', control.category_title); addTextBlock(config, 'Niveau', control.level); addTextBlock(config, 'Zugeordnete SCAP-Regeln', (control.matched_rules || []).map(rule => rule.short_id || rule.id).join('\n') || 'Keine technische Zuordnung'); item.append(config); if (control.manual) { const manual = document.createElement('div'); manual.className = 'report-manual-note'; manual.textContent = `Manuelle Ergänzung: ${control.manual}`; item.append(manual); } if (entry.sources.length) { const sources = document.createElement('div'); sources.className = 'report-sources'; entry.sources.forEach(source => { const sourceEntry = document.createElement('div'); const link = document.createElement('a'); link.href = source.url; link.target = '_blank'; link.rel = 'noopener noreferrer'; link.textContent = `${source.id} · ${source.title}`; const scope = document.createElement('span'); scope.textContent = source.scope; sourceEntry.append(link, scope); sources.append(sourceEntry); }); item.append(sources); } container.append(item); });
  }
  if (!visible.length) { const empty = document.createElement('div'); empty.className = 'control-placeholder'; empty.textContent = 'Keine Berichtseinträge entsprechen den gewählten Filtern.'; container.append(empty); }
}

function renderReportSummary() {
  const container = document.getElementById('report-summary'); container.replaceChildren();
  const scan = state.lastGuideline?.scap_scan;
  const addSummary = (kind, label, titleText, detail, counts, actionText = '') => {
    const card = document.createElement('article'); card.className = `report-summary-card ${kind}`;
    const labelNode = document.createElement('span'); labelNode.textContent = label;
    const title = document.createElement('strong'); title.textContent = titleText;
    const description = document.createElement('p'); description.textContent = detail;
    const countLine = document.createElement('small'); countLine.textContent = counts;
    card.append(labelNode, title, description, countLine);
    if (actionText && scan) { const button = document.createElement('button'); button.type = 'button'; button.className = 'secondary'; button.textContent = actionText; button.addEventListener('click', () => downloadPolicyReport(button)); card.append(button); }
    container.append(card);
  };
  if (scan && state.scapResults.length) {
    const counts = scan.counts || {}; const stream = String(scan.data_stream || '').split('/').pop() || 'Datenstrom unbekannt'; const profile = String(scan.profile || '').replace('xccdf_org.ssgproject.content_profile_', '') || 'Vollprofil';
    addSummary('benchmark', 'OFFIZIELLER HERSTELLER-BENCHMARK', `${state.scapResults.length} SCAP-Regeln`, `${stream} · Profil ${profile}`, `${counts.pass || 0} bestanden · ${counts.fail || 0} offen · ${counts.notapplicable || 0} nicht anwendbar · ${(counts.notselected || 0) + (counts.notchecked || 0)} Abdeckungslücken`, 'Benchmark-Bericht herunterladen');
  } else {
    addSummary('benchmark empty', 'OFFIZIELLER HERSTELLER-BENCHMARK', 'Noch kein Bericht', 'Zuerst unter Hardening den Full Scan ausführen.', 'Keine Benchmark-Ergebnisse vorhanden');
  }
  if (state.generalBaseline) {
    const counts = state.generalBaseline.counts || {}; const level = state.generalBaseline.level_info?.title || state.generalBaseline.level;
    addSummary('baseline', 'ALLGEMEINES LINUX-HARDENING', `${state.generalBaseline.controls.length} Empfehlungen`, `Separate Einordnung · Niveau ${level}`, `${counts.pass || 0} bestanden · ${counts.fail || 0} offen · ${(counts.manual || 0) + (counts.not_covered || 0) + (counts.technical_gap || 0)} manuell oder nicht abgedeckt`);
  } else {
    addSummary('baseline empty', 'ALLGEMEINES LINUX-HARDENING', 'Noch keine Einordnung', 'Wird nach einem erfolgreichen Full Scan separat ausgewertet.', 'Keine Baseline-Ergebnisse vorhanden');
  }
}

async function downloadPolicyReport(button) {
  button.disabled = true;
  try {
    const scan = state.lastGuideline?.scap_scan;
    if (!scan) throw new Error('Zuerst einen vollständigen OpenSCAP-Scan ausführen');
    const result = await api('/api/compliance/report-package', { method: 'POST', body: JSON.stringify({
      target: document.getElementById('build-target').value,
      profile: scan.profile,
      data_stream: scan.data_stream,
      selected_rule_ids: Array.from(state.selectedPolicyRuleIds)
    }) });
    const blob = await api(`/api/download/${result.download_id}`); const url = URL.createObjectURL(blob);
    const link = document.createElement('a'); link.href = url; link.download = result.filename; link.click(); URL.revokeObjectURL(url);
    toast('Prüfbericht heruntergeladen');
  } catch (error) { toast(error.message); }
  finally { button.disabled = false; }
}

async function loadApplicableControls() {
  const button = document.getElementById('load-controls'); button.disabled = true;
  activity('Systemerkennung und Ermittlung des SCAP-Benchmarks gestartet');
  try {
    const payload = await api('/api/guidelines', { method: 'POST', body: JSON.stringify({
      target: document.getElementById('build-target').value
    }) });
    if (payload.connection_refreshed) { await loadTargets(); activity('Vagrant-SSH-Zugang automatisch aktualisiert', 'success'); }
    state.selectedPolicyRuleIds.clear(); state.selectedAuditRuleIds.clear(); state.scapResults = [];
    state.reportPlatform = payload.guideline.platform.pretty_name;
    renderGuidelineSummary(payload.guideline, null);
    const scanner = payload.guideline.native_scanner; const count = scanner.data_streams.reduce((sum, item) => sum + (item.rules || 0), 0);
    activity(`${payload.guideline.platform.pretty_name}: ${count || '?'} maschinenlesbare Benchmark-Regeln erkannt`, scanner.ready ? 'success' : 'error');
    payload.warnings.forEach(warning => activity(warning, warning.includes('used QEMU Guest Agent') ? 'success' : 'error'));
    toast('SCAP-Benchmark geladen – jetzt Full Scan starten');
  } catch (error) { activity(error.message, 'error'); toast(error.message); }
  finally { button.disabled = false; }
}

function renderVulnerabilityResults(container, vulnerabilities) {
  const results = vulnerabilities.results || [];
  const section = document.createElement('section'); section.className = 'vulnerability-results';
  const heading = document.createElement('div'); heading.className = 'vulnerability-results-head';
  const identity = document.createElement('div'); const title = document.createElement('strong'); title.textContent = 'OVAL-Schwachstellenresultate';
  const feed = vulnerabilities.feed || {}; const source = document.createElement('p'); source.textContent = feed.title ? `${feed.title} · Stand ${feed.fetched_at || 'unbekannt'}` : (vulnerabilities.message || 'Kein passender OVAL-Feed verfügbar'); identity.append(title, source);
  const filter = document.createElement('select'); filter.setAttribute('aria-label', 'Schwachstellen filtern');
  [['affected', 'Nur betroffen'], ['unclear', 'Unklar oder Fehler'], ['all', 'Alle Resultate'], ['not_affected', 'Nicht betroffen']].forEach(([value, label]) => { const option = document.createElement('option'); option.value = value; option.textContent = label; filter.append(option); });
  const affectedCount = results.filter(item => item.status === 'affected').length; const unclearCount = results.filter(item => ['unknown', 'error'].includes(item.status)).length;
  filter.value = affectedCount ? 'affected' : unclearCount ? 'unclear' : 'all'; heading.append(identity, filter); section.append(heading);
  if (feed.url) { const link = document.createElement('a'); link.className = 'vulnerability-feed-link'; link.href = feed.url; link.target = '_blank'; link.rel = 'noopener noreferrer'; link.textContent = 'Offiziellen OVAL-Feed öffnen'; section.append(link); }
  const summary = document.createElement('p'); summary.className = 'vulnerability-list-summary'; section.append(summary);
  const list = document.createElement('div'); list.className = 'vulnerability-result-list'; section.append(list);
  const render = () => {
    list.replaceChildren();
    const visible = results.filter(item => filter.value === 'all' || item.status === filter.value || (filter.value === 'unclear' && ['unknown', 'error'].includes(item.status)));
    summary.textContent = `${visible.length} von ${results.length} Definitionen · maximal 250 gleichzeitig angezeigt`;
    visible.slice(0, 250).forEach(finding => {
      const row = document.createElement('article'); row.className = `vulnerability-row ${finding.status || 'unknown'}`;
      const body = document.createElement('div'); const name = document.createElement('strong'); name.textContent = finding.title || finding.definition_id;
      const meta = document.createElement('span'); const references = (finding.references || []).join(', '); meta.textContent = `${finding.severity || 'Schweregrad unbekannt'} · ${references || finding.definition_id}`;
      const id = document.createElement('code'); id.textContent = finding.definition_id; body.append(name, meta, id);
      const status = document.createElement('b'); const labels = { affected: 'BETROFFEN', not_affected: 'NICHT BETROFFEN', unknown: 'UNKLAR', error: 'FEHLER' }; status.textContent = labels[finding.status] || String(finding.status || 'UNKLAR').toUpperCase();
      row.append(body, status); list.append(row);
    });
    if (!visible.length) { const empty = document.createElement('p'); empty.className = 'vulnerability-empty'; empty.textContent = filter.value === 'affected' ? 'Keine betroffene OVAL-Definition gefunden.' : 'Keine Resultate für diesen Filter.'; list.append(empty); }
  };
  filter.addEventListener('change', render); render(); container.append(section);
}

function renderFullScanResult(payload) {
  const report = payload.report; const engines = report.engines; const container = document.getElementById('full-scan-results'); container.replaceChildren();
  const card = (title, engine, detail) => { const item = document.createElement('article'); const heading = document.createElement('strong'); heading.textContent = title; const status = document.createElement('span'); status.className = `scan-engine-status ${engine.status}`; status.textContent = engine.status; const text = document.createElement('p'); text.textContent = detail; item.append(heading, status, text); container.append(item); };
  const configuration = engines.configuration || {}; const cc = configuration.counts || {};
  const configurationDisplay = configuration.coverage_status === 'partial' ? { ...configuration, status: 'partial' } : configuration;
  card('Vollständiger Konfigurations-Benchmark', configurationDisplay, configuration.message || `${cc.pass || 0} bestanden · ${cc.fail || 0} nicht bestanden · ${cc.notapplicable || 0} nicht anwendbar · ${cc.notselected || 0} nicht ausgewählt · ${cc.notchecked || 0} nicht geprüft · ${configuration.supplemental_rules || 0} Zusatzregeln bewertet`);
  const vulnerabilities = engines.vulnerabilities || {}; const vc = vulnerabilities.counts || {};
  card('Schwachstellen und Patches', vulnerabilities, vulnerabilities.message || `${vc.affected || 0} betroffen · ${vc.not_affected || 0} nicht betroffen · ${(vc.unknown || 0) + (vc.error || 0)} unklar`);
  state.vulnerabilityResults = vulnerabilities.results || [];
  renderVulnerabilityResults(container, vulnerabilities);
}

async function startFullScan() {
  const button = document.getElementById('full-scan');
  if (state.fullScanJobId) return;
  const streamSelect = document.querySelector('#scap-stream-select');
  button.disabled = true; document.getElementById('full-scan-results').replaceChildren();
  document.getElementById('full-scan-badge').textContent = 'Läuft'; document.getElementById('full-scan-stage').textContent = 'Full Scan wird gestartet …';
  try {
    const started = await api('/api/full-scan', { method: 'POST', body: JSON.stringify({ target: document.getElementById('build-target').value, data_stream: streamSelect?.value || '', include_configuration: document.getElementById('scan-configuration').checked, include_vulnerabilities: document.getElementById('scan-vulnerabilities').checked }) });
    state.fullScanJobId = started.job_id; activity('Full Scan im Hintergrund gestartet');
    while (state.fullScanJobId === started.job_id) {
      await new Promise(resolve => window.setTimeout(resolve, 2000));
      const payload = await api(`/api/full-scan/${encodeURIComponent(started.job_id)}`);
      document.getElementById('full-scan-progress').style.width = `${payload.percent || 0}%`; document.getElementById('full-scan-stage').textContent = payload.stage || 'Prüfung läuft';
      if (payload.status === 'running') continue;
      state.fullScanJobId = null;
      if (payload.status === 'completed') {
        document.getElementById('full-scan-badge').textContent = 'Abgeschlossen';
        const configuration = payload.report.engines.configuration || {};
        if (configuration.status === 'completed') {
          state.scapResults = configuration.results || [];
          state.selectedPolicyRuleIds.clear(); state.selectedAuditRuleIds.clear();
          state.aiHardeningReview = null; state.generalBaseline = null; state.baselineSetups.clear(); state.baselineSetupJobs.clear(); state.selectedBaselineControlIds.clear(); state.baselinePlan = null;
          if (payload.report.guideline) { state.lastGuideline = payload.report.guideline; renderGuidelineSummary(state.lastGuideline, null); }
          renderReport(document.getElementById('report-filter').value);
        }
        renderFullScanResult(payload);
        (payload.report.warnings || []).forEach(warning => activity(warning, 'error'));
        activity(`Full Scan abgeschlossen; Bericht: ${payload.report_path}`, 'success');
        toast(configuration.coverage_status === 'partial' ? 'Scan abgeschlossen – nicht auswertbare Regeln sind ausgewiesen' : 'Scan vollständig abgeschlossen');
        if (configuration.status === 'completed') await evaluateGeneralBaseline(true);
        if (configuration.status === 'completed' && state.scapResults.some(item => item.status === 'fail')) startHardeningReview(true);
      }
      else { throw new Error(payload.error || 'Full Scan fehlgeschlagen'); }
    }
  } catch (error) { state.fullScanJobId = null; document.getElementById('full-scan-badge').textContent = 'Fehler'; document.getElementById('full-scan-stage').textContent = error.message; activity(error.message, 'error'); toast(error.message); }
  finally { button.disabled = false; }
}

document.querySelectorAll('.nav').forEach(button => button.addEventListener('click', () => {
  document.querySelectorAll('.nav, .view').forEach(element => element.classList.remove('active'));
  button.classList.add('active'); document.getElementById(button.dataset.view).classList.add('active');
  document.getElementById('page-title').textContent = button.querySelector('span:last-child').textContent;
  if (button.dataset.view === 'report') renderReport();
}));

document.querySelectorAll('.jump').forEach(button => button.addEventListener('click', () => {
  document.querySelector(`.nav[data-view="${button.dataset.jump}"]`).click();
}));

document.getElementById('refresh').addEventListener('click', () => Promise.all([loadStatus(), loadVMs(), loadTargets()]));
document.getElementById('refresh-vms').addEventListener('click', loadVMs);
document.getElementById('report-filter').addEventListener('input', renderReport);
['report-kind', 'report-status', 'report-category', 'report-source', 'report-selection'].forEach(id => document.getElementById(id).addEventListener('change', renderReport));
document.getElementById('report-reset').addEventListener('click', () => { document.getElementById('report-filter').value = ''; document.getElementById('report-kind').value = 'all'; document.getElementById('report-status').value = 'all'; document.getElementById('report-category').value = 'all'; document.getElementById('report-source').value = 'all'; document.getElementById('report-selection').value = 'all'; renderReport(); });
document.getElementById('cancel-source-edit').addEventListener('click', resetGuidelineSourceForm);
document.getElementById('review-guideline-sources').addEventListener('click', reviewGuidelineSources);
document.getElementById('discover-guideline-sources').addEventListener('click', discoverGuidelineSources);
document.getElementById('guideline-source-form').addEventListener('submit', async event => {
  event.preventDefault(); const form = event.currentTarget; setBusy(form, true);
  const source = {
    id: document.getElementById('source-id').value,
    publisher: document.getElementById('source-publisher').value,
    title: document.getElementById('source-title').value,
    url: document.getElementById('source-url').value,
    distribution: document.getElementById('source-distribution').value,
    version_pattern: document.getElementById('source-version').value,
    reviewed: document.getElementById('source-reviewed').value,
    enabled: document.getElementById('source-enabled').checked,
    scope: document.getElementById('source-scope').value,
    categories: [...state.editingSourceCategories]
  };
  try {
    await api('/api/guideline-sources', { method: 'POST', body: JSON.stringify({ source, original_id: document.getElementById('source-original-id').value }) });
    await loadGuidelineSources(); resetGuidelineSourceForm(); state.lastGuideline = null; state.scapResults = []; state.selectedPolicyRuleIds.clear(); toast('Herstellerquelle gespeichert');
  } catch (error) { toast(error.message); }
  finally { setBusy(form, false); }
});
document.getElementById('load-controls').addEventListener('click', loadApplicableControls);
document.getElementById('full-scan').addEventListener('click', startFullScan);
document.getElementById('build-target').addEventListener('change', () => { state.lastGuideline = null; state.scapResults = []; state.generalBaseline = null; state.generalBaselineCategories = null; state.baselineSetups.clear(); state.baselineSetupJobs.clear(); state.selectedBaselineControlIds.clear(); state.baselinePlan = null; state.selectedPolicyRuleIds.clear(); state.selectedAuditRuleIds.clear(); renderReport(); });

function updateTargetMode() {
  const local = document.getElementById('target-mode-local').checked;
  document.querySelectorAll('.ssh-field input').forEach(input => { input.disabled = local; });
  document.getElementById('target-host').required = !local;
}

document.querySelectorAll('input[name="target-mode"]').forEach(input => input.addEventListener('change', updateTargetMode));
document.getElementById('cancel-target-edit').addEventListener('click', cancelTargetEdit);
updateTargetMode();

document.getElementById('target-form').addEventListener('submit', async event => {
  event.preventDefault(); const form = event.currentTarget; setBusy(form, true);
  const local = document.getElementById('target-mode-local').checked;
  const payload = { name: document.getElementById('target-name').value, local,
    host: local ? 'localhost' : document.getElementById('target-host').value,
    user: local ? '' : document.getElementById('target-user').value,
    port: local ? 22 : Number(document.getElementById('target-port').value),
    identity_file: local ? '' : document.getElementById('target-key').value,
    vm_name: document.getElementById('target-vm').value };
  if (state.editingTargetName) payload.original_name = state.editingTargetName;
  const wasEditing = Boolean(state.editingTargetName);
  try { await api('/api/targets', { method: 'POST', body: JSON.stringify(payload) }); state.lastGuideline = null; state.scapResults = []; state.selectedPolicyRuleIds.clear(); cancelTargetEdit(); await loadTargets(); toast(wasEditing ? 'Ziel aktualisiert' : 'Ziel gespeichert'); }
  catch (error) { toast(error.message); } finally { setBusy(form, false); updateTargetMode(); }
});

document.getElementById('pull-model-form').addEventListener('submit', async event => {
  event.preventDefault(); const form = event.currentTarget; setBusy(form, true); toast('Modell wird geladen …');
  try { await api('/api/ollama/pull', { method: 'POST', body: JSON.stringify({ model: document.getElementById('pull-model').value }) }); await loadStatus(); toast('Modell verfügbar'); }
  catch (error) { toast(error.message); } finally { setBusy(form, false); }
});

document.getElementById('select-model').addEventListener('click', async () => {
  const button = document.getElementById('select-model'); const model = document.getElementById('active-model').value;
  button.disabled = true;
  try {
    await api('/api/ollama/select', { method: 'POST', body: JSON.stringify({ model }) });
    window.localStorage.setItem('lha-active-model', model);
    await loadStatus(); activity(`KI-Modell ${model} ausgewählt`, 'success'); toast(`${model} wird verwendet`);
  } catch (error) { activity(error.message, 'error'); toast(error.message); button.disabled = false; }
});

resetGuidelineSourceForm();
Promise.all([loadStatus(), loadVMs(), loadTargets(), loadGuidelineSources(), loadPolicyProfiles()]).catch(error => toast(error.message));
