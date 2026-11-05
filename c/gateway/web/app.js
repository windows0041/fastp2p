'use strict';
(() => {
  const $ = id => document.getElementById(id);
  const state = {token: '', installToken: '', nodes: [], selected: null, apps: [], updates: [],
    refreshing: false, loadingApps: false, selection: 0, editing: null, confirm: null,
    offset: 0, total: 0, registered: 0, upgrades: new Map(), skippedUpgrades: []};
  /* The console keeps its session in sessionStorage: it survives a reload, but
   * it dies with the tab and is never shared with another tab. */
  const STORE = 'fastp2p.console';
  function persist() {
    try {
      if (state.token)
        sessionStorage.setItem(STORE, JSON.stringify({token: state.token, installToken: state.installToken}));
      else
        sessionStorage.removeItem(STORE);
    } catch { /* storage disabled: the console still works for this page view */ }
  }
  function text(id, value) { $(id).textContent = String(value ?? '—'); }
  function element(tag, cls, value) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (value !== undefined) node.textContent = String(value);
    return node;
  }
  function message(value, error = false) {
    text('notice', value); $('notice').hidden = !value; $('notice').classList.toggle('error', error);
  }
  function ruleMessage(value, error = false) {
    text('rule-message', value); $('rule-message').hidden = !value;
    $('rule-message').classList.toggle('error', error);
  }
  function logout(expired = false) {
    state.token = state.installToken = ''; state.nodes = []; state.apps = []; state.selected = null;
    state.upgrades.clear(); state.skippedUpgrades = []; renderUpgradeProgress();
    persist();
    state.selection++; $('console').hidden = true; $('login-screen').hidden = false;
    state.offset = state.total = state.registered = 0; $('node-search').value = '';
    $('install-token').value = ''; $('password').value = ''; $('nodes').replaceChildren(); $('rules').replaceChildren();
    for (const dialog of document.querySelectorAll('dialog[open]')) dialog.close();
    $('login-error').hidden = !expired;
    if (expired) text('login-error', '会话已过期，请重新登录。');
  }
  async function api(path, data, method) {
    const token = state.token, controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15000);
    try {
      const headers = {'Content-Type': 'application/json'};
      if (token) headers.Authorization = 'Bearer ' + token;
      const response = await fetch(path, {method: method || (data === undefined ? 'GET' : 'POST'), headers,
        body: data === undefined ? undefined : JSON.stringify(data), signal: controller.signal,
        credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer'});
      const raw = await response.text();
      let body;
      try { body = raw ? JSON.parse(raw) : {}; } catch { throw new Error('网关返回了无法读取的响应。'); }
      if (response.status === 401) {
        if (token && state.token === token) logout(true);
        throw new Error(token ? '会话已过期，请重新登录。' : '账号或密码不正确。');
      }
      if (!response.ok || body.error) {
        const known = {409: '此节点正在处理另一个查询，请稍后刷新。', 503: '节点暂时无法响应，请稍后重试。',
          504: '客户端响应超时，请检查节点是否仍在线。', 501: '此客户端暂不支持该操作。'};
        const details = {'device offline':'节点已离线。','node is online':'节点已上线，不能删除。',
          'node not found':'节点记录已不存在。','current password incorrect':'当前密码不正确。',
          'no package for this platform and version':'没有适合此节点平台和架构的安装包，请先手动安装新版客户端。',
          'invalid account settings':'请填写有效账号和至少 8 位的新密码。'};
        throw new Error(details[body.detail] || known[response.status] || '网关未能完成请求。');
      }
      return body;
    } catch (error) {
      if (error.name === 'AbortError') throw new Error('请求超时，请稍后重试。');
      if (error instanceof TypeError) throw new Error('无法连接网关，请检查网络或证书。');
      throw error;
    } finally { clearTimeout(timer); }
  }
  const bytes = value => Number(value) >= 1048576 ? (Number(value) / 1048576).toFixed(1) + ' MiB' :
    Number(value) >= 1024 ? (Number(value) / 1024).toFixed(1) + ' KiB' : Number(value || 0) + ' B';
  function uptime(seconds) {
    const days = Math.floor(seconds / 86400), hours = Math.floor(seconds / 3600) % 24, minutes = Math.floor(seconds / 60) % 60;
    return days ? `${days} 天 ${hours} 时` : hours ? `${hours} 时 ${minutes} 分` : `${minutes} 分`;
  }
  function renderNodes() {
    const query = $('node-search').value.toLowerCase().trim();
    const nodes = state.nodes.filter(n => [n.name, n.hostname, n.ip, n.lanip, n.os].some(v => String(v || '').toLowerCase().includes(query)));
    $('nodes').replaceChildren();
    for (const n of nodes) {
      const row = element('tr'); row.classList.toggle('selected', n.name === state.selected?.name);
      const cell = element('td'), info = element('div', 'node-cell'), label = element('div');
      info.append(element('span', 'node-avatar', String(n.os).endsWith('-c') ? 'C' : '◇'));
      label.append(element('span', 'node-title', n.name), element('span', 'node-subtitle', n.os || '未知系统'));
      if (n.hostname) label.append(element('span', 'node-subtitle', '主机：' + n.hostname));
      info.append(label); cell.append(info); row.append(cell);
      for (const value of [n.ip || '—', n.lanip || '—']) row.append(element('td', 'mono', value));
      row.append(element('td', '', 'NAT ' + (n.natType || '—')), element('td', 'mono', n.version || '—'));
      const active = Number(n.isActive) === 1;
      const status = element('td'); status.append(element('span', 'badge ' + (active ? 'online' : 'offline'), active ? '● 在线' : '○ 离线')); row.append(status);
      const action = element('td'), button = element('button', 'link-button', active ? '查看规则 →' : '查看记录 →');
      button.type = 'button'; button.setAttribute('aria-label', '查看 ' + n.name + ' 的规则');
      button.addEventListener('click', event => { event.stopPropagation(); selectNode(n); });
      action.append(button);
      if (n.capabilities?.configPush || (!active && String(n.os).endsWith('-c') && !String(n.os).startsWith('android') && compareVersions(n.version, '2.0.4') >= 0)) {
        const config = element('button', 'link-button', '配置'); config.type = 'button';
        config.setAttribute('aria-label', '配置节点 ' + n.name);
        config.addEventListener('click', event => { event.stopPropagation(); openConfig(n); });
        action.append(config);
      }
      const latest = latestFor(platformForOs(n.os));
      if (active && latest && compareVersions(n.version, latest) < 0) {
        const upgrade = element('button', 'link-button', '升级到 ' + latest); upgrade.type = 'button';
        upgrade.setAttribute('aria-label', '升级节点 ' + n.name + ' 到 ' + latest);
        const pending = state.upgrades.get(n.name);
        if (pending?.status === 'pending') { upgrade.disabled = true; upgrade.textContent = '等待升级完成…'; }
        upgrade.addEventListener('click', event => {
          event.stopPropagation();
          confirm('升级客户端', `${n.name}：${n.version || '未知版本'} → ${latest}。客户端会从网关下载、校验并重启，连接会短暂中断。`, async () => {
            await api('/api/v1/device/' + encodeURIComponent(n.name) + '/upgrade', {version: latest});
            trackUpgrades([{node: n.name, from: n.version, to: latest}], []);
            await new Promise(resolve => setTimeout(resolve, 800));
            await refresh();
            return '升级指令已发送到 ' + n.name + '。';
          });
        });
        action.append(upgrade);
      }
      if (!active) {
        const remove = element('button', 'link-button remove', '删除'); remove.type = 'button';
        remove.setAttribute('aria-label', '删除离线节点 ' + n.name);
        remove.addEventListener('click', event => {
          event.stopPropagation();
          confirm('删除离线节点', `删除 ${n.name} 的登记记录、转发规则和网关下发配置。设备持有接入 Token 时，再次上线会重新登记。`, async () => {
            await api('/api/v1/nodes/' + encodeURIComponent(n.name), undefined, 'DELETE');
            if (state.selected?.name === n.name) selectNode(null);
            state.offset = 0; await refresh();
            return '离线节点已删除。';
          });
        }); action.append(remove);
      }
      row.append(action); row.addEventListener('click', () => selectNode(n));
      $('nodes').append(row);
    }
    text('table-count', state.registered); text('nav-count', state.registered);
    text('search-count', query ? `匹配 ${state.total} / ${state.registered} 个节点` : `共 ${state.registered} 个已登记节点`);
    text('node-page', state.total ? `${state.offset + 1}–${state.offset + state.nodes.length} / ${state.total}` : '0 / 0');
    $('previous-nodes').disabled = !state.offset;
    $('next-nodes').disabled = state.offset + 100 >= state.total;
    $('nodes-empty').hidden = nodes.length > 0;
    const empty = $('nodes-empty');
    empty.querySelector('h3').textContent = query ? '没有匹配的节点' : '还没有登记节点';
    empty.querySelector('p').textContent = query ? '试试其他名称、IP 或系统关键字。' : '让客户端使用此网关的地址、CA 和安装 Token 连接。';
  }
  async function refresh() {
    if (!state.token || state.refreshing) return;
    state.refreshing = true; $('refresh').disabled = true;
    $('previous-nodes').disabled = $('next-nodes').disabled = true;
    const token = state.token, query = $('node-search').value.trim(), offset = state.offset;
    try {
      const [status, devices] = await Promise.all([api('/api/v1/status'),
        api(`/api/v1/nodes?limit=100&offset=${offset}&search=${encodeURIComponent(query)}`)]);
      if (state.token !== token || offset !== state.offset || query !== $('node-search').value.trim()) return;
      text('gateway-label', '网关在线'); $('gateway-status').classList.remove('offline');
      state.nodes = Array.isArray(devices.nodes) ? devices.nodes : [];
      renderUpgradeProgress();
      state.total = Number(devices.total) || 0; state.registered = Number(status.totalNodes) || 0;
      text('online-count', status.online); text('capacity', '/ ' + status.capacity);
      text('uptime', uptime(status.uptimeSeconds)); text('queue', bytes(status.queuedBytes));
      text('queue-limit', '上限 ' + bytes(status.queueLimitBytes)); text('version', status.version);
      text('sidebar-version', 'C Gateway ' + status.version); text('wss-port', 'WSS :' + status.wssPort + ' · HTTPS');
      text('account-name', status.user); text('updated-at', '更新于 ' + new Date().toLocaleTimeString('zh-CN', {hour12: false}));
      if (state.selected) {
        const selected = state.nodes.find(n => n.name === state.selected.name);
        if (!selected) selectNode(null);
        else if (selected.isActive !== state.selected.isActive) selectNode(selected);
        else state.selected = selected;
      }
      renderNodes();
      loadUpdates();
    } catch (error) { if (state.token === token) {
      message(error.message, true); text('gateway-label', '连接中断'); $('gateway-status').classList.add('offline');
    } }
    finally {
      state.refreshing = false; $('refresh').disabled = false;
      $('previous-nodes').disabled = !state.offset;
      $('next-nodes').disabled = state.offset + 100 >= state.total;
      if (state.token && (token !== state.token || offset !== state.offset || query !== $('node-search').value.trim())) refresh();
    }
  }
  function selectNode(node) {
    state.selected = node; state.apps = []; state.selection++; state.loadingApps = false;
    const active = node && Number(node.isActive) === 1;
    $('rules').replaceChildren(); $('add-rule').disabled = !active;
    $('refresh-apps').disabled = !active; renderNodes();
    text('selected-name', node ? node.name : '选择一个节点');
    text('selected-description', node ? `${node.hostname || node.os || '未知主机'} · ${node.ip || '—'} · 最近在线 ${node.lastSeen || '—'}` : '在上方节点列表中打开设备，查看它的应用转发。');
    if (active) loadApps();
    else ruleMessage(node ? `节点已离线，登记信息保留在 SQLite 中。首次在线：${node.firstSeen || '—'}；最近离线：${node.lastOffline || '—'}。` : '尚未选择节点。');
  }
  async function loadApps() {
    if (!state.selected || state.loadingApps) return;
    const node = state.selected, selection = state.selection;
    state.loadingApps = true; $('refresh-apps').disabled = true; ruleMessage('正在读取网关保存的规则…');
    try {
      const body = await api('/api/v1/device/' + encodeURIComponent(node.name) + '/apps');
      if (selection !== state.selection || !state.token) return;
      state.apps = Array.isArray(body.Apps) ? body.Apps : Array.isArray(body.apps) ? body.apps : [];
      renderApps();
      ruleMessage(body.TunError || (state.apps.length ? '' : '此节点尚未配置转发规则。'), Boolean(body.TunError));
    } catch (error) { if (selection === state.selection && state.token) ruleMessage(error.message, true); }
    finally { if (selection === state.selection) { state.loadingApps = false; $('refresh-apps').disabled = false; } }
  }
  function renderApps() {
    $('rules').replaceChildren();
    for (const app of state.apps) {
      const row = element('tr'), name = element('td');
      name.append(element('span', 'node-title', app.appName || '未命名规则'));
      if (app.error) name.append(element('span', 'node-subtitle', app.error)); row.append(name);
      const source = element('td'); source.append(element('span', 'badge protocol', String(app.protocol || '').toUpperCase()), document.createTextNode(' :' + app.srcPort)); row.append(source);
      const destination = element('td', 'rule-destination'); destination.append(element('span', '', app.peerNode || '—'),
        element('small', 'mono', app.protocol === 'socks5' ? '动态目标 · SOCKS5' : `${app.dstHost || '—'}:${app.dstPort || '—'}`)); row.append(destination);
      row.append(element('td', 'mono', app.linkMode || '—'));
      const status = element('td'), active = Number(app.isActive) === 1, enabled = app.enabled === undefined || Number(app.enabled) === 1;
      status.append(element('span', 'badge ' + (active ? 'online' : enabled ? 'warning' : 'offline'), active ? '● 已连接' : enabled ? '等待连接' : '已停用')); row.append(status);
      const actions = element('td');
      if (state.selected.capabilities?.editForward && ['tcp', 'udp', 'socks5'].includes(app.protocol)) {
        const nodeName = state.selected.name;
        const edit = element('button', 'link-button', '编辑'); edit.type = 'button'; edit.addEventListener('click', () => openRule(app)); actions.append(edit);
        const toggle = element('button', 'link-button', enabled ? '停用' : '启用'); toggle.type = 'button';
        toggle.addEventListener('click', () => confirm(`${enabled ? '停用' : '启用'}规则`, `${app.appName || app.srcPort}：${enabled ? '此规则的现有连接将中断。' : '客户端将重新建立转发。'}`, async () => {
          await api('/api/v1/device/' + encodeURIComponent(nodeName) + '/switchapp', {
            appName: app.appName, srcPort: app.srcPort, protocol: app.protocol, peerNode: app.peerNode, enabled: enabled ? 0 : 1});
        })); actions.append(toggle);
        const remove = element('button', 'link-button remove', '删除'); remove.type = 'button';
        remove.addEventListener('click', () => confirm('删除转发规则', `删除 ${app.appName || app.srcPort}，将中断此规则的连接。`, async () => {
          await api('/api/v1/device/' + encodeURIComponent(nodeName) + '/app', {
            appName: app.appName, protocol: app.protocol, srcPort: 0, srcPort0: app.srcPort, protocol0: app.protocol,
            peerNode: app.peerNode, dstHost: app.dstHost, dstPort: app.dstPort, whitelist: app.whitelist || ''});
        })); actions.append(remove);
      } else actions.append(element('span', 'muted', '客户端配置'));
      row.append(actions); $('rules').append(row);
    }
  }
  /* --- Client upgrades ---------------------------------------------------- */
  function trackUpgrades(queued, skipped) {
    for (const item of queued)
      state.upgrades.set(item.node, {...item, started: Date.now(), status: 'pending'});
    state.skippedUpgrades = skipped;
    renderUpgradeProgress(); renderNodes();
  }
  function renderUpgradeProgress() {
    const messages = [];
    for (const [name, item] of state.upgrades) {
      const node = state.nodes.find(n => n.name === name);
      if (node && compareVersions(node.version, item.to) >= 0) item.status = 'complete';
      else if (item.status === 'pending' && Date.now() - item.started > 360000) item.status = 'unconfirmed';
      messages.push(name + '：' + (item.status === 'complete' ? '已升级到 ' + item.to :
        item.status === 'unconfirmed' ? '尚未确认升级完成，请检查客户端日志或手动安装。' :
        '已下发 ' + item.to + '，等待客户端重启并上报新版本…' +
          (String(node?.os || '').startsWith('android') ? '请在手机通知中确认安装。' : '')));
    }
    const reasons = {architecture_not_reported: '旧客户端未上报架构，请先手动安装一次新版。',
      package_unavailable: '没有匹配平台和架构的安装包。', dispatch_failed: '升级指令下发失败，请稍后重试。'};
    for (const item of state.skippedUpgrades)
      messages.push(item.node + '：未下发，' + (reasons[item.reason] || '客户端暂不支持升级。'));
    text('upgrade-message', messages.join('；'));
    $('upgrade-message').hidden = !messages.length;
  }
  function platformForOs(os) {
    const value = String(os || '');
    if (!value.endsWith('-c')) return '';
    if (value.startsWith('windows')) return 'windows';
    if (/^linux-(x86_64|aarch64|armv7|i686|riscv64|s390x|ppc64le|mips64el)-c$/.test(value))
      return value.slice(0, -2);
    if (/^darwin-(arm64|x86_64)-c$/.test(value)) return 'macos' + value.slice(6, -2);
    if (value.startsWith('linux')) return 'linux';
    if (value.startsWith('android')) return 'android';
    if (value.startsWith('darwin')) return 'macos';
    return '';
  }
  function compareVersions(left, right) {
    const a = String(left || '').split('.').map(Number), b = String(right || '').split('.').map(Number);
    for (let i = 0; i < Math.max(a.length, b.length); i++) {
      const x = a[i] || 0, y = b[i] || 0;
      if (x !== y) return x < y ? -1 : 1;
    }
    return 0;
  }
  function latestFor(platform) {
    let best = '';
    for (const update of state.updates)
      if ((update.platform === platform || update.platform === platform.split('-')[0]) &&
          (!best || compareVersions(update.version, best) > 0))
        best = update.version;
    return best;
  }
  function renderUpdates() {
    $('updates').replaceChildren();
    const linux = state.updates.filter(update => /^linux(?:-|$)/.test(update.platform));
    const downloads = state.updates.filter(update => !/^linux(?:-|$)/.test(update.platform));
    if (linux.length) downloads.unshift({platform: 'linux', automatic: true,
      uploadedAt: Math.max(...linux.map(update => update.uploadedAt || 0))});
    for (const update of downloads) {
      const row = element('tr');
      row.append(element('td', '', update.automatic ? 'Linux（自动识别架构）' : update.platform),
        element('td', 'mono', update.automatic ? '按架构选择最新版' : update.version),
        element('td', 'mono', update.automatic ? '按需下载' : bytes(update.size)),
        element('td', 'mono', update.automatic ? '安装时校验 SHA-256' : String(update.sha256 || '').slice(0, 16) + '…'),
        element('td', 'mono', update.uploadedAt
          ? new Date(update.uploadedAt * 1000).toLocaleString('zh-CN', {hour12: false}) : '—'));
      const cell = element('td', '');
      const button = element('button', 'button', update.automatic ? '下载 Linux 通用安装脚本' : '下载安装包');
      button.type = 'button';
      button.addEventListener('click', () => downloadInstaller(update, button));
      cell.append(button);
      row.append(cell);
      $('updates').append(row);
    }
    $('update-message').classList.remove('error');
    text('update-message', state.updates.length ? '' : '尚无安装包。');
  }
  async function downloadInstaller(update, button) {
    const token = state.token;
    button.disabled = true;
    try {
      const params = new URLSearchParams({platform: update.platform});
      if (!update.automatic) params.set('version', update.version);
      const response = await fetch('/api/v1/update/install?' + params, {
        headers: {Authorization: 'Bearer ' + token}, cache: 'no-store',
        credentials: 'omit', referrerPolicy: 'no-referrer'});
      if (response.status === 401 && state.token === token) logout(true);
      if (!response.ok) throw new Error('下载安装包失败，请刷新列表后重试。');
      const filename = /filename="([A-Za-z0-9_.-]+)"/i.exec(response.headers.get('Content-Disposition') || '');
      if (!filename) throw new Error('网关未返回安装包文件名。');
      const blob = await response.blob();
      if (state.token !== token) return;
      const url = URL.createObjectURL(blob);
      const link = element('a', '');
      link.href = url;
      link.download = filename[1];
      document.body.append(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      if (update.platform === 'android') text('update-message', '安装 APK 后，在客户端安装 Token 对话框中点「安卓接入」。');
      else if (update.platform.startsWith('linux')) text('update-message', '执行 sh ' + filename[1] + '（也可用 bash）。脚本自动识别 CPU，从本网关下载对应程序，保留节点身份与配置，安装到 /usr/local/fastp2p 并设置开机启动。需要 curl 或 GNU wget，请勿修改文件名中的 Token。');
    } catch (error) {
      $('update-message').classList.add('error');
      text('update-message', error.message);
    } finally { button.disabled = false; }
  }
  let configNode = null, configTimer;
  const configLabels = {none: '尚未下发配置。', queued: '已保存到网关，等待客户端上线接收。',
    saved: '客户端已保存配置，正在重载并验证连接…', applied: '客户端已确认配置生效。',
    failed: '客户端未能应用此配置。旧配置已保留；请检查字段或客户端日志后重新下发。'};
  async function openConfig(node) {
    clearTimeout(configTimer); configNode = node.name;
    text('config-title', node.name + ' · 配置'); $('config-error').hidden = true;
    $('save-config').disabled = true; $('config-fields').value = '{}';
    text('config-status', '正在读取网关配置…'); $('config-dialog').showModal();
    try {
      const result = await api('/api/v1/device/' + encodeURIComponent(node.name) + '/config');
      if (configNode !== node.name || !$('config-dialog').open) return;
      $('config-fields').value = JSON.stringify(result.fields, null, 2);
      text('config-status', configLabels[result.state] || '');
    } catch (error) { $('config-error').hidden = false; text('config-error', error.message); }
    finally { $('save-config').disabled = false; }
  }
  async function pollConfig(node, revision, until) {
    if (!state.token || configNode !== node || !$('config-dialog').open) return;
    try {
      const result = await api('/api/v1/device/' + encodeURIComponent(node) + '/config');
      if (configNode !== node || !$('config-dialog').open) return;
      text('config-status', configLabels[result.state] || '');
      if (result.revision >= revision && ['applied', 'failed'].includes(result.state)) return;
      if (Date.now() < until) configTimer = setTimeout(() => pollConfig(node, revision, until), 1500);
      else text('config-status', '仍在等待客户端确认；可稍后重新打开配置查看状态。');
    } catch (error) { $('config-error').hidden = false; text('config-error', error.message); }
  }
  $('close-config').addEventListener('click', () => $('config-dialog').close());
  $('config-dialog').addEventListener('close', () => { clearTimeout(configTimer); configNode = null; $('config-fields').value = ''; });
  $('config-form').addEventListener('submit', async event => {
    event.preventDefault(); $('config-error').hidden = true; $('save-config').disabled = true;
    const node = configNode;
    try {
      const fields = JSON.parse($('config-fields').value);
      if (!fields || Array.isArray(fields) || typeof fields !== 'object') throw new Error('请填写 JSON 对象。');
      const result = await api('/api/v1/device/' + encodeURIComponent(node) + '/config', {fields});
      text('config-status', configLabels[result.state] || '配置已排队。');
      clearTimeout(configTimer); pollConfig(node, result.revision, Date.now() + 120000);
    } catch (error) { $('config-error').hidden = false; text('config-error', error.message); }
    finally { $('save-config').disabled = false; }
  });
  let syncTimer;
  async function syncRelease(start = false) {
    const token = state.token;
    clearTimeout(syncTimer);
    if (!token) return;
    $('sync-release').disabled = true;
    try {
      const result = await api('/api/v1/releases/sync', start ? {} : undefined);
      if (state.token !== token) return;
      if (result.status === 'running') {
        text('sync-message', '正在下载并校验 GitHub 安装包…');
        syncTimer = setTimeout(syncRelease, 2000);
        return;
      }
      text('sync-message', result.status === 'failed' ? '同步失败，请查看网关服务日志。' :
        result.version ? '已同步 GitHub 稳定版 ' + result.version + '；较低版本缓存会自动清理（含手动上传包），正在使用的旧包延后清理。' : '');
      if (result.status === 'complete') await loadUpdates();
    } catch (error) {
      if (start) text('sync-message', error.message);
    }
    $('sync-release').disabled = false;
  }
  async function loadUpdates() {
    try {
      const body = await api('/api/v1/updates');
      state.updates = Array.isArray(body.updates) ? body.updates : [];
      renderUpdates();
      // The per-node upgrade buttons depend on which versions are available.
      if (state.nodes.length) renderNodes();
    } catch (error) {
      $('update-message').classList.add('error'); text('update-message', error.message);
    }
  }
  function confirm(title, description, action) {
    text('confirm-title', title); text('confirm-description', description); state.confirm = action;
    $('confirm-dialog').showModal();
  }
  function syncRuleFields() {
    const socks = $('rule-protocol').value === 'socks5';
    $('destination-field').hidden = socks;
    $('socks-field').hidden = !socks;
    // A SOCKS5 exit resolves its target per request, so the fixed destination
    // is not applicable and must not be required by the form.
    for (const id of ['rule-destination', 'rule-target']) {
      $(id).required = !socks;
      if (socks) $(id).value = '';
    }
    if (socks) $('rule-destination').value = '127.0.0.1';
  }
  function openRule(app = null) {
    if (!state.selected) return;
    state.editing = app; $('rule-form').reset(); $('rule-error').hidden = true;
    $('rule-socks-user').value = ''; $('rule-socks-password').value = '';
    text('rule-dialog-title', app ? '编辑转发规则' : '添加转发');
    $('rule-name').value = app?.appName || ''; $('rule-protocol').value = app?.protocol || 'tcp';
    $('rule-source').value = app?.srcPort || ''; $('rule-peer').value = app?.peerNode || '';
    $('rule-destination').value = app?.dstHost || '127.0.0.1'; $('rule-target').value = app?.dstPort || '';
    $('rule-transport').value = app && (Number(app.punchPriority) & 2) ? 'tcp' : 'quic';
    $('rule-whitelist').value = app ? app.whitelist || '' : '127.0.0.1';
    if (app && app.protocol === 'socks5') {
      // The gateway never returns a stored password; show the username and let a
      // blank password mean "keep the existing one".
      $('rule-socks-user').value = app.Username || '';
      $('rule-socks-password').placeholder = app.hasPassword
        ? '留空 = 保留原密码' : '留空 = 不启用认证';
    } else {
      $('rule-socks-password').placeholder = '留空 = 不启用认证';
    }
    $('whitelist-field').hidden = !state.selected.capabilities?.editForward;
    text('rule-help', state.selected.capabilities?.editForward
      ? '规则保存在网关数据库中，节点在线时立即生效，离线时在下次连接后生效。'
      : '规则保存在网关数据库中，节点下次连接后生效。');
    $('peer-names').replaceChildren(...state.nodes.filter(n => n.name !== state.selected.name).map(n => {
      const option = element('option'); option.value = n.name; return option;
    }));
    // Relay candidates: every other registered node, labelled with its NAT type
    // so a node reachable without hairpin NAT is easy to pick.
    const relay = $('rule-relay');
    relay.replaceChildren(element('option', null, '自动选择（按 NAT 质量）'));
    relay.firstChild.value = '';
    for (const n of state.nodes) {
      if (n.name === state.selected.name) continue;
      const option = element('option', null, n.natType === 1 ? `${n.name}（NAT 1）` : `${n.name}（NAT ${n.natType ?? '?'}）`);
      option.value = n.name; relay.append(option);
    }
    relay.value = app?.relayNode || '';
    syncRuleFields();
    $('rule-dialog').showModal();
  }
  $('rule-protocol').addEventListener('change', syncRuleFields);
  $('login-form').addEventListener('submit', async event => {
    event.preventDefault(); $('login-submit').disabled = true; $('login-error').hidden = true;
    try {
      const login = await api('/api/v1/user/login', {user: $('username').value, password: $('password').value});
      if (typeof login.token !== 'string' || typeof login.installToken !== 'string') throw new Error('无法读取登录凭据。');
      state.token = login.token; state.installToken = login.installToken; $('password').value = '';
    persist();
      $('login-screen').hidden = true; $('console').hidden = false; message(''); await refresh();
      syncRelease();
    } catch (error) { text('login-error', error.message); $('login-error').hidden = false; }
    finally { $('login-submit').disabled = false; }
  });
  $('account-button').addEventListener('click', () => {
    $('account-form').reset(); $('account-error').hidden = true;
    $('account-user').value = $('account-name').textContent;
    $('account-dialog').showModal();
  });
  $('account-form').addEventListener('submit', async event => {
    event.preventDefault(); $('save-account').disabled = true; $('account-error').hidden = true;
    const user = $('account-user').value.trim();
    try {
      await api('/api/v1/user/account', {user, currentPassword: $('current-password').value,
        newPassword: $('new-password').value});
      $('account-dialog').close(); logout(); $('username').value = user;
      text('login-error', '账号已更新，请使用新账号和密码登录。'); $('login-error').hidden = false;
    } catch (error) { text('account-error', error.message); $('account-error').hidden = false; }
    finally { $('save-account').disabled = false; }
  });
  $('account-dialog').addEventListener('close', () => $('account-form').reset());
  $('cancel-account').addEventListener('click', () => $('account-dialog').close());
  $('rule-form').addEventListener('submit', async event => {
    event.preventDefault(); if (!state.selected) return;
    $('save-rule').disabled = true; $('rule-error').hidden = true;
    const node = state.selected, old = state.editing;
    try {
      const socks = $('rule-protocol').value === 'socks5';
      const app = {appName: $('rule-name').value.trim(), protocol: $('rule-protocol').value,
        srcPort: Number($('rule-source').value), peerNode: $('rule-peer').value.trim(),
        punchPriority: $('rule-transport').value === 'tcp' ? 3 : 0};
      if (socks) {
        // The exit selects the destination per SOCKS5 request, so no fixed
        // target is sent. Credentials are optional but must come as a pair.
        app.Username = $('rule-socks-user').value.trim();
        app.Password = $('rule-socks-password').value;
        const keep = old && old.protocol === 'socks5' && old.hasPassword && !app.Password;
        if (keep) {
          // Blank password while editing an authenticated proxy keeps the stored
          // one; the browser never receives it in the first place.
          app.keepPassword = 1;
        } else if (Boolean(app.Username) !== Boolean(app.Password)) {
          throw new Error('SOCKS5 用户名和密码必须同时填写，或同时留空。');
        }
      } else {
        app.dstHost = $('rule-destination').value.trim();
        app.dstPort = Number($('rule-target').value);
      }
      const relay = $('rule-relay').value;
      if (relay) {
        if (relay === app.peerNode) throw new Error('中继节点不能是对端节点本身。');
        if (relay === node.name) throw new Error('中继节点不能是本节点本身。');
        app.relayNode = relay;
      }
      if (!app.appName || app.peerNode === node.name ||
          (!socks && !app.dstHost)) throw new Error('请填写有效名称、对端节点' + (socks ? '' : '和目标地址') + '。');
      if (!node.capabilities?.editForward && (new TextEncoder().encode(app.appName).length > 63 ||
          (!socks && new TextEncoder().encode(app.dstHost).length > 255) ||
          (socks && new TextEncoder().encode(app.Username).length > 255)))
        throw new Error('名称、目标地址或用户名过长，请缩短后重试。');
      if (state.apps.some(a => a !== old && a.protocol === app.protocol && Number(a.srcPort) === app.srcPort))
        throw new Error('此应用协议和入口端口已被使用。');
      if (node.capabilities?.editForward) app.whitelist = $('rule-whitelist').value.trim();
      if (old) { app.protocol0 = old.protocol; app.srcPort0 = old.srcPort; }
      await api('/api/v1/device/' + encodeURIComponent(node.name) + '/app', app);
      $('rule-dialog').close(); message('指令已发送到客户端，正在刷新规则。');
      await new Promise(resolve => setTimeout(resolve, 600)); await loadApps();
    } catch (error) { text('rule-error', error.message); $('rule-error').hidden = false; }
    finally { $('save-rule').disabled = false; }
  });
  $('upload-update').addEventListener('click', () => {
    $('update-form').reset(); $('update-error').hidden = true;
    $('update-dialog').showModal();
  });
  $('close-update-dialog').addEventListener('click', () => $('update-dialog').close());
  $('cancel-update').addEventListener('click', () => $('update-dialog').close());
  $('refresh-updates').addEventListener('click', loadUpdates);
  $('sync-release').addEventListener('click', () => syncRelease(true));
  $('update-form').addEventListener('submit', async event => {
    event.preventDefault();
    const file = $('update-file').files[0];
    const platform = $('update-platform').value, version = $('update-version').value.trim();
    if (!file) { text('update-error', '请选择安装包文件。'); $('update-error').hidden = false; return; }
    if (!/^\d+(\.\d+){0,3}$/.test(version)) {
      text('update-error', '版本号应类似 2.0.2。'); $('update-error').hidden = false; return;
    }
    $('save-update').disabled = true; $('update-error').hidden = true;
    try {
      // Raw binary upload: the gateway hashes the stream as it writes it.
      const response = await fetch('/api/v1/update?platform=' + encodeURIComponent(platform) +
        '&version=' + encodeURIComponent(version), {
        method: 'PUT', body: file, credentials: 'omit',
        headers: {Authorization: 'Bearer ' + state.token, 'Content-Type': 'application/octet-stream'}});
      const body = await response.json().catch(() => ({}));
      if (response.status === 401) { logout(true); throw new Error('会话已过期，请重新登录。'); }
      if (!response.ok || body.error) throw new Error(body.detail || '上传失败。');
      $('update-dialog').close();
      message('安装包已上传：' + platform + ' ' + version);
      await loadUpdates(); await refresh();
    } catch (error) { text('update-error', error.message); $('update-error').hidden = false; }
    finally { $('save-update').disabled = false; }
  });
  $('upgrade-all').addEventListener('click', () => confirm('升级所有旧版本',
    '对所有版本低于最新安装包的在线节点下发升级。客户端会从网关下载、校验并重启，连接会短暂中断。',
    async () => {
      const body = await api('/api/v1/upgrades', {});
      const queued = Array.isArray(body.queued) ? body.queued : [];
      const skipped = Array.isArray(body.skipped) ? body.skipped : [];
      trackUpgrades(queued, skipped);
      await new Promise(resolve => setTimeout(resolve, 800)); await refresh();
      return queued.length ? '已向 ' + queued.length + ' 个节点下发升级' + (skipped.length ? '，另有 ' + skipped.length + ' 个节点未下发，原因见客户端升级面板。' : '，正在等待客户端上报新版本。') :
        skipped.length ? skipped.length + ' 个节点无法自动升级，原因见客户端升级面板。' : '没有需要升级的在线节点。';
    }));
  $('confirm-form').addEventListener('submit', async event => {
    event.preventDefault(); $('confirm-action').disabled = true;
    try { const result = await state.confirm?.(); $('confirm-dialog').close(); message(result || '操作已完成。');
      await new Promise(resolve => setTimeout(resolve, 600)); await loadApps();
    } catch (error) { message(error.message, true); $('confirm-dialog').close(); }
    finally { $('confirm-action').disabled = false; state.confirm = null; }
  });
  $('token-button').addEventListener('click', () => {
    $('install-token').value = state.installToken; $('install-token').type = 'password'; $('android-install').href = 'intent://install?token=' + encodeURIComponent(state.installToken) + '#Intent;scheme=fastp2p;package=top.fastp2p.cclient;end'; text('reveal-token', '显示'); $('token-dialog').showModal();
  });
  $('reveal-token').addEventListener('click', () => {
    const hidden = $('install-token').type === 'password'; $('install-token').type = hidden ? 'text' : 'password'; text('reveal-token', hidden ? '隐藏' : '显示');
  });
  $('copy-token').addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(state.installToken); text('copy-token', '已复制'); }
    catch { $('install-token').type = 'text'; $('install-token').select(); text('copy-token', '请手动复制'); }
  });
  $('token-dialog').addEventListener('close', () => { $('install-token').value = ''; $('android-install').removeAttribute('href'); text('copy-token', '复制 Token'); });
  $('close-token').addEventListener('click', () => $('token-dialog').close());
  $('logout').addEventListener('click', () => logout()); $('refresh').addEventListener('click', refresh);
  $('overview-nav').addEventListener('click', () => window.scrollTo({top: 0, behavior: 'smooth'}));
  let searchTimer;
  $('node-search').addEventListener('input', () => {
    state.offset = 0; renderNodes(); clearTimeout(searchTimer); searchTimer = setTimeout(refresh, 200);
  });
  $('previous-nodes').addEventListener('click', () => { state.offset = Math.max(0, state.offset - 100); refresh(); });
  $('next-nodes').addEventListener('click', () => { state.offset += 100; refresh(); });
  $('refresh-apps').addEventListener('click', loadApps);
  $('add-rule').addEventListener('click', () => openRule());
  for (const id of ['close-rule-dialog', 'cancel-rule']) $(id).addEventListener('click', () => $('rule-dialog').close());
  $('cancel-confirm').addEventListener('click', () => $('confirm-dialog').close());
  setInterval(() => { if (!document.hidden) refresh(); }, 10000);
  try {
    const saved = JSON.parse(sessionStorage.getItem(STORE) || 'null');
    if (saved && typeof saved.token === 'string' && saved.token) {
      state.token = saved.token;
      state.installToken = typeof saved.installToken === 'string' ? saved.installToken : '';
      $('login-screen').hidden = true; $('console').hidden = false;
      refresh();
      syncRelease();
    }
  } catch { try { sessionStorage.removeItem(STORE); } catch { /* ignore */ } }
})();
