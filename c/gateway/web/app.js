'use strict';
(() => {
  const $ = id => document.getElementById(id);
  const state = {token: '', installToken: '', nodes: [], selected: null, apps: [],
    refreshing: false, loadingApps: false, selection: 0, editing: null, confirm: null};
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
    state.selection++; $('console').hidden = true; $('login-screen').hidden = false;
    $('install-token').value = ''; $('password').value = ''; $('nodes').replaceChildren(); $('rules').replaceChildren();
    for (const dialog of document.querySelectorAll('dialog[open]')) dialog.close();
    $('login-error').hidden = !expired;
    if (expired) text('login-error', '会话已过期，请重新登录。');
  }
  async function api(path, data) {
    const token = state.token, controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15000);
    try {
      const headers = {'Content-Type': 'application/json'};
      if (token) headers.Authorization = 'Bearer ' + token;
      const response = await fetch(path, {method: data === undefined ? 'GET' : 'POST', headers,
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
        throw new Error(known[response.status] || (body.detail === 'device offline' ? '节点已离线。' : '网关未能完成请求。'));
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
    const nodes = state.nodes.filter(n => [n.name, n.ip, n.lanip, n.os].some(v => String(v || '').toLowerCase().includes(query)));
    $('nodes').replaceChildren();
    for (const n of nodes) {
      const row = element('tr'); row.classList.toggle('selected', n.name === state.selected?.name);
      const cell = element('td'), info = element('div', 'node-cell'), label = element('div');
      info.append(element('span', 'node-avatar', String(n.os).endsWith('-c') ? 'C' : '◇'));
      label.append(element('span', 'node-title', n.name), element('span', 'node-subtitle', n.os || '未知系统'));
      info.append(label); cell.append(info); row.append(cell);
      for (const value of [n.ip || '—', n.lanip || '—']) row.append(element('td', 'mono', value));
      row.append(element('td', '', 'NAT ' + (n.natType || '—')), element('td', 'mono', n.version || '—'));
      const status = element('td'); status.append(element('span', 'badge online', '● 在线')); row.append(status);
      const action = element('td'), button = element('button', 'link-button', '查看规则 →');
      button.type = 'button'; button.setAttribute('aria-label', '查看 ' + n.name + ' 的规则');
      button.addEventListener('click', event => { event.stopPropagation(); selectNode(n); });
      action.append(button); row.append(action); row.addEventListener('click', () => selectNode(n));
      $('nodes').append(row);
    }
    text('table-count', state.nodes.length); text('nav-count', state.nodes.length);
    text('search-count', query ? `匹配 ${nodes.length} / ${state.nodes.length} 个节点` : `共 ${state.nodes.length} 个在线节点`);
    $('nodes-empty').hidden = nodes.length > 0;
    const empty = $('nodes-empty');
    empty.querySelector('h3').textContent = query ? '没有匹配的节点' : '还没有在线节点';
    empty.querySelector('p').textContent = query ? '试试其他名称、IP 或系统关键字。' : '让客户端使用此网关的地址、CA 和安装 Token 连接。';
  }
  async function refresh() {
    if (!state.token || state.refreshing) return;
    state.refreshing = true; $('refresh').disabled = true;
    const token = state.token;
    try {
      const [status, devices] = await Promise.all([api('/api/v1/status'), api('/api/v1/devices')]);
      if (state.token !== token) return;
      text('gateway-label', '网关在线'); $('gateway-status').classList.remove('offline');
      state.nodes = (Array.isArray(devices.nodes) ? devices.nodes : []).sort((a, b) => a.name.localeCompare(b.name));
      text('online-count', status.online); text('capacity', '/ ' + status.capacity);
      text('uptime', uptime(status.uptimeSeconds)); text('queue', bytes(status.queuedBytes));
      text('queue-limit', '上限 ' + bytes(status.queueLimitBytes)); text('version', status.version);
      text('sidebar-version', 'C Gateway ' + status.version); text('wss-port', 'WSS :' + status.wssPort + ' · HTTPS');
      text('account-name', status.user); text('updated-at', '更新于 ' + new Date().toLocaleTimeString('zh-CN', {hour12: false}));
      if (state.selected) {
        const selected = state.nodes.find(n => n.name === state.selected.name);
        if (!selected) selectNode(null); else state.selected = selected;
      }
      renderNodes();
    } catch (error) { if (state.token) {
      message(error.message, true); text('gateway-label', '连接中断'); $('gateway-status').classList.add('offline');
    } }
    finally { state.refreshing = false; $('refresh').disabled = false; }
  }
  function selectNode(node) {
    state.selected = node; state.apps = []; state.selection++; state.loadingApps = false;
    $('rules').replaceChildren(); $('add-rule').disabled = !node;
    $('refresh-apps').disabled = !node; renderNodes();
    text('selected-name', node ? node.name : '选择一个节点');
    text('selected-description', node ? `${node.os || '未知系统'} · ${node.ip || '—'} · 版本 ${node.version || '—'}` : '在上方节点列表中打开设备，查看它的应用转发。');
    if (node) loadApps(); else ruleMessage('尚未选择节点，或之前选择的节点已离线。');
  }
  async function loadApps() {
    if (!state.selected || state.loadingApps) return;
    const node = state.selected, selection = state.selection;
    state.loadingApps = true; $('refresh-apps').disabled = true; ruleMessage('正在向客户端查询规则…');
    try {
      const body = await api('/api/v1/device/' + encodeURIComponent(node.name) + '/apps');
      if (selection !== state.selection || !state.token) return;
      state.apps = Array.isArray(body.Apps) ? body.Apps : Array.isArray(body.apps) ? body.apps : [];
      renderApps();
      const c = !node.capabilities?.editForward;
      ruleMessage(body.TunError || (c ? '此 C 客户端支持查询和添加固定转发；现有规则与 SOCKS5 请在客户端配置中修改。' : state.apps.length ? '' : '此节点尚未配置转发规则。'), Boolean(body.TunError));
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
      if (state.selected.capabilities?.editForward && ['tcp', 'udp'].includes(app.protocol)) {
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
  function confirm(title, description, action) {
    text('confirm-title', title); text('confirm-description', description); state.confirm = action;
    $('confirm-dialog').showModal();
  }
  function openRule(app = null) {
    if (!state.selected) return;
    state.editing = app; $('rule-form').reset(); $('rule-error').hidden = true;
    text('rule-dialog-title', app ? '编辑转发规则' : '添加转发');
    $('rule-name').value = app?.appName || ''; $('rule-protocol').value = app?.protocol || 'tcp';
    $('rule-source').value = app?.srcPort || ''; $('rule-peer').value = app?.peerNode || '';
    $('rule-destination').value = app?.dstHost || '127.0.0.1'; $('rule-target').value = app?.dstPort || '';
    $('rule-transport').value = app && (Number(app.punchPriority) & 2) ? 'tcp' : 'quic';
    $('rule-whitelist').value = app ? app.whitelist || '' : '127.0.0.1';
    $('whitelist-field').hidden = !state.selected.capabilities?.editForward;
    text('rule-help', state.selected.capabilities?.editForward ? '规则保存在 Go 客户端；UDP 优先模式可能按客户端策略选择其他链路。' : 'C 客户端新增规则仅在本次进程中生效，入口绑定 127.0.0.1。需要持久化时同步修改客户端配置。');
    $('peer-names').replaceChildren(...state.nodes.filter(n => n.name !== state.selected.name).map(n => {
      const option = element('option'); option.value = n.name; return option;
    }));
    $('rule-dialog').showModal();
  }
  $('login-form').addEventListener('submit', async event => {
    event.preventDefault(); $('login-submit').disabled = true; $('login-error').hidden = true;
    try {
      const login = await api('/api/v1/user/login', {user: $('username').value, password: $('password').value});
      if (typeof login.token !== 'string' || typeof login.nodeToken !== 'string') throw new Error('无法读取登录凭据。');
      state.token = login.token; state.installToken = login.nodeToken; $('password').value = '';
      $('login-screen').hidden = true; $('console').hidden = false; message(''); await refresh();
    } catch (error) { text('login-error', error.message); $('login-error').hidden = false; }
    finally { $('login-submit').disabled = false; }
  });
  $('rule-form').addEventListener('submit', async event => {
    event.preventDefault(); if (!state.selected) return;
    $('save-rule').disabled = true; $('rule-error').hidden = true;
    const node = state.selected, old = state.editing;
    try {
      const app = {appName: $('rule-name').value.trim(), protocol: $('rule-protocol').value,
        srcPort: Number($('rule-source').value), peerNode: $('rule-peer').value.trim(),
        dstHost: $('rule-destination').value.trim(), dstPort: Number($('rule-target').value),
        punchPriority: $('rule-transport').value === 'tcp' ? 3 : 0};
      if (!app.appName || !app.dstHost || app.peerNode === node.name) throw new Error('请填写有效名称、目标地址和其他对端节点。');
      if (!node.capabilities?.editForward && (new TextEncoder().encode(app.appName).length > 63 ||
          new TextEncoder().encode(app.dstHost).length > 255)) throw new Error('名称或目标地址过长，请缩短后重试。');
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
  $('confirm-form').addEventListener('submit', async event => {
    event.preventDefault(); $('confirm-action').disabled = true;
    try { await state.confirm?.(); $('confirm-dialog').close(); message('指令已发送到客户端。');
      await new Promise(resolve => setTimeout(resolve, 600)); await loadApps();
    } catch (error) { message(error.message, true); $('confirm-dialog').close(); }
    finally { $('confirm-action').disabled = false; state.confirm = null; }
  });
  $('token-button').addEventListener('click', () => {
    $('install-token').value = state.installToken; $('install-token').type = 'password'; text('reveal-token', '显示'); $('token-dialog').showModal();
  });
  $('reveal-token').addEventListener('click', () => {
    const hidden = $('install-token').type === 'password'; $('install-token').type = hidden ? 'text' : 'password'; text('reveal-token', hidden ? '隐藏' : '显示');
  });
  $('copy-token').addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(state.installToken); text('copy-token', '已复制'); }
    catch { $('install-token').type = 'text'; $('install-token').select(); text('copy-token', '请手动复制'); }
  });
  $('token-dialog').addEventListener('close', () => { $('install-token').value = ''; text('copy-token', '复制 Token'); });
  $('close-token').addEventListener('click', () => $('token-dialog').close());
  $('logout').addEventListener('click', () => logout()); $('refresh').addEventListener('click', refresh);
  $('overview-nav').addEventListener('click', () => window.scrollTo({top: 0, behavior: 'smooth'}));
  $('node-search').addEventListener('input', renderNodes); $('refresh-apps').addEventListener('click', loadApps);
  $('add-rule').addEventListener('click', () => openRule());
  for (const id of ['close-rule-dialog', 'cancel-rule']) $(id).addEventListener('click', () => $('rule-dialog').close());
  $('cancel-confirm').addEventListener('click', () => $('confirm-dialog').close());
  setInterval(() => { if (!document.hidden) refresh(); }, 10000);
})();
