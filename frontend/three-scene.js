function signalThreeUnavailable(error) {
  window.CyberThreeSceneUnavailable = String(error);
  window.dispatchEvent(new CustomEvent('cyber3dunavailable', { detail: String(error) }));
}

(async () => {
  const THREE = await import('./vendor/three.module.js');
  const host = document.querySelector('#sceneWrap');
  if (!host) return;

  const canvas = document.createElement('canvas');
  canvas.id = 'threatCanvas3d';
  canvas.setAttribute('aria-hidden', 'true');
  host.prepend(canvas);

  let renderer;
  try {
    renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true, powerPreference: 'high-performance' });
  } catch (error) {
    canvas.remove();
    signalThreeUnavailable(error);
    return;
  }

  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.5));
  renderer.setClearColor(0x06111c, 0);
  renderer.outputColorSpace = THREE.SRGBColorSpace;

  const scene = new THREE.Scene();
  scene.fog = new THREE.FogExp2(0x071522, 0.012);
  const camera = new THREE.PerspectiveCamera(33, 1, 0.1, 80);
  camera.position.set(0, 6.1, 10.2);
  camera.lookAt(0, 0.2, 0);
  scene.add(new THREE.HemisphereLight(0x8edfff, 0x07121c, 2.0));
  const keyLight = new THREE.PointLight(0x56d9f3, 38, 30); keyLight.position.set(-4, 7, 5); scene.add(keyLight);
  const warmLight = new THREE.PointLight(0x3958ff, 18, 25); warmLight.position.set(5, 4, -4); scene.add(warmLight);

  const world = new THREE.Group(); scene.add(world);
  const grid = new THREE.GridHelper(9, 14, 0x1c6074, 0x173345);
  grid.position.y = -0.17;
  grid.material.transparent = true; grid.material.opacity = 0.105;
  world.add(grid);
  const floor = new THREE.Mesh(
    new THREE.PlaneGeometry(18, 18),
    new THREE.MeshBasicMaterial({ color: 0x071521, transparent: true, opacity: 0.18, side: THREE.DoubleSide }),
  );
  floor.rotation.x = -Math.PI / 2; floor.position.y = -0.2; world.add(floor);

  const raycaster = new THREE.Raycaster();
  const pointer = new THREE.Vector2();
  const pickMeshes = [];
  const nodesByKey = new Map();
  let activeGroup = new THREE.Group(); world.add(activeGroup);
  let current = { mode: 'live', nodes: [], edges: [], scenario: null, elapsed: 0, duration: 12000, graphTime: 0, selected: null };
  let graphSignature = null;
  let sceneSignature = null;
  let flowObjects = [];
  let dragged = false;
  let pointerStart = null;

  const mat = (color, opts = {}) => new THREE.MeshStandardMaterial({ color, roughness: 0.35, metalness: 0.42, emissive: color, emissiveIntensity: 0.25, ...opts });
  const colors = { ATTACK: '#ff526d', REVIEW: '#ffb547', BENIGN: '#21c9a0', FAILED: '#8194a6', SOURCE: '#f05b75', DESTINATION: '#40d9e6', ROUTER: '#9d79ff', SERVER: '#32ddb0', PURPLE: '#a775ff', AMBER: '#ffb547' };
  const glowTexture = (() => {
    const c = document.createElement('canvas'); c.width = c.height = 64;
    const x = c.getContext('2d'); const g = x.createRadialGradient(32, 32, 2, 32, 32, 32);
    g.addColorStop(0, 'rgba(255,255,255,0.8)'); g.addColorStop(0.2, 'rgba(255,255,255,0.34)'); g.addColorStop(1, 'rgba(255,255,255,0)');
    x.fillStyle = g; x.fillRect(0, 0, 64, 64); return new THREE.CanvasTexture(c);
  })();

  function colorHex(value, fallback = '#56d9f3') { return /^#[0-9a-f]{6}$/i.test(String(value)) ? value : fallback; }
  function makeLabel(text, color = '#dff8ff') {
    const c = document.createElement('canvas'); c.width = 512; c.height = 96;
    const ctx = c.getContext('2d'); ctx.font = '700 27px Segoe UI, sans-serif'; ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
    const label = String(text || '').length > 28 ? `${String(text).slice(0, 26)}…` : String(text || 'Endpoint');
    ctx.fillStyle = 'rgba(5, 17, 29, 0.9)'; ctx.beginPath(); ctx.roundRect(18, 14, 476, 68, 18); ctx.fill();
    ctx.strokeStyle = `${color}88`; ctx.lineWidth = 2; ctx.stroke();
    ctx.fillStyle = color; ctx.beginPath(); ctx.arc(45, 48, 7, 0, Math.PI * 2); ctx.fill();
    ctx.shadowColor = color; ctx.shadowBlur = 8; ctx.fillStyle = '#e6f4fb'; ctx.fillText(label, 270, 48, 405); ctx.shadowBlur = 0;
    const texture = new THREE.CanvasTexture(c); texture.colorSpace = THREE.SRGBColorSpace;
    const sprite = new THREE.Sprite(new THREE.SpriteMaterial({ map: texture, transparent: true, depthWrite: false, sizeAttenuation: true }));
    sprite.scale.set(2.45, 0.46, 1); sprite.position.y = 1.7;
    return sprite;
  }
  function addGlow(parent, hex, scale = 1.9) {
    const material = new THREE.SpriteMaterial({ map: glowTexture, color: hex, transparent: true, opacity: 0.52, depthWrite: false, blending: THREE.AdditiveBlending });
    const sprite = new THREE.Sprite(material); sprite.scale.set(scale, scale, 1); sprite.position.y = 0.28; parent.add(sprite); return sprite;
  }
  function box(parent, size, position, color, options = {}) {
    const mesh = new THREE.Mesh(new THREE.BoxGeometry(...size), mat(color, options)); mesh.position.set(...position); mesh.castShadow = false; mesh.receiveShadow = false; parent.add(mesh); return mesh;
  }
  function addDevice(group, node, position, tintOverride = null) {
    const hex = colorHex(tintOverride || node.color || (node.role === 'source' ? colors.SOURCE : colors.DESTINATION));
    const tint = new THREE.Color(hex);
    const object = new THREE.Group(); object.position.set(position.x, position.y, position.z); object.userData.nodeKey = node.key; group.add(object);
    object.scale.setScalar(1.5);
    const glow = addGlow(object, tint, node.flows > 1 ? 3.1 : 2.1);
    const pad = new THREE.Mesh(new THREE.CylinderGeometry(0.58, 0.63, 0.07, 32), new THREE.MeshStandardMaterial({ color: 0x102332, roughness: 0.42, metalness: 0.55, emissive: tint, emissiveIntensity: 0.08 }));
    pad.position.y = -0.08; object.add(pad);
    const ring = new THREE.Mesh(new THREE.TorusGeometry(0.59, 0.018, 8, 40), new THREE.MeshBasicMaterial({ color: tint, transparent: true, opacity: 0.68 }));
    ring.rotation.x = -Math.PI / 2; ring.position.y = -0.07; object.add(ring);
    const role = node.visualType || (node.role === 'destination' ? 'server' : 'computer');
    if (role === 'server') {
      for (let i = 0; i < 3; i++) {
        box(object, [0.78, 0.36, 0.5], [0, 0.32 + i * 0.4, 0], hex, { emissiveIntensity: 0.35 });
        const led = new THREE.Mesh(new THREE.SphereGeometry(0.035, 8, 8), new THREE.MeshBasicMaterial({ color: i === 2 ? '#ecfff7' : hex }));
        led.position.set(-0.27, 0.32 + i * 0.4, 0.27); object.add(led);
        box(object, [0.28, 0.055, 0.018], [0.07, 0.32 + i * 0.4, 0.265], '#b8dbe7', { emissive: '#204658', emissiveIntensity: 0.3 });
      }
    } else if (role === 'gateway' || role === 'firewall' || role === 'router') {
      const shell = new THREE.Mesh(new THREE.CylinderGeometry(0.39, 0.48, 0.28, 6), mat(hex, { emissiveIntensity: 0.55 })); shell.position.y = 0.38; object.add(shell);
      const crown = new THREE.Mesh(new THREE.TorusGeometry(0.3, 0.035, 8, 32), new THREE.MeshBasicMaterial({ color: hex })); crown.rotation.x = -Math.PI / 2; crown.position.y = 0.55; object.add(crown);
      if (role === 'firewall') {
        const shape = new THREE.Shape(); shape.moveTo(-0.17, 0.16); shape.lineTo(0.17, 0.16); shape.lineTo(0.15, -0.03); shape.quadraticCurveTo(0.1, -0.15, 0, -0.22); shape.quadraticCurveTo(-0.1, -0.15, -0.15, -0.03); shape.closePath();
        const emblem = new THREE.Mesh(new THREE.ShapeGeometry(shape), new THREE.MeshBasicMaterial({ color: '#fff0c4', transparent: true, opacity: 0.9, side: THREE.DoubleSide })); emblem.position.set(0, 0.39, 0.31); object.add(emblem);
      }
    } else if (role === 'database' || role === 'memory') {
      const cyl = new THREE.Mesh(new THREE.CylinderGeometry(0.36, 0.36, 0.72, 20), mat(hex, { emissiveIntensity: 0.4 })); cyl.position.y = 0.42; object.add(cyl);
      for (let y = 0.16; y < 0.8; y += 0.22) { const rim = new THREE.Mesh(new THREE.TorusGeometry(0.36, 0.018, 6, 24), new THREE.MeshBasicMaterial({ color: hex })); rim.rotation.x = Math.PI / 2; rim.position.y = y; object.add(rim); }
    } else if (role === 'attacker' || role === 'bot') {
      box(object, [0.86, 0.62, 0.12], [0, 0.59, 0], hex, { emissiveIntensity: 0.52, metalness: 0.55 });
      box(object, [0.71, 0.46, 0.025], [0, 0.6, 0.073], '#091522', { emissive: hex, emissiveIntensity: 0.35, metalness: 0.12 });
      box(object, [0.12, 0.2, 0.1], [0, 0.16, 0], '#96aebd', { emissive: '#173345', emissiveIntensity: 0.2 });
      box(object, [0.5, 0.055, 0.3], [0, 0.055, 0.02], '#a7becb', { emissive: '#173345', emissiveIntensity: 0.16 });
      const mark = new THREE.Mesh(new THREE.OctahedronGeometry(0.13, 0), new THREE.MeshBasicMaterial({ color: '#ff8794' })); mark.position.set(0.22, 0.78, 0.12); object.add(mark);
    } else {
      box(object, [0.72, 0.48, 0.12], [0, 0.5, 0], hex, { emissiveIntensity: 0.4 });
      box(object, [0.1, 0.22, 0.1], [0, 0.15, 0], hex);
      box(object, [0.42, 0.055, 0.28], [0, 0.035, 0], '#91b5c2', { emissive: '#153040', emissiveIntensity: 0.15 });
    }
    object.add(makeLabel(node.label, hex));
    pickMeshes.push(object.children.find(child => child.isMesh));
    nodesByKey.set(node.key, { object, node, glow, ring });
    return object;
  }
  function clearGroup() {
    activeGroup.traverse(obj => {
      if (obj.geometry) obj.geometry.dispose();
      if (obj.material) {
        const materials = Array.isArray(obj.material) ? obj.material : [obj.material];
        materials.forEach(m => { if (m.map && m.map !== glowTexture) m.map.dispose(); m.dispose(); });
      }
    });
    while (activeGroup.children.length) activeGroup.remove(activeGroup.children[0]);
    pickMeshes.length = 0; nodesByKey.clear(); flowObjects = [];
  }
  function addFlow(group, from, to, hex, options = {}) {
    const a = from.position, b = to.position;
    const mid = new THREE.Vector3((a.x + b.x) / 2, Math.max(a.y, b.y) + (options.arc || 0.35), (a.z + b.z) / 2 + (options.bend || 0));
    const curve = new THREE.QuadraticBezierCurve3(a.clone().add(new THREE.Vector3(0, 0.42, 0)), mid, b.clone().add(new THREE.Vector3(0, 0.42, 0)));
    const line = new THREE.Line(new THREE.BufferGeometry().setFromPoints(curve.getPoints(32)), new THREE.LineBasicMaterial({ color: hex, transparent: true, opacity: options.opacity ?? 0.78 }));
    group.add(line);
    const particleCount = options.particles ?? 2;
    for (let i = 0; i < particleCount; i++) {
      const material = new THREE.MeshBasicMaterial({ color: hex, transparent: true, opacity: 0.95 });
      const particle = new THREE.Mesh(new THREE.SphereGeometry(options.size || 0.09, 10, 10), material);
      group.add(particle);
      flowObjects.push({ particle, curve, offset: i / particleCount + (options.phase || 0), speed: options.speed || 0.42, start: options.start || 0, end: options.end ?? 1, loop: options.loop !== false });
    }
    return line;
  }
  function buildLive() {
    clearGroup(); graphSignature = current.nodes;
    const positions = new Map();
    current.nodes.forEach(node => {
      positions.set(node.key, node);
      addDevice(activeGroup, node, { x: node.x * 4.4, y: node.y * 2.7, z: node.z * 4.4 });
    });
    let edges = current.edges.slice(0, 100);
    if (current.nodes.length === 2 && current.nodes.every(node => node.key.includes('unknown-'))) {
      const byDecision = new Map();
      edges.forEach(edge => { const existing = byDecision.get(edge.decision) || { ...edge, count: 0 }; existing.count++; byDecision.set(edge.decision, existing); });
      edges = [...byDecision.values()].map(edge => ({ ...edge, offset: 0 }));
    }
    edges.forEach((edge, index) => {
      const source = nodesByKey.get(edge.source.key)?.object, target = nodesByKey.get(edge.target.key)?.object;
      if (!source || !target) return;
      const hex = colorHex(edge.color, colors.FAILED);
      addFlow(activeGroup, source, target, hex, { particles: 1, size: 0.075, phase: index * 0.173, speed: 0.22 + (index % 3) * 0.045, arc: 0.35 + (index % 4) * 0.12 });
      if (edge.count > 1) {
        const label = makeLabel(`${edge.decision} · ${edge.count} FLOWS`, hex); label.scale.set(2.65, 0.48, 1); label.position.copy(source.position).lerp(target.position, 0.5); label.position.y += 1.7 + index * 0.28; activeGroup.add(label);
      }
    });
    highlightSelected();
  }

  function attackDefinition(scenario) {
    const id = scenario?.id || 'generic';
    const n = (key, label, type, x, y = 0, z = 0, color) => ({ key, label, type, position: new THREE.Vector3(x, y, z), color: color || '#4ad7e7' });
    const e = (from, to, color, opts = {}) => ({ from, to, color, opts });
    if (id === 'ddos') {
      const bots = Array.from({ length: 7 }, (_, i) => n(`bot${i}`, `REMOTE DEVICE ${i + 1}`, 'attacker', -4.6, 0, (i - 3) * 0.9, '#ff596e'));
      const gate = n('gateway', 'NETWORK EDGE', 'gateway', -0.2, 0, 0, '#ffb547'); const target = n('target', 'PUBLIC SERVICE', 'server', 4.1, 0, 0, '#ff596e');
      return { nodes: [...bots, gate, target], edges: [...bots.map(bot => e(bot.key, gate.key, '#ff6878', { particles: 2, speed: 0.5, arc: 0.3 })), e(gate.key, target.key, '#ff445f', { particles: 8, speed: 0.66, arc: 0.55 })] };
    }
    if (id === 'dos') {
      const attacker = n('attacker', 'ONE ATTACKER', 'attacker', -4.4, 0, 0, '#ff596e'); const gate = n('gateway', 'NETWORK EDGE', 'firewall', -0.2, 0, 0, '#ffb547'); const target = n('target', 'BUSY WEBSITE SERVER', 'server', 4.2, 0, 0, '#ff596e'); const user = n('visitor', 'REAL VISITOR', 'computer', -3.3, 0, 2.3, '#32ddb0');
      return { nodes: [attacker, gate, target, user], edges: [e(attacker.key, gate.key, '#ff596e', { particles: 5, speed: 0.62 }), e(gate.key, target.key, '#ff596e', { particles: 5, speed: 0.62 }), e(user.key, target.key, '#32ddb0', { particles: 1, speed: 0.25, arc: 0.2 })] };
    }
    if (id === 'botnet') {
      const c2 = n('c2', 'ATTACKER CONTROL', 'attacker', -4.5, 0, 0, '#ffb547'); const bots = Array.from({ length: 5 }, (_, i) => n(`bot${i}`, `COMPROMISED DEVICE ${i + 1}`, 'bot', -0.6, 0, (i - 2) * 1.15, '#ff6878')); const target = n('target', 'TARGET SERVICE', 'server', 4.2, 0, 0, '#ff596e');
      return { nodes: [c2, ...bots, target], edges: [...bots.map((bot, i) => e(c2.key, bot.key, '#ffb547', { particles: 1, speed: 0.3, phase: i * 0.17 })), ...bots.map((bot, i) => e(bot.key, target.key, '#ff596e', { particles: 2, speed: 0.5, phase: i * 0.14 }))] };
    }
    if (id === 'bruteforce' || id === 'web-brute') {
      const source = n('source', id === 'web-brute' ? 'REMOTE CLIENT' : 'ONE ATTACKER', 'attacker', -4.3, 0, 0, '#ff596e'); const login = n('login', id === 'web-brute' ? 'WEB LOGIN' : 'LOGIN SERVICE', 'firewall', 0, 0, 0, '#ffb547'); const account = n('account', 'PROTECTED ACCOUNT', 'server', 4.2, 0, 0, '#4ad7e7');
      return { nodes: [source, login, account], edges: [e(source.key, login.key, '#ff596e', { particles: 4, speed: 0.54 }), e(login.key, source.key, '#4ad7e7', { particles: 2, speed: 0.34, phase: 0.3 }), e(login.key, account.key, '#4ad7e7', { particles: 1, speed: 0.22, opacity: 0.3 })] };
    }
    if (id === 'portscan') {
      const scanner = n('scanner', 'ONE SCANNER', 'attacker', -4.3, 0, 0, '#ff596e'); const ports = Array.from({ length: 6 }, (_, i) => n(`port${i}`, ['FTP · 21', 'SSH · 22', 'MAIL · 25', 'WEB · 80', 'TLS · 443', 'DB · 3306'][i], 'gateway', 3.8, 0, (i - 2.5) * 0.82, i % 2 ? '#40d9e6' : '#ffb547'));
      return { nodes: [scanner, ...ports], edges: ports.map((port, i) => e(scanner.key, port.key, '#ffb547', { particles: 1, speed: 0.5, phase: i * 0.16, arc: 0.25 })) };
    }
    if (id === 'infiltration') {
      const nodes = [n('outside', 'OUTSIDE DEVICE', 'attacker', -5, 0, 0, '#ff596e'), n('gate', 'FIREWALL', 'firewall', -2.1, 0, 0, '#ffb547'), n('host', 'INTERNAL HOST', 'computer', 0.7, 0, 0, '#ff8a65'), n('files', 'FILE SHARE', 'server', 3.3, 0, -0.6, '#a775ff'), n('protected', 'PROTECTED SERVER', 'server', 5.1, 0, 1.3, '#a775ff')];
      return { nodes, edges: nodes.slice(0, -1).map((node, i) => e(node.key, nodes[i + 1].key, ['#ff596e', '#ffb547', '#ff8a65', '#a775ff'][i], { particles: 1, speed: 0.32, phase: i * 0.21, arc: 0.35 })) };
    }
    if (id === 'web-sql') {
      const client = n('client', 'REMOTE CLIENT', 'attacker', -4.1, 0, 0, '#ff596e'); const app = n('app', 'WEB APPLICATION', 'gateway', 0, 0, 0, '#ffb547'); const db = n('database', 'DATABASE', 'database', 4.2, 0, 0, '#a775ff');
      return { nodes: [client, app, db], edges: [e(client.key, app.key, '#ff596e', { particles: 3, speed: 0.46 }), e(app.key, db.key, '#a775ff', { particles: 2, speed: 0.35, phase: 0.35 })] };
    }
    if (id === 'web-xss') {
      const attacker = n('attacker', 'ATTACKER', 'attacker', -4.1, 0, 0, '#ff596e'); const app = n('app', 'WEB APPLICATION', 'gateway', 0, 0, 0, '#ffb547'); const visitor = n('visitor', 'VISITOR BROWSER', 'computer', 4.2, 0, 0, '#a775ff');
      return { nodes: [attacker, app, visitor], edges: [e(attacker.key, app.key, '#ff596e', { particles: 2, speed: 0.35 }), e(app.key, visitor.key, '#a775ff', { particles: 1, speed: 0.28, phase: 0.4 })] };
    }
    if (id === 'data-leak') {
      const requester = n('requester', 'REMOTE REQUESTER', 'computer', -4.2, 0, 0, '#40d9e6'); const tls = n('tls', 'TLS SERVICE', 'gateway', 0, 0, 0, '#ffb547'); const memory = n('memory', 'SERVER MEMORY', 'database', 4.2, 0, 0, '#a775ff');
      return { nodes: [requester, tls, memory], edges: [e(requester.key, tls.key, '#40d9e6', { particles: 1, speed: 0.28 }), e(tls.key, memory.key, '#ffb547', { particles: 1, speed: 0.27, phase: 0.3 }), e(memory.key, requester.key, '#a775ff', { particles: 3, speed: 0.48, phase: 0.6, arc: 1.2 })] };
    }
    if (id === 'web') {
      const client = n('client', 'REMOTE CLIENT', 'attacker', -4.2, 0, 0, '#ff596e'); const gateway = n('gateway', 'WEB GATEWAY', 'firewall', -0.1, 0, 0, '#ffb547'); const app = n('app', 'WEB APPLICATION', 'server', 4.2, 0, 0, '#40d9e6');
      return { nodes: [client, gateway, app], edges: [e(client.key, gateway.key, '#ff596e', { particles: 2, speed: 0.4 }), e(gateway.key, app.key, '#40d9e6', { particles: 2, speed: 0.32, phase: 0.4 })] };
    }
    const source = n('source', String(scenario?.source || 'REMOTE SOURCE').toUpperCase(), 'attacker', -4.2, 0, 0, '#ff596e'); const gate = n('gate', String(scenario?.middle || 'NETWORK GATEWAY').toUpperCase(), 'firewall', 0, 0, 0, '#ffb547'); const target = n('target', String(scenario?.target || 'DESTINATION SERVICE').toUpperCase(), 'server', 4.2, 0, 0, '#40d9e6');
    return { nodes: [source, gate, target], edges: [e(source.key, gate.key, '#ff596e', { particles: 2 }), e(gate.key, target.key, '#40d9e6', { particles: 2, phase: 0.4 })] };
  }
  function buildAttack() {
    clearGroup(); sceneSignature = current.scenario?.id || 'generic';
    const spec = attackDefinition(current.scenario);
    const refs = new Map();
    spec.nodes.forEach(node => {
      const visual = { key: node.key, label: node.label, role: node.type === 'server' || node.type === 'database' || node.type === 'memory' ? 'destination' : 'source', color: node.color, flows: 1, visualType: node.type };
      refs.set(node.key, addDevice(activeGroup, visual, node.position, node.color));
    });
    spec.edges.forEach(edge => addFlow(activeGroup, refs.get(edge.from), refs.get(edge.to), edge.color, edge.opts));
    highlightSelected();
  }
  function highlightSelected() {
    nodesByKey.forEach(({ object, node, glow, ring }, key) => {
      const selected = key === current.selected;
      ring.material.opacity = selected ? 1 : 0.62;
      ring.scale.setScalar(selected ? 1.25 : 1);
      glow.material.opacity = selected ? 0.78 : node.flows > 1 ? 0.58 : 0.38;
    });
  }
  function updateParticles() {
    const elapsed = current.mode === 'demo' ? current.elapsed : current.graphTime;
    flowObjects.forEach(flow => {
      const phase = (elapsed / (1000 / flow.speed) + flow.offset) % 1;
      const visible = phase >= flow.start && phase <= flow.end;
      flow.particle.visible = visible;
      if (visible) flow.particle.position.copy(flow.curve.getPoint(phase));
    });
  }
  function render() {
    if (document.visibilityState === 'hidden') return;
    if (current.mode === 'live' && graphSignature !== current.nodes) buildLive();
    if (current.mode === 'demo' && sceneSignature !== (current.scenario?.id || 'generic')) buildAttack();
    if (current.selected) highlightSelected();
    updateParticles();
    renderer.render(scene, camera);
  }
  function setState(next) {
    const oldMode = current.mode; const oldScenario = current.scenario?.id;
    current = { ...current, ...next };
    if (oldMode !== current.mode) { graphSignature = null; sceneSignature = null; }
    if (oldScenario !== current.scenario?.id && current.mode === 'demo') sceneSignature = null;
    render();
  }
  function resize() {
    const width = Math.max(1, host.clientWidth), height = Math.max(1, host.clientHeight);
    renderer.setSize(width, height, false); camera.aspect = width / height; camera.updateProjectionMatrix(); render();
  }
  const resizeObserver = new ResizeObserver(resize); resizeObserver.observe(host);
  window.addEventListener('resize', resize, { passive: true });
  canvas.addEventListener('pointerdown', event => { dragged = false; pointerStart = { x: event.clientX, y: event.clientY }; canvas.setPointerCapture(event.pointerId); });
  canvas.addEventListener('pointermove', event => {
    if (!pointerStart) return;
    const dx = event.clientX - pointerStart.x, dy = event.clientY - pointerStart.y;
    if (Math.abs(dx) + Math.abs(dy) > 2) dragged = true;
    world.rotation.y += dx * 0.006; world.rotation.x = THREE.MathUtils.clamp(world.rotation.x + dy * 0.003, -0.22, 0.42);
    pointerStart = { x: event.clientX, y: event.clientY }; render();
  });
  const finishPointer = event => {
    if (!dragged && event.type === 'pointerup') {
      const bounds = canvas.getBoundingClientRect(); pointer.x = ((event.clientX - bounds.left) / bounds.width) * 2 - 1; pointer.y = -((event.clientY - bounds.top) / bounds.height) * 2 + 1;
      raycaster.setFromCamera(pointer, camera);
      const hit = raycaster.intersectObjects(pickMeshes, true)[0];
      const key = hit?.object?.parent?.userData?.nodeKey || hit?.object?.userData?.nodeKey;
      if (key) window.dispatchEvent(new CustomEvent('cyber3dselect', { detail: { key } }));
    }
    pointerStart = null;
  };
  canvas.addEventListener('pointerup', finishPointer); canvas.addEventListener('pointercancel', finishPointer);
  canvas.addEventListener('wheel', event => {
    event.preventDefault(); camera.position.multiplyScalar(event.deltaY < 0 ? 0.93 : 1.075);
    const distance = THREE.MathUtils.clamp(camera.position.length(), 7.5, 19); camera.position.setLength(distance); camera.lookAt(0, 0.2, 0); render();
  }, { passive: false });

  window.CyberThreeScene = {
    setState,
    reset() { world.rotation.set(0, -0.18, 0); camera.position.set(0, 6.1, 10.2); camera.lookAt(0, 0.2, 0); render(); },
    destroy() { resizeObserver.disconnect(); renderer.dispose(); clearGroup(); canvas.remove(); },
  };
  document.documentElement.classList.add('three-ready');
  window.dispatchEvent(new Event('cyber3dready'));
  resize();
})().catch(error => {
  console.error('Three.js visualization could not load:', error);
  signalThreeUnavailable(error);
});
