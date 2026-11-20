/* Attack scenes: one distinct, plain-language visual story per attack type.
   Called from app.js -> renderAttackScene(). Draws on a virtual 800x340 stage. */
(() => {
  const W = 800, H = 340;
  const C = { txt: '#e8f0f7', mut: '#8fa6b8', red: '#f3787e', amb: '#f1b95f', grn: '#53d69a', cyan: '#54d6e6', pur: '#c58aff', line: '#2c4a5e', fill: '#10263a' };
  let c, t = 0;
  const clamp = (v, a = 0, b = 1) => Math.min(b, Math.max(a, v));
  const lerp = (a, b, p) => a + (b - a) * p;
  const ph = (a, b, x) => clamp((x - a) / (b - a));
  const rr = (x, y, w, h, r = 6) => { c.beginPath(); c.roundRect(x, y, w, h, r); };
  const T = (s, x, y, sz = 11, col = C.txt, al = 'center', bold = false) => { c.fillStyle = col; c.font = `${bold ? '700 ' : ''}${sz}px "Segoe UI",sans-serif`; c.textAlign = al; c.textBaseline = 'middle'; c.fillText(s, x, y); };
  const glow = (x, y, r, col, a = .2) => { c.globalAlpha = a; c.fillStyle = col; c.beginPath(); c.arc(x, y, r, 0, 7); c.fill(); c.globalAlpha = 1; };
  const ln = (x1, y1, x2, y2, col) => { c.save(); c.strokeStyle = col; c.lineWidth = 1.5; c.setLineDash([5, 5]); c.beginPath(); c.moveTo(x1, y1); c.lineTo(x2, y2); c.stroke(); c.restore(); };
  const pk = (x1, y1, x2, y2, p, col, label) => { if (p <= 0 || p >= 1) return; const x = lerp(x1, x2, p), y = lerp(y1, y2, p); glow(x, y, 9, col, .3); c.fillStyle = col; c.beginPath(); c.arc(x, y, 3.5, 0, 7); c.fill(); if (label) T(label, x, y - 13, 9, C.txt, 'center', true); };
  const device = (x, y, col, label, s = 1) => {
    c.save(); c.translate(x, y); c.scale(s, s); c.fillStyle = C.fill; c.strokeStyle = col; c.lineWidth = 2; rr(-20, -15, 40, 26, 4); c.fill(); c.stroke();
    c.fillStyle = col + '55'; rr(-16, -11, 32, 18, 2); c.fill(); c.beginPath(); c.moveTo(-9, 16); c.lineTo(9, 16); c.moveTo(0, 11); c.lineTo(0, 16); c.stroke(); c.restore();
    if (label) T(label, x, y + 30 * s, 10, C.mut, 'center', true);
  };
  const server = (x, y, col, label, shake = 0) => {
    c.save(); c.translate(x + (shake ? Math.sin(t / 40) * shake : 0), y);
    for (let i = 0; i < 3; i++) { c.fillStyle = C.fill; c.strokeStyle = col; c.lineWidth = 2; rr(-28, -42 + i * 29, 56, 25, 4); c.fill(); c.stroke(); c.fillStyle = (Math.floor(t / 200) + i) % 2 ? col : col + '55'; c.beginPath(); c.arc(-18, -29.5 + i * 29, 3, 0, 7); c.fill(); c.fillStyle = col + '66'; rr(-8, -33 + i * 29, 28, 6, 2); c.fill(); }
    c.restore(); T(label, x, y + 58, 10, C.mut, 'center', true);
  };
  const lock = (x, y, col) => { c.save(); c.translate(x, y); c.strokeStyle = col; c.lineWidth = 4; c.beginPath(); c.arc(0, -4, 12, Math.PI, 0); c.stroke(); c.fillStyle = col; rr(-19, -4, 38, 30, 5); c.fill(); c.fillStyle = '#0b1b2b'; c.beginPath(); c.arc(0, 8, 4, 0, 7); c.fill(); c.fillRect(-1.5, 8, 3, 9); c.restore(); };
  const meter = (x, y, w, p, label) => { const col = p < .5 ? C.grn : p < .8 ? C.amb : C.red; T(label, x, y - 13, 9, C.mut, 'center', true); c.fillStyle = '#0a1826'; rr(x - w / 2, y - 6, w, 12, 6); c.fill(); c.fillStyle = col; rr(x - w / 2, y - 6, Math.max(8, w * p), 12, 6); c.fill(); T(Math.round(p * 100) + '%', x + w / 2 + 20, y, 10, col, 'center', true); };
  const cap = s => { c.fillStyle = '#0a1826'; c.strokeStyle = C.line; c.lineWidth = 1; rr(40, 304, 720, 28, 14); c.fill(); c.stroke(); T(s, 400, 318, 12, C.txt, 'center', true); };
  const like = (s, col) => T('Think of it like: ' + s, 400, 22, 12, col);
  const bubble = (x, y, w, h, s, col) => { c.fillStyle = '#0a1826'; c.strokeStyle = col; c.lineWidth = 1.5; rr(x, y, w, h, 8); c.fill(); c.stroke(); T(s, x + w / 2, y + h / 2, 10, C.txt, 'center', true); };
  const step = (u, a, b, d) => u < .34 ? a : u < .68 ? b : d;

  const scenes = {
    /* DoS — ONE source hammers ONE server */
    dos(r) {
      const load = clamp(.08 + r * 1.05), hot = load > .7;
      like('one person phoning a shop non-stop, so real customers only hear a busy tone', C.amb);
      device(100, 140, C.red, 'ONE ATTACKER'); server(690, 140, hot ? C.red : C.amb, 'WEBSITE SERVER', hot ? 2.5 : 0);
      ln(135, 140, 655, 140, C.red + '66');
      for (let i = 0; i < 8; i++) pk(135, 140, 655, 140, (t / 650 + i / 8) % 1, C.red, i === 0 ? 'REQUEST' : '');
      meter(690, 232, 120, load, 'SERVER LOAD');
      device(100, 262, C.grn, 'REAL VISITOR'); ln(135, 262, 655, 170, C.grn + '44');
      const p = (t / 2600) % 1;
      if (!hot) pk(135, 262, 655, 170, p, C.grn, 'PAGE PLEASE'); else { pk(135, 262, 655, 170, p < .5 ? p * 1.1 : (1 - p) * 1.1, C.grn); T('✗ BUSY - try later', 400, 232, 11, C.red, 'center', true); }
      cap(step(r, 'Step 1: One computer sends requests again and again, as fast as it can', 'Step 2: The server tries to answer every request and runs out of capacity', 'Step 3: Real visitors get "busy" - the site is slow or down'));
    },
    /* DDoS — MANY sources, one server */
    ddos(r) {
      const n = Math.ceil(4 + r * 20), load = clamp(.1 + r * 1.05), hot = load > .7;
      like('a huge crowd jamming a shop door so no real customer can get in', C.amb);
      for (let i = 0; i < 24; i++) {
        const x = 50 + (i % 6) * 48 + (i * 37) % 17, y = 55 + Math.floor(i / 6) * 58 + (i * 53) % 23, on = i < n;
        device(x, y, on ? C.red : C.mut, '', .55);
        if (on) pk(x + 12, y, 655, 175, (t / 1100 + i * .137) % 1, C.red);
      }
      T('THOUSANDS OF HIJACKED DEVICES', 170, 290, 10, C.mut, 'center', true);
      server(700, 160, hot ? C.red : C.amb, 'OVERWHELMED SERVER', hot ? 3 : 0); meter(700, 255, 120, load, 'SERVER LOAD');
      device(470, 255, C.grn, 'REAL VISITOR', .8); const p = (t / 2800) % 1;
      if (!hot) pk(490, 255, 670, 190, p, C.grn, 'PAGE PLEASE'); else { pk(490, 255, 670, 190, p < .5 ? p * .8 : (1 - p) * .8, C.grn); T('✗ BUSY', 560, 232, 11, C.red, 'center', true); }
      cap(step(r, 'Step 1: Many devices (from many places) start sending requests', 'Step 2: All of the requests converge on one service', 'Step 3: The flood is too big to block by one address - real users are shut out'));
    },
    /* Botnet — hijacked devices obey a controller */
    botnet() {
      const u = (t % 10000) / 10000, pos = [[300, 110], [390, 110], [480, 110], [300, 230], [390, 230], [480, 230]];
      like('a puppet master secretly controlling many hijacked computers', C.amb);
      device(80, 170, C.amb, 'ATTACKER (CONTROLLER)'); device(710, 170, C.cyan, 'TARGET');
      T('ORDINARY DEVICES - OWNERS DON\'T KNOW', 390, 62, 10, C.mut, 'center', true);
      pos.forEach(([x, y], i) => {
        const a = .08 + i * .05, inf = u > a;
        pk(100, 170, x - 25, y, ph(a - .12, a, u), C.amb, i === 0 ? 'SECRET ORDER' : '');
        glow(x, y, 30, inf ? C.red : C.grn, .12); device(x, y, inf ? C.red : C.grn, inf ? 'HIJACKED' : 'NORMAL');
        if (inf) { c.fillStyle = C.red; c.beginPath(); c.arc(x + 20, y - 15, 7, 0, 7); c.fill(); T('!', x + 20, y - 15, 10, '#fff', 'center', true); }
        if (u > .62) pk(x + 25, y, 685, 170, ((u - .62) * 10000 / 800 + i * .17) % 1, C.red, '');
      });
      if (u > .62) glow(710, 170, 40 + 8 * Math.sin(t / 120), C.red, .18);
      cap(u < .3 ? 'Step 1: The attacker secretly sends orders to infected devices' : u < .62 ? 'Step 2: The hijacked devices wait quietly for the signal' : 'Step 3: On command, they all hit the target at the same time');
    },
    /* Heartbleed — over-reading server memory */
    data(r) {
      const u = (t % 11000) / 11000, mx = 290, my = 70, cw = 40, ch = 34, cols = 6, rows = 5;
      const words = ['HAT', 'password', 'secret key', 'card no.', 'chat', 'user id', 'cookie', 'email', 'PIN', 'token'];
      like('asking a clerk to repeat "HAT" but claiming it was 500 letters - so he reads out his private notebook too', C.pur);
      device(90, 170, C.cyan, 'REQUESTER');
      T('SERVER MEMORY (private notes)', mx + cols * cw / 2, my - 14, 10, C.mut, 'center', true);
      const lp = ph(.28, .58, u) * cols * rows;
      for (let i = 0; i < cols * rows; i++) {
        const x = mx + (i % cols) * cw, y = my + Math.floor(i / cols) * ch, leaked = i > 0 && i < lp;
        c.fillStyle = i === 0 ? '#1d4d38' : leaked ? '#4a2d6d' : C.fill; c.strokeStyle = i === 0 ? C.grn : leaked ? C.pur : C.line; c.lineWidth = 1; rr(x + 1, y + 1, cw - 3, ch - 3, 3); c.fill(); c.stroke();
        T(words[i % words.length], x + cw / 2 - 1, y + ch / 2, 8, leaked || i === 0 ? '#fff' : C.mut, 'center', i === 0);
      }
      T('"HAT"', mx + 20, my + rows * ch + 12, 9, C.grn, 'center', true); T('<- what was asked for', mx + 90, my + rows * ch + 12, 9, C.mut, 'left');
      if (u < .3) bubble(30, 80, 190, 34, '"Repeat HAT - it is 500 letters!"', C.cyan);
      pk(125, 165, mx - 4, 165, ph(.02, .26, u), C.cyan, 'HEARTBEAT');
      pk(mx + 120, 262, 110, 200, ph(.62, .86, u), C.pur, 'HAT + SECRETS');
      T('POSSIBLE EXPOSURE', 680, 80, 10, C.pur, 'center', true);
      ['Passwords', 'Private keys', 'Session cookies', 'Private messages'].forEach((s, i) => { if (u > .8 + i * .04) { c.fillStyle = '#2b1b40'; c.strokeStyle = C.pur; rr(600, 98 + i * 36, 160, 28, 6); c.fill(); c.stroke(); T(s, 680, 112 + i * 36, 11, C.txt, 'center', true); } });
      cap(u < .26 ? 'Step 1: A tiny "heartbeat" asks the server to echo a short word' : u < .6 ? 'Step 2: The server trusts the claimed length and reads too much memory' : 'Step 3: The reply carries extra private memory back to the requester');
    },
    /* Password guessing */
    brute(r, scen) {
      const words = ['123456', 'password', 'admin', 'qwerty', 'letmein', 'welcome', 'iloveyou', 'abc123', 'root', 'dragon', 'monkey', '111111'], idx = Math.floor(t / 450), web = scen.web, p = (t % 450) / 450;
      like('trying one key after another from a huge keyring on a single door', C.amb);
      device(80, 170, C.red, 'ONE ATTACKER');
      c.strokeStyle = C.line; c.fillStyle = '#0a1826'; rr(190, 60, 150, 210, 8); c.fill(); c.stroke(); T('PASSWORD GUESSES', 265, 76, 9, C.mut, 'center', true);
      for (let k = -2; k <= 3; k++) { const i = idx + k; if (i < 0) continue; const y = 150 + k * 32, cur = k === 0;
        if (cur) { c.fillStyle = '#3a3018'; c.strokeStyle = C.amb; rr(200, y - 13, 130, 26, 5); c.fill(); c.stroke(); }
        T(words[i % words.length], 265, y, 11, cur ? C.amb : k < 0 ? C.red : C.mut, 'center', cur); if (k < 0) T('✗', 318, y, 11, C.red, 'center', true); }
      pk(340, 150, web ? 540 : 590, 170, p, C.amb, 'GUESS');
      const deny = idx > 0 && p < .4, col = deny ? C.red : C.cyan;
      if (web) {
        c.fillStyle = C.fill; c.strokeStyle = col; c.lineWidth = 2; rr(545, 60, 190, 190, 8); c.fill(); c.stroke(); c.fillStyle = '#0a1826'; c.fillRect(546, 61, 188, 20); [0, 1, 2].forEach(i => { c.fillStyle = C.mut; c.beginPath(); c.arc(558 + i * 12, 71, 3, 0, 7); c.fill(); });
        T('Sign in', 640, 100, 12, C.txt, 'center', true); [125, 160].forEach(y => { c.strokeStyle = C.line; c.lineWidth = 1; rr(565, y, 150, 24, 4); c.stroke(); }); T('username', 575, 137, 9, C.mut, 'left'); T('••••••••', 575, 172, 10, C.amb, 'left');
        c.fillStyle = col; rr(565, 200, 150, 28, 5); c.fill(); T(deny ? 'WRONG PASSWORD' : 'Log in', 640, 214, 10, '#0b1b2b', 'center', true); T('WEBSITE LOGIN PAGE', 640, 265, 10, C.mut, 'center', true);
      } else { glow(660, 170, 50, col, deny ? .2 : .08); lock(660, 150, col); T(deny ? '✗ DENIED' : scen.label, 660, 205, 12, col, 'center', true); T(scen.label, 660, 255, 10, C.mut, 'center', true); }
      T('FAILED TRIES: ' + idx, 640, 283, 11, C.red, 'center', true);
      cap(idx < 4 ? 'Step 1: A program tries a password, then the next, then the next' : idx < 9 ? 'Step 2: Each wrong guess is rejected - but the tries keep coming' : 'Step 3: Dozens of failed logins in a row is the warning sign');
    },
    /* Port scan */
    portscan() {
      const ports = [[21, 'FTP - file transfer', 0], [22, 'SSH - remote login', 1], [25, 'MAIL', 0], [80, 'WEB', 1], [443, 'SECURE WEB', 1], [3306, 'DATABASE', 0]], st = 1100, tt = t % (st * 7.5), cur = Math.floor(tt / st);
      like('a burglar trying every door handle on a street to find which are unlocked', C.amb);
      device(90, 170, C.red, 'ONE SCANNER');
      c.fillStyle = '#0e2133'; c.strokeStyle = C.line; c.lineWidth = 1.5; rr(430, 44, 340, 244, 10); c.fill(); c.stroke(); T('ONE SERVER = MANY "DOORS" (PORTS)', 600, 60, 10, C.mut, 'center', true);
      ports.forEach(([n, lab, open], i) => {
        const y = 82 + i * 33, active = i === cur && cur < 6, probed = i < cur || (active && tt % st > st * .55), col = !probed ? C.mut : open ? C.grn : C.red;
        if (probed && open) glow(467, y + 12, 24, C.grn, .15);
        c.fillStyle = C.fill; c.strokeStyle = col; c.lineWidth = 2; rr(450, y, 34, 26, 3); c.fill(); c.stroke(); if (probed && open) { c.fillStyle = C.grn + '55'; rr(452, y + 2, 14, 22, 2); c.fill(); }
        T(`PORT ${n} · ${lab}`, 496, y + 13, 10, C.txt, 'left'); T(probed ? (open ? 'OPEN' : 'CLOSED') : '?', 755, y + 13, 10, col, 'right', true);
        if (active) { ln(125, 170, 448, y + 13, C.amb + 'aa'); pk(125, 170, 448, y + 13, clamp((tt % st) / (st * .55)), C.amb, 'KNOCK'); }
      });
      cap(cur < 2 ? 'Step 1: The scanner knocks on one service "door" to see if it answers' : cur < 6 ? 'Step 2: It moves to the next door, then the next' : 'Step 3: Now the attacker has a map of which doors are open');
    },
    /* SQL injection */
    sql() {
      const u = (t % 10000) / 10000, inj = '\' OR 1=1 --', typed = inj.slice(0, Math.floor(ph(.02, .3, u) * inj.length)), hot = u > .62;
      like('writing extra orders on a form - and the clerk obeys them instead of just reading them', C.red);
      device(60, 100, C.red, 'ATTACKER', .8);
      c.fillStyle = C.fill; c.strokeStyle = C.line; c.lineWidth = 1.5; rr(110, 60, 200, 100, 8); c.fill(); c.stroke(); T('SEARCH BOX ON A WEBSITE', 210, 75, 9, C.mut, 'center', true);
      c.strokeStyle = C.red; rr(122, 92, 176, 30, 4); c.stroke(); T(typed + (Math.floor(t / 300) % 2 && u < .3 ? '|' : ''), 130, 107, 12, C.red, 'left', true); T('"search" or "log in" text, typed by the attacker', 210, 142, 8, C.mut);
      c.fillStyle = C.fill; c.strokeStyle = C.amb; rr(370, 70, 110, 80, 8); c.fill(); c.stroke(); T('WEB APP', 425, 100, 11, C.txt, 'center', true); T('builds a command', 425, 120, 9, C.mut);
      pk(310, 107, 370, 107, ph(.32, .42, u), C.red, '');
      if (u > .42) { c.fillStyle = '#0a1826'; c.strokeStyle = C.line; rr(110, 190, 450, 40, 6); c.fill(); c.stroke(); const a = 'SELECT * FROM users WHERE name = \''; c.font = '11px Consolas,monospace'; const wa = c.measureText(a).width; T(a, 122, 210, 11, C.mut, 'left'); T(typed, 122 + wa, 210, 11, C.red, 'left', true); T('the injected part becomes a COMMAND', 335, 246, 9, C.red); }
      c.save(); c.translate(690, 120); c.fillStyle = C.fill; c.strokeStyle = hot ? C.red : C.pur; c.lineWidth = 2; c.fillRect(-45, -35, 90, 90); c.beginPath(); c.ellipse(0, 55, 45, 14, 0, 0, 7); c.fill(); c.stroke(); c.beginPath(); c.ellipse(0, -35, 45, 14, 0, 0, 7); c.fill(); c.stroke(); c.beginPath(); c.moveTo(-45, -35); c.lineTo(-45, 55); c.moveTo(45, -35); c.lineTo(45, 55); c.stroke();
      for (let i = 0; i < 4; i++) { c.fillStyle = hot || i === 0 ? (hot ? C.red : C.pur) : C.line; rr(-30, -20 + i * 18, 60, 10, 3); c.fill(); } c.restore();
      T('DATABASE (all users)', 690, 195, 10, C.mut, 'center', true);
      pk(480, 110, 640, 110, ph(.5, .62, u), C.amb, 'QUERY'); T(hot ? 'Tricked: EVERY row is returned' : 'Normally: only 1 matching row', 690, 212, 10, hot ? C.red : C.grn, 'center', true);
      pk(660, 200, 90, 130, ph(.64, .92, u), C.red, 'ALL USER RECORDS');
      cap(u < .3 ? 'Step 1: The attacker types special text into a normal website box' : u < .62 ? 'Step 2: The site pastes that text into its database command' : 'Step 3: The database obeys - and hands back far more than it should');
    },
    /* Cross-site scripting */
    xss() {
      const u = (t % 11000) / 11000;
      like('leaving a booby-trapped note on a public notice board that goes off when the next person reads it', C.red);
      device(80, 110, C.red, 'ATTACKER'); device(710, 190, C.grn, 'NORMAL VISITOR');
      c.fillStyle = C.fill; c.strokeStyle = C.amb; c.lineWidth = 2; rr(310, 70, 190, 190, 8); c.fill(); c.stroke(); T('COMMENT PAGE', 405, 88, 11, C.txt, 'center', true);
      [0, 1].forEach(i => { c.fillStyle = C.line; rr(325, 105 + i * 36, 160, 26, 4); c.fill(); T(i ? 'Nice post!' : 'Thanks for sharing', 335, 118 + i * 36, 9, C.mut, 'left'); });
      if (u > .24) { c.fillStyle = '#4a2020'; c.strokeStyle = C.red; rr(325, 177, 160, 26, 4); c.fill(); c.stroke(); T('<script> hidden code', 335, 190, 10, C.red, 'left', true); }
      pk(115, 110, 305, 130, ph(.04, .24, u), C.red, 'BOOBY-TRAPPED COMMENT');
      pk(680, 190, 505, 170, ph(.42, .52, u), C.grn, 'OPEN PAGE'); pk(505, 185, 680, 200, ph(.52, .62, u), C.red, 'PAGE + TRAP');
      if (u > .64 && u < .84) { glow(710, 190, 45 + 6 * Math.sin(t / 90), C.red, .2); T('HIDDEN CODE RUNS!', 710, 140, 11, C.red, 'center', true); }
      pk(690, 205, 110, 130, ph(.72, .96, u), C.amb, 'STOLEN LOGIN COOKIE');
      cap(u < .3 ? 'Step 1: The attacker posts a comment containing hidden code' : u < .64 ? 'Step 2: The site stores it and shows it to the next visitor' : 'Step 3: The visitor\'s browser runs the code and leaks private info');
    },
    /* General web request abuse — distinct from SQLi and XSS */
    web() {
      const u = (t % 9000) / 9000;
      like('a suspicious request passing through the front desk before reaching a website', C.red);
      device(90, 170, C.red, 'REMOTE CLIENT');
      c.fillStyle = C.fill; c.strokeStyle = C.amb; c.lineWidth = 2; rr(300, 90, 150, 150, 8); c.fill(); c.stroke();
      T('WEB GATEWAY', 375, 112, 11, C.txt, 'center', true); T('request inspection', 375, 132, 9, C.mut);
      for (let i = 0; i < 3; i++) { c.fillStyle = i === 0 ? C.red : C.line; rr(325, 155 + i * 20, 100, 10, 3); c.fill(); }
      server(680, 170, u > .68 ? C.red : C.cyan, 'WEB APPLICATION', u > .68 ? 1.5 : 0);
      ln(125, 170, 295, 170, C.red + '88'); ln(455, 170, 650, 170, u > .68 ? C.red + '99' : C.cyan + '66');
      pk(125, 170, 295, 170, ph(.02, .33, u), C.red, 'WEB REQUEST');
      if (u > .34) pk(455, 170, 650, 170, ph(.36, .68, u), u > .68 ? C.red : C.amb, u > .68 ? 'SUSPICIOUS INPUT' : 'FORWARDED');
      cap(u < .34 ? 'Step 1: A remote client sends a request toward the website' : u < .68 ? 'Step 2: The gateway inspects and forwards the request' : 'Step 3: The request reaches the application; the model flagged its traffic pattern');
    },
    /* Infiltration */
    infil() {
      const u = (t % 10000) / 10000, P = [[110, 170], [250, 170], [385, 115], [525, 115], [525, 245], [665, 245]], pos = clamp(u / .85) * 5, sg = Math.min(4, Math.floor(pos)), fr = pos - sg;
      like('a stranger slipping in a side door, then wandering room to room looking for the safe', C.pur);
      const rooms = [[320, 60, 'OFFICE PC', 2], [460, 60, 'FILE SHARE', 3], [600, 60, 'PRINTER', -1], [320, 190, 'CAMERA', -1], [460, 190, 'ADMIN PC', 4], [600, 190, 'PROTECTED SERVER', 5]];
      c.fillStyle = '#0e2133'; c.strokeStyle = C.line; rr(300, 44, 450, 270, 8); c.fill(); c.stroke(); T('INSIDE THE COMPANY NETWORK', 525, 54, 9, C.mut, 'center', true);
      rooms.forEach(([x, y, l, k]) => { const seen = k > 0 && pos >= k, vault = k === 5; c.fillStyle = seen ? (vault ? '#3a2358' : '#3a3018') : C.fill; c.strokeStyle = seen ? (vault ? C.pur : C.amb) : C.line; c.lineWidth = vault ? 2 : 1.2; rr(x + 5, y + 8, 125, 100, 6); c.fill(); c.stroke(); T(l, x + 67, y + 58, 10, seen ? C.txt : C.mut, 'center', true); if (seen) T(vault ? 'REACHED' : 'VISITED', x + 67, y + 78, 9, vault ? C.pur : C.amb, 'center', true); });
      T('OUTSIDE', 100, 130, 10, C.mut, 'center', true); c.fillStyle = C.amb; c.fillRect(246, 70, 8, 80); c.fillRect(246, 190, 8, 80); T('ENTRANCE', 250, 285, 9, C.amb, 'center', true); T('(firewall)', 250, 298, 9, C.mut);
      c.strokeStyle = C.red + '99'; c.lineWidth = 2; c.beginPath(); c.moveTo(P[0][0], P[0][1]); for (let i = 1; i <= sg; i++) c.lineTo(P[i][0], P[i][1]); const mx = lerp(P[sg][0], P[sg + 1][0], fr), my = lerp(P[sg][1], P[sg + 1][1], fr); c.lineTo(mx, my); c.stroke();
      glow(mx, my, 16, C.red, .3); c.fillStyle = C.red; c.beginPath(); c.arc(mx, my, 6, 0, 7); c.fill(); T('INTRUDER', mx, my - 16, 9, C.txt, 'center', true);
      cap(pos < 1.2 ? 'Step 1: Suspicious activity starts outside and slips through an entrance' : pos < 4 ? 'Step 2: It moves from one internal machine to the next' : 'Step 3: It heads for the most valuable system');
    },
    generic(r, scen) {
      like('traffic that looks unusual moving from a source to a target', C.amb);
      device(100, 170, C.red, String(scen.source || 'SOURCE').toUpperCase()); device(400, 170, C.amb, String(scen.middle || 'GATEWAY').toUpperCase()); server(690, 170, C.cyan, String(scen.target || 'TARGET').toUpperCase());
      ln(135, 170, 365, 170, C.red + '88'); ln(435, 170, 655, 170, C.cyan + '88');
      for (let i = 0; i < 3; i++) { pk(135, 170, 365, 170, (t / 1400 + i / 3) % 1, C.red, i ? '' : scen.packet); pk(435, 170, 655, 170, (t / 1400 + i / 3) % 1, C.red, ''); }
      cap('The model flagged this traffic pattern as unusual');
    },
  };
  const route = { ddos: 'ddos', dos: 'dos', botnet: 'botnet', 'data-leak': 'data', bruteforce: 'brute', 'web-brute': 'brute', portscan: 'portscan', 'web-sql': 'sql', 'web-xss': 'xss', web: 'web', infiltration: 'infil' };

  window.AttackScenes = {
    scenes,
    draw(ctx, w, h, scenario, tick, ratio) {
      c = ctx; t = tick || 0;
      const text = `${scenario.detectedFamily || ''} ${scenario.selectedSampleType || ''} ${scenario.name || ''}`.toLowerCase();
      const scen = { ...scenario, web: scenario.id === 'web-brute', label: text.includes('ftp') ? 'FTP LOGIN' : text.includes('ssh') ? 'SSH LOGIN' : 'LOGIN SERVICE' };
      const fn = scenes[route[scenario.id]] || scenes.generic, s = Math.min(w / W, h / H);
      c.save(); c.translate((w - W * s) / 2, (h - H * s) / 2); c.scale(s, s); c.lineWidth = 1;
      try { fn(clamp(ratio || 0), scen); } finally { c.restore(); c.textAlign = 'left'; c.textBaseline = 'alphabetic'; c.setLineDash([]); }
      return true;
    },
  };
})();
