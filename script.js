(function(){
  'use strict';

  // ---------- Theme Switcher ----------
  const root = document.documentElement;
  const btnDark = document.getElementById('btnDark');
  const btnLight = document.getElementById('btnLight');
  function setTheme(t){
    if(t==='light'){
      root.setAttribute('data-theme','light');
      btnLight.classList.add('active');
      btnDark.classList.remove('active');
      btnLight.setAttribute('aria-pressed','true');
      btnDark.setAttribute('aria-pressed','false');
    } else {
      root.removeAttribute('data-theme');
      btnDark.classList.add('active');
      btnLight.classList.remove('active');
      btnDark.setAttribute('aria-pressed','true');
      btnLight.setAttribute('aria-pressed','false');
    }
  }
  btnDark.onclick = () => setTheme('dark');
  btnLight.onclick = () => setTheme('light');

  // ---------- View Switcher (Transport / Application / Split) ----------
  const viewTabs = document.querySelectorAll('#viewTabs .vtab');
  const lanesContainer = document.getElementById('lanesContainer');
  let currentView = 'l4';

  viewTabs.forEach(tab => {
    tab.onclick = () => {
      viewTabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      currentView = tab.dataset.view;
      lanesContainer.className = 'view-mode-' + currentView;
      render();
    };
  });

  // ---------- Activity Switching ----------
  const tabs = document.querySelectorAll('.tabs .tab-btn');
  const forms = {browse:'form-browse', mail:'form-mail', stream:'form-stream'};
  const protoLabels = {
    browse: '— DNS (UDP) → TCP 3-Way Handshake → HTTP/1.1 → Teardown',
    mail: '— DNS MX (UDP) → TCP Handshake → SMTP Conversation → Teardown',
    stream: '— DNS (UDP) → HLS over TCP / Optional UDP RTP Stream'
  };
  let currentActivity = 'browse';

  tabs.forEach(t => {
    t.onclick = () => {
      tabs.forEach(x => x.classList.remove('active'));
      t.classList.add('active');
      currentActivity = t.dataset.act;
      Object.values(forms).forEach(id => document.getElementById(id).style.display = 'none');
      document.getElementById(forms[currentActivity]).style.display = 'block';
      document.getElementById('protoLabel').textContent = protoLabels[currentActivity];
    };
  });
  document.getElementById('protoLabel').textContent = protoLabels.browse;

  // Quality selector buttons
  document.querySelectorAll('#qualsel button').forEach(b => {
    b.onclick = () => {
      document.querySelectorAll('#qualsel button').forEach(x => x.classList.remove('active'));
      b.classList.add('active');
    };
  });

  // Protocol selector (TCP vs UDP for Streaming)
  let streamingProto = 'tcp';
  document.querySelectorAll('#protoSel button').forEach(b => {
    b.onclick = () => {
      document.querySelectorAll('#protoSel button').forEach(x => x.classList.remove('active'));
      b.classList.add('active');
      streamingProto = b.dataset.proto;
      log('streaming transport protocol switched to <b>' + streamingProto.toUpperCase() + '</b>');
    };
  });

  // Speed controls
  let stepIntervalMs = 850;
  document.querySelectorAll('#speedToggle button').forEach(b => {
    b.onclick = () => {
      document.querySelectorAll('#speedToggle button').forEach(x => x.classList.remove('active'));
      b.classList.add('active');
      stepIntervalMs = parseInt(b.dataset.speed, 10);
      if(playing){
        clearInterval(timer);
        timer = setInterval(runPlayLoop, stepIntervalMs);
      }
    };
  });

  // ---------- Activity Log & Status ----------
  const logBox = document.getElementById('logBox');
  const statusBadge = document.getElementById('statusBadge');
  function ts(){ return new Date().toLocaleTimeString([], {hour12:false}); }
  function log(msg){
    const d = document.createElement('div');
    d.innerHTML = '<span class="t">' + ts() + '</span>' + msg;
    logBox.prepend(d);
  }
  function setStatus(text, live){
    statusBadge.textContent = text;
    statusBadge.classList.toggle('live', !!live);
  }

  // ---------- Telemetry Bar Elements ----------
  const clientStatePill = document.getElementById('clientStatePill');
  const serverStatePill = document.getElementById('serverStatePill');
  const cwndVal = document.getElementById('cwndVal');
  const rwndVal = document.getElementById('rwndVal');
  const activePhase = document.getElementById('activePhase');

  function updateTelemetry(pkt){
    if(!pkt){
      clientStatePill.textContent = 'CLOSED';
      clientStatePill.className = 't-val state-pill closed';
      serverStatePill.textContent = 'LISTEN';
      serverStatePill.className = 't-val state-pill';
      cwndVal.textContent = '1 MSS';
      rwndVal.textContent = '64 KB';
      activePhase.textContent = 'Ready';
      return;
    }

    // Client state
    clientStatePill.textContent = pkt.clientState || 'CLOSED';
    clientStatePill.className = 't-val state-pill ' + getStateClass(pkt.clientState);

    // Server state
    serverStatePill.textContent = pkt.serverState || 'LISTEN';
    serverStatePill.className = 't-val state-pill ' + getStateClass(pkt.serverState);

    // Flow / Congestion metrics
    cwndVal.textContent = pkt.cwnd ? (pkt.cwnd + ' MSS') : 'N/A (UDP)';
    rwndVal.textContent = pkt.win ? (pkt.win.toLocaleString() + ' B') : '64 KB';
    activePhase.textContent = pkt.phase || pkt.summary || 'Executing';
  }

  function getStateClass(st){
    if(!st) return 'closed';
    st = st.toUpperCase();
    if(st.includes('SYN')) return 'syn-sent';
    if(st.includes('ESTABLISHED')) return 'established';
    if(st.includes('FIN') || st.includes('CLOSE') || st.includes('TIME_WAIT')) return 'fin-wait';
    if(st.includes('UDP')) return 'udp-mode';
    return 'closed';
  }

  // ---------- Helpers ----------
  function esc(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
  function hl(label, val){ return '<span class="field-hl">'+esc(label)+'</span> '+esc(val); }

  // ---------- Packet & Application Builders ----------

  /* 1. Browsing Exchange */
  function buildBrowsingScenario(host){
    host = host.replace(/^https?:\/\//,'').replace(/\/.*$/,'') || 'www.example.com';
    const ip = '203.0.113.' + (10 + (host.length % 40));
    const cPort = 52140;
    const sPort = 80;

    // L7 Application Steps
    const l7 = [
      { id: 0, title: 'DNS Resolution', dir: 'c2s', head: 'DNS Query (A Record)', lines: [hl('Host:', host), hl('Type:', 'A (IPv4)'), hl('Resolver:', '8.8.8.8:53 (UDP)')] },
      { id: 1, title: 'DNS Resolution', dir: 's2c', head: 'DNS Response', lines: [hl('Answer:', host + ' → ' + ip), hl('TTL:', '300s'), hl('RCODE:', 'NOERROR')] },
      { id: 2, title: 'TCP Connection Setup', dir: 'c2s', head: 'TCP 3-Way Handshake', lines: [hl('Action:', 'Synchronize ISN & negotiate MSS/Window scaling'), hl('Endpoints:', '192.168.1.100:'+cPort+' ↔ '+ip+':80')] },
      { id: 3, title: 'HTTP Request', dir: 'c2s', head: 'HTTP GET / HTTP/1.1', lines: [hl('Request-Line:', 'GET / HTTP/1.1'), hl('Host:', host), hl('User-Agent:', 'Wireline/2.0 (Dual-Panel L4/L7)'), hl('Accept:', 'text/html'), hl('Connection:', 'keep-alive')] },
      { id: 4, title: 'HTTP Response Headers & Content', dir: 's2c', head: 'HTTP/1.1 200 OK', lines: [hl('Status:', '200 OK'), hl('Content-Type:', 'text/html; charset=utf-8'), hl('Content-Length:', '2440 bytes'), hl('Body:', '<!DOCTYPE html><html><head><title>Example</title>...</html>')] },
      { id: 5, title: 'TCP Teardown', dir: 'c2s', head: 'TCP Connection Teardown (FIN/ACK)', lines: [hl('Action:', 'Graceful bidirectional 4-way connection release'), hl('Final State:', 'Client TIME_WAIT (2MSL) → CLOSED')] }
    ];

    // L4 Transport Packets
    const l4 = [
      // 0. DNS Query
      {
        proto: 'UDP', dir: 'c2s', srcPort: cPort, dstPort: 53,
        flags: ['UDP'], len: 34, seq: null, ack: null, win: null,
        time: '+0.0 ms', summary: 'DNS Query: ' + host + ' A',
        phase: 'DNS Lookup (UDP/53)',
        clientState: 'CLOSED', serverState: 'LISTEN', cwnd: 1,
        l7Index: 0,
        explanation: 'DNS uses connectionless UDP datagrams on port 53 for low latency. No 3-way handshake or sequence numbers required.',
        payloadPreview: 'Transaction ID: 0x4a12, Flags: Standard Query, Questions: ' + host + ' IN A'
      },
      // 1. DNS Response
      {
        proto: 'UDP', dir: 's2c', srcPort: 53, dstPort: cPort,
        flags: ['UDP'], len: 50, seq: null, ack: null, win: null,
        time: '+18.2 ms', summary: 'DNS Response: ' + host + ' → ' + ip,
        phase: 'DNS Lookup (UDP/53)',
        clientState: 'CLOSED', serverState: 'LISTEN', cwnd: 1,
        l7Index: 1,
        explanation: 'DNS server returns IP address 203.0.113.' + (10 + (host.length % 40)) + '. The browser can now initiate a reliable TCP connection to port 80.',
        payloadPreview: 'Answers: ' + host + ' A ' + ip + ' (TTL 300s)'
      },
      // 2. TCP SYN
      {
        proto: 'TCP', dir: 'c2s', srcPort: cPort, dstPort: sPort,
        flags: ['SYN'], len: 0, seq: 1000, ack: 0, win: 64240,
        time: '+22.5 ms', summary: '[SYN] Client Handshake Initiate',
        phase: 'TCP Handshake (1/3)',
        clientState: 'SYN_SENT', serverState: 'LISTEN', cwnd: 1,
        l7Index: 2,
        explanation: 'Client sends SYN with Initial Sequence Number (ISN_c = 1000). SYN consumes 1 phantom sequence number byte. Window size advertised = 64240 bytes.',
        payloadPreview: 'MSS=1460, SACK_PERM=1, WS=7 (Scale factor 128)'
      },
      // 3. TCP SYN-ACK
      {
        proto: 'TCP', dir: 's2c', srcPort: sPort, dstPort: cPort,
        flags: ['SYN', 'ACK'], len: 0, seq: 4000, ack: 1001, win: 65535,
        time: '+38.7 ms', summary: '[SYN, ACK] Server Handshake Reply',
        phase: 'TCP Handshake (2/3)',
        clientState: 'SYN_SENT', serverState: 'SYN_RCVD', cwnd: 1,
        l7Index: 2,
        explanation: 'Server sends SYN with its own ISN_s = 4000, and acknowledges client SYN by setting Ack = 1000 + 1 = 1001. Server transitions to SYN_RCVD.',
        payloadPreview: 'MSS=1460, SACK_PERM=1, WS=8 (Scale factor 256)'
      },
      // 4. TCP ACK
      {
        proto: 'TCP', dir: 'c2s', srcPort: cPort, dstPort: sPort,
        flags: ['ACK'], len: 0, seq: 1001, ack: 4001, win: 64240,
        time: '+41.2 ms', summary: '[ACK] Handshake Complete (ESTABLISHED)',
        phase: 'TCP Handshake (3/3)',
        clientState: 'ESTABLISHED', serverState: 'ESTABLISHED', cwnd: 2,
        l7Index: 2,
        explanation: 'Client ACKs server SYN: Ack = 4000 + 1 = 4001. Both endpoints are now in ESTABLISHED state. Reliable full-duplex byte-stream is open.',
        payloadPreview: 'Connection established. Ready for L7 application payload.'
      },
      // 5. HTTP GET (PSH, ACK)
      {
        proto: 'TCP', dir: 'c2s', srcPort: cPort, dstPort: sPort,
        flags: ['PSH', 'ACK'], len: 185, seq: 1001, ack: 4001, win: 64240,
        time: '+43.0 ms', summary: '[PSH, ACK] HTTP GET Request',
        phase: 'HTTP Data Transfer',
        clientState: 'ESTABLISHED', serverState: 'ESTABLISHED', cwnd: 2,
        l7Index: 3,
        explanation: 'Client sends 185 bytes of HTTP GET request data. PSH flag instructs the receiver to push data immediately to the application layer. Next expected Seq from client will be 1001 + 185 = 1186.',
        payloadPreview: 'GET / HTTP/1.1\\r\\nHost: ' + host + '\\r\\nUser-Agent: Wireline/2.0\\r\\n\\r\\n'
      },
      // 6. Server ACK of HTTP GET
      {
        proto: 'TCP', dir: 's2c', srcPort: sPort, dstPort: cPort,
        flags: ['ACK'], len: 0, seq: 4001, ack: 1186, win: 65535,
        time: '+57.1 ms', summary: '[ACK] Server confirms HTTP GET',
        phase: 'HTTP Data Transfer',
        clientState: 'ESTABLISHED', serverState: 'ESTABLISHED', cwnd: 3,
        l7Index: 3,
        explanation: 'Server sends pure ACK (Len=0). Ack = 1001 + 185 = 1186, acknowledging all 185 bytes of the HTTP GET request.',
        payloadPreview: 'Cumulative ACK confirming bytes [1001..1185]'
      },
      // 7. Server HTTP Response Chunk 1 (PSH, ACK)
      {
        proto: 'TCP', dir: 's2c', srcPort: sPort, dstPort: cPort,
        flags: ['PSH', 'ACK'], len: 1460, seq: 4001, ack: 1186, win: 65535,
        time: '+62.4 ms', summary: '[PSH, ACK] HTTP 200 OK + Body Chunk 1',
        phase: 'HTTP Response Transfer',
        clientState: 'ESTABLISHED', serverState: 'ESTABLISHED', cwnd: 4,
        l7Index: 4,
        explanation: 'Server transmits 1460 bytes (1 full MSS) containing HTTP/1.1 200 OK headers and HTML markup. Seq = 4001. Next expected Ack = 4001 + 1460 = 5461.',
        payloadPreview: 'HTTP/1.1 200 OK\\r\\nContent-Type: text/html\\r\\nContent-Length: 2440\\r\\n\\r\\n<!DOCTYPE html><html>...'
      },
      // 8. Client ACK Chunk 1
      {
        proto: 'TCP', dir: 'c2s', srcPort: cPort, dstPort: sPort,
        flags: ['ACK'], len: 0, seq: 1186, ack: 5461, win: 64240,
        time: '+64.0 ms', summary: '[ACK] Client confirms Chunk 1',
        phase: 'HTTP Response Transfer',
        clientState: 'ESTABLISHED', serverState: 'ESTABLISHED', cwnd: 5,
        l7Index: 4,
        explanation: 'Client cumulative ACK confirms receipt of bytes [4001..5460]. Requests byte 5461 next.',
        payloadPreview: 'Cumulative ACK for chunk 1 (1460 bytes)'
      },
      // 9. Server HTTP Response Chunk 2 (PSH, ACK)
      {
        proto: 'TCP', dir: 's2c', srcPort: sPort, dstPort: cPort,
        flags: ['PSH', 'ACK'], len: 980, seq: 5461, ack: 1186, win: 65535,
        time: '+66.8 ms', summary: '[PSH, ACK] HTTP Response Chunk 2 (Final)',
        phase: 'HTTP Response Transfer',
        clientState: 'ESTABLISHED', serverState: 'ESTABLISHED', cwnd: 6,
        l7Index: 4,
        explanation: 'Server transmits remaining 980 bytes of HTML document. Seq = 5461, Len = 980. Next expected Ack = 5461 + 980 = 6441.',
        payloadPreview: '<div class="content">Welcome to ' + host + '</div></body></html>'
      },
      // 10. Client ACK Chunk 2
      {
        proto: 'TCP', dir: 'c2s', srcPort: cPort, dstPort: sPort,
        flags: ['ACK'], len: 0, seq: 1186, ack: 6441, win: 64240,
        time: '+68.5 ms', summary: '[ACK] Client confirms Chunk 2',
        phase: 'HTTP Response Complete',
        clientState: 'ESTABLISHED', serverState: 'ESTABLISHED', cwnd: 6,
        l7Index: 4,
        explanation: 'Client sends ACK confirming all 2440 bytes of HTTP response. Full HTML page is rendered in the browser DOM.',
        payloadPreview: 'Payload download complete. Rendering page.'
      },
      // 11. Client initiates FIN
      {
        proto: 'TCP', dir: 'c2s', srcPort: cPort, dstPort: sPort,
        flags: ['FIN', 'ACK'], len: 0, seq: 1186, ack: 6441, win: 64240,
        time: '+85.0 ms', summary: '[FIN, ACK] Client Closes Send Channel',
        phase: 'TCP Teardown (1/4)',
        clientState: 'FIN_WAIT_1', serverState: 'CLOSE_WAIT', cwnd: 6,
        l7Index: 5,
        explanation: 'Client finishes transmission and sends FIN. FIN consumes 1 sequence number byte. Client transitions to FIN_WAIT_1; Server transitions to CLOSE_WAIT.',
        payloadPreview: 'Client teardown initiation: Seq 1186, Ack 6441'
      },
      // 12. Server ACK of Client FIN
      {
        proto: 'TCP', dir: 's2c', srcPort: sPort, dstPort: cPort,
        flags: ['ACK'], len: 0, seq: 6441, ack: 1187, win: 65535,
        time: '+98.2 ms', summary: '[ACK] Server confirms Client FIN',
        phase: 'TCP Teardown (2/4)',
        clientState: 'FIN_WAIT_2', serverState: 'CLOSE_WAIT', cwnd: 6,
        l7Index: 5,
        explanation: 'Server ACKs client FIN: Ack = 1186 + 1 = 1187. Client enters FIN_WAIT_2 (waiting for server FIN). Server enters CLOSE_WAIT.',
        payloadPreview: 'Server acknowledges half-close.'
      },
      // 13. Server sends FIN
      {
        proto: 'TCP', dir: 's2c', srcPort: sPort, dstPort: cPort,
        flags: ['FIN', 'ACK'], len: 0, seq: 6441, ack: 1187, win: 65535,
        time: '+104.5 ms', summary: '[FIN, ACK] Server Closes Send Channel',
        phase: 'TCP Teardown (3/4)',
        clientState: 'TIME_WAIT', serverState: 'LAST_ACK', cwnd: 6,
        l7Index: 5,
        explanation: 'Server finishes background cleanup and sends its own FIN. Seq = 6441. Server enters LAST_ACK; Client enters TIME_WAIT.',
        payloadPreview: 'Server final FIN transmission.'
      },
      // 14. Client ACK of Server FIN
      {
        proto: 'TCP', dir: 'c2s', srcPort: cPort, dstPort: sPort,
        flags: ['ACK'], len: 0, seq: 1187, ack: 6442, win: 64240,
        time: '+106.1 ms', summary: '[ACK] Client Final ACK (CLOSED)',
        phase: 'TCP Teardown (4/4)',
        clientState: 'TIME_WAIT', serverState: 'CLOSED', cwnd: 6,
        l7Index: 5,
        explanation: 'Client sends final ACK: Ack = 6441 + 1 = 6442. Server transitions to CLOSED immediately. Client remains in TIME_WAIT for 2MSL (Maximum Segment Lifetime) to absorb wandering duplicate packets before closing.',
        payloadPreview: 'Connection closed successfully. Byte-stream finished.'
      }
    ];

    return { l7, l4 };
  }

  /* 2. Mail Scenario (SMTP over TCP) */
  function buildMailScenario(to, subject, body){
    const domain = (to.split('@')[1] || 'mailhost.net');
    const cPort = 53890;
    const sPort = 25;

    // L7 Application Steps
    const l7 = [
      { id: 0, title: 'DNS MX Lookup', dir: 'c2s', head: 'DNS MX Query', lines: [hl('Domain:', domain), hl('Record Type:', 'MX (Mail Exchanger)'), hl('Transport:', 'UDP/53')] },
      { id: 1, title: 'DNS MX Response', dir: 's2c', head: 'DNS MX Answer', lines: [hl('Mail Server:', 'mail.' + domain), hl('Preference:', '10'), hl('Host IP:', '198.51.100.25')] },
      { id: 2, title: 'TCP Connection Setup', dir: 'c2s', head: 'TCP 3-Way Handshake (Port 25)', lines: [hl('Target:', 'mail.' + domain + ':25'), hl('Protocol:', 'TCP reliable stream')] },
      { id: 3, title: 'SMTP Server Banner', dir: 's2c', head: 'SMTP 220 Greeting Banner', lines: [hl('Reply-Code:', '220'), hl('Banner:', '220 mail.' + domain + ' ESMTP Wireline-Postfix ready')] },
      { id: 4, title: 'SMTP EHLO Handshake', dir: 'c2s', head: 'SMTP EHLO Handshake', lines: [hl('Client Command:', 'EHLO client.local'), hl('Server Reply:', '250-mail.' + domain + ' Hello / 250 8BITMIME / 250 SIZE 35882400')] },
      { id: 5, title: 'SMTP Envelope (MAIL FROM & RCPT TO)', dir: 'c2s', head: 'SMTP Envelope Addressing', lines: [hl('MAIL FROM:', '<sender@client.local> → 250 2.1.0 OK'), hl('RCPT TO:', '<' + to + '> → 250 2.1.5 Recipient OK')] },
      { id: 6, title: 'SMTP DATA Transfer', dir: 'c2s', head: 'SMTP DATA Message Body', lines: [hl('Command:', 'DATA → 354 Start mail input; end with <CRLF>.<CRLF>'), hl('Subject:', subject), hl('Body:', body.slice(0, 36) + (body.length > 36 ? '…' : '')), hl('Result:', '250 2.0.0 Message queued for delivery')] },
      { id: 7, title: 'SMTP Session Termination', dir: 'c2s', head: 'SMTP QUIT & Teardown', lines: [hl('Client:', 'QUIT → 221 2.0.0 Bye'), hl('Teardown:', 'TCP 4-way FIN/ACK connection release')] }
    ];

    // L4 Transport Packets
    let cSeq = 2000;
    let sSeq = 7000;

    const l4 = [
      // DNS MX
      {
        proto: 'UDP', dir: 'c2s', srcPort: cPort, dstPort: 53,
        flags: ['UDP'], len: 38, seq: null, ack: null, win: null,
        time: '+0.0 ms', summary: 'DNS Query: ' + domain + ' MX',
        phase: 'DNS MX Lookup (UDP/53)',
        clientState: 'CLOSED', serverState: 'LISTEN', cwnd: 1,
        l7Index: 0,
        explanation: 'Client sends UDP query on port 53 to locate MX mail exchangers for ' + domain + '.',
        payloadPreview: 'MX query for ' + domain
      },
      {
        proto: 'UDP', dir: 's2c', srcPort: 53, dstPort: cPort,
        flags: ['UDP'], len: 54, seq: null, ack: null, win: null,
        time: '+16.4 ms', summary: 'DNS Answer: mail.' + domain + ' (pref 10)',
        phase: 'DNS MX Lookup (UDP/53)',
        clientState: 'CLOSED', serverState: 'LISTEN', cwnd: 1,
        l7Index: 1,
        explanation: 'DNS resolves MX record to mail.' + domain + ' (198.51.100.25). Client now opens a TCP socket to port 25.',
        payloadPreview: 'Answer: mail.' + domain + ' Priority: 10'
      },
      // TCP SYN
      {
        proto: 'TCP', dir: 'c2s', srcPort: cPort, dstPort: sPort,
        flags: ['SYN'], len: 0, seq: cSeq, ack: 0, win: 64240,
        time: '+20.1 ms', summary: '[SYN] Port 25 SMTP Connect',
        phase: 'TCP Handshake (1/3)',
        clientState: 'SYN_SENT', serverState: 'LISTEN', cwnd: 1,
        l7Index: 2,
        explanation: 'Client initiates TCP handshake to mail server port 25. ISN_c = ' + cSeq + '.',
        payloadPreview: 'SYN flag set, MSS=1460'
      }
    ];

    // SYN-ACK
    cSeq += 1;
    l4.push({
      proto: 'TCP', dir: 's2c', srcPort: sPort, dstPort: cPort,
      flags: ['SYN', 'ACK'], len: 0, seq: sSeq, ack: cSeq, win: 65535,
      time: '+35.5 ms', summary: '[SYN, ACK] Server Handshake Reply',
      phase: 'TCP Handshake (2/3)',
      clientState: 'SYN_SENT', serverState: 'SYN_RCVD', cwnd: 1,
      l7Index: 2,
      explanation: 'Mail server sends SYN with ISN_s = ' + sSeq + ', acknowledging client SYN (Ack = ' + cSeq + ').',
      payloadPreview: 'SYN+ACK, Window=65535'
    });

    // ACK
    sSeq += 1;
    l4.push({
      proto: 'TCP', dir: 'c2s', srcPort: cPort, dstPort: sPort,
      flags: ['ACK'], len: 0, seq: cSeq, ack: sSeq, win: 64240,
      time: '+37.2 ms', summary: '[ACK] TCP Handshake Complete',
      phase: 'TCP Handshake (3/3)',
      clientState: 'ESTABLISHED', serverState: 'ESTABLISHED', cwnd: 2,
      l7Index: 2,
      explanation: 'Client sends ACK (Ack = ' + sSeq + '). Connection ESTABLISHED. In SMTP, the server speaks first with a 220 banner.',
      payloadPreview: 'ESTABLISHED socket on port 25.'
    });

    // Server sends 220 banner
    const banner = '220 mail.' + domain + ' ESMTP ready\\r\\n';
    const bannerLen = 42;
    l4.push({
      proto: 'TCP', dir: 's2c', srcPort: sPort, dstPort: cPort,
      flags: ['PSH', 'ACK'], len: bannerLen, seq: sSeq, ack: cSeq, win: 65535,
      time: '+42.0 ms', summary: '[PSH, ACK] SMTP 220 Greeting Banner',
      phase: 'SMTP Greeting',
      clientState: 'ESTABLISHED', serverState: 'ESTABLISHED', cwnd: 2,
      l7Index: 3,
      explanation: 'Server transmits 42 bytes containing SMTP 220 banner. PSH flag ensures immediate delivery to client mail agent.',
      payloadPreview: banner
    });
    sSeq += bannerLen;

    // Client ACK banner + sends EHLO
    const ehlo = 'EHLO client.local\\r\\n';
    const ehloLen = 19;
    l4.push({
      proto: 'TCP', dir: 'c2s', srcPort: cPort, dstPort: sPort,
      flags: ['PSH', 'ACK'], len: ehloLen, seq: cSeq, ack: sSeq, win: 64240,
      time: '+48.3 ms', summary: '[PSH, ACK] SMTP: EHLO client.local',
      phase: 'SMTP EHLO Negotiation',
      clientState: 'ESTABLISHED', serverState: 'ESTABLISHED', cwnd: 2,
      l7Index: 4,
      explanation: 'Client piggybacks ACK of banner (Ack = ' + sSeq + ') with 19 bytes of EHLO command.',
      payloadPreview: ehlo
    });
    cSeq += ehloLen;

    // Server sends 250 response
    const ehloReply = '250-mail.' + domain + ' Hello\\r\\n250 8BITMIME\\r\\n';
    const ehloReplyLen = 48;
    l4.push({
      proto: 'TCP', dir: 's2c', srcPort: sPort, dstPort: cPort,
      flags: ['PSH', 'ACK'], len: ehloReplyLen, seq: sSeq, ack: cSeq, win: 65535,
      time: '+62.8 ms', summary: '[PSH, ACK] SMTP: 250 EHLO OK',
      phase: 'SMTP EHLO Negotiation',
      clientState: 'ESTABLISHED', serverState: 'ESTABLISHED', cwnd: 3,
      l7Index: 4,
      explanation: 'Server confirms EHLO and advertises supported ESMTP extensions (8BITMIME, SIZE, PIPELINING).',
      payloadPreview: ehloReply
    });
    sSeq += ehloReplyLen;

    // Client MAIL FROM
    const mailFrom = 'MAIL FROM:<sender@client.local>\\r\\n';
    const mfLen = 33;
    l4.push({
      proto: 'TCP', dir: 'c2s', srcPort: cPort, dstPort: sPort,
      flags: ['PSH', 'ACK'], len: mfLen, seq: cSeq, ack: sSeq, win: 64240,
      time: '+69.2 ms', summary: '[PSH, ACK] SMTP: MAIL FROM',
      phase: 'SMTP Envelope',
      clientState: 'ESTABLISHED', serverState: 'ESTABLISHED', cwnd: 3,
      l7Index: 5,
      explanation: 'Client sets envelope sender. Seq = ' + cSeq + ', Len = ' + mfLen + '.',
      payloadPreview: mailFrom
    });
    cSeq += mfLen;

    // Server 250 OK
    const mfOk = '250 2.1.0 Sender OK\\r\\n';
    const mfOkLen = 22;
    l4.push({
      proto: 'TCP', dir: 's2c', srcPort: sPort, dstPort: cPort,
      flags: ['PSH', 'ACK'], len: mfOkLen, seq: sSeq, ack: cSeq, win: 65535,
      time: '+81.4 ms', summary: '[PSH, ACK] SMTP: 250 Sender OK',
      phase: 'SMTP Envelope',
      clientState: 'ESTABLISHED', serverState: 'ESTABLISHED', cwnd: 3,
      l7Index: 5,
      explanation: 'Server confirms sender envelope address validity.',
      payloadPreview: mfOk
    });
    sSeq += mfOkLen;

    // Client RCPT TO
    const rcptTo = 'RCPT TO:<' + to + '>\\r\\n';
    const rcptLen = rcptTo.length;
    l4.push({
      proto: 'TCP', dir: 'c2s', srcPort: cPort, dstPort: sPort,
      flags: ['PSH', 'ACK'], len: rcptLen, seq: cSeq, ack: sSeq, win: 64240,
      time: '+87.0 ms', summary: '[PSH, ACK] SMTP: RCPT TO',
      phase: 'SMTP Envelope',
      clientState: 'ESTABLISHED', serverState: 'ESTABLISHED', cwnd: 3,
      l7Index: 5,
      explanation: 'Client sets recipient mailbox. Seq = ' + cSeq + ', Len = ' + rcptLen + '.',
      payloadPreview: rcptTo
    });
    cSeq += rcptLen;

    // Server 250 Accepted
    const rcptOk = '250 2.1.5 Recipient OK\\r\\n';
    const rcptOkLen = 25;
    l4.push({
      proto: 'TCP', dir: 's2c', srcPort: sPort, dstPort: cPort,
      flags: ['PSH', 'ACK'], len: rcptOkLen, seq: sSeq, ack: cSeq, win: 65535,
      time: '+99.2 ms', summary: '[PSH, ACK] SMTP: 250 Recipient Accepted',
      phase: 'SMTP Envelope',
      clientState: 'ESTABLISHED', serverState: 'ESTABLISHED', cwnd: 3,
      l7Index: 5,
      explanation: 'Server accepts the recipient mailbox.',
      payloadPreview: rcptOk
    });
    sSeq += rcptOkLen;

    // Client DATA command
    const dataCmd = 'DATA\\r\\n';
    const dataCmdLen = 6;
    l4.push({
      proto: 'TCP', dir: 'c2s', srcPort: cPort, dstPort: sPort,
      flags: ['PSH', 'ACK'], len: dataCmdLen, seq: cSeq, ack: sSeq, win: 64240,
      time: '+105.1 ms', summary: '[PSH, ACK] SMTP: DATA Command',
      phase: 'SMTP Data Mode',
      clientState: 'ESTABLISHED', serverState: 'ESTABLISHED', cwnd: 3,
      l7Index: 6,
      explanation: 'Client requests transition to mail content transmission mode.',
      payloadPreview: dataCmd
    });
    cSeq += dataCmdLen;

    // Server 354 Start Mail
    const s354 = '354 Start mail input; end with <CRLF>.<CRLF>\\r\\n';
    const s354Len = 46;
    l4.push({
      proto: 'TCP', dir: 's2c', srcPort: sPort, dstPort: cPort,
      flags: ['PSH', 'ACK'], len: s354Len, seq: sSeq, ack: cSeq, win: 65535,
      time: '+117.3 ms', summary: '[PSH, ACK] SMTP: 354 Start Input',
      phase: 'SMTP Data Mode',
      clientState: 'ESTABLISHED', serverState: 'ESTABLISHED', cwnd: 3,
      l7Index: 6,
      explanation: 'Server grants permission to send body bytes, terminated by a dot on its own line.',
      payloadPreview: s354
    });
    sSeq += s354Len;

    // Client sends mail body
    const mailPayload = 'Subject: ' + subject + '\\r\\n\\r\\n' + body + '\\r\\n.\\r\\n';
    const bodyLen = 140;
    l4.push({
      proto: 'TCP', dir: 'c2s', srcPort: cPort, dstPort: sPort,
      flags: ['PSH', 'ACK'], len: bodyLen, seq: cSeq, ack: sSeq, win: 64240,
      time: '+124.0 ms', summary: '[PSH, ACK] SMTP: Body + <CRLF>.<CRLF>',
      phase: 'SMTP Message Payload',
      clientState: 'ESTABLISHED', serverState: 'ESTABLISHED', cwnd: 4,
      l7Index: 6,
      explanation: 'Client streams 140 bytes of mail headers, subject, body, and the terminal dot indicator.',
      payloadPreview: mailPayload
    });
    cSeq += bodyLen;

    // Server 250 Message queued
    const sQueued = '250 2.0.0 OK: queued as 7F4A21\\r\\n';
    const sQLen = 32;
    l4.push({
      proto: 'TCP', dir: 's2c', srcPort: sPort, dstPort: cPort,
      flags: ['PSH', 'ACK'], len: sQLen, seq: sSeq, ack: cSeq, win: 65535,
      time: '+142.5 ms', summary: '[PSH, ACK] SMTP: 250 Message Queued',
      phase: 'SMTP Complete',
      clientState: 'ESTABLISHED', serverState: 'ESTABLISHED', cwnd: 4,
      l7Index: 6,
      explanation: 'Server persists mail to spool queue and responds with 250 OK queue identifier.',
      payloadPreview: sQueued
    });
    sSeq += sQLen;

    // Client QUIT
    const quitCmd = 'QUIT\\r\\n';
    const quitLen = 6;
    l4.push({
      proto: 'TCP', dir: 'c2s', srcPort: cPort, dstPort: sPort,
      flags: ['PSH', 'ACK'], len: quitLen, seq: cSeq, ack: sSeq, win: 64240,
      time: '+148.0 ms', summary: '[PSH, ACK] SMTP: QUIT',
      phase: 'SMTP Session Close',
      clientState: 'ESTABLISHED', serverState: 'ESTABLISHED', cwnd: 4,
      l7Index: 7,
      explanation: 'Client terminates SMTP session cleanly by sending QUIT command.',
      payloadPreview: quitCmd
    });
    cSeq += quitLen;

    // Server 221 Bye
    const byeReply = '221 2.0.0 Bye\\r\\n';
    const byeLen = 15;
    l4.push({
      proto: 'TCP', dir: 's2c', srcPort: sPort, dstPort: cPort,
      flags: ['PSH', 'ACK'], len: byeLen, seq: sSeq, ack: cSeq, win: 65535,
      time: '+156.4 ms', summary: '[PSH, ACK] SMTP: 221 Bye',
      phase: 'SMTP Session Close',
      clientState: 'ESTABLISHED', serverState: 'ESTABLISHED', cwnd: 4,
      l7Index: 7,
      explanation: 'Server confirms session termination with 221 Bye.',
      payloadPreview: byeReply
    });
    sSeq += byeLen;

    // TCP Teardown: Client FIN
    l4.push({
      proto: 'TCP', dir: 'c2s', srcPort: cPort, dstPort: sPort,
      flags: ['FIN', 'ACK'], len: 0, seq: cSeq, ack: sSeq, win: 64240,
      time: '+161.0 ms', summary: '[FIN, ACK] Client Teardown Initiate',
      phase: 'TCP Teardown (1/4)',
      clientState: 'FIN_WAIT_1', serverState: 'CLOSE_WAIT', cwnd: 4,
      l7Index: 7,
      explanation: 'Client initiates TCP 4-way teardown. Client enters FIN_WAIT_1.',
      payloadPreview: 'FIN flag set. Sequence byte consumed = 1.'
    });
    cSeq += 1;

    // Server ACK
    l4.push({
      proto: 'TCP', dir: 's2c', srcPort: sPort, dstPort: cPort,
      flags: ['ACK'], len: 0, seq: sSeq, ack: cSeq, win: 65535,
      time: '+172.5 ms', summary: '[ACK] Server Confirms Client FIN',
      phase: 'TCP Teardown (2/4)',
      clientState: 'FIN_WAIT_2', serverState: 'CLOSE_WAIT', cwnd: 4,
      l7Index: 7,
      explanation: 'Server ACKs client FIN. Client enters FIN_WAIT_2.',
      payloadPreview: 'Ack confirms client FIN.'
    });

    // Server FIN
    l4.push({
      proto: 'TCP', dir: 's2c', srcPort: sPort, dstPort: cPort,
      flags: ['FIN', 'ACK'], len: 0, seq: sSeq, ack: cSeq, win: 65535,
      time: '+176.8 ms', summary: '[FIN, ACK] Server Teardown Reply',
      phase: 'TCP Teardown (3/4)',
      clientState: 'TIME_WAIT', serverState: 'LAST_ACK', cwnd: 4,
      l7Index: 7,
      explanation: 'Server sends FIN to close its half of the socket. Server enters LAST_ACK; Client enters TIME_WAIT.',
      payloadPreview: 'Server FIN transmitted.'
    });
    sSeq += 1;

    // Client final ACK
    l4.push({
      proto: 'TCP', dir: 'c2s', srcPort: cPort, dstPort: sPort,
      flags: ['ACK'], len: 0, seq: cSeq, ack: sSeq, win: 64240,
      time: '+179.0 ms', summary: '[ACK] Client Final ACK (CLOSED)',
      phase: 'TCP Teardown (4/4)',
      clientState: 'TIME_WAIT', serverState: 'CLOSED', cwnd: 4,
      l7Index: 7,
      explanation: 'Client confirms server FIN. Server socket closed. Client holds 2MSL timer in TIME_WAIT before socket release.',
      payloadPreview: 'Connection teardown complete.'
    });

    return { l7, l4 };
  }

  /* 3. Streaming Scenario (TCP HLS vs UDP Live RTP) */
  function buildStreamingScenario(quality, proto){
    const cdnHost = 'cdn.streamhost.net';
    const cdnIp = '198.51.100.7';
    const cPort = 54900;
    const sPort = proto === 'udp' ? 5004 : 443;

    if(proto === 'udp'){
      // UDP RTP Streaming Mode
      const l7 = [
        { id: 0, title: 'DNS Resolution', dir: 'c2s', head: 'DNS Query (CDN Host)', lines: [hl('Host:', cdnHost), hl('Type:', 'A'), hl('Transport:', 'UDP/53')] },
        { id: 1, title: 'DNS Resolution', dir: 's2c', head: 'DNS Response', lines: [hl('Resolved IP:', cdnIp), hl('TTL:', '60s')] },
        { id: 2, title: 'RTP Session Request', dir: 'c2s', head: 'UDP RTSP / RTP Setup', lines: [hl('Request:', 'SETUP rtsp://'+cdnHost+'/live/'+quality), hl('Transport:', 'RTP/AVP/UDP;unicast;client_port=5004-5005')] },
        { id: 3, title: 'RTP Media Datagrams', dir: 's2c', head: 'Real-Time UDP Datagrams (' + quality + ')', lines: [hl('Format:', 'H.264 Video + AAC Audio RTP Packets'), hl('Characteristics:', 'Stateless datagram delivery, 0 RTT setup, zero retransmission delay, loss-tolerant live streaming')] }
      ];

      const l4 = [
        // DNS Query
        {
          proto: 'UDP', dir: 'c2s', srcPort: cPort, dstPort: 53,
          flags: ['UDP'], len: 36, seq: null, ack: null, win: null,
          time: '+0.0 ms', summary: 'DNS Query: ' + cdnHost,
          phase: 'DNS Lookup (UDP/53)',
          clientState: 'UDP_ACTIVE', serverState: 'UDP_ACTIVE', cwnd: null,
          l7Index: 0,
          explanation: 'Standard connectionless DNS query for CDN streaming edge.',
          payloadPreview: 'QNAME: ' + cdnHost + ' (UDP port 53)'
        },
        // DNS Response
        {
          proto: 'UDP', dir: 's2c', srcPort: 53, dstPort: cPort,
          flags: ['UDP'], len: 52, seq: null, ack: null, win: null,
          time: '+14.5 ms', summary: 'DNS Response: ' + cdnHost + ' → ' + cdnIp,
          phase: 'DNS Lookup (UDP/53)',
          clientState: 'UDP_ACTIVE', serverState: 'UDP_ACTIVE', cwnd: null,
          l7Index: 1,
          explanation: 'DNS returns CDN edge IP ' + cdnIp + '.',
          payloadPreview: 'Answer: ' + cdnHost + ' → ' + cdnIp
        },
        // RTSP / Session Setup over UDP
        {
          proto: 'UDP', dir: 'c2s', srcPort: cPort, dstPort: sPort,
          flags: ['UDP'], len: 142, seq: null, ack: null, win: null,
          time: '+18.0 ms', summary: 'UDP Session Setup (RTSP PLAY)',
          phase: 'UDP Session Initiation',
          clientState: 'UDP_ACTIVE', serverState: 'UDP_ACTIVE', cwnd: null,
          l7Index: 2,
          explanation: 'Client sends session setup command in a lightweight UDP datagram to port 5004. No TCP 3-way handshake required (0-RTT connection start!).',
          payloadPreview: 'SETUP rtsp://' + cdnHost + '/live/' + quality + ' RTP/AVP/UDP'
        },
        // RTP Datagram 1
        {
          proto: 'UDP', dir: 's2c', srcPort: sPort, dstPort: cPort,
          flags: ['UDP'], len: 1316, seq: null, ack: null, win: null,
          time: '+22.5 ms', summary: 'RTP Datagram 1: SPS/PPS Video Header',
          phase: 'UDP Real-Time Media Stream',
          clientState: 'UDP_STREAMING', serverState: 'UDP_STREAMING', cwnd: null,
          l7Index: 3,
          explanation: 'Media server immediately transmits 1316-byte RTP video header datagram. Header overhead is only 8 bytes (vs 20-60 bytes for TCP).',
          payloadPreview: 'RTP v2: PT=96 (H.264), Seq=3101, Timestamp=90000, SPS/PPS NALU'
        },
        // RTP Datagram 2
        {
          proto: 'UDP', dir: 's2c', srcPort: sPort, dstPort: cPort,
          flags: ['UDP'], len: 1316, seq: null, ack: null, win: null,
          time: '+24.1 ms', summary: 'RTP Datagram 2: I-Frame Keyframe slice 1',
          phase: 'UDP Real-Time Media Stream',
          clientState: 'UDP_STREAMING', serverState: 'UDP_STREAMING', cwnd: null,
          l7Index: 3,
          explanation: 'Video Keyframe (IDR) payload slice. In UDP, no cumulative ACK is expected. If lost, client decodes around it without head-of-line blocking!',
          payloadPreview: 'RTP v2: PT=96 (H.264), Seq=3102, Timestamp=90000, IDR Slice'
        },
        // RTP Datagram 3
        {
          proto: 'UDP', dir: 's2c', srcPort: sPort, dstPort: cPort,
          flags: ['UDP'], len: 1316, seq: null, ack: null, win: null,
          time: '+26.8 ms', summary: 'RTP Datagram 3: I-Frame Keyframe slice 2',
          phase: 'UDP Real-Time Media Stream',
          clientState: 'UDP_STREAMING', serverState: 'UDP_STREAMING', cwnd: null,
          l7Index: 3,
          explanation: 'Consecutive video packet. Jitter buffer on the client re-assembles frames at exact rendering timestamp.',
          payloadPreview: 'RTP v2: PT=96 (H.264), Seq=3103, Timestamp=90000, Slice 2'
        },
        // RTP Datagram 4 (Audio)
        {
          proto: 'UDP', dir: 's2c', srcPort: sPort, dstPort: cPort,
          flags: ['UDP'], len: 680, seq: null, ack: null, win: null,
          time: '+29.0 ms', summary: 'RTP Datagram 4: AAC Audio Frame',
          phase: 'UDP Real-Time Media Stream',
          clientState: 'UDP_STREAMING', serverState: 'UDP_STREAMING', cwnd: null,
          l7Index: 3,
          explanation: 'Audio sync packet transmitted on multiplexed UDP port. 0 ms buffering latency.',
          payloadPreview: 'RTP v2: PT=97 (MPEG4-GENERIC / AAC 48kHz Stereo)'
        },
        // RTP Datagram 5 (Video P-Frame)
        {
          proto: 'UDP', dir: 's2c', srcPort: sPort, dstPort: cPort,
          flags: ['UDP'], len: 1316, seq: null, ack: null, win: null,
          time: '+33.2 ms', summary: 'RTP Datagram 5: P-Frame Predictive slice',
          phase: 'UDP Real-Time Media Stream',
          clientState: 'UDP_STREAMING', serverState: 'UDP_STREAMING', cwnd: null,
          l7Index: 3,
          explanation: 'Predictive video slice. Streaming continues uninterrupted without handshake, ACKs, or teardown overhead.',
          payloadPreview: 'RTP v2: PT=96 (H.264), Seq=3104, Timestamp=93000 (Δ 33ms 30fps)'
        }
      ];

      return { l7, l4 };
    }

    // Default: TCP HLS Mode
    const l7 = [
      { id: 0, title: 'DNS Resolution', dir: 'c2s', head: 'DNS Query (A Record)', lines: [hl('Host:', cdnHost), hl('Record:', 'A'), hl('Transport:', 'UDP/53')] },
      { id: 1, title: 'DNS Resolution', dir: 's2c', head: 'DNS Response', lines: [hl('Answer:', cdnHost + ' → ' + cdnIp), hl('TTL:', '300s')] },
      { id: 2, title: 'TCP Connection Setup', dir: 'c2s', head: 'TCP 3-Way Handshake (Port 443)', lines: [hl('Edge Server:', cdnIp + ':443'), hl('Feature:', 'Window Scaling & SACK enabled')] },
      { id: 3, title: 'HLS Master Manifest', dir: 'c2s', head: 'HTTP GET /video/master.m3u8', lines: [hl('Request:', 'GET /video/master.m3u8 HTTP/1.1'), hl('Response:', 'HTTP 200 OK — Variants: 480p, 720p, 1080p')] },
      { id: 4, title: 'HLS Media Playlist', dir: 'c2s', head: 'HTTP GET /video/' + quality + '/index.m3u8', lines: [hl('Request:', 'GET /video/' + quality + '/index.m3u8 HTTP/1.1'), hl('Response:', 'HTTP 200 OK — Segments: seg000.ts … seg014.ts (6s chunks)')] },
      { id: 5, title: 'Media Segment 0 Download', dir: 'c2s', head: 'HTTP GET seg000.ts (' + quality + ')', lines: [hl('Request:', 'GET /video/' + quality + '/seg000.ts HTTP/1.1'), hl('Transfer:', 'Pipelined TCP segments with cumulative ACKs and Congestion Window ramp-up')] },
      { id: 6, title: 'Persistent TCP Connection Reuse', dir: 'c2s', head: 'HTTP GET seg001.ts (Keep-Alive Reuse)', lines: [hl('Action:', 'Pipelining seg001.ts over existing established TCP socket'), hl('Efficiency:', '0 RTT connection reuse; avoids re-handshaking!')] }
    ];

    let cSeq = 3000;
    let sSeq = 9000;

    const l4 = [
      // DNS Query
      {
        proto: 'UDP', dir: 'c2s', srcPort: cPort, dstPort: 53,
        flags: ['UDP'], len: 36, seq: null, ack: null, win: null,
        time: '+0.0 ms', summary: 'DNS Query: ' + cdnHost,
        phase: 'DNS Lookup (UDP/53)',
        clientState: 'CLOSED', serverState: 'LISTEN', cwnd: 1,
        l7Index: 0,
        explanation: 'Client sends UDP query on port 53 to locate the CDN video edge node.',
        payloadPreview: 'QNAME: ' + cdnHost + ' A'
      },
      // DNS Response
      {
        proto: 'UDP', dir: 's2c', srcPort: 53, dstPort: cPort,
        flags: ['UDP'], len: 52, seq: null, ack: null, win: null,
        time: '+13.8 ms', summary: 'DNS Response: ' + cdnHost + ' → ' + cdnIp,
        phase: 'DNS Lookup (UDP/53)',
        clientState: 'CLOSED', serverState: 'LISTEN', cwnd: 1,
        l7Index: 1,
        explanation: 'DNS resolves CDN edge IP address: ' + cdnIp + '.',
        payloadPreview: 'Answer: ' + cdnHost + ' A ' + cdnIp
      },
      // TCP SYN
      {
        proto: 'TCP', dir: 'c2s', srcPort: cPort, dstPort: sPort,
        flags: ['SYN'], len: 0, seq: cSeq, ack: 0, win: 64240,
        time: '+18.0 ms', summary: '[SYN] CDN Edge Handshake Initiate',
        phase: 'TCP Handshake (1/3)',
        clientState: 'SYN_SENT', serverState: 'LISTEN', cwnd: 1,
        l7Index: 2,
        explanation: 'Client opens TCP connection to CDN server. ISN_c = ' + cSeq + '. Advertises window size 64240 bytes and MSS 1460.',
        payloadPreview: 'MSS=1460, WS=7, SACK_PERM=1'
      }
    ];

    // SYN-ACK
    cSeq += 1;
    l4.push({
      proto: 'TCP', dir: 's2c', srcPort: sPort, dstPort: cPort,
      flags: ['SYN', 'ACK'], len: 0, seq: sSeq, ack: cSeq, win: 65535,
      time: '+32.4 ms', summary: '[SYN, ACK] CDN Server Handshake Reply',
      phase: 'TCP Handshake (2/3)',
      clientState: 'SYN_SENT', serverState: 'SYN_RCVD', cwnd: 1,
      l7Index: 2,
      explanation: 'Server ACKs client SYN (Ack = ' + cSeq + ') and sends its ISN_s = ' + sSeq + '.',
      payloadPreview: 'SYN+ACK, Server MSS=1460, Window=65535'
    });

    // ACK
    sSeq += 1;
    l4.push({
      proto: 'TCP', dir: 'c2s', srcPort: cPort, dstPort: sPort,
      flags: ['ACK'], len: 0, seq: cSeq, ack: sSeq, win: 64240,
      time: '+34.1 ms', summary: '[ACK] TCP Connection Established',
      phase: 'TCP Handshake (3/3)',
      clientState: 'ESTABLISHED', serverState: 'ESTABLISHED', cwnd: 2,
      l7Index: 2,
      explanation: 'Connection ESTABLISHED. Congestion window begins in Slow Start at cwnd = 2 MSS.',
      payloadPreview: 'Socket ESTABLISHED. Ready for HLS manifest download.'
    });

    // GET Master Manifest
    const getManifest = 'GET /video/master.m3u8 HTTP/1.1\\r\\nHost: ' + cdnHost + '\\r\\n\\r\\n';
    const gmLen = 98;
    l4.push({
      proto: 'TCP', dir: 'c2s', srcPort: cPort, dstPort: sPort,
      flags: ['PSH', 'ACK'], len: gmLen, seq: cSeq, ack: sSeq, win: 64240,
      time: '+36.0 ms', summary: '[PSH, ACK] HTTP GET master.m3u8',
      phase: 'HLS Manifest Retrieval',
      clientState: 'ESTABLISHED', serverState: 'ESTABLISHED', cwnd: 2,
      l7Index: 3,
      explanation: 'Client requests root HLS master manifest containing adaptive bitrate variant streams.',
      payloadPreview: getManifest
    });
    cSeq += gmLen;

    // Server returns Master Manifest
    const manifestResp = 'HTTP/1.1 200 OK\\r\\n#EXTM3U\\r\\n#EXT-X-STREAM-INF:BANDWIDTH=2500000,RESOLUTION=1280x720\\r\\n720p/index.m3u8\\r\\n';
    const mrLen = 220;
    l4.push({
      proto: 'TCP', dir: 's2c', srcPort: sPort, dstPort: cPort,
      flags: ['PSH', 'ACK'], len: mrLen, seq: sSeq, ack: cSeq, win: 65535,
      time: '+51.2 ms', summary: '[PSH, ACK] 200 OK Master Manifest',
      phase: 'HLS Manifest Retrieval',
      clientState: 'ESTABLISHED', serverState: 'ESTABLISHED', cwnd: 4,
      l7Index: 3,
      explanation: 'Server transmits master playlist. Client inspects bandwidth and chooses ' + quality + ' quality.',
      payloadPreview: manifestResp
    });
    sSeq += mrLen;

    // Client GET Media Playlist
    const getPlaylist = 'GET /video/' + quality + '/index.m3u8 HTTP/1.1\\r\\nHost: ' + cdnHost + '\\r\\n\\r\\n';
    const gpLen = 104;
    l4.push({
      proto: 'TCP', dir: 'c2s', srcPort: cPort, dstPort: sPort,
      flags: ['PSH', 'ACK'], len: gpLen, seq: cSeq, ack: sSeq, win: 64240,
      time: '+54.5 ms', summary: '[PSH, ACK] HTTP GET ' + quality + ' Playlist',
      phase: 'Media Playlist Retrieval',
      clientState: 'ESTABLISHED', serverState: 'ESTABLISHED', cwnd: 4,
      l7Index: 4,
      explanation: 'Client requests media playlist for chosen ' + quality + ' stream.',
      payloadPreview: getPlaylist
    });
    cSeq += gpLen;

    // Server returns Media Playlist
    const playlistResp = 'HTTP/1.1 200 OK\\r\\n#EXTINF:6.0,\\r\\nseg000.ts\\r\\n#EXTINF:6.0,\\r\\nseg001.ts\\r\\n';
    const prLen = 180;
    l4.push({
      proto: 'TCP', dir: 's2c', srcPort: sPort, dstPort: cPort,
      flags: ['PSH', 'ACK'], len: prLen, seq: sSeq, ack: cSeq, win: 65535,
      time: '+68.0 ms', summary: '[PSH, ACK] 200 OK ' + quality + ' Segment List',
      phase: 'Media Playlist Retrieval',
      clientState: 'ESTABLISHED', serverState: 'ESTABLISHED', cwnd: 6,
      l7Index: 4,
      explanation: 'Server sends chunk playlist. Video player begins fetching media segments (seg000.ts, seg001.ts...).',
      payloadPreview: playlistResp
    });
    sSeq += prLen;

    // Client GET seg000.ts
    const getSeg0 = 'GET /video/' + quality + '/seg000.ts HTTP/1.1\\r\\nHost: ' + cdnHost + '\\r\\nRange: bytes=0-\\r\\n\\r\\n';
    const gs0Len = 112;
    l4.push({
      proto: 'TCP', dir: 'c2s', srcPort: cPort, dstPort: sPort,
      flags: ['PSH', 'ACK'], len: gs0Len, seq: cSeq, ack: sSeq, win: 64240,
      time: '+71.2 ms', summary: '[PSH, ACK] HTTP GET seg000.ts',
      phase: 'Segment 0 Streaming',
      clientState: 'ESTABLISHED', serverState: 'ESTABLISHED', cwnd: 6,
      l7Index: 5,
      explanation: 'Player issues HTTP GET for initial 6-second video transport stream segment (seg000.ts).',
      payloadPreview: getSeg0
    });
    cSeq += gs0Len;

    // Server sends Seg0 Chunk 1 (1460 bytes)
    const segChunk1Len = 1460;
    l4.push({
      proto: 'TCP', dir: 's2c', srcPort: sPort, dstPort: cPort,
      flags: ['PSH', 'ACK'], len: segChunk1Len, seq: sSeq, ack: cSeq, win: 65535,
      time: '+84.5 ms', summary: '[PSH, ACK] seg000.ts Packet 1 (1460 B)',
      phase: 'Segment 0 Streaming (cwnd ramp)',
      clientState: 'ESTABLISHED', serverState: 'ESTABLISHED', cwnd: 8,
      l7Index: 5,
      explanation: 'Server transmits first 1460 bytes of MPEG-2 TS video data. cwnd expands in Slow Start.',
      payloadPreview: 'MPEG-2 Transport Stream: Sync Byte 0x47, PID 0x100 (H.264 Video)'
    });
    sSeq += segChunk1Len;

    // Client ACKs Seg0 Chunk 1
    l4.push({
      proto: 'TCP', dir: 'c2s', srcPort: cPort, dstPort: sPort,
      flags: ['ACK'], len: 0, seq: cSeq, ack: sSeq, win: 64240,
      time: '+86.0 ms', summary: '[ACK] Client confirms Seg0 Packet 1',
      phase: 'Segment 0 Streaming',
      clientState: 'ESTABLISHED', serverState: 'ESTABLISHED', cwnd: 10,
      l7Index: 5,
      explanation: 'Cumulative ACK confirms receipt of first media chunk. Receiver window buffer has ample room.',
      payloadPreview: 'ACK=' + sSeq + ', Win=64240'
    });

    // Server sends Seg0 Chunk 2 (1460 bytes)
    l4.push({
      proto: 'TCP', dir: 's2c', srcPort: sPort, dstPort: cPort,
      flags: ['PSH', 'ACK'], len: segChunk1Len, seq: sSeq, ack: cSeq, win: 65535,
      time: '+89.0 ms', summary: '[PSH, ACK] seg000.ts Packet 2 (1460 B)',
      phase: 'Segment 0 Streaming',
      clientState: 'ESTABLISHED', serverState: 'ESTABLISHED', cwnd: 12,
      l7Index: 5,
      explanation: 'Server sends next video chunk. cwnd grows to 12 MSS.',
      payloadPreview: 'MPEG-2 Transport Stream: Audio AAC & Video I-Frames'
    });
    sSeq += segChunk1Len;

    // Client ACKs Seg0 Chunk 2
    l4.push({
      proto: 'TCP', dir: 'c2s', srcPort: cPort, dstPort: sPort,
      flags: ['ACK'], len: 0, seq: cSeq, ack: sSeq, win: 64240,
      time: '+91.2 ms', summary: '[ACK] Client confirms Seg0 Packet 2',
      phase: 'Segment 0 Streaming',
      clientState: 'ESTABLISHED', serverState: 'ESTABLISHED', cwnd: 14,
      l7Index: 5,
      explanation: 'Video buffer fills with initial 2.92 KB of video stream. Playback starts smoothly!',
      payloadPreview: 'Cumulative ACK confirms bytes up to ' + sSeq
    });

    // Client GET seg001.ts over existing Persistent Connection!
    const getSeg1 = 'GET /video/' + quality + '/seg001.ts HTTP/1.1\\r\\nHost: ' + cdnHost + '\\r\\n\\r\\n';
    const gs1Len = 102;
    l4.push({
      proto: 'TCP', dir: 'c2s', srcPort: cPort, dstPort: sPort,
      flags: ['PSH', 'ACK'], len: gs1Len, seq: cSeq, ack: sSeq, win: 64240,
      time: '+105.0 ms', summary: '[PSH, ACK] HTTP GET seg001.ts (Keep-Alive)',
      phase: 'Persistent TCP Reuse',
      clientState: 'ESTABLISHED', serverState: 'ESTABLISHED', cwnd: 16,
      l7Index: 6,
      explanation: 'Key Transport Feature: Connection is kept open (HTTP Keep-Alive). Next segment seg001.ts is fetched over the already established TCP pipe without undergoing another 3-way handshake!',
      payloadPreview: getSeg1
    });
    cSeq += gs1Len;

    // Server sends Seg1 Packet
    l4.push({
      proto: 'TCP', dir: 's2c', srcPort: sPort, dstPort: cPort,
      flags: ['PSH', 'ACK'], len: segChunk1Len, seq: sSeq, ack: cSeq, win: 65535,
      time: '+118.4 ms', summary: '[PSH, ACK] seg001.ts Packet 1',
      phase: 'Persistent TCP Reuse',
      clientState: 'ESTABLISHED', serverState: 'ESTABLISHED', cwnd: 16,
      l7Index: 6,
      explanation: 'Media server immediately streams seg001.ts bytes at full line speed using the ramped cwnd.',
      payloadPreview: 'High-throughput video segment transfer in progress.'
    });
    sSeq += segChunk1Len;

    // Client ACKs Seg1
    l4.push({
      proto: 'TCP', dir: 'c2s', srcPort: cPort, dstPort: sPort,
      flags: ['ACK'], len: 0, seq: cSeq, ack: sSeq, win: 64240,
      time: '+120.0 ms', summary: '[ACK] seg001.ts Confirmed (Stream Active)',
      phase: 'Streaming Active',
      clientState: 'ESTABLISHED', serverState: 'ESTABLISHED', cwnd: 16,
      l7Index: 6,
      explanation: 'Continuous streaming loop active. Connection remains ESTABLISHED ready for upcoming segments.',
      payloadPreview: 'Stream continuous buffer active. 0 packet loss.'
    });

    return { l7, l4 };
  }

  // ---------- Visualizer State & Controls ----------
  const l4Track = document.getElementById('l4Track');
  const l7Track = document.getElementById('l7Track');
  const progBar = document.getElementById('progBar');
  const stepCount = document.getElementById('stepCount');
  const btnPrev = document.getElementById('btnPrev');
  const btnNext = document.getElementById('btnNext');
  const btnPlayPause = document.getElementById('btnPlayPause');
  const btnReplay = document.getElementById('btnReplay');
  const inspectorBody = document.getElementById('inspectorBody');
  const inspSub = document.getElementById('inspSub');

  let currentScenario = null;
  let cursor = -1;
  let playing = false;
  let timer = null;
  let selectedPktIndex = -1;

  function renderInspector(pkt, idx){
    if(!pkt){
      inspectorBody.innerHTML = '<div class="insp-empty">Select a packet from the track to view its full 20-byte TCP / 8-byte UDP header fields and sequence number calculation.</div>';
      inspSub.textContent = 'Click or advance to any packet to inspect RFC fields';
      return;
    }

    inspSub.innerHTML = 'Packet <b>#' + (idx+1) + '</b>: ' + esc(pkt.summary);

    const isUdp = pkt.proto === 'UDP';
    let flagsBadges = '';
    if(pkt.flags){
      flagsBadges = pkt.flags.map(f => '<span class="flag-tag ' + f.toLowerCase() + '">' + esc(f) + '</span>').join(' ');
    }

    let mathCard = '';
    if(!isUdp && pkt.seq !== null){
      if(pkt.flags.includes('SYN')){
        mathCard = '<div class="math-card"><b>SYN Sequence Space Rule:</b> SYN consumes <b>1 sequence byte</b>. ISN = ' + pkt.seq + '. Next expected ACK from peer will be <b>' + (pkt.seq + 1) + '</b>.</div>';
      } else if(pkt.flags.includes('FIN')){
        mathCard = '<div class="math-card"><b>FIN Sequence Space Rule:</b> FIN consumes <b>1 sequence byte</b>. Seq = ' + pkt.seq + '. Peer ACK will confirm with Ack = <b>' + (pkt.seq + 1) + '</b>.</div>';
      } else if(pkt.len > 0){
        mathCard = '<div class="math-card"><b>Byte-Stream Accounting:</b> Packet transmits <b>' + pkt.len + ' bytes</b> starting at Seq <b>' + pkt.seq + '</b>. Next expected byte requested by peer ACK = <b>' + pkt.seq + ' + ' + pkt.len + ' = ' + (pkt.seq + pkt.len) + '</b>.</div>';
      } else {
        mathCard = '<div class="math-card"><b>Pure ACK Rule:</b> ACK-only segment carries <b>0 data payload bytes</b>. It does not advance the sequence number sequence. Confirms peer bytes up to <b>' + (pkt.ack - 1) + '</b>.</div>';
      }
    } else if(isUdp){
      mathCard = '<div class="math-card"><b>UDP Datagram Characteristics:</b> Stateless delivery. No sequence/acknowledgment numbers, no handshake, no window scaling overhead. Exactly <b>8 bytes</b> of UDP header.</div>';
    }

    // Header breakdown visualizer table
    let hdrVisualizer = '';
    if(!isUdp){
      hdrVisualizer = `
        <div class="hdr-visualizer">
          <div class="hdr-row">
            <div class="hdr-field"><span class="hf-k">Source Port:</span><span class="hf-v">${pkt.srcPort}</span></div>
            <div class="hdr-field"><span class="hf-k">Destination Port:</span><span class="hf-v">${pkt.dstPort}</span></div>
          </div>
          <div class="hdr-row single">
            <div class="hdr-field"><span class="hf-k">Sequence Number (32-bit):</span><span class="hf-v">${pkt.seq !== null ? pkt.seq : 'N/A'}</span></div>
          </div>
          <div class="hdr-row single">
            <div class="hdr-field"><span class="hf-k">Acknowledgment Number (32-bit):</span><span class="hf-v">${pkt.ack !== null ? pkt.ack : 'N/A'}</span></div>
          </div>
          <div class="hdr-row">
            <div class="hdr-field"><span class="hf-k">Data Offset:</span><span class="hf-v">32 bytes (8 words)</span></div>
            <div class="hdr-field"><span class="hf-k">Flags:</span><span class="hf-v">${pkt.flags.join(', ')}</span></div>
          </div>
          <div class="hdr-row">
            <div class="hdr-field"><span class="hf-k">Window Size (rwnd):</span><span class="hf-v">${pkt.win !== null ? pkt.win.toLocaleString() + ' B' : 'N/A'}</span></div>
            <div class="hdr-field"><span class="hf-k">Checksum:</span><span class="hf-v">0x8B3E (Verified)</span></div>
          </div>
        </div>
      `;
    } else {
      hdrVisualizer = `
        <div class="hdr-visualizer">
          <div class="hdr-row">
            <div class="hdr-field"><span class="hf-k">Source Port:</span><span class="hf-v">${pkt.srcPort}</span></div>
            <div class="hdr-field"><span class="hf-k">Destination Port:</span><span class="hf-v">${pkt.dstPort}</span></div>
          </div>
          <div class="hdr-row">
            <div class="hdr-field"><span class="hf-k">Length:</span><span class="hf-v">${(pkt.len || 0) + 8} bytes</span></div>
            <div class="hdr-field"><span class="hf-k">Checksum:</span><span class="hf-v">0x5F21 (Verified)</span></div>
          </div>
        </div>
      `;
    }

    inspectorBody.innerHTML = `
      <div class="inspector-grid">
        <div class="insp-card">
          <div class="k">Protocol &amp; Dir</div>
          <div class="v">${esc(pkt.proto)} (${pkt.dir === 'c2s' ? 'Client → Server' : 'Server → Client'})</div>
        </div>
        <div class="insp-card">
          <div class="k">Active Flags</div>
          <div class="v">${flagsBadges}</div>
        </div>
        <div class="insp-card">
          <div class="k">Payload Length</div>
          <div class="v hl">${pkt.len !== null ? pkt.len + ' bytes' : '0'}</div>
        </div>
        <div class="insp-card">
          <div class="k">Timing Offset</div>
          <div class="v">${esc(pkt.time)}</div>
        </div>
      </div>
      ${mathCard}
      <div style="font-size:11px; color:var(--text-dim); margin:6px 0 3px; font-weight:600;">RFC Header Structure:</div>
      ${hdrVisualizer}
      <div style="font-size:11px; color:var(--text-dim); margin-top:8px;"><b>Protocol Rationale:</b> ${esc(pkt.explanation)}</div>
    `;
  }

  function renderL4Track(){
    if(!currentScenario || !currentScenario.l4.length){
      l4Track.innerHTML = '<div class="empty"><b>No activity yet</b>Choose Browsing, Mail, or Streaming on the left and run it — the message exchange will appear here, message by message.</div>';
      return;
    }

    l4Track.innerHTML = '';
    currentScenario.l4.forEach((pkt, i) => {
      const row = document.createElement('div');
      const isRevealed = i <= cursor;
      const isCurrent = i === cursor;
      row.className = 'msg-row ' + pkt.dir + (isRevealed ? ' revealed' : '') + (isCurrent ? ' current' : '');

      row.onclick = () => {
        selectedPktIndex = i;
        renderInspector(pkt, i);
      };

      // Flags HTML
      const flagsHtml = (pkt.flags || []).map(f => '<span class="flag-tag ' + f.toLowerCase() + '">' + esc(f) + '</span>').join(' ');

      // Fields Grid
      let fieldsHtml = '';
      if(pkt.proto === 'TCP'){
        fieldsHtml = `
          <div class="pkt-fields">
            <div class="pkt-f"><span class="lbl">Seq</span><span class="val">${pkt.seq !== null ? pkt.seq : '—'}</span></div>
            <div class="pkt-f"><span class="lbl">Ack</span><span class="val">${pkt.ack !== null ? pkt.ack : '—'}</span></div>
            <div class="pkt-f"><span class="lbl">Win</span><span class="val">${pkt.win !== null ? pkt.win : '—'}</span></div>
            <div class="pkt-f"><span class="lbl">Len</span><span class="val">${pkt.len !== null ? pkt.len + 'B' : '0B'}</span></div>
          </div>
        `;
      } else {
        fieldsHtml = `
          <div class="pkt-fields">
            <div class="pkt-f"><span class="lbl">Protocol</span><span class="val">UDP</span></div>
            <div class="pkt-f"><span class="lbl">Ports</span><span class="val">${pkt.srcPort} → ${pkt.dstPort}</span></div>
            <div class="pkt-f"><span class="lbl">Length</span><span class="val">${pkt.len}B</span></div>
            <div class="pkt-f"><span class="lbl">Ack/Seq</span><span class="val">None</span></div>
          </div>
        `;
      }

      const bubbleContent = `
        <div class="bubble">
          <div class="head">
            <span class="head-title">${pkt.dir === 'c2s' ? '→ ' : ''}${esc(pkt.summary)}${pkt.dir === 's2c' ? ' →' : ''}</span>
            <span class="head-time">${esc(pkt.time)}</span>
          </div>
          <div class="flags-row">${flagsHtml}</div>
          ${fieldsHtml}
          ${pkt.payloadPreview ? '<div class="pkt-data-preview">' + esc(pkt.payloadPreview) + '</div>' : ''}
          <div class="pkt-state-trans">
            <span>Client: <b>${pkt.clientState}</b></span>
            <span>·</span>
            <span>Server: <b>${pkt.serverState}</b></span>
          </div>
        </div>
      `;

      const arrowHtml = `
        <div class="arrowcol">
          <span class="seq-idx">#${i+1}</span>
          <span class="arrow">${pkt.dir === 'c2s' ? '→' : '←'}</span>
        </div>
      `;

      if(pkt.dir === 'c2s'){
        row.innerHTML = bubbleContent + arrowHtml + '<div class="spacer"></div>';
      } else {
        row.innerHTML = '<div class="spacer-l"></div>' + arrowHtml + bubbleContent;
      }

      l4Track.appendChild(row);
    });

    const cur = l4Track.querySelector('.msg-row.current');
    if(cur) cur.scrollIntoView({block:'nearest', behavior:'auto'});
  }

  function renderL7Track(){
    if(!currentScenario || !currentScenario.l7.length){
      l7Track.innerHTML = '<div class="empty"><b>No activity yet</b>Choose an activity on the left to inspect high-level application messages.</div>';
      return;
    }

    l7Track.innerHTML = '';
    const currentPkt = cursor >= 0 && cursor < currentScenario.l4.length ? currentScenario.l4[cursor] : null;
    const activeL7Idx = currentPkt ? currentPkt.l7Index : -1;

    currentScenario.l7.forEach((s, idx) => {
      const row = document.createElement('div');
      const isRevealed = activeL7Idx >= 0 && idx <= activeL7Idx;
      const isCurrent = idx === activeL7Idx;
      row.className = 'msg-row ' + s.dir + (isRevealed ? ' revealed' : '') + (isCurrent ? ' current' : '');

      const bubble = `
        <div class="bubble">
          <div class="head">
            <span class="head-title">${s.dir === 'c2s' ? '→ ' : ''}${esc(s.head)}${s.dir === 's2c' ? ' →' : ''}</span>
            <span class="head-time">${esc(s.title)}</span>
          </div>
          ${s.lines.map(l => '<div>' + l + '</div>').join('')}
        </div>
      `;

      const arrowHtml = `
        <div class="arrowcol">
          <span class="seq-idx">L7 #${idx+1}</span>
          <span class="arrow">${s.dir === 'c2s' ? '→' : '←'}</span>
        </div>
      `;

      if(s.dir === 'c2s'){
        row.innerHTML = bubble + arrowHtml + '<div class="spacer"></div>';
      } else {
        row.innerHTML = '<div class="spacer-l"></div>' + arrowHtml + bubble;
      }

      l7Track.appendChild(row);
    });

    const cur = l7Track.querySelector('.msg-row.current');
    if(cur) cur.scrollIntoView({block:'nearest', behavior:'auto'});
  }

  function render(){
    renderL4Track();
    renderL7Track();

    const total = currentScenario && currentScenario.l4 ? currentScenario.l4.length : 0;
    const pct = total ? Math.round(((cursor + 1) / total) * 100) : 0;
    progBar.style.width = pct + '%';
    stepCount.textContent = (Math.max(cursor + 1, 0)) + ' / ' + total;

    btnPrev.disabled = cursor <= 0;
    btnNext.disabled = cursor >= total - 1 || total === 0;
    btnReplay.disabled = total === 0;
    btnPlayPause.disabled = total === 0;
    btnPlayPause.textContent = playing ? '⏸' : '▶';

    const curPkt = total && cursor >= 0 ? currentScenario.l4[cursor] : null;
    updateTelemetry(curPkt);

    // If inspector wasn't pinned by manual user click, sync to current packet
    if(curPkt && selectedPktIndex === -1){
      renderInspector(curPkt, cursor);
    }
  }

  function stopPlay(){
    playing = false;
    clearInterval(timer);
    timer = null;
    render();
  }

  function stepNext(){
    if(!currentScenario) return;
    if(cursor < currentScenario.l4.length - 1){
      cursor++;
      selectedPktIndex = -1; // reset manual pin
      render();
      const curPkt = currentScenario.l4[cursor];
      log('L4 Frame #' + (cursor + 1) + ': ' + esc(curPkt.summary));
    } else {
      stopPlay();
      setStatus('complete');
      log('protocol sequence complete');
    }
  }

  function stepPrev(){
    if(cursor > 0){
      cursor--;
      selectedPktIndex = -1;
      render();
    }
  }

  function runPlayLoop(){
    if(cursor >= currentScenario.l4.length - 1){
      stopPlay();
      setStatus('complete');
      return;
    }
    stepNext();
  }

  function startScenario(scenario, label){
    currentScenario = scenario;
    cursor = -1;
    selectedPktIndex = -1;
    stopPlay();
    log('<b>' + label + '</b> started');
    setStatus('running', true);
    playing = true;
    render();
    timer = setInterval(runPlayLoop, stepIntervalMs);
  }

  // ---------- Control Button Handlers ----------
  btnPrev.onclick = stepPrev;
  btnNext.onclick = stepNext;
  btnReplay.onclick = () => {
    if(!currentScenario) return;
    cursor = -1;
    selectedPktIndex = -1;
    stopPlay();
    playing = true;
    render();
    timer = setInterval(runPlayLoop, stepIntervalMs);
  };
  btnPlayPause.onclick = () => {
    if(playing){
      stopPlay();
      setStatus('paused');
    } else if(currentScenario && currentScenario.l4.length){
      if(cursor >= currentScenario.l4.length - 1) cursor = -1;
      playing = true;
      setStatus('running', true);
      render();
      timer = setInterval(runPlayLoop, stepIntervalMs);
    }
  };

  // Keyboard navigation shortcuts
  window.addEventListener('keydown', (e) => {
    if(e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
    if(e.code === 'Space'){
      e.preventDefault();
      btnPlayPause.click();
    } else if(e.code === 'ArrowRight'){
      e.preventDefault();
      stepNext();
    } else if(e.code === 'ArrowLeft'){
      e.preventDefault();
      stepPrev();
    }
  });

  // ---------- Left Panel Activity Triggers ----------
  document.getElementById('btnVisit').onclick = () => {
    const url = document.getElementById('urlInput').value.trim() || 'www.example.com';
    log('visiting <b>' + esc(url) + '</b>');
    const scenario = buildBrowsingScenario(url);
    startScenario(scenario, 'Browsing ' + url);
  };

  document.getElementById('btnSend').onclick = () => {
    const to = document.getElementById('mailTo').value.trim() || 'someone@example.com';
    const subj = document.getElementById('mailSubject').value.trim() || '(no subject)';
    const body = document.getElementById('mailBody').value.trim() || '(empty body)';
    log('sending mail to <b>' + esc(to) + '</b>');
    const scenario = buildMailScenario(to, subj, body);
    startScenario(scenario, 'Mail to ' + to);
  };

  const btnPlayStream = document.getElementById('btnPlay');
  const btnPauseStream = document.getElementById('btnPauseStream');

  btnPlayStream.onclick = () => {
    const qElem = document.querySelector('#qualsel button.active');
    const q = qElem ? qElem.dataset.q : '720p';
    log('starting stream at <b>' + q + '</b> via <b>' + streamingProto.toUpperCase() + '</b>');
    const scenario = buildStreamingScenario(q, streamingProto);
    startScenario(scenario, 'Streaming ' + q + ' (' + streamingProto.toUpperCase() + ')');
    btnPauseStream.disabled = false;
  };

  btnPauseStream.onclick = () => {
    stopPlay();
    setStatus('paused');
    log('stream paused');
  };

  // Initial render
  updateTelemetry(null);
  renderInspector(null);
  render();

  // URL Query Parameters support for direct state linking & screenshot automation
  try {
    const urlParams = new URLSearchParams(window.location.search);
    const paramAct = urlParams.get('act') || urlParams.get('action');
    const paramView = urlParams.get('view');
    const paramStep = urlParams.get('step');
    const paramProto = urlParams.get('proto');

    if(paramView){
      const targetViewBtn = document.querySelector('#viewTabs .vtab[data-view="' + paramView + '"]');
      if(targetViewBtn) targetViewBtn.click();
    }
    if(paramProto && (paramProto === 'tcp' || paramProto === 'udp')){
      const targetProtoBtn = document.querySelector('#protoSel button[data-proto="' + paramProto + '"]');
      if(targetProtoBtn) targetProtoBtn.click();
    }
    if(paramAct){
      const actTab = document.querySelector('.tabs .tab-btn[data-act="' + paramAct + '"]');
      if(actTab) actTab.click();

      if(paramAct === 'browse'){
        document.getElementById('btnVisit').click();
      } else if(paramAct === 'mail'){
        document.getElementById('btnSend').click();
      } else if(paramAct === 'stream'){
        document.getElementById('btnPlay').click();
      }

      if(paramStep !== null){
        stopPlay();
        cursor = Math.min(Math.max(parseInt(paramStep, 10), 0), (currentScenario && currentScenario.l4 ? currentScenario.l4.length - 1 : 0));
        render();
      }
    }
  } catch(e) {
    console.error('URL params parsing error:', e);
  }

})();
