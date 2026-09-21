(function(){
  const root = document.documentElement;
  const btnDark = document.getElementById('btnDark'), btnLight = document.getElementById('btnLight');
  function setTheme(t){
    if(t==='light'){ root.setAttribute('data-theme','light'); btnLight.classList.add('active'); btnDark.classList.remove('active'); btnLight.setAttribute('aria-pressed','true'); btnDark.setAttribute('aria-pressed','false'); }
    else{ root.removeAttribute('data-theme'); btnDark.classList.add('active'); btnLight.classList.remove('active'); btnDark.setAttribute('aria-pressed','true'); btnLight.setAttribute('aria-pressed','false'); }
  }
  btnDark.onclick=()=>setTheme('dark'); btnLight.onclick=()=>setTheme('light');

  // ---------- Activity switching ----------
  const tabs = document.querySelectorAll('.tab-btn');
  const forms = {browse:'form-browse', mail:'form-mail', stream:'form-stream'};
  const protoLabels = {browse:'— DNS → HTTP', mail:'— SMTP', stream:'— DNS → HTTP (manifest & segments)'};
  tabs.forEach(t=>t.onclick=()=>{
    tabs.forEach(x=>x.classList.remove('active')); t.classList.add('active');
    Object.values(forms).forEach(id=>document.getElementById(id).style.display='none');
    document.getElementById(forms[t.dataset.act]).style.display='block';
    document.getElementById('protoLabel').textContent = protoLabels[t.dataset.act];
  });
  document.getElementById('protoLabel').textContent = protoLabels.browse;

  document.querySelectorAll('#qualsel button').forEach(b=>b.onclick=()=>{
    document.querySelectorAll('#qualsel button').forEach(x=>x.classList.remove('active')); b.classList.add('active');
  });

  // ---------- Activity log ----------
  const logBox = document.getElementById('logBox');
  const statusBadge = document.getElementById('statusBadge');
  function ts(){ return new Date().toLocaleTimeString([], {hour12:false}); }
  function log(msg){
    const d = document.createElement('div');
    d.innerHTML = '<span class="t">'+ts()+'</span>'+msg;
    logBox.prepend(d);
  }
  function setStatus(text, live){
    statusBadge.textContent = text;
    statusBadge.classList.toggle('live', !!live);
  }

  // ---------- Protocol step builders ----------
  function esc(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;'); }
  function hl(label, val){ return '<span class="field-hl">'+esc(label)+'</span> '+esc(val); }

  function buildBrowsing(host){
    host = host.replace(/^https?:\/\//,'') || 'www.example.com';
    const ip = '203.0.113.' + (10 + (host.length % 40));
    return [
      {dir:'c2s', head:'DNS Query', lines:[hl('QNAME:', host), hl('QTYPE:', 'A'), hl('Transport:', 'UDP/53')]},
      {dir:'s2c', head:'DNS Response', lines:[hl('ANSWER:', host+' → '+ip), hl('TTL:', '300s'), hl('RCODE:', 'NOERROR')]},
      {dir:'c2s', head:'TCP handshake → HTTP GET', lines:[hl('Request-Line:', 'GET / HTTP/1.1'), hl('Host:', host), hl('Accept:', 'text/html'), hl('Connection:', 'keep-alive')]},
      {dir:'s2c', head:'HTTP Response — headers', lines:[hl('Status-Line:', 'HTTP/1.1 200 OK'), hl('Content-Type:', 'text/html; charset=utf-8'), hl('Content-Length:', '18402')]},
      {dir:'s2c', head:'HTTP Response — body', lines:[hl('Payload:', '<html>… page content …</html>'), hl('Connection:', 'kept open for reuse')]},
    ];
  }
  function buildMail(to, subject, body){
    const domain = (to.split('@')[1] || 'mailhost.net');
    return [
      {dir:'c2s', head:'DNS Query (MX lookup)', lines:[hl('QNAME:', domain), hl('QTYPE:', 'MX')]},
      {dir:'s2c', head:'DNS Response', lines:[hl('ANSWER:', 'mail.'+domain+' pri 10')]},
      {dir:'c2s', head:'SMTP: EHLO', lines:[hl('Command:', 'EHLO client.local')]},
      {dir:'s2c', head:'SMTP: 250 greeting', lines:[hl('Reply:', '250-mail.'+domain+' Hello'), hl('Reply:', '250 8BITMIME')]},
      {dir:'c2s', head:'SMTP: MAIL FROM', lines:[hl('Command:', 'MAIL FROM:<sender@client.local>')]},
      {dir:'s2c', head:'SMTP: 250 OK', lines:[hl('Reply:', '250 2.1.0 Sender OK')]},
      {dir:'c2s', head:'SMTP: RCPT TO', lines:[hl('Command:', 'RCPT TO:<'+to+'>')]},
      {dir:'s2c', head:'SMTP: 250 Accepted', lines:[hl('Reply:', '250 2.1.5 Recipient OK')]},
      {dir:'c2s', head:'SMTP: DATA', lines:[hl('Command:', 'DATA'), hl('Subject:', subject), hl('Body:', body.slice(0,40)+(body.length>40?'…':''))]},
      {dir:'s2c', head:'SMTP: 354 → 250', lines:[hl('Reply:', '354 Start input, end with <CRLF>.<CRLF>'), hl('Reply:', '250 2.0.0 Message queued')]},
      {dir:'c2s', head:'SMTP: QUIT', lines:[hl('Command:', 'QUIT')]},
      {dir:'s2c', head:'SMTP: 221 Closing', lines:[hl('Reply:', '221 2.0.0 Bye')]},
    ];
  }
  function buildStream(quality){
    return [
      {dir:'c2s', head:'DNS Query', lines:[hl('QNAME:', 'cdn.streamhost.net'), hl('QTYPE:', 'A')]},
      {dir:'s2c', head:'DNS Response', lines:[hl('ANSWER:', 'cdn.streamhost.net → 198.51.100.7')]},
      {dir:'c2s', head:'HTTP GET manifest', lines:[hl('Request-Line:', 'GET /video/master.m3u8 HTTP/1.1'), hl('Host:', 'cdn.streamhost.net')]},
      {dir:'s2c', head:'HTTP 200 — manifest body', lines:[hl('Content-Type:', 'application/vnd.apple.mpegurl'), hl('Variants:', '480p, 720p, 1080p')]},
      {dir:'c2s', head:'HTTP GET playlist', lines:[hl('Request-Line:', 'GET /video/'+quality+'/index.m3u8 HTTP/1.1')]},
      {dir:'s2c', head:'HTTP 200 — segment list', lines:[hl('Segments:', 'seg000.ts … seg014.ts (6s each)')]},
      {dir:'c2s', head:'HTTP GET segment 0', lines:[hl('Request-Line:', 'GET /video/'+quality+'/seg000.ts HTTP/1.1'), hl('Range:', 'bytes=0-')]},
      {dir:'s2c', head:'HTTP 200 — segment data', lines:[hl('Content-Type:', 'video/MP2T'), hl('Content-Length:', quality==='1080p'?'2,410,880':(quality==='720p'?'1,180,224':'620,112'))]},
      {dir:'c2s', head:'HTTP GET segment 1', lines:[hl('Request-Line:', 'GET /video/'+quality+'/seg001.ts HTTP/1.1')]},
      {dir:'s2c', head:'HTTP 200 — segment data', lines:[hl('Note:', 'buffer fills; playback continues')]},
    ];
  }

  // ---------- Visualizer engine ----------
  const track = document.getElementById('msgTrack');
  const progBar = document.getElementById('progBar');
  const stepCount = document.getElementById('stepCount');
  const btnPrev = document.getElementById('btnPrev'), btnNext = document.getElementById('btnNext');
  const btnPlayPause = document.getElementById('btnPlayPause'), btnReplay = document.getElementById('btnReplay');

  let steps = [], cursor = -1, playing = false, timer = null;

  function render(){
    track.innerHTML = '';
    steps.forEach((s, i)=>{
      const row = document.createElement('div');
      row.className = 'msg-row ' + s.dir + (i<=cursor?' revealed':'') + (i===cursor?' current':'');
      const bubble = '<div class="bubble"><div class="head">'+(s.dir==='c2s'?'→ ':'')+esc(s.head)+(s.dir==='s2c'?' →':'')+'</div>'+s.lines.map(l=>'<div>'+l+'</div>').join('')+'</div>';
      if(s.dir==='c2s'){
        row.innerHTML = bubble + '<div class="arrowcol"><span class="arrow">→</span></div><div class="spacer"></div>';
      } else {
        row.innerHTML = '<div class="spacer-l"></div><div class="arrowcol"><span class="arrow">←</span></div>' + bubble;
      }
      track.appendChild(row);
    });
    if(steps.length===0){
      track.innerHTML = '<div class="empty"><b>No activity yet</b>Choose Browsing, Mail, or Streaming on the left and run it — the message exchange will appear here, message by message.</div>';
    }
    const pct = steps.length ? Math.round(((cursor+1)/steps.length)*100) : 0;
    progBar.style.width = pct+'%';
    stepCount.textContent = (Math.max(cursor+1,0))+' / '+steps.length;
    btnPrev.disabled = cursor<=0;
    btnNext.disabled = cursor>=steps.length-1 || steps.length===0;
    btnReplay.disabled = steps.length===0;
    btnPlayPause.disabled = steps.length===0;
    btnPlayPause.textContent = playing ? '⏸' : '▶';
    const cur = track.querySelector('.msg-row.current');
    if(cur) cur.scrollIntoView({block:'nearest', behavior:'smooth'});
  }

  function stopPlay(){ playing=false; clearInterval(timer); timer=null; render(); }
  function stepNext(){
    if(cursor < steps.length-1){ cursor++; render(); log('protocol step: '+esc(steps[cursor].head)); }
    else stopPlay();
  }
  function startSequence(newSteps, activityLabel){
    steps = newSteps; cursor = -1; stopPlay();
    log('<b>'+activityLabel+'</b> started');
    setStatus('running', true);
    render();
    playing = true;
    render();
    timer = setInterval(()=>{
      if(cursor >= steps.length-1){ stopPlay(); setStatus('complete'); log(activityLabel+' complete'); return; }
      stepNext();
    }, 1100);
  }

  btnPrev.onclick = ()=>{ if(cursor>0){ cursor--; render(); } };
  btnNext.onclick = ()=>{ if(cursor<steps.length-1){ cursor++; render(); } };
  btnReplay.onclick = ()=>{ cursor=-1; stopPlay(); playing=true; render();
    timer = setInterval(()=>{ if(cursor>=steps.length-1){ stopPlay(); return;} stepNext(); }, 1100); };
  btnPlayPause.onclick = ()=>{
    if(playing){ stopPlay(); }
    else if(steps.length){
      if(cursor>=steps.length-1) cursor=-1;
      playing=true; render();
      timer = setInterval(()=>{ if(cursor>=steps.length-1){ stopPlay(); return;} stepNext(); }, 1100);
    }
  };

  // ---------- Activity triggers ----------
  document.getElementById('btnVisit').onclick = ()=>{
    const url = document.getElementById('urlInput').value.trim() || 'www.example.com';
    log('visiting <b>'+esc(url)+'</b>');
    startSequence(buildBrowsing(url), 'Browsing '+url);
  };
  document.getElementById('btnSend').onclick = ()=>{
    const to = document.getElementById('mailTo').value.trim() || 'someone@example.com';
    const subj = document.getElementById('mailSubject').value.trim() || '(no subject)';
    const body = document.getElementById('mailBody').value.trim() || '(empty body)';
    log('sending mail to <b>'+esc(to)+'</b>');
    startSequence(buildMail(to, subj, body), 'Mail to '+to);
  };
  const btnPlayStream = document.getElementById('btnPlay');
  const btnPauseStream = document.getElementById('btnPauseStream');
  btnPlayStream.onclick = ()=>{
    const q = document.querySelector('#qualsel button.active').dataset.q;
    log('starting stream at <b>'+q+'</b>');
    startSequence(buildStream(q), 'Streaming '+q);
    btnPauseStream.disabled = false;
  };
  btnPauseStream.onclick = ()=>{
    stopPlay(); setStatus('paused'); log('stream paused');
  };

  render();
})();
