local H = require("auth.html")
local css_content = [[  * {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
  }

  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    line-height: 1.5;
    color: #333;
    background-color: #f5f5f5;
    padding: 1rem;
    max-width: 1200px;
    margin: 0 auto;
  }

  form {
    background: white;
    padding: 2rem;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    margin: 1rem 0;
  }

  label {
    display: block;
    margin-bottom: 0.5rem;
    font-weight: 500;
  }

  input[type="text"],
  input[type="password"] {
    width: 100%;
    padding: 0.75rem;
    border: 1px solid #ddd;
    border-radius: 4px;
    font-size: 1rem;
    margin-bottom: 1rem;
  }

  button {
    background-color: #007bff;
    color: white;
    border: none;
    padding: 0.75rem 1.5rem;
    border-radius: 4px;
    font-size: 1rem;
    cursor: pointer;
    transition: background-color 0.2s;
  }

  button:hover { background-color: #0056b3; }

  p { margin: 1rem 0; }

  a {
    color: #007bff;
    text-decoration: none;
  }

  a:hover { text-decoration: underline; }

  #refusals {
    background: white;
    padding: 1rem 2rem;
    border-radius: 8px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    margin: 1rem 0;
  }

  #refusals h2 {
    font-size: 1rem;
    margin-bottom: 0.5rem;
  }

  #refusals-list {
    list-style: none;
    max-height: 14rem;
    overflow-y: auto;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 0.85rem;
    border: 1px solid #eee;
    border-radius: 4px;
  }

  #refusals-list li {
    padding: 0.3rem 0.6rem;
    border-bottom: 1px solid #f0f0f0;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  #refusals-list li:last-child { border-bottom: none; }

  #refusals-empty { color: #888; }

  @media (max-width: 768px) {
    body { padding: 0.5rem; }
    form { padding: 1rem; }
  }

  @media (max-width: 480px) {
    body { padding: 0.25rem; }
    form { padding: 0.75rem; }
  }
  ]]
local CRYPTO_JS = [[var PBKDF2_ITER = 10000;
function _rotr(x,n){return (x>>>n)|(x<<(32-n));}
function _hex(buf){var b=new Uint8Array(buf),s='';for(var i=0;i<b.length;i++){s+=(b[i]>>>4).toString(16)+(b[i]&15).toString(16);}return s;}
function _utf8(str){return new TextEncoder().encode(str);}
function _hexToBytes(h){var a=new Uint8Array(h.length/2);for(var i=0;i<a.length;i++){a[i]=parseInt(h.substr(i*2,2),16);}return a;}
function _concat(a,b){var c=new Uint8Array(a.length+b.length);c.set(a);c.set(b,a.length);return c;}
var _K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
function _sha256(data){
  var H=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
  var l=data.length, withOne=l+1, k=(56-(withOne%64)+64)%64, total=withOne+k+8;
  var m=new Uint8Array(total); m.set(data); m[l]=0x80;
  var dv=new DataView(m.buffer), bitLen=l*8;
  dv.setUint32(total-4, bitLen>>>0); dv.setUint32(total-8, Math.floor(bitLen/0x100000000));
  var w=new Array(64);
  for(var off=0;off<total;off+=64){
    for(var i=0;i<16;i++) w[i]=dv.getUint32(off+i*4);
    for(var i=16;i<64;i++){
      var s0=_rotr(w[i-15],7)^_rotr(w[i-15],18)^(w[i-15]>>>3);
      var s1=_rotr(w[i-2],17)^_rotr(w[i-2],19)^(w[i-2]>>>10);
      w[i]=(w[i-16]+s0+w[i-7]+s1)|0;
    }
    var a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
    for(var i=0;i<64;i++){
      var S1=_rotr(e,6)^_rotr(e,11)^_rotr(e,25), ch=(e&f)^((~e)&g);
      var t1=(h+S1+ch+_K[i]+w[i])|0;
      var S0=_rotr(a,2)^_rotr(a,13)^_rotr(a,22), maj=(a&b)^(a&c)^(b&c), t2=(S0+maj)|0;
      h=g;g=f;f=e;e=(d+t1)|0;d=c;c=b;b=a;a=(t1+t2)|0;
    }
    H[0]=(H[0]+a)|0;H[1]=(H[1]+b)|0;H[2]=(H[2]+c)|0;H[3]=(H[3]+d)|0;
    H[4]=(H[4]+e)|0;H[5]=(H[5]+f)|0;H[6]=(H[6]+g)|0;H[7]=(H[7]+h)|0;
  }
  var out=new Uint8Array(32), odv=new DataView(out.buffer);
  for(var i=0;i<8;i++) odv.setUint32(i*4,H[i]>>>0);
  return out;
}
function _hmacPure(key,msg){
  var bs=64; if(key.length>bs) key=_sha256(key);
  var ko=new Uint8Array(bs); ko.set(key);
  var oi=new Uint8Array(bs), ii=new Uint8Array(bs);
  for(var i=0;i<bs;i++){oi[i]=ko[i]^0x5c; ii[i]=ko[i]^0x36;}
  return _sha256(_concat(oi,_sha256(_concat(ii,msg))));
}
function _pbkdf2Pure(pw,salt,iter,dkLen){
  var u=_hmacPure(pw,_concat(salt,new Uint8Array([0,0,0,1]))), t=u.slice();
  for(var i=1;i<iter;i++){u=_hmacPure(pw,u); for(var j=0;j<t.length;j++) t[j]^=u[j];}
  return t.slice(0,dkLen);
}
function _randSaltHex(){
  var s=new Uint8Array(16);
  if(window.crypto&&crypto.getRandomValues){crypto.getRandomValues(s);}
  else{for(var i=0;i<16;i++) s[i]=Math.floor(Math.random()*256);}
  return _hex(s);
}
function _pbkdf2Hex(password,saltHex,iter){
  var pw=_utf8(password), salt=_hexToBytes(saltHex);
  if(window.crypto&&crypto.subtle){
    return crypto.subtle.importKey('raw',pw,{name:'PBKDF2'},false,['deriveBits'])
      .then(function(bk){return crypto.subtle.deriveBits({name:'PBKDF2',salt:salt,iterations:iter,hash:'SHA-256'},bk,256);})
      .then(function(bits){return {dk:new Uint8Array(bits),hex:_hex(bits)};})
      .catch(function(){var dk=_pbkdf2Pure(pw,salt,iter,32);return {dk:dk,hex:_hex(dk)};});
  }
  var dk=_pbkdf2Pure(pw,salt,iter,32);
  return Promise.resolve({dk:dk,hex:_hex(dk)});
}
function _hmacHex(keyBytes,msg){
  var m=_utf8(msg);
  if(window.crypto&&crypto.subtle){
    return crypto.subtle.importKey('raw',keyBytes,{name:'HMAC',hash:'SHA-256'},false,['sign'])
      .then(function(hk){return crypto.subtle.sign('HMAC',hk,m);})
      .then(function(sig){return _hex(sig);})
      .catch(function(){return _hex(_hmacPure(keyBytes,m));});
  }
  return Promise.resolve(_hex(_hmacPure(keyBytes,m)));
}
function deriveResponse(password,saltHex,iter,nonce){
  return _pbkdf2Hex(password,saltHex,iter).then(function(r){return _hmacHex(r.dk,nonce);});
}
function deriveRecord(password){
  var saltHex=_randSaltHex();
  return _pbkdf2Hex(password,saltHex,PBKDF2_ITER).then(function(r){return {salt:saltHex,iter:PBKDF2_ITER,hash:r.hex};});
}
]]
local LOGIN_JS = [[(function(){
  var form=document.getElementById('login-form');
  if(!form) return;
  form.addEventListener('submit',function(ev){
    ev.preventDefault();
    var user=form.user.value, password=form.password.value;
    var btn=form.querySelector('button'); if(btn) btn.disabled=true;
    fetch('/challenge',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},credentials:'same-origin',body:'user='+encodeURIComponent(user)})
      .then(function(r){return r.json();})
      .then(function(ch){return deriveResponse(password,ch.salt,ch.iter,ch.nonce).then(function(resp){
        var body='user='+encodeURIComponent(user)+'&nonce='+encodeURIComponent(ch.nonce)+'&response='+encodeURIComponent(resp);
        return fetch('/login',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},credentials:'same-origin',body:body});
      });})
      .then(function(r){
        if(r.ok){location.href='/'; return;}
        if(btn) btn.disabled=false;
        alert('Identifiants invalides.');
      })
      .catch(function(){if(btn) btn.disabled=false; alert('Erreur de connexion.');});
  });
})();
]]
local REGISTER_JS = [[(function(){
  var form=document.getElementById('register-form');
  if(!form) return;
  form.addEventListener('submit',function(ev){
    ev.preventDefault();
    var user=form.user.value, password=form.password.value;
    var btn=form.querySelector('button'); if(btn) btn.disabled=true;
    deriveRecord(password).then(function(rec){
      var body='user='+encodeURIComponent(user)+'&salt='+rec.salt+'&iter='+rec.iter+'&hash='+rec.hash;
      return fetch('/register',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},credentials:'same-origin',body:body});
    }).then(function(r){
      return r.text().then(function(t){
        if(r.ok){document.open();document.write(t);document.close();return;}
        if(btn) btn.disabled=false;
        alert(t||'Inscription refusée.');
      });
    }).catch(function(){if(btn) btn.disabled=false; alert('Erreur réseau.');});
  });
})();
]]
local PASSWORD_JS = [[(function(){
  var form=document.getElementById('password-form');
  if(!form) return;
  form.addEventListener('submit',function(ev){
    ev.preventDefault();
    var oldp=form.oldpassword.value, p1=form.password.value, p2=form.password2.value;
    if(p1!==p2){alert('Les mots de passe ne correspondent pas.');return;}
    if(p1.length<8){alert('Au moins 8 caractères.');return;}
    var btn=form.querySelector('button'); if(btn) btn.disabled=true;
    // 1) challenge pour vérifier l'ancien mot de passe (sans le transmettre).
    fetch('/challenge',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},credentials:'same-origin',body:''})
      .then(function(r){return r.json();})
      .then(function(ch){
        return Promise.all([
          deriveResponse(oldp,ch.salt,ch.iter,ch.nonce),
          deriveRecord(p1)
        ]).then(function(out){
          var resp=out[0], rec=out[1];
          var body='nonce='+encodeURIComponent(ch.nonce)+'&response='+resp+'&salt='+rec.salt+'&iter='+rec.iter+'&hash='+rec.hash;
          return fetch('/password',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},credentials:'same-origin',body:body});
        });
      }).then(function(r){
        return r.text().then(function(t){
          if(r.ok){document.open();document.write(t);document.close();return;}
          if(btn) btn.disabled=false;
          alert(t||'Changement refusé.');
        });
      }).catch(function(){if(btn) btn.disabled=false; alert('Erreur réseau.');});
  });
})();
]]
local page
page = function(self)
  return "<!DOCTYPE html>\n" .. H.html({
    lang = "fr",
    H.head({
      H.meta({
        charset = "UTF-8"
      }),
      H.title("CustosVirginum"),
      H.link({
        rel = "icon",
        href = "data:image/svg+xml,<svg viewBox='0 0 100 100'><text y='75' font-size='75'>✞</text></svg>"
      }),
      H.style(css_content)
    }),
    H.body(self)
  })
end
local success_page
success_page = function(auth_cfg, created_at, is_admin)
  local interval = tonumber(auth_cfg and auth_cfg.heartbeat_interval) or 30
  if interval <= 0 then
    interval = 30
  end
  local refusals_interval = tonumber(auth_cfg and auth_cfg.refusals_poll_interval) or 5
  if refusals_interval <= 0 then
    refusals_interval = 5
  end
  local idle_timeout = tonumber(auth_cfg and auth_cfg.idle_timeout) or 300
  local session_start = tonumber(created_at) or 0
  local admin_link
  if is_admin then
    admin_link = H.p(H.a({
      href = "/admin",
      target = "_blank",
      rel = "noopener"
    }, "Administration"))
  else
    admin_link = ""
  end
  return page({
    H.p("Connexion réussie. Votre accès est actif tant que cette fenêtre est ouverte."),
    H.p({
      id = "session-timer"
    }, "Session ouverte depuis : --"),
    admin_link,
    H.p(H.a({
      href = "/password"
    }, "Changer de mot de passe")),
    H.p(H.a({
      href = "/logout"
    }, "Déconnexion")),
    H.div({
      id = "refusals"
    }, H.h2("Domaines bloqués récemment")),
    H.ul({
      id = "refusals-list"
    }, H.li({
      id = "refusals-empty"
    }, "Aucun domaine bloqué pour le moment.")),
    H.script("\n      var refusalsIv = " .. tostring(refusals_interval) .. " * 1000;\n      function renderRefusals(items){\n        var list = document.getElementById('refusals-list');\n        if (!list) return;\n        while (list.firstChild) list.removeChild(list.firstChild);\n        if (!items || items.length === 0) {\n          var empty = document.createElement('li');\n          empty.id = 'refusals-empty';\n          empty.textContent = 'Aucun domaine bloqué pour le moment.';\n          list.appendChild(empty);\n          return;\n        }\n        for (var i = 0; i < items.length; i++) {\n          var it = items[i];\n          var li = document.createElement('li');\n          var txt = it.qname;\n          if (it.reason) txt += ' — ' + it.reason;\n          if (it.count && it.count > 1) txt += ' (×' + it.count + ')';\n          li.textContent = txt;\n          list.appendChild(li);\n        }\n      }\n      function refreshRefusals(){\n        fetch('/refusals',{method:'GET',credentials:'same-origin'})\n          .then(function(r){ return r.ok ? r.json() : null; })\n          .then(function(items){ if (items) renderRefusals(items); })\n          .catch(function(){});\n      }\n      refreshRefusals();\n      setInterval(refreshRefusals, refusalsIv);\n    "),
    H.script("\n      var iv = " .. tostring(interval) .. " * 1000;\n      var idle = " .. tostring(idle_timeout) .. " * 1000;\n      var sessionStart = " .. tostring(session_start) .. ";\n      var workerJs = \"self.onmessage = function(e) { \\n        if (e.data.type === 'start') { \\n          setInterval(function() { self.postMessage({type: 'tick'}); }, e.data.interval); \\n          setTimeout(function() { self.postMessage({type: 'tick'}); }, 3000); \\n        } \\n        if (e.data.type === 'visible') { self.postMessage({type: 'tick'}); } \\n      }\";\n      var worker = new Worker(URL.createObjectURL(new Blob([workerJs], {type: 'application/javascript'})));\n      var lastSuccess = Date.now();\n      var unauthorized = 0;\n      function ping(){\n        fetch('/ping',{method:'GET',credentials:'same-origin'})\n          .then(function(r){\n            if(r.status===401){\n              // Un 401 isolé peut venir d'un ping retardé par le navigateur :\n              // confirmer par un second ping avant d'alerter.\n              unauthorized++;\n              if(unauthorized < 2){ setTimeout(ping, 2000); return; }\n              if(document.visibilityState==='visible')\n                alert('Connexion perdue, veuillez vous authentifier de nouveau.');\n              location.href='/';\n              return;\n            }\n            unauthorized = 0;\n            lastSuccess = Date.now();\n          })\n          .catch(function(){\n            if (Date.now() - lastSuccess > idle) {\n              if (document.visibilityState === 'visible') location.href='/';\n            }\n          });\n      }\n      worker.onmessage = function(e) {\n        if (e.data.type === 'tick') ping();\n      };\n      worker.postMessage({type: 'start', interval: iv});\n      function updateTimer(){\n        var now = Math.floor(Date.now() / 1000);\n        var elapsed = now - sessionStart;\n        if (elapsed < 0) elapsed = 0;\n        var h = Math.floor(elapsed / 3600);\n        var m = Math.floor((elapsed % 3600) / 60);\n        var txt;\n        if (h > 0) {\n          txt = h + 'h ' + (m < 10 ? '0' : '') + m + 'min';\n        } else {\n          txt = m + ' min';\n        }\n        var el = document.getElementById('session-timer');\n        if (el) el.textContent = 'Session ouverte depuis : ' + txt;\n      }\n      setInterval(updateTimer, 10000);\n      updateTimer();\n      document.addEventListener('visibilitychange', function(){\n        if (document.visibilityState === 'visible') worker.postMessage({type: 'visible'});\n      });\n      // pagehide se déclenche aussi sur reload/navigation : ne PAS détruire la\n      // session ici (/logout), seulement raccourcir son expiration (/bye).\n      function bye(){\n        if (navigator.sendBeacon) {\n          navigator.sendBeacon('/bye');\n        } else {\n          fetch('/bye', {method:'POST', keepalive:true, credentials:'same-origin'});\n        }\n      }\n      window.addEventListener('pagehide', function(e){\n        if (!e.persisted) bye();\n      });\n    ")
  })
end
local password_page
password_page = function()
  return page({
    H.form({
      id = "password-form",
      method = "POST",
      action = "/password"
    }, H.label("Ancien mot de passe ", H.input({
      name = "oldpassword",
      type = "password",
      autocomplete = "current-password"
    }), H.br()), H.label("Nouveau mot de passe ", H.input({
      name = "password",
      type = "password",
      autocomplete = "new-password"
    }), H.br()), H.label("Confirmer ", H.input({
      name = "password2",
      type = "password",
      autocomplete = "new-password"
    }), H.br()), H.button({
      type = "submit"
    }, "Changer le mot de passe")),
    H.a({
      href = "/"
    }, "Retour"),
    H.script(CRYPTO_JS .. PASSWORD_JS)
  })
end
local password_changed_page
password_changed_page = function()
  return page({
    H.p("Mot de passe changé."),
    H.a({
      href = "/"
    }, "Retour")
  })
end
return {
  page = page,
  success_page = success_page,
  css_content = css_content,
  password_page = password_page,
  password_changed_page = password_changed_page,
  CRYPTO_JS = CRYPTO_JS,
  LOGIN_JS = LOGIN_JS,
  REGISTER_JS = REGISTER_JS,
  PASSWORD_JS = PASSWORD_JS
}
