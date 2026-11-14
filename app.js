const STORAGE_KEY = "cloud_2fa_accounts_v1";
const $ = s => document.querySelector(s);
let accounts = loadAccounts();

function loadAccounts(){
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]"); }
  catch { return []; }
}
function persist(){ localStorage.setItem(STORAGE_KEY, JSON.stringify(accounts)); }
function uid(){ return crypto.randomUUID ? crypto.randomUUID() : Date.now()+"-"+Math.random(); }

function base32Decode(str){
  const clean = str.toUpperCase().replace(/[\s-]/g,"").replace(/=+$/,"");
  const alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits="", out=[];
  for(const ch of clean){
    const n=alphabet.indexOf(ch);
    if(n<0) throw new Error("Secret Key không hợp lệ.");
    bits += n.toString(2).padStart(5,"0");
  }
  for(let i=0;i+8<=bits.length;i+=8) out.push(parseInt(bits.slice(i,i+8),2));
  return new Uint8Array(out);
}
function parseOtpAuth(raw){
  if(!raw.trim().toLowerCase().startsWith("otpauth://")) return null;
  const u=new URL(raw.trim());
  if(u.protocol!=="otpauth:" || u.host!=="totp") throw new Error("Chỉ hỗ trợ otpauth://totp/...");

  const secret=u.searchParams.get("secret");
  if(!secret) throw new Error("URI chưa có secret.");
  return {
    name: decodeURIComponent(u.pathname.replace(/^\/+/,"")) || "2FA Account",
    issuer: u.searchParams.get("issuer") || "",
    secret,
    digits: Number(u.searchParams.get("digits") || 6),
    algorithm: (u.searchParams.get("algorithm") || "SHA1").toUpperCase().replace("-","-"),
    period: Number(u.searchParams.get("period") || 30)
  };
}
function algoName(a){ return a === "SHA-256" ? "SHA-256" : a === "SHA-512" ? "SHA-512" : "SHA-1"; }

async function hotp(secret, counter, digits, algorithm){
  const key=await crypto.subtle.importKey("raw",base32Decode(secret),{name:"HMAC",hash:{name:algoName(algorithm)}},false,["sign"]);
  const buf=new ArrayBuffer(8), view=new DataView(buf);
  view.setUint32(0,Math.floor(counter/0x100000000));
  view.setUint32(4,counter>>>0);
  const mac=new Uint8Array(await crypto.subtle.sign("HMAC",key,buf));
  const offset=mac[mac.length-1]&15;
  const bin=((mac[offset]&127)<<24)|((mac[offset+1]&255)<<16)|((mac[offset+2]&255)<<8)|(mac[offset+3]&255);
  return String(bin % 10**digits).padStart(digits,"0");
}
async function totp(account, now=Date.now()){
  const period=account.period || 30;
  const counter=Math.floor(now/1000/period);
  return hotp(account.secret,counter,account.digits||6,account.algorithm||"SHA-1");
}

function esc(s){return String(s).replace(/[&<>"']/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[m]));}

function render(){
  $("#countStat").textContent=accounts.length;
  $("#emptyState").classList.toggle("hidden",accounts.length!==0);
  const list=$("#keyList");
  list.innerHTML="";
  accounts.forEach(a=>{
    const card=document.createElement("article");
    card.className="card";
    card.dataset.id=a.id;
    card.innerHTML=`
      <div class="card-top">
        <div>
          <div class="account">${esc(a.name || "2FA Account")}</div>
          <div class="meta">${esc(a.issuer || "Local TOTP")} · ${a.digits||6} digits · ${esc(a.algorithm||"SHA-1")}</div>
        </div>
        <div class="menu">
          <button class="menu-btn" aria-label="Menu">⋮</button>
          <div class="menu-pop">
            <button class="rename-btn">Đổi tên</button>
            <button class="delete delete-btn">Xóa key</button>
          </div>
        </div>
      </div>
      <div class="code-row"><div class="code">------</div><button class="copy">Copy</button></div>
      <div class="progress"><i></i></div>
      <div class="count"><span>Refresh tự động</span><span class="seconds">--s</span></div>`;
    list.appendChild(card);
  });
}
function openModal(account=null){
  $("#modal").classList.remove("hidden");
  $("#formError").classList.add("hidden");
  $("#nameInput").value=account?.name||"";
  $("#secretInput").value=account?.secret||"";
  $("#digitsInput").value=account?.digits||6;
  $("#algorithmInput").value=account?.algorithm||"SHA-1";
  $("#periodInput").value=account?.period||30;
  $("#saveBtn").dataset.editId=account?.id||"";
  $("#nameInput").focus();
}
function closeModal(){$("#modal").classList.add("hidden");}
function toast(msg){
  const t=$("#toast");t.textContent=msg;t.classList.add("show");
  clearTimeout(window.__toast);window.__toast=setTimeout(()=>t.classList.remove("show"),1800);
}

async function saveAccount(){
  const raw=$("#secretInput").value.trim();
  const err=$("#formError");
  try{
    let parsed=parseOtpAuth(raw);
    const secret=parsed?.secret || raw.replace(/\s/g,"");
    base32Decode(secret);
    if(!secret) throw new Error("Hãy nhập Secret Key.");
    const account={
      id:$("#saveBtn").dataset.editId || uid(),
      name:$("#nameInput").value.trim() || parsed?.name || "2FA Account",
      issuer:parsed?.issuer || "",
      secret,
      digits:Number(parsed?.digits || $("#digitsInput").value),
      algorithm:parsed?.algorithm ? algoName(parsed.algorithm) : $("#algorithmInput").value,
      period:Number(parsed?.period || $("#periodInput").value),
      createdAt:Date.now()
    };
    const test=await totp(account);
    if(!/^\\d+$/.test(test)) throw new Error("Không tạo được OTP.");
    const idx=accounts.findIndex(x=>x.id===account.id);
    if(idx>=0) accounts[idx]=account; else accounts.unshift(account);
    persist(); render(); closeModal(); toast("Đã lưu key.");
  }catch(e){
    err.textContent=e.message||"Secret Key không hợp lệ.";
    err.classList.remove("hidden");
  }
}

document.addEventListener("click",async e=>{
  if(e.target.id==="addTopBtn"||e.target.id==="emptyAddBtn") openModal();
  if(e.target.id==="closeModal"||e.target.classList.contains("backdrop")) closeModal();
  if(e.target.id==="saveBtn") await saveAccount();
  if(e.target.id==="themeBtn"){
    document.body.classList.toggle("light");
    localStorage.setItem("cloud_2fa_theme",document.body.classList.contains("light")?"light":"dark");
  }
  if(e.target.classList.contains("menu-btn")){
    const pop=e.target.nextElementSibling;
    document.querySelectorAll(".menu-pop").forEach(x=>x!==pop&&x.classList.remove("show"));
    pop.classList.toggle("show");
  }
  if(e.target.classList.contains("delete-btn")){
    const id=e.target.closest(".card").dataset.id;
    if(confirm("Xóa key này khỏi trình duyệt?")){
      accounts=accounts.filter(x=>x.id!==id);persist();render();toast("Đã xóa key.");
    }
  }
  if(e.target.classList.contains("rename-btn")){
    const card=e.target.closest(".card"), id=card.dataset.id, a=accounts.find(x=>x.id===id);
    const name=prompt("Tên mới:",a.name);
    if(name!==null && name.trim()){a.name=name.trim();persist();render();toast("Đã đổi tên.");}
  }
  if(e.target.classList.contains("copy")){
    const code=e.target.closest(".card").querySelector(".code").textContent;
    if(code!=="------"){await navigator.clipboard.writeText(code);toast("Đã copy OTP.");}
  }
});
$("#secretInput").addEventListener("keydown",e=>{if((e.ctrlKey||e.metaKey)&&e.key==="Enter")saveAccount();});
if(localStorage.getItem("cloud_2fa_theme")==="light")document.body.classList.add("light");

async function refreshCodes(){
  const now=Date.now();
  document.querySelectorAll(".card").forEach(async card=>{
    const a=accounts.find(x=>x.id===card.dataset.id); if(!a)return;
    try{
      card.querySelector(".code").textContent=await totp(a,now);
      const period=a.period||30, elapsed=Math.floor(now/1000)%period, left=period-elapsed;
      card.querySelector(".seconds").textContent=left+"s";
      card.querySelector(".progress i").style.width=(left/period*100)+"%";
    }catch{card.querySelector(".code").textContent="ERROR";}
  });
}
render(); refreshCodes(); setInterval(refreshCodes,1000);
