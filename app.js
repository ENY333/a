const KEY="cloud_2fa_accounts_v2";
let accounts=JSON.parse(localStorage.getItem(KEY)||"[]");
const $=s=>document.querySelector(s);

function uid(){return crypto.randomUUID?crypto.randomUUID():Date.now()+"-"+Math.random()}
function save(){localStorage.setItem(KEY,JSON.stringify(accounts))}
function cleanSecret(s){return String(s||"").toUpperCase().replace(/[\s\-_=]/g,"")}
function base32(s){
 s=cleanSecret(s);if(!s)throw Error("Chưa nhập Secret Key.");
 const abc="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";let bits="",out=[];
 for(const c of s){let n=abc.indexOf(c);if(n<0)throw Error("Secret Key không hợp lệ.");bits+=n.toString(2).padStart(5,"0")}
 for(let i=0;i+8<=bits.length;i+=8)out.push(parseInt(bits.slice(i,i+8),2));
 return new Uint8Array(out)
}
function alg(a){return a==="SHA-256"?"SHA-256":a==="SHA-512"?"SHA-512":"SHA-1"}
function parseUri(raw){
 let u;try{u=new URL(raw.trim())}catch{throw Error("otpauth URI không hợp lệ.")}
 if(u.protocol!=="otpauth:"||u.host!=="totp")throw Error("URI phải có dạng otpauth://totp/...")
 const secret=u.searchParams.get("secret");if(!secret)throw Error("URI không có secret.")
 return {secret,name:decodeURIComponent(u.pathname.slice(1))||"2FA Account",issuer:u.searchParams.get("issuer")||"",digits:+(u.searchParams.get("digits")||6),algorithm:alg((u.searchParams.get("algorithm")||"SHA-1").toUpperCase().replace("SHA1","SHA-1")),period:+(u.searchParams.get("period")||30)}
}
function findKey(text){
 const uri=text.match(/otpauth:\/\/totp\/[^\s<>"']+/i);if(uri)return {uri:uri[0],...parseUri(uri[0])};
 const lines=text.split(/\r?\n/);
 let email="",key="";
 for(const l of lines){
  if(/email|account|username/i.test(l)&&!email){let m=l.match(/(?:email|account|username)\s*[:=]\s*(.+)/i);if(m)email=m[1].trim()}
  if(/(?:secret\s*key|security\s*key|key|mã|ma)\s*[:=]/i.test(l)&&!key){let m=l.match(/(?:secret\s*key|security\s*key|key|mã|ma)\s*[:=]\s*([A-Za-z2-7\s=-]{8,})/i);if(m)key=m[1]}
 }
 if(!key){
  const candidates=text.match(/\b[A-Z2-7](?:[\s-]*[A-Z2-7]){15,}\b/gi)||[];
  key=candidates.sort((a,b)=>b.length-a.length)[0]||"";
 }
 if(!key)throw Error("Không tìm thấy Secret Key. Hãy nhập key hoặc dán otpauth URI.");
 return {secret:cleanSecret(key),email}
}
async function hotp(a,c){
 const k=await crypto.subtle.importKey("raw",base32(a.secret),{name:"HMAC",hash:{name:alg(a.algorithm)}},false,["sign"]);
 const b=new ArrayBuffer(8),v=new DataView(b);v.setUint32(0,Math.floor(c/4294967296));v.setUint32(4,c>>>0);
 const m=new Uint8Array(await crypto.subtle.sign("HMAC",k,b)),o=m[m.length-1]&15;
 const n=((m[o]&127)<<24)|((m[o+1]&255)<<16)|((m[o+2]&255)<<8)|(m[o+3]&255);
 return String(n%(10**a.digits)).padStart(a.digits,"0")
}
async function otp(a){return hotp(a,Math.floor(Date.now()/1000/(a.period||30)))}

function render(){
 $("#count").textContent=accounts.length;$("#empty").classList.toggle("hidden",accounts.length>0);$("#list").innerHTML="";
 for(const a of accounts){
  let c=document.createElement("article");c.className="card";c.dataset.id=a.id;
  c.innerHTML=`<div class="top"><div><div class="name">${esc(a.name)}</div><div class="meta">${esc(a.account||a.issuer||"TOTP")} · ${a.digits} digits · ${a.algorithm}</div></div>
  <div class="menu"><button class="menubtn">⋮</button><div class="pop"><button class="rename">Đổi tên</button><button class="del delete">Xóa key</button></div></div></div>
  <div class="code-row"><div class="code">------</div><button class="copy">Copy</button></div>
  <div class="bar"><i></i></div><div class="bottom"><span>TOTP · tự động đổi</span><span class="left">--s</span></div>`;
  $("#list").appendChild(c)
 }
}
function esc(s){return String(s||"").replace(/[&<>"']/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[m]))}
function openModal(){ $("#modal").classList.remove("hidden");$("#error").classList.add("hidden");$("#name").focus() }
function closeModal(){$("#modal").classList.add("hidden")}
function toast(s){let t=$("#toast");t.textContent=s;t.classList.add("show");clearTimeout(window.tt);window.tt=setTimeout(()=>t.classList.remove("show"),1700)}

document.addEventListener("click",async e=>{
 if(e.target.id==="addBtn"||e.target.id==="emptyAdd")openModal();
 if(e.target.id==="close"||e.target.classList.contains("backdrop"))closeModal();
 if(e.target.classList.contains("tab")){
  document.querySelectorAll(".tab").forEach(x=>x.classList.remove("active"));e.target.classList.add("active");
  ["keyMode","uriMode","pasteMode"].forEach(x=>$("#"+x).classList.add("hidden"));$("#"+e.target.dataset.mode+"Mode").classList.remove("hidden");
 }
 if(e.target.id==="advancedToggle")$("#advancedFields").classList.toggle("hidden");
 if(e.target.id==="save"){
  try{
   let mode=document.querySelector(".tab.active").dataset.mode, data;
   if(mode==="uri")data=parseUri($("#uri").value);
   else if(mode==="paste")data=findKey($("#paste").value);
   else data={secret:cleanSecret($("#secret").value),name:$("#name").value.trim(),account:$("#account").value.trim()};
   if(!data.secret)throw Error("Chưa nhập Secret Key.");
   base32(data.secret);
   let a={id:uid(),name:data.name||data.account||"2FA Account",account:data.account||"",issuer:data.issuer||"",secret:data.secret,digits:data.digits||+$("#digits").value,algorithm:data.algorithm||$("#algorithm").value,period:data.period||+$("#period").value};
   await otp(a);accounts.unshift(a);save();render();closeModal();toast("Đã lưu tài khoản.");
  }catch(err){$("#error").textContent=err.message||"Dữ liệu không hợp lệ.";$("#error").classList.remove("hidden")}
 }
 if(e.target.classList.contains("menubtn")){let p=e.target.nextElementSibling;document.querySelectorAll(".pop").forEach(x=>x!==p&&x.classList.remove("show"));p.classList.toggle("show")}
 if(e.target.classList.contains("delete")){let id=e.target.closest(".card").dataset.id;if(confirm("Xóa key này khỏi trình duyệt?")){accounts=accounts.filter(x=>x.id!==id);save();render();toast("Đã xóa.")}}
 if(e.target.classList.contains("rename")){let a=accounts.find(x=>x.id===e.target.closest(".card").dataset.id),n=prompt("Tên mới:",a.name);if(n&&n.trim()){a.name=n.trim();save();render();toast("Đã đổi tên.")}}
 if(e.target.classList.contains("copy")){let code=e.target.closest(".card").querySelector(".code").textContent;if(code!=="------"){await navigator.clipboard.writeText(code);toast("Đã copy OTP.")}}
});
$("#secret").addEventListener("input",()=>{$("#secret").value=$("#secret").value.replace(/[^\x00-\x7F]/g,"")});
render();
async function tick(){
 const now=Date.now();
 for(const c of document.querySelectorAll(".card")){
  const a=accounts.find(x=>x.id===c.dataset.id);if(!a)continue;
  try{c.querySelector(".code").textContent=await otp(a);let p=a.period||30,left=p-(Math.floor(now/1000)%p);c.querySelector(".left").textContent=left+"s";c.querySelector(".bar i").style.width=(left/p*100)+"%"}catch{c.querySelector(".code").textContent="ERROR"}
 }
}
tick();setInterval(tick,1000)
