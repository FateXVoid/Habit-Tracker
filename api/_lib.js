const crypto = require('crypto');

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const DEV_PASSWORD_SALT_B64 = process.env.DEV_PASSWORD_SALT_B64;
const DEV_PASSWORD_HASH_B64 = process.env.DEV_PASSWORD_HASH_B64;
const DEV_SESSION_SECRET = process.env.DEV_SESSION_SECRET;

function parseCookie(req,name){
  const h=req.headers.cookie||'';
  const m=h.split(';').map(x=>x.trim()).find(x=>x.startsWith(name+'='));
  return m?decodeURIComponent(m.slice(name.length+1)):'';
}
function setCookie(res,name,value,maxAge){
  const attrs=[`${name}=${encodeURIComponent(value)}`,'Path=/','HttpOnly','Secure','SameSite=Lax',`Max-Age=${Math.max(0,Math.floor(maxAge||0))}`];
  res.setHeader('Set-Cookie',attrs.join('; '));
}
function rnd(n=24){return crypto.randomBytes(n).toString('hex')}
function maskKey(k){return k.slice(0,4)+'••••'+k.slice(-4)}
async function readBody(req){
  if(req.method==='GET') return {};
  return new Promise((resolve,reject)=>{
    let s='';req.on('data',c=>s+=c);req.on('end',()=>{try{resolve(s?JSON.parse(s):{})}catch(e){reject(e)}});req.on('error',reject);
  });
}
function send(res,status,data,headers={}){
  res.statusCode=status;
  Object.entries(headers).forEach(([k,v])=>res.setHeader(k,v));
  res.setHeader('Content-Type','application/json; charset=utf-8');
  res.end(JSON.stringify(data));
}
async function sb(path,init={}){
  if(!SUPABASE_URL||!SUPABASE_SERVICE_ROLE_KEY) throw new Error('Supabase server environment is not configured.');
  const r=await fetch(SUPABASE_URL+path,{
    ...init,
    headers:{
      apikey:SUPABASE_SERVICE_ROLE_KEY,
      Authorization:'Bearer '+SUPABASE_SERVICE_ROLE_KEY,
      'Content-Type':'application/json',
      ...(init.headers||{})
    }
  });
  const text=await r.text();
  let data=null;try{data=text?JSON.parse(text):null}catch{data=text}
  if(!r.ok){const e=new Error(data?.message||data?.error||'Database request failed');e.status=r.status;throw e}
  return data;
}
function passwordOk(pass){
  if(!DEV_PASSWORD_SALT_B64||!DEV_PASSWORD_HASH_B64)return false;
  const salt=Buffer.from(DEV_PASSWORD_SALT_B64,'base64');
  const expected=Buffer.from(DEV_PASSWORD_HASH_B64,'base64');
  const got=crypto.scryptSync(String(pass||''),salt,32,{N:16384,r:8,p:1});
  return got.length===expected.length && crypto.timingSafeEqual(got,expected);
}
function adminSign(ts,nonce){
  if(!DEV_SESSION_SECRET) throw new Error('DEV_SESSION_SECRET is not configured.');
  return crypto.createHmac('sha256',DEV_SESSION_SECRET).update(ts+'.'+nonce).digest('hex');
}
function isAdmin(req){
  const cookie=parseCookie(req,'htx_dev_session');if(!cookie)return false;
  const [ts,nonce,sig]=cookie.split('.');
  if(!ts||!nonce||!sig)return false;
  const age=Date.now()-Number(ts);
  if(!Number.isFinite(age)||age<0||age>8*60*60*1000)return false;
  const expected=adminSign(ts,nonce);
  try{return crypto.timingSafeEqual(Buffer.from(sig),Buffer.from(expected))}catch{return false}
}
function genKey(){
  const part=()=>crypto.randomBytes(4).toString('hex').toUpperCase();
  return `${part()}-${part()}-${part()}-${part()}`;
}
async function getLicenseByKey(key){
  const rows=await sb('/rest/v1/license_keys?select=id,license_key,role,is_revoked,created_at,last_login_at&license_key=eq.'+encodeURIComponent(key)+'&limit=1');
  return rows?.[0]||null;
}
async function getDevices(licenseId){
  return await sb('/rest/v1/license_devices?select=id,device_id,created_at&license_id=eq.'+encodeURIComponent(licenseId)+'&order=created_at.asc');
}
async function currentSession(req){
  const token=parseCookie(req,'htx_session');if(!token)return null;
  const rows=await sb('/rest/v1/license_sessions?select=id,license_id,device_id,expires_at,license_keys!inner(id,license_key,role,is_revoked)&token=eq.'+encodeURIComponent(token)+'&limit=1');
  const row=rows?.[0];if(!row||row.license_keys.is_revoked)return null;
  if(row.expires_at && new Date(row.expires_at)<new Date())return null;
  const devices=await getDevices(row.license_id);
  return {
    licenseId:row.license_id,
    role:row.license_keys.role,
    deviceId:row.device_id,
    deviceCount:devices.length,
    maxDevices:row.license_keys.role==='developer'?null:1,
    keyMasked:maskKey(row.license_keys.license_key)
  };
}
module.exports={parseCookie,setCookie,rnd,maskKey,readBody,send,sb,passwordOk,adminSign,isAdmin,genKey,getLicenseByKey,getDevices,currentSession};
