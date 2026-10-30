/** SYNTERX Netlify API: single same-origin bridge to Google Sheets. */
import { randomBytes, createHmac, createHash, scrypt as scryptCb, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
const scrypt = promisify(scryptCb);
const COOKIE_NAME = 'synterx_session';
const SESSION_AGE_SECONDS = 86400;
const json = (data,status=200,extras={})=>new Response(JSON.stringify(data),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff',...extras}});
const hash = s=>createHash('sha256').update(s).digest('hex');
const equal = (a,b)=>{const x=Buffer.from(hash(String(a))),y=Buffer.from(hash(String(b)));return timingSafeEqual(x,y)};
const required = (key)=>{const v=process.env[key];if(!v)throw new Error('Hiányzó Netlify környezeti változó: '+key);return v};
const safeUser = u=>({id:String(u.id),email:String(u.email),displayName:String(u.displayName||''),role:u.role==='developer'?'developer':'customer',discordId:String(u.discordId||''),discordName:String(u.discordName||'')});
async function bridge(action,payload={}){
  const url=required('APPS_SCRIPT_URL'),secret=required('APPS_SCRIPT_BRIDGE_SECRET');
  if(!/^https:\/\/script\.google\.com\/macros\/s\/[A-Za-z0-9_-]+\/exec$/.test(url))throw Error('Hibás APPS_SCRIPT_URL.');
  const controller=new AbortController();
  const timeout=setTimeout(()=>controller.abort(),22000);
  try{
    const res=await fetch(url,{method:'POST',headers:{'content-type':'text/plain;charset=utf-8'},body:JSON.stringify({secret,action,payload}),redirect:'follow',signal:controller.signal});
    const txt=await res.text();let response;
    try{response=JSON.parse(txt)}catch{throw Error('Az Apps Script nem adott JSON választ. Ellenőrizd a hozzáférést és az új telepítést.');}
    if(!response.ok)throw Error(response.error||'Apps Script hiba.');
    return response.data;
  }finally{clearTimeout(timeout)}
}
async function passwordHash(password,salt){return (await scrypt(password+required('PASSWORD_PEPPER'),Buffer.from(salt,'hex'),64)).toString('hex')}
function makeSession(u){
  const content=Buffer.from(JSON.stringify({id:String(u.id),exp:Math.floor(Date.now()/1000)+SESSION_AGE_SECONDS})).toString('base64url');
  const sign=createHmac('sha256',required('SESSION_SECRET')).update(content).digest('base64url');
  return content+'.'+sign;
}
function readSession(req){
  const cookies=req.headers.get('cookie')||'';
  const match=cookies.split(';').map(x=>x.trim()).find(x=>x.startsWith(COOKIE_NAME+'='));
  if(!match)return null;
  const token=match.slice(COOKIE_NAME.length+1);const [content,sig,other]=token.split('.');
  if(!content||!sig||other!==undefined)return null;
  const sign=createHmac('sha256',required('SESSION_SECRET')).update(content).digest('base64url');
  if(!equal(sig,sign))return null;
  try{const obj=JSON.parse(Buffer.from(content,'base64url').toString());return obj.id&&Number(obj.exp)>Date.now()/1000?obj:null}catch{return null}
}
const setCookie=token=>`${COOKIE_NAME}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_AGE_SECONDS}`;
const clearCookie=()=>`${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
async function me(req){const session=readSession(req);if(!session)return null;const u=await bridge('findUserById',{id:session.id});return u?u:null}
async function needUser(req,admin=false){const u=await me(req);if(!u)throw Error('Előbb jelentkezz be.');if(admin&&u.role!=='developer')throw Error('Nincs fejlesztői jogosultságod.');return u}
// Discord OAuth2: server-side code exchange, session-bound state cookie.
const DISCORD_STATE_COOKIE = 'sx_discord_state';
function getCookie(req, key) {
  return (req.headers.get('cookie') || '').split(';').map(x=>x.trim())
    .find(x=>x.startsWith(key+'='))?.slice(key.length+1) || '';
}
const oauthCookie = (value, maxAge) =>
  `${DISCORD_STATE_COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
const oauthRedirect = (path, cookie) => new Response(null,{status:302,headers:{
  location:path,'cache-control':'no-store',...(cookie?{'set-cookie':cookie}:{})
}});
function discordCallbackUrl(req){
  // Always derive from current deployment origin. Add this exact URL in the Discord portal.
  return new URL('/.netlify/functions/api?oauth=callback',req.url).href;
}
async function discordRoute(req) {
  const url = new URL(req.url), mode=url.searchParams.get('oauth');
  const u = await needUser(req);
  if(mode==='start') {
    const state=randomBytes(24).toString('hex');
    const redirect=discordCallbackUrl(req);
    const auth=new URL('https://discord.com/oauth2/authorize');
    auth.searchParams.set('response_type','code');
    auth.searchParams.set('client_id',required('DISCORD_CLIENT_ID'));
    auth.searchParams.set('redirect_uri',redirect);
    auth.searchParams.set('scope','identify');
    auth.searchParams.set('state',state);
    auth.searchParams.set('prompt','consent');
    const packed=Buffer.from(JSON.stringify({state,userId:u.id,created:Date.now()})).toString('base64url');
    return oauthRedirect(auth.href,oauthCookie(packed,600));
  }
  if(mode==='callback') {
    const packed=getCookie(req,DISCORD_STATE_COOKIE);
    const clear=oauthCookie('',0);
    let data;
    try { data=JSON.parse(Buffer.from(packed,'base64url').toString()); }catch{return oauthRedirect('/?discord=error',clear)}
    if(!data||data.userId!==u.id||Date.now()-Number(data.created)>600000||
       !equal(url.searchParams.get('state')||'',data.state||'')||
       !/^[a-f0-9]{48}$/.test(data.state||'')||
       !url.searchParams.has('code')) return oauthRedirect('/?discord=error',clear);
    const form=new URLSearchParams({client_id:required('DISCORD_CLIENT_ID'),client_secret:required('DISCORD_CLIENT_SECRET'),
      grant_type:'authorization_code',code:url.searchParams.get('code'),redirect_uri:discordCallbackUrl(req)});
    try {
      const exchange=await fetch('https://discord.com/api/v10/oauth2/token',{
        method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:form
      });
      if(!exchange.ok) throw Error('OAuth token exchange failed');
      const token=await exchange.json();
      const meResponse=await fetch('https://discord.com/api/v10/users/@me',{
        headers:{authorization:'Bearer '+token.access_token}
      });
      if(!meResponse.ok) throw Error('Discord account request failed');
      const discord=await meResponse.json();
      if(!/^\d{15,22}$/.test(String(discord.id))) throw Error('Invalid Discord ID');
      await bridge('linkDiscord',{userId:u.id,discordId:String(discord.id),
        discordName:String(discord.global_name||discord.username||'Discord user').slice(0,80)});
      return oauthRedirect('/?discord=connected',clear);
    } catch(err) {
      console.error('Discord OAuth error:',String(err.message));
      return oauthRedirect('/?discord=error',clear);
    }
  }
  return json({ok:false,error:'Unknown OAuth route'},404);
}

function validateEmail(v){const s=String(v||'').trim().toLowerCase();if(s.length>254||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s))throw Error('Hibás e-mail cím.');return s}
function validatePassword(s){if(typeof s!=='string'||s.length<12||s.length>128)throw Error('A jelszó legyen 12–128 karakter.');return s}
export default async (req)=>{
  if(req.method==='GET' && new URL(req.url).searchParams.has('oauth')) {
    try{return await discordRoute(req)}catch(err){console.error('Discord route:',String(err.message));return oauthRedirect('/?discord=error',oauthCookie('',0))}
  }
  if(req.method!=='POST')return json({ok:false,error:'POST required.'},405);
  const origin=req.headers.get('origin');
  if(origin&&origin!==new URL(req.url).origin)return json({ok:false,error:'Origin rejected.'},403);
  if(!(req.headers.get('content-type')||'').startsWith('application/json'))return json({ok:false,error:'JSON required.'},415);
  try{
    if(Number(req.headers.get('content-length')||0)>3500000)throw Error('Túl nagy kérés.');
    const {action,payload:p={}}=await req.json();
    let data,extra={};
    switch(action){
      case 'getStorefront':data=await bridge('getStorefront');break;
      case 'register':{
        const email=validateEmail(p.email),password=validatePassword(p.password),displayName=String(p.displayName||'').trim().slice(0,55);
        if(displayName.length<2)throw Error('A név legalább 2 karakter.');
        const reserved=(process.env.ADMIN_EMAIL||'').trim().toLowerCase();
        let role='customer';
        if(reserved&&email===reserved){
          if(!process.env.ADMIN_SETUP_CODE||!equal(p.adminCode||'',process.env.ADMIN_SETUP_CODE))throw Error('A tulajdonosi fiókhoz az aktiváló kód szükséges.');
          role='developer';
        }else if(p.adminCode){throw Error('Ez az aktiváló kód csak a tulajdonosi e-mail címmel használható.');}
        const salt=randomBytes(16).toString('hex');
        const u=await bridge('createUser',{email,displayName,role,passwordSalt:salt,passwordHash:await passwordHash(password,salt)});
        data={user:safeUser(u)};extra={'set-cookie':setCookie(makeSession(u))};break;
      }
      case 'login':{
        const email=validateEmail(p.email),password=String(p.password||'');
        const u=await bridge('findUserByEmail',{email});
        const lockExpiry=u?.lockedUntil?new Date(u.lockedUntil).getTime():0;
        if(lockExpiry>Date.now())throw Error('Túl sok hibás próbálkozás. Próbáld 15 perc múlva.');
        const salt=u&&/^[a-f0-9]{32}$/.test(String(u.passwordSalt||''))?String(u.passwordSalt):'00000000000000000000000000000000';
        const calculated=await passwordHash(password,salt);
        if(!u||!equal(calculated,u.passwordHash||'')){
          if(u)await bridge('loginFailure',{id:u.id});
          throw Error('Hibás e-mail cím vagy jelszó.');
        }
        await bridge('loginSuccess',{id:u.id});
        data={user:safeUser(u)};extra={'set-cookie':setCookie(makeSession(u))};break;
      }
      case 'me':{
        const u=await me(req);data={user:u?safeUser(u):null};break;
      }
      case 'logout':data={ok:true};extra={'set-cookie':clearCookie()};break;
      case 'requestReset':{
        const email=validateEmail(p.email);const u=await bridge('findUserByEmail',{email});
        if(u){
          const token=randomBytes(32).toString('base64url');
          const link=new URL('/',req.url);
          link.searchParams.set('reset',token);link.searchParams.set('email',email);
          await bridge('saveResetToken',{id:u.id,resetHash:hash(token),url:link.toString()});
        }
        data={message:'Ha az e-mail címed regisztrálva van, érkezik egy visszaállító link.'};break;
      }
      case 'resetPassword':{
        const email=validateEmail(p.email),token=String(p.token||'');
        if(!/^[A-Za-z0-9_-]{32,100}$/.test(token))throw Error('Érvénytelen visszaállító link.');
        const password=validatePassword(p.password),salt=randomBytes(16).toString('hex');
        await bridge('consumeResetToken',{email,resetHash:hash(token),passwordSalt:salt,passwordHash:await passwordHash(password,salt)});
        data={message:'Jelszó megváltoztatva. Jelentkezz be.'};extra={'set-cookie':clearCookie()};break;
      }
      case 'getAdminProducts':await needUser(req,true);data=await bridge('getAdminProducts');break;
      case 'getAdminOrders':await needUser(req,true);data=await bridge('getAdminOrders');break;
      case 'saveProduct':await needUser(req,true);data=await bridge('saveProduct',p);break;
      case 'deleteProduct':await needUser(req,true);data=await bridge('hideProduct',{id:p.id});break;
      case 'uploadProductImage':await needUser(req,true);data=await bridge('uploadImage',p);break;
      case 'startCheckout':{
        const u=await needUser(req);
        if(!u.discordId)throw Error('Vásárláshoz előbb kösd össze a Discord-fiókodat!');
        data=await bridge('startCheckout',{productId:String(p.productId||''),userId:u.id});break;
      }
      default:throw Error('Ismeretlen művelet.');
    }
    return json({ok:true,data},200,extra);
  }catch(err){
    console.error('SYNTERX API:',String(err.message||err));
    // No database hashes, passwords or secrets are returned in errors.
    return json({ok:false,error:String(err.message||'Szerverhiba').slice(0,190)},400);
  }
};

// Imported by the separately deployed Stripe webhook function. This is never exposed to the browser.
export { bridge };
