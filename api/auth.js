const {setCookie,readBody,send,rnd,maskKey,getLicenseByKey,currentSession,sb}=require('./_lib');

module.exports = async (req,res)=>{

try{

const url=new URL(req.url,'http://localhost');

const action=url.searchParams.get('action')||'session';

if(action==='session'){

const s=await currentSession(req);

if(!s)return send(res,401,{error:'Not authenticated'});

return send(res,200,{authenticated:true,...s});

}

const b=await readBody(req);

if(action==='login'){
const key=String(b.key||'').trim().toUpperCase();
const deviceId=String(b.deviceId||'').trim();

if(!key||!deviceId)return send(res,400,{error:'Key and device ID are required.'});

const license=await getLicenseByKey(key);

if(!license||license.is_revoked)return send(res,401,{error:'Invalid or revoked key.'});

const claimRows=await sb('/rest/v1/rpc/claim_license_device',{
method:'POST',headers:{Prefer:'return=representation'},
body:JSON.stringify({p_license_id:license.id,p_device_id:deviceId})
});
const claim=claimRows?.[0]||claimRows;

if(!claim?.ok){
if(claim?.code==='device_bound') return send(res,409,{error:'This key is already active on another device. Use Device logged out first.'});
if(claim?.code==='revoked') return send(res,401,{error:'This key has been revoked.'});
return send(res,401,{error:'This key is not available.'});
}

const token=rnd(32);

await sb('/rest/v1/license_sessions',{
method:'POST',headers:{Prefer:'return=minimal'},
body:JSON.stringify({token,license_id:license.id,device_id:deviceId,expires_at:new Date(Date.now()+365*24*60*60*1000).toISOString()})
});

/* PostgREST filters require field=eq.value. */
await sb('/rest/v1/license_keys?id=eq.'+encodeURIComponent(license.id),{
method:'PATCH',headers:{Prefer:'return=minimal'},
body:JSON.stringify({last_login_at:new Date().toISOString()})
});

setCookie(res,'htx_session',token,365*24*60*60);

return send(res,200,{
authenticated:true,licenseId:license.id,role:license.role,
deviceCount:Number(claim.device_count||1),maxDevices:license.role==='developer'?null:1,
keyMasked:maskKey(license.license_key)
});

}

if(action==='logout'){

const s=await currentSession(req);

if(!s){setCookie(res,'htx_session','',0);return send(res,200,{ok:true})}

const deviceId=String(b.deviceId||s.deviceId);

await sb('/rest/v1/license_sessions?license_id=eq.'+encodeURIComponent(s.licenseId)+'&device_id=eq.'+encodeURIComponent(deviceId),{method:'DELETE'});
await sb('/rest/v1/license_devices?license_id=eq.'+encodeURIComponent(s.licenseId)+'&device_id=eq.'+encodeURIComponent(deviceId),{method:'DELETE'});

setCookie(res,'htx_session','',0);

return send(res,200,{ok:true});

}

return send(res,400,{error:'Unknown action'});

}catch(err){

return send(res,500,{error:err.message||'Server error'});

}

};
