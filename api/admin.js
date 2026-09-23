const {setCookie,readBody,send,passwordOk,adminSign,isAdmin,genKey,sb}=require('./_lib');

module.exports = async (req,res)=>{
  try{
    const url=new URL(req.url,'http://localhost');
    const action=url.searchParams.get('action')||'session';

    if(action==='login'){
      const b=await readBody(req);
      if(!passwordOk(b.password))return send(res,401,{error:'Invalid developer password.'});
      const ts=String(Date.now()),nonce=genKey(),sig=adminSign(ts,nonce);
      setCookie(res,'htx_dev_session',ts+'.'+nonce+'.'+sig,8*60*60);
      return send(res,200,{ok:true});
    }
    if(action==='logout'){
      setCookie(res,'htx_dev_session','',0);return send(res,200,{ok:true});
    }
    if(!isAdmin(req))return send(res,401,{error:'Developer access required.'});

    if(action==='session')return send(res,200,{authenticated:true});

    if(action==='generate'){
      const b=await readBody(req);
      const role=b.role==='developer'?'developer':'user';
      let key='';
      for(let i=0;i<6;i++){
        key=genKey();
        try{
          const rows=await sb('/rest/v1/license_keys?select=id&license_key=eq.'+encodeURIComponent(key)+'&limit=1');
          if(!rows?.length)break;
        }catch{}
        key='';
      }
      if(!key)throw new Error('Could not generate a unique key.');
      await sb('/rest/v1/license_keys',{
        method:'POST',
        headers:{Prefer:'return=representation'},
        body:JSON.stringify({license_key:key,role,is_revoked:false})
      });
      return send(res,200,{ok:true,key,role});
    }

    if(action==='list'){
      const keys=await sb('/rest/v1/license_keys?select=id,license_key,role,is_revoked,created_at,last_login_at&order=created_at.desc');
      const devices=await sb('/rest/v1/license_devices?select=id,license_id,device_id,created_at&order=created_at.asc');
      const byLicense=new Map();
      for(const d of devices){const a=byLicense.get(d.license_id)||[];a.push(d);byLicense.set(d.license_id,a)}
      const result=(keys||[]).map(k=>{
        const ds=byLicense.get(k.id)||[];
        return {
          id:k.id,key:k.license_key,role:k.role,revoked:!!k.is_revoked,active:!k.is_revoked&&ds.length>0,
          deviceCount:ds.length,createdAt:new Date(k.created_at).toLocaleString('en-US',{dateStyle:'medium',timeStyle:'short'}),
          lastLogin:k.last_login_at?new Date(k.last_login_at).toLocaleString('en-US',{dateStyle:'medium',timeStyle:'short'}):''
        };
      });
      const active=result.filter(k=>k.active).length;
      return send(res,200,{stats:{total:result.length,active,inactive:result.length-active},keys:result});
    }

    if(action==='device-logout'){
      const b=await readBody(req);const id=String(b.keyId||'');
      if(!id)return send(res,400,{error:'keyId required'});
      await sb('/rest/v1/license_sessions?license_id=eq.'+encodeURIComponent(id),{method:'DELETE'});
      await sb('/rest/v1/license_devices?license_id=eq.'+encodeURIComponent(id),{method:'DELETE'});
      return send(res,200,{ok:true});
    }

    if(action==='revoke'){
      const b=await readBody(req);const id=String(b.keyId||'');
      if(!id)return send(res,400,{error:'keyId required'});
      await sb('/rest/v1/license_keys?id=eq.'+encodeURIComponent(id),{method:'PATCH',headers:{Prefer:'return=minimal'},body:JSON.stringify({is_revoked:true})});
      await sb('/rest/v1/license_sessions?license_id=eq.'+encodeURIComponent(id),{method:'DELETE'});
      await sb('/rest/v1/license_devices?license_id=eq.'+encodeURIComponent(id),{method:'DELETE'});
      return send(res,200,{ok:true});
    }

    return send(res,400,{error:'Unknown action'});
  }catch(err){
    return send(res,500,{error:err.message||'Server error'});
  }
};
