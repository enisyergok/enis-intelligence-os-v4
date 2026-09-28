
import os,time,uuid,secrets,hmac,hashlib,json
from fastapi import FastAPI,HTTPException,Header
from pydantic import BaseModel
app=FastAPI(title="Enis V4 Bridge",version="0.1")
DEVICES={}; CODES={}; JOBS={}; RESULTS={}
ADMIN=os.getenv("ENIS_V4_ADMIN_TOKEN","CHANGE_ME")
def auth(x): 
    if x!=ADMIN: raise HTTPException(401,"unauthorized")
def sign(secret,obj):
    b=json.dumps(obj,sort_keys=True,separators=(",",":")).encode()
    return hmac.new(secret.encode(),b,hashlib.sha256).hexdigest()
class PairReq(BaseModel): name:str
class ConfirmReq(BaseModel): code:str
class JobReq(BaseModel):
    device_id:str; kind:str; payload:dict={}; risk:str="READ"; ttl:int=120
class ResultReq(BaseModel): device_id:str; job_id:str; result:dict
@app.get("/health")
def health(): return {"ok":True,"service":"enis-v4-bridge"}
@app.post("/admin/pair")
def pair(q:PairReq,x_admin_token:str|None=Header(None)):
    auth(x_admin_token); did=str(uuid.uuid4()); code=secrets.token_hex(4).upper(); secret=secrets.token_urlsafe(32)
    DEVICES[did]={"name":q.name,"secret":secret,"paired":False,"last_seen":0}; CODES[code]=did
    return {"device_id":did,"pair_code":code,"device_secret":secret}
@app.post("/admin/confirm")
def confirm(q:ConfirmReq,x_admin_token:str|None=Header(None)):
    auth(x_admin_token)
    if q.code not in CODES: raise HTTPException(404,"bad code")
    did=CODES.pop(q.code);DEVICES[did]["paired"]=True;return {"device_id":did,"paired":True}
@app.get("/device/{did}/poll")
def poll(did:str,x_device_secret:str|None=Header(None)):
    d=DEVICES.get(did)
    if not d or not d["paired"] or x_device_secret!=d["secret"]: raise HTTPException(401,"device auth failed")
    d["last_seen"]=time.time(); out=[]
    for r in JOBS.values():
        p=r["payload"]
        if r["device_id"]==did and r["state"]=="QUEUED" and p["expires_at"]>=time.time():
            if p["risk"]=="APPROVAL_REQUIRED" and not p["approved"]:
                r["state"]="WAITING_APPROVAL";continue
            r["state"]="CLAIMED";out.append({**p,"signature":sign(d["secret"],p)})
    return {"jobs":out}
@app.post("/admin/jobs")
def create_job(q:JobReq,x_admin_token:str|None=Header(None)):
    auth(x_admin_token);d=DEVICES.get(q.device_id)
    if not d or not d["paired"]: raise HTTPException(404,"device unavailable")
    now=time.time();jid=str(uuid.uuid4())
    p={"job_id":jid,"device_id":q.device_id,"kind":q.kind,"payload":q.payload,"risk":q.risk,
       "approved":q.risk!="APPROVAL_REQUIRED","nonce":secrets.token_urlsafe(16),"issued_at":now,"expires_at":now+min(max(q.ttl,10),600)}
    JOBS[jid]={"device_id":q.device_id,"payload":p,"state":"QUEUED"}
    return {"job_id":jid,"state":"QUEUED"}
@app.post("/admin/jobs/{jid}/approve")
def approve(jid:str,x_admin_token:str|None=Header(None)):
    auth(x_admin_token);r=JOBS.get(jid)
    if not r: raise HTTPException(404,"job")
    r["payload"]["approved"]=True;r["payload"]["issued_at"]=time.time();r["payload"]["nonce"]=secrets.token_urlsafe(16);r["state"]="QUEUED"
    return {"job_id":jid,"state":"QUEUED","approved":True}
@app.post("/device/result")
def result(q:ResultReq,x_device_secret:str|None=Header(None)):
    d=DEVICES.get(q.device_id);r=JOBS.get(q.job_id)
    if not d or x_device_secret!=d["secret"] or not r or r["device_id"]!=q.device_id: raise HTTPException(401,"bad result auth")
    r["state"]="DONE";RESULTS[q.job_id]=q.result;return {"ok":True}
@app.get("/admin/jobs/{jid}")
def job(jid:str,x_admin_token:str|None=Header(None)):
    auth(x_admin_token);r=JOBS.get(jid)
    if not r: raise HTTPException(404,"job")
    return {"job_id":jid,"state":r["state"],"result":RESULTS.get(jid)}
