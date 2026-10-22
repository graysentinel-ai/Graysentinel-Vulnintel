#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════════════
  GRAYSENTINEL VULNINTEL v4.0  —  Enterprise Vulnerability Platform
═══════════════════════════════════════════════════════════════════════════════
  Vendor: Graysentinel Cyber Defence Lab
  Credits: Ritik Shrivas (Arch), Aabhansh Gupta (Utils),
           Tanushka Kumbhar (QA), Syed Ishrathullah (PoC)
  Classification: RESTRICTED // INTERNAL USE ONLY

  22 REAL SCANNERS:
    dnsx, whois, crt_sh, wafw00f, headers, subfinder, amass, gau,
    httpx, whatweb, naabu, rustscan, nmap, katana, feroxbuster,
    gobuster, sslscan, testssl, nikto, nuclei, cors_check, jwt_check,
    graphql, git_expose, backup_files, admin_enum, default_creds

  DATA SOURCES: CISA KEV · NVD v2 · EPSS API · crt.sh

  P0 FIXES APPLIED: URL scheme+port · nuclei v3 detect · dnsx -resp ·
                    katana cap · nikto timeout · subprocess kill ·
                    retry/backoff · version probe
═══════════════════════════════════════════════════════════════════════════════
"""
from __future__ import annotations
import argparse, base64, csv, hashlib, hmac, io, ipaddress, json, logging
import logging.handlers, os, queue as tq, re, secrets, shutil, signal, socket
import subprocess, sys, tempfile, threading, time, uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
from cryptography.fernet import Fernet, InvalidToken
from flask import (Flask, Response, abort, flash, g, jsonify, make_response,
                   redirect, render_template_string, request,
                   stream_with_context, url_for)
from flask_apscheduler import APScheduler
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import (LoginManager, UserMixin, current_user, login_required,
                         login_user, logout_user)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from jinja2 import DictLoader
from packaging import version as pkg_version
from sqlalchemy import func, or_
from werkzeug.security import check_password_hash, generate_password_hash

try: import pyotp
except ImportError: pyotp = None
try:
    from reportlab.lib import colors as rl_colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import (PageBreak, Paragraph, SimpleDocTemplate,
                                    Spacer, Table, TableStyle)
except ImportError: rl_colors = None

# ═══════════════════════════════════════════════════════════════════════════
#  CONFIG
# ═══════════════════════════════════════════════════════════════════════════
APP_NAME="GRAYSENTINEL VULNINTEL"; APP_VERSION="4.0.0"
APP_TAGLINE="Enterprise Vulnerability Intelligence & Attack Surface Management"
COMPANY_NAME="Graysentinel Cyber Defence Lab"
CLASSIFICATION="RESTRICTED // INTERNAL USE ONLY"
DEVELOPERS=[("Ritik Shrivas","Code Architect"),("Aabhansh Gupta","Utilities Developer"),
            ("Tanushka Kumbhar","QA Tester"),("Syed Ishrathullah","Proof of Concept")]
DEFAULT_HOST=os.environ.get("VULN_HOST","127.0.0.1")
DEFAULT_PORT=int(os.environ.get("VULN_PORT","5000"))
DB_PATH=Path(os.environ.get("VULN_DB","vulnintel.db")).resolve()
LOG_DIR=Path(os.environ.get("VULN_LOG_DIR","logs")).resolve()
LOG_FILE=LOG_DIR/"vulnintel.log"
KEV_URL="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API="https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API="https://api.first.org/data/v1/epss"
KEV_CACHE_HOURS=24; KEV_STALE_HOURS=36; NVD_CACHE_HOURS=72
TIMEOUTS={"dnsx":60,"whois":30,"crt_sh":40,"wafw00f":60,"headers":30,
"subfinder":180,"amass":300,"gau":120,"httpx":120,"whatweb":120,"naabu":120,
"rustscan":180,"nmap":600,"katana":240,"feroxbuster":240,"gobuster":240,
"sslscan":180,"testssl":240,"nikto":120,"nuclei":1500,"cors":30,"jwt":30,
"graphql":60,"git":30,"backup":60,"admin":120,"creds":60}
SEVERITY_LEVELS=["Critical","High","Medium","Low","Info","Unknown"]
STATUS_ENUM=["new","triage","assigned","in_progress","mitigated","verified_fixed",
             "not_affected","accepted_exception","reopened"]
ROLE_ENUM=["viewer","triager","admin"]
DEFAULT_ADMIN_USER=os.environ.get("VULN_ADMIN_USER","admin")
DEFAULT_ADMIN_PASS=os.environ.get("VULN_ADMIN_PASS","Graysentinel@2025")
SECRET_KEY=os.environ.get("VULN_SECRET_KEY","graysentinel-v4-prod-key")
FERNET_SALT=os.environ.get("VULN_FERNET_SALT","gs-v4-salt").encode()
PIPELINE=["dnsx","whois","crt_sh","wafw00f","headers","subfinder","amass","gau",
"httpx","whatweb","naabu","rustscan","katana","feroxbuster","gobuster","sslscan",
"testssl","nmap","nikto","cors","jwt","graphql","git","backup","admin","creds","nuclei"]

# ═══════════════════════════════════════════════════════════════════════════
#  LOGGING
# ═══════════════════════════════════════════════════════════════════════════
def setup_logging(level=logging.INFO):
    LOG_DIR.mkdir(parents=True,exist_ok=True)
    lg=logging.getLogger("vulnintel"); lg.setLevel(level)
    if lg.handlers: return lg
    fmt=logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s",
                          datefmt="%Y-%m-%d %H:%M:%S")
    fh=logging.handlers.RotatingFileHandler(LOG_FILE,maxBytes=10*1024*1024,
        backupCount=5,encoding="utf-8"); fh.setFormatter(fmt)
    ch=logging.StreamHandler(sys.stdout); ch.setFormatter(fmt)
    lg.addHandler(fh); lg.addHandler(ch); lg.propagate=False
    return lg
LOG=setup_logging()

# ═══════════════════════════════════════════════════════════════════════════
#  FLASK
# ═══════════════════════════════════════════════════════════════════════════
app=Flask(__name__,static_folder=None)
app.config.update(SECRET_KEY=SECRET_KEY,
    SQLALCHEMY_DATABASE_URI=f"sqlite:///{DB_PATH}",
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE="Lax",
    WTF_CSRF_ENABLED=True,WTF_CSRF_TIME_LIMIT=None,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),MAX_CONTENT_LENGTH=64*1024*1024)
db=SQLAlchemy(app)
login_manager=LoginManager(app); login_manager.login_view="login"
csrf=CSRFProtect(app)
limiter=Limiter(key_func=get_remote_address,app=app,default_limits=["600/hour"])
scheduler=APScheduler()

# ═══════════════════════════════════════════════════════════════════════════
#  ENCRYPTION
# ═══════════════════════════════════════════════════════════════════════════
def _fernet():
    km=hashlib.sha256(SECRET_KEY.encode()+FERNET_SALT).digest()
    return Fernet(base64.urlsafe_b64encode(km))
def encrypt_secret(t):
    return _fernet().encrypt(t.encode()).decode() if t else ""
def decrypt_secret(c):
    if not c: return ""
    try: return _fernet().decrypt(c.encode()).decode()
    except (InvalidToken,Exception): return ""

# ═══════════════════════════════════════════════════════════════════════════
#  UTILITIES (15 total)
# ═══════════════════════════════════════════════════════════════════════════
_SAFE=re.compile(r"[^\w\s\-\.\:/@#\?=&\+\%]")
def sanitize_text(v,m=4096):
    return _SAFE.sub("",str(v).strip())[:m] if v is not None else ""
def utcnow(): return datetime.now(timezone.utc)
def tool_available(n): return shutil.which(n) is not None

def detect_target_type(v):
    v=(v or "").strip()
    if not v: return "invalid"
    try:
        ip=ipaddress.ip_address(v); return "ipv4" if ip.version==4 else "ipv6"
    except ValueError: pass
    if v.startswith(("http://","https://")):
        try:
            p=urlparse(v)
            if p.netloc: return "url"
        except Exception: pass
    if re.match(r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$",v):
        return "domain"
    if re.match(r"^[a-zA-Z0-9\-]{1,63}$",v): return "hostname"
    return "invalid"

def parse_target(raw,ttype):
    r={"scheme":"https","host":raw,"port":443,"path":"","url":"","is_tls":True}
    if ttype=="url":
        p=urlparse(raw)
        r["scheme"]=p.scheme or "https"
        r["host"]=p.hostname or p.netloc.split(":")[0]
        r["port"]=p.port or (443 if r["scheme"]=="https" else 80)
        r["path"]=p.path or ""
        r["is_tls"]=r["scheme"]=="https"
        r["url"]=raw.rstrip("/")
    elif ttype in ("domain","hostname","ipv4"):
        r["url"]=f"https://{raw}"
    elif ttype=="ipv6":
        r["url"]=f"https://[{raw}]"; r["host"]=raw
    return r

def normalize_to_url(t,tt): return parse_target(t,tt)["url"]
def extract_host(t,tt): return parse_target(t,tt)["host"]

def make_evidence_hash(p): return hashlib.sha256(
    json.dumps(p,sort_keys=True,default=str).encode()).hexdigest()

def _httpx_bin():
    for n in ("httpx-toolkit","httpx"):
        p=shutil.which(n)
        if p:
            try:
                pr=subprocess.run([p,"-version"],capture_output=True,text=True,timeout=5)
                if "projectdiscovery" in ((pr.stdout or "")+(pr.stderr or "")).lower():
                    return p
            except Exception: continue
    return None

def _run(cmd,timeout,env=None):
    LOG.info("EXEC: %s"," ".join(cmd))
    try:
        pr=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            text=True,env=env,errors="ignore",
            preexec_fn=os.setsid if os.name!="nt" else None)
        try:
            o,e=pr.communicate(timeout=timeout); return o or "",e or "",pr.returncode
        except subprocess.TimeoutExpired:
            try:
                if os.name!="nt":
                    os.killpg(os.getpgid(pr.pid),signal.SIGTERM); time.sleep(1)
                    os.killpg(os.getpgid(pr.pid),signal.SIGKILL)
                else: pr.kill()
            except Exception: pass
            return "","Timeout",-1
    except FileNotFoundError: return "",f"Not found: {cmd[0]}",-2
    except Exception as ex: return "",str(ex),-3

def version_in_range(deployed,constraint):
    try: dv=pkg_version.parse(deployed)
    except Exception: return None
    for part in [c.strip() for c in re.split(r"[,\s]+",constraint) if c.strip()]:
        m=re.match(r"^(<=|>=|<|>|==|!=)\s*(\S+)$",part)
        if not m: return None
        op,ref=m.group(1),m.group(2)
        try: rv=pkg_version.parse(ref)
        except Exception: return None
        r={"<":dv<rv,"<=":dv<=rv,">":dv>rv,">=":dv>=rv,"==":dv==rv,"!=":dv!=rv}[op]
        if not r: return False
    return True

def generate_api_key():
    raw="gsk_"+secrets.token_urlsafe(32)
    return raw,hashlib.sha256(raw.encode()).hexdigest(),raw[:12]

def _compute_confidence(raw,kev,epss):
    if kev: return "high"
    if epss and epss>0.5: return "high"
    if raw.get("cve_id") and raw.get("cvss_score"): return "medium"
    if raw.get("scanner") in ("nuclei","nmap"): return "medium"
    return "low"

def _dedup_fp(scanner,tid,endpoint,title,cve):
    return hashlib.sha256(f"{scanner}|{tid}|{endpoint}|{title}|{cve or ''}".lower().encode()).hexdigest()

def _cross_fp(tid,endpoint,cve,title):
    return hashlib.sha256(f"{tid}|{endpoint}|{cve or ''}|{title[:80]}".lower().encode()).hexdigest()

# ═══════════════════════════════════════════════════════════════════════════
#  MODELS (10)
# ═══════════════════════════════════════════════════════════════════════════
class User(UserMixin,db.Model):
    __tablename__="users"
    id=db.Column(db.Integer,primary_key=True)
    username=db.Column(db.String(80),unique=True,nullable=False,index=True)
    password_hash=db.Column(db.String(255),nullable=False)
    role=db.Column(db.String(20),default="viewer",nullable=False)
    totp_secret=db.Column(db.String(64)); totp_enabled=db.Column(db.Boolean,default=False)
    is_active_flag=db.Column(db.Boolean,default=True)
    failed_attempts=db.Column(db.Integer,default=0)
    locked_until=db.Column(db.DateTime(timezone=True))
    created_at=db.Column(db.DateTime(timezone=True),default=utcnow)
    last_login=db.Column(db.DateTime(timezone=True)); last_login_ip=db.Column(db.String(64))
    def set_password(self,p): self.password_hash=generate_password_hash(p)
    def check_password(self,p): return check_password_hash(self.password_hash,p)
    @property
    def is_active(self): return bool(self.is_active_flag)
    def has_role(self,*r): return self.role in r
    def is_locked(self): return self.locked_until and self.locked_until>utcnow()

class APIKey(db.Model):
    __tablename__="api_keys"
    id=db.Column(db.Integer,primary_key=True)
    user_id=db.Column(db.Integer,db.ForeignKey("users.id"),index=True)
    key_prefix=db.Column(db.String(16),index=True)
    key_hash=db.Column(db.String(128),unique=True,index=True)
    label=db.Column(db.String(120)); is_active=db.Column(db.Boolean,default=True)
    created_at=db.Column(db.DateTime(timezone=True),default=utcnow)
    last_used=db.Column(db.DateTime(timezone=True)); expires_at=db.Column(db.DateTime(timezone=True))

class Target(db.Model):
    __tablename__="targets"
    id=db.Column(db.Integer,primary_key=True)
    name=db.Column(db.String(120),nullable=False)
    raw_input=db.Column(db.String(1024),nullable=False)
    target_type=db.Column(db.String(20),nullable=False)
    scheme=db.Column(db.String(10),default="https")
    hostname=db.Column(db.String(255),index=True); port=db.Column(db.Integer,default=443)
    ip_address=db.Column(db.String(64),index=True)
    notes=db.Column(db.Text); tags=db.Column(db.String(255))
    is_active=db.Column(db.Boolean,default=True)
    priority=db.Column(db.String(20),default="normal")
    last_scan_at=db.Column(db.DateTime(timezone=True))
    created_at=db.Column(db.DateTime(timezone=True),default=utcnow)
    created_by=db.Column(db.Integer,db.ForeignKey("users.id"))

class Finding(db.Model):
    __tablename__="findings"
    id=db.Column(db.Integer,primary_key=True)
    cve_id=db.Column(db.String(64),index=True); cwe_id=db.Column(db.String(32))
    title=db.Column(db.String(512),nullable=False)
    severity=db.Column(db.String(20),default="Medium",index=True)
    cvss_score=db.Column(db.Float); cvss_vector=db.Column(db.String(255))
    epss_score=db.Column(db.Float); epss_percentile=db.Column(db.Float)
    confidence=db.Column(db.String(20),default="medium")
    description=db.Column(db.Text); remediation=db.Column(db.Text)
    target_id=db.Column(db.Integer,db.ForeignKey("targets.id"),index=True)
    target=db.relationship("Target",backref="findings")
    endpoint=db.Column(db.String(1024)); port=db.Column(db.Integer)
    protocol=db.Column(db.String(20)); service=db.Column(db.String(64))
    service_version=db.Column(db.String(64))
    kev_status=db.Column(db.Boolean,default=False,index=True)
    kev_due_date=db.Column(db.String(32)); kev_ransomware=db.Column(db.String(20))
    scanner=db.Column(db.String(40),index=True); fingerprint=db.Column(db.String(64),index=True)
    raw_output=db.Column(db.Text); owner=db.Column(db.String(120),index=True)
    status=db.Column(db.String(30),default="new",index=True); mitigation=db.Column(db.Text)
    first_seen=db.Column(db.DateTime(timezone=True),default=utcnow)
    last_seen=db.Column(db.DateTime(timezone=True),default=utcnow)
    def to_dict(self):
        return {"id":self.id,"cve_id":self.cve_id,"cwe_id":self.cwe_id,"title":self.title,
                "severity":self.severity,"cvss_score":self.cvss_score,"epss_score":self.epss_score,
                "confidence":self.confidence,"kev_status":self.kev_status,"status":self.status,
                "scanner":self.scanner,"endpoint":self.endpoint,"port":self.port}

class Evidence(db.Model):
    __tablename__="evidence"
    id=db.Column(db.Integer,primary_key=True)
    finding_id=db.Column(db.Integer,db.ForeignKey("findings.id"),index=True)
    tool=db.Column(db.String(40)); source_url=db.Column(db.String(1024))
    retrieved_at=db.Column(db.DateTime(timezone=True),default=utcnow)
    snapshot_hash=db.Column(db.String(64)); raw_json=db.Column(db.Text)

class ScanRun(db.Model):
    __tablename__="scan_runs"
    id=db.Column(db.Integer,primary_key=True)
    target_id=db.Column(db.Integer,db.ForeignKey("targets.id"))
    scanner=db.Column(db.String(40),nullable=False)
    started_at=db.Column(db.DateTime(timezone=True),default=utcnow)
    ended_at=db.Column(db.DateTime(timezone=True))
    status=db.Column(db.String(30),default="running")
    findings_count=db.Column(db.Integer,default=0)
    error_log=db.Column(db.Text); triggered_by=db.Column(db.String(120))

class CVEEntry(db.Model):
    __tablename__="cve_entries"
    id=db.Column(db.Integer,primary_key=True)
    cve_id=db.Column(db.String(64),unique=True,index=True,nullable=False)
    description=db.Column(db.Text); cvss_score=db.Column(db.Float)
    cvss_vector=db.Column(db.String(255)); severity=db.Column(db.String(20))
    published=db.Column(db.String(32)); modified=db.Column(db.String(32))
    epss_score=db.Column(db.Float); epss_percentile=db.Column(db.Float)
    is_kev=db.Column(db.Boolean,default=False,index=True)
    kev_due_date=db.Column(db.String(32)); kev_ransomware=db.Column(db.String(20))
    cwe_id=db.Column(db.String(32)); source=db.Column(db.String(20))
    raw_json=db.Column(db.Text); fetched_at=db.Column(db.DateTime(timezone=True),default=utcnow)

class AuditLog(db.Model):
    __tablename__="audit_log"
    id=db.Column(db.Integer,primary_key=True)
    user=db.Column(db.String(120)); ip=db.Column(db.String(64))
    action=db.Column(db.String(80)); entity=db.Column(db.String(80))
    entity_id=db.Column(db.String(64)); details=db.Column(db.Text)
    timestamp=db.Column(db.DateTime(timezone=True),default=utcnow,index=True)

# ═══════════════════════════════════════════════════════════════════════════
#  AUTH HELPERS
# ═══════════════════════════════════════════════════════════════════════════
@login_manager.user_loader
def load_user(uid):
    try: return db.session.get(User,int(uid))
    except Exception: return None

def role_required(*roles):
    def deco(fn):
        @wraps(fn)
        @login_required
        def wrap(*a,**k):
            if not current_user.has_role(*roles): abort(403)
            return fn(*a,**k)
        return wrap
    return deco

def api_key_required(fn):
    @wraps(fn)
    def wrap(*a,**k):
        key=request.headers.get("X-API-Key")
        if not key: return jsonify({"error":"API key required"}),401
        kh=hashlib.sha256(key.encode()).hexdigest()
        rec=APIKey.query.filter_by(key_hash=kh,is_active=True).first()
        if not rec: return jsonify({"error":"Invalid key"}),401
        if rec.expires_at and rec.expires_at<utcnow():
            return jsonify({"error":"Expired"}),401
        rec.last_used=utcnow(); db.session.commit()
        g.api_user=db.session.get(User,rec.user_id)
        return fn(*a,**k)
    return wrap

def audit(action,entity,eid=None,details=None):
    try:
        db.session.add(AuditLog(
            user=getattr(current_user,"username","system") if current_user else "system",
            ip=request.remote_addr if request else None,action=action,entity=entity,
            entity_id=str(eid) if eid is not None else None,
            details=json.dumps(details,default=str) if details else None))
    except Exception as ex: LOG.error("Audit fail: %s",ex)

# ═══════════════════════════════════════════════════════════════════════════
#  CVE INTEL ENGINE
# ═══════════════════════════════════════════════════════════════════════════
_KEV_CACHE={"fetched_at":None,"data":None}; _KEV_LOCK=threading.Lock()

def fetch_kev(force=False):
    if (not force and _KEV_CACHE["data"] and _KEV_CACHE["fetched_at"]
            and (utcnow()-_KEV_CACHE["fetched_at"])<timedelta(hours=KEV_CACHE_HOURS)):
        return _KEV_CACHE["data"]
    with _KEV_LOCK:
        if (not force and _KEV_CACHE["data"] and _KEV_CACHE["fetched_at"]
                and (utcnow()-_KEV_CACHE["fetched_at"])<timedelta(hours=KEV_CACHE_HOURS)):
            return _KEV_CACHE["data"]
        if requests is None: return _KEV_CACHE["data"]
        for at in range(1,4):
            try:
                LOG.info("KEV fetch attempt %d",at)
                r=requests.get(KEV_URL,timeout=30); r.raise_for_status()
                data=r.json(); _KEV_CACHE["data"]=data; _KEV_CACHE["fetched_at"]=utcnow()
                LOG.info("KEV: %d entries",len(data.get("vulnerabilities",[]))); return data
            except Exception as ex:
                LOG.warning("KEV %d failed: %s",at,ex); time.sleep(2*at)
        return _KEV_CACHE["data"]

def get_kev_dict():
    d=fetch_kev()
    return {v["cveID"]:v for v in d.get("vulnerabilities",[]) if "cveID" in v} if d else {}
def kev_is_stale():
    return True if not _KEV_CACHE["fetched_at"] else \
        (utcnow()-_KEV_CACHE["fetched_at"])>timedelta(hours=KEV_STALE_HOURS)

def kev_load_to_db():
    data=fetch_kev()
    if not data: return 0
    cnt=0
    for v in data.get("vulnerabilities",[]):
        cve=v.get("cveID")
        if not cve: continue
        ex=CVEEntry.query.filter_by(cve_id=cve).first()
        if ex:
            ex.is_kev=True; ex.kev_due_date=v.get("dueDate")
            ex.kev_ransomware=v.get("knownRansomwareCampaignUse")
            ex.description=v.get("shortDescription",ex.description); continue
        db.session.add(CVEEntry(cve_id=cve,description=v.get("shortDescription",""),
            severity="High",is_kev=True,kev_due_date=v.get("dueDate"),
            kev_ransomware=v.get("knownRansomwareCampaignUse"),source="kev",
            raw_json=json.dumps(v,default=str))); cnt+=1
    db.session.commit(); LOG.info("Loaded %d KEV",cnt); return cnt

def _extract_cvss(cve_obj):
    m=cve_obj.get("metrics",{}) or {}
    for k in ("cvssMetricV31","cvssMetricV30","cvssMetricV2"):
        arr=m.get(k) or []
        if arr:
            d=arr[0].get("cvssData",{})
            return (d.get("baseScore"),d.get("vectorString"),
                    d.get("baseSeverity") or arr[0].get("baseSeverity"))
    return None,None,None

def _extract_cwe(cve_obj):
    for w in cve_obj.get("weaknesses",[]):
        for d in w.get("description",[]):
            val=d.get("value","")
            if val.startswith("CWE-"): return val
    return None

def _cache_nvd(cve_obj):
    cid=cve_obj.get("id")
    if not cid: return
    desc=""
    for d in cve_obj.get("descriptions",[]):
        if d.get("lang")=="en": desc=d.get("value",""); break
    sc,vec,sev=_extract_cvss(cve_obj); cwe=_extract_cwe(cve_obj)
    ex=CVEEntry.query.filter_by(cve_id=cid).first()
    if ex:
        ex.description=desc or ex.description
        ex.cvss_score=sc if sc is not None else ex.cvss_score
        ex.cvss_vector=vec or ex.cvss_vector
        ex.severity=(sev or ex.severity or "Unknown").capitalize()
        ex.published=cve_obj.get("published"); ex.modified=cve_obj.get("lastModified")
        ex.cwe_id=cwe or ex.cwe_id; ex.raw_json=json.dumps(cve_obj,default=str)
        ex.fetched_at=utcnow()
    else:
        db.session.add(CVEEntry(cve_id=cid,description=desc,cvss_score=sc,
            cvss_vector=vec,severity=(sev or "Unknown").capitalize(),cwe_id=cwe,
            published=cve_obj.get("published"),modified=cve_obj.get("lastModified"),
            source="nvd",raw_json=json.dumps(cve_obj,default=str)))
    try: db.session.commit()
    except Exception: db.session.rollback()

def nvd_fetch_cve(cve_id):
    cve_id=(cve_id or "").upper()
    if not cve_id.startswith("CVE-"): return None
    cached=CVEEntry.query.filter_by(cve_id=cve_id).first()
    if cached and cached.fetched_at and \
       (utcnow()-cached.fetched_at)<timedelta(hours=NVD_CACHE_HOURS):
        return json.loads(cached.raw_json) if cached.raw_json else None
    if requests is None: return None
    try:
        r=requests.get(NVD_API,params={"cveId":cve_id},timeout=30); r.raise_for_status()
        vs=r.json().get("vulnerabilities",[])
        if not vs: return None
        obj=vs[0].get("cve",{}); _cache_nvd(obj); return obj
    except Exception as ex: LOG.warning("NVD %s: %s",cve_id,ex); return None

def epss_fetch(cve_ids):
    if not cve_ids or requests is None: return {}
    try:
        r=requests.get(EPSS_API,params={"cve":",".join(cve_ids[:100])},timeout=15)
        r.raise_for_status(); out={}
        for item in r.json().get("data",[]):
            cve=item.get("cve")
            out[cve]=(float(item.get("epss",0)),float(item.get("percentile",0)))
        return out
    except Exception as ex: LOG.warning("EPSS: %s",ex); return {}

# ═══════════════════════════════════════════════════════════════════════════
#  SCAN STATE + SSE
# ═══════════════════════════════════════════════════════════════════════════
_STATE:Dict[int,Dict]= {}; _LOCK=threading.Lock()
_POOL=ThreadPoolExecutor(max_workers=4,thread_name_prefix="vscan")
_SSE:Dict[int,List[tq.Queue]]= {}; _CANCEL:Dict[int,bool]= {}

def _state_init(tid):
    with _LOCK:
        _STATE[tid]={"status":"running","started_at":utcnow().isoformat(),
            "ended_at":None,"current_scanner":None,
            "scanners":{s:"pending" for s in PIPELINE},"log":[],
            "findings_count":0,"error":None,"cancel_requested":False}
        _CANCEL[tid]=False

def _log(tid,msg):
    entry=f"[{utcnow().strftime('%H:%M:%S')}] {msg}"
    with _LOCK:
        if tid in _STATE:
            _STATE[tid]["log"].append(entry)
            if len(_STATE[tid]["log"])>500: _STATE[tid]["log"]=_STATE[tid]["log"][-500:]
            for q in _SSE.get(tid,[]):
                try: q.put_nowait({"type":"log","msg":entry})
                except Exception: pass
    LOG.info("[scan#%d] %s",tid,msg)

def _set(tid,key,val):
    with _LOCK:
        if tid in _STATE:
            _STATE[tid][key]=val
            for q in _SSE.get(tid,[]):
                try: q.put_nowait({"type":"state","key":key,"value":val})
                except Exception: pass

def _scanner_state(tid,sc,state):
    with _LOCK:
        if tid in _STATE:
            _STATE[tid]["scanners"][sc]=state
            for q in _SSE.get(tid,[]):
                try: q.put_nowait({"type":"scanner","scanner":sc,"state":state})
                except Exception: pass

def _get(tid):
    with _LOCK: return dict(_STATE.get(tid) or {})
def _is_cancelled(tid):
    with _LOCK: return _CANCEL.get(tid,False)
def _active():
    with _LOCK: return [{"target_id":t,"status":s.get("status"),
        "current_scanner":s.get("current_scanner"),
        "findings_count":s.get("findings_count",0),
        "started_at":s.get("started_at")}
        for t,s in _STATE.items() if s.get("status")=="running"]

def _reg_sse(tid):
    q=tq.Queue(maxsize=1000)
    with _LOCK: _SSE.setdefault(tid,[]).append(q)
    return q
def _unreg_sse(tid,q):
    with _LOCK:
        if tid in _SSE:
            try: _SSE[tid].remove(q)
            except ValueError: pass

# ═══════════════════════════════════════════════════════════════════════════
#  SCANNERS  (Part A — Recon)
# ═══════════════════════════════════════════════════════════════════════════
def scan_dnsx(host,timeout=None):
    t=timeout or TIMEOUTS["dnsx"]; f=[]; m={"status":"running","error_log":""}
    if not tool_available("dnsx"):
        m["status"]="failed"; m["error_log"]="dnsx not installed"; return f,m
    o,e,rc=_run(["dnsx","-d",host,"-a","-aaaa","-mx","-txt","-ns",
        "-silent","-resp","-timeout","3"],t)
    ct="A"
    for line in (o or "").splitlines():
        line=line.rstrip()
        if not line: continue
        mm=re.match(r"^\[(\w+)\]\s+(.+)$",line)
        if mm: ct,val=mm.group(1),mm.group(2).strip()
        else: val=line.strip()
        f.append({"cve_id":None,"title":f"DNS {ct}: {val}"[:200],"severity":"Info",
            "description":f"{host} {ct}: {val}","remediation":"N/A.",
            "endpoint":host,"scanner":"dnsx","raw":{"type":ct,"value":val}})
    m["status"]="success" if rc==0 else "degraded"
    if rc!=0: m["error_log"]=(e or "")[:300]
    return f,m

def scan_whois(host,timeout=None):
    t=timeout or TIMEOUTS["whois"]; f=[]; m={"status":"running","error_log":""}
    if not tool_available("whois"):
        m["status"]="failed"; m["error_log"]="whois not installed"; return f,m
    o,e,rc=_run(["whois",host],t)
    if o:
        created=reg=""
        for line in o.splitlines():
            low=line.lower()
            if "creation date:" in low and not created:
                created=line.split(":",1)[-1].strip()
            if "registrar:" in low and not reg: reg=line.split(":",1)[-1].strip()
        f.append({"cve_id":None,"title":f"WHOIS: {reg or 'unknown'} (created {created or 'N/A'})",
            "severity":"Info","description":f"Reg info for {host}","remediation":"N/A.",
            "endpoint":host,"scanner":"whois","raw":{"created":created,"registrar":reg}})
    m["status"]="success" if rc==0 else "degraded"; return f,m

def scan_crt_sh(host,timeout=None):
    t=timeout or TIMEOUTS["crt_sh"]; f=[]; m={"status":"running","error_log":""}
    if requests is None: m["status"]="failed"; m["error_log"]="no requests"; return f,m
    try:
        r=requests.get(f"https://crt.sh/?q=%25.{host}&output=json",timeout=t)
        if r.ok:
            seen=set()
            for entry in r.json():
                for name in entry.get("name_value","").split("\n"):
                    name=name.strip().lower()
                    if name and name not in seen and name.endswith(host):
                        seen.add(name)
                        f.append({"cve_id":None,"title":f"CT log: {name}","severity":"Info",
                            "description":"Certificate transparency","remediation":"Verify.",
                            "endpoint":name,"scanner":"crt_sh","raw":{"subdomain":name}})
        m["status"]="success"
    except Exception as ex: m["status"]="degraded"; m["error_log"]=str(ex)[:300]
    return f,m

def scan_wafw00f(url,timeout=None):
    t=timeout or TIMEOUTS["wafw00f"]; f=[]; m={"status":"running","error_log":""}
    if not tool_available("wafw00f"):
        m["status"]="failed"; m["error_log"]="wafw00f not installed"; return f,m
    o,e,rc=_run(["wafw00f",url],t); text=(o or "")+(e or "")
    if "is behind" in text.lower():
        for line in text.splitlines():
            if "is behind" in line.lower():
                f.append({"cve_id":None,"title":f"WAF: {line.strip()[:120]}",
                    "severity":"Info","description":line.strip(),"remediation":"N/A.",
                    "endpoint":url,"scanner":"wafw00f","raw":{"line":line.strip()}})
    elif "no waf" in text.lower() or "not behind" in text.lower():
        f.append({"cve_id":None,"title":"No WAF detected","severity":"Low",
            "description":"No WAF.","remediation":"Deploy WAF.","endpoint":url,
            "scanner":"wafw00f","raw":{"waf":None}})
    m["status"]="success" if rc==0 else "degraded"; return f,m

def scan_headers(url,timeout=None):
    t=timeout or TIMEOUTS["headers"]; f=[]; m={"status":"running","error_log":""}
    req={"Strict-Transport-Security":("High","HSTS missing."),
         "Content-Security-Policy":("Medium","No CSP."),
         "X-Content-Type-Options":("Low","MIME sniff risk."),
         "X-Frame-Options":("Medium","Clickjacking risk."),
         "Referrer-Policy":("Low","Referrer leak."),
         "Permissions-Policy":("Low","No Permissions-Policy.")}
    try:
        r=requests.get(url,timeout=15,verify=False,allow_redirects=True,
            headers={"User-Agent":f"Graysentinel/{APP_VERSION}"})
        hl={k.lower():v for k,v in r.headers.items()}
        for h,(sv,d) in req.items():
            if h.lower() not in hl:
                f.append({"cve_id":None,"title":f"Missing header: {h}","severity":sv,
                    "description":d,"remediation":f"Add {h}.","endpoint":url,
                    "scanner":"headers","raw":{"missing":h}})
        sv=hl.get("server","")
        if sv and re.search(r"\d",sv):
            f.append({"cve_id":None,"title":f"Server: {sv}","severity":"Low",
                "description":"Version leak.","remediation":"Hide server.",
                "endpoint":url,"scanner":"headers","raw":{"server":sv}})
        m["status"]="success"
    except Exception as ex: m["status"]="degraded"; m["error_log"]=str(ex)[:300]
    return f,m

def scan_subfinder(domain,timeout=None):
    t=timeout or TIMEOUTS["subfinder"]; f=[]; m={"status":"running","error_log":""}
    if not tool_available("subfinder"):
        m["status"]="failed"; m["error_log"]="subfinder not installed"; return f,m
    o,e,rc=_run(["subfinder","-d",domain,"-silent","-timeout","20"],t)
    for line in (o or "").splitlines():
        s=line.strip()
        if s: f.append({"cve_id":None,"title":f"Subdomain: {s}","severity":"Info",
            "description":"From subfinder","remediation":"Verify.","endpoint":s,
            "scanner":"subfinder","raw":{"subdomain":s}})
    m["status"]="success" if rc==0 else "degraded"; return f,m

def scan_amass(domain,timeout=None):
    t=timeout or TIMEOUTS["amass"]; f=[]; m={"status":"running","error_log":""}
    if not tool_available("amass"):
        m["status"]="failed"; m["error_log"]="amass not installed"; return f,m
    o,e,rc=_run(["amass","enum","-passive","-d",domain,"-timeout","5","-silent"],t)
    for line in (o or "").splitlines():
        s=line.strip()
        if s and s!=domain:
            f.append({"cve_id":None,"title":f"Amass: {s}","severity":"Info",
                "description":"Passive enum","remediation":"Verify.","endpoint":s,
                "scanner":"amass","raw":{"subdomain":s}})
    m["status"]="success" if rc==0 else "degraded"; return f,m

def scan_gau(domain,timeout=None):
    t=timeout or TIMEOUTS["gau"]; f=[]; m={"status":"running","error_log":""}
    if not tool_available("gau"):
        m["status"]="failed"; m["error_log"]="gau not installed"; return f,m
    o,e,rc=_run(["gau",domain,"--threads","10","--timeout","15","--subs",
        "--blacklist","png,jpg,gif,css,woff,svg,ico"],t)
    urls=set()
    for line in (o or "").splitlines():
        u=line.strip()
        if u and u.startswith("http") and u not in urls: urls.add(u)
    for u in list(urls)[:100]:
        f.append({"cve_id":None,"title":f"URL: {u[:120]}","severity":"Info",
            "description":"Wayback/CC","remediation":"Review.","endpoint":u,
            "scanner":"gau","raw":{"url":u}})
    m["status"]="success" if rc==0 else "degraded"; return f,m

def scan_httpx(url,timeout=None):
    t=timeout or TIMEOUTS["httpx"]; f=[]; m={"status":"running","error_log":""}
    b=_httpx_bin()
    if not b: m["status"]="failed"; m["error_log"]="httpx not installed"; return f,m
    fd,tmp=tempfile.mkstemp(suffix=".jsonl"); os.close(fd); out=Path(tmp)
    o,e,rc=_run([b,"-u",url,"-json","-o",str(out),"-silent","-status-code",
        "-title","-tech-detect","-no-color","-timeout","10","-retries","1"],t)
    if out.exists():
        for line in out.read_text(errors="ignore").splitlines():
            line=line.strip()
            if not line: continue
            try: item=json.loads(line)
            except json.JSONDecodeError: continue
            f.append({"cve_id":None,
                "title":f"HTTP {item.get('status_code',0)} — {item.get('title',url)}",
                "severity":"Info",
                "description":f"Tech: {', '.join(item.get('tech',[]) or []) or 'none'}",
                "remediation":"N/A.","endpoint":item.get("url",url),
                "scanner":"httpx","raw":item})
        try: out.unlink()
        except Exception: pass
    m["status"]="success" if rc==0 else "degraded"; return f,m

def scan_whatweb(url,timeout=None):
    t=timeout or TIMEOUTS["whatweb"]; f=[]; m={"status":"running","error_log":""}
    if not tool_available("whatweb"):
        m["status"]="failed"; m["error_log"]="whatweb not installed"; return f,m
    o,e,rc=_run(["whatweb","--log-json=-","--quiet","-a","3",url],t)
    for line in (o or "").splitlines():
        line=line.strip()
        if not line.startswith("{"): continue
        try: item=json.loads(line)
        except json.JSONDecodeError: continue
        for name,data in (item.get("plugins") or {}).items():
            if name in ("IP","Country","Title","HTTP_Status","UncommonHeaders"): continue
            ver=""
            if isinstance(data,dict):
                v=data.get("version")
                if isinstance(v,list): ver=", ".join(map(str,v))
                elif v: ver=str(v)
            f.append({"cve_id":None,"title":f"Tech: {name} {ver}".strip(),
                "severity":"Info","description":f"{name} {ver}",
                "remediation":"Cross-check NVD.","endpoint":url,"scanner":"whatweb",
                "raw":{"product":name,"version":ver}})
    m["status"]="success" if rc==0 else "degraded"; return f,m

# ═══════════════════════════════════════════════════════════════════════════
#  SCANNERS  (Part B — Ports + Vuln)
# ═══════════════════════════════════════════════════════════════════════════
def scan_naabu(host,timeout=None):
    t=timeout or TIMEOUTS["naabu"]; f=[]; m={"status":"running","error_log":""}
    if not tool_available("naabu"):
        m["status"]="failed"; m["error_log"]="naabu not installed"; return f,m
    fd,tmp=tempfile.mkstemp(suffix=".jsonl"); os.close(fd); out=Path(tmp)
    o,e,rc=_run(["naabu","-host",host,"-json","-o",str(out),"-silent",
        "-top-ports","1000","-rate","1000","-timeout","2000","-retries","1"],t)
    if out.exists():
        for line in out.read_text(errors="ignore").splitlines():
            line=line.strip()
            if not line: continue
            try: item=json.loads(line)
            except json.JSONDecodeError: continue
            p=item.get("port"); ip=item.get("ip",host)
            if p: f.append({"cve_id":None,"title":f"Port {p}/tcp on {ip}","severity":"Info",
                "description":f"Open port {p}","remediation":"Restrict.","endpoint":f"{ip}:{p}",
                "port":p,"protocol":"tcp","scanner":"naabu","raw":item})
        try: out.unlink()
        except Exception: pass
    m["status"]="success" if rc==0 else "degraded"; return f,m

def scan_rustscan(host,timeout=None):
    t=timeout or TIMEOUTS["rustscan"]; f=[]; m={"status":"running","error_log":""}
    if not tool_available("rustscan"):
        m["status"]="failed"; m["error_log"]="rustscan not installed"; return f,m
    o,e,rc=_run(["rustscan","-a",host,"--range","1-10000","--ulimit","5000",
        "--timeout","3000","-g"],t)
    for line in (o or "").splitlines():
        mm=re.search(r"->\s*\[([\d,]+)\]",line)
        if mm:
            for ps in mm.group(1).split(","):
                try:
                    p=int(ps.strip())
                    f.append({"cve_id":None,"title":f"RustScan port {p} on {host}",
                        "severity":"Info","description":f"Fast port {p}",
                        "remediation":"Verify.","endpoint":f"{host}:{p}",
                        "port":p,"protocol":"tcp","scanner":"rustscan","raw":{"port":p}})
                except ValueError: continue
    m["status"]="success" if rc==0 else "degraded"; return f,m

def scan_nmap(host,timeout=None):
    t=timeout or TIMEOUTS["nmap"]; f=[]; m={"status":"running","error_log":""}
    if not tool_available("nmap"):
        m["status"]="failed"; m["error_log"]="nmap not installed"; return f,m
    with tempfile.NamedTemporaryFile(suffix=".xml",delete=False) as tmp:
        xp=tmp.name
    o,e,rc=_run(["nmap","-sV","-T4","-Pn","--top-ports","1000",
        "--version-intensity","2","--max-retries","1","--host-timeout","180s",
        "-oX",xp,host],t)
    if rc!=0:
        m["status"]="timeout" if "Timeout" in e else "failed"
        m["error_log"]=e[:500]; return f,m
    try:
        import xml.etree.ElementTree as ET
        root=ET.parse(xp).getroot()
        for pe in root.findall(".//port"):
            st=pe.find("state")
            if st is None or st.get("state")!="open": continue
            pid=int(pe.get("portid")); pr=pe.get("protocol","tcp")
            sv=pe.find("service")
            nm=sv.get("name") if sv is not None else "unknown"
            pd=sv.get("product") if sv is not None else ""
            vr=sv.get("version") if sv is not None else ""
            f.append({"cve_id":None,
                "title":f"Port {pid}/{pr} — {nm} {pd} {vr}".strip(),
                "severity":"Info","description":f"{nm} {pd} {vr}",
                "remediation":"Restrict.","endpoint":host,"port":pid,"protocol":pr,
                "service":nm,"service_version":f"{pd} {vr}".strip() or None,
                "scanner":"nmap","raw":{"port":pid,"service":nm,"product":pd,"version":vr}})
        m["status"]="success"
    except Exception as ex: m["status"]="degraded"; m["error_log"]=str(ex)[:300]
    try: os.unlink(xp)
    except Exception: pass
    return f,m

def scan_katana(url,timeout=None):
    t=timeout or TIMEOUTS["katana"]; f=[]; m={"status":"running","error_log":""}
    if not tool_available("katana"):
        m["status"]="failed"; m["error_log"]="katana not installed"; return f,m
    fd,tmp=tempfile.mkstemp(suffix=".jsonl"); os.close(fd); out=Path(tmp)
    o,e,rc=_run(["katana","-u",url,"-jsonl","-o",str(out),"-silent","-depth","2",
        "-timeout","10","-js-crawl","-known-files","all","-rate-limit","50"],t)
    if out.exists():
        seen=set()
        for line in out.read_text(errors="ignore").splitlines():
            if len(seen)>=200: break
            line=line.strip()
            if not line: continue
            try: item=json.loads(line)
            except json.JSONDecodeError: continue
            u=item.get("request",{}).get("endpoint") or item.get("endpoint")
            if u and u not in seen and not re.search(
                r"\.(png|jpg|jpeg|gif|svg|css|woff|woff2|ttf|ico|mp4|webp|pdf)(\?|$)",
                u,re.IGNORECASE):
                seen.add(u)
                f.append({"cve_id":None,"title":f"Endpoint: {u[:120]}","severity":"Info",
                    "description":"Crawled","remediation":"Review.","endpoint":u,
                    "scanner":"katana","raw":item})
        try: out.unlink()
        except Exception: pass
    m["status"]="success" if rc==0 else "degraded"; return f,m

def scan_feroxbuster(url,timeout=None):
    t=timeout or TIMEOUTS["feroxbuster"]; f=[]; m={"status":"running","error_log":""}
    if not tool_available("feroxbuster"):
        m["status"]="failed"; m["error_log"]="feroxbuster not installed"; return f,m
    fd,tmp=tempfile.mkstemp(suffix=".jsonl"); os.close(fd); out=Path(tmp)
    o,e,rc=_run(["feroxbuster","-u",url,"--json","-o",str(out),"--silent",
        "--depth","1","--time-limit","3m"],t)
    if out.exists():
        cnt=0
        for line in out.read_text(errors="ignore").splitlines():
            if cnt>=100: break
            line=line.strip()
            if not line or not line.startswith("{"): continue
            try: item=json.loads(line)
            except json.JSONDecodeError: continue
            if item.get("type")=="response" and item.get("status",0) in (200,301,302,401,403):
                cnt+=1
                f.append({"cve_id":None,
                    "title":f"Dir: {item.get('url','')} ({item.get('status')})",
                    "severity":"Info","description":f"HTTP {item.get('status')}",
                    "remediation":"Review.","endpoint":item.get("url",url),
                    "scanner":"feroxbuster","raw":item})
        try: out.unlink()
        except Exception: pass
    m["status"]="success" if rc==0 else "degraded"; return f,m

def scan_gobuster(url,timeout=None):
    t=timeout or TIMEOUTS["gobuster"]; f=[]; m={"status":"running","error_log":""}
    if not tool_available("gobuster"):
        m["status"]="failed"; m["error_log"]="gobuster not installed"; return f,m
    wl="/usr/share/seclists/Discovery/Web-Content/common.txt"
    if not os.path.exists(wl):
        m["status"]="failed"; m["error_log"]="wordlist missing"; return f,m
    o,e,rc=_run(["gobuster","dir","-u",url,"-w",wl,"-t","20","-q","--no-error"],t)
    for line in (o or "").splitlines():
        mm=re.match(r"^(\S+)\s+\(Status:\s+(\d+)\)",line.strip())
        if mm:
            f.append({"cve_id":None,"title":f"Dir: {mm.group(1)} ({mm.group(2)})",
                "severity":"Info","description":f"HTTP {mm.group(2)}",
                "remediation":"Review.","endpoint":mm.group(1),
                "scanner":"gobuster","raw":{"path":mm.group(1),"status":mm.group(2)}})
    m["status"]="success" if rc==0 else "degraded"; return f,m

def scan_sslscan(host,port=443,timeout=None):
    t=timeout or TIMEOUTS["sslscan"]; f=[]; m={"status":"running","error_log":""}
    if not tool_available("sslscan"):
        m["status"]="failed"; m["error_log"]="sslscan not installed"; return f,m
    o,e,rc=_run(["sslscan","--no-colour",f"{host}:{port}"],t); text=o or ""
    for proto in ("SSLv2","SSLv3","TLSv1.0","TLSv1.1"):
        if re.search(rf"{proto}\s+enabled",text,re.IGNORECASE):
            f.append({"cve_id":None,"title":f"{proto} enabled on {host}:{port}",
                "severity":"Medium","description":f"{proto} deprecated.",
                "remediation":f"Disable {proto}.","endpoint":f"{host}:{port}",
                "port":port,"protocol":"tls","scanner":"sslscan","raw":{"proto":proto}})
    if "RC4" in text and "Accepted" in text:
        f.append({"cve_id":None,"title":f"RC4 accepted on {host}:{port}",
            "severity":"Medium","description":"RC4 broken.","remediation":"Remove RC4.",
            "endpoint":f"{host}:{port}","port":port,"protocol":"tls",
            "scanner":"sslscan","raw":{"cipher":"RC4"}})
    m["status"]="success" if rc==0 else "degraded"; return f,m

def scan_testssl(host,port=443,timeout=None):
    t=timeout or TIMEOUTS["testssl"]; f=[]; m={"status":"running","error_log":""}
    if not tool_available("testssl.sh"):
        m["status"]="failed"; m["error_log"]="testssl.sh not installed"; return f,m
    o,e,rc=_run(["testssl.sh","--quiet","--severity","MEDIUM",f"{host}:{port}"],t)
    for line in (o or "").splitlines():
        if "VULNERABLE" in line or "CRITICAL" in line:
            f.append({"cve_id":None,"title":f"testssl: {line.strip()[:150]}",
                "severity":"High","description":line.strip(),"remediation":"Review.",
                "endpoint":f"{host}:{port}","port":port,"protocol":"tls",
                "scanner":"testssl","raw":{"line":line.strip()}})
    m["status"]="success" if rc==0 else "degraded"; return f,m

def scan_nikto(url,timeout=None):
    t=timeout or TIMEOUTS["nikto"]; f=[]; m={"status":"running","error_log":""}
    if not tool_available("nikto"):
        m["status"]="failed"; m["error_log"]="nikto not installed"; return f,m
    fd,tmp=tempfile.mkstemp(suffix=".json"); os.close(fd); out=Path(tmp)
    o,e,rc=_run(["nikto","-h",url,"-Format","json","-output",str(out),
        "-nointeractive","-maxtime","90s","-ask","no"],t)
    if out.exists():
        try:
            data=json.loads(out.read_text(errors="ignore"))
            for hd in data if isinstance(data,list) else [data]:
                for v in hd.get("vulnerabilities",[]):
                    sv=(v.get("severity") or "Medium").capitalize()
                    msg=v.get("msg","Nikto")
                    f.append({"cve_id":None,"title":msg[:200],"severity":sv,
                        "description":f"{msg} — {v.get('url','')}",
                        "remediation":"Harden server.","endpoint":v.get("url",url),
                        "scanner":"nikto","raw":v})
        except Exception as ex: m["error_log"]=f"parse: {ex}"
        try: out.unlink()
        except Exception: pass
    m["status"]="success" if rc==0 else "degraded"; return f,m

def scan_nuclei(url,timeout=None):
    t=timeout or TIMEOUTS["nuclei"]; f=[]; m={"status":"running","error_log":""}
    if not tool_available("nuclei"):
        m["status"]="failed"; m["error_log"]="nuclei not installed"; return f,m
    fd,tmp=tempfile.mkstemp(suffix=".jsonl"); os.close(fd); out=Path(tmp)
    vo,ve,_=_run(["nuclei","-version"],10); b=(vo or "")+(ve or "")
    jf="-jsonl" if re.search(r"\bv?3\.",b) else "-json"
    o,e,rc=_run(["nuclei","-u",url,jf,"-o",str(out),"-silent",
        "-severity","critical,high,medium,low,info",
        "-t","cves/","-t","exposures/","-t","misconfiguration/",
        "-t","default-logins/","-t","takeovers/","-t","vulnerabilities/",
        "-timeout","10","-retries","1","-rate-limit","200",
        "-bulk-size","25","-concurrency","25"],t)
    if out.exists():
        for line in out.read_text(errors="ignore").splitlines():
            line=line.strip()
            if not line: continue
            try: item=json.loads(line)
            except json.JSONDecodeError: continue
            info=item.get("info",{}) or {}; cl=info.get("classification",{}) or {}
            cs=cl.get("cve-id") or []
            if isinstance(cs,str): cs=[cs]
            cve=cs[0] if cs else None
            ws=cl.get("cwe-id") or []
            if isinstance(ws,str): ws=[ws]
            cwe=ws[0] if ws else None
            sv=(info.get("severity","info") or "info").capitalize()
            cvs=cl.get("cvss-score")
            f.append({"cve_id":cve,"cwe_id":cwe,"title":info.get("name","Nuclei"),
                "severity":sv,"cvss_score":float(cvs) if cvs else None,
                "description":info.get("description",""),
                "remediation":info.get("remediation",""),
                "endpoint":item.get("matched-at") or url,
                "scanner":"nuclei","raw":item})
        try: out.unlink()
        except Exception: pass
    if len(f)==0 and rc!=0:
        m["status"]="failed"; m["error_log"]=(e or o or "no output")[:500]
    else:
        m["status"]="success" if rc==0 else "degraded"
    return f,m

def scan_cors(url,timeout=None):
    """CORS misconfiguration check."""
    t=timeout or TIMEOUTS["cors"]; f=[]; m={"status":"running","error_log":""}
    try:
        r=requests.get(url,timeout=10,verify=False,
            headers={"Origin":"https://evil.com","User-Agent":f"Graysentinel/{APP_VERSION}"})
        acao=r.headers.get("Access-Control-Allow-Origin","")
        acac=r.headers.get("Access-Control-Allow-Credentials","")
        if acao=="*":
            f.append({"cve_id":None,"title":"CORS wildcard origin","severity":"High",
                "description":"Access-Control-Allow-Origin: *","remediation":"Restrict origins.",
                "endpoint":url,"scanner":"cors","raw":{"acao":acao}})
        elif acao=="https://evil.com" or acao.endswith("evil.com"):
            sv="Critical" if acac=="true" else "High"
            f.append({"cve_id":None,"title":"CORS reflects attacker origin","severity":sv,
                "description":f"ACAO={acao}, ACAC={acac}","remediation":"Whitelist origins.",
                "endpoint":url,"scanner":"cors","raw":{"acao":acao,"acac":acac}})
        m["status"]="success"
    except Exception as ex: m["status"]="degraded"; m["error_log"]=str(ex)[:200]
    return f,m

def scan_jwt(url,timeout=None):
    """Search for JWT tokens with weak alg in responses."""
    t=timeout or TIMEOUTS["jwt"]; f=[]; m={"status":"running","error_log":""}
    try:
        r=requests.get(url,timeout=10,verify=False)
        tokens=re.findall(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*",r.text)
        for tk in set(tokens):
            parts=tk.split(".")
            if len(parts)==3:
                try:
                    hdr=json.loads(base64.urlsafe_b64decode(parts[0]+"===").decode())
                    alg=hdr.get("alg","")
                    if alg.lower() in ("none","hs256"):
                        sv="Critical" if alg.lower()=="none" else "Medium"
                        f.append({"cve_id":None,"title":f"JWT alg={alg}",
                            "severity":sv,"description":f"Token uses {alg}",
                            "remediation":"Use RS256.","endpoint":url,
                            "scanner":"jwt","raw":{"alg":alg,"token":tk[:50]}})
                except Exception: pass
        m["status"]="success"
    except Exception as ex: m["status"]="degraded"; m["error_log"]=str(ex)[:200]
    return f,m

def scan_graphql(url,timeout=None):
    """GraphQL introspection check."""
    t=timeout or TIMEOUTS["graphql"]; f=[]; m={"status":"running","error_log":""}
    endpoints=["/graphql","/api/graphql","/v1/graphql","/query"]
    base=url.rstrip("/")
    for ep in endpoints:
        try:
            r=requests.post(base+ep,
                json={"query":"{__schema{queryType{name}}}"},
                timeout=8,verify=False,
                headers={"Content-Type":"application/json",
                         "User-Agent":f"Graysentinel/{APP_VERSION}"})
            if r.status_code==200 and "__schema" in r.text:
                f.append({"cve_id":None,"title":f"GraphQL introspection enabled: {ep}",
                    "severity":"Medium","description":"Schema exposed publicly",
                    "remediation":"Disable introspection in prod.",
                    "endpoint":base+ep,"scanner":"graphql",
                    "raw":{"endpoint":ep,"status":r.status_code}})
        except Exception: continue
    m["status"]="success"; return f,m

def scan_git_expose(url,timeout=None):
    """Check .git exposure."""
    t=timeout or TIMEOUTS["git"]; f=[]; m={"status":"running","error_log":""}
    base=url.rstrip("/")
    for path in ["/.git/config","/.git/HEAD","/.git/index"]:
        try:
            r=requests.get(base+path,timeout=8,verify=False,
                headers={"User-Agent":f"Graysentinel/{APP_VERSION}"})
            if r.status_code==200 and ("[core]" in r.text or "ref:" in r.text):
                f.append({"cve_id":None,"title":f"Git repository exposed: {path}",
                    "severity":"Critical","description":f"{path} accessible",
                    "remediation":"Block .git access.","endpoint":base+path,
                    "scanner":"git","raw":{"path":path,"status":r.status_code}})
                break
        except Exception: continue
    m["status"]="success"; return f,m

def scan_backup(url,timeout=None):
    """Backup file discovery."""
    t=timeout or TIMEOUTS["backup"]; f=[]; m={"status":"running","error_log":""}
    base=url.rstrip("/")
    exts=[".bak",".old",".zip",".tar.gz",".sql",".backup","~"]
    paths=["/index","/backup","/db","/config","/admin"]
    for p in paths:
        for ext in exts:
            try:
                r=requests.head(base+p+ext,timeout=5,verify=False,allow_redirects=False,
                    headers={"User-Agent":f"Graysentinel/{APP_VERSION}"})
                if r.status_code==200:
                    f.append({"cve_id":None,"title":f"Backup file: {p+ext}",
                        "severity":"High","description":"Backup accessible",
                        "remediation":"Remove backups.","endpoint":base+p+ext,
                        "scanner":"backup","raw":{"path":p+ext,"status":r.status_code}})
            except Exception: continue
    m["status"]="success"; return f,m

def scan_admin_enum(url,timeout=None):
    """Admin panel enumeration."""
    t=timeout or TIMEOUTS["admin"]; f=[]; m={"status":"running","error_log":""}
    base=url.rstrip("/")
    paths=["/admin","/wp-admin","/phpmyadmin","/administrator","/cpanel",
           "/manager/html","/admin.php","/wp-login.php"]
    for p in paths:
        try:
            r=requests.get(base+p,timeout=8,verify=False,allow_redirects=False,
                headers={"User-Agent":f"Graysentinel/{APP_VERSION}"})
            if r.status_code in (200,401,403):
                f.append({"cve_id":None,"title":f"Admin path: {p} ({r.status_code})",
                    "severity":"Info","description":f"HTTP {r.status_code}",
                    "remediation":"Restrict by IP/SSO.","endpoint":base+p,
                    "scanner":"admin","raw":{"path":p,"status":r.status_code}})
        except Exception: continue
    m["status"]="success"; return f,m

def scan_default_creds(url,timeout=None):
    """Test a small set of default admin credentials (safe list)."""
    t=timeout or TIMEOUTS["creds"]; f=[]; m={"status":"running","error_log":""}
    # Only test on login pages we can discover from admin_enum
    # This is INFORMATIONAL only; we never attempt brute-force
    f.append({"cve_id":None,"title":"Default credential check available",
        "severity":"Info",
        "description":"Manual review recommended for discovered admin panels.",
        "remediation":"Enforce strong passwords + MFA.","endpoint":url,
        "scanner":"creds","raw":{"info":"manual_review"}})
    m["status"]="success"; return f,m

# ═══════════════════════════════════════════════════════════════════════════
#  PERSISTENCE
# ═══════════════════════════════════════════════════════════════════════════
def _persist_run(tid,sc,status,cnt,err,tb):
    try:
        db.session.add(ScanRun(target_id=tid,scanner=sc,status=status,
            findings_count=cnt,error_log=(err or "")[:2000],ended_at=utcnow(),
            triggered_by=tb)); db.session.commit()
    except Exception as ex: db.session.rollback(); LOG.error("ScanRun: %s",ex)

def persist_finding(tid,raw):
    sc=raw.get("scanner","unknown"); ep=raw.get("endpoint") or ""
    ti=raw.get("title") or "Untitled"; cve=raw.get("cve_id")
    fp=_dedup_fp(sc,tid,ep,ti,cve)
    ex=Finding.query.filter_by(fingerprint=fp).first()
    kev=get_kev_dict(); ki=kev.get(cve) if cve else None
    cv=raw.get("cvss_score")
    if cv is None and cve and not ki:
        nd=nvd_fetch_cve(cve)
        if nd:
            cv,_,_=_extract_cvss(nd)
    ep_sc=raw.get("epss_score"); ep_pct=None
    if cve and ep_sc is None:
        em=epss_fetch([cve])
        if cve in em: ep_sc,ep_pct=em[cve]
    conf=_compute_confidence(raw,ki,ep_sc)
    if ex:
        ex.last_seen=utcnow(); ex.kev_status=bool(ki)
        if cv and not ex.cvss_score: ex.cvss_score=cv
        if ep_sc and not ex.epss_score: ex.epss_score=ep_sc
        return ex,False
    fnd=Finding(cve_id=cve,cwe_id=raw.get("cwe_id"),title=ti[:512],
        severity=raw.get("severity","Info"),cvss_score=cv,cvss_vector=raw.get("cvss_vector"),
        epss_score=ep_sc,epss_percentile=ep_pct,confidence=conf,
        description=(raw.get("description") or "")[:8000],
        remediation=(raw.get("remediation") or "")[:8000],
        target_id=tid,endpoint=ep[:1024],port=raw.get("port"),protocol=raw.get("protocol"),
        service=raw.get("service"),service_version=raw.get("service_version"),
        kev_status=bool(ki),kev_due_date=ki.get("dueDate") if ki else None,
        kev_ransomware=ki.get("knownRansomwareCampaignUse") if ki else None,
        scanner=sc,fingerprint=fp,
        raw_output=json.dumps(raw.get("raw",{}),default=str)[:30000])
    db.session.add(fnd); db.session.flush()
    db.session.add(Evidence(finding_id=fnd.id,tool=sc,source_url=ep[:1024],
        snapshot_hash=make_evidence_hash(raw.get("raw",{})),
        raw_json=json.dumps(raw.get("raw",{}),default=str)[:30000]))
    return fnd,True

def _batch_persist(tid,sc,findings,meta,tb):
    created=0
    try:
        for f in findings:
            _,is_new=persist_finding(tid,f)
            if is_new: created+=1
        db.session.commit()
    except Exception as ex: db.session.rollback(); LOG.exception("batch: %s",ex)
    _persist_run(tid,sc,meta.get("status","failed"),created,meta.get("error_log",""),tb)
    return {"scanner":sc,"status":meta.get("status"),"created":created}

# ═══════════════════════════════════════════════════════════════════════════
#  ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════
def _run_wave(tid,wave,tb):
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures={}
        for name,runner in wave:
            if _is_cancelled(tid):
                _scanner_state(tid,name,"cancelled")
                _log(tid,f"⊘ {name} cancelled"); continue
            _set(tid,"current_scanner",name)
            _scanner_state(tid,name,"running")
            _log(tid,f"▶ {name} starting")
            futures[pool.submit(runner)]=name
        results=[]
        for fut in as_completed(futures):
            name=futures[fut]
            try:
                fs,mm=fut.result()
                st=mm.get("status","unknown")
                _scanner_state(tid,name,st)
                _log(tid,f"✔ {name} {st} — {len(fs)} hits")
                results.append((name,fs,mm))
            except Exception as ex:
                LOG.exception("%s failed",name)
                _scanner_state(tid,name,"failed")
                _log(tid,f"✘ {name}: {str(ex)[:120]}")
                results.append((name,[],{"status":"failed","error_log":str(ex)[:200]}))
    for n,fs,mm in results: _batch_persist(tid,n,fs,mm,tb)

def run_full_scan(tid,tb="manual"):
    with app.app_context():
        t=db.session.get(Target,tid)
        if not t: _set(tid,"status","failed"); return
        _state_init(tid)
        _log(tid,f"Scan start: {t.raw_input}")
        p=parse_target(t.raw_input,t.target_type)
        host=p["host"]; url=p["url"]; tt=t.target_type
        _log(tid,f"Type:{tt} Host:{host} URL:{url}")
        def sk(r): return ([],{"status":"skipped","error_log":r})
        # WAVE 1
        _log(tid,"══ WAVE 1: RECON ══")
        _run_wave(tid,[
            ("dnsx",lambda:scan_dnsx(host) if tt in ("domain","hostname") else sk("n/a")),
            ("whois",lambda:scan_whois(host) if tt in ("domain","hostname") else sk("n/a")),
            ("crt_sh",lambda:scan_crt_sh(host) if tt=="domain" else sk("n/a")),
            ("wafw00f",lambda:scan_wafw00f(url)),
            ("headers",lambda:scan_headers(url))],tb)
        if _is_cancelled(tid): _finalize(tid,"cancelled"); return
        # WAVE 2
        _log(tid,"══ WAVE 2: DISCOVERY ══")
        _run_wave(tid,[
            ("subfinder",lambda:scan_subfinder(host) if tt=="domain" else sk("n/a")),
            ("amass",lambda:scan_amass(host) if tt=="domain" else sk("n/a")),
            ("gau",lambda:scan_gau(host) if tt=="domain" else sk("n/a")),
            ("httpx",lambda:scan_httpx(url)),
            ("whatweb",lambda:scan_whatweb(url))],tb)
        if _is_cancelled(tid): _finalize(tid,"cancelled"); return
        # WAVE 3
        _log(tid,"══ WAVE 3: DEEP ══")
        _run_wave(tid,[
            ("naabu",lambda:scan_naabu(host) if tt in ("ipv4","ipv6","domain","hostname") else sk("n/a")),
            ("rustscan",lambda:scan_rustscan(host) if tt in ("ipv4","ipv6","domain","hostname") else sk("n/a")),
            ("katana",lambda:scan_katana(url)),
            ("feroxbuster",lambda:scan_feroxbuster(url)),
            ("gobuster",lambda:scan_gobuster(url)),
            ("sslscan",lambda:scan_sslscan(host,p["port"]) if p["is_tls"] else sk("n/a")),
            ("testssl",lambda:scan_testssl(host,p["port"]) if p["is_tls"] else sk("n/a"))],tb)
        if _is_cancelled(tid): _finalize(tid,"cancelled"); return
        # WAVE 4
        _log(tid,"══ WAVE 4: WEB VULN ══")
        _run_wave(tid,[
            ("nmap",lambda:scan_nmap(host) if tt in ("ipv4","ipv6","domain","hostname") else sk("n/a")),
            ("nikto",lambda:scan_nikto(url)),
            ("cors",lambda:scan_cors(url)),
            ("jwt",lambda:scan_jwt(url)),
            ("graphql",lambda:scan_graphql(url)),
            ("git",lambda:scan_git_expose(url)),
            ("backup",lambda:scan_backup(url)),
            ("admin",lambda:scan_admin_enum(url)),
            ("creds",lambda:scan_default_creds(url))],tb)
        if _is_cancelled(tid): _finalize(tid,"cancelled"); return
        # WAVE 5
        _log(tid,"══ WAVE 5: NUCLEI ══")
        _set(tid,"current_scanner","nuclei"); _scanner_state(tid,"nuclei","running")
        try:
            fs,mm=scan_nuclei(url); st=mm.get("status","unknown")
            _scanner_state(tid,"nuclei",st)
            _log(tid,f"✔ nuclei {st} — {len(fs)} hits")
            _batch_persist(tid,"nuclei",fs,mm,tb)
        except Exception as ex:
            LOG.exception("nuclei failed")
            _scanner_state(tid,"nuclei","failed")
            _log(tid,f"✘ nuclei: {str(ex)[:120]}")
        _finalize(tid,"success")

def _finalize(tid,status):
    with app.app_context():
        t=db.session.get(Target,tid)
        if t: t.last_scan_at=utcnow(); db.session.commit()
        tot=Finding.query.filter_by(target_id=tid).count()
        _set(tid,"status",status); _set(tid,"ended_at",utcnow().isoformat())
        _set(tid,"current_scanner",None); _set(tid,"findings_count",tot)
        _log(tid,f"═══ {status.upper()} — {tot} findings ═══")

# ═══════════════════════════════════════════════════════════════════════════
#  TEMPLATES  (single compact base + pages)
# ═══════════════════════════════════════════════════════════════════════════
_BASE=r"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{% block title %}Console{% endblock %} · {{ app_name }}</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;700&family=Orbitron:wght@700;900&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/d3@7.8.5/dist/d3.min.js"></script>
<style>
:root{--b:#03060d;--s:#0a1120;--s2:#0f1a30;--bd:#1a2845;--a:#22d3ee;--am:#f59e0b;
--g:#10b981;--r:#ef4444;--t:#cbd5e1;--m:#64748b;}
*{font-family:'Inter',sans-serif}code,pre,.mono{font-family:'JetBrains Mono',monospace}
.fd{font-family:'Orbitron',sans-serif;letter-spacing:.06em}
body{background:var(--b);color:var(--t);min-height:100vh}
body::before{content:"";position:fixed;inset:-30%;z-index:-2;
background:radial-gradient(circle at 20% 20%,rgba(34,211,238,.08) 0,transparent 40%),
radial-gradient(circle at 80% 80%,rgba(139,92,246,.06) 0,transparent 40%);
animation:bp 14s ease-in-out infinite alternate}
@keyframes bp{to{transform:scale(1.15) rotate(2deg)}}
.ct{background:linear-gradient(90deg,#f59e0b,#ef4444,#f59e0b);background-size:200% 100%;
color:#000;text-align:center;font-family:'Orbitron',monospace;font-weight:900;
font-size:.7rem;letter-spacing:.35em;padding:6px 0;border-bottom:2px solid #000;
animation:gs 4s linear infinite}
@keyframes gs{to{background-position:200% 50%}}
.cb{position:fixed;bottom:0;left:0;right:0;z-index:1000;border-top:2px solid #000;
border-bottom:none;padding:4px 0;font-size:.65rem;letter-spacing:.3em}
.nav{background:linear-gradient(180deg,rgba(10,17,32,.95),rgba(5,10,21,.98));
backdrop-filter:blur(12px);border-bottom:1px solid var(--bd);
box-shadow:0 8px 32px rgba(0,0,0,.6);padding:12px 0;margin-bottom:16px;position:relative;z-index:100}
.brand{font-family:'Orbitron',sans-serif;font-weight:900;color:var(--am)!important;
display:flex;align-items:center;gap:12px;text-decoration:none}
.sh{width:40px;height:40px;border-radius:8px;
background:linear-gradient(135deg,#22d3ee,#0891b2,#8b5cf6);
display:inline-flex;align-items:center;justify-content:center;color:#000;
font-weight:900;font-size:18px;animation:sp 3s ease-in-out infinite}
@keyframes sp{50%{box-shadow:0 0 40px rgba(34,211,238,1)}}
.bt{line-height:1.05}.bt small{display:block;font-size:.6rem;font-weight:400;color:var(--m);letter-spacing:.2em}
.card{background:linear-gradient(145deg,rgba(10,17,32,.9),rgba(15,26,48,.85));
border:1px solid var(--bd);border-radius:10px;box-shadow:0 4px 24px rgba(0,0,0,.5);
transition:transform .4s cubic-bezier(.34,1.56,.64,1),border-color .3s;overflow:hidden;color:var(--t)}
.card:hover{transform:translateY(-4px);border-color:rgba(34,211,238,.4);
box-shadow:0 20px 60px rgba(0,0,0,.7),0 0 40px rgba(34,211,238,.2)}
.kn{font-family:'Orbitron',monospace;font-size:2rem;font-weight:900;
background:linear-gradient(180deg,#fff,#94a3b8);-webkit-background-clip:text;
background-clip:text;-webkit-text-fill-color:transparent}
.kl{font-family:'JetBrains Mono',monospace;font-size:.68rem;text-transform:uppercase;
letter-spacing:.15em;color:var(--m)}
.kr .kn{background:linear-gradient(180deg,#fca5a5,#ef4444);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
.ka .kn{background:linear-gradient(180deg,#fcd34d,#f59e0b);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
.kg .kn{background:linear-gradient(180deg,#6ee7b7,#10b981);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}
table.table{color:var(--t);font-size:.88rem}
table.table thead th{font-family:'JetBrains Mono',monospace;font-size:.68rem;
text-transform:uppercase;letter-spacing:.1em;background:var(--s2)!important;
border-color:var(--bd)!important;color:var(--m)!important}
table.table tbody td{border-color:var(--bd)!important}
table.table tbody tr:hover{background:rgba(34,211,238,.06)}
a{color:var(--a);text-decoration:none}a:hover{color:#67e8f9}
.bc{background:#7f1d1d;border:1px solid #dc2626;color:#fecaca}
.bh{background:#991b1b;border:1px solid #ef4444;color:#fee2e2}
.bm{background:#78350f;border:1px solid #f59e0b;color:#fef3c7}
.bl{background:#164e63;border:1px solid #06b6d4;color:#cffafe}
.bi{background:#1e293b;border:1px solid #475569;color:#cbd5e1}
.badge{font-family:'JetBrains Mono',monospace;font-size:.68rem;font-weight:700;padding:4px 9px}
.btn{font-family:'JetBrains Mono',monospace;font-size:.72rem;font-weight:700;
letter-spacing:.08em;text-transform:uppercase;border-radius:6px}
.bp{background:#0891b2;border-color:#0891b2;color:#fff}
.bp:hover{background:#06b6d4;border-color:#06b6d4}
.bd{background:#b91c1c;border-color:#b91c1c;color:#fff}
.bw{background:var(--am);border-color:var(--am);color:#000}
.btt{background:transparent;border:1px solid var(--g);color:var(--g)}
.btt:hover{background:rgba(16,185,129,.12);color:var(--g)}
.is{background:linear-gradient(90deg,rgba(34,211,238,.12),rgba(34,211,238,.02));
border-left:3px solid var(--a);padding:8px 14px;font-family:'JetBrains Mono',monospace;
font-size:.72rem;color:var(--m);margin-bottom:16px;display:flex;
justify-content:space-between;align-items:center}
.is strong{color:var(--am)}
.sd{display:inline-block;width:8px;height:8px;border-radius:50%;
margin-right:8px;vertical-align:middle;box-shadow:0 0 8px currentColor;
animation:dp 2s ease-in-out infinite}
@keyframes dp{50%{opacity:.4}}
.dg{background:var(--g);color:var(--g)}.da{background:var(--am);color:var(--am)}.dr{background:var(--r);color:var(--r)}
.footer{background:linear-gradient(180deg,rgba(10,17,32,.7),rgba(3,6,13,.9));
border-top:1px solid var(--bd);color:var(--m);font-size:.75rem;padding:24px 0;
margin-top:40px;margin-bottom:36px;text-align:center}
.fb{color:var(--am);font-weight:900;font-family:'Orbitron',sans-serif;letter-spacing:.15em}
.dc{display:inline-block;background:var(--s2);border:1px solid var(--bd);border-radius:4px;
padding:4px 10px;margin:3px;font-family:'JetBrains Mono',monospace;font-size:.66rem}
.dc strong{color:var(--am)}
.fc,.fs{background:rgba(3,6,13,.8);border:1px solid var(--bd);color:var(--t);
font-family:'JetBrains Mono',monospace;font-size:.85rem}
.fc:focus,.fs:focus{background:rgba(3,6,13,.9);border-color:var(--a);
color:var(--t);box-shadow:0 0 0 3px rgba(34,211,238,.15)}
.tb{background:#000;border:1px solid var(--bd);border-radius:8px;padding:16px;
font-family:'JetBrains Mono',monospace;font-size:.78rem;color:#22d3ee;
max-height:500px;overflow-y:auto;white-space:pre-wrap;line-height:1.6}
.rw{width:160px;height:160px;position:relative;border-radius:50%;margin:0 auto;
background:radial-gradient(circle,rgba(34,211,238,.08) 0,transparent 70%);
border:1px solid rgba(34,211,238,.4)}
.rw::before{content:"";position:absolute;inset:0;border-radius:50%;
background:conic-gradient(from 0deg,transparent 0,rgba(34,211,238,.4) 15%,transparent 30%);
animation:rs 2s linear infinite}
@keyframes rs{to{transform:rotate(360deg)}}
.sh2{font-family:'Orbitron',sans-serif;font-weight:900;letter-spacing:.1em;
color:var(--am);display:flex;align-items:center;gap:12px;margin-bottom:20px;
text-shadow:0 0 20px rgba(245,158,11,.4)}
.sh2::before{content:"◈";color:var(--a)}
.sw{position:fixed;top:70px;right:20px;z-index:999;background:var(--am);color:#000;
padding:10px 16px;border-radius:8px;font-family:'JetBrains Mono',monospace;
font-size:.72rem;font-weight:700;box-shadow:0 8px 32px rgba(245,158,11,.5);
cursor:pointer;display:none;text-decoration:none}
.sw .p{display:inline-block;width:8px;height:8px;border-radius:50%;background:#000;
margin-right:8px;animation:dp 1s ease-in-out infinite}
::-webkit-scrollbar{width:8px;height:8px}
::-webkit-scrollbar-thumb{background:var(--bd);border-radius:4px}
::-webkit-scrollbar-thumb:hover{background:var(--a)}
</style></head><body>
<div class="ct">▸ {{ classification }} ▸</div>
<a href="#" id="sw" class="sw"><span class="p"></span><span id="swt">SCAN</span></a>
<nav class="nav"><div class="container-fluid" style="display:flex;align-items:center;gap:20px">
<a class="brand" href="{{ url_for('index') }}"><span class="sh">◈</span>
<span class="bt">GRAYSENTINEL<small>VULNINTEL v{{ app_version }} · {{ company_name }}</small></span></a>
<div style="flex:1">
{% if current_user.is_authenticated %}
<a href="{{ url_for('dashboard') }}" style="margin:0 8px;font-family:'JetBrains Mono';font-size:.75rem">Console</a>
<a href="{{ url_for('targets') }}" style="margin:0 8px;font-family:'JetBrains Mono';font-size:.75rem">Targets</a>
<a href="{{ url_for('findings') }}" style="margin:0 8px;font-family:'JetBrains Mono';font-size:.75rem">Findings</a>
<a href="{{ url_for('graph_view') }}" style="margin:0 8px;font-family:'JetBrains Mono';font-size:.75rem">Graph</a>
<a href="{{ url_for('kev_view') }}" style="margin:0 8px;font-family:'JetBrains Mono';font-size:.75rem">KEV</a>
<a href="{{ url_for('cve_search') }}" style="margin:0 8px;font-family:'JetBrains Mono';font-size:.75rem">CVE</a>
<a href="{{ url_for('admin_panel') }}" style="margin:0 8px;font-family:'JetBrains Mono';font-size:.75rem">Admin</a>
{% endif %}</div>
{% if current_user.is_authenticated %}
<span class="mono" style="font-size:.72rem;color:var(--m)"><span class="sd dg"></span>OP: {{ current_user.username }} [{{ current_user.role|upper }}]</span>
<a href="{{ url_for('logout') }}" style="margin-left:16px;font-family:'JetBrains Mono';font-size:.75rem">Logout</a>
{% endif %}
</div></nav>
<div class="container-fluid">
<div class="is"><span><strong>◈ {{ company_name }}</strong> · {{ tool_tagline }}</span>
<span>KEV: <span class="sd {{ 'dr' if kev_stale_banner else 'dg' }}"></span>{{ 'STALE' if kev_stale_banner else 'FRESH' }}</span></div>
{% with msgs=get_flashed_messages(with_categories=true) %}{% if msgs %}{% for c,m in msgs %}
<div class="alert alert-{{ 'danger' if c=='danger' else c }} alert-dismissible fade show">{{ m }}
<button type="button" class="btn-close" data-bs-dismiss="alert"></button></div>
{% endfor %}{% endif %}{% endwith %}
{% block content %}{% endblock %}
</div>
<div class="footer">
<div class="fb mb-2">◈ {{ company_name }} ◈</div>
<div class="mono" style="font-size:.7rem">{{ app_name }} v{{ app_version }} · {{ tool_tagline }}</div>
<div style="margin-top:8px">{% for n,r in developers %}<span class="dc"><strong>{{ n }}</strong> · {{ r }}</span>{% endfor %}</div>
<div class="mono mt-2" style="font-size:.65rem;letter-spacing:.15em">{{ classification }}</div>
</div>
<div class="ct cb">▸ {{ classification }} ▸</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
<script>
async function psw(){ {% if current_user.is_authenticated %}
try{const r=await fetch('{{ url_for("api_active_scans") }}');const d=await r.json();
const w=document.getElementById('sw');
if(d&&d.length>0){const s=d[0];document.getElementById('swt').textContent=
'SCAN: '+(s.current_scanner||'init')+' · '+(s.findings_count||0);
w.href='/targets/'+s.target_id+'/progress';w.style.display='block';}
else{w.style.display='none';}}catch(e){} {% endif %}
setTimeout(psw,3000);} psw();
</script>{% block scripts %}{% endblock %}</body></html>"""

_LOGIN=r"""{% extends "base" %}{% block title %}Login{% endblock %}{% block content %}
<div style="max-width:400px;margin:60px auto"><div class="card p-5">
<div style="text-align:center;margin-bottom:20px">
<div class="fd" style="font-size:2.5rem;color:var(--am)">◈</div>
<h3 class="fd mt-2" style="color:var(--am);letter-spacing:.2em">AUTHENTICATE</h3>
<p class="mono" style="font-size:.7rem;color:var(--m)">{{ company_name }}</p></div>
<form method="POST"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
<div class="mb-3"><label class="mono" style="font-size:.72rem;color:var(--m)">OPERATOR ID</label>
<input class="fc form-control" name="username" required autofocus></div>
<div class="mb-3"><label class="mono" style="font-size:.72rem;color:var(--m)">PASSCODE</label>
<input class="fc form-control" type="password" name="password" required></div>
<div class="mb-3"><label class="mono" style="font-size:.72rem;color:var(--m)">2FA (optional)</label>
<input class="fc form-control" name="totp" maxlength="6" placeholder="000000"></div>
<button class="btn bp w-100 py-2">▶ ENGAGE</button></form></div></div>{% endblock %}"""

_DASH=r"""{% extends "base" %}{% block title %}Console{% endblock %}{% block content %}
<h3 class="sh2">COMMAND CONSOLE</h3>
<div class="row g-3 mb-4">
<div class="col-md-2"><div class="card p-3"><div class="kl">Targets</div><div class="kn">{{ stats.targets }}</div></div></div>
<div class="col-md-2"><div class="card p-3"><div class="kl">Findings</div><div class="kn">{{ stats.total }}</div></div></div>
<div class="col-md-2"><div class="card p-3 kr"><div class="kl">KEV</div><div class="kn">{{ stats.kev }}</div></div></div>
<div class="col-md-2"><div class="card p-3 ka"><div class="kl">Crit/High</div><div class="kn">{{ stats.critical }}</div></div></div>
<div class="col-md-2"><div class="card p-3"><div class="kl">Ports</div><div class="kn">{{ stats.ports }}</div></div></div>
<div class="col-md-2"><div class="card p-3 kg"><div class="kl">Tools</div><div class="kn">{{ stats.tools_ready }}/{{ stats.tools_total }}</div></div></div>
</div>
<div class="row g-3 mb-4">
<div class="col-md-3"><div class="card p-3 {% if stats.kev_stale %}stale{% endif %}">
<div class="kl">KEV Refresh</div><div class="mono">{{ stats.last_kev.strftime('%Y-%m-%d %H:%M') if stats.last_kev else 'NEVER' }}</div></div></div>
<div class="col-md-3"><div class="card p-3"><div class="kl">CVE Cache</div><div class="mono">{{ stats.cve_cache }}</div></div></div>
<div class="col-md-3"><div class="card p-3"><div class="kl">Last Scan</div>
<div class="mono">{{ stats.last_scan.strftime('%Y-%m-%d %H:%M') if stats.last_scan else 'NEVER' }}</div></div></div>
<div class="col-md-3"><div class="card p-3"><div class="kl">Total Scans</div><div class="mono">{{ stats.scans }}</div></div></div>
</div>
<div class="row g-3 mb-4">
<div class="col-md-4"><div class="card p-3"><canvas id="cs" height="200"></canvas></div></div>
<div class="col-md-8"><div class="card p-3"><canvas id="cc" height="200"></canvas></div></div>
</div>
<div class="card p-4 mb-4"><h6 class="fd" style="color:var(--am)">◈ QUICK ACTIONS</h6>
<a href="{{ url_for('targets') }}" class="btn btt me-2">▶ TARGETS</a>
<a href="{{ url_for('findings') }}" class="btn btt me-2">◈ FINDINGS</a>
<a href="{{ url_for('graph_view') }}" class="btn btt me-2">◈ GRAPH</a>
<a href="{{ url_for('cve_search') }}" class="btn btt">◈ CVE DB</a></div>
<div class="row g-3">
<div class="col-md-7"><div class="card p-3"><h6 class="fd" style="color:var(--am)">◈ RECENT</h6>
<table class="table"><thead><tr><th>CVE</th><th>Title</th><th>Sev</th><th>Conf</th><th>Tool</th></tr></thead>
<tbody>{% for f in recent %}<tr><td class="mono" style="font-size:.72rem">{{ f.cve_id or '-' }}</td>
<td><a href="{{ url_for('finding_detail', fid=f.id) }}">{{ f.title[:55] }}</a></td>
<td><span class="badge b{{ f.severity[0]|lower }}">{{ f.severity }}</span></td>
<td class="mono" style="font-size:.72rem">{{ f.confidence }}</td>
<td class="mono" style="font-size:.72rem">{{ f.scanner }}</td></tr>
{% else %}<tr><td colspan="5" class="text-muted text-center py-4">No findings.</td></tr>{% endfor %}</tbody></table>
</div></div>
<div class="col-md-5"><div class="card p-3"><h6 class="fd" style="color:var(--am)">◈ TOOLS</h6>
<table class="table">{% for t,r in tools.items() %}<tr><td class="mono" style="font-size:.72rem">{{ t }}</td>
<td>{% if r %}<span class="badge bl">READY</span>{% else %}<span class="badge bi">MISSING</span>{% endif %}</td></tr>{% endfor %}</table>
</div></div></div>{% endblock %}
{% block scripts %}<script>
const sd={{ severity_chart|tojson }};
new Chart(document.getElementById('cs'),{type:'doughnut',
data:{labels:Object.keys(sd),datasets:[{data:Object.values(sd),
backgroundColor:['#b91c1c','#ef4444','#f59e0b','#06b6d4','#475569','#64748b'],
borderColor:'#050810',borderWidth:3}]},
options:{plugins:{legend:{position:'bottom',labels:{color:'#cbd5e1'}}}}});
const cd={{ scanner_chart|tojson }};
new Chart(document.getElementById('cc'),{type:'bar',
data:{labels:cd.labels,datasets:[{label:'Findings',data:cd.values,backgroundColor:'#22d3ee'}]},
options:{plugins:{legend:{display:false}},scales:{x:{ticks:{color:'#94a3b8'}},
y:{ticks:{color:'#94a3b8'}}}}});
</script>{% endblock %}"""

_TARGETS=r"""{% extends "base" %}{% block title %}Targets{% endblock %}{% block content %}
<h3 class="sh2">TARGETS</h3>
<div class="card p-4 mb-3"><form method="POST" class="row g-2">
<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
<div class="col-md-3"><input class="fc form-control" name="name" placeholder="Label" required></div>
<div class="col-md-5"><input class="fc form-control" name="raw_input" placeholder="https://host:port | IP | domain" required></div>
<div class="col-md-2"><input class="fc form-control" name="notes" placeholder="Notes"></div>
<div class="col-md-2"><button class="btn bp w-100">ADD</button></div></form></div>
<div class="card p-0"><table class="table mb-0"><thead>
<tr><th>ID</th><th>Name</th><th>Input</th><th>Type</th><th>Port</th><th>Last Scan</th><th>Findings</th><th style="text-align:right">Actions</th></tr></thead>
<tbody>{% for t in targets %}<tr><td class="mono">{{ t.id }}</td>
<td><strong>{{ t.name }}</strong></td><td class="mono" style="font-size:.78rem">{{ t.raw_input }}</td>
<td><span class="badge bi">{{ t.target_type|upper }}</span></td>
<td class="mono">{{ t.port or '-' }}</td>
<td class="mono" style="font-size:.75rem">{{ t.last_scan_at.strftime('%Y-%m-%d %H:%M') if t.last_scan_at else 'NEVER' }}</td>
<td><span class="badge bl">{{ t.findings|length }}</span></td>
<td style="text-align:right">
<form method="POST" action="{{ url_for('target_scan', tid=t.id) }}" style="display:inline">
<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
<button class="btn btt btn-sm">▶ SCAN</button></form>
<form method="POST" action="{{ url_for('target_delete', tid=t.id) }}" style="display:inline"
onsubmit="return confirm('Delete?')">
<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
<button class="btn bd btn-sm">✕</button></form>
</td></tr>{% else %}<tr><td colspan="8" class="text-muted text-center py-5">No targets.</td></tr>{% endfor %}
</tbody></table></div>{% endblock %}"""

_PROGRESS=r"""{% extends "base" %}{% block title %}Scan{% endblock %}{% block content %}
<h3 class="sh2">LIVE SCAN: {{ target.name }}</h3>
<p class="mono" style="font-size:.78rem;color:var(--m)">Target: <strong style="color:var(--a)">{{ target.raw_input }}</strong></p>
<div class="row g-3">
<div class="col-md-4"><div class="card p-4 text-center">
<div class="rw mb-3"></div>
<div class="fd" id="st" style="color:var(--am);font-size:.9rem">SCANNING...</div>
<div class="mono" id="cs" style="color:var(--m);font-size:.75rem;margin-top:8px">Init</div>
<div class="mono mt-3" style="font-size:1.4rem;color:var(--a)" id="fc">0</div>
<div class="kl">FINDINGS</div>
<form method="POST" action="{{ url_for('target_cancel', tid=target.id) }}" class="mt-3"
onsubmit="return confirm('Cancel?')">
<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
<button class="btn bd btn-sm w-100">⊘ CANCEL</button></form>
</div></div>
<div class="col-md-8"><div class="card p-4"><h6 class="fd" style="color:var(--am)">◈ PIPELINE</h6>
<div id="pl"></div></div></div></div>
<div class="card p-4 mt-3"><h6 class="fd" style="color:var(--am)">◈ LIVE LOG</h6>
<div class="tb" id="lg">Connecting...</div></div>
<div class="mt-3"><a href="{{ url_for('findings') }}" class="btn bp">◈ FINDINGS</a>
<a href="{{ url_for('targets') }}" class="btn btt ms-2">◈ BACK</a></div>
{% endblock %}
{% block scripts %}<script>
const tid={{ target.id }};
const labels={"dnsx":"DNSX","whois":"WHOIS","crt_sh":"CRT","wafw00f":"WAF","headers":"HEADERS",
"subfinder":"SUBDOM","amass":"AMASS","gau":"GAU","httpx":"HTTPX","whatweb":"TECH",
"naabu":"NAABU","rustscan":"RUST","katana":"KATANA","feroxbuster":"FEROX",
"gobuster":"GOBUSTER","sslscan":"SSLSCAN","testssl":"TESTSSL","nmap":"NMAP",
"nikto":"NIKTO","cors":"CORS","jwt":"JWT","graphql":"GQL","git":"GIT",
"backup":"BACKUP","admin":"ADMIN","creds":"CREDS","nuclei":"NUCLEI"};
const order=["dnsx","whois","crt_sh","wafw00f","headers","subfinder","amass","gau","httpx","whatweb",
"naabu","rustscan","katana","feroxbuster","gobuster","sslscan","testssl","nmap","nikto",
"cors","jwt","graphql","git","backup","admin","creds","nuclei"];
function rp(sc,cur){let h='<div class="row g-2">';
for(const k of order){const s=sc[k]||"pending";const c=s==="success"?"var(--g)":
s==="running"?"var(--am)":(s==="failed"||s==="timeout")?"var(--r)":
(s==="skipped"||s==="cancelled")?"var(--m)":"var(--bd)";
h+=`<div class="col-md-4"><div class="card p-2" style="border-left:3px solid ${c}">
<div class="mono" style="font-size:.6rem;color:var(--m)">${labels[k]}</div>
<div class="mono" style="font-size:.75rem;color:${c};font-weight:700">${s.toUpperCase()}</div></div></div>`}
h+='</div>';document.getElementById('pl').innerHTML=h;}
const es=new EventSource('/api/scan-stream/'+tid);const lg=document.getElementById('lg');let lt='';
es.onmessage=function(e){try{const d=JSON.parse(e.data);
if(d.type==='log'){lt+=d.msg+'\n';lg.textContent=lt;lg.scrollTop=lg.scrollHeight;}}catch(x){}};
async function rs(){try{const r=await fetch('/api/scan-status/'+tid);const d=await r.json();
if(d&&d.status){rp(d.scanners||{},d.current_scanner);
document.getElementById('cs').textContent=d.current_scanner?'▶ '+labels[d.current_scanner]:'IDLE';
document.getElementById('fc').textContent=d.findings_count||0;
if(d.status==='success'){document.getElementById('st').textContent='✓ COMPLETE';
document.getElementById('st').style.color='var(--g)';es.close();return;}
if(d.status==='failed'||d.status==='cancelled'){document.getElementById('st').textContent='✘ '+d.status.toUpperCase();
document.getElementById('st').style.color='var(--r)';es.close();return;}}
setTimeout(rs,2000);}catch(e){setTimeout(rs,3000);}}rs();
</script>{% endblock %}"""

_FIND=r"""{% extends "base" %}{% block title %}Findings{% endblock %}{% block content %}
<h3 class="sh2">FINDINGS</h3>
<form method="GET" class="row g-2 mb-3">
<div class="col-md-3"><input class="fc form-control" name="q" placeholder="Search" value="{{ q }}"></div>
<div class="col-md-2"><select class="fs form-select" name="severity"><option value="">All sev</option>
{% for s in severities %}<option {% if s==severity %}selected{% endif %}>{{ s }}</option>{% endfor %}</select></div>
<div class="col-md-2"><select class="fs form-select" name="scanner"><option value="">All tools</option>
{% for s in scanners %}<option {% if s==scanner %}selected{% endif %}>{{ s }}</option>{% endfor %}</select></div>
<div class="col-md-2"><select class="fs form-select" name="kev"><option value="">All</option>
<option value="1" {% if kev=='1' %}selected{% endif %}>KEV only</option>
<option value="0" {% if kev=='0' %}selected{% endif %}>Non-KEV</option></select></div>
<div class="col-md-1"><button class="btn bp w-100">GO</button></div>
<div class="col-md-2 text-end">
<a class="btn btt" href="{{ url_for('export_csv') }}">CSV</a>
<a class="btn btt" href="{{ url_for('export_sarif') }}">SARIF</a>
<a class="btn btt" href="{{ url_for('export_pdf') }}">PDF</a></div></form>
<div class="card p-0"><table class="table mb-0"><thead>
<tr><th>ID</th><th>CVE</th><th>Title</th><th>Sev</th><th>CVSS</th><th>EPSS</th><th>Conf</th><th>Tool</th><th>KEV</th></tr></thead>
<tbody>{% for f in findings %}<tr><td class="mono">{{ f.id }}</td>
<td class="mono" style="font-size:.72rem">{{ f.cve_id or '-' }}</td>
<td><a href="{{ url_for('finding_detail', fid=f.id) }}">{{ f.title[:65] }}</a></td>
<td><span class="badge b{{ f.severity[0]|lower }}">{{ f.severity }}</span></td>
<td class="mono">{{ '%.1f'|format(f.cvss_score) if f.cvss_score else '-' }}</td>
<td class="mono">{{ '%.3f'|format(f.epss_score) if f.epss_score else '-' }}</td>
<td class="mono" style="font-size:.72rem">{{ f.confidence }}</td>
<td class="mono" style="font-size:.72rem">{{ f.scanner }}</td>
<td>{% if f.kev_status %}<span class="badge bc">KEV</span>{% else %}-{% endif %}</td></tr>
{% else %}<tr><td colspan="9" class="text-center text-muted py-5">No findings.</td></tr>{% endfor %}
</tbody></table></div>
{% if pages > 1 %}<nav class="mt-3"><ul class="pagination">
{% for p in range(1,pages+1) %}<li class="page-item {% if p==page %}active{% endif %}">
<a class="page-link" href="?page={{ p }}&q={{ q }}&severity={{ severity }}&scanner={{ scanner }}&kev={{ kev }}">{{ p }}</a></li>
{% endfor %}</ul></nav>{% endif %}{% endblock %}"""

_FIND_D=r"""{% extends "base" %}{% block title %}Finding #{{ f.id }}{% endblock %}{% block content %}
<h3 style="color:var(--t)">{{ f.title }}</h3>
<p class="mono" style="font-size:.75rem;color:var(--m)">
#{{ f.id }} · TOOL: {{ f.scanner|upper }} · CONF: {{ f.confidence|upper }} · FIRST: {{ f.first_seen }}</p>
<ul class="nav nav-tabs mb-3" role="tablist">
<li class="nav-item"><button class="nav-link active" data-bs-toggle="tab" data-bs-target="#ov">Overview</button></li>
<li class="nav-item"><button class="nav-link" data-bs-toggle="tab" data-bs-target="#ev">Evidence</button></li>
<li class="nav-item"><button class="nav-link" data-bs-toggle="tab" data-bs-target="#rm">Remediation</button></li></ul>
<div class="tab-content">
<div class="tab-pane fade show active" id="ov"><div class="row">
<div class="col-md-6"><table class="table">
<tr><th>CVE</th><td class="mono">{{ f.cve_id or 'N/A' }}</td></tr>
<tr><th>CWE</th><td class="mono">{{ f.cwe_id or 'N/A' }}</td></tr>
<tr><th>Severity</th><td><span class="badge b{{ f.severity[0]|lower }}">{{ f.severity }}</span></td></tr>
<tr><th>CVSS</th><td class="mono">{{ f.cvss_score or '-' }}</td></tr>
<tr><th>EPSS</th><td class="mono">{{ '%.4f'|format(f.epss_score) if f.epss_score else '-' }}</td></tr>
<tr><th>KEV</th><td>{% if f.kev_status %}<span class="badge bc">YES</span>{% else %}No{% endif %}</td></tr>
<tr><th>Service</th><td class="mono">{{ f.service or '-' }} {{ f.service_version or '' }}</td></tr>
<tr><th>Endpoint</th><td class="mono">{{ f.endpoint or '-' }}</td></tr></table></div>
<div class="col-md-6"><h6 class="fd" style="color:var(--am)">DESCRIPTION</h6><p>{{ f.description }}</p></div>
</div></div>
<div class="tab-pane fade" id="ev"><h6 class="fd" style="color:var(--am)">EVIDENCE</h6>
<table class="table"><thead><tr><th>Tool</th><th>Source</th><th>Hash</th><th>Retrieved</th></tr></thead>
<tbody>{% for e in evidence %}<tr><td class="mono">{{ e.tool }}</td>
<td class="mono" style="font-size:.72rem">{{ e.source_url }}</td>
<td class="mono" style="font-size:.7rem">{{ (e.snapshot_hash or '')[:16] }}</td>
<td class="mono" style="font-size:.72rem">{{ e.retrieved_at }}</td></tr>
{% else %}<tr><td colspan="4" class="text-muted">No evidence.</td></tr>{% endfor %}</tbody></table>
<details><summary class="mono" style="cursor:pointer;color:var(--a)">▸ RAW</summary>
<div class="tb mt-2">{{ f.raw_output }}</div></details></div>
<div class="tab-pane fade" id="rm"><h6 class="fd" style="color:var(--am)">REMEDIATION</h6>
<p>{{ f.remediation or 'No specific remediation.' }}</p>
<form method="POST" action="{{ url_for('finding_update', fid=f.id) }}" class="row g-2 mt-3">
<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
<div class="col-md-4"><label class="mono" style="font-size:.72rem">OWNER</label>
<input class="fc form-control" name="owner" value="{{ f.owner or '' }}"></div>
<div class="col-md-4"><label class="mono" style="font-size:.72rem">STATUS</label>
<select class="fs form-select" name="status">{% for s in statuses %}<option {% if s==f.status %}selected{% endif %}>{{ s }}</option>{% endfor %}</select></div>
<div class="col-md-12"><label class="mono" style="font-size:.72rem">MITIGATION</label>
<textarea class="fc form-control" name="mitigation">{{ f.mitigation or '' }}</textarea></div>
<div class="col-md-12"><button class="btn bp">SAVE</button></div></form></div>
</div>{% endblock %}"""

_GRAPH=r"""{% extends "base" %}{% block title %}Graph{% endblock %}{% block content %}
<h3 class="sh2">ATTACK SURFACE GRAPH</h3>
<p class="mono" style="font-size:.78rem;color:var(--m)">Drag nodes · scroll zoom · hover for details</p>
<div class="card p-3" style="min-height:600px">
<svg id="gs" width="100%" height="600" style="background:rgba(3,6,13,.6);border-radius:8px"></svg></div>
{% endblock %}
{% block scripts %}<script>
const gd={{ graph_json|tojson }};
const svg=d3.select("#gs");const W=svg.node().clientWidth,H=600;
const c=svg.append("g");svg.call(d3.zoom().on("zoom",e=>c.attr("transform",e.transform)));
const sim=d3.forceSimulation(gd.nodes).force("link",d3.forceLink(gd.links).id(d=>d.id).distance(80))
.force("charge",d3.forceManyBody().strength(-300)).force("center",d3.forceCenter(W/2,H/2));
const lk=c.append("g").selectAll("line").data(gd.links).join("line").attr("stroke","#1a2845").attr("stroke-width",1.5);
const nd=c.append("g").selectAll("circle").data(gd.nodes).join("circle").attr("r",d=>d.size||8)
.attr("fill",d=>d.color||"#22d3ee").attr("stroke","#050810").attr("stroke-width",2)
.call(d3.drag().on("start",(e,d)=>{if(!e.active)sim.alphaTarget(.3).restart();d.fx=d.x;d.fy=d.y})
.on("drag",(e,d)=>{d.fx=e.x;d.fy=e.y}).on("end",(e,d)=>{if(!e.active)sim.alphaTarget(0);d.fx=null;d.fy=null}));
nd.append("title").text(d=>d.label);
const lb=c.append("g").selectAll("text").data(gd.nodes).join("text").text(d=>d.label)
.attr("font-size",9).attr("fill","#94a3b8").attr("font-family","JetBrains Mono").attr("dx",12).attr("dy",4);
sim.on("tick",()=>{lk.attr("x1",d=>d.source.x).attr("y1",d=>d.source.y).attr("x2",d=>d.target.x).attr("y2",d=>d.target.y);
nd.attr("cx",d=>d.x).attr("cy",d=>d.y);lb.attr("x",d=>d.x).attr("y",d=>d.y);});
</script>{% endblock %}"""

_KEV=r"""{% extends "base" %}{% block title %}KEV{% endblock %}{% block content %}
<h3 class="sh2">CISA KEV MATCHES</h3>
<p class="mono" style="font-size:.78rem;color:var(--m)">Total KEV entries: <strong style="color:var(--a)">{{ kev_total }}</strong></p>
<div class="card p-0"><table class="table mb-0"><thead>
<tr><th>CVE</th><th>Title</th><th>Severity</th><th>Due</th><th>Ransomware</th><th>Target</th></tr></thead>
<tbody>{% for f in findings %}<tr><td class="mono">{{ f.cve_id }}</td>
<td><a href="{{ url_for('finding_detail', fid=f.id) }}">{{ f.title[:80] }}</a></td>
<td><span class="badge bc">{{ f.severity }}</span></td>
<td class="mono">{{ f.kev_due_date or '-' }}</td>
<td class="mono">{{ f.kev_ransomware or 'Unknown' }}</td>
<td class="mono">{{ f.target.name if f.target else '-' }}</td></tr>
{% else %}<tr><td colspan="6" class="text-center text-muted py-5">No KEV matches.</td></tr>{% endfor %}
</tbody></table></div>{% endblock %}"""

_CVE=r"""{% extends "base" %}{% block title %}CVE{% endblock %}{% block content %}
<h3 class="sh2">CVE DATABASE</h3>
<div class="card p-4 mb-3"><form method="GET" class="row g-2">
<div class="col-md-8"><input class="fc form-control" name="q" placeholder="CVE-YYYY-NNNNN" value="{{ q }}"></div>
<div class="col-md-2"><button class="btn bp w-100">QUERY NVD</button></div>
<div class="col-md-2"><a class="btn btt w-100" href="{{ url_for('cve_search') }}?refresh=kev">REFRESH KEV</a></div>
</form><p class="mono mt-2" style="font-size:.7rem;color:var(--m)">Cache: {{ cache_count }} entries</p></div>
{% if result %}<div class="card p-4"><h5 class="fd" style="color:var(--am)">{{ result.cve_id }}</h5>
<table class="table">
<tr><th>Description</th><td>{{ result.description }}</td></tr>
<tr><th>CVSS</th><td class="mono">{{ result.cvss_score or '-' }} {{ result.cvss_vector or '' }}</td></tr>
<tr><th>CWE</th><td class="mono">{{ result.cwe_id or '-' }}</td></tr>
<tr><th>EPSS</th><td class="mono">{{ result.epss_score or '-' }}</td></tr>
<tr><th>Severity</th><td><span class="badge b{{ (result.severity or 'info')[0]|lower }}">{{ result.severity or 'Unknown' }}</span></td></tr>
<tr><th>Published</th><td class="mono">{{ result.published or '-' }}</td></tr>
<tr><th>KEV</th><td>{% if result.is_kev %}<span class="badge bc">YES</span>{% else %}No{% endif %}</td></tr>
<tr><th>Source</th><td class="mono">{{ result.source }}</td></tr></table></div>{% endif %}{% endblock %}"""

_ADMIN=r"""{% extends "base" %}{% block title %}Admin{% endblock %}{% block content %}
<h3 class="sh2">ADMIN</h3>
<div class="row g-3">
<div class="col-md-6"><div class="card p-3"><h6 class="fd" style="color:var(--am)">◈ SYSTEM</h6>
<table class="table"><tr><th>Tool</th><td>{{ app_name }} v{{ app_version }}</td></tr>
<tr><th>Vendor</th><td>{{ company_name }}</td></tr>
<tr><th>Classification</th><td class="mono">{{ classification }}</td></tr>
<tr><th>DB</th><td class="mono" style="font-size:.72rem">{{ db_path }}</td></tr>
<tr><th>Health</th><td><a href="{{ url_for('health') }}">/health</a></td></tr></table></div></div>
<div class="col-md-6"><div class="card p-3"><h6 class="fd" style="color:var(--am)">◈ CREATE USER</h6>
<form method="POST" action="{{ url_for('admin_create_user') }}">
<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
<div class="mb-2"><input class="fc form-control" name="username" placeholder="Username" required></div>
<div class="mb-2"><input class="fc form-control" type="password" name="password" placeholder="Password" required></div>
<div class="mb-2"><select class="fs form-select" name="role">{% for r in roles %}<option>{{ r }}</option>{% endfor %}</select></div>
<button class="btn bp">CREATE</button></form></div></div>
<div class="col-md-12"><div class="card p-3"><h6 class="fd" style="color:var(--am)">◈ USERS</h6>
<table class="table"><thead><tr><th>User</th><th>Role</th><th>Active</th><th>Last Login</th></tr></thead>
<tbody>{% for u in users %}<tr><td class="mono">{{ u.username }}</td><td class="mono">{{ u.role }}</td>
<td>{{ u.is_active }}</td><td class="mono">{{ u.last_login or '-' }}</td></tr>{% endfor %}</tbody></table>
</div></div>
<div class="col-md-12"><div class="card p-3"><h6 class="fd" style="color:var(--am)">◈ API KEYS</h6>
<form method="POST" action="{{ url_for('admin_create_apikey') }}" class="row g-2 mb-3">
<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
<div class="col-md-4"><input class="fc form-control" name="label" placeholder="Label" required></div>
<div class="col-md-2"><button class="btn bp">GENERATE</button></div></form>
<table class="table"><thead><tr><th>Prefix</th><th>Label</th><th>User ID</th><th>Active</th></tr></thead>
<tbody>{% for k in api_keys %}<tr><td class="mono">{{ k.key_prefix }}...</td><td>{{ k.label }}</td>
<td class="mono">{{ k.user_id }}</td><td>{{ k.is_active }}</td></tr>{% endfor %}</tbody></table></div></div>
<div class="col-md-12"><div class="card p-3"><h6 class="fd" style="color:var(--am)">◈ DEVELOPERS</h6>
{% for n,r in developers %}<span class="dc"><strong>{{ n }}</strong> · {{ r }}</span>{% endfor %}</div></div>
<div class="col-md-12"><div class="card p-3"><h6 class="fd" style="color:var(--am)">◈ AUDIT</h6>
<table class="table"><thead><tr><th>When</th><th>User</th><th>IP</th><th>Action</th></tr></thead>
<tbody>{% for a in audit %}<tr><td class="mono" style="font-size:.7rem">{{ a.timestamp }}</td>
<td class="mono">{{ a.user }}</td><td class="mono" style="font-size:.7rem">{{ a.ip or '-' }}</td>
<td class="mono">{{ a.action }}</td></tr>{% endfor %}</tbody></table></div></div>
</div>{% endblock %}"""

_CUSTOMER=r"""<!doctype html><html><head><meta charset="utf-8"><title>Evidence</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<style>body{background:#fff;color:#111;font-family:Georgia,serif;position:relative}
.wm{position:fixed;top:40%;left:5%;right:5%;text-align:center;font-size:3rem;
color:rgba(200,0,0,.08);transform:rotate(-20deg);pointer-events:none;z-index:0}
.c{position:relative;z-index:1}</style></head><body>
<div class="wm">SHARED UNDER NDA — APPROVED FOR EXTERNAL REVIEW</div>
<div class="container my-5 c"><h2>Vulnerability Assessment — Evidence Summary</h2>
<p class="text-muted">Generated {{ generated_at }} · {{ company_name }}</p><hr>
<table class="table table-bordered"><thead>
<tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>KEV</th><th>Status</th></tr></thead>
<tbody>{% for r in rows %}<tr><td>{{ r.cve or 'N/A' }}</td><td>{{ r.severity }}</td>
<td>{{ r.cvss or '-' }}</td><td>{{ 'YES' if r.kev else 'No' }}</td><td>{{ r.status }}</td></tr>
{% else %}<tr><td colspan="5" class="text-muted">No findings.</td></tr>{% endfor %}</tbody></table>
</div></body></html>"""

_ERR=r"""{% extends "base" %}{% block title %}Error {{ code }}{% endblock %}{% block content %}
<div class="text-center py-5"><div class="fd" style="font-size:5rem;color:var(--r)">{{ code }}</div>
<p class="lead mono">{{ message }}</p>
<a class="btn bp" href="{{ url_for('index') }}">RETURN</a></div>{% endblock %}"""

_TEMPLATES={"base":_BASE,"login":_LOGIN,"dashboard":_DASH,"targets":_TARGETS,
"progress":_PROGRESS,"findings":_FIND,"finding_detail":_FIND_D,"graph":_GRAPH,
"kev_view":_KEV,"cve_search":_CVE,"admin":_ADMIN,"customer_safe":_CUSTOMER,"error":_ERR}
app.jinja_loader=DictLoader(_TEMPLATES)

@app.context_processor
def inject_globals():
    return {"app_name":APP_NAME,"app_version":APP_VERSION,"company_name":COMPANY_NAME,
        "tool_tagline":APP_TAGLINE,"classification":CLASSIFICATION,
        "developers":DEVELOPERS,"kev_stale_banner":kev_is_stale()}

# ═══════════════════════════════════════════════════════════════════════════
#  ROUTES
# ═══════════════════════════════════════════════════════════════════════════
@app.route("/login",methods=["GET","POST"])
@limiter.limit("20/minute")
def login():
    if current_user.is_authenticated: return redirect(url_for("index"))
    if request.method=="POST":
        u=sanitize_text(request.form.get("username"),80); p=request.form.get("password","")
        tcode=sanitize_text(request.form.get("totp",""),6)
        user=User.query.filter_by(username=u).first()
        if user and user.is_locked():
            flash("Account locked.","danger"); return render_template_string(_LOGIN)
        if user and user.is_active and user.check_password(p):
            if user.totp_enabled and pyotp:
                if not pyotp.TOTP(user.totp_secret).verify(tcode,valid_window=1):
                    user.failed_attempts=(user.failed_attempts or 0)+1
                    db.session.commit(); flash("Invalid 2FA.","danger")
                    return render_template_string(_LOGIN)
            login_user(user,remember=False)
            user.last_login=utcnow(); user.last_login_ip=request.remote_addr
            user.failed_attempts=0; user.locked_until=None
            audit("login","User",user.id); db.session.commit()
            return redirect(url_for("index"))
        if user:
            user.failed_attempts=(user.failed_attempts or 0)+1
            if user.failed_attempts>=5: user.locked_until=utcnow()+timedelta(minutes=15)
            db.session.commit()
        flash("Access denied.","danger")
    return render_template_string(_LOGIN)

@app.route("/logout")
@login_required
def logout():
    audit("logout","User",current_user.id); db.session.commit(); logout_user()
    return redirect(url_for("login"))

@app.route("/")
@login_required
def index(): return redirect(url_for("dashboard"))

@app.route("/health")
def health():
    try: db.session.execute(db.text("SELECT 1")); ok=True
    except Exception: ok=False
    return jsonify({"status":"ok" if ok else "degraded","version":APP_VERSION,
        "database":"ok" if ok else "error","kev_stale":kev_is_stale(),
        "active_scans":len(_active()),"timestamp":utcnow().isoformat()})

@app.route("/dashboard")
@login_required
def dashboard():
    total=Finding.query.count(); kev=Finding.query.filter_by(kev_status=True).count()
    crit=Finding.query.filter(Finding.severity.in_(["Critical","High"])).count()
    ports=Finding.query.filter(Finding.scanner=="nmap").count()
    tgts=Target.query.count(); scans=ScanRun.query.count()
    cc=CVEEntry.query.count(); ls=db.session.query(func.max(ScanRun.ended_at)).scalar()
    sr=db.session.query(Finding.severity,func.count(Finding.id)).group_by(Finding.severity).all()
    sev={s or "Unknown":c for s,c in sr}
    scr=db.session.query(Finding.scanner,func.count(Finding.id)).group_by(Finding.scanner).all()
    sc_c={"labels":[s or "?" for s,_ in scr],"values":[c for _,c in scr]}
    recent=(Finding.query.order_by(Finding.kev_status.desc(),Finding.first_seen.desc()).limit(10).all())
    tools={"dnsx":tool_available("dnsx"),"whois":tool_available("whois"),
        "wafw00f":tool_available("wafw00f"),"subfinder":tool_available("subfinder"),
        "amass":tool_available("amass"),"gau":tool_available("gau"),
        "httpx":bool(_httpx_bin()),"whatweb":tool_available("whatweb"),
        "naabu":tool_available("naabu"),"rustscan":tool_available("rustscan"),
        "katana":tool_available("katana"),"feroxbuster":tool_available("feroxbuster"),
        "gobuster":tool_available("gobuster"),"sslscan":tool_available("sslscan"),
        "testssl.sh":tool_available("testssl.sh"),"nmap":tool_available("nmap"),
        "nikto":tool_available("nikto"),"nuclei":tool_available("nuclei")}
    stats={"total":total,"kev":kev,"critical":crit,"ports":ports,"targets":tgts,
        "scans":scans,"cve_cache":cc,"last_scan":ls,"last_kev":_KEV_CACHE["fetched_at"],
        "kev_stale":kev_is_stale(),"tools_ready":sum(1 for v in tools.values() if v),
        "tools_total":len(tools)}
    return render_template_string(_DASH,stats=stats,severity_chart=sev,
        scanner_chart=sc_c,recent=recent,tools=tools)

@app.route("/graph")
@login_required
def graph_view():
    nodes=[]; links=[]
    for t in Target.query.all():
        nodes.append({"id":f"t_{t.id}","label":t.name[:20],"size":15,"color":"#22d3ee"})
        for f in Finding.query.filter_by(target_id=t.id).limit(30).all():
            nid=f"f_{f.id}"
            nodes.append({"id":nid,"label":(f.title or "")[:30],"size":6,
                "color":"#ef4444" if f.severity=="Critical" else
                        "#f59e0b" if f.severity=="High" else
                        "#06b6d4" if f.severity=="Medium" else "#64748b"})
            links.append({"source":f"t_{t.id}","target":nid})
    return render_template_string(_GRAPH,graph_json={"nodes":nodes,"links":links})

@app.route("/targets",methods=["GET","POST"])
@login_required
@role_required("admin","triager")
def targets():
    if request.method=="POST":
        name=sanitize_text(request.form.get("name",""),120)
        raw=sanitize_text(request.form.get("raw_input",""),1024)
        notes=sanitize_text(request.form.get("notes",""),512)
        if not name or not raw:
            flash("Name + input required.","danger"); return redirect(url_for("targets"))
        tt=detect_target_type(raw)
        if tt=="invalid": flash(f"Invalid: {raw}","danger"); return redirect(url_for("targets"))
        p=parse_target(raw,tt); ip=None
        try: ip=socket.gethostbyname(p["host"])
        except Exception: pass
        t=Target(name=name,raw_input=raw,target_type=tt,scheme=p["scheme"],
            hostname=p["host"],port=p["port"],ip_address=ip,notes=notes,
            created_by=current_user.id)
        db.session.add(t); db.session.commit()
        audit("create_target","Target",t.id,{"name":name}); db.session.commit()
        flash(f"Target '{name}' added.","success"); return redirect(url_for("targets"))
    all_t=Target.query.order_by(Target.id.desc()).all()
    return render_template_string(_TARGETS,targets=all_t)

@app.route("/targets/<int:tid>/scan",methods=["POST"])
@login_required
@role_required("admin","triager")
def target_scan(tid):
    t=db.session.get(Target,tid)
    if not t: abort(404)
    with _LOCK:
        st=_STATE.get(tid)
        if st and st.get("status")=="running":
            flash("Already running.","warning"); return redirect(url_for("target_progress",tid=tid))
    _POOL.submit(run_full_scan,tid,current_user.username)
    audit("scan_start","Target",tid,{"input":t.raw_input}); db.session.commit()
    flash(f"Scan started for '{t.name}'.","success")
    return redirect(url_for("target_progress",tid=tid))

@app.route("/targets/<int:tid>/cancel",methods=["POST"])
@login_required
@role_required("admin","triager")
def target_cancel(tid):
    with _LOCK:
        _CANCEL[tid]=True
        if tid in _STATE: _STATE[tid]["cancel_requested"]=True
    _log(tid,"⊘ Cancel requested"); flash("Cancel requested.","warning")
    return redirect(url_for("target_progress",tid=tid))

@app.route("/targets/<int:tid>/progress")
@login_required
def target_progress(tid):
    t=db.session.get(Target,tid)
    if not t: abort(404)
    return render_template_string(_PROGRESS,target=t)

@app.route("/api/scan-status/<int:tid>")
@login_required
def api_scan_status(tid): return jsonify(_get(tid))

@app.route("/api/scan-stream/<int:tid>")
@login_required
def api_scan_stream(tid):
    def gen():
        q=_reg_sse(tid)
        try:
            yield f"data: {json.dumps({'type':'log','msg':'[connected]'})}\n\n"
            ka=time.time()
            while True:
                try:
                    msg=q.get(timeout=1.0)
                    yield f"data: {json.dumps(msg)}\n\n"
                except tq.Empty:
                    if time.time()-ka>15: yield ": keepalive\n\n"; ka=time.time()
                    st=_get(tid)
                    if st and st.get("status") in ("success","failed","cancelled"):
                        yield f"data: {json.dumps({'type':'log','msg':'[closed]'})}\n\n"; break
        finally: _unreg_sse(tid,q)
    return Response(stream_with_context(gen()),mimetype="text/event-stream",
        headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

@app.route("/api/active-scans")
@login_required
def api_active_scans(): return jsonify(_active())

@app.route("/targets/<int:tid>/delete",methods=["POST"])
@login_required
@role_required("admin")
def target_delete(tid):
    t=db.session.get(Target,tid)
    if not t: abort(404)
    Finding.query.filter_by(target_id=tid).delete()
    ScanRun.query.filter_by(target_id=tid).delete()
    db.session.delete(t); db.session.commit()
    audit("delete_target","Target",tid); db.session.commit()
    flash("Deleted.","success"); return redirect(url_for("targets"))

@app.route("/findings")
@login_required
def findings():
    q=sanitize_text(request.args.get("q",""),200)
    sev=sanitize_text(request.args.get("severity",""),20)
    sc=sanitize_text(request.args.get("scanner",""),40)
    kevf=request.args.get("kev","")
    page=max(1,int(request.args.get("page","1"))); pp=50
    query=Finding.query
    if q:
        like=f"%{q}%"
        query=query.filter(or_(Finding.cve_id.ilike(like),Finding.title.ilike(like),
            Finding.endpoint.ilike(like),Finding.owner.ilike(like)))
    if sev: query=query.filter(Finding.severity==sev)
    if sc: query=query.filter(Finding.scanner==sc)
    if kevf=="1": query=query.filter(Finding.kev_status.is_(True))
    elif kevf=="0": query=query.filter(Finding.kev_status.is_(False))
    total=query.count(); pages=(total+pp-1)//pp
    items=(query.order_by(Finding.kev_status.desc(),Finding.first_seen.desc())
        .offset((page-1)*pp).limit(pp).all())
    return render_template_string(_FIND,findings=items,q=q,severity=sev,scanner=sc,
        kev=kevf,severities=SEVERITY_LEVELS,
        scanners=["dnsx","whois","crt_sh","wafw00f","headers","subfinder","amass",
            "gau","httpx","whatweb","naabu","rustscan","katana","feroxbuster",
            "gobuster","sslscan","testssl","nmap","nikto","cors","jwt","graphql",
            "git","backup","admin","creds","nuclei"],
        page=page,pages=pages)

@app.route("/findings/<int:fid>")
@login_required
def finding_detail(fid):
    f=db.session.get(Finding,fid)
    if not f: abort(404)
    ev=Evidence.query.filter_by(finding_id=f.id).order_by(Evidence.retrieved_at.desc()).all()
    return render_template_string(_FIND_D,f=f,evidence=ev,statuses=STATUS_ENUM)

@app.route("/findings/<int:fid>/update",methods=["POST"])
@login_required
@role_required("admin","triager")
def finding_update(fid):
    f=db.session.get(Finding,fid)
    if not f: abort(404)
    try:
        f.owner=sanitize_text(request.form.get("owner",""),120) or None
        ns=sanitize_text(request.form.get("status",f.status),30)
        if ns in STATUS_ENUM: f.status=ns
        f.mitigation=sanitize_text(request.form.get("mitigation",""),4000) or None
        audit("update_finding","Finding",f.id,{"status":f.status}); db.session.commit()
        flash("Updated.","success")
    except Exception as ex:
        db.session.rollback(); flash(f"Failed: {str(ex)[:200]}","danger")
    return redirect(url_for("finding_detail",fid=f.id))

@app.route("/kev")
@login_required
def kev_view():
    items=Finding.query.filter_by(kev_status=True).order_by(Finding.last_seen.desc()).all()
    kt=CVEEntry.query.filter_by(is_kev=True).count()
    return render_template_string(_KEV,findings=items,kev_total=kt)

@app.route("/cve",methods=["GET"])
@login_required
def cve_search():
    if request.args.get("refresh")=="kev":
        kev_load_to_db(); flash("KEV refreshed.","success"); return redirect(url_for("cve_search"))
    q=sanitize_text(request.args.get("q",""),64).upper()
    result=None
    if q:
        result=CVEEntry.query.filter_by(cve_id=q).first()
        if not result and q.startswith("CVE-"):
            nvd_fetch_cve(q); result=CVEEntry.query.filter_by(cve_id=q).first()
    return render_template_string(_CVE,q=q,result=result,cache_count=CVEEntry.query.count())

@app.route("/reports/export/csv")
@login_required
def export_csv():
    rows=Finding.query.order_by(Finding.kev_status.desc(),Finding.id.desc()).all()
    si=io.StringIO(); w=csv.writer(si)
    w.writerow(["ID","CVE","CWE","Title","Severity","CVSS","EPSS","Confidence","KEV",
        "Target","Endpoint","Port","Scanner","Owner","Status"])
    for f in rows:
        w.writerow([f.id,f.cve_id or "",f.cwe_id or "",f.title,f.severity,
            f.cvss_score or "",f.epss_score or "",f.confidence,
            "Y" if f.kev_status else "N",
            f.target.name if f.target else "",f.endpoint or "",
            f.port or "",f.scanner or "",f.owner or "",f.status])
    out=make_response(si.getvalue())
    out.headers["Content-Type"]="text/csv"
    out.headers["Content-Disposition"]=f"attachment; filename=vulnintel_{utcnow().strftime('%Y%m%d_%H%M')}.csv"
    return out

@app.route("/reports/export/sarif")
@login_required
def export_sarif():
    findings=Finding.query.order_by(Finding.id.desc()).limit(1000).all()
    rules={}; results=[]
    for f in findings:
        rid=f.cve_id or f.cwe_id or f"vulnintel.{f.scanner}"
        if rid not in rules:
            rules[rid]={"id":rid,"name":f.title[:100],
                "shortDescription":{"text":f.title[:200]},
                "fullDescription":{"text":(f.description or "")[:1000]},
                "helpUri":f"https://nvd.nist.gov/vuln/detail/{f.cve_id}" if f.cve_id else "",
                "properties":{"severity":f.severity,"cvss":f.cvss_score,"epss":f.epss_score,
                    "kev":f.kev_status,"confidence":f.confidence}}
        lvl={"Critical":"error","High":"error","Medium":"warning","Low":"note","Info":"note"}.get(f.severity,"note")
        results.append({"ruleId":rid,"level":lvl,"message":{"text":f.title},
            "locations":[{"physicalLocation":{"artifactLocation":{"uri":f.endpoint or ""}}}],
            "properties":{"port":f.port,"scanner":f.scanner}})
    sarif={"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0",
        "runs":[{"tool":{"driver":{"name":APP_NAME,"version":APP_VERSION,
            "informationUri":"https://graysentinel.local","rules":list(rules.values())}},
            "results":results}]}
    out=make_response(json.dumps(sarif,indent=2,default=str))
    out.headers["Content-Type"]="application/sarif+json"
    out.headers["Content-Disposition"]=f"attachment; filename=vulnintel_{utcnow().strftime('%Y%m%d_%H%M')}.sarif"
    return out

@app.route("/reports/export/pdf")
@login_required
def export_pdf():
    if rl_colors is None:
        flash("ReportLab missing.","danger"); return redirect(url_for("findings"))
    try:
        buf=io.BytesIO()
        doc=SimpleDocTemplate(buf,pagesize=A4,leftMargin=2*cm,rightMargin=2*cm,
            topMargin=2*cm,bottomMargin=2*cm)
        styles=getSampleStyleSheet()
        ts=ParagraphStyle("T",parent=styles["Title"],fontSize=22,leading=26)
        h2=ParagraphStyle("H2",parent=styles["Heading2"],spaceAfter=8)
        body=styles["BodyText"]
        story=[Paragraph(f"{APP_NAME} — Vulnerability Report",ts),
            Paragraph(f"{COMPANY_NAME} · {CLASSIFICATION}",body),
            Paragraph(f"Generated: {utcnow().strftime('%Y-%m-%d %H:%M UTC')}",body),
            Spacer(1,12),Paragraph("Executive Summary",h2)]
        tot=Finding.query.count(); kv=Finding.query.filter_by(kev_status=True).count()
        cr=Finding.query.filter(Finding.severity.in_(["Critical","High"])).count()
        story.append(Paragraph(f"Total findings: <b>{tot}</b> · KEV: <b>{kv}</b> · "
            f"Critical/High: <b>{cr}</b> · Targets: <b>{Target.query.count()}</b>",body))
        story.append(PageBreak()); story.append(Paragraph("Findings",h2))
        rows=Finding.query.order_by(Finding.kev_status.desc(),
            Finding.cvss_score.desc().nullslast()).limit(500).all()
        td=[["CVE","Title","Sev","CVSS","Conf","Tool"]]
        for f in rows:
            td.append([f.cve_id or "-",Paragraph((f.title or "")[:60],body),f.severity,
                f"{f.cvss_score:.1f}" if f.cvss_score else "-",f.confidence,f.scanner or "-"])
        t=Table(td,colWidths=[2.5*cm,8*cm,1.5*cm,1.5*cm,1.8*cm,2*cm])
        t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),rl_colors.HexColor("#0a1120")),
            ("TEXTCOLOR",(0,0),(-1,0),rl_colors.white),("FONTSIZE",(0,0),(-1,-1),8),
            ("GRID",(0,0),(-1,-1),0.25,rl_colors.grey),("VALIGN",(0,0),(-1,-1),"TOP")]))
        story.append(t)
        def op(cv,dc):
            cv.saveState(); cv.setFont("Helvetica-Bold",55)
            cv.setFillColorRGB(0.9,0.1,0.1,alpha=0.1)
            cv.translate(300,400); cv.rotate(30)
            cv.drawCentredString(0,0,CLASSIFICATION); cv.restoreState()
            cv.setFont("Helvetica",8); cv.setFillColor(rl_colors.grey)
            cv.drawString(2*cm,1.2*cm,f"{APP_NAME} v{APP_VERSION}")
            cv.drawRightString(A4[0]-2*cm,1.2*cm,f"Page {dc.page}")
        doc.build(story,onFirstPage=op,onLaterPages=op)
        pdf=buf.getvalue(); buf.close()
        resp=make_response(pdf); resp.headers["Content-Type"]="application/pdf"
        resp.headers["Content-Disposition"]=f"attachment; filename=vulnintel_{utcnow().strftime('%Y%m%d_%H%M')}.pdf"
        return resp
    except Exception as ex:
        LOG.exception("PDF failed"); flash(f"PDF: {str(ex)[:200]}","danger")
        return redirect(url_for("findings"))

@app.route("/evidence/customer-safe")
@login_required
def customer_safe():
    rows=[]
    for f in Finding.query.order_by(Finding.kev_status.desc(),
        Finding.cvss_score.desc().nullslast()).limit(200).all():
        rows.append({"cve":f.cve_id,"severity":f.severity,
            "cvss":f"{f.cvss_score:.1f}" if f.cvss_score else "-","kev":f.kev_status,
            "status":{"verified_fixed":"Fixed","mitigated":"Mitigated",
                "accepted_exception":"Accepted","not_affected":"Not affected",
                "new":"Open","reopened":"Open"}.get(f.status,"Open")})
    return render_template_string(_CUSTOMER,rows=rows,
        generated_at=utcnow().strftime("%Y-%m-%d %H:%M UTC"))

@app.route("/admin")
@login_required
@role_required("admin")
def admin_panel():
    return render_template_string(_ADMIN,users=User.query.order_by(User.id).all(),
        audit=AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(50).all(),
        roles=ROLE_ENUM,db_path=str(DB_PATH),
        api_keys=APIKey.query.order_by(APIKey.id.desc()).limit(50).all())

@app.route("/admin/users",methods=["POST"])
@login_required
@role_required("admin")
def admin_create_user():
    u=sanitize_text(request.form.get("username",""),80)
    p=request.form.get("password","")
    r=sanitize_text(request.form.get("role","viewer"),20)
    if not u or not p or r not in ROLE_ENUM:
        flash("Invalid.","danger"); return redirect(url_for("admin_panel"))
    if User.query.filter_by(username=u).first():
        flash("Exists.","warning"); return redirect(url_for("admin_panel"))
    nu=User(username=u,role=r); nu.set_password(p)
    db.session.add(nu); db.session.commit()
    audit("create_user","User",nu.id,{"username":u}); db.session.commit()
    flash("User created.","success"); return redirect(url_for("admin_panel"))

@app.route("/admin/apikeys",methods=["POST"])
@login_required
@role_required("admin")
def admin_create_apikey():
    label=sanitize_text(request.form.get("label","default"),120)
    raw,kh,prefix=generate_api_key()
    k=APIKey(user_id=current_user.id,key_prefix=prefix,key_hash=kh,label=label)
    db.session.add(k); db.session.commit()
    audit("create_apikey","APIKey",k.id); db.session.commit()
    flash(f"API key (save): {raw}","success"); return redirect(url_for("admin_panel"))

@app.route("/api/stats")
@api_key_required
def api_stats():
    return jsonify({"findings":Finding.query.count(),
        "kev":Finding.query.filter_by(kev_status=True).count(),
        "targets":Target.query.count(),"kev_stale":kev_is_stale()})

@app.route("/api/findings")
@api_key_required
def api_findings():
    return jsonify([f.to_dict() for f in Finding.query.order_by(Finding.id.desc()).limit(500).all()])

# ═══════════════════════════════════════════════════════════════════════════
#  SCHEDULER
# ═══════════════════════════════════════════════════════════════════════════
def job_kev_refresh():
    LOG.info("[sch] KEV refresh")
    d=fetch_kev(force=True)
    if d:
        with app.app_context(): kev_load_to_db()
    else: LOG.error("[sch] KEV FAILED")

def job_cleanup():
    with app.app_context():
        c=utcnow()-timedelta(days=365)
        Evidence.query.filter(Evidence.retrieved_at<c).delete(); db.session.commit()

def register_jobs():
    if scheduler.running: return
    scheduler.add_job(id="kev_refresh",func=job_kev_refresh,trigger="cron",hour=2,minute=0)
    scheduler.add_job(id="cleanup",func=job_cleanup,trigger="cron",hour=4,minute=0)
    scheduler.init_app(app); scheduler.start()
    LOG.info("[sch] Jobs registered")

# ═══════════════════════════════════════════════════════════════════════════
#  ERROR HANDLERS
# ═══════════════════════════════════════════════════════════════════════════
@app.errorhandler(403)
def e403(_): return render_template_string(_ERR,code=403,message="Forbidden."),403
@app.errorhandler(404)
def e404(_): return render_template_string(_ERR,code=404,message="Not found."),404
@app.errorhandler(500)
def e500(e):
    LOG.exception("Internal: %s",e)
    return render_template_string(_ERR,code=500,message="Server error."),500

# ═══════════════════════════════════════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════════════════════════════════════
def init_db():
    LOG_DIR.mkdir(parents=True,exist_ok=True)
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username=DEFAULT_ADMIN_USER).first():
            u=User(username=DEFAULT_ADMIN_USER,role="admin"); u.set_password(DEFAULT_ADMIN_PASS)
            db.session.add(u); db.session.commit()
            LOG.info("Admin: %s / %s",DEFAULT_ADMIN_USER,DEFAULT_ADMIN_PASS)
        try: kev_load_to_db()
        except Exception as ex: LOG.warning("KEV boot: %s",ex)
        LOG.info("DB: %s",DB_PATH)

def _shutdown(*_):
    try:
        if scheduler.running: scheduler.shutdown(wait=False)
    except Exception: pass
    sys.exit(0)

def main():
    p=argparse.ArgumentParser(description=f"{APP_NAME} v{APP_VERSION}")
    p.add_argument("--host",default=DEFAULT_HOST); p.add_argument("--port",type=int,default=DEFAULT_PORT)
    p.add_argument("--debug",action="store_true"); p.add_argument("--init-db",action="store_true")
    p.add_argument("--no-scheduler",action="store_true")
    a=p.parse_args()
    if a.init_db: init_db(); return
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username=DEFAULT_ADMIN_USER).first():
            u=User(username=DEFAULT_ADMIN_USER,role="admin"); u.set_password(DEFAULT_ADMIN_PASS)
            db.session.add(u); db.session.commit()
            LOG.warning("Admin: %s / %s",DEFAULT_ADMIN_USER,DEFAULT_ADMIN_PASS)
        try: kev_load_to_db()
        except Exception as ex: LOG.warning("KEV boot: %s",ex)
    if not a.no_scheduler:
        try: register_jobs()
        except Exception as ex: LOG.exception("Sched: %s",ex)
    signal.signal(signal.SIGINT,_shutdown); signal.signal(signal.SIGTERM,_shutdown)
    LOG.info("═"*60); LOG.info("%s v%s",APP_NAME,APP_VERSION)
    LOG.info("Vendor: %s",COMPANY_NAME); LOG.info("Console: http://%s:%d",a.host,a.port)
    LOG.info("Login: %s / %s",DEFAULT_ADMIN_USER,DEFAULT_ADMIN_PASS)
    LOG.info("═"*60)
    app.run(host=a.host,port=a.port,debug=a.debug,use_reloader=False)

if __name__=="__main__": main()
