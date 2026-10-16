"""
OSINT Platform v2.0 — Backend FastAPI
Lancer : uvicorn main:app --reload --port 8000
"""

from fastapi import FastAPI, HTTPException, Response, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel
from typing import Optional, List
import httpx
import sqlite3
import json
import os
import re
import asyncio
import base64
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# ── Configuration ─────────────────────────────────────────────────────────────
APP_PASSWORD   = os.getenv("APP_PASSWORD", "")
PREMIUM_ENABLED = os.getenv("PREMIUM_ENABLED", "false").lower() == "true"
GROQ_KEY       = os.getenv("GROQ_API_KEY", "")
PAPPERS_KEY    = os.getenv("PAPPERS_API_KEY", "")
HIBP_KEY       = os.getenv("HIBP_API_KEY", "")
VT_KEY         = os.getenv("VIRUSTOTAL_API_KEY", "")
IPINFO_KEY     = os.getenv("IPINFO_TOKEN", "")
ABUSEIPDB_KEY  = os.getenv("ABUSEIPDB_API_KEY", "")
OTX_KEY        = os.getenv("OTX_API_KEY", "")
HUNTER_KEY     = os.getenv("HUNTER_API_KEY", "")
SHODAN_KEY     = os.getenv("SHODAN_API_KEY", "")
DB_PATH        = os.getenv("DB_PATH", "osint.db")

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(title="OSINT Platform", version="2.0.0", docs_url="/api/docs")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class BasicAuthMiddleware(BaseHTTPMiddleware):
    """Protège toute l'app par un mot de passe unique si APP_PASSWORD est défini."""
    async def dispatch(self, request: Request, call_next):
        if not APP_PASSWORD:
            return await call_next(request)
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("basic "):
            try:
                decoded = base64.b64decode(auth.split(" ", 1)[1]).decode("utf-8")
                _, _, password = decoded.partition(":")
                if secrets.compare_digest(password, APP_PASSWORD):
                    return await call_next(request)
            except Exception:
                pass
        return Response(status_code=401, headers={"WWW-Authenticate": 'Basic realm="OSINT Platform"'})

app.add_middleware(BasicAuthMiddleware)

# ── Rate limiting ────────────────────────────────────────────────────────────
RATE_LIMIT   = 60   # requêtes
RATE_WINDOW  = 60   # secondes
_rate_buckets: dict = defaultdict(deque)

class RateLimitMiddleware(BaseHTTPMiddleware):
    """Limite chaque IP à RATE_LIMIT requêtes /api/* par fenêtre de RATE_WINDOW secondes."""
    async def dispatch(self, request: Request, call_next):
        if request.url.path.startswith("/api/"):
            ip = request.client.host if request.client else "unknown"
            now = time.time()
            bucket = _rate_buckets[ip]
            while bucket and now - bucket[0] > RATE_WINDOW:
                bucket.popleft()
            if len(bucket) >= RATE_LIMIT:
                return Response(
                    content='{"detail":"Trop de requêtes — réessayez dans une minute."}',
                    status_code=429, media_type="application/json",
                )
            bucket.append(now)
        return await call_next(request)

app.add_middleware(RateLimitMiddleware)

# ── Database ──────────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS cases (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT NOT NULL,
            status     TEXT DEFAULT 'En cours',
            risk       INTEGER DEFAULT 0,
            notes      TEXT DEFAULT '',
            timeline   TEXT DEFAULT '[]',
            created_at TEXT,
            updated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS history (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            query      TEXT,
            mode       TEXT,
            mode_label TEXT,
            mode_icon  TEXT,
            risk       INTEGER DEFAULT 0,
            summary    TEXT,
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS waitlist (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            email      TEXT NOT NULL UNIQUE,
            created_at TEXT
        );
    """)
    conn.commit()
    conn.close()

init_db()

# ── Pydantic models ───────────────────────────────────────────────────────────
class ReportRequest(BaseModel):
    query: str
    mode: str
    ctx: Optional[str] = ""

class BatchRequest(BaseModel):
    targets: List[str]
    mode: str

class UsernameRequest(BaseModel):
    username: str

class CaseCreate(BaseModel):
    name: str
    notes: Optional[str] = ""

class CaseUpdate(BaseModel):
    status:   Optional[str]  = None
    risk:     Optional[int]  = None
    notes:    Optional[str]  = None
    timeline: Optional[list] = None

class PDFRequest(BaseModel):
    report:     dict
    mode_label: Optional[str] = "Investigation"

class WaitlistRequest(BaseModel):
    email: str

# ── Helpers ───────────────────────────────────────────────────────────────────
def detect_query_type(q: str) -> str:
    s = q.strip()
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', s):                              return 'ip'
    if re.search(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', s):   return 'email'
    if re.match(r'^\d{9}$', s.replace(' ', '').replace('.', '')):             return 'siren'
    if re.match(r'^[a-zA-Z0-9\-]+(\.[a-zA-Z]{2,})+$', s) and ' ' not in s:  return 'domain'
    return 'name'

def clean_json(raw: str) -> dict:
    raw = raw.strip()
    m = re.search(r'\{.*\}', raw, re.DOTALL)
    if m:
        raw = m.group(0)
    return json.loads(raw)

PDF_CHAR_MAP = {
    "—": "-", "–": "-", "’": "'", "‘": "'", "“": '"', "”": '"', "…": "...",
    "✓": "[OK]", "🚩": "[!]", "☑": "[x]", "☐": "[ ]",
}

def pdf_safe(text: str) -> str:
    """Rend un texte compatible avec la police latin-1 (Helvetica) utilisée par fpdf2."""
    if not text:
        return text
    for k, v in PDF_CHAR_MAP.items():
        text = text.replace(k, v)
    return text.encode("latin-1", errors="replace").decode("latin-1")

# ── AI Prompts ────────────────────────────────────────────────────────────────
def build_prompt(mode: str, query: str, ctx: str = "", real_data: str = "") -> str:
    q  = query.replace('"', '\\"')
    qe = q.replace(' ', '%20')
    base = f'Cible: "{q}"' + (f', contexte: "{ctx}"' if ctx else "")
    if real_data:
        base += (
            f'\n\nDONNÉES RÉELLES COLLECTÉES (sources publiques interrogées automatiquement) :\n{real_data}\n\n'
            "Base ton analyse UNIQUEMENT sur ces données réelles quand elles sont disponibles. "
            "N'invente aucun fait, SIREN, société ou fuite de données qui n'est pas listé ci-dessus. "
            "Si les données réelles ne contiennent rien d'exploitable pour un champ, dis-le explicitement "
            "('aucune donnée publique trouvée') plutôt que d'inventer un exemple."
        )
    rule = (
        "RÈGLES ABSOLUES: Tu es expert OSINT senior. "
        "JSON valide UNIQUEMENT — aucun texte avant/après, aucun bloc markdown. "
        "Zéro disclaimer sur internet. Signaux réalistes et actionnables, fondés sur les données réelles fournies."
    )
    graph = (
        f'"graph":{{"nodes":['
        f'{{"id":"n0","label":"{q}","type":"person","detail":"cible principale"}},'
        f'{{"id":"n1","label":"société ex","type":"company","detail":"à identifier"}},'
        f'{{"id":"n2","label":"email@ex.com","type":"email","detail":"à identifier"}},'
        f'{{"id":"n3","label":"LinkedIn","type":"social","detail":"à vérifier"}},'
        f'{{"id":"n4","label":"France","type":"location","detail":"localisation"}}'
        f'],"edges":['
        f'{{"source":"n0","target":"n1","label":"liée à"}},'
        f'{{"source":"n0","target":"n2","label":"utilise"}},'
        f'{{"source":"n0","target":"n3","label":"présent sur"}},'
        f'{{"source":"n1","target":"n4","label":"basée en"}}'
        f']}}'
    )

    if mode == "investigation":
        return f"""{rule} {base}. Retourne ce JSON exact:
{{"target":"{q}","type":"person","executive_summary":"synthèse opérationnelle 2-3 phrases","identity":{{"possible_names":["{q}"],"aliases":["alias éventuel"],"age_range":"tranche estimée","locations":["France"],"summary":"analyse identité 2 phrases"}},"digital_footprint":{{"social_profiles":[{{"platform":"LinkedIn","likely":true,"url":"https://linkedin.com/search/results/people/?keywords={qe}","signals":["profil probable"]}},{{"platform":"Twitter","likely":false,"url":"https://twitter.com/search?q={qe}","signals":["à vérifier"]}}],"web_presence":"synthèse présence web","summary":"synthèse empreinte numérique"}},"records":{{"pappers_url":"https://www.pappers.fr/recherche?q={qe}","companies":[{{"name":"ex société","role":"Président","status":"Active","siren":"XXX XXX XXX","creation":"2018","address":"Paris"}}],"summary":"synthèse registres"}},"google_dorks":[{{"query":"\\"{q}\\"","url":"https://google.com/search?q=%22{qe}%22","purpose":"Recherche générale"}},{{"query":"\\"{q}\\" site:linkedin.com","url":"https://google.com/search?q=%22{qe}%22+site%3Alinkedin.com","purpose":"Profil LinkedIn"}},{{"query":"\\"{q}\\" arnaque OR fraude","url":"https://google.com/search?q=%22{qe}%22+arnaque+OR+fraude","purpose":"Signalements fraude"}},{{"query":"\\"{q}\\" tribunal OR condamné","url":"https://google.com/search?q=%22{qe}%22+tribunal","purpose":"Antécédents"}},{{"query":"\\"{q}\\" filetype:pdf","url":"https://google.com/search?q=%22{qe}%22+filetype%3Apdf","purpose":"Documents officiels"}}],"risk":{{"score":28,"level":"low","flags":["point à vérifier"],"positive":["aucun signalement négatif"],"summary":"profil à risque faible selon sources publiques"}},"timeline":[{{"date":"2020","event":"Activité détectée"}}],{graph},"conclusion":"conclusion investigation 2 phrases"}}"""

    if mode == "particulier":
        return f"""{rule} {base}. Retourne ce JSON:
{{"target":"{q}","type":"person","executive_summary":"synthèse claire 2-3 phrases","quick_checks":[{{"label":"Existence vérifiable","result":"incertain","detail":"explication simple"}},{{"label":"Présence réseaux sociaux","result":"incertain","detail":"explication"}},{{"label":"Signalements négatifs","result":"non","detail":"aucun trouvé"}},{{"label":"Cohérence des infos","result":"incertain","detail":"à vérifier"}}],"risk":{{"score":18,"level":"low","verdict":"Profil normal, aucun signalement notable"}},"advice":["Faites une recherche Google avec le nom entre guillemets","Vérifiez ses profils réseaux sociaux","Cherchez des avis ou témoignages en ligne"],"social_media":[{{"platform":"Facebook","url":"https://www.facebook.com/search/people/?q={qe}","icon":"📘"}},{{"platform":"LinkedIn","url":"https://linkedin.com/search/results/people/?keywords={qe}","icon":"💼"}},{{"platform":"Instagram","url":"https://www.instagram.com/{qe}/","icon":"📸"}},{{"platform":"Twitter/X","url":"https://twitter.com/search?q={qe}","icon":"🐦"}}],"google_dorks":[{{"query":"\\"{q}\\"","url":"https://google.com/search?q=%22{qe}%22","purpose":"Recherche générale"}},{{"query":"\\"{q}\\" arnaque OR fraude","url":"https://google.com/search?q=%22{qe}%22+arnaque+OR+fraude","purpose":"Signalements arnaque"}},{{"query":"\\"{q}\\" site:leboncoin.fr","url":"https://google.com/search?q=%22{qe}%22+site%3Aleboncoin.fr","purpose":"Présence Leboncoin"}}],{graph},"conclusion":"conclusion simple 2 phrases"}}"""

    if mode == "entreprise":
        return f"""{rule} {base}. Retourne ce JSON:
{{"target":"{q}","type":"company","executive_summary":"synthèse due diligence 2-3 phrases","legal_identity":{{"legal_name":"{q}","legal_form":"SAS","siren":"À vérifier Pappers","creation_year":"À vérifier","hq_location":"France","activity":"À identifier","summary":"synthèse identité légale"}},"registries":{{"pappers_url":"https://pappers.fr/recherche?q={qe}","management":[{{"name":"Dirigeant à identifier","role":"Président","other_mandates":0}}],"financial_signals":["Bilan à consulter Infogreffe"],"red_flags":[],"summary":"synthèse registres légaux"}},"google_dorks":[{{"query":"\\"{q}\\" avis OR arnaque","url":"https://google.com/search?q=%22{qe}%22+avis+OR+arnaque","purpose":"Avis et signalements"}},{{"query":"\\"{q}\\" liquidation OR redressement","url":"https://google.com/search?q=%22{qe}%22+liquidation","purpose":"Difficultés financières"}},{{"query":"\\"{q}\\" site:pappers.fr","url":"https://google.com/search?q=%22{qe}%22+site%3Apappers.fr","purpose":"Registre Pappers"}},{{"query":"\\"{q}\\" tribunal commerce","url":"https://google.com/search?q=%22{qe}%22+tribunal+commerce","purpose":"Procédures judiciaires"}}],"risk":{{"score":22,"level":"low","flags":[],"positive":["Société enregistrée légalement"],"summary":"synthèse risque due diligence"}},{graph},"conclusion":"conclusion due diligence 2 phrases"}}"""

    if mode == "recrutement":
        return f"""{rule} {base}. Retourne ce JSON:
{{"target":"{q}","type":"person","executive_summary":"synthèse RH 2-3 phrases","identity":{{"full_name":"{q}","aliases":[],"locations":["France"],"summary":"synthèse identité"}},"professional":{{"linkedin_url":"https://linkedin.com/search/results/people/?keywords={qe}","career_signals":["Parcours à vérifier LinkedIn","Compétences à recouper"],"education_signals":["Diplômes à vérifier"],"summary":"synthèse profil professionnel"}},"legal_records":{{"pappers_url":"https://pappers.fr/recherche?q={qe}","companies":[],"judicial_signals":[],"summary":"Aucun antécédent dans les sources publiques"}},"checklist":[{{"item":"Identité vérifiée","done":false}},{{"item":"Pappers vérifié","done":false}},{{"item":"LinkedIn cohérent","done":false}},{{"item":"Diplômes vérifiés","done":false}},{{"item":"Casier judiciaire (B3)","done":false}},{{"item":"Références contactées","done":false}}],"google_dorks":[{{"query":"\\"{q}\\" site:linkedin.com","url":"https://google.com/search?q=%22{qe}%22+site%3Alinkedin.com","purpose":"Profil LinkedIn"}},{{"query":"\\"{q}\\" diplôme OR certification","url":"https://google.com/search?q=%22{qe}%22+dipl%C3%B4me","purpose":"Diplômes"}},{{"query":"\\"{q}\\" tribunal OR fraude","url":"https://google.com/search?q=%22{qe}%22+tribunal","purpose":"Antécédents"}}],"risk":{{"score":15,"level":"low","flags":[],"positive":["Profil à confirmer"],"summary":"synthèse risque candidat"}},{graph},"conclusion":"conclusion RH 2 phrases"}}"""

    return build_prompt("investigation", query, ctx, real_data)

# ── AI Report ─────────────────────────────────────────────────────────────────
async def ai_generate(query: str, mode: str, ctx: str = "") -> dict:
    if not PREMIUM_ENABLED:
        raise HTTPException(402, detail="Le rapport IA est une fonctionnalité Premium.")
    if not GROQ_KEY:
        raise HTTPException(400, detail="GROQ_API_KEY manquante dans .env")
    qt, real_results = await gather_real_data(query)
    real_data = summarize_real_data(qt, real_results)
    prompt = build_prompt(mode, query, ctx, real_data)
    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {GROQ_KEY}"},
            json={
                "model": "openai/gpt-oss-120b",
                "max_tokens": 2000,
                "response_format": {"type": "json_object"},
                "messages": [
                    {"role": "system", "content": (
                        "Tu es un expert OSINT senior. "
                        "Tu réponds TOUJOURS et UNIQUEMENT en JSON valide. "
                        "Aucun texte avant ou après. Aucun bloc markdown. Aucun backtick."
                    )},
                    {"role": "user", "content": prompt},
                ],
            },
        )
        r.raise_for_status()
        data = r.json()
    return clean_json(data["choices"][0]["message"]["content"])

# ── Routes : Report & Batch ───────────────────────────────────────────────────
@app.post("/api/report")
async def api_report(req: ReportRequest):
    report = await ai_generate(req.query, req.mode, req.ctx or "")
    mode_meta = {
        "investigation": ("Investigation", "🔍"),
        "particulier":   ("Particulier",   "👤"),
        "entreprise":    ("Entreprise",    "🏢"),
        "recrutement":   ("Recrutement",   "💼"),
    }
    label, icon = mode_meta.get(req.mode, ("Analyse", "🔭"))
    conn = get_db()
    conn.execute(
        "INSERT INTO history (query,mode,mode_label,mode_icon,risk,summary,created_at) VALUES (?,?,?,?,?,?,?)",
        (req.query, req.mode, label, icon,
         report.get("risk", {}).get("score", 0),
         (report.get("executive_summary") or "")[:200],
         datetime.now().isoformat())
    )
    conn.commit(); conn.close()
    return report

@app.post("/api/batch")
async def api_batch(req: BatchRequest):
    async def one(target: str):
        try:
            r = await ai_generate(target, req.mode)
            mode_meta = {"investigation":("Investigation","🔍"),"particulier":("Particulier","👤"),"entreprise":("Entreprise","🏢"),"recrutement":("Recrutement","💼")}
            label, icon = mode_meta.get(req.mode, ("Analyse","🔭"))
            conn = get_db()
            conn.execute("INSERT INTO history (query,mode,mode_label,mode_icon,risk,summary,created_at) VALUES (?,?,?,?,?,?,?)",
                (target, req.mode, label, icon, r.get("risk",{}).get("score",0), (r.get("executive_summary") or "")[:150], datetime.now().isoformat()))
            conn.commit(); conn.close()
            return {"query": target, "status": "done", "report": r}
        except Exception as e:
            return {"query": target, "status": "error", "error": str(e)}
    results = await asyncio.gather(*[one(t) for t in req.targets[:10]])
    return {"results": list(results)}

# ── Routes : APIs externes ────────────────────────────────────────────────────
@app.get("/api/config")
def api_config():
    return {
        "premium":    PREMIUM_ENABLED,
        "groq":       bool(GROQ_KEY),
        "pappers":    bool(PAPPERS_KEY),
        "hibp":       bool(HIBP_KEY),
        "virustotal": bool(VT_KEY),
        "ipinfo":     bool(IPINFO_KEY),
        "abuseipdb":  bool(ABUSEIPDB_KEY),
        "otx":        bool(OTX_KEY),
        "hunter":     bool(HUNTER_KEY),
        "shodan":     bool(SHODAN_KEY),
    }

ANALYZE_CACHE_TTL = 3600  # secondes
_analyze_cache: dict = {}

async def run_analyze_tasks(qt: str, q: str) -> dict:
    """Interroge toutes les APIs publiques pertinentes selon le type de cible."""
    tasks: dict = {}

    if qt in ('name', 'siren', 'domain'):
        tasks['annuaire']      = _fetch("https://recherche-entreprises.api.gouv.fr/search", {"q": q, "per_page": 5})
        tasks['bodacc']        = _fetch("https://bodacc-datadila.opendatasoft.com/api/explore/v2.1/catalog/datasets/annonces-commerciales/records", {"q": q, "limit": 5, "order_by": "dateparution desc"})
        tasks['opensanctions'] = _fetch("https://api.opensanctions.org/search/default", {"q": q, "limit": 5})
        if PAPPERS_KEY:
            tasks['pappers'] = _fetch("https://api.pappers.fr/v2/recherche", {"api_token": PAPPERS_KEY, "q": q, "nombre": 5})

    if qt == 'email':
        if HIBP_KEY:
            tasks['hibp'] = _fetch_hibp(q)
        if HUNTER_KEY:
            tasks['hunter'] = _fetch("https://api.hunter.io/v2/email-verifier", {"email": q, "api_key": HUNTER_KEY})

    if qt in ('ip', 'domain'):
        tasks['urlscan'] = _fetch("https://urlscan.io/api/v1/search/", {"q": q, "size": 5})
        if VT_KEY:
            resource = f"ip_addresses/{q}" if qt == 'ip' else f"domains/{q}"
            tasks['virustotal'] = _fetch_vt(resource, VT_KEY)
        if qt == 'domain':
            tasks['crtsh'] = _fetch("https://crt.sh/", {"q": f"%.{q}", "output": "json"})
            tasks['rdap']  = _fetch(f"https://rdap.org/domain/{q}")
        if qt == 'ip':
            tasks['ipapi'] = _fetch(f"http://ip-api.com/json/{q}")
            if IPINFO_KEY:
                tasks['ipinfo'] = _fetch(f"https://ipinfo.io/{q}", {"token": IPINFO_KEY})
            if ABUSEIPDB_KEY:
                tasks['abuseipdb'] = _fetch_abuse(q, ABUSEIPDB_KEY)
        if SHODAN_KEY:
            url = f"https://api.shodan.io/shodan/host/{q}" if qt=='ip' else "https://api.shodan.io/shodan/host/search"
            params = {"key": SHODAN_KEY} if qt=='ip' else {"key": SHODAN_KEY, "query": q}
            tasks['shodan'] = _fetch(url, params)
        if OTX_KEY:
            ind = "IPv4" if qt=='ip' else "domain"
            tasks['otx'] = _fetch(f"https://otx.alienvault.com/api/v1/indicators/{ind}/{q}/general", {}, {"X-OTX-API-KEY": OTX_KEY})

    results = {}
    async def run(name, coro):
        try:    results[name] = await coro
        except Exception as e: results[name] = {"error": str(e)}
    await asyncio.gather(*[run(n, c) for n, c in tasks.items()])
    return results

async def gather_real_data(q: str) -> tuple:
    """Version mise en cache (TTL) de la collecte multi-APIs, partagée par /api/analyze et le rapport IA."""
    key = q.strip().lower()
    now = time.time()
    cached = _analyze_cache.get(key)
    if cached and now - cached[0] < ANALYZE_CACHE_TTL:
        return cached[1], cached[2]
    qt = detect_query_type(q)
    results = await run_analyze_tasks(qt, q)
    _analyze_cache[key] = (now, qt, results)
    return qt, results

def summarize_real_data(qt: str, results: dict) -> str:
    """Condense les résultats des APIs publiques en quelques lignes exploitables par le LLM."""
    lines = [f"Type de cible détecté : {qt}"]
    for key, v in results.items():
        if not isinstance(v, dict) or v.get("error"):
            continue
        try:
            if key == 'annuaire' and v.get('results'):
                r = v['results'][0]
                lines.append(f"- Annuaire Entreprises : {len(v['results'])} résultat(s), ex. {r.get('nom_complet') or r.get('nom_raison_sociale')} (SIREN {r.get('siren')})")
            elif key == 'pappers' and v.get('resultats'):
                r = v['resultats'][0]
                lines.append(f"- Pappers : {len(v['resultats'])} résultat(s), ex. {r.get('nom_entreprise') or r.get('denomination')} (SIREN {r.get('siren')})")
            elif key == 'bodacc' and v.get('results'):
                r = v['results'][0]
                lines.append(f"- BODACC : {len(v['results'])} annonce(s), ex. {r.get('commercant')} ({r.get('familleavis_lib')}, {r.get('dateparution')})")
            elif key == 'opensanctions' and v.get('results'):
                lines.append(f"- OpenSanctions : {len(v['results'])} correspondance(s) potentielle(s) sur listes de sanctions/PEP")
            elif key == 'hibp':
                if v.get('clean'):
                    lines.append("- Have I Been Pwned : aucune fuite de données connue")
                else:
                    noms = ", ".join(b.get('Title') or b.get('Name','') for b in v.get('breaches', [])[:5])
                    lines.append(f"- Have I Been Pwned : {len(v.get('breaches',[]))} fuite(s) de données ({noms})")
            elif key == 'urlscan' and v.get('results'):
                lines.append(f"- URLScan.io : {v.get('total', len(v['results']))} scan(s) référencé(s)")
            elif key == 'virustotal' and v.get('data', {}).get('attributes', {}).get('last_analysis_stats'):
                stats = v['data']['attributes']['last_analysis_stats']
                bad = (stats.get('malicious',0) + stats.get('suspicious',0))
                lines.append(f"- VirusTotal : {bad} moteur(s) signalent cette cible comme malveillante/suspecte" if bad else "- VirusTotal : aucune détection malveillante")
            elif key == 'ipapi' and v.get('status') == 'success':
                lines.append(f"- Géolocalisation IP : {v.get('city')}, {v.get('country')} — {v.get('isp') or v.get('org')}")
            elif key == 'abuseipdb' and v.get('data'):
                score = v['data'].get('abuseConfidenceScore', 0)
                lines.append(f"- AbuseIPDB : score d'abus {score}%" if score else "- AbuseIPDB : aucun signalement")
            elif key == 'shodan':
                matches = v.get('data') or v.get('matches') or []
                if matches:
                    lines.append(f"- Shodan : {len(matches)} service(s) exposé(s)")
            elif key == 'otx' and v.get('pulse_info', {}).get('count'):
                lines.append(f"- AlienVault OTX : référencé dans {v['pulse_info']['count']} pulse(s) de threat intelligence")
            elif key == 'crtsh' and isinstance(v, list) and v:
                subs = {n.strip() for c in v for n in (c.get('name_value') or '').split('\n')}
                lines.append(f"- Certificats SSL (crt.sh) : {len(subs)} sous-domaine(s) unique(s) détecté(s)")
            elif key == 'rdap' and v.get('ldhName'):
                lines.append(f"- WHOIS (RDAP) : domaine {v['ldhName']} — statut {', '.join(v.get('status', []))}")
        except Exception:
            continue
    return "\n".join(lines) if len(lines) > 1 else f"Type de cible détecté : {qt}\nAucune donnée publique exploitable trouvée pour cette cible."

@app.get("/api/analyze")
async def api_analyze_all(q: str):
    """Lance toutes les APIs pertinentes selon le type de cible (mis en cache 1h)."""
    qt, results = await gather_real_data(q)
    return {"query_type": qt, "results": results}

# helpers bas niveau
async def _fetch(url: str, params: dict = {}, headers: dict = {}):
    async with httpx.AsyncClient(timeout=12, follow_redirects=True) as c:
        r = await c.get(url, params=params, headers=headers)
        r.raise_for_status()
        return r.json()

async def _fetch_hibp(email: str):
    async with httpx.AsyncClient(timeout=12) as c:
        r = await c.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                        headers={"hibp-api-key": HIBP_KEY, "user-agent": "OSINT-Platform"})
        if r.status_code == 404: return {"breaches": [], "clean": True}
        r.raise_for_status()
        return {"breaches": r.json(), "clean": False}

async def _fetch_vt(resource: str, key: str):
    async with httpx.AsyncClient(timeout=12) as c:
        r = await c.get(f"https://www.virustotal.com/api/v3/{resource}", headers={"x-apikey": key})
        r.raise_for_status()
        return r.json()

async def _fetch_abuse(ip: str, key: str):
    async with httpx.AsyncClient(timeout=12) as c:
        r = await c.get("https://api.abuseipdb.com/api/v2/check",
                        params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": "true"},
                        headers={"Key": key, "Accept": "application/json"})
        r.raise_for_status()
        return r.json()

@app.get("/api/pappers/detail")
async def pappers_detail(siren: str):
    if not PAPPERS_KEY: return {"error": "PAPPERS_API_KEY manquante"}
    return await _fetch("https://api.pappers.fr/v2/entreprise", {"api_token": PAPPERS_KEY, "siren": siren.replace(" ","")})

# ── Username Checker ──────────────────────────────────────────────────────────
PLATFORMS = [
    {"name":"GitHub",       "url":"https://github.com/{u}",                           "api":"https://api.github.com/users/{u}"},
    {"name":"Reddit",       "url":"https://reddit.com/user/{u}",                      "api":"https://www.reddit.com/user/{u}/about.json"},
    {"name":"Twitter/X",    "url":"https://twitter.com/{u}"},
    {"name":"Instagram",    "url":"https://instagram.com/{u}"},
    {"name":"LinkedIn",     "url":"https://linkedin.com/in/{u}"},
    {"name":"TikTok",       "url":"https://tiktok.com/@{u}"},
    {"name":"YouTube",      "url":"https://youtube.com/@{u}"},
    {"name":"Twitch",       "url":"https://twitch.tv/{u}"},
    {"name":"Steam",        "url":"https://steamcommunity.com/id/{u}"},
    {"name":"Medium",       "url":"https://medium.com/@{u}"},
    {"name":"Tumblr",       "url":"https://{u}.tumblr.com"},
    {"name":"Telegram",     "url":"https://t.me/{u}"},
    {"name":"Pinterest",    "url":"https://pinterest.com/{u}"},
    {"name":"Dribbble",     "url":"https://dribbble.com/{u}"},
    {"name":"Behance",      "url":"https://behance.net/{u}"},
    {"name":"Patreon",      "url":"https://patreon.com/{u}"},
    {"name":"Substack",     "url":"https://{u}.substack.com"},
    {"name":"Spotify",      "url":"https://open.spotify.com/user/{u}"},
    {"name":"SoundCloud",   "url":"https://soundcloud.com/{u}"},
    {"name":"Last.fm",      "url":"https://last.fm/user/{u}"},
    {"name":"GitLab",       "url":"https://gitlab.com/{u}"},
    {"name":"Stackoverflow","url":"https://stackoverflow.com/users/{u}"},
    {"name":"Keybase",      "url":"https://keybase.io/{u}"},
    {"name":"npm",          "url":"https://npmjs.com/~{u}"},
    {"name":"PyPI",         "url":"https://pypi.org/user/{u}"},
    {"name":"CodePen",      "url":"https://codepen.io/{u}"},
    {"name":"Replit",       "url":"https://replit.com/@{u}"},
    {"name":"Hackthebox",   "url":"https://app.hackthebox.com/profile/{u}"},
    {"name":"TryHackMe",    "url":"https://tryhackme.com/p/{u}"},
    {"name":"Goodreads",    "url":"https://goodreads.com/{u}"},
    {"name":"Letterboxd",   "url":"https://letterboxd.com/{u}"},
    {"name":"About.me",     "url":"https://about.me/{u}"},
    {"name":"Linktree",     "url":"https://linktr.ee/{u}"},
    {"name":"Gravatar",     "url":"https://gravatar.com/{u}"},
    {"name":"Ko-fi",        "url":"https://ko-fi.com/{u}"},
    {"name":"Vk",           "url":"https://vk.com/{u}"},
    {"name":"Quora",        "url":"https://quora.com/profile/{u}"},
    {"name":"Flickr",       "url":"https://flickr.com/people/{u}"},
    {"name":"Vimeo",        "url":"https://vimeo.com/{u}"},
    {"name":"Mastodon",     "url":"https://mastodon.social/@{u}"},
    {"name":"Snapchat",     "url":"https://snapchat.com/add/{u}"},
    {"name":"DeviantArt",   "url":"https://{u}.deviantart.com"},
    {"name":"Product Hunt", "url":"https://producthunt.com/@{u}"},
    {"name":"Wattpad",      "url":"https://wattpad.com/user/{u}"},
    {"name":"Hackernews",   "url":"https://news.ycombinator.com/user?id={u}"},
    {"name":"500px",        "url":"https://500px.com/p/{u}"},
    {"name":"Xing",         "url":"https://xing.com/profile/{u}"},
    {"name":"Dailymotion",  "url":"https://dailymotion.com/{u}"},
    {"name":"Discord",      "url":"https://discord.com/users/{u}"},
    {"name":"Patreon",      "url":"https://patreon.com/{u}"},
]

@app.post("/api/username")
async def api_username(req: UsernameRequest):
    u = req.username.strip()
    api_platforms = [p for p in PLATFORMS if "api" in p]
    results = {}

    async def check(p):
        try:
            url = p["api"].replace("{u}", u)
            async with httpx.AsyncClient(timeout=8, follow_redirects=True) as c:
                r = await c.get(url, headers={"User-Agent": "Mozilla/5.0 OSINT-Platform/2.0"})
                results[p["name"]] = "found" if r.status_code == 200 else "notfound"
        except:
            results[p["name"]] = "unknown"

    await asyncio.gather(*[check(p) for p in api_platforms])
    links = [{"name": p["name"], "url": p["url"].replace("{u}", u)} for p in PLATFORMS]
    return {"api_results": results, "links": links, "total": len(links)}

# ── PDF Export (fpdf2) ────────────────────────────────────────────────────────
@app.post("/api/export/pdf")
async def export_pdf(req: PDFRequest):
    if not PREMIUM_ENABLED:
        raise HTTPException(402, detail="L'export PDF est une fonctionnalité Premium.")
    try:
        from fpdf import FPDF
    except ImportError:
        raise HTTPException(500, detail="fpdf2 non installé. Lancez: pip install fpdf2")

    report     = req.report
    mode_label = req.mode_label
    score      = report.get("risk", {}).get("score", 0)
    risk_col   = (34, 197, 94) if score < 30 else (245, 158, 11) if score < 60 else (239, 68, 68)
    risk_txt   = "FAIBLE" if score < 30 else "MOYEN" if score < 60 else "ÉLEVÉ"

    pdf = FPDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Header band
    pdf.set_fill_color(11, 12, 15)
    pdf.rect(0, 0, 210, 28, "F")
    pdf.set_font("Helvetica", "B", 15)
    pdf.set_text_color(91, 124, 250)
    pdf.cell(0, 10, "OSINT PLATFORM", ln=False, align="C")
    pdf.ln(8)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_text_color(139, 141, 150)
    ts = datetime.now().strftime("%d/%m/%Y %H:%M")
    pdf.cell(0, 6, pdf_safe(f"Rapport {mode_label}  |  Confidentiel  |  {ts}"), ln=True, align="C")
    pdf.ln(8)

    # Target title
    pdf.set_font("Helvetica", "B", 17)
    pdf.set_text_color(30, 35, 50)
    pdf.cell(0, 10, pdf_safe(str(report.get("target", ""))[:60]), ln=True)

    # Risk badge
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(*risk_col)
    pdf.cell(0, 7, pdf_safe(f"Score de risque : {score}/100  —  {risk_txt}"), ln=True)
    pdf.ln(4)

    def h2(title: str):
        pdf.set_fill_color(240, 243, 248)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(50, 55, 70)
        pdf.cell(0, 7, pdf_safe(f"  {title}"), ln=True, fill=True)
        pdf.ln(1)

    def body(text: str, indent: int = 5):
        if not text: return
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(60, 65, 80)
        pdf.set_x(10 + indent)
        pdf.multi_cell(0, 5, pdf_safe(str(text)[:600]))
        pdf.ln(1)

    def bullet(text: str, col=(60,65,80)):
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(*col)
        pdf.set_x(14)
        pdf.multi_cell(0, 5, pdf_safe(f"- {text}"))

    # Sections
    h2("SYNTHÈSE EXÉCUTIVE")
    body(report.get("executive_summary", ""))

    ident = report.get("identity") or report.get("legal_identity")
    if ident:
        h2("IDENTITÉ")
        body(ident.get("summary", ""))
        if ident.get("locations"):
            bullet("Localisations : " + ", ".join(ident["locations"]))
        if ident.get("aliases"):
            bullet("Alias : " + ", ".join(ident["aliases"]))

    rec = report.get("records") or report.get("registries") or report.get("legal_records")
    if rec:
        h2("REGISTRES LÉGAUX")
        body(rec.get("summary", ""))
        for co in rec.get("companies", []):
            bullet(f"{co.get('name','')} — {co.get('role','')} ({co.get('status','')}){' ['+co['siren']+']' if co.get('siren') else ''}")

    if report.get("professional"):
        h2("PROFIL PROFESSIONNEL")
        body(report["professional"].get("summary", ""))
        for s in report["professional"].get("career_signals", []):
            bullet(s)

    if report.get("risk"):
        h2("ÉVALUATION DES RISQUES")
        body(report["risk"].get("summary", ""))
        for f in report["risk"].get("flags", []):
            if f: bullet(f"🚩 {f}", (200, 80, 40))
        for p in report["risk"].get("positive", []):
            bullet(f"✓ {p}", (40, 150, 80))

    if report.get("google_dorks"):
        h2("GOOGLE DORKS")
        for d in report["google_dorks"]:
            bullet(f"{d.get('purpose','')}: {d.get('query','')}")

    if report.get("checklist"):
        h2("CHECKLIST VÉRIFICATION")
        for item in report["checklist"]:
            chk = "☑" if item.get("done") else "☐"
            bullet(f"{chk} {item.get('item','')}")

    h2("CONCLUSION")
    body(report.get("conclusion") or report.get("risk", {}).get("verdict", ""))

    # Footer
    pdf.set_y(-18)
    pdf.set_font("Helvetica", "", 7)
    pdf.set_text_color(150, 155, 165)
    pdf.cell(0, 5, pdf_safe("Sources publiques uniquement  |  Respectez le RGPD  |  Document confidentiel — ne pas diffuser"), align="C")

    pdf_bytes = bytes(pdf.output())
    fname = f"osint-{(report.get('target','rapport'))[:30].replace(' ','-')}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )

# ── Cases ─────────────────────────────────────────────────────────────────────
@app.get("/api/cases")
def list_cases():
    conn = get_db()
    rows = conn.execute("SELECT * FROM cases ORDER BY updated_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/api/cases")
def create_case(case: CaseCreate):
    now = datetime.now().isoformat()
    tl  = json.dumps([{"date": now[:10], "event": "Dossier créé", "type": "auto"}])
    conn = get_db()
    cur  = conn.execute(
        "INSERT INTO cases (name,notes,created_at,updated_at,timeline) VALUES (?,?,?,?,?)",
        (case.name, case.notes, now, now, tl)
    )
    conn.commit()
    row = conn.execute("SELECT * FROM cases WHERE id=?", (cur.lastrowid,)).fetchone()
    conn.close()
    return dict(row)

@app.put("/api/cases/{case_id}")
def update_case(case_id: int, upd: CaseUpdate):
    fields: dict = {}
    if upd.status   is not None: fields["status"]   = upd.status
    if upd.risk     is not None: fields["risk"]      = upd.risk
    if upd.notes    is not None: fields["notes"]     = upd.notes
    if upd.timeline is not None: fields["timeline"]  = json.dumps(upd.timeline)
    fields["updated_at"] = datetime.now().isoformat()
    set_clause = ", ".join(f"{k}=?" for k in fields)
    conn = get_db()
    conn.execute(f"UPDATE cases SET {set_clause} WHERE id=?", list(fields.values()) + [case_id])
    conn.commit()
    row = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    conn.close()
    if not row: raise HTTPException(404, "Dossier non trouvé")
    return dict(row)

@app.delete("/api/cases/{case_id}")
def delete_case(case_id: int):
    conn = get_db()
    conn.execute("DELETE FROM cases WHERE id=?", (case_id,))
    conn.commit(); conn.close()
    return {"ok": True}

# ── History ───────────────────────────────────────────────────────────────────
@app.get("/api/history")
def get_history(limit: int = 30):
    conn = get_db()
    rows = conn.execute(
        "SELECT id,query,mode,mode_label,mode_icon,risk,summary,created_at FROM history ORDER BY id DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.delete("/api/history")
def clear_history():
    conn = get_db()
    conn.execute("DELETE FROM history")
    conn.commit(); conn.close()
    return {"ok": True}

# ── Waitlist Premium ─────────────────────────────────────────────────────────
EMAIL_RE = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')

@app.post("/api/waitlist")
def join_waitlist(req: WaitlistRequest):
    email = req.email.strip().lower()
    if not EMAIL_RE.match(email):
        raise HTTPException(400, detail="Adresse email invalide.")
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO waitlist (email, created_at) VALUES (?, ?)",
            (email, datetime.now().isoformat())
        )
        conn.commit()
    except sqlite3.IntegrityError:
        pass  # déjà inscrit — pas une erreur du point de vue utilisateur
    finally:
        conn.close()
    return {"ok": True}

# ── Frontend ──────────────────────────────────────────────────────────────────
static_dir = Path("static")
static_dir.mkdir(exist_ok=True)

if (static_dir / "index.html").exists():
    app.mount("/", StaticFiles(directory="static", html=True), name="static")
else:
    @app.get("/")
    def root():
        return HTMLResponse(
            "<h1 style='font-family:monospace;padding:40px'>OSINT Platform API</h1>"
            "<p style='font-family:monospace;padding:0 40px'>Placez <code>index.html</code> dans <code>static/</code></p>"
            "<p style='padding:0 40px'><a href='/api/docs'>→ Swagger API Docs</a></p>"
        )

# ── Entrypoint ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    dev_mode = os.getenv("ENV", "development") != "production"
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=dev_mode)
