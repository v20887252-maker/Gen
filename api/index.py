# ═══════════════════════════════════════════════════════════════
#  ARIYAN API — FREE FIRE BD ACCOUNT GENERATOR (OB55)
#  Vercel Native Handler
# ═══════════════════════════════════════════════════════════════

import json, random, string, hmac, hashlib, base64, re, uuid
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import BaseHTTPRequestHandler
import requests, urllib3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ═══════════════════════════════════════════════════════════════
#  CONSTANTS
# ═══════════════════════════════════════════════════════════════
HEX_KEY = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
API_KEY = bytes.fromhex(HEX_KEY)
AES_KEY = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
AES_IV  = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])

API_BASE   = "https://100067.connect.garena.com"
MAJOR_BASE = "https://loginbp.ggpolarbear.com"
CLIENT_BASE = "https://clientbp.ggpolarbear.com"

RELEASE_VERSION = "OB55"
UNITY_VERSION   = "2018.4.12f1"
CLIENT_VERSION  = "1.132.6"
CLIENT_VER_CODE = "2019121227"

BD_CARRIERS = ["Grameenphone", "Robi", "Banglalink", "Teletalk", "Airtel"]
BD_IP_PREFIXES = ["103.230.", "103.108.", "103.148.", "103.87.",
                  "119.30.", "119.148.", "202.134.", "202.4.",
                  "103.4.", "103.84.", "103.99.", "27.147."]
BD_DEVICES = [
    "SM-A515F", "SM-A125F", "SM-M215F", "Redmi 9A",
    "Redmi Note 10", "Realme C15", "Vivo Y20", "Oppo A15",
    "Infinix Hot 10", "Walton Primo", "Symphony Z35", "Lava Z2",
]
BD_ANDROID = ["9", "10", "11", "12"]

# ═══════════════════════════════════════════════════════════════
#  PROTO HELPERS
# ═══════════════════════════════════════════════════════════════
def enc_varint(n):
    if n < 0: return b''
    buf = []
    while True:
        b = n & 0x7F; n >>= 7
        if n: b |= 0x80
        buf.append(b)
        if not n: break
    return bytes(buf)

def fvarint(tag, val):
    return enc_varint((tag << 3) | 0) + enc_varint(val)

def flength(tag, val):
    tb = enc_varint((tag << 3) | 2)
    d = val.encode('utf-8') if isinstance(val, str) else val
    return tb + enc_varint(len(d)) + d

def create_proto(fields):
    out = bytearray()
    for tag, val in fields.items():
        if isinstance(val, int):
            out.extend(fvarint(tag, val))
        elif isinstance(val, (str, bytes)):
            out.extend(flength(tag, val))
    return bytes(out)

def aes_encrypt(data):
    return AES.new(AES_KEY, AES.MODE_CBC, AES_IV).encrypt(pad(data, AES.block_size))

def decode_jwt(token):
    try:
        parts = token.split('.')
        if len(parts) >= 2:
            b = parts[1] + '=' * ((4 - len(parts[1]) % 4) % 4)
            return json.loads(base64.urlsafe_b64decode(b).decode('utf-8', errors='ignore'))
    except Exception:
        pass
    return {}

def random_bd_ip():
    p = random.choice(BD_IP_PREFIXES)
    return p + f"{random.randint(1,254)}.{random.randint(1,254)}" if p.count('.') == 2 else p + f"{random.randint(1,254)}"

# ═══════════════════════════════════════════════════════════════
#  FIELD 14 (open_id XOR keystream)
# ═══════════════════════════════════════════════════════════════
KEYSTREAM = [
    0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,
    0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,
    0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,
    0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,
]
def build_field_14(open_id):
    ob = open_id.encode('utf-8')
    return bytes([ob[i] ^ KEYSTREAM[i % 32] for i in range(len(ob))])

# ═══════════════════════════════════════════════════════════════
#  FIELD_22 (OB55 mandatory)
# ═══════════════════════════════════════════════════════════════
FIELD_22 = bytes.fromhex(
    "4747524501010100620200001052aa0d669c6a368f08338060d2ee0690053af84a41edcd3558556ec10f24f4"
    "6c93ac64ca41a16732c46a2cb071246a79b8929032f9e1b6f4ef331bd53cabf29b09b97349a46e9863c0314e"
    "1a0d80819fef8aabf03876b3d037db354a7ccb5c1bce96411fb3753f6f50e44c69c4ed617fa30efb8ffc0517"
    "ff2f636739be1f304d999cfd6fd48bf69454199794c3dc88f55a4bdbd66534d5a061359cdfd1fb680cd37918"
    "df9fdb3cf7d80067b0a3506c90063cf62b2ccec11e23913a2fd7c4ef091331967bb518a5ad1e551146b90821"
    "be800883abadde39d6c80a5d798611466c748f075481806c5842ce45e6bd4e3368ec08fe2ec41ceb880cd862"
    "49eb71693f79f0bccf9e590c3fae12519fe08c7a1905d0927690109e0df28574bb14847225db1a59230e6662"
    "ed7730e15ff9a6c815cb41b420edeada735a4b03e181037c37c2c850257311df2f07b0a56e759372cbd0268e"
    "3f13a292ee4373e38ab5096e0342a5e0d7fec6da2bbc265d74baadd2b24ee4f74862f82c21d6694bac53f8ce"
    "80312a30068a6276a641c19b11d0305c6fe2f531ac7de578b29f543697f5c73663e6f23aa15277b6122dcd4d"
    "4171e38f9ac0b173f39c58416a16c5c1f4a35acd065ce78f449cf538a249339e763272d458e4ed86c976591a"
    "9c066b3a37111e44091eb6b5a795249f3e5145db022a6055f2cc675936391312f688f89627845df222a91156"
    "555225be36f9714a0ba50246d0f003bda3c9c1292ab73b4f79635ddd023218eda93a302d79e023404c143965"
    "44a930b98ed54771aca7fec10d095587685b473e81a9619764fad9256529dcd6e911f4f4629612287d4ee3ec"
    "5389f6ec4ec020b0e2aac017232a9197be9e46239ce690fe5d4872b2e98e651510c971667f3aca8b59f3e9d5"
    "0e43"
)

# ═══════════════════════════════════════════════════════════════
#  MAJOR LOGIN PROTO (dynamic, BD-aware)
# ═══════════════════════════════════════════════════════════════
def build_major_login_proto(open_id, access_token, region="BD"):
    dev = random.choice(BD_DEVICES)
    av = random.choice(BD_ANDROID)
    carrier = random.choice(BD_CARRIERS)
    ip = random_bd_ip()
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    api_level = {"9":28, "10":29, "11":30, "12":31}.get(av, 28)
    did = f"Google|{uuid.uuid4()}"

    fields = {
        3: now, 4: "free fire", 5: 4,
        7: CLIENT_VERSION, 8: CLIENT_VER_CODE,
        9: f"Android OS {av} / API-{api_level}",
        10: "Handheld", 11: dev,
        12: 1280, 13: 720, 14: "240",
        15: "ARMv7 VFPv3 NEON | 2400 | 4",
        16: random.choice([5951, 6000, 6100]),
        17: random.choice(["Adreno 610", "Mali-G72", "PowerVR GE8320"]),
        18: "OpenGL ES 3.1 v1.46",
        19: did, 20: ip, 21: "en",
        22: open_id, 23: "4", 24: "Handheld",
        25: dev, 26: region.upper(),
        29: access_token, 30: 1,
        41: carrier, 42: "WIFI",
        92: random.choice([19788, 20000, 21000]),
        93: "android_max",
        97: 1, 98: 1, 99: "4", 100: "4",
        104: 77149, 105: 1,
    }
    return aes_encrypt(create_proto(fields))

# ═══════════════════════════════════════════════════════════════
#  NAME SANITIZER
# ═══════════════════════════════════════════════════════════════
DIRTY = {'admin','mod','freefire','ff','garena','bot','fuck','sex','porn',
         'xxx','dick','ass','gay','bitch','kill','death','hate','terror',
         'bomb','gun','drug','scam','hack','cheat','official','support'}

def sanitize_name(name):
    if not name: name = "Ariyan"
    c = ''.join(ch for ch in name if ch.isalnum())
    low = c.lower()
    for w in DIRTY:
        if w in low:
            c = re.sub(re.escape(w),
                       ''.join(random.choice('0123456789') for _ in range(len(w))),
                       c, flags=re.IGNORECASE)
            low = c.lower()
    c = re.sub(r'(.)\1{2,}', r'\1\1', c)
    if c and not c[0].isalpha():
        c = random.choice(string.ascii_letters) + c
    if len(c) < 4:
        c += ''.join(random.choice(string.digits) for _ in range(4 - len(c)))
    return c[:12]

def generate_name():
    prefixes = ["Ariyan", "BD", "Dhaka", "Sylhet", "Rajshahi", "Khulna",
                "Chatta", "Rangpur", "Barishal", "Mymensing"]
    p = sanitize_name(random.choice(prefixes))
    suf = ''.join(random.choice(string.digits) for _ in range(max(1, 12 - len(p))))
    return (p + suf)[:12]

# ═══════════════════════════════════════════════════════════════
#  SINGLE ATTEMPT — BD ACCOUNT
# ═══════════════════════════════════════════════════════════════
def single_attempt():
    try:
        session = requests.Session()
        session.verify = False
        session.headers.update({
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-A515F Build/RP1A.200720.012)",
            "Connection": "Keep-Alive",
        })

        username = generate_name()
        password = "ariyan_" + ''.join(random.choices(string.ascii_letters + string.digits, k=8))

        # 1) Guest register
        try:
            pr = json.dumps({"app_id": 100067, "client_type": 2,
                             "password": password, "source": 2}, separators=(',', ':'))
            sig = hmac.new(API_KEY, pr.encode(), hashlib.sha256).hexdigest()
            r = session.post(f"{API_BASE}/api/v2/oauth/guest:register",
                             headers={"Authorization": f"Signature {sig}",
                                      "Content-Type": "application/json; charset=utf-8"},
                             data=pr, timeout=10, verify=False)
            if r.status_code != 200: return None
            j = r.json()
            if j.get("code") != 0: return None
            uid = j["data"]["uid"]
        except Exception:
            return None

        # 2) Token grant
        try:
            pt = json.dumps({
                "client_id": 100067, "client_secret": HEX_KEY,
                "client_type": 2, "password": password,
                "response_type": "token", "uid": str(uid),
            }, separators=(',', ':'))
            sig = hmac.new(API_KEY, pt.encode(), hashlib.sha256).hexdigest()
            r = session.post(f"{API_BASE}/api/v2/oauth/guest/token:grant",
                             headers={"Authorization": f"Signature {sig}",
                                      "Content-Type": "application/json; charset=utf-8"},
                             data=pt, timeout=10, verify=False)
            if r.status_code != 200: return None
            j = r.json()
            if j.get("code") != 0: return None
            access_token = j["data"]["access_token"]
            open_id = j["data"]["open_id"]
        except Exception:
            return None

        # 3) MajorRegister
        reg_fields = {
            1: username, 2: access_token, 3: open_id,
            5: 102000007, 6: 4, 7: 1, 13: 1,
            14: build_field_14(open_id),
            15: "en", 16: 1,
            22: FIELD_22,
        }
        headers_mr = {
            "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
            "Accept-Encoding": "deflate, gzip",
            "X-GA-SV": "1789535859",
            "Authorization": f"Bearer {access_token}",
            "X-GA": "v1 1",
            "ReleaseVersion": RELEASE_VERSION,
            "Content-Type": "application/octet-stream",
            "X-Unity-Version": UNITY_VERSION,
            "Host": "loginbp.ggpolarbear.com",
        }
        try:
            session.post(f"{MAJOR_BASE}/MajorRegister",
                         headers=headers_mr, data=aes_encrypt(create_proto(reg_fields)),
                         timeout=15, verify=False)
        except Exception:
            pass

        # 4) MajorLogin
        jwt = ""
        acc_id = "N/A"
        try:
            enc_login = build_major_login_proto(open_id, access_token, region="BD")
            headers_ml = dict(headers_mr)
            r = session.post(f"{MAJOR_BASE}/MajorLogin",
                             headers=headers_ml, data=enc_login,
                             timeout=15, verify=False)
            if r.status_code == 200:
                m = re.search(rb"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", r.content)
                if m:
                    jwt = m.group(0).decode('utf-8', errors='ignore')
                    jd = decode_jwt(jwt)
                    acc_id = str(jd.get("account_id") or jd.get("external_id", "N/A"))
        except Exception:
            pass

        # 5) ChooseRegion BD + Beginner Guide
        if jwt:
            try:
                hb = {
                    "User-Agent": "Dalvik/2.1.0 (Linux; Android 12)",
                    "Authorization": f"Bearer {jwt}",
                    "ReleaseVersion": RELEASE_VERSION,
                    "Content-Type": "application/octet-stream",
                }
                session.post(f"{MAJOR_BASE}/ChooseRegion",
                             data=aes_encrypt(create_proto({1: "BD"})),
                             headers=hb, timeout=10, verify=False)
                session.post(f"{CLIENT_BASE}/ActiveBeginnerGuide",
                             data=aes_encrypt(create_proto({1: 3})),
                             headers=hb, timeout=10, verify=False)
            except Exception:
                pass

        return {
            "status": "success",
            "region": "BD",
            "name": username,
            "uid": str(uid),
            "password": password,
            "account_id": acc_id,
            "token": jwt if jwt else access_token,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
    except Exception:
        return None

# ═══════════════════════════════════════════════════════════════
#  RUN 10 PARALLEL ATTEMPTS
# ═══════════════════════════════════════════════════════════════
def run_generator():
    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = [ex.submit(single_attempt) for _ in range(10)]
        for f in as_completed(futures):
            try:
                r = f.result()
                if r and r.get("uid") and r.get("token"):
                    return r
            except Exception:
                pass
    return {"status": "error", "message": "Busy, please retry."}

# ═══════════════════════════════════════════════════════════════
#  VERCEL HANDLER
# ═══════════════════════════════════════════════════════════════
class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            result = run_generator()
            body = json.dumps(result).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception as e:
            err = json.dumps({"status": "error", "message": str(e)}).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(err)
