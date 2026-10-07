import math
import re
import hashlib
import secrets
import string
import json
from urllib.request import Request, urlopen
from http.server import HTTPServer, BaseHTTPRequestHandler

def check_pwned_password(password: str) -> int:
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_password[:5]
    suffix = sha1_password[5:]
    
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        req = Request(url, headers={'User-Agent': 'Python-Password-Analyzer'})
        with urlopen(req, timeout=3) as response:
            if response.status == 200:
                lines = response.read().decode('utf-8').splitlines()
                for line in lines:
                    h, count = line.split(':')
                    if h == suffix:
                        return int(count)
    except Exception:
        pass
    return 0

class RequestHandler(BaseHTTPRequestHandler):
    def _set_cors_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')

    def do_OPTIONS(self):
        self.send_response(200)
        self._set_cors_headers()
        self.end_headers()

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else '{}'
        data = json.loads(body) if body else {}

        if self.path == '/analyze':
            pwd = data.get('password', '')
            if not pwd:
                res = {
                    "score": 0,
                    "rating": "Vide",
                    "entropy_bits": 0,
                    "feedback": ["Veuillez saisir un mot de passe."],
                    "pwned_count": 0
                }
            else:
                score = 0
                feedback = []
                length = len(pwd)

                if length >= 16:
                    score += 35
                elif length >= 12:
                    score += 25
                elif length >= 8:
                    score += 10
                else:
                    feedback.append("Longueur trop courte (au moins 8 caractères, 12+ recommandé).")

                pool_size = 0
                if re.search(r'[a-z]', pwd):
                    pool_size += 26
                    score += 10
                else:
                    feedback.append("Ajoutez au moins une lettre minuscule.")

                if re.search(r'[A-Z]', pwd):
                    pool_size += 26
                    score += 10
                else:
                    feedback.append("Ajoutez au moins une lettre majuscule.")

                if re.search(r'[0-9]', pwd):
                    pool_size += 10
                    score += 10
                else:
                    feedback.append("Ajoutez au moins un chiffre.")

                if re.search(r'[^a-zA-Z0-9]', pwd):
                    pool_size += 32
                    score += 15
                else:
                    feedback.append("Ajoutez au moins un caractère spécial (!@#$%...).")

                entropy = length * math.log2(pool_size) if pool_size > 0 else 0

                if re.search(r'(123|abc|qwerty|azerty|password|motdepasse|admin)', pwd.lower()):
                    score -= 25
                    feedback.append("Évitez les séquences ou mots prévisibles.")

                pwned_count = check_pwned_password(pwd)
                if pwned_count > 0:
                    score -= 40
                    feedback.append(f"⚠️ Ce mot de passe apparaît dans {pwned_count:,} fuites de données publiques !")

                score = max(0, min(100, score))
                if score >= 80:
                    rating = "Très Fort"
                elif score >= 60:
                    rating = "Fort"
                elif score >= 40:
                    rating = "Moyen"
                else:
                    rating = "Faible"

                res = {
                    "score": score,
                    "rating": rating,
                    "entropy_bits": round(entropy, 1),
                    "feedback": feedback,
                    "pwned_count": pwned_count
                }

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps(res).encode('utf-8'))

        elif self.path == '/generate':
            length = max(8, min(64, data.get('length', 16)))
            alphabet = string.ascii_letters + string.digits + "!@#$%^&*()_+-="
            while True:
                pwd = ''.join(secrets.choice(alphabet) for _ in range(length))
                if (any(c.islower() for c in pwd)
                        and any(c.isupper() for c in pwd)
                        and any(c.isdigit() for c in pwd)
                        and any(c in "!@#$%^&*()_+-=" for c in pwd)):
                    break

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self._set_cors_headers()
            self.end_headers()
            self.wfile.write(json.dumps({"password": pwd}).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

if __name__ == '__main__':
    server = HTTPServer(('127.0.0.1', 8000), RequestHandler)
    print("Serveur démarré sur http://127.0.0.1:8000")
    server.serve_forever()