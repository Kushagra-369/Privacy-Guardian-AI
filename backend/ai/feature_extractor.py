import whois
import socket
import ssl
from urllib.parse import urlparse
from datetime import datetime

def extract_advanced_features(url: str):
    features = {}

    try:
        domain = urlparse(url).netloc

        # ===== DOMAIN AGE =====
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            age_days = (datetime.now() - creation_date).days
            features["domain_age"] = age_days
        except:
            features["domain_age"] = -1

        # ===== DNS CHECK =====
        try:
            socket.gethostbyname(domain)
            features["dns_valid"] = 1
        except:
            features["dns_valid"] = 0

        # ===== SSL CHECK =====
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(3)
                s.connect((domain, 443))
                s.getpeercert()
                features["ssl_valid"] = 1
        except:
            features["ssl_valid"] = 0

    except:
        pass

    return features