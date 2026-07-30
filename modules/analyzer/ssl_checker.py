import ssl
import socket
from urllib.parse import urlparse


def check_ssl(url):
    try:
        if "://" not in url:
            url = "https://" + url

        hostname = urlparse(url).hostname

        context = ssl.create_default_context()

        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(
                sock,
                server_hostname=hostname
            ) as secure_sock:

                cert = secure_sock.getpeercert()

                return {
                    "valid": True,
                    "hostname": hostname,
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "expires": cert.get("notAfter"),
                    "protocol": secure_sock.version(),
                    "cipher": secure_sock.cipher()[0],
                }

    except Exception as e:
        return {
            "valid": False,
            "error": str(e),
        }
