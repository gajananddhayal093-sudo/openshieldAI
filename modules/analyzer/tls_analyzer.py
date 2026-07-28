import socket
import ssl
from datetime import datetime, timezone


def analyze_tls(host, port=443, timeout=5):
    if not host:
        return {
            "host": host,
            "port": port,
            "valid": False,
            "error": "Host is empty.",
        }

    host = host.strip()

    result = {
        "host": host,
        "port": port,
        "valid": False,
        "tls_version": None,
        "cipher": None,
        "issuer": None,
        "subject": None,
        "expires": None,
        "days_remaining": None,
        "error": None,
    }

    try:
        context = ssl.create_default_context()

        with socket.create_connection(
            (host, port),
            timeout=timeout,
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=host,
            ) as tls_sock:

                certificate = tls_sock.getpeercert()

                result["valid"] = True
                result["tls_version"] = tls_sock.version()

                cipher = tls_sock.cipher()
                if cipher:
                    result["cipher"] = cipher[0]

                issuer = certificate.get("issuer", ())
                subject = certificate.get("subject", ())

                result["issuer"] = issuer
                result["subject"] = subject

                expires = certificate.get("notAfter")

                if expires:
                    expiry = datetime.strptime(
                        expires,
                        "%b %d %H:%M:%S %Y %Z",
                    ).replace(tzinfo=timezone.utc)

                    result["expires"] = expiry.isoformat()

                    remaining = expiry - datetime.now(timezone.utc)
                    result["days_remaining"] = remaining.days

    except (socket.timeout, OSError, ssl.SSLError, ValueError) as error:
        result["error"] = str(error)

    return result
