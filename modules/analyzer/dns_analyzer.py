import socket


def analyze_dns(domain):
    if not domain:
        return {
            "domain": domain,
            "error": "Domain is empty."
        }

    domain = domain.strip().lower()

    result = {
        "domain": domain,
        "addresses": [],
        "ipv4": [],
        "ipv6": [],
        "error": None,
    }

    try:
        infos = socket.getaddrinfo(
            domain,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        )

        addresses = sorted({
            info[4][0]
            for info in infos
            if info[4]
        })

        result["addresses"] = addresses
        result["ipv4"] = [
            ip for ip in addresses if ":" not in ip
        ]
        result["ipv6"] = [
            ip for ip in addresses if ":" in ip
        ]

    except socket.gaierror as error:
        result["error"] = str(error)

    return result
