import socket


COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    465: "SMTPS",
    587: "SMTP Submission",
    993: "IMAPS",
    995: "POP3S",
}


def check_port(host, port, timeout=2):
    result = {
        "port": port,
        "service": COMMON_PORTS.get(port, "Unknown"),
        "status": "closed",
    }

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            connection = sock.connect_ex((host, port))

            if connection == 0:
                result["status"] = "open"

    except (socket.timeout, OSError):
        result["status"] = "filtered"

    return result


def analyze_ports(host, ports=None):
    if not host:
        return {
            "host": host,
            "ports": [],
            "error": "Host is empty.",
        }

    host = host.strip()

    if ports is None:
        ports = list(COMMON_PORTS.keys())

    result = {
        "host": host,
        "ports": [],
        "error": None,
    }

    try:
        socket.gethostbyname(host)
    except socket.gaierror as error:
        result["error"] = str(error)
        return result

    for port in ports:
        if not isinstance(port, int) or not 1 <= port <= 65535:
            continue

        result["ports"].append(
            check_port(host, port)
        )

    return result
