import ipaddress
import socket

import requests
from urllib.parse import urlparse

MAX_RESPONSE_SIZE = 2 * 1024 * 1024  # 2 MB

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

def _is_unsafe_target(hostname):
    if hostname.lower() == "localhost":
        return True

    try:
        ip = ipaddress.ip_address(hostname)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        )
    except ValueError:
        pass

    try:
        addresses = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM,
        )

        for address in addresses:
            ip = ipaddress.ip_address(address[4][0])

            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_multicast
                or ip.is_unspecified
            ):
                return True

    except (socket.gaierror, ValueError):
        return False

    return False


def analyze_url(url):
    if not url:
        return {"error": "URL is empty."}

    url = url.strip()

    # Reject explicit unsupported schemes before normalization.
    if "://" in url:
        scheme = url.split("://", 1)[0].lower()

        if scheme not in ("http", "https"):
            return {
                "url": url,
                "risk": "UNKNOWN",
                "risk_score": 0,
                "error": "Unsupported URL scheme. Use HTTP or HTTPS."
            }

    # Add HTTPS only when no scheme was supplied.
    if "://" not in url:
        url = "https://" + url

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        return {
            "url": url,
            "risk": "UNKNOWN",
            "risk_score": 0,
            "error": "Unsupported URL scheme. Use HTTP or HTTPS."
        }

    if parsed.username is not None or parsed.password is not None:
        return {
            "url": url,
            "domain": parsed.hostname,
            "risk": "UNKNOWN",
            "risk_score": 0,
            "error": "URLs containing username or password are not allowed.",
        }

    if not parsed.hostname:
        return {
            "url": url,
            "risk": "UNKNOWN",
            "risk_score": 0,
            "error": "Invalid URL or domain."
        }

    hostname = parsed.hostname

    if _is_unsafe_target(hostname):
        return {
            "url": url,
            "domain": hostname,
            "risk": "UNKNOWN",
            "risk_score": 0,
            "error": "Local or private network targets are not allowed.",
        }


    if (
        hostname.startswith(".")
        or hostname.endswith(".")
        or ".." in hostname
        or " " in hostname
    ):
        return {
            "url": url,
            "domain": hostname,
            "risk": "UNKNOWN",
            "risk_score": 0,
            "error": "Invalid hostname format."
        }

    # Basic hostname sanity check.
    if "." not in hostname and hostname not in ("localhost",):
        return {
            "url": url,
            "domain": hostname,
            "risk": "UNKNOWN",
            "risk_score": 0,
            "error": "Hostname must contain a valid domain name."
        }

    result = {
        "url": url,
        "domain": parsed.hostname,
        "https": parsed.scheme == "https",
        "status": None,
        "status_text": None,
        "final_url": None,
        "redirects": [],
        "headers": {},
        "missing_headers": [],
        "cookies": [],
        "cookie_flags": {
            "secure": 0,
            "httponly": 0,
            "samesite": 0,
        },
        "risk": "UNKNOWN",
        "findings": [],
        "recommendations": [],
        "error": None,
    }

    try:
        response = requests.get(
            url,
            timeout=8,
            allow_redirects=False,
            stream=True,
            headers={
                "User-Agent": "OpenShieldAI-Security-Analyzer/2.0"
            },
        )

        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get("Location", "")

            if not location:
                result["error"] = "Redirect target is missing."
                result["risk"] = "UNKNOWN"
                result["risk_score"] = 0
                return result

            redirected = urlparse(location)

            if not redirected.scheme:
                redirected = urlparse(
                    requests.compat.urljoin(url, location)
                )

            if redirected.scheme not in ("http", "https"):
                result["error"] = "Redirect target uses an unsupported scheme."
                result["risk"] = "UNKNOWN"
                result["risk_score"] = 0
                return result

            if not redirected.hostname:
                result["error"] = "Redirect target has an invalid hostname."
                result["risk"] = "UNKNOWN"
                result["risk_score"] = 0
                return result

            if _is_unsafe_target(redirected.hostname):
                response.close()
                result["error"] = (
                    "Redirect target points to a local or private network."
                )
                result["risk"] = "UNKNOWN"
                result["risk_score"] = 0
                return result

            response.close()

            response = requests.get(
                requests.compat.urljoin(url, location),
                timeout=8,
                allow_redirects=False,
                headers={
                    "User-Agent": "OpenShieldAI-Security-Analyzer/2.0"
                },
            )

        result["status"] = response.status_code
        result["status_text"] = response.reason
        result["final_url"] = response.url

        result["redirects"] = [
            {
                "status": r.status_code,
                "url": r.url,
                "location": r.headers.get("Location", "")
            }
            for r in response.history
        ]

        content_length = response.headers.get("Content-Length")

        if content_length:
            try:
                if int(content_length) > MAX_RESPONSE_SIZE:
                    result["error"] = (
                        "Response exceeds the maximum allowed size."
                    )
                    result["risk"] = "UNKNOWN"
                    result["risk_score"] = 0
                    return result
            except ValueError:
                pass

        response_headers = {
            key.lower(): value
            for key, value in response.headers.items()
        }

        for header in SECURITY_HEADERS:
            if header.lower() in response_headers:
                result["headers"][header] = True
            else:
                result["missing_headers"].append(header)

        set_cookie_headers = response.raw.headers.getlist("Set-Cookie")

        for index, cookie in enumerate(set_cookie_headers, 1):
            parts = [part.strip() for part in cookie.split(";")]

            name = parts[0].split("=", 1)[0].strip()
            cookie_lower = cookie.lower()

            secure = any(
                part.lower() == "secure"
                for part in parts[1:]
            )

            httponly = any(
                part.lower() == "httponly"
                for part in parts[1:]
            )

            samesite = "Not Set"

            for part in parts[1:]:
                if part.lower().startswith("samesite="):
                    samesite = part.split("=", 1)[1].strip()
                    break

            result["cookies"].append({
                "number": index,
                "name": name or f"Cookie-{index}",
                "secure": secure,
                "httponly": httponly,
                "samesite": samesite,
            })

            result["cookie_flags"]["secure"] += int(secure)
            result["cookie_flags"]["httponly"] += int(httponly)
            result["cookie_flags"]["samesite"] += int(
                samesite.lower() != "not set"
            )

        response.close()

        findings = []

        if not result["https"]:
            findings.append("HTTPS is not enabled.")

        if result["missing_headers"]:
            findings.append(
                f"{len(result['missing_headers'])} security headers are missing."
            )

        for cookie in result["cookies"]:
            if not cookie["secure"]:
                findings.append(
                    f"Cookie '{cookie['name']}' is missing the Secure flag."
                )

            if not cookie["httponly"]:
                findings.append(
                    f"Cookie '{cookie['name']}' is missing the HttpOnly flag."
                )

            if cookie["samesite"].lower() == "not set":
                findings.append(
                    f"Cookie '{cookie['name']}' does not declare SameSite."
                )

        result["findings"] = list(dict.fromkeys(findings))

        recommendations = []

        if not result["https"]:
            recommendations.append(
                "Enable HTTPS and redirect HTTP traffic to HTTPS."
            )

        if "Strict-Transport-Security" in result["missing_headers"]:
            recommendations.append(
                "Consider enabling HSTS after HTTPS is correctly configured."
            )

        if "Content-Security-Policy" in result["missing_headers"]:
            recommendations.append(
                "Consider adding a suitable Content-Security-Policy."
            )

        if "X-Content-Type-Options" in result["missing_headers"]:
            recommendations.append(
                "Add X-Content-Type-Options: nosniff."
            )

        if "X-Frame-Options" in result["missing_headers"]:
            recommendations.append(
                "Consider clickjacking protection with X-Frame-Options or CSP frame-ancestors."
            )

        if "Referrer-Policy" in result["missing_headers"]:
            recommendations.append(
                "Consider setting an appropriate Referrer-Policy."
            )

        if "Permissions-Policy" in result["missing_headers"]:
            recommendations.append(
                "Consider restricting unnecessary browser features with Permissions-Policy."
            )

        result["recommendations"] = recommendations

        score = 0

        if not result["https"]:
            score += 4

        score += min(len(result["missing_headers"]), 6)

        for cookie in result["cookies"]:
            if not cookie["secure"]:
                score += 2

            if not cookie["httponly"]:
                score += 2

            if cookie["samesite"].lower() == "not set":
                score += 1

        result["risk_score"] = score

        if score >= 9:
            result["risk"] = "HIGH"
        elif score >= 4:
            result["risk"] = "MEDIUM"
        else:
            result["risk"] = "LOW"

    except requests.RequestException as error:
        result["error"] = str(error)
        result["risk"] = "UNKNOWN"
        result["risk_score"] = 0

    return result
