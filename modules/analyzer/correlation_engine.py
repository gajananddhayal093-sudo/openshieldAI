def correlate_findings(findings):
    """
    Groups related security findings and identifies security themes.
    """

    groups = {
        "headers": [],
        "cookies": [],
        "tls": [],
        "network": [],
        "other": [],
    }

    for finding in findings:
        item = dict(finding)
        title = str(item.get("title", "")).lower()
        key = str(item.get("key", "")).lower()

        text = f"{title} {key}"

        if any(x in text for x in [
            "content-security-policy",
            "strict-transport-security",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
        ]):
            groups["headers"].append(item)

        elif any(x in text for x in [
            "cookie",
            "httponly",
            "secure cookie",
            "samesite",
        ]):
            groups["cookies"].append(item)

        elif any(x in text for x in [
            "tls",
            "ssl",
            "certificate",
            "https",
        ]):
            groups["tls"].append(item)

        elif any(x in text for x in [
            "port",
            "dns",
            "network",
        ]):
            groups["network"].append(item)

        else:
            groups["other"].append(item)

    active_groups = {
        name: items
        for name, items in groups.items()
        if items
    }

    return {
        "groups": active_groups,
        "group_count": len(active_groups),
        "correlated": len(active_groups) > 1,
    }


def correlation_summary(correlation):
    groups = correlation.get("groups", {})

    if not groups:
        return "No related security findings detected."

    names = ", ".join(
        name.title()
        for name in groups
    )

    return f"Related security areas detected: {names}."
