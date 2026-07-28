def create_evidence(
    source,
    target,
    evidence_type,
    value,
    details=None,
):
    return {
        "source": source,
        "target": target,
        "type": evidence_type,
        "value": value,
        "details": details or {},
    }


def create_finding_evidence(finding, evidence):
    result = dict(finding)
    result["evidence"] = evidence
    return result


def validate_evidence(evidence):
    required = (
        "source",
        "target",
        "type",
        "value",
    )

    return all(
        key in evidence
        and evidence[key] is not None
        for key in required
    )
