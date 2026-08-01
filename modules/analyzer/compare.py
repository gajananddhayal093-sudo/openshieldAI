"""OpenShield AI scan comparison engine."""

from database.scan_history import get_history


def compare_scans():
    history = get_history(2)

    if len(history) < 2:
        return {
            "status": "insufficient_data",
            "message": "Need at least two scans for comparison."
        }

    current = history[0]
    previous = history[1]

    return {
        "status": "success",
        "current": {
            "target": current[1],
            "risk": current[3],
            "score": current[4],
        },
        "previous": {
            "target": previous[1],
            "risk": previous[3],
            "score": previous[4],
        },
        "score_change": current[4] - previous[4],
        "risk_changed": current[3] != previous[3],
    }
