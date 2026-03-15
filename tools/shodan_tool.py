import os

def query_shodan(target: str) -> dict:
    """Query Shodan for passive intel on target IP."""
    api_key = os.getenv("SHODAN_API_KEY", "")
    if not api_key or api_key == "your_key_here":
        return {"error": "No Shodan API key set", "target": target}
    try:
        import shodan
        api = shodan.Shodan(api_key)
        host = api.host(target)
        return {
            "target":       target,
            "org":          host.get("org", "unknown"),
            "country":      host.get("country_name", "unknown"),
            "open_ports":   host.get("ports", []),
            "vulns":        list(host.get("vulns", [])),
            "hostnames":    host.get("hostnames", []),
            "isp":          host.get("isp", "unknown"),
            "last_update":  host.get("last_update", "")
        }
    except Exception as e:
        return {"error": str(e), "target": target}
