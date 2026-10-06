"""
Rival (CortexOne) tool that lets a Rival agent read from the Dummy Alert Service.

Paste this file into Rival Studio as `cortexone_function.py` (runtime: Python 3.13)
and attach two Secrets:
  ALERT_API_BASE_URL  - public URL of the alert service, e.g. https://xyz.trycloudflare.com
  ALERT_API_KEY       - same value as ALERT_API_KEY in the service's .env

Input (event):
  {"action": "list_alerts", "status": "firing", "severity": "critical", "service": "...", "scenario": "..."}
  {"action": "logs" | "metrics" | "history", "fingerprint": "a1c9f0", "scenario": "..."}
  {"action": "service", "service": "checkout-api"}
  {"action": "runbook", "runbook_id": "RB-101"}
  {"action": "set_scenario", "name": "db_storm"}
"""

import os

import requests

ALERT_ACTIONS = {"logs", "metrics", "history"}


def cortexone_handler(event, context):
    base_url = (os.environ.get("ALERT_API_BASE_URL") or "").rstrip("/")
    if not base_url:
        return {"statusCode": 400, "body": {"error": "ALERT_API_BASE_URL secret is not attached"}}

    headers = {}
    api_key = os.environ.get("ALERT_API_KEY")
    if api_key:
        headers["X-API-Key"] = api_key

    action = event.get("action", "list_alerts")
    scenario = {"scenario": event["scenario"]} if event.get("scenario") else {}

    if action == "list_alerts":
        params = {k: event[k] for k in ("status", "severity", "service") if event.get(k)}
        method, path, params = "GET", "/api/v1/alerts", {**params, **scenario}
    elif action in ALERT_ACTIONS:
        if not event.get("fingerprint"):
            return {"statusCode": 400, "body": {"error": f"'{action}' needs a 'fingerprint'"}}
        method, path, params = "GET", f"/api/v1/alerts/{event['fingerprint']}/{action}", scenario
    elif action == "service":
        method, path, params = "GET", f"/api/v1/services/{event.get('service', '')}", {}
    elif action == "runbook":
        method, path, params = "GET", f"/api/v1/runbooks/{event.get('runbook_id', '')}", {}
    elif action == "set_scenario":
        method, path, params = "POST", "/api/v1/scenario", {}
    else:
        return {"statusCode": 400, "body": {"error": f"Unknown action '{action}'"}}

    try:
        resp = requests.request(
            method, base_url + path, params=params, headers=headers, timeout=10,
            json={"name": event.get("name")} if method == "POST" else None,
        )
    except requests.RequestException as e:
        return {"statusCode": 502, "body": {"error": f"Alert service unreachable: {e}"}}

    try:
        body = resp.json()
    except ValueError:
        body = {"raw": resp.text[:2000]}
    return {"statusCode": resp.status_code, "body": body}
