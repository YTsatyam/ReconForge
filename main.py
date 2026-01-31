import json
import os
from datetime import datetime

from config import SCAN_HISTORY_DIR
from core.discovery import discover_services
from core.tech_detect import detect_tech_for_hosts
from core.risk_engine import calculate_risk
from core.change_detect import compare_scans
from core.cve_lookup import search_cves
from reporting.report_generator import generate_report


def load_last_scan():
    if not os.path.exists(SCAN_HISTORY_DIR):
        return None

    files = sorted(os.listdir(SCAN_HISTORY_DIR))
    if not files:
        return None

    with open(os.path.join(SCAN_HISTORY_DIR, files[-1]), "r") as f:
        return json.load(f)


def save_scan(data):
    os.makedirs(SCAN_HISTORY_DIR, exist_ok=True)
    fname = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    path = os.path.join(SCAN_HISTORY_DIR, fname)

    with open(path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"[+] Scan history saved: {path}")


def main():
    target = input("Enter target IP/domain (lab/authorized only): ").strip()
    targets = [target]

    print("[*] Discovering services...")
    services = discover_services(targets)

    print("[*] Detecting technologies...")
    tech = detect_tech_for_hosts(targets)

    print("[*] Calculating risk scores...")
    risks = calculate_risk(services, tech)

    print("[*] Performing CVE lookup...")
    cve_results = {}

    for host, techs in tech.items():
        cve_results[host] = {}
        for t in techs:
            cve_results[host][t] = search_cves(t)

    last = load_last_scan()
    if last:
        changes = compare_scans(last.get("services", {}), services)
    else:
        changes = {"info": "No previous scan found"}

    # ===== FULL CURRENT SCAN OBJECT (UPDATED) =====
    current_scan = {
        "target": target,
        "services": services,
        "tech": tech,
        "cves": cve_results,
        "risks": risks,
        "changes": changes,
        "timestamp": datetime.now().isoformat()
    }

    save_scan(current_scan)
    generate_report(target, services, risks, changes)

    print("[+] Scan completed successfully!")


if __name__ == "__main__":
    main()
