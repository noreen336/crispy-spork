import argparse
import json
import os
from pathlib import Path
from collector import (
    collect_system_info,
    collect_filesystem_evidence,
    collect_event_logs,
    collect_browser_history,
    collect_usb_history,
    generate_case_manifest,
    generate_master_summary
)

def load_config(config_path):
    """Loads lab configuration JSON file."""
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)

def main():
    parser = argparse.ArgumentParser(description="Windows Forensic Evidence Collector")
    parser.add_argument("--config", required=True, help="Path to configuration JSON file")
    args = parser.parse_args()

    print("[*] DFIR Evidence Collector v0.1.0 Initialized.")
    
    # Load configuration
    config = load_config(args.config)
    case_id = config.get("case_id", "case-default")
    output_base = config.get("output_directory", "./cases")
    
    case_dir = Path(output_base) / case_id
    case_dir.mkdir(parents=True, exist_ok=True)
    print(f"[+] Loaded Case ID: {case_id}")
    print(f"[+] Output directory created at: {case_dir.resolve()}")

    # 1. Collect System Information
    print("[*] Collecting system information...")
    sys_info = collect_system_info()
    sys_info_path = case_dir / "system_info.json"
    with open(sys_info_path, "w", encoding="utf-8") as f:
        json.dump(sys_info, f, indent=4, ensure_ascii=False)
    print(f"[+] System info saved successfully to {sys_info_path}")

    # 2. Collect Filesystem Evidence & Hashes
    target_paths = config.get("target_paths", [])
    hash_algo = config.get("hash_algorithm", "sha256")
    if target_paths:
        print(f"[*] Collecting filesystem evidence from: {target_paths}")
        fs_evidence = collect_filesystem_evidence(target_paths, hash_algo)
        fs_path = case_dir / "filesystem_evidence.json"
        with open(fs_path, "w", encoding="utf-8") as f:
            json.dump(fs_evidence, f, indent=4, ensure_ascii=False)
        print(f"[+] Filesystem evidence saved successfully to {fs_path}")

    # 3. Collect Windows Event Logs
    event_logs = config.get("event_logs", [])
    if event_logs:
        print(f"[*] Collecting windows event logs: {event_logs}")
        logs_dir = case_dir / "event_logs"
        exported_logs = collect_event_logs(event_logs, logs_dir)
        logs_report = case_dir / "event_logs_report.json"
        with open(logs_report, "w", encoding="utf-8") as f:
            json.dump(exported_logs, f, indent=4, ensure_ascii=False)
        print(f"[+] Event logs exported and report saved successfully to {logs_report}")

    # 4. Collect Browser History Artifacts
    print("[*] Collecting browser history artifacts...")
    browser_dir = case_dir / "browser_artifacts"
    browser_results = collect_browser_history(browser_dir)
    browser_report = case_dir / "browser_history_report.json"
    with open(browser_report, "w", encoding="utf-8") as f:
        json.dump(browser_results, f, indent=4, ensure_ascii=False)
    print(f"[+] Browser history report generated successfully to {browser_report}")

    # 5. Collect USB History Artifacts
    print("[*] Collecting USB connection artifacts...")
    usb_dir = case_dir / "usb_artifacts"
    usb_results = collect_usb_history(usb_dir)
    usb_report = case_dir / "usb_history_report.json"
    with open(usb_report, "w", encoding="utf-8") as f:
        json.dump(usb_results, f, indent=4, ensure_ascii=False)
    print(f"[+] USB history report generated successfully to {usb_report}")

    # 6. Generate Case Manifest & Chain of Custody Hashes
    print("[*] Generating Case Manifest & Chain of Custody hashes...")
    manifest_records = generate_case_manifest(case_dir, hash_algo)
    manifest_path = case_dir / "case_manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest_records, f, indent=4, ensure_ascii=False)
    print(f"[+] Case manifest generated successfully at {manifest_path}")

    # 7. Generate Master Summary Report
    print("[*] Generating Master Summary Report...")
    summary_path = generate_master_summary(case_dir)
    print(f"[+] Master summary report generated successfully at {summary_path}")

    print("[+] Collection and summary completed successfully!")

if __name__ == "__main__":
    main()