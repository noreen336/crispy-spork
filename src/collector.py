import platform
import os
import json
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import subprocess
import sqlite3
import shutil
import winreg

def collect_system_info():
    """Gathers basic Windows system forensic information."""
    sys_info = {
        "collection_timestamp": datetime.now(timezone.utc).isoformat(),
        "system": platform.system(),
        "node_name": platform.node(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "username": os.getlogin()
    }
    return sys_info

def calculate_file_hash(file_path, algorithm="sha256"):
    """Calculates cryptographic hash of a given file."""
    hash_func = hashlib.new(algorithm)
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except Exception as e:
        return str(e)

def collect_filesystem_evidence(target_paths, hash_algo="sha256"):
    """Scans target paths and collects file metadata & hashes."""
    evidence_records = []
    for target_path in target_paths:
        path_obj = Path(target_path)
        if not path_obj.exists():
            continue
        
        files = path_obj.rglob("*") if path_obj.is_dir() else [path_obj]
        
        for file_p in files:
            if file_p.is_file():
                file_hash = calculate_file_hash(file_p, hash_algo)
                stat = file_p.stat()
                evidence_records.append({
                    "file_path": str(file_p.resolve()),
                    "size_bytes": stat.st_size,
                    "created_utc": datetime.fromtimestamp(stat.st_ctime, timezone.utc).isoformat(),
                    "modified_utc": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                    f"hash_{hash_algo}": file_hash
                })
    return evidence_records

def collect_event_logs(log_names, output_dir):
    """Exports Windows event logs using wevtutil."""
    exported_logs = []
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    for log_name in log_names:
        dest_file = output_path / f"{log_name}_log.evtx"
        cmd = ["wevtutil", "epl", log_name, str(dest_file)]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            if dest_file.exists():
                exported_logs.append({
                    "log_name": log_name,
                    "export_path": str(dest_file.resolve()),
                    "status": "Success"
                })
        except subprocess.CalledProcessError as e:
            exported_logs.append({
                "log_name": log_name,
                "status": "Failed",
                "error": e.stderr.strip()
            })
    return exported_logs

def collect_browser_history(output_dir):
    """Collects Google Chrome and Microsoft Edge web history artifacts safely."""
    exported_artifacts = []
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    
    user_profile = os.environ.get('USERPROFILE', '')
    browsers = {
        "Chrome": Path(user_profile) / r"AppData\Local\Google\Chrome\User Data\Default\History",
        "Edge": Path(user_profile) / r"AppData\Local\Microsoft\Edge\User Data\Default\History"
    }
    
    for browser_name, db_path in browsers.items():
        if db_path.exists():
            print(f"[*] Processing {browser_name} history database...")
            try:
                temp_copy = out_path / f"{browser_name}_History.db"
                shutil.copy2(db_path, temp_copy)
                
                conn = sqlite3.connect(f"file:{temp_copy}?mode=ro", uri=True)
                cursor = conn.cursor()
                cursor.execute("SELECT url, title, visit_count, last_visit_time FROM urls LIMIT 500")
                rows = cursor.fetchall()
                
                history_records = []
                for row in rows:
                    history_records.append({
                        "url": row[0],
                        "title": row[1],
                        "visit_count": row[2],
                        "last_visit_time": row[3]
                    })
                conn.close()
                
                if temp_copy.exists():
                    temp_copy.unlink()
                
                json_dest = out_path / f"{browser_name}_history.json"
                with open(json_dest, "w", encoding="utf-8") as jf:
                    json.dump(history_records, jf, indent=4, ensure_ascii=False)
                    
                exported_artifacts.append({
                    "browser": browser_name,
                    "status": "Success",
                    "records_count": len(history_records),
                    "output_path": str(json_dest.resolve())
                })
                print(f"[+] {browser_name} history collected successfully.")
            except Exception as e:
                exported_artifacts.append({
                    "browser": browser_name,
                    "status": "Failed",
                    "error": str(e)
                })
                print(f"[!] Failed to collect {browser_name} history: {e}")
        else:
            print(f"[-] {browser_name} history path not found.")
    return exported_artifacts

def collect_usb_history(output_dir):
    """Extracts connected USB storage device artifacts from the Windows Registry safely."""
    usb_records = []
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    
    usb_path = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
    try:
        print("[*] Collecting USB connection artifacts from Registry...")
        reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, usb_path)
        i = 0
        while True:
            try:
                device_name = winreg.EnumKey(reg_key, i)
                device_key_path = f"{usb_path}\\{device_name}"
                device_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, device_key_path)
                
                j = 0
                while True:
                    try:
                        instance_id = winreg.EnumKey(device_key, j)
                        instance_key_path = f"{device_key_path}\\{instance_id}"
                        instance_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, instance_key_path)
                        
                        friendly_name = ""
                        try:
                            friendly_name, _ = winreg.QueryValueEx(instance_key, "FriendlyName")
                        except FileNotFoundError:
                            pass
                        
                        usb_records.append({
                            "device_class": device_name,
                            "instance_id": instance_id,
                            "friendly_name": friendly_name
                        })
                        j += 1
                    except OSError:
                        break
                i += 1
            except OSError:
                break
        
        json_dest = out_path / "usb_devices.json"
        with open(json_dest, "w", encoding="utf-8") as jf:
            json.dump(usb_records, jf, indent=4, ensure_ascii=False)
            
        print(f"[+] USB history collected successfully. Total devices found: {len(usb_records)}")
        return {
            "status": "Success",
            "records_count": len(usb_records),
            "output_path": str(json_dest.resolve())
        }
    except FileNotFoundError:
        print("[-] No USB storage history found in Registry (USBSTOR path does not exist yet).")
        return {
            "status": "Skipped",
            "message": "USBSTOR registry key not found."
        }
    except Exception as e:
        print(f"[!] Failed to collect USB history: {e}")
        return {
            "status": "Failed",
            "error": str(e)
        }

def generate_case_manifest(case_output_dir, hash_algo="sha256"):
    """Generates a cryptographic manifest of all collected evidence files."""
    manifest_records = []
    case_path = Path(case_output_dir)
    
    for file_p in case_path.rglob("*"):
        if file_p.is_file() and file_p.name != "case_manifest.json":
            file_hash = calculate_file_hash(file_p, hash_algo)
            stat = file_p.stat()
            manifest_records.append({
                "file_name": file_p.name,
                "relative_path": str(file_p.relative_to(case_path)),
                "size_bytes": stat.st_size,
                f"hash_{hash_algo}": file_hash
            })
    return manifest_records

def generate_master_summary(case_output_dir):
    """Compiles a high-level master summary report for the forensic case."""
    case_path = Path(case_output_dir)
    summary_data = {
        "case_id": case_path.name,
        "summary_timestamp": datetime.now(timezone.utc).isoformat()
    }
    
    files_to_check = {
        "system_info": "system_info.json",
        "filesystem_evidence": "filesystem_evidence.json",
        "event_logs_report": "event_logs_report.json",
        "browser_history_report": "browser_history_report.json",
        "usb_history_report": "usb_history_report.json",
        "case_manifest": "case_manifest.json"
    }
    
    collected_artifacts = {}
    for key, fname in files_to_check.items():
        fpath = case_path / fname
        if fpath.exists():
            collected_artifacts[key] = {
                "status": "Available",
                "path": str(fpath.resolve())
            }
        else:
            collected_artifacts[key] = {
                "status": "Not Found"
            }
            
    summary_data["artifacts"] = collected_artifacts
    
    summary_path = case_path / "case_summary.json"
    with open(summary_path, "w", encoding="utf-8") as sf:
        json.dump(summary_data, sf, indent=4, ensure_ascii=False)
        
    return str(summary_path.resolve())