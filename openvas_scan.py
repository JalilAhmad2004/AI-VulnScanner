import subprocess
import time
import xml.etree.ElementTree as ET
import base64
import os
import threading
import pandas as pd
import io
import re
import requests

# Configuration
GMP_USERNAME = 'Your_username_here'
GMP_PASSWORD = 'Your_password_here'
SOCKET_PATH = '/run/gvmd/gvmd.sock'
SCAN_CONFIG_NAME = 'Full and fast'
PORT_LIST_ID = '4a4717fe-57d2-11e1-9a26-406186ea4fc5'
REPORT_FORMAT_NAME = 'CSV Results'
RESULT_DIR = 'scan_results'

def run_gvm_cli(xml_command):
    cmd = [
        'gvm-cli',
        '--gmp-username', GMP_USERNAME,
        '--gmp-password', GMP_PASSWORD,
        'socket',
        '--socketpath', SOCKET_PATH,
        '--xml', xml_command
    ]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"GVM CLI Error: {result.stderr.strip()}")
    return result.stdout

def get_id_from_response(response, tag):
    root = ET.fromstring(response)
    return root.attrib['id']

def get_config_id_by_name(name):
    xml = "<get_configs/>"
    response = run_gvm_cli(xml)
    root = ET.fromstring(response)
    for config in root.findall('.//config'):
        if config.find('name').text == name:
            return config.attrib['id']
    raise ValueError(f"Scan config '{name}' not found")

def get_report_format_id_by_name(name):
    xml = "<get_report_formats/>"
    response = run_gvm_cli(xml)
    root = ET.fromstring(response)
    for fmt in root.findall('.//report_format'):
        if fmt.find('name').text == name:
            return fmt.attrib['id']
    raise ValueError(f"Report format '{name}' not found")

def create_target(ip_address):
    xml = "<get_targets/>"
    response = run_gvm_cli(xml)
    root = ET.fromstring(response)
    for target in root.findall('.//target'):
        hosts = target.find('hosts')
        if hosts is not None and hosts.text == ip_address:
            return target.attrib['id']

    xml = f"""
    <create_target>
        <name>Target {ip_address}</name>
        <hosts>{ip_address}</hosts>
        <port_list id="{PORT_LIST_ID}"/>
    </create_target>
    """
    response = run_gvm_cli(xml)
    return get_id_from_response(response, 'target')

def create_task(target_id, config_id):
    xml = f"""
    <create_task>
        <name>Scan Task {target_id}</name>
        <config id="{config_id}"/>
        <target id="{target_id}"/>
        <schedule/>
    </create_task>
    """
    response = run_gvm_cli(xml)
    return get_id_from_response(response, 'task')

def start_task(task_id):
    xml = f'<start_task task_id="{task_id}"/>'
    run_gvm_cli(xml)

def get_task_status(task_id):
    xml = f'<get_tasks task_id="{task_id}"/>'
    response = run_gvm_cli(xml)
    root = ET.fromstring(response)
    status = root.find('.//status')
    progress = root.find('.//progress')
    return (status.text if status is not None else "Unknown",
            progress.text if progress is not None else "0")

def get_report_id(task_id):
    xml = f'<get_tasks task_id="{task_id}"/>'
    response = run_gvm_cli(xml)
    root = ET.fromstring(response)
    report = root.find('.//last_report/report')
    if report is not None:
        return report.attrib['id']
    raise RuntimeError("No report ID found.")

def get_report(report_id, format_id):
    xml = f'<get_reports report_id="{report_id}" format_id="{format_id}" details="1"/>'
    response = run_gvm_cli(xml)
    root = ET.fromstring(response)
    report = root.find('.//report')
    if report is not None and report.text:
        return base64.b64decode(report.text)
    raise RuntimeError("Empty report content.")

def _wait_and_save_report(task_id, ip_address, report_format_id):
    print(f"[INFO] Waiting for scan on {ip_address} to complete...")
    while True:
        status, _ = get_task_status(task_id)
        if status == "Done":
            break
        elif status in ["Running", "Queued", "Requested", "Scheduled", "Paused"]:
            time.sleep(10)
        else:
            print(f"[ERROR] Unexpected status: {status}")
            return

    try:
        import io
        import pandas as pd
        import re
        import os

        # Fetch report from OpenVAS
        report_id = get_report_id(task_id)
        raw_data = get_report(report_id, report_format_id)
        df = pd.read_csv(io.BytesIO(raw_data))

        # Filter and rename columns
        keep_cols = {
            "CVEs": "cve_id",
            "CVSS": "cvss_score",
            "Impact": "impact",
            "Solution": "solution",
            "Affected Software/OS": "affected_software"
        }
        df = df[list(keep_cols.keys())]
        df = df.rename(columns=keep_cols)

        # Drop rows with empty cve_id or cvss_score
        df = df.dropna(subset=["cve_id", "cvss_score"])
        df = df[df["cve_id"].str.strip() != ""]

        # Normalize and explode CVEs
        df = df.assign(cve_id=df["cve_id"].str.replace(r"\s+", "", regex=True).str.split(",")).explode("cve_id")

        # Lowercase all values
        df = df.applymap(lambda x: str(x).lower() if pd.notnull(x) else x)

        # Merge impact + affected_software into 'description'
        df["description"] = df["affected_software"].fillna('') + " " + df["impact"].fillna('')
        df["description"] = df["description"].apply(lambda x: re.sub(r'\s+', ' ', x.replace('\n', ' ')).strip())
        df["description"] = df["description"].replace(r'^\s*$', 'null', regex=True)
        df = df.drop(columns=["affected_software", "impact"])

        # Enrich with access_vector, access_complexity, exploit
        lookup_path = 'checkup_database/lookup_corpus.csv'
        if os.path.exists(lookup_path):
            lookup_df = pd.read_csv(lookup_path, usecols=["cve_id", "access_vector", "access_complexity", "exploit"])
            lookup_df = lookup_df.applymap(lambda x: str(x).lower() if pd.notnull(x) else x)
            df = df.merge(lookup_df, on="cve_id", how="left")
        else:
            df["access_vector"] = "network"
            df["access_complexity"] = "medium"
            df["exploit"] = "null"

        # Fill missing values conditionally
        df["access_vector"] = df["access_vector"].fillna("network")
        df["access_complexity"] = df["access_complexity"].fillna("medium")
        df["exploit"] = df["exploit"].fillna("null")

        # Save result
        os.makedirs(RESULT_DIR, exist_ok=True)
        filename = f"{RESULT_DIR}/{ip_address.replace('.', '_')}.csv"
        df.to_csv(filename, index=False)

        print(f"[INFO] Final enriched report saved to: {filename}")
    except Exception as e:
        print(f"[ERROR] Failed to clean, enrich, and save report: {str(e)}")


def start_scan_task(ip_address):
    config_id = get_config_id_by_name(SCAN_CONFIG_NAME)
    report_format_id = get_report_format_id_by_name(REPORT_FORMAT_NAME)
    target_id = create_target(ip_address)
    task_id = create_task(target_id, config_id)
    start_task(task_id)

    # Start background thread to wait and save report
    threading.Thread(
        target=_wait_and_save_report,
        args=(task_id, ip_address, report_format_id),
        daemon=True
    ).start()

    return task_id

def get_scan_progress(task_id):
    return get_task_status(task_id)

def pause_task(task_id):
    status, _ = get_task_status(task_id)
    if status not in ["Running", "Requested", "Queued"]:
        raise RuntimeError(f"Cannot pause task while in '{status}' state.")
    
    xml = f'<stop_task task_id="{task_id}"/>'
    result = run_gvm_cli(xml)

    # Confirm if task stopped
    root = ET.fromstring(result)
    status_text = root.attrib.get("status_text", "")
    if "Paused" not in status_text:
        raise RuntimeError(f"Task stop request failed: {status_text}")


def resume_task(task_id):
    status, _ = get_task_status(task_id)
    if status not in ["Paused", "Stopped"]:
        raise RuntimeError(f"Cannot resume scan while status is '{status}'")
    xml = f'<resume_task task_id="{task_id}"/>'
    run_gvm_cli(xml)
    


