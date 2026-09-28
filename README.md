Windows Forensic Evidence Collector (DFIR Tool):

A modular Python-based tool designed for Digital Forensics and Incident Response (DFIR) and digital investigation analysts to efficiently collect, analyze, and preserve critical Windows system artifacts.

Features
Browser Artifacts Extraction: Collects browsing history and artifacts from popular web browsers (Chrome, Edge).

System Logs Collection: Gathers essential Windows Event Logs (.evtx) for security auditing and threat hunting.

USB History Tracking: Extracts USB connection artifacts to analyze device usage timelines.

System Information Gathering: Captures core host details and system configurations for initial triage.

Modular Architecture: Easily expandable structure to add custom evidence collection modules.

Requirements
Python 3.x

Windows Operating System (Host Environment)

Installation & Usage
Clone the repository:

Bash
git clone https://github.com/noreen336/crispy-spork.git
cd crispy-spork
Install dependencies:

Bash
pip install -r requirements.txt
Run the collector:

Bash
python src/main.py

License
This project is open-source and protected under the MIT License.
