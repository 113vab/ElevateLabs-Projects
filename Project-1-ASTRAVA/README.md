# ASTRAVA: Cyber Threat Detection & Monitoring Platform

A lightweight, real-time intrusion detection and network monitoring dashboard built using Python, Flask, Scapy, SQLite, and SQLAlchemy.

---

##  Project Directory Structure

```text
network_packet_sniffer/
├── app.py                  # Main Flask Web Server & routing controller
├── database.py             # SQLite database configuration & SQLAlchemy session setups
├── models.py               # Database schemas (PacketLog & AlertLog tables)
├── detector.py             # Intrusion detection and threat analysis signatures
├── sniffer.py              # Threaded Scapy network interface listener
├── requirements.txt        # Python package dependencies
├── README.md               # Setup and implementation documentation
├── database/               # Directory housing SQLite file (auto-created)
│   └── sniffer.db          
├── static/
│   ├── css/
│   │   └── style.css       # Custom Glassmorphic Dark UI styles
│   └── js/
│       └── charts.js       # Dynamic polling chart.js scripts
└── templates/
    ├── index.html          # Dashboard home page
    ├── packets.html        # Live captured traffic table view
    └── alerts.html         # Threat alerts and warnings catalog
```

---

##  Core Architecture

1. **[app.py](file:///C:/Users/visha/network_packet_sniffer/app.py)**: Spawns the background Sniffer thread, exposes statistics REST endpoints (`/api/stats`), manages database lifecycles, and binds UI templates.
2. **[sniffer.py](file:///C:/Users/visha/network_packet_sniffer/sniffer.py)**: Listens for raw interface events, converts raw Scapy packets into database models, and sends entries to the ThreatDetector engine.
3. **[detector.py](file:///C:/Users/visha/network_packet_sniffer/detector.py)**: Matches packets against predefined alert rules (e.g. tracking sliding-window port scans, large packet limits, or insecure cleartext protocols).
4. **[database.py](file:///C:/Users/visha/network_packet_sniffer/database.py)** & **[models.py](file:///C:/Users/visha/network_packet_sniffer/models.py)**: Standardize persistent SQLite interaction using declarative base structures.

---

##  Prerequisites

Running a socket sniffer requires raw socket privileges.

### 1. Packet Capture Drivers
* **Windows**: Install **Npcap** (recommended, in WinPcap compatibility mode) or **WinPcap**. Download from [Npcap Website](https://npcap.com/).
* **Linux**: Install standard `libpcap` dependencies:
  ```bash
  sudo apt-get install libpcap-dev
  ```

##Screenshots
## Screenshots

### Dashboard Overview

![Dashboard Overview](screenshots/01-dashboard-overview.png)

### Security Analytics

![Security Analytics](screenshots/02-security-analytics.png)

### Live Activity Feed

![Live Activity Feed](screenshots/03-live-activity-feed.png)

### Top Threat Sources

![Top Threat Sources](screenshots/04-top-threat-sources.png)





### 2. Admin Permissions
* **Windows**: Run command prompt / IDE as **Administrator**.
* **Linux/macOS**: Run the Flask app with `sudo` permissions.

---

##  Installation & Running

1. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Start the application**:
   On Windows (Cmd run as Administrator):
   ```bash
   python app.py
   ```
   On Linux / macOS:
   ```bash
   sudo python app.py
   ```

3. **View Dashboard**:
   Open browser at: [http://127.0.0.1:5000](http://127.0.0.1:5000)
