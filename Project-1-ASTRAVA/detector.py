"""
detector.py
Purpose: Implements threat detection rules for identifying suspicious activity
on network traffic (e.g. port scanning, ICMP floods, DNS tunneling, excessive TCP
connection attempts, suspicious ports, cleartext protocols, and oversized payloads).
Includes severity classification (Low, Medium, High, Critical) and suppression windows
to prevent duplicate alert spam.
"""
from datetime import datetime
from models import AlertLog

class ThreatDetector:
    """
    Analyzes live packets and returns any security alerts triggered, with duplicate suppression.
    """
    def __init__(self):
        # Keeps track of connected ports per source IP to detect TCP port scans
        # Key: Source IP -> Value: Set of unique destination ports scanned
        self.port_scan_tracker = {}
        self.PORT_SCAN_THRESHOLD = 10

        # Tracks ICMP packet timestamps for flood detection
        # Key: Source IP -> Value: List of timestamps (datetime objects)
        self.icmp_tracker = {}
        self.ICMP_FLOOD_LIMIT = 50
        self.ICMP_WINDOW_SECS = 30

        # Tracks TCP SYN packet timestamps for excessive connection attempt detection
        # Key: Source IP -> Value: List of timestamps (datetime objects)
        self.tcp_conn_tracker = {}
        self.TCP_CONN_LIMIT = 30
        self.TCP_WINDOW_SECS = 60

        # High-risk/Suspicious ports associated with malwares, trojans, or hacking tools
        self.SUSPICIOUS_PORTS = {
            4444: ("Metasploit Listener / Trojan", "Critical"),
            5555: ("Android Debug Bridge (ADB) / Trojan", "High"),
            6667: ("IRC Botnet Control Channel", "High"),
            1337: ("Hacker Custom Listener", "High"),
            31337: ("Back Orifice Trojan", "Critical")
        }

        # Cooldown/Suppression tracker to prevent duplicate alert spam
        # Key: Tuple (Source IP, Rule Name) -> Value: Timestamp of the last generated alert
        self.last_alert_time = {}

    def _should_alert(self, src_ip, rule_name, cooldown_secs=30) -> bool:
        """
        Helper function to implement alert throttling/suppression.
        Returns True if the alert should be triggered, False if suppressed.
        """
        if not src_ip:
            return True
        
        now = datetime.utcnow()
        key = (src_ip, rule_name)
        if key in self.last_alert_time:
            last_time = self.last_alert_time[key]
            if (now - last_time).total_seconds() < cooldown_secs:
                return False
        
        self.last_alert_time[key] = now
        return True

    def analyze_packet(self, packet_db_entry, scapy_pkt) -> list:
        """
        Analyzes a packet against defined threat signatures.
        Returns a list of AlertLog database model instances.
        """
        alerts = []
        now_time = datetime.utcnow()
        src_ip = packet_db_entry.source_ip
        dst_ip = packet_db_entry.destination_ip

        # --- Rule 1: TCP Port Scan Detection (Existing Rule) ---
        # Detects hosts scanning multiple unique ports
        if packet_db_entry.protocol == "TCP" and scapy_pkt.haslayer("TCP") and scapy_pkt.haslayer("IP"):
            dst_port = scapy_pkt["TCP"].dport
            if src_ip:
                if src_ip not in self.port_scan_tracker:
                    self.port_scan_tracker[src_ip] = set()
                
                self.port_scan_tracker[src_ip].add(dst_port)
                
                if len(self.port_scan_tracker[src_ip]) > self.PORT_SCAN_THRESHOLD:
                    if self._should_alert(src_ip, "Port Scan Detected", cooldown_secs=30):
                        alerts.append(AlertLog(
                            rule_name="Port Scan Detected",
                            severity="High",
                            description=f"Host {src_ip} attempted connections to {len(self.port_scan_tracker[src_ip])} different ports.",
                            timestamp=now_time
                        ))
                    # Reset tracker to start clean for next window
                    self.port_scan_tracker[src_ip] = set()

        # --- Rule 2: Large Payload Detection (Existing Rule, added throttling) ---
        # Flagging packet lengths exceeding 1400 bytes (potential data exfiltration)
        if packet_db_entry.length > 1400:
            if self._should_alert(src_ip, "Large Packet Size Alert", cooldown_secs=60):
                alerts.append(AlertLog(
                    rule_name="Large Packet Size Alert",
                    severity="Low",
                    description=f"Large payload detected ({packet_db_entry.length} bytes) from {src_ip} to {dst_ip}.",
                    timestamp=now_time
                ))

        # --- Rule 3: Insecure Protocol Usage (Existing Rule, added throttling) ---
        # Flagging unencrypted Telnet traffic (TCP Port 23)
        if scapy_pkt.haslayer("TCP") and (scapy_pkt["TCP"].sport == 23 or scapy_pkt["TCP"].dport == 23):
            if self._should_alert(src_ip, "Insecure Protocol Usage (Telnet)", cooldown_secs=60):
                alerts.append(AlertLog(
                    rule_name="Insecure Protocol Usage",
                    severity="Medium",
                    description=f"Unencrypted Telnet traffic (TCP Port 23) detected between {src_ip} and {dst_ip}.",
                    timestamp=now_time
                ))

        # --- Rule 4: ICMP Flood Detection (New Rule) ---
        # Detect more than 50 ICMP packets from the same source within 30 seconds
        if packet_db_entry.protocol == "ICMP" and scapy_pkt.haslayer("ICMP") and src_ip:
            if src_ip not in self.icmp_tracker:
                self.icmp_tracker[src_ip] = []
            
            # Prune timestamps older than 30 seconds
            self.icmp_tracker[src_ip] = [t for t in self.icmp_tracker[src_ip] if (now_time - t).total_seconds() <= self.ICMP_WINDOW_SECS]
            self.icmp_tracker[src_ip].append(now_time)

            if len(self.icmp_tracker[src_ip]) > self.ICMP_FLOOD_LIMIT:
                if self._should_alert(src_ip, "ICMP Flood Detected", cooldown_secs=30):
                    alerts.append(AlertLog(
                        rule_name="ICMP Flood Detected",
                        severity="High",
                        description=f"Potential Denial of Service (DoS): Host {src_ip} sent {len(self.icmp_tracker[src_ip])} ICMP packets within {self.ICMP_WINDOW_SECS} seconds.",
                        timestamp=now_time
                    ))
                # Clear tracker after alerting to prevent immediate duplicate logs
                self.icmp_tracker[src_ip] = []

        # --- Rule 5: Suspicious Port Detection (New Rule) ---
        # Detect traffic involving malware or trojan ports (4444, 5555, 6667, 1337, 31337)
        has_suspicious_port = False
        susp_port = None
        susp_reason = ""
        susp_severity = "High"

        if scapy_pkt.haslayer("TCP"):
            sport, dport = scapy_pkt["TCP"].sport, scapy_pkt["TCP"].dport
            if sport in self.SUSPICIOUS_PORTS:
                has_suspicious_port, susp_port = True, sport
            elif dport in self.SUSPICIOUS_PORTS:
                has_suspicious_port, susp_port = True, dport
        elif scapy_pkt.haslayer("UDP"):
            sport, dport = scapy_pkt["UDP"].sport, scapy_pkt["UDP"].dport
            if sport in self.SUSPICIOUS_PORTS:
                has_suspicious_port, susp_port = True, sport
            elif dport in self.SUSPICIOUS_PORTS:
                has_suspicious_port, susp_port = True, dport

        if has_suspicious_port:
            susp_reason, susp_severity = self.SUSPICIOUS_PORTS[susp_port]
            # Suppress matching alert types to once every 60 seconds per IP pair and port
            alert_key = f"Suspicious Port {susp_port}"
            if self._should_alert(src_ip, alert_key, cooldown_secs=60):
                alerts.append(AlertLog(
                    rule_name="Suspicious Port Traffic",
                    severity=susp_severity,
                    description=f"Traffic involving suspicious port {susp_port} ({susp_reason}) detected between {src_ip} and {dst_ip}.",
                    timestamp=now_time
                ))

        # --- Rule 6: DNS Tunneling Detection (New Rule) ---
        # Detect DNS queries longer than 50 characters (potential command-and-control exfiltration)
        if scapy_pkt.haslayer("DNSQR") and src_ip:
            try:
                qname = scapy_pkt["DNSQR"].qname
                if qname:
                    qname_str = qname.decode('utf-8', errors='ignore')
                    # Strip trailing DNS root dot
                    if qname_str.endswith('.'):
                        qname_str = qname_str[:-1]
                    
                    if len(qname_str) > 50:
                        if self._should_alert(src_ip, "DNS Tunneling Detected", cooldown_secs=30):
                            alerts.append(AlertLog(
                                rule_name="DNS Tunneling Detected",
                                severity="Critical",
                                description=f"Covert channel threat: Host {src_ip} queried abnormal DNS name length ({len(qname_str)} chars): '{qname_str[:60]}...'",
                                timestamp=now_time
                            ))
            except Exception:
                pass  # Robust processing to prevent parser crash

        # --- Rule 7: Excessive Connection Attempts (New Rule) ---
        # Detect more than 30 TCP SYN packets (connection attempts) from the same IP within 60 seconds
        if scapy_pkt.haslayer("TCP") and src_ip:
            flags = scapy_pkt["TCP"].flags
            # TCP SYN flag set, and ACK flag not set (initial connection handshake attempt)
            is_syn_attempt = ("S" in flags) and ("A" not in flags)
            
            if is_syn_attempt:
                if src_ip not in self.tcp_conn_tracker:
                    self.tcp_conn_tracker[src_ip] = []
                
                # Prune timestamps older than 60 seconds
                self.tcp_conn_tracker[src_ip] = [t for t in self.tcp_conn_tracker[src_ip] if (now_time - t).total_seconds() <= self.TCP_WINDOW_SECS]
                self.tcp_conn_tracker[src_ip].append(now_time)

                if len(self.tcp_conn_tracker[src_ip]) > self.TCP_CONN_LIMIT:
                    if self._should_alert(src_ip, "Excessive Connection Attempts", cooldown_secs=60):
                        alerts.append(AlertLog(
                            rule_name="Excessive Connection Attempts",
                            severity="High",
                            description=f"Potential port sweep/DoS: Host {src_ip} generated {len(self.tcp_conn_tracker[src_ip])} TCP connection attempts within {self.TCP_WINDOW_SECS} seconds.",
                            timestamp=now_time
                        ))
                    # Clear tracker after alerting to prevent immediate duplicate logs
                    self.tcp_conn_tracker[src_ip] = []

        return alerts
