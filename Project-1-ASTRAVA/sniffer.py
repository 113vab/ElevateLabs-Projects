"""
sniffer.py
Purpose: Handles asynchronous network packet sniffing using Scapy.
Runs inside a daemonized thread, processes incoming packets, extracts metadata,
calls the ThreatDetector, and saves results to the database.
"""
import threading
import time
from scapy.all import sniff, IP, TCP, UDP, ICMP
from database import SessionLocal
from models import PacketLog
from detector import ThreatDetector

class PacketSniffer(threading.Thread):
    """
    Background worker thread that runs Scapy's sniff loop.
    """
    def __init__(self, interface=None):
        super().__init__()
        self.interface = interface
        self.stop_event = threading.Event()
        self.detector = ThreatDetector()
        self.daemon = True  # Allows program to exit even if this thread is running

    def stop(self):
        """Instructs the sniffing loop to terminate."""
        self.stop_event.set()

    def packet_callback(self, pkt):
        """
        Invoked for every packet captured. Extracts layers and commits data to SQLite.
        """
        # Focus on IP packets to log source and destination
        if pkt.haslayer(IP):
            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            proto = ip_layer.proto
            length = len(pkt)
            
            # Map protocols to readable strings
            proto_name = "IP"
            if pkt.haslayer(TCP):
                proto_name = "TCP"
            elif pkt.haslayer(UDP):
                proto_name = "UDP"
            elif pkt.haslayer(ICMP):
                proto_name = "ICMP"
            else:
                proto_name = f"Proto-{proto}"

            info = pkt.summary()

            # Create a database session to record the packet
            db = SessionLocal()
            try:
                db_packet = PacketLog(
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    protocol=proto_name,
                    length=length,
                    info=info
                )
                db.add(db_packet)
                db.commit()
                db.refresh(db_packet)

                # Process the packet through threat detection rules
                alerts = self.detector.analyze_packet(db_packet, pkt)
                for alert in alerts:
                    alert.packet_id = db_packet.id
                    db.add(alert)
                
                if alerts:
                    db.commit()
            except Exception as e:
                db.rollback()
                print(f"[Sniffer Error] Database write failed: {e}")
            finally:
                db.close()

    def run(self):
        print(f"[+] Starting packet sniffer thread on interface: {self.interface or 'Default'}")
        
        # Keep sniffing in chunks to allow check of stop_event
        while not self.stop_event.is_set():
            try:
                sniff(
                    iface=self.interface,
                    prn=self.packet_callback,
                    store=False,
                    timeout=1  # Checks for stop_event every 1 second
                )
            except Exception as e:
                print(f"[-] Sniffer encountered an error: {e}")
                print("[!] Note: On Windows, Scapy requires Npcap/WinPcap installed and Admin rights.")
                time.sleep(5)  # Rest before retrying
        
        print("[*] Packet sniffer thread stopped.")
