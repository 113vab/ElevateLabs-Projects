"""
app.py
Purpose: Main Flask web application server for ASTRAVA.
Serves UI templates (dashboard, live traffic logs, threat alerts) and API endpoints.
Spawns the packet sniffer thread automatically on startup.
"""
import os
from flask import Flask, render_template, jsonify, request
from database import engine, Base, SessionLocal
from models import PacketLog, AlertLog
from sniffer import PacketSniffer

app = Flask(__name__)

# Create all database tables if they do not exist
Base.metadata.create_all(bind=engine)

# Global tracker for the sniffer thread
sniffer_thread = None

@app.before_request
def start_sniffer():
    """Starts the packet sniffer background thread once before any request."""
    global sniffer_thread
    if sniffer_thread is None:
        # Note: Interface=None defaults to Scapy's default sniffing interface.
        # Run app as Administrator/Root to enable socket operations.
        sniffer_thread = PacketSniffer(interface=None)
        sniffer_thread.start()

@app.route('/')
def dashboard():
    """Renders the main network analytics dashboard."""
    db = SessionLocal()
    try:
        total_packets = db.query(PacketLog).count()
        total_alerts = db.query(AlertLog).count()
        high_alerts = db.query(AlertLog).filter(AlertLog.severity.in_(['High', 'Critical'])).count()

        latest_packets = db.query(PacketLog).order_by(PacketLog.id.desc()).limit(10).all()
        latest_alerts = db.query(AlertLog).order_by(AlertLog.id.desc()).limit(10).all()

        return render_template(
            'index.html',
            total_packets=total_packets,
            total_alerts=total_alerts,
            high_alerts=high_alerts,
            latest_packets=latest_packets,
            latest_alerts=latest_alerts
        )
    finally:
        db.close()

@app.route('/packets')
def packets_page():
    """Renders the historical list of packets captured (latest 100)."""
    db = SessionLocal()
    try:
        packets = db.query(PacketLog).order_by(PacketLog.id.desc()).limit(100).all()
        return render_template('packets.html', packets=packets)
    finally:
        db.close()

@app.route('/alerts')
def alerts_page():
    """Renders the triggered alerts history list (latest 100)."""
    db = SessionLocal()
    try:
        alerts = db.query(AlertLog).order_by(AlertLog.id.desc()).limit(100).all()
        return render_template('alerts.html', alerts=alerts)
    finally:
        db.close()

@app.route('/api/stats')
def api_stats():
    """API endpoint providing real-time data for charts, feeds, and SOC indicators."""
    db = SessionLocal()
    try:
        from sqlalchemy import func
        from datetime import datetime, timedelta

        # 1. Count packet logs grouped by protocol type
        proto_counts = db.query(PacketLog.protocol, func.count(PacketLog.id)).group_by(PacketLog.protocol).all()
        protocols = {proto: count for proto, count in proto_counts if proto is not None}

        # 2. Count security alerts grouped by severity level
        severity_counts = db.query(AlertLog.severity, func.count(AlertLog.id)).group_by(AlertLog.severity).all()
        severities = {sev: count for sev, count in severity_counts if sev is not None}

        # 3. Compute current threat level based on alert counts in the last 60 seconds
        recent_cutoff = datetime.utcnow() - timedelta(seconds=60)
        recent_alert_count = db.query(AlertLog).filter(AlertLog.timestamp >= recent_cutoff).count()
        
        if recent_alert_count == 0:
            threat_level = "STABLE"
        elif recent_alert_count <= 3:
            threat_level = "GUARDED"
        elif recent_alert_count <= 10:
            threat_level = "ELEVATED"
        elif recent_alert_count <= 25:
            threat_level = "SEVERE"
        else:
            threat_level = "CRITICAL"

        # 4. Identify Top Threat Sources (IP addresses generating the most alerts)
        top_sources = db.query(
            PacketLog.source_ip,
            func.count(AlertLog.id).label('alert_count'),
            func.max(AlertLog.severity).label('max_severity')
        ).join(
            AlertLog, AlertLog.packet_id == PacketLog.id
        ).group_by(
            PacketLog.source_ip
        ).order_by(
            func.count(AlertLog.id).desc()
        ).limit(5).all()

        top_sources_list = [{
            'ip': ip,
            'count': count,
            'severity': max_sev
        } for ip, count, max_sev in top_sources if ip is not None]

        # 5. Alerts count trend line over the last 10 minutes (1-minute intervals)
        now = datetime.utcnow()
        time_labels = []
        alert_counts_over_time = []
        for i in range(9, -1, -1):
            start = now - timedelta(minutes=i+1)
            end = now - timedelta(minutes=i)
            count = db.query(AlertLog).filter(AlertLog.timestamp >= start, AlertLog.timestamp < end).count()
            time_labels.append(end.strftime('%H:%M'))
            alert_counts_over_time.append(count)

        # 6. Live feeds (Latest 20 packets and alerts)
        packets = db.query(PacketLog).order_by(PacketLog.id.desc()).limit(20).all()
        latest_packets_list = [{
            'id': p.id,
            'timestamp': p.timestamp.strftime('%H:%M:%S'),
            'protocol': p.protocol,
            'source_ip': p.source_ip,
            'destination_ip': p.destination_ip,
            'length': p.length,
            'info': p.info
        } for p in packets]

        alerts = db.query(AlertLog).order_by(AlertLog.id.desc()).limit(20).all()
        latest_alerts_list = [{
            'id': a.id,
            'timestamp': a.timestamp.strftime('%H:%M:%S'),
            'rule_name': a.rule_name,
            'severity': a.severity,
            'description': a.description,
            'packet_id': a.packet_id,
            'packet_protocol': a.packet.protocol if a.packet else 'N/A'
        } for a in alerts]

        return jsonify({
            'protocols': protocols,
            'severities': severities,
            'threat_level': threat_level,
            'top_sources': top_sources_list,
            'alerts_over_time': {
                'labels': time_labels,
                'counts': alert_counts_over_time
            },
            'latest_packets': latest_packets_list,
            'latest_alerts': latest_alerts_list
        })
    finally:
        db.close()

@app.route('/api/clear', methods=['POST'])
def clear_logs():
    """API endpoint to wipe all logs from the database."""
    db = SessionLocal()
    try:
        db.query(AlertLog).delete()
        db.query(PacketLog).delete()
        db.commit()
        return jsonify({'status': 'success', 'message': 'Database logged data cleared.'})
    except Exception as e:
        db.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        db.close()

if __name__ == '__main__':
    # use_reloader=False is critical to prevent the reloader from spawning two sniffer threads.
    print("[*] Starting ASTRAVA - Cyber Threat Detection & Monitoring Platform on http://127.0.0.1:5000")
    app.run(host='127.0.0.1', port=5000, debug=True, use_reloader=False)
