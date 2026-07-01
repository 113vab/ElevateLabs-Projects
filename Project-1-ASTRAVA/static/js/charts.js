/**
 * charts.js
 * Purpose: Handles client-side API requests to fetch traffic stats
 * and renders interactive Chart.js visualizations (protocol share, alert distribution, timeline).
 * Updates live activity feeds and threat dials in real time.
 */

document.addEventListener('DOMContentLoaded', function () {
    const protocolCtx = document.getElementById('protocolChart');
    const severityCtx = document.getElementById('severityChart');
    const timelineCtx = document.getElementById('timelineChart');

    if (!protocolCtx || !severityCtx || !timelineCtx) return;

    let protocolChart = null;
    let severityChart = null;
    let timelineChart = null;

    // Custom Chart.js Defaults for Dark Mode compatibility
    Chart.defaults.color = '#9ca3af';
    Chart.defaults.borderColor = 'rgba(255, 255, 255, 0.05)';
    Chart.defaults.font.family = 'Outfit, sans-serif';

    function updateSOCDashboard() {
        fetch('/api/stats')
            .then(response => response.json())
            .then(data => {
                // 1. Update Core Metric Counters
                const highCount = data.severities.High || 0;
                const criticalCount = data.severities.Critical || 0;
                const totalAlerts = Object.values(data.severities).reduce((a, b) => a + b, 0);
                const totalPackets = Object.values(data.protocols).reduce((a, b) => a + b, 0);

                document.getElementById('countPackets').innerText = totalPackets;
                document.getElementById('countAlerts').innerText = totalAlerts;
                document.getElementById('countCritical').innerText = (highCount + criticalCount);

                // 2. Update System Threat Level Dial
                const threatDial = document.getElementById('threatDial');
                const threatIcon = document.getElementById('threatIcon');
                const threatValue = document.getElementById('threatValue');
                const threatDesc = document.getElementById('threatDesc');

                // Remove existing threat status classes
                threatDial.className = 'threat-dial-container';
                
                const level = data.threat_level;
                threatValue.innerText = level;

                if (level === 'STABLE') {
                    threatDial.classList.add('threat-status-STABLE');
                    threatIcon.className = 'bi bi-shield-check fs-1';
                    threatDesc.innerText = 'NO THREAT SIGNATURES DETECTED';
                } else if (level === 'GUARDED') {
                    threatDial.classList.add('threat-status-GUARDED');
                    threatIcon.className = 'bi bi-info-circle fs-1';
                    threatDesc.innerText = 'LOW LEVEL THREAT DETECTED';
                } else if (level === 'ELEVATED') {
                    threatDial.classList.add('threat-status-ELEVATED');
                    threatIcon.className = 'bi bi-exclamation-circle fs-1';
                    threatDesc.innerText = 'SUSPICIOUS SYSTEM ACTIVITY';
                } else if (level === 'SEVERE') {
                    threatDial.classList.add('threat-status-SEVERE');
                    threatIcon.className = 'bi bi-exclamation-triangle fs-1';
                    threatDesc.innerText = 'MULTIPLE HOST THREATS IGNORED';
                } else if (level === 'CRITICAL') {
                    threatDial.classList.add('threat-status-CRITICAL');
                    threatIcon.className = 'bi bi-radioactive fs-1';
                    threatDesc.innerText = 'ACTIVE ATTACK / CRITICAL SIGNATURE FIRED';
                }

                // 3. Render Timeline Line Chart (Alerts Trend)
                if (timelineChart) {
                    timelineChart.destroy();
                }
                timelineChart = new Chart(timelineCtx, {
                    type: 'line',
                    data: {
                        labels: data.alerts_over_time.labels,
                        datasets: [{
                            label: 'Intrusions / Min',
                            data: data.alerts_over_time.counts,
                            fill: true,
                            backgroundColor: 'rgba(6, 182, 212, 0.1)',
                            borderColor: '#06b6d4',
                            borderWidth: 2,
                            tension: 0.4,
                            pointBackgroundColor: '#06b6d4',
                            pointHoverRadius: 6
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: { legend: { display: false } },
                        scales: {
                            y: {
                                beginAtZero: true,
                                ticks: { stepSize: 1 }
                            }
                        }
                    }
                });

                // 4. Render Protocol Share Doughnut Chart
                const protoLabels = Object.keys(data.protocols);
                const protoValues = Object.values(data.protocols);
                if (protocolChart) {
                    protocolChart.destroy();
                }
                protocolChart = new Chart(protocolCtx, {
                    type: 'doughnut',
                    data: {
                        labels: protoLabels,
                        datasets: [{
                            data: protoValues,
                            backgroundColor: ['#3b82f6', '#06b6d4', '#10b981', '#f59e0b', '#8b5cf6', '#ec4899'],
                            borderWidth: 1,
                            borderColor: '#111827'
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                position: 'bottom',
                                labels: { boxWidth: 12, padding: 8 }
                            }
                        }
                    }
                });

                // 5. Render Severity Spread Bar Chart
                const severityLabels = Object.keys(data.severities);
                const severityValues = Object.values(data.severities);
                if (severityChart) {
                    severityChart.destroy();
                }
                severityChart = new Chart(severityCtx, {
                    type: 'bar',
                    data: {
                        labels: severityLabels,
                        datasets: [{
                            data: severityValues,
                            backgroundColor: severityLabels.map(lbl => {
                                const l = lbl.toLowerCase();
                                if (l === 'critical') return '#f43f5e';
                                if (l === 'high') return '#ef4444';
                                if (l === 'medium') return '#f59e0b';
                                return '#3b82f6';
                            }),
                            borderRadius: 4
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: { legend: { display: false } },
                        scales: {
                            y: {
                                beginAtZero: true,
                                ticks: { stepSize: 1 }
                            }
                        }
                    }
                });

                // 6. Update Live Packet Activity Feed
                const packetFeed = document.getElementById('packetFeed');
                if (data.latest_packets.length === 0) {
                    packetFeed.innerHTML = '<div class="text-center py-5">Listening for active network sockets...</div>';
                } else {
                    let packetHtml = '';
                    data.latest_packets.forEach(p => {
                        packetHtml += `
                            <div class="feed-item">
                                <div class="feed-item-meta">
                                    <span class="text-info">[${p.timestamp}]</span>
                                    <span class="badge bg-secondary">${p.protocol}</span>
                                    <span class="text-light">${p.source_ip}</span>
                                    <i class="bi bi-arrow-right text-muted"></i>
                                    <span class="text-light">${p.destination_ip}</span>
                                </div>
                                <span class="text-secondary mono-text fs-8">${p.length} B</span>
                            </div>
                        `;
                    });
                    packetFeed.innerHTML = packetHtml;
                }

                // 7. Update Live Security Alerts Feed
                const alertFeed = document.getElementById('alertFeed');
                if (data.latest_alerts.length === 0) {
                    alertFeed.innerHTML = '<div class="text-center py-5 text-success"><i class="bi bi-shield-check me-1"></i>No threats flagged. System secure.</div>';
                } else {
                    let alertHtml = '';
                    data.latest_alerts.forEach(a => {
                        let badgeClass = 'badge-severity-low';
                        const s = a.severity.toLowerCase();
                        if (s === 'critical') badgeClass = 'badge-severity-critical';
                        else if (s === 'high') badgeClass = 'badge-severity-high';
                        else if (s === 'medium') badgeClass = 'badge-severity-medium';

                        alertHtml += `
                            <div class="feed-item ${s === 'critical' ? 'bg-danger bg-opacity-10 border-start border-danger border-2' : ''}">
                                <div class="d-flex flex-column gap-1">
                                    <div class="d-flex align-items-center gap-2">
                                        <span class="text-danger font-monospace">[${a.timestamp}]</span>
                                        <span class="fw-bold text-light">${a.rule_name}</span>
                                    </div>
                                    <span class="text-secondary fs-8">${a.description}</span>
                                </div>
                                <span class="badge ${badgeClass} text-uppercase font-monospace px-2 py-1">${a.severity}</span>
                            </div>
                        `;
                    });
                    alertFeed.innerHTML = alertHtml;
                }

                // 8. Update Top Threat Sources Table
                const topSourcesBody = document.getElementById('topSourcesBody');
                if (data.top_sources.length === 0) {
                    topSourcesBody.innerHTML = `
                        <tr>
                            <td colspan="3" class="text-center text-secondary py-5 font-monospace">No threats mapped to source IPs yet.</td>
                        </tr>
                    `;
                } else {
                    let sourcesHtml = '';
                    data.top_sources.forEach(src => {
                        let badgeClass = 'badge-severity-low';
                        const s = src.severity.toLowerCase();
                        if (s === 'critical') badgeClass = 'badge-severity-critical';
                        else if (s === 'high') badgeClass = 'badge-severity-high';
                        else if (s === 'medium') badgeClass = 'badge-severity-medium';

                        sourcesHtml += `
                            <tr>
                                <td class="mono-text fw-bold text-light">${src.ip}</td>
                                <td class="mono-text text-center text-warning fw-bold">${src.count}</td>
                                <td class="text-end">
                                    <span class="badge ${badgeClass} text-uppercase font-monospace">${src.severity}</span>
                                </td>
                            </tr>
                        `;
                    });
                    topSourcesBody.innerHTML = sourcesHtml;
                }
            })
            .catch(err => console.error("[SOC Error] Dashboard update failed:", err));
    }

    // Initial load
    updateSOCDashboard();

    // Auto refresh every 3 seconds to feel truly "live" in a security center context
    setInterval(updateSOCDashboard, 3000);

    // Bind Clear Button
    const clearBtn = document.getElementById('clearLogsBtn');
    if (clearBtn) {
        clearBtn.addEventListener('click', function () {
            if (confirm("Are you sure you want to clear all logged packets and alerts? This action is irreversible.")) {
                fetch('/api/clear', { method: 'POST' })
                    .then(response => response.json())
                    .then(res => {
                        if (res.status === 'success') {
                            alert(res.message);
                            location.reload();
                        } else {
                            alert("Failed to clear logs: " + res.message);
                        }
                    })
                    .catch(err => console.error("Error clearing logs:", err));
            }
        });
    }
});
