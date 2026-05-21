/**
 * HADES Dashboard — Chart.js with Green Palette
 */
document.addEventListener('DOMContentLoaded', () => {
    const COLORS = {
        greenLight: '#B0E4CC',
        greenBright: '#408A71',
        greenMid: '#285A48',
        greenDark: '#091413',
        red: '#ff6b6b',
        purple: '#a29bfe',
        orange: '#ffa94d',
        yellow: '#ffd43b',
        pink: '#f783ac',
        blue: '#74c0fc',
    };

    const CATEGORY_COLORS = {
        'DOS+DDOS': COLORS.red,
        'BOTNET': COLORS.purple,
        'INFILTRATION': COLORS.orange,
        'WEB_ATTACKS': COLORS.pink,
        'BRUTE_FORCE': COLORS.yellow,
    };

    const SEVERITY_COLORS = {
        'info': COLORS.blue,
        'low': COLORS.greenBright,
        'medium': COLORS.orange,
        'high': COLORS.pink,
        'critical': COLORS.red,
    };

    // Global Chart.js defaults
    Chart.defaults.color = '#8fb8a8';
    Chart.defaults.font.family = "'Inter', sans-serif";
    Chart.defaults.plugins.legend.labels.usePointStyle = true;
    Chart.defaults.plugins.legend.labels.padding = 16;

    // ─── Category Distribution (Doughnut) ───
    fetch('/api/attack-distribution')
        .then(r => r.json())
        .then(data => {
            const ctx = document.getElementById('categoryChart');
            if (!ctx || Object.keys(data).length === 0) {
                if (ctx) showEmpty(ctx, 'No attack data yet');
                return;
            }
            new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: Object.keys(data),
                    datasets: [{
                        data: Object.values(data),
                        backgroundColor: Object.keys(data).map(k => CATEGORY_COLORS[k] || COLORS.greenLight),
                        borderColor: '#091413',
                        borderWidth: 3,
                        hoverOffset: 8,
                    }]
                },
                options: {
                    responsive: true, maintainAspectRatio: false, cutout: '65%',
                    plugins: {
                        legend: { position: 'bottom' },
                        tooltip: {
                            backgroundColor: 'rgba(9, 20, 19, 0.95)',
                            borderColor: 'rgba(64, 138, 113, 0.3)',
                            borderWidth: 1,
                        }
                    },
                    animation: { animateRotate: true, duration: 1500 },
                }
            });
        });

    // ─── Severity Distribution (Doughnut) ───
    fetch('/api/severity-distribution')
        .then(r => r.json())
        .then(data => {
            const ctx = document.getElementById('severityChart');
            if (!ctx || Object.keys(data).length === 0) {
                if (ctx) showEmpty(ctx, 'No severity data yet');
                return;
            }
            new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: Object.keys(data).map(s => s.toUpperCase()),
                    datasets: [{
                        data: Object.values(data),
                        backgroundColor: Object.keys(data).map(k => SEVERITY_COLORS[k] || '#666'),
                        borderColor: '#091413',
                        borderWidth: 3,
                    }]
                },
                options: {
                    responsive: true, maintainAspectRatio: false, cutout: '65%',
                    plugins: { legend: { position: 'bottom' } },
                    animation: { animateRotate: true, duration: 1500 },
                }
            });
        });

    // ─── Specific Attacks (Horizontal Bar) ───
    fetch('/api/specific-attacks')
        .then(r => r.json())
        .then(data => {
            const ctx = document.getElementById('specificChart');
            if (!ctx || Object.keys(data).length === 0) {
                if (ctx) showEmpty(ctx, 'No specific attack data yet');
                return;
            }
            const barColors = [COLORS.greenLight, COLORS.greenBright, COLORS.red, COLORS.purple, COLORS.orange, COLORS.pink, COLORS.yellow, COLORS.blue];
            new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: Object.keys(data),
                    datasets: [{
                        label: 'Detections',
                        data: Object.values(data),
                        backgroundColor: Object.keys(data).map((_, i) => barColors[i % barColors.length] + '44'),
                        borderColor: Object.keys(data).map((_, i) => barColors[i % barColors.length]),
                        borderWidth: 1, borderRadius: 4,
                    }]
                },
                options: {
                    responsive: true, maintainAspectRatio: false, indexAxis: 'y',
                    plugins: { legend: { display: false } },
                    scales: {
                        x: { ticks: { color: '#8fb8a8' }, grid: { color: 'rgba(64,138,113,0.08)' } },
                        y: { ticks: { color: '#8fb8a8', font: { size: 11 } }, grid: { display: false } }
                    },
                    animation: { duration: 1200 },
                }
            });
        });

    // ─── Timeline (Line Chart) ───
    fetch('/api/timeline')
        .then(r => r.json())
        .then(data => {
            const ctx = document.getElementById('timelineChart');
            if (!ctx || data.length === 0) {
                if (ctx) showEmpty(ctx, 'No timeline data yet');
                return;
            }
            new Chart(ctx, {
                type: 'line',
                data: {
                    labels: data.map(d => d.date),
                    datasets: [
                        {
                            label: 'Scans',
                            data: data.map(d => d.scans),
                            borderColor: COLORS.greenBright,
                            backgroundColor: COLORS.greenBright + '22',
                            fill: true, tension: 0.4,
                            pointRadius: 4, pointHoverRadius: 6,
                            pointBackgroundColor: COLORS.greenBright,
                        },
                        {
                            label: 'Anomalies',
                            data: data.map(d => d.anomalies),
                            borderColor: COLORS.red,
                            backgroundColor: COLORS.red + '18',
                            fill: true, tension: 0.4,
                            pointRadius: 4, pointHoverRadius: 6,
                            pointBackgroundColor: COLORS.red,
                        }
                    ]
                },
                options: {
                    responsive: true, maintainAspectRatio: false,
                    plugins: {
                        legend: { position: 'top' },
                        tooltip: {
                            backgroundColor: 'rgba(9, 20, 19, 0.95)',
                            borderColor: 'rgba(64, 138, 113, 0.3)',
                            borderWidth: 1,
                        }
                    },
                    scales: {
                        x: { ticks: { color: '#8fb8a8' }, grid: { color: 'rgba(64,138,113,0.08)' } },
                        y: { ticks: { color: '#8fb8a8' }, grid: { color: 'rgba(64,138,113,0.08)' }, beginAtZero: true }
                    },
                    animation: { duration: 1500 },
                }
            });
        });

    // ─── Utility ───
    function showEmpty(canvas, msg) {
        const p = canvas.parentElement;
        p.innerHTML = `<div style="display:flex;align-items:center;justify-content:center;height:100%;color:#5a8a78;font-size:0.85rem;font-style:italic;">${msg}</div>`;
    }

    // ─── Animated stat counters ───
    document.querySelectorAll('.stat-value').forEach(el => {
        const text = el.textContent.trim();
        if (!/^\d+$/.test(text)) return;
        const target = parseInt(text);
        if (isNaN(target) || target === 0) return;
        let current = 0;
        const step = Math.max(1, Math.floor(target / 40));
        const timer = setInterval(() => {
            current += step;
            if (current >= target) {
                el.textContent = target.toLocaleString();
                clearInterval(timer);
            } else {
                el.textContent = current.toLocaleString();
            }
        }, 30);
    });
});
