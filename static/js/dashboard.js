const refreshButton = document.getElementById('refreshButton');
const refreshStatus = document.getElementById('refreshStatus');
const healthScore = document.getElementById('healthScore');
const healthLabel = document.getElementById('healthLabel');
const vpnState = document.getElementById('vpnState');
const vpnBadge = document.getElementById('vpnBadge');
const deviceCount = document.getElementById('deviceCount');
const portCount = document.getElementById('portCount');
const cveCount = document.getElementById('cveCount');
const localIp = document.getElementById('localIp');
const publicIp = document.getElementById('publicIp');
const wifiName = document.getElementById('wifiName');
const vpnInterface = document.getElementById('vpnInterface');
const lastUpdated = document.getElementById('lastUpdated');
const portsTable = document.getElementById('portsTable');
const cvesTable = document.getElementById('cvesTable');
const devicesTable = document.getElementById('devicesTable');

let riskChart;

const riskLabels = ['High risk ports', 'Medium risk ports', 'Low risk ports', 'Critical CVEs'];

function formatDateTime(isoString) {
  if (!isoString) return '—';
  const date = new Date(isoString);
  return date.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function getBadgeClass(score) {
  if (score >= 80) return 'badge-good';
  if (score >= 55) return 'badge-warning';
  return 'badge-danger';
}

function buildTable(rows, header) {
  return `
    <table>
      <thead>
        <tr>${header.map(col => `<th>${col}</th>`).join('')}</tr>
      </thead>
      <tbody>
        ${rows.join('')}
      </tbody>
    </table>
  `;
}

function renderPorts(ports) {
  if (!ports.length) {
    return '<p class="status-text">No open ports found or lsof could not run.</p>';
  }
  const rows = ports.map(port => `
    <tr>
      <td>${port.port}</td>
      <td>${port.process}</td>
      <td>${port.type}</td>
      <td><span class="badge ${port.risk === 'high' ? 'badge-danger' : port.risk === 'medium' ? 'badge-warning' : 'badge-good'}">${port.risk}</span></td>
    </tr>
  `);
  return buildTable(rows, ['Port', 'Process', 'Type', 'Risk']);
}

function renderCves(cves) {
  if (!cves.length) {
    return '<p class="status-text">No critical CVEs found in the last 48 hours.</p>';
  }
  const rows = cves.map(cve => `
    <tr>
      <td><a href="${cve.url}" target="_blank" rel="noreferrer">${cve.id}</a></td>
      <td>${cve.score}</td>
      <td>${cve.published}</td>
      <td>${cve.description}</td>
    </tr>
  `);
  return buildTable(rows, ['CVE', 'Score', 'Published', 'Description']);
}

function renderDevices(devices) {
  if (!devices.length) {
    return '<p class="status-text">No scanner device data available. Run scanner.py and save results to the Argus data path.</p>';
  }
  const rows = devices.map(device => `
    <tr>
      <td>${device.hostname || 'Unknown'}</td>
      <td>${device.ip || '—'}</td>
      <td>${device.mac || '—'}</td>
      <td>${device.vendor || 'Unknown'}</td>
    </tr>
  `);
  return buildTable(rows, ['Hostname', 'IP', 'MAC', 'Vendor']);
}

function updateRiskChart(data) {
  const high = data.ports.filter(p => p.risk === 'high').length;
  const medium = data.ports.filter(p => p.risk === 'medium').length;
  const low = data.ports.filter(p => p.risk === 'low').length;
  const critical = data.cves.length;

  const chartData = [high, medium, low, critical];
  if (!riskChart) {
    const ctx = document.getElementById('riskChart').getContext('2d');
    riskChart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: riskLabels,
        datasets: [{
          label: 'Risk overview',
          data: chartData,
          backgroundColor: ['#ff6b6b', '#ffd60a', '#30d158', '#5ac8fa'],
          borderRadius: 999,
          borderSkipped: false,
        }]
      },
      options: {
        responsive: true,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { display: false }, ticks: { color: '#b6c6d3' } },
          y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.08)' }, ticks: { color: '#b6c6d3' } }
        }
      }
    });
  } else {
    riskChart.data.datasets[0].data = chartData;
    riskChart.update();
  }
}

async function refreshDashboard() {
  refreshStatus.textContent = 'Refreshing…';
  try {
    const response = await fetch('/api/data');
    const data = await response.json();

    healthScore.textContent = `${data.health.score} / 100`;
    healthLabel.textContent = data.health.label;
    healthLabel.className = `status-text ${getBadgeClass(data.health.score)}`;

    vpnState.textContent = data.network.vpn ? 'Connected' : 'Off';
    vpnBadge.className = `badge ${data.network.vpn ? 'badge-good' : 'badge-danger'}`;
    vpnBadge.textContent = data.network.vpn ? 'Active' : 'Inactive';

    deviceCount.textContent = data.devices.length;
    portCount.textContent = data.ports.length;
    cveCount.textContent = data.cves.length;

    localIp.textContent = data.network.local_ip || 'Unknown';
    publicIp.textContent = data.network.public_ip || 'Unknown';
    wifiName.textContent = data.network.wifi || 'Unknown';
    vpnInterface.textContent = data.network.interface || 'Auto-detected';

    portsTable.innerHTML = renderPorts(data.ports);
    cvesTable.innerHTML = renderCves(data.cves);
    devicesTable.innerHTML = renderDevices(data.devices);

    updateRiskChart(data);
    lastUpdated.textContent = `Updated ${formatDateTime(data.generated_at)}`;
    refreshStatus.textContent = 'Live';
  } catch (error) {
    refreshStatus.textContent = 'Failed';
    portsTable.innerHTML = '<p class="status-text">Unable to load dashboard data.</p>';
    cvesTable.innerHTML = '<p class="status-text">Unable to load dashboard data.</p>';
    devicesTable.innerHTML = '<p class="status-text">Unable to load dashboard data.</p>';
  }
}

refreshButton.addEventListener('click', refreshDashboard);
refreshDashboard();
setInterval(refreshDashboard, 45000);
