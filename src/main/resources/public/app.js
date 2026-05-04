let statusChartInstance = null;
let currentRisks = [];

function escapeHtml(unsafe) {
  if (typeof unsafe !== 'string') return unsafe;
  return unsafe
       .replace(/&/g, "&amp;")
       .replace(/</g, "&lt;")
       .replace(/>/g, "&gt;")
       .replace(/"/g, "&quot;")
       .replace(/'/g, "&#039;");
}

async function fetchReports() {
  try {
    const res = await fetch('/api/reports');
    if (!res.ok) throw new Error('Failed to fetch reports. Ensure you are authenticated.');
    const reports = await res.json();
    
    document.getElementById('loading').classList.add('hidden');
    document.getElementById('reportData').classList.remove('hidden');
    
    if (reports.length > 0) {
      renderReport(reports[0]);
      renderReportList(reports);
    } else {
      document.getElementById('reportData').innerHTML = `
        <div class="empty-state">
          <svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
          <h3>No reports generated yet</h3>
          <p>Wait for the background job to run, or trigger an analysis manually.</p>
        </div>
      `;
    }
  } catch (e) {
    console.error(e);
    document.getElementById('loading').innerHTML = `<div class="text-danger">Error loading reports. Check console or ensure you are logged in.</div>`;
  }
}

function renderReport(report) {
  document.getElementById('valRequests').innerText = report.totalRequests.toLocaleString();
  document.getElementById('valClients').innerText = report.uniqueClients.toLocaleString();
  document.getElementById('valTime').innerText = new Date(report.analyzedAt).toLocaleString();
  document.getElementById('valSource').innerText = escapeHtml(report.sourceName);
  
  // Endpoints
  const endpoints = JSON.parse(report.topEndpointsJson);
  const tbodyE = document.querySelector('#tableEndpoints tbody');
  tbodyE.innerHTML = '';
  for (const [path, count] of Object.entries(endpoints)) {
    tbodyE.innerHTML += `<tr><td><span class="code-snippet">${escapeHtml(path)}</span></td><td style="text-align: right; font-weight: 500;">${count.toLocaleString()}</td></tr>`;
  }
  
  // Agents
  const agents = JSON.parse(report.suspiciousAgentsJson);
  const tbodyA = document.querySelector('#tableAgents tbody');
  tbodyA.innerHTML = '';
  for (const [agent, count] of Object.entries(agents)) {
    tbodyA.innerHTML += `<tr><td style="color: var(--text-secondary);">${agent ? escapeHtml(agent) : '<em>Empty User Agent</em>'}</td><td style="text-align: right; font-weight: 500;">${count.toLocaleString()}</td></tr>`;
  }
  
  // Risks
  currentRisks = JSON.parse(report.riskEventsJson);
  let highRiskCount = 0;
  currentRisks.forEach(r => {
    if (r.severity === 'high' || r.severity === 'critical') highRiskCount++;
  });
  document.getElementById('valRisks').innerText = highRiskCount.toLocaleString();
  
  renderRiskTable(currentRisks);
  
  // Reset search
  const searchInput = document.getElementById('searchRisks');
  if(searchInput) searchInput.value = '';

  // Chart
  renderChart(JSON.parse(report.statusBreakdownJson));
}

function renderRiskTable(risksToRender) {
  const tbodyR = document.querySelector('#tableRisks tbody');
  tbodyR.innerHTML = '';
  risksToRender.forEach(r => {
    tbodyR.innerHTML += `<tr>
      <td><span class="badge ${escapeHtml(r.severity)}">${escapeHtml(r.severity)}</span></td>
      <td style="font-weight: 500;">${escapeHtml(r.reason)}</td>
      <td style="color: var(--text-secondary);">${escapeHtml(r.evidence)}</td>
      <td><span class="code-snippet">${escapeHtml(r.relatedIpHash) || '-'}</span></td>
    </tr>`;
  });
  if (risksToRender.length === 0) {
    tbodyR.innerHTML = `<tr><td colspan="4" style="text-align: center; color: var(--text-secondary);">No risk events matched.</td></tr>`;
  }
}

function filterRisks() {
  const query = document.getElementById('searchRisks').value.toLowerCase();
  const filtered = currentRisks.filter(r => {
    const searchString = `${r.reason} ${r.evidence} ${r.relatedIpHash || ''} ${r.severity}`.toLowerCase();
    return searchString.includes(query);
  });
  renderRiskTable(filtered);
}

function exportRisksCSV() {
  if (currentRisks.length === 0) return alert("No data to export");
  
  // Get filtered data if search is active
  const query = document.getElementById('searchRisks').value.toLowerCase();
  let exportData = currentRisks;
  if (query) {
    exportData = currentRisks.filter(r => {
      const searchString = `${r.reason} ${r.evidence} ${r.relatedIpHash || ''} ${r.severity}`.toLowerCase();
      return searchString.includes(query);
    });
  }

  const headers = ['Severity', 'Reason', 'Evidence', 'Client Hash', 'First Seen', 'Last Seen', 'Request Count'];
  const rows = exportData.map(r => [
    r.severity,
    `"${(r.reason || '').replace(/"/g, '""')}"`,
    `"${(r.evidence || '').replace(/"/g, '""')}"`,
    r.relatedIpHash || '',
    r.firstSeen,
    r.lastSeen,
    r.requestCount
  ]);
  
  const csvContent = "data:text/csv;charset=utf-8," 
    + headers.join(",") + "\n" 
    + rows.map(e => e.join(",")).join("\n");
    
  const encodedUri = encodeURI(csvContent);
  const link = document.createElement("a");
  link.setAttribute("href", encodedUri);
  link.setAttribute("download", `logrisk_export_${new Date().getTime()}.csv`);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

function renderChart(statusData) {
  const ctx = document.getElementById('statusChart').getContext('2d');
  
  if (statusChartInstance) {
    statusChartInstance.destroy();
  }

  const labels = Object.keys(statusData);
  const data = Object.values(statusData);
  
  // Assign colors based on status family
  const bgColors = labels.map(status => {
    if (status.startsWith('2')) return 'rgba(34, 197, 94, 0.6)'; // Success green
    if (status.startsWith('3')) return 'rgba(59, 130, 246, 0.6)'; // Redirect blue
    if (status.startsWith('4')) return 'rgba(234, 179, 8, 0.6)';  // Client error yellow
    if (status.startsWith('5')) return 'rgba(239, 68, 68, 0.6)';  // Server error red
    return 'rgba(148, 163, 184, 0.6)';
  });
  
  const borderColors = bgColors.map(c => c.replace('0.6)', '1)'));

  Chart.defaults.color = '#94a3b8';
  Chart.defaults.font.family = "'Inter', sans-serif";

  statusChartInstance = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [{
        label: 'Requests',
        data: data,
        backgroundColor: bgColors,
        borderColor: borderColors,
        borderWidth: 1,
        borderRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: 'rgba(15, 17, 23, 0.9)',
          titleColor: '#fff',
          bodyColor: '#cbd5e1',
          borderColor: '#262c3d',
          borderWidth: 1,
          padding: 10
        }
      },
      scales: {
        y: {
          beginAtZero: true,
          grid: { color: 'rgba(38, 44, 61, 0.5)' },
          ticks: { precision: 0 }
        },
        x: {
          grid: { display: false }
        }
      }
    }
  });
}

function renderReportList(reports) {
  const tbody = document.querySelector('#tableReports tbody');
  tbody.innerHTML = '';
  reports.slice(0, 10).forEach(r => {
    tbody.innerHTML += `<tr>
      <td>${new Date(r.analyzedAt).toLocaleString()}</td>
      <td><span class="badge low" style="background: rgba(255,255,255,0.05); color: #fff; border: none;">${escapeHtml(r.sourceName)}</span></td>
      <td style="font-weight: 500;">${r.totalRequests.toLocaleString()}</td>
      <td style="text-align: right;"><button class="btn" onclick="renderReportById('${r.id}')" style="padding: 0.25rem 0.5rem; font-size: 0.75rem;">View Report</button></td>
    </tr>`;
  });
}

async function renderReportById(id) {
  try {
    const res = await fetch(`/api/reports/${id}`);
    if (res.ok) {
      const report = await res.json();
      renderReport(report);
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
  } catch (e) {
    console.error("Error loading report", e);
  }
}

async function runAnalysis() {
  const btn = document.querySelector('button[onclick="runAnalysis()"]');
  const originalHtml = btn.innerHTML;
  btn.innerHTML = `<div class="spinner" style="width: 16px; height: 16px; margin: 0;"></div> Starting...`;
  btn.disabled = true;

  try {
    const res = await fetch('/api/analyze', { method: 'POST' });
    if (res.ok) {
      setTimeout(() => {
        fetchReports();
        btn.innerHTML = originalHtml;
        btn.disabled = false;
      }, 3000);
    } else {
      throw new Error("Failed");
    }
  } catch (e) {
    alert('Error starting analysis');
    btn.innerHTML = originalHtml;
    btn.disabled = false;
  }
}

async function analyzeSample() {
  const logs = document.getElementById('sampleLogs').value;
  if (!logs.trim()) return alert("Paste some logs first");
  
  const btn = document.querySelector('button[onclick="analyzeSample()"]');
  const originalHtml = btn.innerHTML;
  btn.innerHTML = `Analyzing...`;
  btn.disabled = true;

  try {
    const res = await fetch('/api/analyze/sample', {
      method: 'POST',
      body: logs
    });
    if (res.ok) {
      const report = await res.json();
      renderReport(report);
      document.getElementById('sampleModal').classList.add('hidden');
      window.scrollTo({ top: 0, behavior: 'smooth' });
    } else {
      alert('Error analyzing sample (maybe too large?)');
    }
  } catch (e) {
    console.error(e);
  } finally {
    btn.innerHTML = originalHtml;
    btn.disabled = false;
  }
}

fetchReports();
