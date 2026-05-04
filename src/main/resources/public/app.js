async function fetchReports() {
  try {
    const res = await fetch('/api/reports');
    if (!res.ok) throw new Error('Failed to fetch');
    const reports = await res.json();
    
    document.getElementById('loading').classList.add('hidden');
    document.getElementById('reportData').classList.remove('hidden');
    
    if (reports.length > 0) {
      renderReport(reports[0]);
      renderReportList(reports);
    } else {
      document.getElementById('loading').innerText = "No reports found.";
      document.getElementById('loading').classList.remove('hidden');
      document.getElementById('reportData').classList.add('hidden');
    }
  } catch (e) {
    console.error(e);
    document.getElementById('loading').innerText = "Error loading reports. Check console or login.";
  }
}

function renderReport(report) {
  document.getElementById('valRequests').innerText = report.totalRequests;
  document.getElementById('valClients').innerText = report.uniqueClients;
  document.getElementById('valTime').innerText = new Date(report.analyzedAt).toLocaleString();
  
  const endpoints = JSON.parse(report.topEndpointsJson);
  const tbodyE = document.querySelector('#tableEndpoints tbody');
  tbodyE.innerHTML = '';
  for (const [path, count] of Object.entries(endpoints)) {
    tbodyE.innerHTML += `<tr><td>${path}</td><td>${count}</td></tr>`;
  }
  
  const agents = JSON.parse(report.suspiciousAgentsJson);
  const tbodyA = document.querySelector('#tableAgents tbody');
  tbodyA.innerHTML = '';
  for (const [agent, count] of Object.entries(agents)) {
    tbodyA.innerHTML += `<tr><td>${agent}</td><td>${count}</td></tr>`;
  }
  
  const risks = JSON.parse(report.riskEventsJson);
  const tbodyR = document.querySelector('#tableRisks tbody');
  tbodyR.innerHTML = '';
  let highRiskCount = 0;
  risks.forEach(r => {
    if (r.severity === 'high' || r.severity === 'critical') highRiskCount++;
    tbodyR.innerHTML += `<tr>
      <td><span class="badge ${r.severity}">${r.severity}</span></td>
      <td>${r.reason}</td>
      <td>${r.evidence}</td>
      <td>${r.relatedIpHash || '-'}</td>
    </tr>`;
  });
  document.getElementById('valRisks').innerText = highRiskCount;
}

function renderReportList(reports) {
  const tbody = document.querySelector('#tableReports tbody');
  tbody.innerHTML = '';
  reports.slice(0, 10).forEach(r => {
    tbody.innerHTML += `<tr>
      <td>${new Date(r.analyzedAt).toLocaleString()}</td>
      <td>${r.sourceName}</td>
      <td>${r.totalRequests}</td>
      <td><button onclick="renderReportById('${r.id}')">View</button></td>
    </tr>`;
  });
}

async function renderReportById(id) {
  const res = await fetch(`/api/reports/${id}`);
  const report = await res.json();
  renderReport(report);
}

async function runAnalysis() {
  const res = await fetch('/api/analyze', { method: 'POST' });
  if (res.ok) {
    alert('Analysis started in background.');
    setTimeout(fetchReports, 2000);
  } else {
    alert('Error starting analysis');
  }
}

async function analyzeSample() {
  const logs = document.getElementById('sampleLogs').value;
  if (!logs.trim()) return alert("Paste some logs first");
  
  const res = await fetch('/api/analyze/sample', {
    method: 'POST',
    body: logs
  });
  if (res.ok) {
    const report = await res.json();
    renderReport(report);
    document.getElementById('sampleModal').classList.add('hidden');
    alert('Sample analyzed successfully');
  } else {
    alert('Error analyzing sample');
  }
}

fetchReports();
