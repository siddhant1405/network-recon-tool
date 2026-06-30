import { useState, useMemo } from 'react';
import axios from 'axios';
import { Activity, ShieldAlert, Server, ActivitySquare } from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip as RechartsTooltip, ResponsiveContainer, Cell,
  PieChart, Pie
} from 'recharts';

function App() {
  const [target, setTarget] = useState('');
  const [scanMode, setScanMode] = useState('fast');
  const [isLoading, setIsLoading] = useState(false);
  const [data, setData] = useState(null);
  const [error, setError] = useState('');

  const hosts = useMemo(() => {
    if (!data) return [];
    return Array.isArray(data) ? data : data.hosts || [];
  }, [data]);

  const aiExplanation = data && !Array.isArray(data) ? data.ai_explanation : null;
  const completedScanMode = data && !Array.isArray(data) ? data.scan_mode : scanMode;

  const handleScan = async (e) => {
    e.preventDefault();
    if (!target) return;

    setIsLoading(true);
    setError('');
    setData(null);

    try {
      const response = await axios.post('http://127.0.0.1:8000/api/scan', { target, scan_mode: scanMode });
      setData(response.data);
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'An error occurred during scanning.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleFileUpload = (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (evt) => {
      const content = evt.target.result;
      setTarget(prev => {
        const sep = prev && !prev.endsWith('\n') ? '\n' : '';
        return prev ? prev + sep + content : content;
      });
    };
    reader.readAsText(file);
    // Reset file input so same file can be uploaded again if needed
    e.target.value = null;
  };

  const stats = useMemo(() => {
    if (!hosts.length) return null;

    let totalVulns = 0;
    let criticalVulns = 0;
    let highVulns = 0;
    let highestRiskHost = null;
    let maxRisk = -1;

    const severityCount = {
      Critical: 0,
      High: 0,
      Medium: 0,
      Low: 0
    };

    hosts.forEach(host => {
      if (host.risk_score > maxRisk) {
        maxRisk = host.risk_score;
        highestRiskHost = host.ip;
      }

      host.ports.forEach(port => {
        totalVulns += port.cves.length;
        port.cves.forEach(cve => {
          if (cve.severity.toUpperCase() === 'CRITICAL') {
            criticalVulns++;
          } else if (cve.severity.toUpperCase() === 'HIGH') {
            highVulns++;
          }

          const sev = cve.severity.charAt(0).toUpperCase() + cve.severity.slice(1).toLowerCase();
          if (severityCount[sev] !== undefined) {
            severityCount[sev]++;
          }
        });
      });
    });

    const severityData = [
      { name: 'Critical', value: severityCount.Critical, color: '#ef4444' },
      { name: 'High', value: severityCount.High, color: '#f97316' },
      { name: 'Medium', value: severityCount.Medium, color: '#eab308' },
      { name: 'Low', value: severityCount.Low, color: '#22c55e' }
    ].filter(d => d.value > 0);

    const riskData = hosts.map(h => ({
      ip: h.ip,
      score: h.risk_score
    }));

    return { totalVulns, criticalVulns, highVulns, highestRiskHost, severityData, riskData };
  }, [hosts]);

  return (
    <div className="app-container">
      <header className="header">
        <ActivitySquare size={36} color="#00ff00" />
        <h1>Network Reconnaissance and CVE assesment tool</h1>
      </header>


      <form className="scan-form" onSubmit={handleScan}>
        <textarea
          className="scan-input"
          placeholder="Enter IP, CIDR, or upload a file with targets (one per line)"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          disabled={isLoading}
          rows={3}
          style={{ resize: 'vertical', fontFamily: 'inherit' }}
        />
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', justifyContent: 'center' }}>
          <div className="scan-mode-toggle" role="group" aria-label="Scan mode">
            <button
              type="button"
              className={scanMode === 'fast' ? 'active' : ''}
              onClick={() => setScanMode('fast')}
              disabled={isLoading}
            >
              Fast
            </button>
            <button
              type="button"
              className={scanMode === 'deep' ? 'active' : ''}
              onClick={() => setScanMode('deep')}
              disabled={isLoading}
            >
              Deep
            </button>
          </div>
          <label className="upload-button" style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer', backgroundColor: 'var(--bg-surface-elevated)', border: '1px solid var(--border-color)', color: 'var(--text-primary)', padding: '0.5rem 1rem', borderRadius: '0.5rem', fontSize: '0.875rem' }}>
            <span>Upload File</span>
            <input type="file" accept=".txt,.csv" onChange={handleFileUpload} style={{ display: 'none' }} disabled={isLoading} />
          </label>
          <button type="submit" className="scan-button" disabled={isLoading || !target} style={{ flexGrow: 1 }}>
            {isLoading ? 'Scanning...' : 'Start Scan'}
          </button>
        </div>
      </form>

      {error && (
        <div style={{ color: 'var(--risk-critical)', marginBottom: '2rem', padding: '1rem', background: 'rgba(255, 0, 0, 0.1)', border: '1px solid var(--risk-critical)', borderRadius: '0.5rem' }}>
          {error}
        </div>
      )}

      {!data && !isLoading && !error && (
        <div className="hero-section">
          <h2>Advanced Threat Discovery & Vulnerability Assessment</h2>
          <div className="features-grid">
            <div className="feature-card">
              <ShieldAlert size={32} color="var(--accent-color)" />
              <h3>Real-Time CVE Mapping</h3>
              <p>Automatically correlate discovered services with the latest NIST NVD vulnerability database.</p>
            </div>
            <div className="feature-card">
              <Server size={32} color="var(--accent-color)" />
              <h3>Deep Infrastructure Recon</h3>
              <p>Perform stealthy port scanning, service version detection, and OS fingerprinting.</p>
            </div>
            <div className="feature-card">
              <Activity size={32} color="var(--accent-color)" />
              <h3>Risk Scoring Engine</h3>
              <p>Calculate dynamic risk scores based on CVSS severity and exposure metrics.</p>
            </div>
          </div>
        </div>
      )}

      {isLoading && (
        <div className="loading">
          <Activity size={48} className="spinner" />
          <h2>{scanMode === 'deep' ? 'Running deep scan...' : 'Running fast scan...'}</h2>
          <p>
            {scanMode === 'deep'
              ? 'Deep mode checks versions, fingerprints, and CVE matches, so it can take longer.'
              : 'Fast mode checks reachable ports first and skips slower external vulnerability lookups.'}
          </p>
        </div>
      )}

      {data && stats && (
        <div className="dashboard">
          <div className="risk-explainer">
            <div className="risk-explainer-header">
              <ShieldAlert size={24} color="var(--text-primary)" />
              <div>
                <span className="summary-label">AI Summary</span>
                <h3>{aiExplanation?.status_label || (stats.criticalVulns > 0 ? 'Review Needed' : 'Normal')}</h3>
              </div>
            </div>
            <div className="scan-mode-note">
              {completedScanMode === 'deep'
                ? 'Deep scan: service versions, fingerprints, and CVE matches were checked.'
                : 'Fast scan: open ports were checked. Use Deep mode when you want slower CVE and fingerprint checks.'}
            </div>
            <p className="risk-headline">
              {aiExplanation?.headline || (stats.totalVulns > 0
                ? 'Your system looks normal, with informational CVE matches.'
                : 'Your system looks normal.')}
            </p>
            <p className="risk-copy">
              {aiExplanation?.explanation || (stats.totalVulns > 0
                ? 'The scan found public CVE matches, but no critical findings. A CVE match is not proof that your device is actively vulnerable or compromised.'
                : 'No known CVE matches were found in this scan. Keep software updated as normal.')}
            </p>
            {aiExplanation?.recommended_actions?.length > 0 && (
              <div className="risk-actions">
                {aiExplanation.recommended_actions.map((action, index) => (
                  <span key={index}>{action}</span>
                ))}
              </div>
            )}
            <div className="privacy-note">
              {aiExplanation?.privacy_note || 'AI was not used for this explanation.'}
            </div>
          </div>

          <div className="summary-grid">
            <div className="summary-card">
              <span className="summary-label">Live Hosts</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Server size={24} color="var(--accent-color)" />
                <span className="summary-value">{hosts.length}</span>
              </div>
            </div>
            <div className="summary-card">
              <span className="summary-label">Known CVE Matches</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <ShieldAlert size={24} color="var(--risk-medium)" />
                <span className="summary-value">{stats.totalVulns}</span>
              </div>
            </div>
            <div className="summary-card">
              <span className="summary-label">Critical Findings</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <ShieldAlert size={24} color="var(--risk-critical)" />
                <span className="summary-value" style={{ color: stats.criticalVulns > 0 ? 'var(--risk-critical)' : 'inherit' }}>{stats.criticalVulns}</span>
              </div>
            </div>
            <div className="summary-card">
              <span className="summary-label">Highest Risk Host</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Activity size={24} color="var(--risk-high)" />
                <span className="summary-value" style={{ fontSize: '1.25rem' }}>{stats.highestRiskHost || 'None'}</span>
              </div>
            </div>
          </div>

          <div className="charts-grid">
            <div className="chart-card">
              <h3>Vulnerability Severity Distribution</h3>
              <ResponsiveContainer width="100%" height="85%">
                <PieChart>
                  <Pie
                    data={stats.severityData}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={100}
                    paddingAngle={5}
                    dataKey="value"
                    label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                  >
                    {stats.severityData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <RechartsTooltip contentStyle={{ backgroundColor: 'var(--bg-surface-elevated)', border: 'none', borderRadius: '0.5rem' }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="chart-card">
              <h3>Risk Score per Host</h3>
              <ResponsiveContainer width="100%" height="85%">
                <BarChart data={stats.riskData}>
                  <XAxis dataKey="ip" stroke="var(--text-secondary)" />
                  <YAxis stroke="var(--text-secondary)" domain={[0, 100]} />
                  <RechartsTooltip contentStyle={{ backgroundColor: 'var(--bg-surface-elevated)', border: 'none', borderRadius: '0.5rem' }} />
                  <Bar dataKey="score" fill="var(--accent-color)" radius={[4, 4, 0, 0]}>
                    {stats.riskData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.score > 75 ? 'var(--risk-critical)' : entry.score > 50 ? 'var(--risk-high)' : entry.score > 25 ? 'var(--risk-medium)' : 'var(--risk-low)'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="assets-list">
            <h2 style={{ marginBottom: '1rem', borderBottom: '1px solid var(--border-color)', paddingBottom: '0.5rem' }}>Asset Inventory</h2>
            {hosts.map((host, i) => (
              <div key={i} className="host-card">
                <div className="host-header">
                  <div className="host-info">
                    <h2>{host.ip}</h2>
                    <span className="host-meta">OS: {host.os} | Open Ports: {host.ports.length}</span>
                  </div>
                  <div className={`risk-badge risk-${host.risk_label.toLowerCase()}`}>
                    Risk: {host.risk_score} ({host.risk_label})
                  </div>
                </div>

                {host.ports.length > 0 && (
                  <div className="ports-list">
                    {host.ports.map((port, j) => (
                      <div key={j} className="port-item">
                        <div className="port-header">
                          <span>Port {port.port}/{port.protocol.toUpperCase()}</span>
                          <span className="port-service">{port.product || port.service} {port.version}</span>
                        </div>

                        {port.summary && (
                          <div className="finding-summary">
                            <strong>What this means:</strong> {port.summary}
                          </div>
                        )}

                        {port.fingerprint && (Object.keys(port.fingerprint.raw_headers || {}).length > 0 || port.fingerprint.ssl_issuer) && (
                          <div className="fingerprint-data">
                            {port.fingerprint.http_server && <div><strong>Server:</strong> {port.fingerprint.http_server}</div>}
                            {port.fingerprint.http_powered_by && <div><strong>X-Powered-By:</strong> {port.fingerprint.http_powered_by}</div>}
                            {port.fingerprint.ssl_issuer && <div><strong>SSL Issuer:</strong> {port.fingerprint.ssl_issuer}</div>}
                            {port.fingerprint.ssl_subject && <div><strong>SSL Subject:</strong> {port.fingerprint.ssl_subject}</div>}
                            {port.fingerprint.ssl_expiry && <div><strong>SSL Expiry:</strong> {port.fingerprint.ssl_expiry}</div>}
                          </div>
                        )}

                        {port.cves && port.cves.length > 0 && (
                          <div className="cves-list">
                            {port.cves.map((cve, k) => (
                              <div key={k} className={`cve-item ${cve.severity.toLowerCase()}`}>
                                <div className="cve-id">{cve.id}</div>
                                <div className="cve-body">
                                  <div className="cve-desc">{cve.description}</div>
                                  {cve.summary && (
                                    <div className="finding-summary cve-summary">
                                      <strong>What this means:</strong> {cve.summary}
                                    </div>
                                  )}
                                </div>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
