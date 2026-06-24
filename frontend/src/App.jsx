import { useState, useMemo } from 'react';
import axios from 'axios';
import { Activity, ShieldAlert, Server, ActivitySquare } from 'lucide-react';
import { 
  BarChart, Bar, XAxis, YAxis, Tooltip as RechartsTooltip, ResponsiveContainer, Cell,
  PieChart, Pie
} from 'recharts';

function App() {
  const [target, setTarget] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [data, setData] = useState(null);
  const [error, setError] = useState('');

  const handleScan = async (e) => {
    e.preventDefault();
    if (!target) return;
    
    setIsLoading(true);
    setError('');
    setData(null);

    try {
      const response = await axios.post('http://127.0.0.1:8000/api/scan', { target });
      setData(response.data);
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'An error occurred during scanning.');
    } finally {
      setIsLoading(false);
    }
  };

  const stats = useMemo(() => {
    if (!data) return null;
    
    let totalVulns = 0;
    let criticalVulns = 0;
    let highestRiskHost = null;
    let maxRisk = -1;
    
    const severityCount = {
      Critical: 0,
      High: 0,
      Medium: 0,
      Low: 0
    };

    data.forEach(host => {
      if (host.risk_score > maxRisk) {
        maxRisk = host.risk_score;
        highestRiskHost = host.ip;
      }
      
      host.ports.forEach(port => {
        totalVulns += port.cves.length;
        port.cves.forEach(cve => {
          if (cve.severity.toUpperCase() === 'CRITICAL') {
            criticalVulns++;
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

    const riskData = data.map(h => ({
      ip: h.ip,
      score: h.risk_score
    }));

    return { totalVulns, criticalVulns, highestRiskHost, severityData, riskData };
  }, [data]);

  return (
    <div className="app-container">
      <header className="header">
        <ActivitySquare size={36} color="#3b82f6" />
        <h1>Antigravity Network Recon</h1>
      </header>

      <form className="scan-form" onSubmit={handleScan}>
        <input 
          type="text" 
          className="scan-input" 
          placeholder="Enter IP, CIDR, or path to hosts.txt (e.g., 192.168.1.0/24)"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          disabled={isLoading}
        />
        <button type="submit" className="scan-button" disabled={isLoading || !target}>
          {isLoading ? 'Scanning...' : 'Start Scan'}
        </button>
      </form>

      {error && (
        <div style={{ color: 'var(--risk-critical)', marginBottom: '2rem', padding: '1rem', background: 'rgba(239, 68, 68, 0.1)', borderRadius: '0.5rem' }}>
          {error}
        </div>
      )}

      {isLoading && (
        <div className="loading">
          <Activity size={48} className="spinner" />
          <h2>Scanning target infrastructure...</h2>
          <p>This might take a while depending on the target scope and NIST API rate limits.</p>
        </div>
      )}

      {data && stats && (
        <div className="dashboard">
          <div className="summary-grid">
            <div className="summary-card">
              <span className="summary-label">Live Hosts</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Server size={24} color="var(--accent-color)" />
                <span className="summary-value">{data.length}</span>
              </div>
            </div>
            <div className="summary-card">
              <span className="summary-label">Total Vulnerabilities</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <ShieldAlert size={24} color="var(--risk-medium)" />
                <span className="summary-value">{stats.totalVulns}</span>
              </div>
            </div>
            <div className="summary-card">
              <span className="summary-label">Critical Findings</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <ShieldAlert size={24} color="var(--risk-critical)" />
                <span className="summary-value" style={{ color: stats.criticalVulns > 0 ? 'var(--risk-critical)' : 'inherit'}}>{stats.criticalVulns}</span>
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
                    label={({name, percent}) => `${name} ${(percent * 100).toFixed(0)}%`}
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
            {data.map((host, i) => (
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
                          <span className="port-service">{port.product} {port.version}</span>
                        </div>
                        
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
                                <div className="cve-desc">{cve.description}</div>
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
