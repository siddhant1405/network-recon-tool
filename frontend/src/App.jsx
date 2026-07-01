import { useState, useMemo, useCallback, useEffect, useRef } from 'react';
import axios from 'axios';
import { Activity, ShieldAlert, Server, ActivitySquare } from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip as RechartsTooltip, ResponsiveContainer, Cell,
  PieChart, Pie, LineChart, Line, CartesianGrid
} from 'recharts';
import { jsPDF } from 'jspdf';
import * as XLSX from 'xlsx';

const severityRank = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  UNKNOWN: 0
};

const confidenceRank = {
  confirmed: 2,
  speculative: 1,
  unknown: 0
};

function App() {
  const [target, setTarget] = useState('');
  const [scanMode, setScanMode] = useState('fast');
  const [isLoading, setIsLoading] = useState(false);
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [confidenceFilter, setConfidenceFilter] = useState('all');
  const [sortBy, setSortBy] = useState('risk');
  const [scanHistory, setScanHistory] = useState([]);
  const [isExporting, setIsExporting] = useState(false);
  const dashboardRef = useRef(null);

  const hosts = useMemo(() => {
    if (!data) return [];
    return Array.isArray(data) ? data : data.hosts || [];
  }, [data]);

  const aiExplanation = data && !Array.isArray(data) ? data.ai_explanation : null;
  const completedScanMode = data && !Array.isArray(data) ? data.scan_mode : scanMode;
  const scanSummary = data && !Array.isArray(data) ? data.summary : null;
  const likelyNoise = scanSummary?.likely_noise || [];
  const notableFindings = scanSummary?.notable_findings || [];

  useEffect(() => {
    try {
      const stored = JSON.parse(localStorage.getItem('network-recon-history') || '[]');
      setScanHistory(Array.isArray(stored) ? stored : []);
    } catch (error) {
      console.error('Unable to read scan history', error);
    }
  }, []);

  const matchesCveFilters = useCallback((cve) => {
    const severity = (cve.severity || 'UNKNOWN').toUpperCase();
    const confidence = (cve.confidence || 'unknown').toLowerCase();
    return (severityFilter === 'all' || severity === severityFilter)
      && (confidenceFilter === 'all' || confidence === confidenceFilter);
  }, [severityFilter, confidenceFilter]);

  const sortCves = useCallback((cves) => {
    return [...cves].sort((a, b) => {
      if (sortBy === 'severity') {
        return (severityRank[(b.severity || 'UNKNOWN').toUpperCase()] || 0)
          - (severityRank[(a.severity || 'UNKNOWN').toUpperCase()] || 0);
      }
      if (sortBy === 'confidence') {
        return (confidenceRank[(b.confidence || 'unknown').toLowerCase()] || 0)
          - (confidenceRank[(a.confidence || 'unknown').toLowerCase()] || 0);
      }
      return a.id.localeCompare(b.id);
    });
  }, [sortBy]);

  const filteredHosts = useMemo(() => {
    const hasCveFilter = severityFilter !== 'all' || confidenceFilter !== 'all';
    const mappedHosts = hosts.map(host => ({
      ...host,
      ports: [...host.ports]
        .sort((a, b) => sortBy === 'port' ? a.port - b.port : 0)
        .map(port => ({
          ...port,
          cves: sortCves((port.cves || []).filter(matchesCveFilters))
        }))
        .filter(port => !hasCveFilter || port.cves.length > 0)
    })).filter(host => host.ports.length > 0 || !hasCveFilter);

    return mappedHosts.sort((a, b) => {
      if (sortBy === 'ip') return a.ip.localeCompare(b.ip);
      if (sortBy === 'port') return (a.ports[0]?.port || 0) - (b.ports[0]?.port || 0);
      return (b.risk_score || 0) - (a.risk_score || 0);
    });
  }, [hosts, severityFilter, confidenceFilter, sortBy, matchesCveFilters, sortCves]);

  const visibleCveCount = useMemo(() => {
    return filteredHosts.reduce((total, host) => (
      total + host.ports.reduce((portTotal, port) => portTotal + (port.cves || []).length, 0)
    ), 0);
  }, [filteredHosts]);

  const csvEscape = (value) => {
    const text = String(value ?? '');
    return `"${text.replaceAll('"', '""')}"`;
  };

  const handleExportCsv = () => {
    const rows = [
      [
        'Host',
        'Port',
        'Protocol',
        'Service',
        'Product',
        'Detected Version',
        'CVE',
        'Severity',
        'CVSS',
        'Confidence',
        'Match Basis',
        'Affected Versions',
        'Noise Note',
        'Summary'
      ]
    ];

    filteredHosts.forEach(host => {
      host.ports.forEach(port => {
        if (port.cves?.length) {
          port.cves.forEach(cve => {
            rows.push([
              host.ip,
              port.port,
              port.protocol,
              port.service,
              port.product,
              cve.detected_version || port.version,
              cve.id,
              cve.severity,
              cve.cvss,
              cve.confidence,
              cve.match_basis,
              cve.affected_versions,
              cve.noise_reason,
              cve.summary
            ]);
          });
        } else {
          rows.push([
            host.ip,
            port.port,
            port.protocol,
            port.service,
            port.product,
            port.version,
            '',
            '',
            '',
            '',
            '',
            '',
            '',
            port.summary
          ]);
        }
      });
    });

    const csv = rows.map(row => row.map(csvEscape).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `network-recon-${new Date().toISOString().slice(0, 10)}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const handleExportPdf = async () => {
    setIsExporting(true);
    try {
      const pdf = new jsPDF('p', 'mm', 'a4');
      const pageWidth = pdf.internal.pageSize.getWidth();
      const pageHeight = pdf.internal.pageSize.getHeight();
      const margin = 10;
      const contentWidth = pageWidth - margin * 2;
      let yPos = margin;

      // Helper: add text with auto-page-break
      const addText = (text, size = 10, style = 'normal', color = [220, 220, 220]) => {
        pdf.setFontSize(size);
        pdf.setFont('helvetica', style);
        pdf.setTextColor(...color);
        const lines = pdf.splitTextToSize(text, contentWidth);
        lines.forEach(line => {
          if (yPos > pageHeight - margin) {
            pdf.addPage();
            yPos = margin;
          }
          pdf.text(line, margin, yPos);
          yPos += size * 0.45;
        });
        yPos += 2;
      };

      // Helper: draw a table
      const addTable = (headers, rows, colWidths) => {
        const rowHeight = 6;
        const fontSize = 7;
        pdf.setFontSize(fontSize);

        // Header
        if (yPos > pageHeight - margin - rowHeight * 2) {
          pdf.addPage();
          yPos = margin;
        }
        pdf.setFillColor(0, 40, 0);
        pdf.rect(margin, yPos - 4, contentWidth, rowHeight, 'F');
        pdf.setFont('helvetica', 'bold');
        pdf.setTextColor(0, 255, 0);
        let xPos = margin + 1;
        headers.forEach((h, i) => {
          pdf.text(String(h), xPos, yPos);
          xPos += colWidths[i];
        });
        yPos += rowHeight;

        // Rows
        pdf.setFont('helvetica', 'normal');
        pdf.setTextColor(200, 200, 200);
        rows.forEach((row, rowIdx) => {
          if (yPos > pageHeight - margin) {
            pdf.addPage();
            yPos = margin;
          }
          if (rowIdx % 2 === 0) {
            pdf.setFillColor(15, 15, 15);
          } else {
            pdf.setFillColor(25, 25, 25);
          }
          pdf.rect(margin, yPos - 4, contentWidth, rowHeight, 'F');
          xPos = margin + 1;
          row.forEach((cell, i) => {
            const cellText = String(cell ?? '').substring(0, Math.floor(colWidths[i] / 1.8));
            pdf.text(cellText, xPos, yPos);
            xPos += colWidths[i];
          });
          yPos += rowHeight;
        });
        yPos += 4;
      };

      // Background for data pages
      const addPageBg = () => {
        pdf.setFillColor(10, 10, 10);
        pdf.rect(0, 0, pageWidth, pageHeight, 'F');
      };
      addPageBg();

      // Override addPage to auto-add background
      const origAddPage = pdf.addPage.bind(pdf);
      pdf.addPage = (...args) => {
        origAddPage(...args);
        addPageBg();
      };

      // Title
      addText('NETWORK RECONNAISSANCE REPORT', 18, 'bold', [0, 255, 0]);
      yPos += 2;
      addText(`Generated: ${new Date().toLocaleString()}`, 10, 'normal', [100, 200, 100]);
      addText(`Scan Mode: ${(completedScanMode || scanMode).toUpperCase()}`, 10, 'normal', [100, 200, 100]);
      addText(`Target: ${target}`, 10, 'normal', [100, 200, 100]);
      yPos += 4;

      // Executive Summary
      addText('EXECUTIVE SUMMARY', 14, 'bold', [0, 255, 0]);
      pdf.setDrawColor(0, 255, 0);
      pdf.line(margin, yPos - 1, margin + contentWidth, yPos - 1);
      yPos += 3;

      addText(`Total Hosts Scanned: ${hosts.length}`, 10, 'normal', [200, 200, 200]);
      addText(`Total CVE Matches: ${stats?.totalVulns || 0}`, 10, 'normal', [200, 200, 200]);
      addText(`Critical Findings: ${stats?.criticalVulns || 0}`, 10, 'bold', stats?.criticalVulns > 0 ? [255, 80, 80] : [200, 200, 200]);
      addText(`High Findings: ${stats?.highVulns || 0}`, 10, 'normal', stats?.highVulns > 0 ? [255, 150, 50] : [200, 200, 200]);
      addText(`Highest Risk Host: ${stats?.highestRiskHost || 'None'}`, 10, 'normal', [200, 200, 200]);
      yPos += 2;

      // AI Summary
      if (aiExplanation) {
        addText('AI ANALYSIS', 14, 'bold', [0, 255, 0]);
        pdf.setDrawColor(0, 255, 0);
        pdf.line(margin, yPos - 1, margin + contentWidth, yPos - 1);
        yPos += 3;
        addText(`Status: ${aiExplanation.status_label || 'Normal'}`, 11, 'bold', [0, 255, 0]);
        if (aiExplanation.headline) addText(aiExplanation.headline, 10, 'bold', [220, 220, 220]);
        if (aiExplanation.explanation) addText(aiExplanation.explanation, 9, 'normal', [180, 180, 180]);
        if (aiExplanation.recommended_actions?.length > 0) {
          addText('Recommended Actions:', 10, 'bold', [0, 220, 0]);
          aiExplanation.recommended_actions.forEach((action, i) => {
            addText(`  ${i + 1}. ${action}`, 9, 'normal', [180, 180, 180]);
          });
        }
        yPos += 4;
      }

      // Host Details
      filteredHosts.forEach(host => {
        addText(`HOST: ${host.ip}`, 13, 'bold', [0, 255, 0]);
        pdf.setDrawColor(0, 180, 0);
        pdf.line(margin, yPos - 1, margin + contentWidth, yPos - 1);
        yPos += 3;
        addText(`OS: ${host.os || 'Unknown'}  |  Risk Score: ${host.risk_score ?? 'N/A'} (${host.risk_label || 'Unknown'})  |  Open Ports: ${host.ports.length}`, 10, 'normal', [180, 180, 180]);
        yPos += 2;

        // Port table for this host
        const portHeaders = ['Port', 'Protocol', 'Service', 'Product', 'Version', 'CVEs'];
        const portColWidths = [18, 18, 30, 35, 35, contentWidth - 136];
        const portRows = host.ports.map(port => [
          port.port,
          (port.protocol || '').toUpperCase(),
          port.service || '',
          port.product || '',
          port.version || '',
          (port.cves || []).length
        ]);
        if (portRows.length > 0) {
          addText('Open Ports:', 10, 'bold', [0, 200, 0]);
          addTable(portHeaders, portRows, portColWidths);
        }

        // CVE details for this host
        const allCves = host.ports.flatMap(port =>
          (port.cves || []).map(cve => ({
            port: port.port,
            service: port.service || port.product || '',
            ...cve
          }))
        );
        if (allCves.length > 0) {
          addText('CVE Matches:', 10, 'bold', [0, 200, 0]);
          const cveHeaders = ['CVE ID', 'Port', 'Severity', 'CVSS', 'Confidence', 'Affected Versions'];
          const cveColWidths = [32, 16, 22, 16, 24, contentWidth - 110];
          const cveRows = allCves.map(cve => [
            cve.id,
            cve.port,
            (cve.severity || 'UNKNOWN').toUpperCase(),
            cve.cvss ?? '',
            cve.confidence || 'unknown',
            cve.affected_versions || ''
          ]);
          addTable(cveHeaders, cveRows, cveColWidths);

          // CVE descriptions
          allCves.forEach(cve => {
            if (cve.description || cve.summary) {
              const sevColor = (cve.severity || '').toUpperCase() === 'CRITICAL' ? [255, 80, 80]
                : (cve.severity || '').toUpperCase() === 'HIGH' ? [255, 150, 50]
                  : [200, 200, 200];
              addText(`${cve.id} (${(cve.severity || 'UNKNOWN').toUpperCase()})`, 9, 'bold', sevColor);
              if (cve.description) addText(`  ${cve.description}`, 8, 'normal', [160, 160, 160]);
              if (cve.summary) addText(`  Impact: ${cve.summary}`, 8, 'italic', [140, 140, 140]);
            }
          });
        }
        yPos += 4;
      });

      // Save
      pdf.save(`network-recon-report-${new Date().toISOString().slice(0, 10)}.pdf`);
    } catch (err) {
      console.error('PDF export failed', err);
      window.alert('PDF export failed. Check console for details.');
    } finally {
      setIsExporting(false);
    }
  };

  const handleExportExcel = () => {
    const wb = XLSX.utils.book_new();

    // Sheet 1: Summary
    const summaryData = [
      ['Network Recon Report'],
      ['Generated', new Date().toLocaleString()],
      ['Scan Mode', (completedScanMode || scanMode).toUpperCase()],
      ['Target', target],
      [],
      ['Total Hosts', hosts.length],
      ['Total CVE Matches', stats?.totalVulns || 0],
      ['Critical Findings', stats?.criticalVulns || 0],
      ['High Findings', stats?.highVulns || 0],
      ['Highest Risk Host', stats?.highestRiskHost || 'None'],
    ];
    if (aiExplanation) {
      summaryData.push([], ['AI Status', aiExplanation.status_label || '']);
      if (aiExplanation.headline) summaryData.push(['AI Headline', aiExplanation.headline]);
      if (aiExplanation.explanation) summaryData.push(['AI Explanation', aiExplanation.explanation]);
      if (aiExplanation.recommended_actions?.length > 0) {
        summaryData.push([], ['Recommended Actions']);
        aiExplanation.recommended_actions.forEach((a, i) => summaryData.push([`  ${i + 1}`, a]));
      }
    }
    const summarySheet = XLSX.utils.aoa_to_sheet(summaryData);
    summarySheet['!cols'] = [{ wch: 22 }, { wch: 80 }];
    XLSX.utils.book_append_sheet(wb, summarySheet, 'Summary');

    // Sheet 2: Hosts
    const hostsData = [
      ['IP', 'OS', 'Risk Score', 'Risk Label', 'Open Ports', 'CVE Count']
    ];
    filteredHosts.forEach(host => {
      const cveCount = host.ports.reduce((sum, p) => sum + (p.cves || []).length, 0);
      hostsData.push([host.ip, host.os || '', host.risk_score ?? '', host.risk_label || '', host.ports.length, cveCount]);
    });
    const hostsSheet = XLSX.utils.aoa_to_sheet(hostsData);
    hostsSheet['!cols'] = [{ wch: 18 }, { wch: 20 }, { wch: 12 }, { wch: 12 }, { wch: 12 }, { wch: 12 }];
    XLSX.utils.book_append_sheet(wb, hostsSheet, 'Hosts');

    // Sheet 3: Ports
    const portsData = [
      ['Host', 'Port', 'Protocol', 'Service', 'Product', 'Version', 'CVE Count', 'Summary']
    ];
    filteredHosts.forEach(host => {
      host.ports.forEach(port => {
        portsData.push([
          host.ip, port.port, (port.protocol || '').toUpperCase(),
          port.service || '', port.product || '', port.version || '',
          (port.cves || []).length, port.summary || ''
        ]);
      });
    });
    const portsSheet = XLSX.utils.aoa_to_sheet(portsData);
    portsSheet['!cols'] = [{ wch: 18 }, { wch: 8 }, { wch: 10 }, { wch: 16 }, { wch: 20 }, { wch: 16 }, { wch: 10 }, { wch: 50 }];
    XLSX.utils.book_append_sheet(wb, portsSheet, 'Ports');

    // Sheet 4: CVEs
    const cvesData = [
      ['Host', 'Port', 'Service', 'CVE ID', 'Severity', 'CVSS', 'Confidence',
        'Match Basis', 'Detected Version', 'Affected Versions', 'Description', 'Summary', 'Noise Reason']
    ];
    filteredHosts.forEach(host => {
      host.ports.forEach(port => {
        (port.cves || []).forEach(cve => {
          cvesData.push([
            host.ip, port.port, port.service || port.product || '',
            cve.id, (cve.severity || 'UNKNOWN').toUpperCase(), cve.cvss ?? '',
            cve.confidence || 'unknown', cve.match_basis || '',
            cve.detected_version || '', cve.affected_versions || '',
            cve.description || '', cve.summary || '', cve.noise_reason || ''
          ]);
        });
      });
    });
    const cvesSheet = XLSX.utils.aoa_to_sheet(cvesData);
    cvesSheet['!cols'] = [
      { wch: 18 }, { wch: 8 }, { wch: 16 }, { wch: 18 }, { wch: 10 }, { wch: 8 },
      { wch: 12 }, { wch: 14 }, { wch: 14 }, { wch: 20 }, { wch: 50 }, { wch: 40 }, { wch: 30 }
    ];
    XLSX.utils.book_append_sheet(wb, cvesSheet, 'CVEs');

    XLSX.writeFile(wb, `network-recon-report-${new Date().toISOString().slice(0, 10)}.xlsx`);
  };

  const handleShareReport = async () => {
    const summaryText = [
      `Network Recon Report`,
      `Generated: ${new Date().toLocaleString()}`,
      `Scan mode: ${completedScanMode || scanMode}`,
      `Hosts: ${filteredHosts.length}`,
      `Visible CVE matches: ${visibleCveCount}`,
      ...filteredHosts.flatMap(host => [
        `${host.ip} (${host.risk_label}, score ${host.risk_score})`,
        ...host.ports.map(port => `${port.port}/${port.protocol.toUpperCase()} ${port.product || port.service} ${port.version || ''} (${(port.cves || []).length} findings)`)
      ])
    ].join('\n');

    if (navigator.share) {
      try {
        await navigator.share({
          title: 'Network Recon Report',
          text: summaryText,
        });
        return;
      } catch (error) {
        console.error('Share cancelled', error);
      }
    }

    try {
      await navigator.clipboard.writeText(summaryText);
      window.alert('Report summary copied to clipboard.');
    } catch (error) {
      window.alert('Sharing is not available in this browser.');
    }
  };

  const getServiceConfidenceNote = (port) => {
    if (completedScanMode === 'fast') {
      return 'Fast mode confirms the port is reachable, but it does not verify service version or CVE applicability.';
    }
    if (port.version) {
      return `Deep mode detected version ${port.version}. CVE confidence is based on whether that version matches NVD affected-version data.`;
    }
    return 'Deep mode did not detect a service version, so CVE matching is intentionally limited to reduce false positives.';
  };

  const getGroupedCves = (cves) => {
    const groups = new Map();
    cves.forEach(cve => {
      const key = cve.group_key || cve.id;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(cve);
    });
    return [...groups.values()];
  };

  const trendData = useMemo(() => {
    const grouped = new Map();
    scanHistory.forEach(entry => {
      const hostsForEntry = Array.isArray(entry.hosts) ? entry.hosts : [];
      hostsForEntry.forEach(host => {
        const key = host.ip || 'unknown';
        if (!grouped.has(key)) {
          grouped.set(key, []);
        }
        grouped.get(key).push({
          timestamp: entry.timestamp,
          risk: host.risk_score || 0,
          vulns: (host.ports || []).reduce((count, port) => count + (port.cves || []).length, 0),
          scanMode: entry.scan_mode,
        });
      });
    });

    return Array.from(grouped.entries()).map(([ip, points]) => ({
      ip,
      points: points.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp))
    }));
  }, [scanHistory]);

  const renderCveItem = (cve) => (
    <div key={cve.id} className={`cve-item ${(cve.severity || 'unknown').toLowerCase()}`}>
      <div className="cve-id">
        <span>{cve.id}</span>
        <span className={`confidence-badge confidence-${(cve.confidence || 'unknown').toLowerCase()}`}>
          {cve.confidence || 'unknown'}
        </span>
      </div>
      <div className="cve-body">
        <div className="cve-meta-grid">
          <span><strong>Detected:</strong> {cve.detected_version || 'Unknown'}</span>
          <span><strong>Affected:</strong> {cve.affected_versions || 'Unknown'}</span>
          <span><strong>Basis:</strong> {cve.match_basis || 'Keyword match'}</span>
        </div>
        <div className="cve-desc">{cve.description}</div>
        {cve.noise_reason && (
          <div className="noise-note">{cve.noise_reason}</div>
        )}
        {cve.summary && (
          <div className="finding-summary cve-summary">
            <strong>What this means:</strong> {cve.summary}
          </div>
        )}
      </div>
    </div>
  );

  const renderCveGroup = (group) => {
    if (group.length === 1) return renderCveItem(group[0]);
    const primary = group[0];
    return (
      <details key={primary.group_key || primary.id} className={`cve-group ${(primary.severity || 'unknown').toLowerCase()}`}>
        <summary>
          <span>{group.length} related {primary.severity?.toLowerCase() || 'unknown'} findings</span>
          <span>{group.map(cve => cve.id).join(', ')}</span>
        </summary>
        <div className="group-body">
          {group.map(renderCveItem)}
        </div>
      </details>
    );
  };

  const handleScan = async (e) => {
    e.preventDefault();
    if (!target) return;

    setIsLoading(true);
    setError('');
    setData(null);

    try {
      const response = await axios.post('http://127.0.0.1:8000/api/scan', { target, scan_mode: scanMode });
      setData(response.data);

      const entry = {
        id: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
        timestamp: new Date().toISOString(),
        scan_mode: scanMode,
        target,
        hosts: Array.isArray(response.data.hosts) ? response.data.hosts : [],
      };

      try {
        const stored = JSON.parse(localStorage.getItem('network-recon-history') || '[]');
        const updated = [entry, ...(Array.isArray(stored) ? stored : [])].slice(0, 8);
        localStorage.setItem('network-recon-history', JSON.stringify(updated));
        setScanHistory(updated);
      } catch (historyError) {
        console.error('Unable to save scan history', historyError);
      }
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
        <div className="dashboard" ref={dashboardRef}>
          <div className="report-card report-card-prominent">
            <div className="report-card-header">
              <span className="report-card-icon">📄</span>
              <div className="report-card-title">Generate / Share Report</div>
            </div>
            <div className="report-tools">
              <button type="button" className="export-button" onClick={handleExportCsv}>
                ⬇ Export CSV
              </button>
              <button type="button" className="export-button" onClick={handleExportExcel}>
                📊 Export Excel
              </button>
              <button type="button" className="export-button" onClick={handleExportPdf} disabled={isExporting}>
                {isExporting ? '⏳ Generating...' : '🖨 Export PDF'}
              </button>
              <button type="button" className="export-button" onClick={handleShareReport}>
                🔗 Share Report
              </button>
            </div>
            <div className="report-hint">Export or share the current scan report. CSV includes all host, port, and CVE data. Excel provides multi-sheet workbook with hosts, ports, and CVEs. PDF captures a full page screenshot with detailed data tables. Share copies a text summary to your clipboard.</div>
          </div>
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
            {likelyNoise.length > 0 && (
              <div className="noise-panel">
                <strong>Likely noise to review:</strong>
                <ul>
                  {likelyNoise.map((item, index) => (
                    <li key={index}>{item.id}: {item.reason}</li>
                  ))}
                </ul>
              </div>
            )}
            {notableFindings.length > 0 && (
              <div className="notable-findings">
                <strong>Notable findings:</strong>
                <ul>
                  {notableFindings.slice(0, 3).map((item, index) => (
                    <li key={index}>{item.id} on {item.service} — {item.detail || 'Review this finding for applicability.'}</li>
                  ))}
                </ul>
              </div>
            )}
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

          <div className="charts-grid">
            <div className="chart-card">
              <h3>Recent Risk Trend</h3>
              {trendData.length > 0 ? (
                <div className="trend-list">
                  {trendData.map((series) => (
                    <div key={series.ip} className="trend-item">
                      <div className="trend-title">{series.ip}</div>
                      <ResponsiveContainer width="100%" height={120}>
                        <LineChart data={series.points}>
                          <CartesianGrid stroke="rgba(0,255,0,0.12)" vertical={false} />
                          <XAxis dataKey="timestamp" tick={false} />
                          <YAxis domain={[0, 100]} stroke="var(--text-secondary)" />
                          <RechartsTooltip contentStyle={{ backgroundColor: 'var(--bg-surface-elevated)', border: 'none', borderRadius: '0.5rem' }} />
                          <Line type="monotone" dataKey="risk" stroke="var(--accent-color)" strokeWidth={2} dot={{ r: 3 }} />
                        </LineChart>
                      </ResponsiveContainer>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="empty-trend">Scan the same host more than once to build a trend view.</p>
              )}
            </div>
          </div>


          <div className="assets-list">
            <div className="inventory-toolbar">
              <div>
                <h2>Asset Inventory</h2>
                <span>{filteredHosts.length} host(s), {visibleCveCount} visible CVE match(es)</span>
              </div>
              <div className="inventory-controls">
                <label>
                  Severity
                  <select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}>
                    <option value="all">All</option>
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                    <option value="UNKNOWN">Unknown</option>
                  </select>
                </label>
                <label>
                  Confidence
                  <select value={confidenceFilter} onChange={(event) => setConfidenceFilter(event.target.value)}>
                    <option value="all">All</option>
                    <option value="confirmed">Confirmed</option>
                    <option value="speculative">Speculative</option>
                    <option value="unknown">Unknown</option>
                  </select>
                </label>
                <label>
                  Sort
                  <select value={sortBy} onChange={(event) => setSortBy(event.target.value)}>
                    <option value="risk">Risk</option>
                    <option value="ip">Host IP</option>
                    <option value="port">Port</option>
                    <option value="severity">Severity</option>
                    <option value="confidence">Confidence</option>
                  </select>
                </label>
              </div>
            </div>
            {filteredHosts.map((host, i) => (
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

                        <div className="service-confidence-note">
                          <strong>Confidence note:</strong> {getServiceConfidenceNote(port)}
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
                            {getGroupedCves(port.cves).map(renderCveGroup)}
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
