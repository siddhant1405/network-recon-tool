from jinja2 import Template
import json

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Scan Report - {{ target }}</title>
    <style>
        body { font-family: Arial, sans-serif; background: #0d0d0d; color: #e0e0e0; padding: 20px; }
        h1 { color: #00ff99; }
        h2 { color: #00ccff; border-bottom: 1px solid #333; padding-bottom: 5px; }
        h3 { color: #ffaa00; }
        .port-box { background: #1a1a1a; border: 1px solid #333; border-radius: 8px; padding: 15px; margin: 10px 0; }
        .cve { background: #1f1f1f; border-left: 4px solid #ff4444; padding: 10px; margin: 8px 0; border-radius: 4px; }
        .HIGH { border-left-color: #ff4444; }
        .MEDIUM { border-left-color: #ffaa00; }
        .LOW { border-left-color: #00ff99; }
        .UNKNOWN { border-left-color: #888; }
        .CRITICAL { border-left-color: #ff0000; }
        .severity { font-weight: bold; font-size: 12px; padding: 2px 8px; border-radius: 4px; display: inline-block; margin-bottom: 5px; }
        .badge-HIGH { background: #ff4444; color: white; }
        .badge-MEDIUM { background: #ffaa00; color: black; }
        .badge-LOW { background: #00ff99; color: black; }
        .badge-CRITICAL { background: #ff0000; color: white; }
        .badge-UNKNOWN { background: #888; color: white; }
        .meta { color: #888; font-size: 13px; }
    </style>
</head>
<body>
    <h1>🔍 Network Recon Report</h1>
    <p class="meta">Target: {{ target }} | Hosts Found: {{ hosts|length }}</p>
    <hr>

    {% for host in hosts %}
    <h2>🖥️ Host: {{ host.ip }}</h2>
    <p class="meta">OS: {{ host.os }}</p>

        {% for port in host.ports %}
        <div class="port-box">
            <h3>Port {{ port.port }}/{{ port.protocol }} — {{ port.product }} {{ port.version }}</h3>
            <p class="meta">Service: {{ port.service }}</p>

            {% if port.cves %}
                {% for cve in port.cves %}
                <div class="cve {{ cve.severity }}">
                    <span class="severity badge-{{ cve.severity }}">{{ cve.severity }}</span>
                    <strong>{{ cve.id }}</strong>
                    <p>{{ cve.description }}</p>
                </div>
                {% endfor %}
            {% else %}
                <p class="meta">No CVEs found.</p>
            {% endif %}
        </div>
        {% endfor %}
    {% endfor %}

</body>
</html>
"""

def generate_report(data, target, output_file="report.html"):
    template = Template(HTML_TEMPLATE)
    html = template.render(target=target, hosts=data)
    
    with open(output_file, "w") as f:
        f.write(html)
    
    print(f"[+] Report saved: {output_file}")