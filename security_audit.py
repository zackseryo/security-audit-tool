import whois
import dns.resolver
import socket
import requests
import json
import time
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

OPENROUTER_API_KEY = "your-openrouter-api-key-here"

FREE_MODELS = [
    "meta-llama/llama-3.3-70b-instruct:free",
    "poolside/laguna-xs-2.1:free",
    "qwen/qwen3-coder:free",
]

def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return {
            "registrar": str(w.registrar or "N/A"),
            "creation_date": str(w.creation_date or "N/A"),
            "expiration_date": str(w.expiration_date or "N/A"),
            "country": str(w.country or "N/A")
        }
    except:
        return {"error": "WHOIS lookup failed"}

def get_dns_records(domain):
    records = {}
    for rtype in ["A", "MX", "TXT", "NS"]:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [str(r) for r in answers]
        except:
            records[rtype] = []
    return records

def get_ip_info(domain):
    try:
        ip = socket.gethostbyname(domain)
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = response.json()
        return {
            "ip": ip,
            "org": data.get("org", "N/A"),
            "country": data.get("country", "N/A"),
            "city": data.get("city", "N/A"),
            "isp": data.get("isp", "N/A")
        }
    except:
        return {"error": "IP lookup failed"}

def check_security_headers(domain):
    try:
        response = requests.get(f"https://{domain}", timeout=8, verify=False,
                                headers={"User-Agent": "Mozilla/5.0 SecurityAuditTool/1.0"})
        h = response.headers
        return {
            "Strict-Transport-Security": h.get("Strict-Transport-Security", "MISSING ⚠️"),
            "X-Frame-Options": h.get("X-Frame-Options", "MISSING ⚠️"),
            "X-Content-Type-Options": h.get("X-Content-Type-Options", "MISSING ⚠️"),
            "Content-Security-Policy": h.get("Content-Security-Policy", "MISSING ⚠️")[:80] if h.get("Content-Security-Policy") else "MISSING ⚠️",
            "X-XSS-Protection": h.get("X-XSS-Protection", "MISSING ⚠️"),
        }
    except Exception as e:
        return {"error": f"Could not check headers: {str(e)[:50]}"}

def generate_ai_analysis(domain, whois_data, dns_data, ip_data, headers_data):
    data_summary = (
        f"Domain: {domain} | "
        f"WHOIS: {json.dumps(whois_data)} | "
        f"IP: {json.dumps(ip_data)} | "
        f"Headers: {json.dumps(headers_data)}"
    )
    prompt = (
        "You are a cybersecurity expert. Analyze this domain security data and provide:\n"
        "1. Executive Summary (2-3 sentences)\n"
        "2. Key Security Issues Found\n"
        "3. Risk Level: Low / Medium / High\n"
        "4. Top 3 Recommendations\n\n"
        f"Data: {data_summary}"
    )

    for model in FREE_MODELS:
        try:
            print(f"    Trying model: {model}")
            response = requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "https://security-audit-tool.local",
                    "X-Title": "Security Audit Tool"
                },
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 800
                },
                timeout=30
            )
            result = response.json()
            if "choices" in result and result["choices"]:
                return result["choices"][0]["message"]["content"]
            elif "error" in result:
                print(f"    Error: {result['error'].get('message', 'Unknown')[:80]}")
                continue
        except Exception as e:
            print(f"    Exception: {str(e)[:80]}")
            continue
        time.sleep(2)

    return "AI analysis unavailable — all free models failed. Report data above is still valid."

def generate_pdf_report(domain, whois_data, dns_data, ip_data, headers_data, ai_analysis):
    safe_domain = domain.replace(":", "_")
    filename = f"C:\\Users\\Mohammed\\Desktop\\security_report_{safe_domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    doc = SimpleDocTemplate(filename, pagesize=letter,
                             leftMargin=0.75*inch, rightMargin=0.75*inch)
    styles = getSampleStyleSheet()
    story = []

    title_style = ParagraphStyle('MyTitle', parent=styles['Title'],
                                  fontSize=22, textColor=colors.HexColor("#8B0000"),
                                  spaceAfter=6)
    h1_style = ParagraphStyle('MyH1', parent=styles['Heading1'],
                               fontSize=13, textColor=colors.HexColor("#1a1a2e"),
                               spaceBefore=12, spaceAfter=4)
    normal_style = ParagraphStyle('MyNormal', parent=styles['Normal'],
                                   fontSize=9, leading=13)

    story.append(Paragraph("Network Security Audit Report", title_style))
    story.append(Paragraph(f"<b>Domain:</b> {domain}", styles['Heading2']))
    story.append(Paragraph(f"<b>Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M')}", normal_style))
    story.append(Spacer(1, 0.2*inch))

    story.append(Paragraph("AI Security Analysis", h1_style))
    for line in ai_analysis.split('\n'):
        clean = line.replace('*', '').replace('#', '').strip()
        if clean:
            story.append(Paragraph(clean, normal_style))
    story.append(Spacer(1, 0.2*inch))

    def make_table(data, col_widths, header_color):
        t = Table(data, colWidths=col_widths)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), header_color),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.4, colors.grey),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
            ('PADDING', (0, 0), (-1, -1), 4),
        ]))
        return t

    story.append(Paragraph("WHOIS Information", h1_style))
    whois_rows = [["Field", "Value"]] + [[k, str(v)[:65]] for k, v in whois_data.items()]
    story.append(make_table(whois_rows, [2*inch, 4.5*inch], colors.HexColor("#8B0000")))
    story.append(Spacer(1, 0.2*inch))

    story.append(Paragraph("Security Headers", h1_style))
    header_rows = [["Header", "Status"]] + [[k, str(v)[:55]] for k, v in headers_data.items()]
    story.append(make_table(header_rows, [3*inch, 3.5*inch], colors.HexColor("#1a1a2e")))
    story.append(Spacer(1, 0.2*inch))

    story.append(Paragraph("IP & Hosting Information", h1_style))
    ip_rows = [["Field", "Value"]] + [[k, str(v)] for k, v in ip_data.items()]
    story.append(make_table(ip_rows, [2*inch, 4.5*inch], colors.HexColor("#2d6a4f")))

    if dns_data:
        story.append(Spacer(1, 0.2*inch))
        story.append(Paragraph("DNS Records", h1_style))
        dns_rows = [["Type", "Records"]]
        for rtype, recs in dns_data.items():
            dns_rows.append([rtype, ", ".join(recs)[:70] if recs else "None"])
        story.append(make_table(dns_rows, [1*inch, 5.5*inch], colors.HexColor("#555555")))

    doc.build(story)
    return filename

def main():
    print("=" * 50)
    print("  Network Security Audit Tool v2.0")
    print("=" * 50)
    domain = input("\nEnter domain to audit (e.g. example.com): ").strip()
    domain = domain.replace("https://", "").replace("http://", "").rstrip("/").upper()

    print(f"\n[*] Starting audit for: {domain}")
    print("[*] Gathering WHOIS info...")
    whois_data = get_whois_info(domain.lower())
    print("[*] Checking DNS records...")
    dns_data = get_dns_records(domain.lower())
    print("[*] Getting IP information...")
    ip_data = get_ip_info(domain.lower())
    print("[*] Checking security headers...")
    headers_data = check_security_headers(domain.lower())
    print("[*] Running AI analysis...")
    ai_analysis = generate_ai_analysis(domain.lower(), whois_data, dns_data, ip_data, headers_data)
    print("[*] Generating PDF report...")
    filename = generate_pdf_report(domain, whois_data, dns_data, ip_data, headers_data, ai_analysis)
    print(f"\n✅ Report saved to Desktop!")
    print(f"   File: {filename.split(chr(92))[-1]}")

if __name__ == "__main__":
    main()
