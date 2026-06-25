#!/usr/bin/env python3
import shodan
import argparse
import os
import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

# --- CONFIG ---
KEY_FILE = os.path.expanduser("~/.smilex_key")
console = Console()

# --- FILTER DATABASE (UNCHANGED + COMPLETE) ---
# Tiers: 0=Free, 1=Membership, 2=Small Business, 3=Corporate
FILTER_GROUPS = {
    "General": [
        ["after", "after:01/01/2026", "Results after a date (dd/mm/yyyy)", 0],
        ["asn", "asn:AS15169", "Autonomous System Number", 0],
        ["before", "before:01/01/2026", "Results before a date (dd/mm/yyyy)", 0],
        ["category", "category:ics", "Predefined categories", 0],
        ["city", "city:London", "City name", 0],
        ["country", "country:AE", "2-letter country code", 0],
        ["device_type", "device:webcam", "Device type", 0],
        ["geo", "geo:25.2,55.3", "Latitude/longitude search", 0],
        ["hash", "hash:-12345", "Banner hash", 0],
        ["hostname", "hostname:edu", "Hostname search", 0],
        ["ip", "ip:1.1.1.1", "Specific IP", 0],
        ["isp", "isp:Comcast", "ISP filter", 0],
        ["net", "net:192.168.1.0/24", "CIDR network", 0],
        ["org", "org:Microsoft", "Organization", 0],
        ["os", "os:Windows", "Operating system", 0],
        ["port", "port:445", "Port number", 0],
        ["product", "product:nginx", "Product name", 0],
        ["version", "version:1.18", "Version filter", 0],
        ["state", "state:NY", "State filter", 0],
        ["postal", "postal:90210", "Postal code", 0],
        ["has_ipv6", "has_ipv6:true", "IPv6 hosts", 0],
        ["tag", "tag:ics", "Shodan tags", 0]
    ],

    "Web (HTTP)": [
        ["http.component", "http.component:wordpress", "Web tech", 1],
        ["http.component_category", "http.component_category:CMS", "Component category", 1],
        ["http.dom_hash", "http.dom_hash:54321", "DOM hash", 1],
        ["http.favicon.hash", "http.favicon.hash:1234", "Favicon hash", 1],
        ["http.headers_hash", "http.headers_hash:4321", "Headers hash", 1],
        ["http.html", "http.html:login", "HTML search", 1],
        ["http.html_hash", "http.html_hash:9876", "HTML hash", 1],
        ["http.robots_hash", "http.robots_hash:1122", "Robots hash", 1],
        ["http.securitytxt", "http.securitytxt:contact", "Security.txt", 1],
        ["http.server_header", "http.server_header:apache", "Server header", 1],
        ["http.status", "http.status:200", "HTTP status", 1],
        ["http.title", "http.title:dashboard", "Title filter", 1],
        ["http.waf", "http.waf:cloudflare", "WAF detection", 1]
    ],

    "SSL / Certificates": [
        ["ssl.alpn", "ssl.alpn:h2", "ALPN protocol", 1],
        ["ssl.cert.alg", "ssl.cert.alg:sha256", "Cert algorithm", 1],
        ["ssl.cert.expired", "ssl.cert.expired:true", "Expired certs", 1],
        ["ssl.cert.extension", "ssl.cert.extension:ocsp", "Extensions", 1],
        ["ssl.cert.issuer.cn", "ssl.cert.issuer.cn:R3", "Issuer CN", 1],
        ["ssl.cert.pubkey.bits", "ssl.cert.pubkey.bits:2048", "Key size", 1],
        ["ssl.cert.pubkey.type", "ssl.cert.pubkey.type:rsa", "Key type", 1],
        ["ssl.cert.serial", "ssl.cert.serial:12345", "Serial", 1],
        ["ssl.cert.subject.cn", "ssl.cert.subject.cn:google", "Subject CN", 1],
        ["ssl.chain_count", "ssl.chain_count:3", "Chain count", 1],
        ["ssl.version", "ssl.version:tlsv1.3", "TLS version", 1],
        ["has_ssl", "has_ssl:true", "SSL enabled", 0]
    ],

    "Security & Vulns": [
        ["has_vuln", "has_vuln:true", "Has CVEs", 1],

        # ✔ REQUIRED Tier 2 filters (kept / ensured)
        ["vuln", "vuln:CVE-2019-0708", "CVE search", 2],
        ["cve", "cve:CVE-2024-1234", "Direct CVE", 2],
        ["cpe", "cpe:cpe:/a:apache:http_server", "CPE match", 2],
        ["vuln.verified", "vuln.verified:true", "Verified vulnerabilities", 2],

        ["has_screenshot", "has_screenshot:true", "Screenshots", 1],
        ["screenshot.label", "screenshot.label:ics", "Screenshot type", 1],
        ["screenshot.hash", "screenshot.hash:1234", "Screenshot hash", 1]
    ],

    "Cloud & Infrastructure": [
        ["cloud.provider", "cloud.provider:aws", "Cloud provider", 1],
        ["cloud.region", "cloud.region:us-east-1", "Region", 1],
        ["cloud.service", "cloud.service:EC2", "Service", 1],
        ["domain", "domain:example.com", "Domain search", 1]
    ],

    "Specialized Protocols": [
        ["ssh.hassh", "ssh.hassh:12345", "SSH fingerprint", 1],
        ["ssh.type", "ssh.type:OpenSSH", "SSH type", 1],
        ["telnet.do", "telnet.do:echo", "Telnet DO", 1],
        ["telnet.dont", "telnet.dont:echo", "Telnet DONT", 1],
        ["telnet.option", "telnet.option:echo", "Telnet option", 1],
        ["bitcoin.ip", "bitcoin.ip:1.2.3.4", "Bitcoin IP", 1],
        ["bitcoin.version", "bitcoin.version:70015", "Bitcoin version", 1],
        ["ntp.ip", "ntp.ip:1.1.1.1", "NTP IP", 1],
        ["ntp.more", "ntp.more:true", "NTP extra", 1],
        ["snmp.contact", "snmp.contact:admin", "SNMP contact", 1],
        ["snmp.location", "snmp.location:DC1", "SNMP location", 1],
        ["snmp.name", "snmp.name:router", "SNMP name", 1]
    ]
}

# --- BANNER ---
BANNER = r"""
   _____           _ _             ______
  / ___/____ ___  (_) /__  _  __  / ____/_  _____
  \__ \/ __ `__ \/ / / _ \| |/_/ / __/ / / / / _ \
 ___/ / / / / / / / /  __/>  <  / /___/ /_/ /  __/
/____/_/ /_/ /_/_/_/\___/_/|_| /_____/\__, /\___/
                                     /____/
          >> SMILEX-EYE PRO v21.0 <<
          >> CREATED BY: 0x0smilex <<
"""

# --- API KEY (FIRST RUN FIXED) ---
def get_api_key():
    if os.path.exists(KEY_FILE):
        return open(KEY_FILE).read().strip()

    console.print(Panel("[yellow]First Run Setup[/]\nEnter your Shodan API key:"))
    key = input("> ").strip()

    if not key:
        console.print("[red]No API key provided[/]")
        sys.exit(1)

    open(KEY_FILE, "w").write(key)
    return key

# --- TIER DETECTION ---
def get_user_tier(api):
    try:
        info = api.info()
        plan = info.get("plan", "free").lower()

        if "enterprise" in plan or "corporate" in plan:
            return 3, plan
        if "small-business" in plan:
            return 2, plan
        if any(x in plan for x in ["membership", "academic", "dev"]):
            return 1, plan
        return 0, plan
    except:
        return 0, "free"

# --- SEARCH FILTERS ---
def search_filters(keyword):
    keyword = keyword.lower()
    table = Table(title=f"Filter Search: {keyword}", show_lines=True)

    table.add_column("Category")
    table.add_column("Filter")
    table.add_column("Example")
    table.add_column("Description")
    table.add_column("Tier")

    for cat, items in FILTER_GROUPS.items():
        for f in items:
            if keyword in f[0].lower() or keyword in f[1].lower() or keyword in f[2].lower():
                table.add_row(cat, f[0], f[1], f[2], str(f[3]))

    console.print(table)

# --- LIST FILTERS ---
def list_filters(api, category=None):
    tier, plan = get_user_tier(api)

    console.print(f"[magenta]Shodan Plan:[/] {plan}")

    table = Table(title="Available Categories")
    table.add_column("Category")
    table.add_column("Filters")

    for cat, items in FILTER_GROUPS.items():
        unlocked = [f for f in items if f[3] <= tier]
        if unlocked:
            table.add_row(cat, str(len(unlocked)))

    console.print(table)

# --- MAIN ---
def main():
    console.print(BANNER)

    parser = argparse.ArgumentParser(
        prog="smilex-eye",
        add_help=True
    )

    parser.add_argument("-q", "--query")
    parser.add_argument("-l", "--limit", type=int, default=15)
    parser.add_argument("--list", nargs="?", const="all")
    parser.add_argument("--search-filter")

    args = parser.parse_args()

    api = None

    if args.search_filter:
        search_filters(args.search_filter)
        return

    if args.list:
        api = shodan.Shodan(get_api_key())
        list_filters(api, args.list)
        return

    if not args.query:
        parser.print_help()
        return

    api = shodan.Shodan(get_api_key())

    try:
        res = api.search(args.query, limit=args.limit)

        table = Table(title=f"Results for {args.query}")
        table.add_column("IP:PORT")
        table.add_column("ORG")

        for m in res["matches"]:
            table.add_row(
                f"{m['ip_str']}:{m['port']}",
                m.get("org", "N/A")[:20]
            )

        console.print(table)

    except Exception as e:
        console.print(f"[red]Error:[/] {e}")


if __name__ == "__main__":
    main()
