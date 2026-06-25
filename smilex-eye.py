#!/usr/bin/env python3
import shodan
import argparse
import os
import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

# ---------------- CONFIG ----------------
KEY_FILE = os.path.expanduser("~/.smilex_key")
console = Console()

# ---------------- BANNER ----------------
BANNER = """
[bold yellow]
   _____           _ _             ______
  / ___/____ ___  (_) /__  _  __  / ____/_  _____
  \\__ \\/ __ `__ \\/ / / _ \\| |/_/ / __/ / / / / _ \\
 ___/ / / / / / / / /  __/>  <  / /___/ /_/ /  __/
/____/_/ /_/ /_/_/_/\\___/_/|_| /_____/,___/\\___/

          >> SMILEX-EYE PRO v21.0 <<
          >> CREATED BY: 0x0smilex <<
[/bold yellow]
"""

# ---------------- FILTER DATABASE (NO TIERS) ----------------
FILTER_GROUPS = {

    "General": [
        ["asn", "asn:AS15169", "Autonomous System Number"],
        ["city", "city:London", "City filter"],
        ["country", "country:AE", "Country code"],
        ["geo", "geo:25.2,55.3", "Latitude/longitude search"],
        ["hostname", "hostname:example.com", "Hostname search"],
        ["ip", "ip:1.1.1.1", "Specific IP"],
        ["net", "net:192.168.1.0/24", "CIDR network"],
        ["org", "org:Microsoft", "Organization filter"],
        ["isp", "isp:Comcast", "ISP filter"],
        ["port", "port:445", "Port filter"],
        ["product", "product:nginx", "Product/service"],
        ["version", "version:1.18", "Version filter"],
        ["os", "os:Windows", "Operating system"],
        ["device", "device:webcam", "Device type"],
        ["state", "state:NY", "State/region"],
        ["postal", "postal:90210", "Postal code"],
        ["tag", "tag:ics", "Shodan tags"],
    ],

    "Web (HTTP)": [
        ["http.title", "http.title:login", "Page title search"],
        ["http.html", "http.html:admin", "HTML body search"],
        ["http.body", "http.body:login", "HTTP body search"],
        ["http.status", "http.status:200", "HTTP status code"],
        ["http.server", "http.server:apache", "Server header"],
        ["http.waf", "http.waf:cloudflare", "WAF detection"],
        ["http.component", "http.component:wordpress", "Web framework"],
        ["http.component_category", "http.component_category:CMS", "Component category"],
        ["http.favicon.hash", "http.favicon.hash:1234", "Favicon hash"],
        ["http.headers_hash", "http.headers_hash:4321", "Headers hash"],
        ["http.dom_hash", "http.dom_hash:54321", "DOM hash"],
        ["http.robots_hash", "http.robots_hash:1122", "Robots hash"],
        ["http.securitytxt", "http.securitytxt:contact", "Security.txt"],
        ["http.redirect", "http.redirect:true", "Redirect filter"],
        ["http.response", "http.response:200", "Response filter"],
        ["http.host", "http.host:example.com", "Host header"],
    ],

    "SSL / Certificates": [
        ["ssl.version", "ssl.version:tlsv1.3", "TLS version"],
        ["ssl.alpn", "ssl.alpn:h2", "ALPN protocol"],
        ["ssl.cert.expired", "ssl.cert.expired:true", "Expired certificates"],
        ["ssl.cert.subject.cn", "ssl.cert.subject.cn:google", "Subject CN"],
        ["ssl.cert.issuer.cn", "ssl.cert.issuer.cn:R3", "Issuer CN"],
        ["ssl.cert.subject.o", "ssl.cert.subject.o:Google", "Subject org"],
        ["ssl.cert.issuer.o", "ssl.cert.issuer.o:Lets Encrypt", "Issuer org"],
        ["ssl.cert.pubkey.bits", "ssl.cert.pubkey.bits:2048", "Key size"],
        ["ssl.cert.pubkey.type", "ssl.cert.pubkey.type:rsa", "Key type"],
        ["ssl.cert.serial", "ssl.cert.serial:12345", "Serial number"],
        ["ssl.chain_count", "ssl.chain_count:3", "Chain length"],
        ["ssl.cipher", "ssl.cipher:TLS_AES", "Cipher suite"],
        ["ssl.cert.fingerprint", "ssl.cert.fingerprint:abc123", "Fingerprint"],
    ],

    "Security & Vulns": [
        ["has_vuln", "has_vuln:true", "Has vulnerabilities"],
        ["vuln", "vuln:CVE-2019-0708", "CVE search"],
        ["cve", "cve:CVE-2024-1234", "Direct CVE search"],
        ["cpe", "cpe:cpe:/a:apache:http_server", "CPE match"],
        ["vuln.verified", "vuln.verified:true", "Verified vulnerabilities"],
        ["has_screenshot", "has_screenshot:true", "Screenshots"],
        ["screenshot.label", "screenshot.label:ics", "Screenshot type"],
        ["screenshot.hash", "screenshot.hash:1234", "Screenshot hash"],
    ],

    "Cloud & Infrastructure": [
        ["cloud.provider", "cloud.provider:aws", "Cloud provider"],
        ["cloud.region", "cloud.region:us-east-1", "Region"],
        ["cloud.service", "cloud.service:EC2", "Service"],
        ["domain", "domain:example.com", "Domain search"],
    ],

    "Specialized Protocols": [
        ["ssh.hassh", "ssh.hassh:12345", "SSH fingerprint"],
        ["ssh.type", "ssh.type:OpenSSH", "SSH type"],

        ["telnet.do", "telnet.do:echo", "Telnet DO"],
        ["telnet.dont", "telnet.dont:echo", "Telnet DONT"],
        ["telnet.option", "telnet.option:echo", "Telnet option"],

        ["bitcoin.ip", "bitcoin.ip:1.2.3.4", "Bitcoin node IP"],
        ["bitcoin.version", "bitcoin.version:70015", "Bitcoin version"],

        ["ntp.ip", "ntp.ip:1.1.1.1", "NTP server IP"],
        ["ntp.more", "ntp.more:true", "NTP extra data"],

        ["snmp.contact", "snmp.contact:admin", "SNMP contact"],
        ["snmp.location", "snmp.location:DC1", "SNMP location"],
        ["snmp.name", "snmp.name:router", "SNMP device name"],
    ]
}

# ---------------- API KEY ----------------
def get_api_key():
    if os.path.exists(KEY_FILE):
        return open(KEY_FILE).read().strip()

    console.print(Panel("[yellow]First Run Setup[/]\nEnter Shodan API key"))
    key = input("> ").strip()

    if not key:
        console.print("[red]No API key provided[/]")
        sys.exit(1)

    open(KEY_FILE, "w").write(key)
    return key


def change_api_key():
    console.print(Panel("[yellow]Update API Key[/]"))
    key = input("> ").strip()

    if not key:
        console.print("[red]Empty key rejected[/]")
        return

    open(KEY_FILE, "w").write(key)
    console.print("[green]API key updated[/]")


# ---------------- FILTER SEARCH ----------------
def search_filters(keyword):
    keyword = keyword.lower()

    table = Table(title=f"Filter Search: {keyword}")
    table.add_column("Category")
    table.add_column("Filter")
    table.add_column("Example")
    table.add_column("Description")

    found = False

    for cat, items in FILTER_GROUPS.items():
        for f in items:
            if (
                keyword in cat.lower()
                or keyword in f[0].lower()
                or keyword in f[1].lower()
                or keyword in f[2].lower()
            ):
                table.add_row(cat, f[0], f[1], f[2])
                found = True

    if found:
        console.print(table)
    else:
        console.print("[dim]No matching filters found[/]")


# ---------------- LIST ----------------
def list_filters():
    table = Table(title="All Available Filters")
    table.add_column("Category")
    table.add_column("Filter")
    table.add_column("Example")
    table.add_column("Description")

    for cat, items in FILTER_GROUPS.items():
        for f in items:
            table.add_row(cat, f[0], f[1], f[2])

    console.print(table)


# ---------------- MAIN ----------------
def main():
    console.print(BANNER)

    parser = argparse.ArgumentParser()

    parser.add_argument("-q", "--query")
    parser.add_argument("-l", "--limit", type=int, default=15)
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--search-filter")
    parser.add_argument("--api", action="store_true")

    args = parser.parse_args()

    if args.api:
        change_api_key()
        return

    if args.search_filter:
        search_filters(args.search_filter)
        return

    if args.list:
        list_filters()
        return

    if not args.query:
        parser.print_help()
        return

    api = shodan.Shodan(get_api_key())

    try:
        res = api.search(args.query, limit=args.limit)

        table = Table(title=f"Results: {args.query}")
        table.add_column("IP:PORT")
        table.add_column("ORG")

        for m in res["matches"]:
            table.add_row(f"{m['ip_str']}:{m['port']}", m.get("org", "N/A")[:20])

        console.print(table)

    except Exception as e:
        console.print(f"[red]Error:[/] {e}")


if __name__ == "__main__":
    main()
