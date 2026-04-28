#!/usr/bin/env python3
"""
=============================================================
  Graylog Netflow Firewall Analyzer — powered by Claude AI
=============================================================
Fetches Netflow data from Graylog, aggregates traffic patterns,
and uses Claude AI to recommend firewall rules.

Usage:
    python graylog_analyzer.py
    python graylog_analyzer.py --hours 48
    python graylog_analyzer.py --query "src_addr:10.0.0.*"
=============================================================
"""

import os
import sys
import json
import base64
import argparse
import ipaddress
import requests
from collections import defaultdict
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# ─────────────────────────────────────────────
#  Configuration (from .env file)
# ─────────────────────────────────────────────
GRAYLOG_URL  = os.getenv("GRAYLOG_URL",  "http://192.168.**:**")
GRAYLOG_USER = os.getenv("GRAYLOG_USER", "admin")
GRAYLOG_PASS = os.getenv("GRAYLOG_PASS", "****")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "*****")

# Netflow field names as they appear in YOUR Graylog
# These differ between firewall vendors — run --list-fields to discover yours
FIELD_SRC_IP   = os.getenv("FIELD_SRC_IP",   "nf_src_address")
FIELD_DST_IP   = os.getenv("FIELD_DST_IP",   "nf_dst_address")
FIELD_DST_PORT = os.getenv("FIELD_DST_PORT", "nf_l4_dst_port")
FIELD_PROTOCOL = os.getenv("FIELD_PROTOCOL", "nf_proto_name")
FIELD_BYTES    = os.getenv("FIELD_BYTES",    "nf_in_bytes")
FIELD_PACKETS  = os.getenv("FIELD_PACKETS",  "nf_in_pkts")

# Protocol number → name mapping (RFC 5237)
PROTO_MAP = {
    1: "ICMP", 6: "TCP", 17: "UDP",
    47: "GRE", 50: "ESP", 51: "AH",
    89: "OSPF", 132: "SCTP"
}

# Private IP ranges for internal vs. internet classification
PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),   # Carrier-grade NAT
]


# ─────────────────────────────────────────────
#  Graylog API helpers
# ─────────────────────────────────────────────

def graylog_headers():
    creds = base64.b64encode(f"{GRAYLOG_USER}:{GRAYLOG_PASS}".encode()).decode()
    return {
        "Authorization": f"Basic {creds}",
        "Accept": "application/json",
        "X-Requested-By": "graylog-firewall-analyzer"
    }


def test_graylog_connection():
    """Verify Graylog is reachable and credentials work."""
    try:
        r = requests.get(f"{GRAYLOG_URL}/api/system", headers=graylog_headers(), timeout=10)
        r.raise_for_status()
        info = r.json()
        print(f"[✓] Connected to Graylog {info.get('version', '?')} at {GRAYLOG_URL}")
        return True
    except requests.exceptions.ConnectionError:
        print(f"[✗] Cannot reach Graylog at {GRAYLOG_URL}")
        print("    → Check that Docker is running and GRAYLOG_URL is correct in .env")
        return False
    except requests.exceptions.HTTPError as e:
        print(f"[✗] Graylog authentication failed: {e}")
        print("    → Check GRAYLOG_USER and GRAYLOG_PASS in .env")
        return False


def list_sample_fields(limit=5):
    """Print field names from the latest messages — helps you find your Netflow fields."""
    params = {"query": "*", "range": 604800, "limit": limit}
    r = requests.get(
        f"{GRAYLOG_URL}/api/search/universal/relative",
        headers=graylog_headers(), params=params, timeout=20
    )
    r.raise_for_status()
    messages = r.json().get("messages", [])
    if not messages:
        print("[!] No messages found in the last hour.")
        return
    print(f"\n[i] Sample field names from last {limit} messages:\n")
    for i, msg in enumerate(messages):
        fields = msg.get("message", msg.get("fields", {}))
        print(f"  Message {i+1}:")
        for k, v in sorted(fields.items()):
            print(f"    {k}: {v}")
        print()


def fetch_netflow(query="*", time_range_secs=86400, max_messages=5000):
    """Fetch Netflow messages from Graylog REST API."""
    fields = [
        FIELD_SRC_IP, FIELD_DST_IP, FIELD_DST_PORT,
        FIELD_PROTOCOL, FIELD_BYTES, FIELD_PACKETS
    ]
    params = {
        "query": query,
        "range": time_range_secs,
        "limit": max_messages,
        "sort": "timestamp:desc"
    }
    hours = time_range_secs / 3600
    print(f"[*] Fetching Netflow from Graylog (last {hours:.0f}h, max {max_messages} messages)...")

    r = requests.get(
        f"{GRAYLOG_URL}/api/search/universal/relative",
        headers=graylog_headers(), params=params, timeout=60
    )
    r.raise_for_status()
    data = r.json()
    total = data.get("total_results", 0)
    messages = data.get("messages", [])
    print(f"[+] Got {len(messages):,} messages (total matching: {total:,})")
    if total > max_messages:
        print(f"[!] Warning: only fetched {max_messages} of {total} messages.")
        print(f"    → Increase MAX_MESSAGES in .env for a more complete picture.")
    return messages


# ─────────────────────────────────────────────
#  Data processing
# ─────────────────────────────────────────────

def parse_message_fields(msg):
    """Extract fields from Graylog message (handles v3 and v4 API formats)."""
    if "message" in msg:
        return msg["message"]
    return msg.get("fields", msg)


def ip_to_subnet(ip_str, prefix=24):
    """Convert IP to its /24 (or custom prefix) subnet."""
    try:
        return str(ipaddress.ip_network(f"{ip_str}/{prefix}", strict=False))
    except (ValueError, TypeError):
        return None


def proto_to_name(proto):
    """Convert protocol number or string to readable name."""
    if isinstance(proto, int):
        return PROTO_MAP.get(proto, str(proto))
    try:
        return PROTO_MAP.get(int(proto), str(proto).upper())
    except (ValueError, TypeError):
        return str(proto).upper() if proto else "UNKNOWN"


def is_private_ip(ip_str):
    """Return True if IP is in a private/RFC1918 range."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in r for r in PRIVATE_RANGES)
    except ValueError:
        return False


def aggregate_flows(messages):
    """
    Aggregate raw Netflow messages into flow patterns.
    Key = (src_subnet/24, dst_subnet/24, dst_port, protocol)
    """
    flows = defaultdict(lambda: {
        "bytes": 0, "packets": 0, "flow_count": 0,
        "src_ips": set(), "dst_ips": set()
    })
    skipped = 0

    for msg in messages:
        f = parse_message_fields(msg)
        src_ip   = str(f.get(FIELD_SRC_IP, "")).strip()
        dst_ip   = str(f.get(FIELD_DST_IP, "")).strip()
        dst_port = str(f.get(FIELD_DST_PORT, "0")).strip()
        protocol = proto_to_name(f.get(FIELD_PROTOCOL, ""))
        bytes_v  = int(f.get(FIELD_BYTES, 0) or 0)
        pkts_v   = int(f.get(FIELD_PACKETS, 0) or 0)

        if not src_ip or not dst_ip or src_ip == "None" or dst_ip == "None":
            skipped += 1
            continue

        src_subnet = ip_to_subnet(src_ip)
        dst_subnet = ip_to_subnet(dst_ip)
        if not src_subnet or not dst_subnet:
            skipped += 1
            continue

        key = (src_subnet, dst_subnet, dst_port, protocol)
        flows[key]["bytes"]      += bytes_v
        flows[key]["packets"]    += pkts_v
        flows[key]["flow_count"] += 1
        flows[key]["src_ips"].add(src_ip)
        flows[key]["dst_ips"].add(dst_ip)

    if skipped:
        print(f"[!] Skipped {skipped} messages with missing IP fields.")
        print(f"    → Check FIELD_SRC_IP / FIELD_DST_IP in .env — run --list-fields to verify.")

    print(f"[+] Aggregated {len(messages) - skipped:,} messages → {len(flows):,} unique flow patterns")
    return flows


def split_flows(flows):
    """Separate internal ↔ internal from internal → internet flows."""
    internal = {}
    internet_bound = {}

    for key, data in flows.items():
        src_subnet, dst_subnet, port, proto = key
        try:
            # Take the first IP of the dst subnet for classification
            dst_ip = str(ipaddress.ip_network(dst_subnet).network_address)
            if is_private_ip(dst_ip):
                internal[key] = data
            else:
                internet_bound[key] = data
        except Exception:
            internal[key] = data  # Default to internal if unsure

    return internal, internet_bound


# ─────────────────────────────────────────────
#  Summary builder
# ─────────────────────────────────────────────

def bytes_to_human(b):
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


def build_prompt_summary(flows, internal, internet_bound, hours):
    lines = []
    lines.append(f"NETFLOW TRAFFIC ANALYSIS — Last {hours:.0f} hours")
    lines.append(f"Total unique flow patterns: {len(flows)}")
    lines.append(f"Internal subnet communications: {len(internal)}")
    lines.append(f"Internet-bound flows: {len(internet_bound)}")
    lines.append("")

    # Top internal flows
    lines.append("=== TOP INTERNAL SUBNET COMMUNICATIONS (by volume) ===")
    lines.append(f"{'Source Subnet':<20} {'Dest Subnet':<20} {'Port/Proto':<12} {'Volume':>10} {'Flows':>8} {'Src IPs':>8}")
    lines.append("-" * 82)
    top_internal = sorted(internal.items(), key=lambda x: x[1]["bytes"], reverse=True)[:60]
    for (src, dst, port, proto), d in top_internal:
        lines.append(
            f"{src:<20} {dst:<20} {port}/{proto:<8} "
            f"{bytes_to_human(d['bytes']):>10} {d['flow_count']:>8} {len(d['src_ips']):>8}"
        )

    lines.append("")
    lines.append("=== TOP INTERNET-BOUND COMMUNICATIONS (by volume) ===")
    lines.append(f"{'Source Subnet':<20} {'Dest Subnet':<20} {'Port/Proto':<12} {'Volume':>10} {'Flows':>8}")
    lines.append("-" * 74)
    top_internet = sorted(internet_bound.items(), key=lambda x: x[1]["bytes"], reverse=True)[:60]
    for (src, dst, port, proto), d in top_internet:
        lines.append(
            f"{src:<20} {dst:<20} {port}/{proto:<8} "
            f"{bytes_to_human(d['bytes']):>10} {d['flow_count']:>8}"
        )

    # Port distribution
    port_dist = defaultdict(int)
    for (_, _, port, proto), d in flows.items():
        port_dist[f"{port}/{proto}"] += d["flow_count"]

    lines.append("")
    lines.append("=== MOST USED PORTS/PROTOCOLS (by flow count) ===")
    for pp, count in sorted(port_dist.items(), key=lambda x: -x[1])[:30]:
        lines.append(f"  {pp:<15} {count:>8} flows")

    # Active subnets
    src_subnets = defaultdict(int)
    for (src, _, _, _), d in flows.items():
        src_subnets[src] += d["flow_count"]

    lines.append("")
    lines.append("=== MOST ACTIVE SOURCE SUBNETS ===")
    for subnet, count in sorted(src_subnets.items(), key=lambda x: -x[1])[:20]:
        lines.append(f"  {subnet:<20} {count:>8} flows")

    return "\n".join(lines)


# ─────────────────────────────────────────────
#  Claude AI analysis
# ─────────────────────────────────────────────

def analyze_with_claude(summary):
    """Send traffic summary to Claude API and return recommendations."""
    try:
        import anthropic
    except ImportError:
        print("[✗] anthropic package not installed. Run: pip install anthropic")
        sys.exit(1)

    if not ANTHROPIC_API_KEY:
        print("[✗] ANTHROPIC_API_KEY is not set in .env")
        sys.exit(1)

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

    system_prompt = """You are a senior network security engineer specializing in firewall policy design and zero-trust architecture. 
You analyze Netflow data to produce concrete, actionable firewall rules. 
You think in terms of business justification, least-privilege access, and defense-in-depth.
Always output firewall rules in a clear table format."""

    user_prompt = f"""Analyze the following Netflow traffic data and provide firewall recommendations.

{summary}

Please provide a structured analysis with these sections:

## 1. TRAFFIC OVERVIEW
Summarize what you observe: communication patterns, main services, segmentation issues.

## 2. SUBNET ZONE GROUPINGS
Based on observed traffic, suggest logical security zones (e.g., DMZ, Servers, Clients, Management).
List which subnets belong to each zone.

## 3. RECOMMENDED FIREWALL RULES — INTERNAL
Table with columns: Priority | Source Zone/Subnet | Destination Zone/Subnet | Port/Protocol | Action | Business Justification

## 4. RECOMMENDED FIREWALL RULES — INTERNET EGRESS
Table with columns: Priority | Source Subnet | Destination | Port/Protocol | Action | Business Justification

## 5. DEFAULT DENY BASELINE
What to block by default. Any implicit deny rules.

## 6. SECURITY CONCERNS & ANOMALIES
- Suspicious traffic patterns
- Unnecessary lateral movement paths
- Recommended immediate blocks
- Any traffic that looks like it should NOT be there

## 7. QUICK WINS
Top 5 most impactful rules to implement first.

Be specific with subnets and ports from the data provided. Flag any patterns that warrant investigation."""

    print("[*] Sending to Claude AI for analysis (this may take 30-60 seconds)...")
    response = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=4096,
        system=system_prompt,
        messages=[{"role": "user", "content": user_prompt}]
    )
    return response.content[0].text


# ─────────────────────────────────────────────
#  Report output
# ─────────────────────────────────────────────

def save_report(analysis, summary, hours):
    """Save markdown report to disk."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"firewall_analysis_{timestamp}.md"

    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"# Firewall Rule Analysis Report\n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n")
        f.write(f"**Data window:** Last {hours:.0f} hours  \n")
        f.write(f"**Graylog:** {GRAYLOG_URL}  \n\n")
        f.write("---\n\n")
        f.write("## Raw Traffic Summary\n\n```\n")
        f.write(summary)
        f.write("\n```\n\n---\n\n")
        f.write("## AI Recommendations\n\n")
        f.write(analysis)

    print(f"[✓] Report saved: {filename}")
    return filename


# ─────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Graylog Netflow Firewall Analyzer"
    )
    parser.add_argument("--hours",       type=float, default=24,    help="Hours of data to analyze (default: 24)")
    parser.add_argument("--max",         type=int,   default=5000,  help="Max messages to fetch (default: 5000)")
    parser.add_argument("--query",       type=str,   default="*",   help="Graylog search query (default: *)")
    parser.add_argument("--list-fields", action="store_true",       help="Print sample field names from Graylog and exit")
    parser.add_argument("--no-ai",       action="store_true",       help="Skip AI analysis, only print traffic summary")
    args = parser.parse_args()

    print("=" * 60)
    print("  Graylog Netflow Firewall Analyzer")
    print("  Powered by Claude AI")
    print("=" * 60)

    # Verify connection
    if not test_graylog_connection():
        sys.exit(1)

    # Just list fields and exit
    if args.list_fields:
        list_sample_fields()
        sys.exit(0)

    # Fetch data
    time_range = int(args.hours * 3600)
    messages = fetch_netflow(
        query=args.query,
        time_range_secs=time_range,
        max_messages=args.max
    )

    if not messages:
        print("[!] No messages returned. Check your Graylog query.")
        print("    Tip: Run with --list-fields to see available field names.")
        sys.exit(1)

    # Aggregate
    print("[*] Aggregating flows...")
    flows = aggregate_flows(messages)
    internal, internet_bound = split_flows(flows)

    # Build summary
    summary = build_prompt_summary(flows, internal, internet_bound, args.hours)

    if args.no_ai:
        print("\n" + summary)
        sys.exit(0)

    # Claude analysis
    analysis = analyze_with_claude(summary)

    # Save & print
    report_file = save_report(analysis, summary, args.hours)

    print("\n" + "=" * 60)
    print("  CLAUDE'S FIREWALL RECOMMENDATIONS")
    print("=" * 60 + "\n")
    print(analysis)
    print(f"\n{'=' * 60}")
    print(f"[✓] Full report: {report_file}")


if __name__ == "__main__":
    main()
