import dns.resolver
import dns.reversename
import dns.name
import dns.query
import dns.flags
import dns.exception
import sys
from urllib.parse import urlparse
from termcolor import colored

def extract_domain(user_input):
    if user_input.lower() == 'exit':
        print("👋 Exiting program.")
        sys.exit()

    if not user_input.startswith("http"):
        user_input = "http://" + user_input
    parsed_url = urlparse(user_input)
    return parsed_url.netloc.lower()

def get_dns_records(domain):
    records = {
        "A": [],
        "MX": [],
        "TXT": [],
        "NS": [],
        "DNSSEC": False,
        "Reverse": "Not found",
        "Exists": True
    }

    try:
        answers = dns.resolver.resolve(domain, 'A')
        records["A"] = [r.to_text() for r in answers]
    except dns.resolver.NXDOMAIN:
        records["Exists"] = False
    except:
        pass

    try:
        answers = dns.resolver.resolve(domain, 'MX')
        records["MX"] = [r.to_text() for r in answers]
    except:
        pass

    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        records["TXT"] = [r.to_text().strip('"') for r in answers]
    except:
        pass

    try:
        answers = dns.resolver.resolve(domain, 'NS')
        records["NS"] = [r.to_text() for r in answers]
    except:
        pass

    try:
        zone = dns.name.from_text(domain)
        default_resolver = dns.resolver.get_default_resolver()
        nameserver = default_resolver.nameservers[0]
        query = dns.message.make_query(zone, dns.rdatatype.DNSKEY, want_dnssec=True)
        response = dns.query.udp(query, nameserver, timeout=3)
        if response.flags & dns.flags.AD:
            records["DNSSEC"] = True
    except:
        pass

    try:
        if records["A"]:
            rev_name = dns.reversename.from_address(records["A"][0])
            rev = dns.resolver.resolve(rev_name, "PTR")[0].to_text()
            records["Reverse"] = rev
    except:
        pass

    return records

def show_results(domain, records):
    output = []

    if not records["Exists"]:
        return f"\n❌ Domain '{domain}' does not exist (NXDOMAIN)\n"

    output.append(f"\n🔍 DNS Security Check for: {domain}\n")

    output.append("\n✅ A Records:" if records["A"] else "\n❌ No A records found.")
    for a in records["A"]:
        output.append(f"  {a}")

    output.append("\n✅ MX Records:" if records["MX"] else "\n❌ No MX records found.")
    for mx in records["MX"]:
        output.append(f"  {mx}")

    output.append("\n✅ TXT Records:" if records["TXT"] else "\n❌ No TXT records found.")
    for txt in records["TXT"]:
        output.append(f"  {txt}")

    output.append("\n✅ NS Records (Nameservers):" if records["NS"] else "\n❌ No NS records found.")
    for ns in records["NS"]:
        output.append(f"  {ns}")

    output.append("\n✅ DNSSEC is enabled. DNS integrity is protected." if records["DNSSEC"] else "\n❌ DNSSEC is not enabled.")

    if records["Reverse"] != "Not found":
        output.append("\n✅ Reverse DNS record found:")
        output.append(f"  {records['Reverse']}")
    else:
        output.append("\n❌ Reverse DNS not found.")

    return "\n".join(output)

def perform_dns_security_check(domain):
    """Perform DNS Security Check. Use this function as the main entry point."""
    clean_domain = extract_domain(domain)
    result = get_dns_records(clean_domain)
    return show_results(clean_domain, result)

# For CLI usage
if __name__ == "__main__":
    user_input = input("🔎 Enter URL or domain (e.g., https://example.com or 'exit' to quit): ").strip()
    print(perform_dns_security_check(user_input))
