import dns.dnssec
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver

from .Scan import Scan


class DnsSecScanner(Scan):
    @staticmethod
    def scan(target: str) -> dict:
        result = {"dnssec": False}

        qname = dns.name.from_text(target)
        rdatatype = dns.rdatatype.DNSKEY
        query = dns.message.make_query(qname, rdatatype, want_dnssec=True)

        try:
            # Use the custom resolver if provided, otherwise use the default resolver
            resolver = dns.resolver.Resolver()

            # Resolve the nameservers and their addresses
            ns_response = resolver.resolve(target, dns.rdatatype.NS)
            if ns_response.rrset:
                nsname = ns_response.rrset[0].to_text()  # Access the first element of the list
                ns_response = resolver.resolve(nsname, dns.rdatatype.A)
            if ns_response.rrset:
                nsaddr = ns_response.rrset[0].to_text()

                # Query the nameserver for DNSKEY records and perform DNSSEC validation
                response = dns.query.udp(query, nsaddr)

                if response.rcode() == dns.rcode.NOERROR:
                    answer = response.answer
                    if len(answer) == 2:
                        # Validate DNSSEC signatures
                        dns.dnssec.validate(answer[0], answer[1], {qname: answer[0]})
                        result["dnssec"] = True

        except Exception as e:
            return result

        return result
