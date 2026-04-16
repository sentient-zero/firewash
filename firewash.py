#!/usr/bin/env python3
"""
Cisco FTD/ASA Configuration Sanitizer
Replaces sensitive values with consistent generic substitutions
so the config remains structurally reviewable.

Usage:
    python3 sanitize_ftd_config.py <input_config> [-o output_file] [--map mapfile]

Mappings are deterministic — same input always produces same output.
An optional mapping file is written so you can reverse-lookup if needed.
"""

import argparse
import ipaddress
import re
import sys
import json
from collections import OrderedDict


class ConfigSanitizer:
    def __init__(self):
        # Counters for generating replacement values
        self.ip_counter = 0
        self.host_counter = 0
        self.domain_counter = 0
        self.object_counter = 0
        self.objgrp_counter = 0
        self.acl_counter = 0
        self.user_counter = 0
        self.iface_counter = 0
        self.pool_counter = 0
        self.tunnel_counter = 0
        self.grouppolicy_counter = 0
        self.crypto_map_counter = 0
        self.community_counter = 0
        self.description_counter = 0
        self.generic_counter = 0

        # Mapping dicts: original -> sanitized
        self.ip_map = OrderedDict()
        self.host_map = OrderedDict()
        self.domain_map = OrderedDict()
        self.object_map = OrderedDict()
        self.objgrp_map = OrderedDict()
        self.acl_map = OrderedDict()
        self.user_map = OrderedDict()
        self.iface_map = OrderedDict()
        self.pool_map = OrderedDict()
        self.tunnel_map = OrderedDict()
        self.grouppolicy_map = OrderedDict()
        self.crypto_map_map = OrderedDict()

        # RFC5737 documentation ranges for IP replacement
        # 192.0.2.0/24 (TEST-NET-1), 198.51.100.0/24 (TEST-NET-2), 203.0.113.0/24 (TEST-NET-3)
        self.pub_ip_base = ipaddress.IPv4Address("192.0.2.1")
        self.priv_ip_base = ipaddress.IPv4Address("10.200.0.1")
        self.ipv6_counter = 0

        # Preserve these well-known IPs/networks
        self.preserve_ips = {
            "0.0.0.0", "255.255.255.255", "127.0.0.1",
            "255.255.255.0", "255.255.0.0", "255.0.0.0",
            "255.255.255.252", "255.255.255.248", "255.255.255.240",
            "255.255.255.224", "255.255.255.192", "255.255.255.128",
            "255.255.254.0", "255.255.252.0", "255.255.248.0",
            "255.255.240.0", "255.255.224.0", "255.255.192.0",
            "255.255.128.0",
        }

        # Preserve these interface names (standardized Cisco names)
        self.preserve_iface = {
            "inside", "outside", "dmz", "management",
            "GigabitEthernet", "TenGigabitEthernet", "Management",
            "Port-channel", "Loopback", "Tunnel", "BVI",
            "diagnostic", "nlp_int_tap",
        }

        # Known default/standard tunnel-group and group-policy names to preserve
        self.preserve_tunnel_groups = {
            "DefaultWEBVPNGroup", "DefaultRAGroup", "DefaultL2LGroup",
        }
        self.preserve_group_policies = {
            "DfltGrpPolicy", "GroupPolicy_DefaultWEBVPNGroup",
            "GroupPolicy_DefaultRAGroup",
        }

        # Secret/key patterns — these get fully redacted, not mapped
        self.secret_patterns = [
            (re.compile(r'(pre-shared-key\s+)\S+', re.IGNORECASE), r'\1REDACTED_PSK'),
            (re.compile(r'(password\s+)\S+(\s+encrypted)?', re.IGNORECASE), r'\1REDACTED_PASS\2'),
            (re.compile(r'(secret\s+)\S+(\s+encrypted)?', re.IGNORECASE), r'\1REDACTED_SECRET\2'),
            (re.compile(r'(key\s+)\S+(\s+encrypted)?', re.IGNORECASE), r'\1REDACTED_KEY\2'),
            (re.compile(r'(community\s+)\S+', re.IGNORECASE), r'\1REDACTED_COMMUNITY'),
            (re.compile(r'(snmp-server\s+host\s+\S+\s+)\S+', re.IGNORECASE), None),  # handled separately
            (re.compile(r'(certificate\s+[0-9a-fA-F]+)'), r'certificate REDACTED_CERT_SERIAL'),
            (re.compile(r'(^\s*[0-9a-f]{2}(?:\s+[0-9a-f]{2}){7,}\s*$)', re.MULTILINE), ' REDACTED_CERT_DATA'),
            (re.compile(r'(trustpoint\s+)\S+', re.IGNORECASE), None),  # mapped, not redacted
            (re.compile(r'(enable\s+password\s+)\S+(\s+.*)?'), r'\1REDACTED_PASS\2'),
            (re.compile(r'(passwd\s+)\S+(\s+.*)?'), r'\1REDACTED_PASS\2'),
        ]

        # Banner content
        self.banner_pattern = re.compile(r'^(banner\s+\w+\s+)(.+)$', re.MULTILINE)

    def _get_replacement_ip(self, original_ip):
        """Map an IP to a sanitized equivalent, preserving private/public distinction."""
        ip_str = str(original_ip).strip()
        if ip_str in self.preserve_ips:
            return ip_str
        if ip_str in self.ip_map:
            return self.ip_map[ip_str]

        try:
            addr = ipaddress.IPv4Address(ip_str)
        except ipaddress.AddressValueError:
            return ip_str

        # Check if it looks like a subnet mask
        binary = f'{int(addr):032b}'
        if binary == '0' * 32 or (binary.startswith('1') and '01' not in binary.rstrip('0')):
            # It's a valid mask pattern, could be a subnet mask
            if ip_str.startswith('255.') or ip_str == '0.0.0.0':
                return ip_str

        if addr.is_private or addr.is_loopback:
            replacement = str(self.priv_ip_base + self.ip_counter)
        else:
            replacement = str(self.pub_ip_base + self.ip_counter)

        self.ip_counter += 1
        self.ip_map[ip_str] = replacement
        return replacement

    def _get_replacement_ipv6(self, original):
        """Map IPv6 to sanitized equivalent."""
        original = original.strip()
        if original in self.ip_map:
            return self.ip_map[original]
        self.ipv6_counter += 1
        replacement = f"2001:db8::{self.ipv6_counter}"
        self.ip_map[original] = replacement
        return replacement

    def _map_name(self, original, mapping, prefix, counter_attr):
        """Generic name mapper with counter."""
        if original in mapping:
            return mapping[original]
        count = getattr(self, counter_attr)
        setattr(self, counter_attr, count + 1)
        replacement = f"{prefix}{count}"
        mapping[original] = replacement
        return replacement

    def sanitize_ip_in_line(self, line):
        """Replace all IPv4 addresses in a line."""
        # IPv4 with CIDR
        def replace_cidr(m):
            ip_part = m.group(1)
            cidr = m.group(2)
            return self._get_replacement_ip(ip_part) + cidr

        line = re.sub(
            r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(/\d{1,2})',
            replace_cidr, line
        )

        # IP ranges (e.g., 10.1.0.1-10.1.0.254)
        def replace_ip_range(m):
            ip1 = m.group(1)
            ip2 = m.group(2)
            return self._get_replacement_ip(ip1) + '-' + self._get_replacement_ip(ip2)

        line = re.sub(
            r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            replace_ip_range, line
        )

        # Standalone IPv4 (not part of a version string like 4.9.01095)
        def replace_ip(m):
            candidate = m.group(0)
            # Skip if it looks like a version string or OID
            pre = m.string[:m.start()]
            if pre.endswith(('.', '-')) or (m.end() < len(m.string) and m.string[m.end()] in '.'):
                return candidate
            # Validate it's actually an IP
            parts = candidate.split('.')
            try:
                if all(0 <= int(p) <= 255 for p in parts):
                    return self._get_replacement_ip(candidate)
            except ValueError:
                pass
            return candidate

        line = re.sub(
            r'(?<![.\w\-])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?![.\w\-])',
            replace_ip, line
        )

        # IPv6 — simplified pattern for common formats
        ipv6_pattern = r'(?<![:\w])([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){2,7})(?![:\w])'
        def replace_ipv6(m):
            candidate = m.group(1)
            try:
                ipaddress.IPv6Address(candidate)
                return self._get_replacement_ipv6(candidate)
            except ipaddress.AddressValueError:
                return candidate

        line = re.sub(ipv6_pattern, replace_ipv6, line)

        return line

    def sanitize_line(self, line):
        """Process a single config line through all sanitization rules."""

        stripped = line.strip()

        # Skip empty lines and comments
        if not stripped or stripped.startswith('!') or stripped.startswith(':'):
            return line

        # --- Redact secrets first ---
        for pattern, replacement in self.secret_patterns:
            if replacement is not None:
                line = pattern.sub(replacement, line)

        # --- Certificate hex blocks ---
        if re.match(r'^\s*[0-9a-fA-F]{2}(\s+[0-9a-fA-F]{2}){7,}\s*$', line):
            return '  REDACTED_CERT_DATA\n'

        # --- Banner ---
        banner_m = self.banner_pattern.match(line)
        if banner_m:
            return f"{banner_m.group(1)}REDACTED_BANNER\n"

        # --- hostname ---
        m = re.match(r'^(hostname\s+)(\S+)', line)
        if m:
            name = self._map_name(m.group(2), self.host_map, "FW-", "host_counter")
            return f"{m.group(1)}{name}\n"

        # --- domain-name ---
        m = re.match(r'^(domain-name\s+)(\S+)', line)
        if m:
            name = self._map_name(m.group(2), self.domain_map, "sanitized-domain-", "domain_counter")
            return f"{m.group(1)}{name}.local\n"

        # --- object / object-group names ---
        m = re.match(r'^(object\s+(?:network|service)\s+)(\S+)(.*)', line)
        if m:
            name = self._map_name(m.group(2), self.object_map, "OBJ-", "object_counter")
            return f"{m.group(1)}{name}{m.group(3)}\n"

        m = re.match(r'^(object-group\s+(?:network|service|protocol|security|user|icmp-type)\s+)(\S+)(.*)', line)
        if m:
            name = self._map_name(m.group(2), self.objgrp_map, "OBJGRP-", "objgrp_counter")
            return f"{m.group(1)}{name}{m.group(3)}\n"

        # --- ACL names ---
        m = re.match(r'^(access-list\s+)(\S+)(\s+.*)', line)
        if m:
            name = self._map_name(m.group(2), self.acl_map, "ACL-", "acl_counter")
            rest = self.sanitize_ip_in_line(m.group(3))
            # Replace object/object-group references in ACL lines
            rest = self._replace_object_refs(rest)
            return f"{m.group(1)}{name}{rest}\n"

        # --- access-group (references ACL names) ---
        m = re.match(r'^(access-group\s+)(\S+)(\s+.*)', line)
        if m:
            name = self._map_name(m.group(2), self.acl_map, "ACL-", "acl_counter")
            return f"{m.group(1)}{name}{m.group(3)}\n"

        # --- tunnel-group ---
        m = re.match(r'^(tunnel-group\s+)(\S+)(.*)', line)
        if m:
            orig = m.group(2)
            if orig in self.preserve_tunnel_groups:
                name = orig
            else:
                name = self._map_name(orig, self.tunnel_map, "TG-", "tunnel_counter")
            rest = m.group(3)
            return f"{m.group(1)}{name}{rest}\n"

        # --- group-policy ---
        m = re.match(r'^(group-policy\s+)(\S+)(.*)', line)
        if m:
            orig = m.group(2)
            if orig in self.preserve_group_policies:
                name = orig
            else:
                name = self._map_name(orig, self.grouppolicy_map, "GP-", "grouppolicy_counter")
            rest = m.group(3)
            return f"{m.group(1)}{name}{rest}\n"

        # --- default-group-policy reference ---
        m = re.match(r'^(\s*default-group-policy\s+)(\S+)(.*)', line)
        if m:
            orig = m.group(2)
            if orig in self.preserve_group_policies:
                name = orig
            elif orig in self.grouppolicy_map:
                name = self.grouppolicy_map[orig]
            else:
                name = self._map_name(orig, self.grouppolicy_map, "GP-", "grouppolicy_counter")
            return f"{m.group(1)}{name}{m.group(3)}\n"

        # --- username ---
        m = re.match(r'^(username\s+)(\S+)(.*)', line)
        if m:
            name = self._map_name(m.group(2), self.user_map, "user", "user_counter")
            return f"{m.group(1)}{name}{m.group(3)}\n"

        # --- ip local pool ---
        m = re.match(r'^(ip\s+local\s+pool\s+)(\S+)(.*)', line)
        if m:
            name = self._map_name(m.group(2), self.pool_map, "POOL-", "pool_counter")
            rest = self.sanitize_ip_in_line(m.group(3))
            return f"{m.group(1)}{name}{rest}\n"

        # --- address-pool reference ---
        m = re.match(r'^(\s*address-pool\s+)(\S+)(.*)', line)
        if m:
            orig = m.group(2)
            if orig in self.pool_map:
                name = self.pool_map[orig]
            else:
                name = self._map_name(orig, self.pool_map, "POOL-", "pool_counter")
            return f"{m.group(1)}{name}{m.group(3)}\n"

        # --- vpn-addr-assign ---
        # (pass through, no sensitive data typically)

        # --- crypto map names ---
        m = re.match(r'^(crypto\s+map\s+)(\S+)(\s+.*)', line)
        if m:
            name = self._map_name(m.group(2), self.crypto_map_map, "CMAP-", "crypto_map_counter")
            rest = self.sanitize_ip_in_line(m.group(3))
            return f"{m.group(1)}{name}{rest}\n"

        # --- description lines ---
        m = re.match(r'^(\s*description\s+)(.*)', line)
        if m:
            self.description_counter += 1
            return f"{m.group(1)}SANITIZED_DESCRIPTION_{self.description_counter}\n"

        # --- dns server-group / name-server ---
        m = re.match(r'^(\s*name-server\s+)(.*)', line)
        if m:
            rest = self.sanitize_ip_in_line(m.group(2))
            return f"{m.group(1)}{rest}\n"

        # --- snmp-server host ---
        m = re.match(r'^(snmp-server\s+host\s+\S+\s+)(\S+)(.*)', line)
        if m:
            ip = self._get_replacement_ip(m.group(2))
            return f"{m.group(1)}{ip} REDACTED_COMMUNITY\n"

        # --- logging host ---
        m = re.match(r'^(logging\s+host\s+\S+\s+)(\S+)(.*)', line)
        if m:
            ip = self._get_replacement_ip(m.group(2))
            return f"{m.group(1)}{ip}{m.group(3)}\n"

        # --- ntp server ---
        m = re.match(r'^(ntp\s+server\s+)(\S+)(.*)', line)
        if m:
            ip = self._get_replacement_ip(m.group(2))
            return f"{m.group(1)}{ip}{m.group(3)}\n"

        # --- route entries ---
        m = re.match(r'^(route\s+\S+\s+)(.*)', line)
        if m:
            rest = self.sanitize_ip_in_line(m.group(2))
            return f"{m.group(1)}{rest}\n"

        # --- nat entries ---
        if stripped.startswith('nat ') or stripped.startswith('nat('):
            line = self.sanitize_ip_in_line(line)
            line = self._replace_object_refs(line)
            return line

        # --- Object/object-group references inside lines ---
        line = self._replace_object_refs(line)

        # --- Catch-all IP sanitization for remaining lines ---
        line = self.sanitize_ip_in_line(line)

        return line

    def _replace_object_refs(self, line):
        """Replace references to object and object-group names within a line."""
        # object-group references
        def replace_objgrp_ref(m):
            orig = m.group(2)
            if orig in self.objgrp_map:
                return f"{m.group(1)}{self.objgrp_map[orig]}"
            return m.group(0)

        line = re.sub(r'(object-group\s+)(\S+)', replace_objgrp_ref, line)

        # object references (but not "object-group" or "object network" definitions)
        def replace_obj_ref(m):
            orig = m.group(2)
            if orig in self.object_map:
                return f"{m.group(1)}{self.object_map[orig]}"
            return m.group(0)

        line = re.sub(r'(?<![-\w])(object\s+)(\S+)(?!\s+(?:network|service))', replace_obj_ref, line)

        return line

    def sanitize(self, config_text):
        """Sanitize an entire configuration."""
        lines = config_text.splitlines()
        output = []
        in_cert_block = False

        for line in lines:
            # Detect certificate blocks
            if re.match(r'^\s*certificate\s+', line.strip()):
                in_cert_block = True
                output.append('  certificate REDACTED_CERT_SERIAL\n')
                continue
            if in_cert_block:
                if line.strip() == 'quit':
                    in_cert_block = False
                    output.append('    quit\n')
                else:
                    output.append('    REDACTED_CERT_DATA\n')
                continue

            sanitized = self.sanitize_line(line)
            if not sanitized.endswith('\n'):
                sanitized += '\n'
            output.append(sanitized)

        return ''.join(output)

    def get_mapping_report(self):
        """Generate a JSON mapping report for reference."""
        report = OrderedDict()
        if self.ip_map:
            report["ip_addresses"] = dict(self.ip_map)
        if self.host_map:
            report["hostnames"] = dict(self.host_map)
        if self.domain_map:
            report["domains"] = dict(self.domain_map)
        if self.object_map:
            report["objects"] = dict(self.object_map)
        if self.objgrp_map:
            report["object_groups"] = dict(self.objgrp_map)
        if self.acl_map:
            report["access_lists"] = dict(self.acl_map)
        if self.tunnel_map:
            report["tunnel_groups"] = dict(self.tunnel_map)
        if self.grouppolicy_map:
            report["group_policies"] = dict(self.grouppolicy_map)
        if self.user_map:
            report["usernames"] = dict(self.user_map)
        if self.pool_map:
            report["address_pools"] = dict(self.pool_map)
        if self.crypto_map_map:
            report["crypto_maps"] = dict(self.crypto_map_map)
        return report


def main():
    parser = argparse.ArgumentParser(
        description="Sanitize Cisco FTD/ASA configuration files for secure sharing"
    )
    parser.add_argument("input_file", help="Path to the raw configuration file")
    parser.add_argument("-o", "--output", help="Output file (default: <input>.sanitized)")
    parser.add_argument("--map", dest="mapfile", help="Write mapping file (JSON) for reference")
    args = parser.parse_args()

    try:
        with open(args.input_file, 'r', encoding='utf-8', errors='replace') as f:
            raw_config = f.read()
    except FileNotFoundError:
        print(f"[!] File not found: {args.input_file}", file=sys.stderr)
        sys.exit(1)

    sanitizer = ConfigSanitizer()
    sanitized = sanitizer.sanitize(raw_config)

    output_file = args.output or f"{args.input_file}.sanitized"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(sanitized)
    print(f"[+] Sanitized config written to: {output_file}")

    # Always write mapping file (keep it local, do NOT share)
    map_file = args.mapfile or f"{args.input_file}.map.json"
    mapping = sanitizer.get_mapping_report()
    with open(map_file, 'w', encoding='utf-8') as f:
        json.dump(mapping, f, indent=2)
    print(f"[+] Mapping file written to:    {map_file}")
    print(f"[!] WARNING: The mapping file contains original values. Do NOT share it.")

    # Summary
    print(f"\n[*] Sanitization summary:")
    print(f"    IPs replaced:           {len(sanitizer.ip_map)}")
    print(f"    Hostnames replaced:     {len(sanitizer.host_map)}")
    print(f"    Domains replaced:       {len(sanitizer.domain_map)}")
    print(f"    Objects replaced:        {len(sanitizer.object_map)}")
    print(f"    Object-groups replaced:  {len(sanitizer.objgrp_map)}")
    print(f"    ACLs replaced:           {len(sanitizer.acl_map)}")
    print(f"    Tunnel-groups replaced:  {len(sanitizer.tunnel_map)}")
    print(f"    Group-policies replaced: {len(sanitizer.grouppolicy_map)}")
    print(f"    Users replaced:          {len(sanitizer.user_map)}")
    print(f"    Address pools replaced:  {len(sanitizer.pool_map)}")
    print(f"    Crypto maps replaced:    {len(sanitizer.crypto_map_map)}")


if __name__ == "__main__":
    main()
