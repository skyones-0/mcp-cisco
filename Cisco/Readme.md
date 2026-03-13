# Cisco MCP Server

Secure Model Context Protocol (MCP) server for Cisco IOS/IOS-XE network automation with multi-layer security controls.

## Features


- **27 Cisco Networking Tools** - From basic show commands to advanced routing protocols
- **4-Layer Security Model**:
  1. Risk Assessment (low/medium/high/blocked)
  2. Command Validation (whitelist/blacklist)
  3. Dry-Run Simulation Mode
  4. Two-Step Token Confirmation

## Security Levels

| Level | Commands | Requires Confirmation |
|-------|----------|---------------------|
| Low | `show`, `ping`, `traceroute`, `health`, `stats` | No |
| Medium | `configure`, `interface`, `vlan`, `routing protocols` | Yes |
| High | `reload`, `erase`, `write erase`, `rollback` | Yes + Token |
| Blocked | `delete`, `format`, `boot` | Never allowed |

## Installation

```bash
# Clone repository
git clone https://github.com/skyones-0/mcp-cisco.git
cd mcp-cisco

# Install dependencies
pip install paramiko

# Set environment variables
export CISCO_HOST="192.168.1.1"
export CISCO_USER="admin"
export CISCO_PASS="password"
```

## Configuration

Add to `~/.kimi/mcp.json`:

```json
{
  "mcpServers": {
    "cisco": {
      "command": "python3",
      "args": ["/path/to/mcp_cisco.py"],
      "env": {
        "CISCO_HOST": "192.168.1.1",
        "CISCO_USER": "admin",
        "CISCO_PASS": "password"
      }
    }
  }
}
```

## Usage Examples

### Low Risk (No Confirmation)
```bash
kimi "show version of the cisco switch"
kimi "check health of cisco device"
kimi "ping 8.8.8.8 from cisco"
```

### Medium Risk (Requires Confirmation)
```bash
# First attempt - returns confirmation token
kimi "configure vlan 10 on cisco"

# Second attempt with token
kimi "configure vlan 10 on cisco with confirmed=true and token=abc123"
```

### Dry-Run Mode (Simulation)
```bash
kimi "simulate configuring ospf on cisco with dry_run=true"
```

## Available Tools

| Tool | Description | Risk |
|------|-------------|------|
| `cisco_show` | Execute show commands | Low |
| `cisco_ping` | Extended ping | Low |
| `cisco_traceroute` | Traceroute | Low |
| `cisco_health` | Health diagnostics | Low |
| `cisco_stats` | Server statistics | Low |
| `cisco_config_batch` | Batch configuration | Medium |
| `cisco_interface` | Interface configuration | Medium |
| `cisco_vlan` | VLAN management | Medium |
| `cisco_vtp` | VTP configuration | Medium |
| `cisco_stp` | Spanning Tree | Medium |
| `cisco_portchannel` | EtherChannel | Medium |
| `cisco_route_static` | Static routes | Medium |
| `cisco_ospf` | OSPF routing | Medium |
| `cisco_eigrp` | EIGRP routing | Medium |
| `cisco_bgp` | BGP routing | Medium |
| `cisco_acl` | Access Control Lists | Medium |
| `cisco_nat` | NAT configuration | Medium |
| `cisco_dhcp` | DHCP server | Medium |
| `cisco_first_hop_redundancy` | HSRP/VRRP/GLBP | Medium |
| `cisco_qos` | Quality of Service | Medium |
| `cisco_snmp` | SNMP configuration | Medium |
| `cisco_ntp` | NTP configuration | Medium |
| `cisco_security` | SSH/AAA/Users | Medium |
| `cisco_monitor` | IP SLA/SPAN/Logging | Medium |
| `cisco_backup` | Backup/Restore | High |
| `cisco_rollback` | Configuration rollback | High |

## Security Configuration

Edit `BLOCKED_COMMANDS` in the script to customize:

```python
BLOCKED_COMMANDS = [
    'reload', 'erase', 'delete', 'format', 
    'write erase', 'confreg', 'boot'
]
```

## Version

- **Current**: 2.1.0-secure
- **Tools**: 27
- **Protocol**: MCP 2024-11-05

## Author

- **Maintainer**: skyones-0
- **License**: MIT

## Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing`)
3. Commit changes (`git commit -m 'feat: add amazing feature'`)
4. Push to branch (`git push origin feature/amazing`)
5. Open Pull Request

```bash
git add README.md
git commit -m "docs: add comprehensive README"
git push
```
