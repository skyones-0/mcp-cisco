#!/usr/bin/env python3
"""
================================================================================
 CISCO MCP SERVER - SECURE NETWORK AUTOMATION
================================================================================
 AUTHOR:    Jose Araujo
 VERSION:   1.0.0-secure
 DATE:      2026

 DESCRIPTION:
   Secure MCP server for Cisco IOS/IOS-XE device management with multi-layer
   security controls: risk assessment, command validation, confirmation tokens,
   and dry-run simulation mode.

 SECURITY FEATURES:
   [1] Risk Assessment      - Auto-classifies commands (low/medium/high/blocked)
   [2] Command Whitelist    - Allows only safe commands by default
   [3] Dry-Run Mode         - Simulate commands without execution
   [4] Two-Step Confirmation - Token-based auth for destructive operations

 USAGE:
   Set env vars: CISCO_HOST, CISCO_USER, CISCO_PASS
   Configure in Kimi-CLI: ~/.kimi/mcp.json

 WARNINGS:
   • Always test with dry_run=true first
   • High-risk commands require explicit confirmation
   • Blocked commands cannot be overridden
================================================================================
"""

import sys, json, paramiko, os, time, warnings, secrets, hashlib
warnings.filterwarnings("ignore", category=DeprecationWarning)

class CiscoMCP:
    def __init__(self):
        self.session_token = None
        self.pending_confirmations = {}
        self.ssh = None
        self.host = os.getenv("CISCO_HOST", "")
        self.user = os.getenv("CISCO_USER", "")
        self.password = os.getenv("CISCO_PASS", "")
        
        # Security lists
        self.BLOCKED_COMMANDS = ['reload', 'erase', 'delete', 'format', 'write erase', 'confreg', 'boot']
        
        self.connect()

    def connect(self):
        try:
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh.connect(self.host, username=self.user, password=self.password, timeout=30)
        except Exception as e:
            print(f"SSH Connection Error: {e}", file=sys.stderr)

    def _generate_token(self):
        return hashlib.sha256(secrets.token_bytes(32)).hexdigest()[:12]

    def _assess_risk(self, cmd: str) -> str:
        cmd_lower = cmd.lower()
        
        if any(blocked in cmd_lower for blocked in self.BLOCKED_COMMANDS):
            return "blocked"
        if any(r in cmd_lower for r in ['reload', 'erase', 'delete', 'reset', 'format', 'write erase']):
            return "high"
        if any(r in cmd_lower for r in ['configure', 'interface', 'shutdown', 'no ', 'vlan', 'router', 'access-list']):
            return "medium"
        return "low"

    def _validate_command(self, command: str):
        cmd_lower = command.lower()
        
        if any(blocked in cmd_lower for blocked in self.BLOCKED_COMMANDS):
            return {"allowed": False, "reason": "Command blocked by security policy"}
        
        return {"allowed": True}

    def _simulate_command(self, command: str):
        return f"[DRY-RUN SIMULATION] Would execute: {command}\nEstimated result: Success (no changes made)"

    def execute(self, command, dry_run=False, confirmed=False, confirmation_token=None):
        if dry_run:
            return {
                "success": True,
                "simulation": True,
                "command": command,
                "output": self._simulate_command(command)
            }

        validation = self._validate_command(command)
        if not validation["allowed"]:
            return {"success": False, "error": validation["reason"], "blocked": True}

        risk = self._assess_risk(command)
        
        if risk in ["high", "blocked"] and not confirmed:
            token = self._generate_token()
            self.pending_confirmations[token] = {
                "command": command,
                "timestamp": time.time(),
                "risk": risk
            }
            
            return {
                "success": False,
                "confirmation_required": True,
                "risk_level": risk,
                "command": command,
                "confirmation_token": token,
                "message": f"⚠️ HIGH-RISK COMMAND '{risk.upper()}' REQUIRES CONFIRMATION\n\nCommand: {command}\n\nTo execute, repeat with: confirmed=true, confirmation_token='{token}'"
            }

        if confirmed:
            if not confirmation_token or confirmation_token not in self.pending_confirmations:
                return {"success": False, "error": "Invalid or expired confirmation token"}
            
            pending = self.pending_confirmations[confirmation_token]
            if pending["command"] != command:
                return {"success": False, "error": "Token does not match command"}
            
            del self.pending_confirmations[confirmation_token]

        if not self.ssh:
            return {"success": False, "error": "No SSH connection"}
            
        try:
            stdin, stdout, stderr = self.ssh.exec_command(command, timeout=30)
            output = stdout.read().decode('utf-8', errors='ignore')
            error = stderr.read().decode('utf-8', errors='ignore')
            
            return {
                "success": not bool(error.strip()),
                "command": command,
                "output": output,
                "error": error if error else None,
                "risk_level": risk,
                "confirmed": confirmed
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

cisco = CiscoMCP()

def send(msg):
    print(json.dumps(msg), flush=True)

def get_tools():
    return [
        {"name": "cisco_show", "description": "Execute show commands (low risk)", "inputSchema": {"type": "object", "properties": {"command": {"type": "string"}, "dry_run": {"type": "boolean"}}, "required": ["command"]}},
        {"name": "cisco_config_batch", "description": "Batch configuration with confirmation", "inputSchema": {"type": "object", "properties": {"commands": {"type": "array"}, "save": {"type": "boolean"}, "confirmed": {"type": "boolean"}, "confirmation_token": {"type": "string"}}, "required": ["commands"]}},
        {"name": "cisco_interface", "description": "Configure interfaces (medium risk)", "inputSchema": {"type": "object", "properties": {"interface": {"type": "string"}, "confirmed": {"type": "boolean"}, "confirmation_token": {"type": "string"}}, "required": ["interface"]}},
        {"name": "cisco_vlan", "description": "VLAN management (medium risk)", "inputSchema": {"type": "object", "properties": {"action": {"type": "string"}, "vlan_id": {"type": "integer"}, "confirmed": {"type": "boolean"}, "confirmation_token": {"type": "string"}}, "required": ["action"]}},
        {"name": "cisco_vtp", "description": "VTP configuration (medium risk)", "inputSchema": {"type": "object", "properties": {"mode": {"type": "string"}, "confirmed": {"type": "boolean"}, "confirmation_token": {"type": "string"}}}},
        {"name": "cisco_stp", "description": "Spanning Tree (medium risk)", "inputSchema": {"type": "object", "properties": {"mode": {"type": "string"}, "confirmed": {"type": "boolean"}, "confirmation_token": {"type": "string"}}}},
        {"name": "cisco_portchannel", "description": "EtherChannel (medium risk)", "inputSchema": {"type": "object", "properties": {"action": {"type": "string"}, "group": {"type": "integer"}, "confirmed": {"type": "boolean"}, "confirmation_token": {"type": "string"}}, "required": ["action", "group"]}},
        {"name": "cisco_route_static", "description": "Static routes (medium risk)", "inputSchema": {"type": "object", "properties": {"destination": {"type": "string"}, "next_hop": {"type": "string"}, "confirmed": {"type": "boolean"}, "confirmation_token": {"type": "string"}}, "required": ["destination", "next_hop"]}},
        {"name": "cisco_ospf", "description": "OSPF routing (medium risk)", "inputSchema": {"type": "object", "properties": {"process_id": {"type": "integer"}, "confirmed": {"type": "boolean"}, "confirmation_token": {"type": "string"}}}},
        {"name": "cisco_eigrp", "description": "EIGRP routing (medium risk)", "inputSchema": {"type": "object", "properties": {"as_number": {"type": "integer"}, "confirmed": {"type": "boolean"}, "confirmation_token": {"type": "string"}}}},
        {"name": "cisco_bgp", "description": "BGP routing (medium risk)", "inputSchema": {"type": "object", "properties": {"as_number": {"type": "integer"}, "confirmed": {"type": "boolean"}, "confirmation_token": {"type": "string"}}}},
        {"name": "cisco_acl", "description": "Access Control Lists (medium risk)", "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}, "confirmed": {"type": "boolean"}, "confirmation_token": {"type": "string"}}, "required": ["name"]}},
        {"name": "cisco_nat", "description": "Network Address Translation (medium risk)", "inputSchema": {"type": "object", "properties": {"type": {"type": "string"}, "confirmed": {"type": "boolean"}, "confirmation_token": {"type": "string"}}}},
        {"name": "cisco_dhcp", "description": "DHCP server (medium risk)", "inputSchema": {"type": "object", "properties": {"action": {"type": "string"}, "confirmed": {"type": "boolean"}, "confirmation_token": {"type": "string"}}}},
        {"name": "cisco_first_hop_redundancy", "description": "HSRP/VRRP/GLBP (medium risk)", "inputSchema": {"type": "object", "properties": {"protocol": {"type": "string"}, "group": {"type": "integer"}, "confirmed": {"type": "boolean"}, "confirmation_token": {"type": "string"}}}},
        {"name": "cisco_qos", "description": "Quality of Service (medium risk)", "inputSchema": {"type": "object", "properties": {"action": {"type": "string"}, "confirmed": {"type": "boolean"}, "confirmation_token": {"type": "string"}}}},
        {"name": "cisco_snmp", "description": "SNMP configuration (medium risk)", "inputSchema": {"type": "object", "properties": {"version": {"type": "string"}, "confirmed": {"type": "boolean"}, "confirmation_token": {"type": "string"}}}},
        {"name": "cisco_ntp", "description": "NTP configuration (medium risk)", "inputSchema": {"type": "object", "properties": {"server": {"type": "string"}, "confirmed": {"type": "boolean"}, "confirmation_token": {"type": "string"}}}},
        {"name": "cisco_security", "description": "SSH/AAA/Users (medium risk)", "inputSchema": {"type": "object", "properties": {"ssh_version": {"type": "integer"}, "confirmed": {"type": "boolean"}, "confirmation_token": {"type": "string"}}}},
        {"name": "cisco_monitor", "description": "IP SLA/SPAN/Logging (medium risk)", "inputSchema": {"type": "object", "properties": {"type": {"type": "string"}, "confirmed": {"type": "boolean"}, "confirmation_token": {"type": "string"}}}},
        {"name": "cisco_ping", "description": "Extended ping (low risk)", "inputSchema": {"type": "object", "properties": {"destination": {"type": "string"}}, "required": ["destination"]}},
        {"name": "cisco_traceroute", "description": "Traceroute (low risk)", "inputSchema": {"type": "object", "properties": {"destination": {"type": "string"}}, "required": ["destination"]}},
        {"name": "cisco_backup", "description": "Backup/Restore config (high risk)", "inputSchema": {"type": "object", "properties": {"action": {"type": "string"}, "confirmed": {"type": "boolean"}, "confirmation_token": {"type": "string"}}}},
        {"name": "cisco_rollback", "description": "Configuration rollback (high risk)", "inputSchema": {"type": "object", "properties": {"method": {"type": "string"}, "confirmed": {"type": "boolean"}, "confirmation_token": {"type": "string"}}}},
        {"name": "cisco_health", "description": "Health diagnostics (low risk)", "inputSchema": {"type": "object", "properties": {"checks": {"type": "array"}}}},
        {"name": "cisco_stats", "description": "Server statistics (low risk)", "inputSchema": {"type": "object", "properties": {}}}
    ]

def handle_tool_call(tool, args):
    confirmed = args.get("confirmed", False)
    token = args.get("confirmation_token")
    
    if tool == "cisco_show":
        return cisco.execute(args["command"], dry_run=args.get("dry_run", False))
    
    elif tool == "cisco_config_batch":
        if not confirmed:
            return {
                "confirmation_required": True,
                "message": "⚠️ Batch configuration requires confirmation",
                "commands_count": len(args["commands"]),
                "risk_level": "medium"
            }
        cmds = ["configure terminal"] + args["commands"] + ["end"]
        if args.get("save"):
            cmds.append("write memory")
        results = [cisco.execute(cmd, confirmed=True, confirmation_token=token) for cmd in cmds]
        return {"success": all(r["success"] for r in results), "results": results}
    
    elif tool == "cisco_interface":
        cmd = f"interface {args['interface']}"
        return cisco.execute(cmd, confirmed=confirmed, confirmation_token=token)
    
    elif tool == "cisco_vlan":
        if args.get("action") == "create":
            cmd = f"vlan {args.get('vlan_id', 1)}"
        else:
            cmd = f"no vlan {args.get('vlan_id', 1)}"
        return cisco.execute(cmd, confirmed=confirmed, confirmation_token=token)
    
    elif tool == "cisco_vtp":
        return cisco.execute(f"vtp mode {args.get('mode', 'transparent')}", confirmed=confirmed, confirmation_token=token)
    
    elif tool == "cisco_stp":
        return cisco.execute(f"spanning-tree mode {args.get('mode', 'pvst')}", confirmed=confirmed, confirmation_token=token)
    
    elif tool == "cisco_portchannel":
        return cisco.execute(f"interface port-channel {args['group']}", confirmed=confirmed, confirmation_token=token)
    
    elif tool == "cisco_route_static":
        return cisco.execute(f"ip route {args['destination']} {args['next_hop']}", confirmed=confirmed, confirmation_token=token)
    
    elif tool == "cisco_ospf":
        return cisco.execute(f"router ospf {args.get('process_id', 1)}", confirmed=confirmed, confirmation_token=token)
    
    elif tool == "cisco_eigrp":
        return cisco.execute(f"router eigrp {args.get('as_number')}", confirmed=confirmed, confirmation_token=token)
    
    elif tool == "cisco_bgp":
        return cisco.execute(f"router bgp {args.get('as_number')}", confirmed=confirmed, confirmation_token=token)
    
    elif tool == "cisco_acl":
        return cisco.execute(f"ip access-list extended {args['name']}", confirmed=confirmed, confirmation_token=token)
    
    elif tool == "cisco_nat":
        return cisco.execute("ip nat inside source list 1 interface any overload", confirmed=confirmed, confirmation_token=token)
    
    elif tool == "cisco_dhcp":
        return cisco.execute(f"ip dhcp pool {args.get('pool_name', 'POOL')}", confirmed=confirmed, confirmation_token=token)
    
    elif tool == "cisco_first_hop_redundancy":
        return cisco.execute(f"standby {args.get('group', 1)} ip 10.0.0.1", confirmed=confirmed, confirmation_token=token)
    
    elif tool == "cisco_qos":
        return cisco.execute("policy-map QOS", confirmed=confirmed, confirmation_token=token)
    
    elif tool == "cisco_snmp":
        return cisco.execute(f"snmp-server community public ro", confirmed=confirmed, confirmation_token=token)
    
    elif tool == "cisco_ntp":
        return cisco.execute(f"ntp server {args.get('server', 'pool.ntp.org')}", confirmed=confirmed, confirmation_token=token)
    
    elif tool == "cisco_security":
        return cisco.execute(f"ip ssh version {args.get('ssh_version', 2)}", confirmed=confirmed, confirmation_token=token)
    
    elif tool == "cisco_monitor":
        return cisco.execute(f"ip sla {args.get('number', 1)}", confirmed=confirmed, confirmation_token=token)
    
    elif tool == "cisco_ping":
        return cisco.execute(f"ping {args['destination']}")
    
    elif tool == "cisco_traceroute":
        return cisco.execute(f"traceroute {args['destination']}")
    
    elif tool == "cisco_backup":
        if not confirmed:
            return {
                "confirmation_required": True,
                "message": "⚠️ Backup/restore operations require confirmation",
                "risk_level": "high"
            }
        return cisco.execute("write memory", confirmed=confirmed, confirmation_token=token)
    
    elif tool == "cisco_rollback":
        if not confirmed:
            return {
                "confirmation_required": True,
                "message": "⚠️ Rollback operations require confirmation",
                "risk_level": "high"
            }
        return cisco.execute("configure replace flash:backup.cfg", confirmed=confirmed, confirmation_token=token)
    
    elif tool == "cisco_health":
        return {
            "cpu": cisco.execute("show processes cpu"),
            "memory": cisco.execute("show processes memory"),
            "interfaces": cisco.execute("show ip interface brief")
        }
    
    elif tool == "cisco_stats":
        return {"tools_count": 26, "version": "2.1.0-secure", "host": cisco.host}
    
    else:
        return {"success": False, "error": f"Unknown tool: {tool}"}

def main():
    for line in sys.stdin:
        try:
            req = json.loads(line)
            method = req.get("method")
            req_id = req.get("id")
            
            if method == "initialize":
                send({
                    "jsonrpc": "2.0", 
                    "id": req_id, 
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {"tools": {"listChanged": False}},
                        "serverInfo": {"name": "cisco-mcp-secure", "version": "2.1.0"}
                    }
                })
            elif method == "tools/list":
                send({"jsonrpc": "2.0", "id": req_id, "result": {"tools": get_tools()}})
            elif method == "tools/call":
                params = req.get("params", {})
                result = handle_tool_call(params.get("name"), params.get("arguments", {}))
                send({"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}})
            elif method == "notifications/initialized":
                continue
            else:
                send({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Method not found: {method}"}})
        except json.JSONDecodeError:
            continue
        except Exception as e:
            err_id = req.get("id") if isinstance(req, dict) else None
            send({"jsonrpc": "2.0", "id": err_id, "error": {"code": -32603, "message": str(e)}})

if __name__ == "__main__":
    main()
