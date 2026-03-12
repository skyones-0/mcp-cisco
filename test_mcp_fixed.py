#!/usr/bin/env python3
# test_mcp_fixed.py - Tester corregido para MCP
import json
import subprocess
import sys
import os


def test_mcp():
    server_path = "/Users/skyones/Desktop/Project/MCP/mcp_cisco.py"
    
    print("🔧 Starting MCP Server...")
    process = subprocess.Popen(
        ["python3", server_path],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )
    
    def send(method, params=None, req_id=None):
        request = {
            "jsonrpc": "2.0",
            "id": req_id or 1,
            "method": method,
            "params": params or {}
        }
        
        json_str = json.dumps(request) + "\n"
        print(f"\n→ Sending: {json_str[:80]}...")
        
        process.stdin.write(json_str)
        process.stdin.flush()
        
        response_line = process.stdout.readline()
        print(f"← Receiving: {response_line[:100]}...")
        
        return json.loads(response_line)
    
    try:
        # Test 1: Initialize
        print("\n" + "="*50)
        print("TEST 1: Initialize")
        resp = send("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "tester", "version": "1.0"}
        })
        print(f"✓ Server: {resp.get('result', {}).get('serverInfo', {})}")
        
        # Test 2: List tools
        print("\n" + "="*50)
        print("TEST 2: List Tools")
        resp = send("tools/list", {}, req_id=2)
        tools = resp.get("result", {}).get("tools", [])
        print(f"✓ {len(tools)} tools encontradas:")
        for t in tools:
            print(f"  • {t['name']}")
        
        print("\n" + "="*50)
        print("✅ All test pass")
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        
    finally:
        process.terminate()
        try:
            process.wait(timeout=2)
        except:
            process.kill()


if __name__ == "__main__":
    test_mcp()


