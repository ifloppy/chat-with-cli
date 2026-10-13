#!/usr/bin/env python3
"""Smoke-test old/new protocol compatibility without real tokens or network ports.

Usage: python3 scripts/compat_matrix.py OLD_BINARY NEW_BINARY
No production service or state is accessed. Only temporary loopback Relay/Agent
instances are started; all processes are terminated at the end.
"""
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

def rpc(base, method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(
        base + "/mcp/compat-test", data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "Accept": "application/json, text/event-stream",
                 "Authorization": "Bearer compatibility-test-client",
                 "MCP-Protocol-Version": "2025-03-26"})
    with urllib.request.urlopen(req, timeout=5) as response:
        raw = response.read().decode()
    return json.loads(raw.split("data: ")[-1])

def one_case(relay_binary, agent_binary, expected_count, expect_gateway, new_relay=False):
    with tempfile.TemporaryDirectory(prefix="cwc-compat-") as tmp:
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        base = f"http://127.0.0.1:{port}"
        relay = [str(relay_binary), "relay", "--config", tmp+"/relay.toml",
                 "--state-dir", tmp+"/relay-state", "--listen", f"127.0.0.1:{port}",
                 "--agent-token", "compatibility-test-agent",
                 "--client-token", "compatibility-test-client"]
        agent = [str(agent_binary), "agent", "--config", tmp+"/agent.toml",
                 "--state-dir", tmp+"/agent-state", "--root", tmp, "--device", "compat-test",
                 "--relay", base, "--token", "compatibility-test-agent",
                 "--profile", "read-only", "--approval-mode", "configured"]
        processes = []
        try:
            for command in (relay, agent):
                proc = subprocess.Popen(command, stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL, start_new_session=True)
                processes.append(proc)
                if command is relay:
                    for _ in range(50):
                        if proc.poll() is not None:
                            raise RuntimeError("Relay exited before ready")
                        try:
                            with urllib.request.urlopen(base+"/health", timeout=.5):
                                break
                        except (OSError, urllib.error.URLError):
                            time.sleep(.1)
                    else:
                        raise RuntimeError("Relay health check timed out")
            for _ in range(70):
                if processes[-1].poll() is not None:
                    raise RuntimeError("Agent exited before responding")
                try:
                    result = rpc(base, "tools/call", {"name": "system_info", "arguments": {}})
                    if "result" in result and not result["result"].get("isError", False):
                        break
                except (OSError, urllib.error.URLError, ValueError):
                    pass
                time.sleep(.1)
            else:
                raise RuntimeError("original system_info did not work")
            for _ in range(35):
                listed = rpc(base, "tools/list", {}).get("result", {}).get("tools", [])
                found = any(tool.get("name") == "mcp_tool_call" for tool in listed)
                if len(listed) == expected_count and found == expect_gateway:
                    break
                time.sleep(.1)
            else:
                raise RuntimeError(f"advertised {len(listed)} tools gateway={found}, "
                                   f"expected {expected_count} gateway={expect_gateway}")
            if expect_gateway:
                gateway = rpc(base, "tools/call", {"name": "mcp_servers_list", "arguments": {}})
                if "result" not in gateway or gateway["result"].get("isError", False):
                    raise RuntimeError("modern gateway method failed: " + str(gateway)[:200])
            if new_relay and not expect_gateway:
                result = rpc(base, "tools/call", {"name": "mcp_servers_list", "arguments": {}})
                text = json.dumps(result)
                # The MCP SDK may reject unadvertised tools before broker dispatch.
                # Neither path may forward them to a legacy Agent as unknown methods.
                if "unknown method" in text or not any(message in text.lower() for message in ("not found", "unknown tool", "does not advertise mcp gateway")):
                    raise RuntimeError("unsupported tool was not safely rejected: " + text[:250])
            print(f"PASS relay={relay_binary.name}, agent={agent_binary.name}: "
                  f"{len(listed)} tools, gateway={found}, system_info OK", flush=True)
        finally:
            for p in reversed(processes):
                if p.poll() is None:
                    os.killpg(p.pid, signal.SIGTERM)
            for p in processes:
                try:
                    p.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(p.pid, signal.SIGKILL)
                    p.wait()

def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: compat_matrix.py OLD_BINARY NEW_BINARY")
    old, new = (Path(arg).resolve() for arg in sys.argv[1:])
    # Old software keeps only the original 34 tools.
    one_case(old, old, 34, False)
    one_case(old, new, 34, False)
    one_case(new, old, 34, False, new_relay=True)
    one_case(new, new, 38, True, new_relay=True)

if __name__ == "__main__":
    main()
