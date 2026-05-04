#!/usr/bin/env python3

import subprocess
import logging

LOG = logging.getLogger("mitigation")

RATE_LIMIT = "10/second"
BURST = "20"

def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

def rule_exists(ip):
    result = run("iptables -S INPUT")
    return f"-s {ip} -j DROP" in result.stdout

def rate_limit_ip(ip):
    if rule_exists(ip):
        LOG.info(f"Already blocked: {ip}")
        return

    result = run("iptables -S INPUT")
    if f"-s {ip} -m limit" in result.stdout:
        LOG.info(f"Already rate-limited: {ip}")
        return

    cmd = f"iptables -I INPUT 1 -s {ip} -m limit --limit {RATE_LIMIT} --limit-burst {BURST} -j ACCEPT"
    run(cmd)
    LOG.info(f"[RATE LIMITED] {ip}")

def block_ip(ip):
    if rule_exists(ip):
        LOG.info(f"Already blocked: {ip}")
        return

    cmd = f"iptables -I INPUT 1 -s {ip} -j DROP"
    run(cmd)
    LOG.warning(f"[BLOCKED] {ip}")