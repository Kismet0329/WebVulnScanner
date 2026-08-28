#!/usr/bin/env python3
"""SSH helper for VMware Ubuntu (local lab only)."""
import argparse
import sys

import paramiko


def run(host, user, password, command, timeout=120):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=user, password=password, timeout=15)
    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        code = stdout.channel.recv_exit_status()
        sys.stdout.write(out)
        if err:
            sys.stderr.write(err)
        return code
    finally:
        client.close()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="192.168.222.134")
    p.add_argument("--user", default="ark")
    p.add_argument("--password", required=True)
    p.add_argument("command")
    p.add_argument("--timeout", type=int, default=300)
    args = p.parse_args()
    sys.exit(run(args.host, args.user, args.password, args.command, args.timeout))


if __name__ == "__main__":
    main()
