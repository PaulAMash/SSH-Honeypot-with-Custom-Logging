#!/usr/bin/env python3

import json
import argparse
from collections import Counter

def parse_logs(logfile):
    ip_counter = Counter()
    cmd_counter = Counter()
    download_counter = Counter()

    with open(logfile, 'r') as f:
        for line in f:
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            event = entry.get('eventid', '')
            if event.startswith('cowrie.login'):
                ip = entry.get('src_ip')
                if ip:
                    ip_counter[ip] += 1
            if event == 'cowrie.command.input':
                cmd = entry.get('input')
                if cmd:
                    cmd_counter[cmd] += 1
            if event == 'cowrie.session.file_download':
                outfile = entry.get('outfile')
                if outfile:
                    download_counter[outfile] += 1

    return ip_counter, cmd_counter, download_counter

def write_summary(ip_c, cmd_c, dl_c, output):
    with open(output, 'w') as out:
        out.write("SSH Honeypot Attack Summary\n")
        out.write("===========================\n\n")
        out.write("Top attacking IPs:\n")
        for ip, count in ip_c.most_common(10):
            out.write(f"{ip}: {count}\n")
        out.write("\nTop commands executed:\n")
        for cmd, count in cmd_c.most_common(10):
            out.write(f'{cmd}: {count}\n')
        out.write("\nDownloaded files:\n")
        for file, count in dl_c.most_common(10):
            out.write(f"{file}: {count}\n")
    print(f"Summary written to {output}")

def main():
    parser = argparse.ArgumentParser(description="Parse Cowrie SSH honeypot logs")
    parser.add_argument("--logfile", default="cowrie.json",
                        help="Path to Cowrie JSON log file")
    parser.add_argument("--output", default="summary.txt",
                        help="Output summary file")
    args = parser.parse_args()

    ip_c, cmd_c, dl_c = parse_logs(args.logfile)
    write_summary(ip_c, cmd_c, dl_c, args.output)

if __name__ == "__main__":
    main()
