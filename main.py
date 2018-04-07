# !/usr/bin/env python3
import sys

import dnsserver
import threading
import argparse


class DNSServerThread(threading.Thread):
    def __init__(self, master_server, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.server = dnsserver.DNSServer(master_server)

    def run(self):
        self.server.start()

    def stop(self):
        self.server.running = False


def parse_args():
    parser = argparse.ArgumentParser(description="Launch a DNS server.")
    parser.add_argument("-s", "--server-address", type=str,
                        default='8.8.8.8',
                        help="Master DNS server address")
    return parser.parse_args()


if __name__ == '__main__':
    parsed_args = parse_args()
    thread = DNSServerThread(parsed_args.server_address)
    thread.start()
    line = ""
    while "quit" not in line and "stop" not in line:
        line = sys.stdin.readline()
    thread.stop()
    thread.join()
