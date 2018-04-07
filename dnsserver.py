# !/usr/bin/env python3
import dnsclient
import socket


def form_server_response_header(id_, rcode):
    return dnsclient.form_header(id_, 0, 0, 0, 0, True, 1, rcode,
                                 recursion_available=1)


def form_resource_record(hostname: str, type_: int, class_: int, ttl: int,
                         data: bytes):
    return dnsclient.encode_hostname(hostname) + \
           type_.to_bytes(2, byteorder='big', signed=False) + \
           class_.to_bytes(2, byteorder='big', signed=False) + \
           ttl.to_bytes(4, byteorder='big', signed=False) + \
           len(data).to_bytes(2, byteorder='big', signed=False) + \
           data


TTL = 3600 * 24


def ipv4_to_bytes(ipv4: str) -> bytes:
    parts = ipv4.split('.')
    if len(parts) != 4:
        raise ValueError
    return bytes([int(part) for part in parts])


class DNSServer:
    def __init__(self, master_server="8.8.8.8"):
        self.server = master_server
        self.client = dnsclient.DNSClient(timeout=0.5)
        self.running = True

    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        sock.bind(("127.0.0.1", 53))
        try:
            while self.running:
                try:
                    message, address = sock.recvfrom(1024)
                    try:
                        query = dnsclient.decode_dns_message(message)
                    except Exception:
                        sock.sendto(form_server_response_header(0, 1), address)
                        continue
                    if query["header"]["is_response"] == 1 or \
                            query["header"]["opcode"] != 0:
                        sock.sendto(
                            form_server_response_header(query["header"]["id"],
                                                        4),
                            address)
                        continue

                    sock.sendto(self.handle_query(query), address)
                except ConnectionError as e:
                    print(str(e))
                except socket.timeout:
                    continue
        finally:
            self.client.save_caches()
            sock.close()

    def handle_query(self, query: dict) -> bytes:
        q_count = 0
        a_count = 0
        questions = bytes()
        answers = bytes()
        for question in query["questions"]:
            hostname = question['hostname'][0]

            q_type = question["type"]
            q_class = question['class']

            question_bytes = dnsclient.form_question(hostname, q_type, q_class)
            questions += question_bytes
            q_count += 1

            try:
                if q_class == dnsclient.CLASS_IN:
                    if q_type == dnsclient.TYPE_A:
                        answer = self.client.hostname_to_ip(hostname,
                                                            dns_server_address
                                                            =self.server,
                                                            ipv6=False)
                        for ip in answer.setdefault(hostname, []):
                            answers += form_resource_record(hostname,
                                                            dnsclient.TYPE_A,
                                                            dnsclient.CLASS_IN,
                                                            TTL,
                                                            ipv4_to_bytes(ip))
                            a_count += 1

                    elif q_type == dnsclient.TYPE_NS:
                        answer = self.client.hostname_to_ns(hostname,
                                                            dns_server_address
                                                            =self.server)
                        for host in answer.setdefault(hostname, []):
                            answers += form_resource_record(hostname,
                                                            dnsclient.TYPE_NS,
                                                            dnsclient.CLASS_IN,
                                                            TTL,
                                                            dnsclient
                                                            .encode_hostname(
                                                                host))
                            a_count += 1
                    else:
                        print("Can't handle type " + str(q_type))
                        continue
            except dnsclient.ResponseError as e:
                return dnsclient.form_header(query["header"]["id"], 1, 0, 0, 0,
                                             True, 1, e.code,
                                             1) + question_bytes

        return dnsclient.form_header(query["header"]["id"], q_count, a_count,
                                     0, 0,
                                     True, 1, 0, 1) + questions + answers


if __name__ == '__main__':
    DNSServer().start()
