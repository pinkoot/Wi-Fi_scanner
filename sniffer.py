import ipaddress
import sys
import socket
import os
import struct
import threading
import time
import logging
import argparse


# настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('sniffer.log'),  
        logging.StreamHandler()  
    ]
)

MESSAGE = 'moomin' #волшебное слово


class IP:
    def __init__(self, buff=None):
        header = struct.unpack("<BBHHHBBH4s4s", buff)
        self.ver = header[0] >> 4
        self.ihl = header[0] & 0xF
        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol_num = header[6]
        self.sum = header[7]
        self.src = header[8]
        self.dst = header[9]

        # IP-адреса, понятные человеку
        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)

        # Сопоставляем константы протоколов с их названиями
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except Exception as e:
            logging.error(f'{e} No protocol for {self.protocol_num}')
            self.protocol = str(self.protocol_num)


class ICMP:
    def __init__(self, buff=None):
        header = struct.unpack("<BBHHH", buff)
        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]


# Эта функция добавляет в UDP-датаграммы наше волшебное сообщение
def udp_sender(subnet):
    logging.info(f'Starting UDP sender for subnet {subnet}')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        for ip in ipaddress.ip_network(subnet).hosts():
            sender.sendto(bytes(MESSAGE, 'utf8'), (str(ip), 64212))
            logging.debug(f'Sent message to {ip}')


class Scanner:
    def __init__(self, host):
        self.host = host
        if os.name == 'nt':
            socket_protocol = socket.IPPROTO_IP
        else:
            socket_protocol = socket.IPPROTO_ICMP

        self.socket = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket_protocol
        )
        self.socket.bind((host, 0))
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        if os.name == 'nt':
            self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        logging.info(f'Scanner initialized on host {host}')

    def sniff(self, subnet):
        hosts_up = set()
        try:
            while True:
                # Читаем пакет
                raw_buffer = self.socket.recvfrom(65535)[0]
                # Создаём IP-заголовок из первых 20 байт
                ip_header = IP(raw_buffer[0:20])
                # Нас интересуют ICMP
                if ip_header.protocol == "ICMP":
                    offset = ip_header.ihl * 4
                    buf = raw_buffer[offset:offset + 8]
                    icmp_header = ICMP(buf)
                    # Ищем тип и код 3
                    if icmp_header.code == 3 and icmp_header.type == 3:
                        if ipaddress.ip_address(
                                ip_header.src_address
                        ) in ipaddress.IPv4Network(subnet):
                            # Проверяем, содержит ли буфер наше волшебное сообщение
                            if raw_buffer[len(raw_buffer) - len(MESSAGE):
                               ] == bytes(MESSAGE, 'utf8'):
                                tgt = str(ip_header.src_address)
                                if tgt != self.host and tgt not in hosts_up:
                                    hosts_up.add(str(ip_header.src_address))
                                    logging.info(f'Host Up: {tgt}')
                                    print(f'Host Up: {tgt}')

        except KeyboardInterrupt:
            # Если мы в Windows, то отключаем неизбирательный режим
            if os.name == 'nt':
                self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            logging.warning('User interrupted the scan.')

        if hosts_up:
            logging.info(f'\n\nSummary: Hosts up on {subnet}')
            print(f'\n\nSummary: Hosts up on {subnet}')
            for host in sorted(hosts_up):
                logging.info(f'{host}')
                print(f'{host}')
        else:
            logging.info('No hosts found.')
        print('')
        sys.exit()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Network scanner")
    parser.add_argument('--host', type=str, default='192.168.0.100', help='Host to scan from')
    parser.add_argument('--subnet', type=str, default='192.168.0.0/24', help='Subnet to scan')
    args = parser.parse_args()

    logging.info(f'Starting scanner on host {args.host} for subnet {args.subnet}')
    s = Scanner(args.host)

    time.sleep(1)
    t = threading.Thread(target=udp_sender, args=(args.subnet,))
    t.start()
    s.sniff(args.subnet)
    