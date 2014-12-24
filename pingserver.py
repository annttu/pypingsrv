#!/usr/bin/env python
# encoding: utf-8
from datetime import datetime, timedelta

import socket
import os
import struct
import threading
import random
import time
import math


class CacheNotFound(Exception):
    pass

class PermissionException(Exception):
    pass

class NotSuchHost(Exception):
    pass

class InvalidPacket(Exception):
    pass

class Cache(object):
    def __init__(self):
        self.items = {}
        self._timeout = 60 # seconds

    def get(self, key):
        if key in self.items.keys():
            i = self.items[key]
            if i[0] < datetime.now():
                # expired
                del self.items[key]
                raise CacheNotFound("Item not found from cache")
            return i[1]
        raise CacheNotFound("Item not found from cache")

    def set(self, key, value):
        self.items[key] = (datetime.now() + timedelta(seconds=self._timeout), value)



def make_pattern(pattern, length):
    return str(pattern * int(math.ceil(length / float(len(pattern)))))[:length]


class PingServer(threading.Thread):
    def __init__(self, ip_version=4, bindaddr=None):
        threading.Thread.__init__(self)
        if ip_version not in [4,6]:
            raise ValueError("Invalid IP version %s" % ip_version)
        if ip_version == 4:
            self._inet_type = socket.AF_INET
        else:
            self._inet_type = socket.AF_INET6
        self._sock = None
        self._bindaddr = bindaddr
        self._mtu = 1508
        self._packet_size = 128
        self._pattern = "A"
        self._create_socket()
        self._stop = False
        self._ids = {}
        self._seqs = {}
        self._sent_packets = {}
        self._results = {}
        self._pongs = []
        self._cache = Cache()

    def _get_next(self, destination):
        if destination not in self._ids:
            # Select unique id
            id = random.choice([i for i in range(1,65535) if i not in self._ids.keys()])
            self._ids[destination] = id
        id = self._ids[destination]
        if id not in self._seqs:
            self._seqs[id] = []
            seq = 1
        else:
            seq = self._seqs[id][-1] + 1
        self._seqs[id].append(seq)
        return (id, seq)

    def _get_current(self, destination):
        if destination not in self._ids:
            return None
        id = self._ids[destination]
        if id not in self._seqs:
            return None
        else:
            seq = self._seqs[id][-1]
        return (id, seq)

    def _get_checksum(self, string):
        # From ping.c in_cksum function
        checksum = 0
        count_to = len(string) & -2
        count = 0
        while count < count_to:
            this_val = ord(string[count + 1]) * 256 + ord(string[count])
            checksum += this_val
            checksum &= 0xffffffff  # Necessary?
            count += 2
        if count_to < len(string):
            checksum += ord(string[len(string) - 1])
            checksum &= 0xffffffff  # Necessary?
        checksum = (checksum >> 16) + (checksum & 0xffff)
        checksum += checksum >> 16
        answer = ~checksum
        answer &= 0xffff
        return answer >> 8 | (answer << 8 & 0xff00)

    def _pack_packet(self, id, seq):
        # Pack ICMP packet header, type, code, checksum, identifier,
        # sequence number.
        # Type is always 8, code is always 0, checksum depends on header
        # and contents and rest of header contains id
        # http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
        # Checksum is calculated with 0 as checksum
        header = struct.pack('bbHHh', 8, 0, 0, id, seq)
        data = make_pattern(self._pattern, self._packet_size)
        chksum = self._get_checksum(header + data)
        header = struct.pack('bbHHh', 8, 0, socket.htons(chksum), id, seq)
        return header + data

    def _unpack_packet(self, packet):
        # Unpack icmp packet, this works only for request and reply packets
        minimum_length = 8
        if self._inet_type == socket.AF_INET:
            minimum_length += 20
        else:
            minimum_length += 40
        if len(packet) <= minimum_length:
            raise InvalidPacket("Too short packet")
        # Packet contains first ip packet and then icmp header and data
        type, code, checksum, _id, seq = struct.unpack('bbHHh', packet[minimum_length-8:minimum_length])
        # TODO: check checksum
        # Checksum seems to be kind of optional.
        data = packet[minimum_length:]
        return {'type': type, 'code': code, 'checksum': checksum, 'id': _id, 'seq': seq, 'data': data}

    def _get_ip(self, destination):
        try:
            return self._cache.get(destination)
        except CacheNotFound:
            pass
        try:
            ip = socket.getaddrinfo(destination, 0, self._inet_type)[0][4][0]
        except socket.gaierror:
            raise NotSuchHost("Cannot resolve %s to IP-address" % destination)
        self._cache.set(destination, ip)
        return ip

    def stop(self):
        self._stop = True

    def _create_socket(self):
        if os.geteuid() != 0:
            raise PermissionException("Root permission required to use raw sockets.")
        self._sock = socket.socket(self._inet_type, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        if self._bindaddr:
            host = socket.gethostbyname(self._bindaddr)
            self._sock.bind((host,0))
        # OS X doesn't support these :/
        #self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        #self._sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)


    def _send(self, ip):
        """
        Send ICMP packet to destination
        :param destination:
        :return: packet sequence number
        """
        id, seq = self._get_next(ip)
        packet = self._pack_packet(id, seq)
        t = datetime.now()
        self._sock.sendto(packet, (ip, 1))
        self._sent_packets[(ip, id, seq)] = t
        if ip not in self._results:
            self._results[ip] = {}
        self._results[ip][t] = None
        return seq

    def ping(self, destination, timeout=5):
        """
        Ping destination
        :param destination: destination address
        :param timeout: Timeout in seconds
        :return:
        """
        ip = self._get_ip(destination)
        self._send(ip)
        return None

    def _prosess_pongs(self):
        while len(self._pongs) > 0:
            pong = self._pongs.pop()
            addr, data, recv_time = pong
            if addr not in self._results:
                continue
            try:
                x = self._unpack_packet(data)
                identifier = (addr, x['id'], x['seq'])
                if identifier in self._sent_packets:
                    sent_time =  self._sent_packets[identifier]
                    diff = recv_time - sent_time
                    self._results[addr][sent_time] = ((diff.seconds * 1000000.0) + diff.microseconds) / 1000.0
                else:
                    continue
                del x['data']
                x['time'] = self._results[addr][sent_time]
                print("%s: %s" % (addr, x))
            except InvalidPacket as e:
                print(e)
                continue

    def run(self):
        while not self._stop:
            data, addr = self._sock.recvfrom(self._mtu)
            t = datetime.now()
            self._pongs.append((addr[0], data, t))



if __name__ == '__main__':
    x = None
    try:
        x = PingServer()
        x.start()
        while True:
            x.ping("annttu.fi")
            x.ping("koti.annttu.fi")
            x.ping("lakka.kapsi.fi")
            x._prosess_pongs()
            time.sleep(0.5)
    except KeyboardInterrupt:
        if x:
            x.stop()
