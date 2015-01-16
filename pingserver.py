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
import logging

# Some definitions from limits.h
# Thanks to struct to not include these....

SHRT_MIN = -0x8000
SHRT_MAX = 0x7FFF


logger = logging.getLogger("PingServer")


class PingException(Exception):
    pass

class CacheNotFound(PingException):
    pass


class PermissionException(PingException):
    pass


class NotSuchHost(PingException):
    pass


class InvalidPacket(PingException):
    pass


# Is there better way to define <type 'function'> ?
function = type(lambda x: x)

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


class PingEventHandlers(object):
    def __init__(self):
        self.on_packetloss = None
        self.on_response = None


class ResultData(object):
    def __init__(self, sent):
        self.sent = sent
        self.timeout_reported = False
        self.time = None

class WorkerThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self._stop = False

    def stop(self):
        self._stop = True


class PingerThread(WorkerThread):
    def __init__(self, instance, destination, interval, count):
        WorkerThread.__init__(self)
        self.instance = instance
        self.destination = destination
        self.interval = interval
        self.count = count

    def run(self):
        while not self._stop:
            self.instance.trigger_ping(self.destination)
            if self.count is not None:
                self.count -= 1
                if self.count == 0:
                    return
            if self.interval < 1:
                time.sleep(self.interval)
            else:
                time_left = float(self.interval)
                while time_left > 0.0 and not self._stop:
                    t = min(time_left, 1.0)
                    time.sleep(t)
                    time_left -= t


class PongThread(WorkerThread):
    def __init__(self, instance):
        WorkerThread.__init__(self)
        self.instance = instance

    def run(self):
        while not self._stop:
            self.instance._process_pongs()
            self.instance._timeout_clear()
            time.sleep(0.5)


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
        self._timeouts = {}
        self._pongs = []
        self._event_handlers = {}
        self._subthreads = []
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
            if seq > SHRT_MAX:
                seq = SHRT_MIN
        self._seqs[id].append(seq)
        return (id, seq)

    def _get_id(self, destination):
        if destination not in self._ids:
            return None
        return self._ids[destination]

    def _get_destination(self, id):
        for key, _id in self._ids.items():
            if _id == id:
                return key

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
        return {'type': type, 'code': code, 'checksum': checksum, 'id': _id, 'seq': seq}

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
        for t in self._subthreads:
            t.stop()

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


    def _send(self, destination):
        """
        Send ICMP packet to destination
        :param destination:
        :return: packet sequence number
        """
        ip = self._get_ip(destination)
        id, seq = self._get_next(destination)
        packet = self._pack_packet(id, seq)
        t = datetime.now()
        try:
            self._sock.sendto(packet, (ip, 1))
        except socket.error:
            logging.exception("Cannot send ping packet")
        self._sent_packets[(ip, id, seq)] = seq
        if destination not in self._results:
            self._results[destination] = {}
        self._results[destination][seq] = ResultData(t)
        return seq

    def ping(self, destination, interval=1, count=None, timeout=5, on_packetloss=None, on_response=None):
        """
        Ping destination
        :param destination: Target address or name
        :param interval: interval in seconds
        :param count: how many times to ping, None means infinite
        :param timeout: timeout for packet
        :param on_loss: function to call on packet loss
        :param on_response: function to call when packet received
        :return:
        """
        if on_packetloss is not None and type(on_packetloss) != function:
            raise ValueError("on_packetloss should be function")
        if on_response is not None and type(on_response) != function:
            raise ValueError("on_response should be function")
        t = PingerThread(self, destination, interval, count)
        t.start()
        self._subthreads.append(t)
        self._event_handlers[destination] = PingEventHandlers()
        self._event_handlers[destination].on_packetloss = on_packetloss
        self._event_handlers[destination].on_response = on_response
        self._timeouts[destination] = timeout

    def trigger_ping(self, destination):
        """
        Ping destination once, not very useful itself.
        :param destination: destination address
        :param timeout: Timeout in seconds
        :return:
        """
        self._send(destination)
        return None

    def _process_pongs(self):
        while len(self._pongs) > 0:
            pong = self._pongs.pop()
            addr, data, recv_time = pong
            #if addr not in self._results:
            #    continue
            try:
                x = self._unpack_packet(data)
                identifier = (addr, x['id'], x['seq'])

                if identifier not in self._sent_packets:
                    continue

                destination = self._get_destination(x['id'])
                resultdata = self._results[destination][x['seq']]
                diff = recv_time - resultdata.sent
                diff = ((diff.seconds * 1000000.0) + diff.microseconds) / 1000.0
                resultdata.time = diff
                x['time'] = diff
                event_handler = self._event_handlers[destination]
                if event_handler.on_response:
                    try:
                        event_handler.on_response(destination, x)
                    except Exception:
                        logging.exception("on_success handler for %s returned error" % destination)
                    except:
                        logging.error("on_success handler for %s returned error" % destination)
                logger.debug("%s: %s" % (addr, x))
            except InvalidPacket:
                logger.exception("Invalid packet received")
                continue

    def _timeout_clear(self):
        # TODO: clear self._sent_packets
        for key in self._seqs.keys():
            if len(self._seqs[key]) > 1000:
                self._seqs[key] = self._seqs[key][-1000:]
        now = datetime.now()
        for destination in self._results.keys():
            if not self._event_handlers[destination].on_packetloss:
                continue
            for seq in self._results[destination].keys():
                res = self._results[destination][seq]
                if res.timeout_reported == True:
                    continue
                if res.time is None and res.sent < (now - timedelta(seconds=self._timeouts[destination])):
                    self._results[destination][seq].timeout_reported = True
                    try:
                        self._event_handlers[destination].on_packetloss(destination, res.sent)
                    except Exception:
                        logging.exception("on_packetloss handler for %s returned error" % destination)
                    except:
                        logging.error("on_packetloss handler for %s returned error" % destination)



    def run(self):
        t = PongThread(self)
        t.start()
        self._subthreads.append(t)
        while not self._stop:
            data, addr = self._sock.recvfrom(self._mtu)
            t = datetime.now()
            self._pongs.append((addr[0], data, t))



if __name__ == '__main__':
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    x = None

    def on_packetloss(dest, x):
        print("Packetloss %s, %s" % (dest, x))

    def on_success(dest, x):
        print("Success %s, %s" % (dest, x))

    try:
        x = PingServer()
        x.start()
        x.ping("annttu.fi", interval=1, on_packetloss=on_packetloss, on_response=on_success)
        x.ping("koti.annttu.fi", interval=4, on_packetloss=on_packetloss)
        x.ping("lakka.kapsi.fi", interval=2, on_packetloss=on_packetloss)
        while True:
            time.sleep(9999999)
    except KeyboardInterrupt:
        if x:
            x.stop()
    except Exception:
        if x:
            x.stop()
