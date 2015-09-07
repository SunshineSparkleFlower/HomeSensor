#!/usr/bin/python

import socket
import sys
import os
import re
import time
import select
import string
import requests
import icmp
import ip

ROUTER_USERNAME = "username"
ROUTER_PASSWORD = "password"

class PingSocket:
    def __init__(self, addr):
        self.dest = (socket.gethostbyname(addr), 0)
        self.open_icmp_socket()

    def open_icmp_socket(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                    socket.IPPROTO_ICMP)
        self.socket.setblocking(1)

    def sendto(self, packet):
        self.socket.sendto(packet, self.dest)

    def recvfrom(self, maxbytes):
        return self.socket.recvfrom(maxbytes)

class Pinger:
    def __init__(self, addr, num):
        self.num = num
        self.last = 0
        self.sent = 0
        self.times = {}
        self.deltas = []
        self.sock = PingSocket(addr)
        self.pid = os.getpid()
        self.addr = addr
        ipaddr = socket.gethostbyname(addr)

    def send_packet(self):
        pkt = icmp.Echo(id=self.pid, seq=self.sent, data='ping')
        buf = icmp.assemble(pkt)
        self.times[self.sent] = time.time()
        self.sock.sendto(buf)
        self.plen = len(buf)
        self.sent = self.sent + 1

    def recv_packet(self, pkt, when):
        try:
            sent = self.times[pkt.get_seq()]
            del self.times[pkt.get_seq()]
        except KeyError:
            return
        # limit to ms precision
        delta = int((when - sent) * 1000.)
        self.deltas.append(delta)
        if pkt.get_seq() > self.last:
            self.last = pkt.get_seq()

    def ping(self):
        # don't wait more than 10 seconds from now for first reply
        self.last_arrival = time.time()
        while 1:
            if self.sent < self.num:
                self.send_packet()
            elif not self.times and self.last == self.num - 1:
                break
            else:
                now = time.time()
                if self.deltas:
                    # Wait no more than 10 times the longest delay so far
                    if (now - self.last_arrival) > max(self.deltas) / 100.:
                        break
                else:
                    # Wait no more than 5 seconds
                    if (now - self.last_arrival) > 5.:
                        break
            self.wait()

        return self.get_summary()

    def wait(self):
        start = time.time()
        timeout = 1.0
        while True:
            rd, wt, er = select.select([self.sock.socket], [], [], timeout)
            if rd:
                # okay to use time here, because select has told us
                # there is data and we don't care to measure the time
                # it takes the system to give us the packet.
                arrival = time.time()
                try:
                    pkt, who = self.sock.recvfrom(4096)
                except socket.error:
                    continue
                # could also use the ip module to get the payload
                repip = ip.disassemble(pkt)
                try:
                    reply = icmp.disassemble(repip.data)
                except ValueError:
                    continue

                if reply.get_type() != icmp.ICMP_ECHOREPLY:
                    continue

                if reply.get_id() == self.pid:
                    self.recv_packet(reply, arrival)
                    self.last_arrival = arrival
            timeout = (start + 1.0) - time.time()
            if timeout < 0:
                break
            
    def get_summary(self):
        dmin = min(self.deltas) if len(self.deltas) > 0 else -1
        dmax = max(self.deltas) if len(self.deltas) > 0 else -1
        davg = reduce(lambda x, y: x + y, self.deltas) / len(self.deltas) if len(self.deltas) > 0 else -1
        sent = self.num
        recv = sent - len(self.times.values())
        loss = float(sent - recv) / float(sent)
        return dmin, davg, dmax, sent, recv, loss

class QuerySocket:
    def __init__(self, host, port):
        self.sd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            print "Hostname '%s' could not be resolved.." % host
            sys.exit()

        self.sd.connect((ip, port))

    def query(self, msg, minrecvlen=5):
        self.sd.sendall(msg)
        ret = self.recv()
        return ret + self.recvmin(minrecvlen)

    def recvmin(self, minsize=10):
        ret = ""
        while len(ret) < minsize:
            ret += self.recv()

        return ret

    def recv_until(self, until):
        ret = ""
        while ret.find(until) == -1:
            ret += self.recv()

        return ret

    def recv(self, size=4096):
        return self.sd.recv(size)
        
    def send(self, msg):
        return self.sd.sendall(msg)

    def close(self):
        self.sd.close()

class RouterInterface:
    def __init__(self, host, port):
        self.sd = QuerySocket(host, port)

    def login(self, user, passwd):
        self.sd.recv(), self.sd.recv()
        self.sd.send("%s\n" % user)
        self.sd.recv(), self.sd.recv()
        self.sd.send("%s\n" % passwd)
        self.sd.recv(), self.sd.recv()

    def get_lanhosts(self):
        self.sd.send("lanhosts show all\n")
        data = self.sd.recv_until("> ")

        data = re.sub("^\s+", "", data, flags=re.MULTILINE)
        data = re.sub("[ \t]+", " ", data)

        ret = [row.split(' ') for row in data.splitlines()][:-1]
        ret[2] = [" ".join(ret[2][:2]), " ".join(ret[2][2:4]), " ".join(ret[2][4:7]), ret[2][7]]

        return ret

    def mac_lookup(self, mac_addr):
        hosts = self.get_lanhosts()

        for host in hosts[3:]:
            if mac_addr == host[0]:
                return host[1]

        return None

    def close(self):
        self.sd.close()

class ServerInterface:
    def __init__(self, url, port):
        self.url = url
        self.port = port

    def get_scan_list(self, suffix):
        url = "http://%s:%d%s" % (self.url, self.port, suffix)
        resp = requests.get(url)
        return resp.json()

def scan_hosts(serv):
    print "Getting scanlist.."
    macs = serv.get_scan_list("/scanlist")
    router = RouterInterface("10.0.0.1", 23)
    router.login(ROUTER_USERNAME, ROUTER_PASSWORD)

    for host in macs:
        ip = router.mac_lookup(host)

        print "scanning %s (%s)" % (host, ip)

        p = Pinger(ip, 5)
        res = p.ping()

        print "    %s: %d/%d (%d%%)" % (host, res[3], res[4], res[5] * 100)

    router.close()

def main():
    serv = ServerInterface("10.0.0.9", 3001)

    while True:
        scan_hosts(serv)
        time.sleep(10)


if __name__ == "__main__":
    main()
