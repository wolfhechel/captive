#!/usr/bin/env python2.7
#
# -*- coding: utf-8 -*-
#
# Copyright (c) 2011, Pontus Carlsson <PontusCarlsson@live.se>
#
# This software is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this software.  If not, see <http://www.gnu.org/licenses/>.
#
from argparse import ArgumentParser, FileType
from SocketServer import ThreadingUDPServer
from time import strftime
import socket, struct

'''
class DNSQuery:
  def __init__(self, data):
    self.data=data
    self.domain=''

    type = (ord(data[2]) >> 3) & 15   # Opcode bits
    if type == 0:                     # Standard query
      start=12
      len=ord(data[start])
      while len != 0:
        self.domain+=data[start+1:start+len+1]+'.'
        start+=len+1
        len=ord(data[start])

  def response(self, ip):
    packet=''
    if self.domain:
      packet+=self.data[:2] + "\x81\x80"
      packet+=self.data[4:6] + self.data[4:6] + '\x00\x00\x00\x00'   # Questions and Answers Counts
      packet+=self.data[12:]                                         # Original Domain Name Question
      packet+='\xc0\x0c'                                             # Pointer to domain name
      packet+='\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'             # Response type, ttl and resource data length -> 4 bytes
      packet+=str.join('',map(lambda x: chr(int(x)), ip.split('.'))) # 4bytes of IP
    return packet
 if __name__ == '__maain__':
  ip='192.168.1.1'
  
  udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  udps.bind(('',53))
  
  try:
    while 1:
      data, addr = udps.recvfrom(1024)
      p=DNSQuery(data)
      udps.sendto(p.response(ip), addr)
      print 'Responded: %s -> %s' % (p.domain, ip)
  except KeyboardInterrupt:
    print 'Done'
    udps.close() '''
 
def logger(msg, *args):
    ''' Writes information to specified logging output.
    
    @param msg: message to write, formatable
    @param args: string formatting arguments
    '''
    logger.write('[%s] -> %s\n' % (strftime('%Y-%m-%d %H:%M:%S'), msg % args))

def get_iface(iface):
    ''' Resolve IP address and netmask from interface name.
    
    @param iface: Interface name
    @return: [net_addr, net_mask]
    '''
    from fcntl import ioctl
    
    iface = iface[:15].ljust(256, '\0')
    sock = socket.socket()
    
    try:
        info = [ioctl(sock, sig, iface)[20:24] for sig in (0x8915, 0x891b)]
    except IOError:
        info = None
    
    sock.close()
    
    return info

def inet_ntoi(packed_ip):
    ''' Unpack a packed IP to an integer representant.
    
    @param packed_ip: Packed IP to convert
    @return: Integer representantive IP
    '''
    return struct.unpack('<I', packed_ip)[0]

def inet_iton(integer_ip):
    ''' Pack an integer representative IP.
    
    @param integer_ip: Integer representative IP to pack
    @return: Packed IP
    '''
    return struct.pack('<I', integer_ip)

class Clients:
    
    PENDING     = 0x01
    ESTABLISHED = 0x02
    AUTHORIZED  = 0x03
    
    current = 1
    
    leases = {}
    
    def __init__(self, addr, mask):
        
        self.addr = addr
        self.i_addr = inet_ntoi(self.addr)
        self.mask = mask
        self.i_mask = inet_ntoi(self.mask)
        
        self.subn = self.i_addr & self.i_mask
        
        self.hosts = (self.i_mask ^ 0xffffffff)

    def offer_lease(self, mac):
        while True:
            self.current += 1
        
            lease_ip = self.subn + self.hosts[self.current]
            
            if lease_ip != self.i_addr:
                addr = inet_iton(lease_ip)
                
                break
        
        self.leases[addr] = {'state'  : self.PENDING,
                             'client' : mac,
                             'leased' : time()}
    
    def authorize_client(self, addr):
        self.leases[addr]['state'] = self.AUTHORIZED
        
    def acknowledge(self, addr):
        self.leases[addr]['state'] = self.ESTABLISHED
        
    def denounce(self, addr):
        del self.leases[addr]

class DHCPServer(ThreadingUDPServer):
    
    allow_reuse_address = True
    
    clients = None
    
    static_options = None
    
    def __init__(self, addr, clients):
        self.clients = clients
        
        broadcast = inet_iton(clients.subnet + clients.hosts + 1)
        
        # Set static options
        self.server_opts = {
                             1 : clients.mask, # Subnet mask
                             3 : clients.addr, # Router address
                             6 : clients.addr, # Domain Name Server address
                            28 : broadcast,    # Broadcast address
                            51 : 60 * 60,      # IP address lease time
                            54 : clients.addr, # DHCP Server identifier
                            58 : 60 * 30,      # Renewal time
                            59 : 60 * 50       # Rebinding time
                            }
        
        ThreadingUDPServer.__init__(self, (addr, 67), self.handle_message)
    
    def handle_message(self, request, *_):
        self.data = [request[0], 0]
        
        header = self.read('2xBxI2xH4I16s192xI')
        
        if header.pop() != 0x63825363:
            # Invalid message
            return 
        
        client_mac = header[7][:header[0]]
        xid = header[1]
        
        broadcast = True if 128 & header[2] else False
        
        addr = dict(zip(('client', 'your', 'server', 'gateway'), header[2:6]))
        
        options = {}
        
        while True:
            opt = self.read('B')
            
            if opt == 0xff: # End option
                break
            elif opt == 0x00: # Padding
                continue
            else:
                options[opt] = self.read('%dx' % self.read('B'))    

        self.respond(xid, client_mac, broadcast, options)
            
    def read(self, fmt):
        data = struct.unpack_from('!%s' % fmt, self.data[0], self.data[1])
        self.data[1] += struct.calcsize(fmt)
        
        if len(data) > 1:
            return list(data)
        elif len(data) == 0:
            return None
        else:
            return data[0]

    def respond(self, xid, client_mac, broadcast):
        
    def server_bind(self):
        ' Use ioctl signal to resolve address from interface. '
        
        ''' Set our socket to accept broadcast messages and limit down our
            multicasting interfaces to the selected one. '''
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                               self.server_address[0])
        
        ' When binding we actually want _every_ address, for broadcasting. '
        self.server_address = ('', self.server_address[1])
        
        ThreadingUDPServer.server_bind(self)
    
if __name__ == '__main__':
    
    # Arguments parsing 
    parser = ArgumentParser(description="Captive portal in pure python.",
                            epilog='Copyright (C) 2011 Pontus Carlsson')
    
    parser.add_argument('-d', '--daemonize', action='store_true',
                      help='daemonize process (fork to background)')
    
    parser.add_argument('-l', '--log', metavar='FILE', default='-',
                      type=FileType('wb',0), help='log process output to FILE')
    
    parser.add_argument('interface', help='bind to interface')
    
    args = parser.parse_args()
    
    iface_info = get_iface(args.interface)
    
    if iface_info == None:
        parser.error('invalid interface')
    
    addr, mask = iface_info
    
    setattr(logger, 'write', args.log.write)
    
    logger('Resolved interface %s to %s/%s', args.interface,
           socket.inet_ntoa(addr), socket.inet_ntoa(mask))
    
    
    clients = Clients(addr, mask)
    
    DHCPServer(addr, clients).serve_forever()