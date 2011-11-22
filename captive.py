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

class DHCPServer(ThreadingUDPServer):
    
    allow_reuse_address = True
    
    _read_offset = 0
    
    def __init__(self, addr):
        ThreadingUDPServer.__init__(self, (addr, 67), None)
        
    def process_request_thread(self, request, client_address):
        try:
            self.package = request[0]
            
            'BxBxL'
            self.shutdown_request(request)
        except:
            self.handle_error(request, client_address)
            self.shutdown_request(request)
        
    def read(self, fmt):
        data = struct.unpack_from('!' + fmt, self.package, self._read_offset)
        self._read_offset += struct.calcsize(fmt)
        
        if len(data) > 1:
            return data
        else:
            return data[0]
     

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
    
    DHCPServer(addr).handle_request()