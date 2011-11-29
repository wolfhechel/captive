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

from socket import *
from os import strerror, _get_exports_list
from ctypes import POINTER, CDLL, c_int, c_void_p, byref, create_string_buffer
from struct import unpack_from, pack

SO_SET_REPLACE          = 0
SO_SET_ADD_COUNTERS     = 1

SO_GET_INFO             = 0
SO_GET_ENTRIES          = 1
SO_GET_REVISION_MATCH   = 2
SO_GET_REVISION_TARGET  = 3

NF_INET_PRE_ROUTING         = 0
NF_INET_LOCAL_IN            = 1
NF_INET_FORWARD             = 2
NF_INET_LOCAL_OUT           = 3
NF_INET_POST_ROUTING        = 4
NF_INET_NUMHOOKS            = 5

XT_TABLE_MAXNAMELEN         = 32
XT_EXTENSION_MAXNAMELEN     = 29
XT_TABLE_MAXNAMELEN         = 32

COUNTER_MAP_NOMAP           = 0
COUNTER_MAP_NORMAL_MAP      = 1
COUNTER_MAP_ZEROED          = 2
COUNTER_MAP_SET             = 3

libc_handle = CDLL('libc.so.6')
libc_handle.__errno_location.restype = POINTER(c_int)

def errcheck(result, func, arguments):
    if result != 0:
        errno = libc_handle.__errno_location().contents.value
        
        raise error(errno, strerror(errno))
    
    return result

libc_handle.getsockopt.errcheck = errcheck
libc_handle.getsockopt.argtypes = (c_int,           # socket
                                   c_int,           # level
                                   c_int,           # option_name
                                   c_void_p,        # option_value
                                   POINTER(c_int))  # option_len

class socket(SocketType):
    def getsockopt(self, level, optname, value, buflen=None):
        buf = create_string_buffer(value, buflen)
        size = c_int(len(buf))
        
        libc_handle.getsockopt(self.fileno(), level, optname, buf, byref(size))
        
        return buf.raw

SocketType = socket

__all__ = ['IPv4', 'IPv6', 'ARP']

''' There's a really horrible nest of relations in the iptables core,
first of all. There's three familites that each has their own set of tables:
 * IPv4
 * IPv6
 * ARP

Each of them has a fixed set of tables;
 * filter - Filters packets. 
 * nat - Translates addresses for routing.
 * mangle - Alters and trashes packets.
 * raw - 

In these tables there's s couple of chains, or hooks if you prefer (right?):
 * INPUT - Packets addressed to our local machine.
 * OUTPUT - Packets addressed from our local machine.
 * FORWARD - Packets addressed to some remote machine (we're doing routing!).
 * PREROUTING - Mangling packets before routing.
 * POSTROUTING - Mangling packets after routing.
A user can create new chains and make a `jump' from one chain to another.

Then there's targets specified for chains. (Oh and also; each chain has it's
 default policy.):
 * ACCEPT - Packet is accepted.
 * DROP - Packet is dropped.
 * REJECT - Packet is rejected.
 * logaccept - ACCEPT and log.
 * logdrop - DROP and log.
 * logreject - Take a guess?
 * DNAT - Altering packet destination address.
 * SNAT - Altering packet source address.
 * TRIGGER - Port triggering, redring input ports based on output traffic.
Additional targets may be defined by extensions.

Right, so a chain can contain several entries in sequence. (Chain, duh?)
(Entries are usualy refered to as rules, however not in the core code.)
Basically, if a rule matches then the iteration breaks and the chain `returns'.
If not, then naturally the iteration continues. If the packet doesn't match any
rule then the default chain policy is used.

So, the relation looks as such;

  Family -> Table -> Chain -> Entries [-> Default policy] 

Now that you know that you'll have no problem what so ever to understand why
this package hierarchy is composed the way it is.
'''

class BaseTable:
    
    " Because we want inheritance, let's avoid setting a default family. "
    af = None
    
    ' This is true for IPv4 and IPv6, ARP overrides this.'
    base_ctl = 64
    
    table = None
    
    ' Share our sockets between all tables. '
    _socks = {}
    
    hooks = []

    def __init__(self, table):
        ''' We try to maintain references to a minimal set of sockets only,
        meaning if a socket of our family already exists that's the one we want
        to use. '''
        if self.af not in self._socks.keys():
            self._socks[self.af] = socket(self.af, SOCK_RAW, IPPROTO_RAW)
   
        self.table = table

        self._initiate_table()

    def _initiate_table(self):
        raw = self.getsockopt(SO_GET_INFO, self.table, 84)

        name, valid_hooks = unpack_from('%dsI' % XT_TABLE_MAXNAMELEN, raw)

        if self.table != name.strip('\0'):
            raise ValueError('Table name does not match name obtained info.')

        hook_entry = unpack_from('%dI' % NF_INET_NUMHOOKS, raw,
                                 XT_TABLE_MAXNAMELEN + 4)

        for hook in range(NF_INET_NUMHOOKS):
            if valid_hooks & (1 << hook):
                entry = hook_entry[hook]
            else:
                entry = None

            self.hooks.append(entry)

        # Ignoring underflows, what are they for anyway?

        num_entries, size = unpack_from('2I', raw, 76)

        alloc_size = XT_TABLE_MAXNAMELEN + 4 + size
        # TODO: Continue from here
        entries = self.getsockopt(SO_GET_ENTRIES, , alloc_size)

        print entries

    def getsockopt(self, opt, value, buflen=None):
        return self._socks[self.af].getsockopt(IPPROTO_IP, self.base_ctl + opt,
                                               value, buflen)
        
    def setsockopt(self, opt, value):
        return self._socks[self.af].setsockopt(IPPROTO_IP, self.base_ctl + opt,
                                               value)

class IPv4(BaseTable):
    af = AF_INET

class IPv6(BaseTable):
    af = AF_INET6
    
class ARP(IPv4):
    base_ctl = 96

if __name__ == '__main__':
    IPv4('filter')
