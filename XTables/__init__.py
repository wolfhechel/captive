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
from os import strerror
from ctypes import *

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

def xt_generator(type_, attr, address, size, offset=0):
    while offset < size:
        data = type_.from_address(address + offset)
        offset += data.__getattribute__(attr)
        
        yield data

class BaseIP(Structure):
    _fields_ = [('src', c_uint),
                ('dst', c_uint),
                ('smsk', c_uint),
                ('dmsk', c_uint),
                ('iniface', c_char * 16),
                ('outiface', c_char * 16),
                ('iniface_mask', c_ubyte * 16),
                ('outiface_mask', c_ubyte * 16),
                ('proto', c_int16),
                ('flags', c_int8),
                ('invflags', c_int8)]

class Match(Structure):
    _fields_ = [('match_size', c_uint16),
                ('name', c_char * XT_EXTENSION_MAXNAMELEN),
                ('revision', c_uint8),
                ('data', c_ubyte * 0)]
    
    def __repr__(self):
        return " -> Match [0x%x] Size: %d" % (addressof(self), self.match_size)

class Entry(Structure):
    _fields_ = [('ip', BaseIP),
                ('nfcache', c_uint),
                ('target_offset', c_int16),
                ('next_offset', c_int16),
                ('comefrom', c_uint),
                ('pcnt', c_uint64),
                ('bcnt', c_uint64),
                ('elems', c_ubyte * 0)]
    
    def __repr__(self):
        return "Entry [0x%x] Bytes: %d Packets: %d" % (addressof(self),
                                                       self.bcnt, self.pcnt)

class Entries(Structure):
    _fields_ = [('name', c_char * XT_TABLE_MAXNAMELEN),
                ('size', c_uint),
                ('entrytable', Entry * 0)]

class BaseTable(Structure):
    _fields_ = [('name', c_char * XT_TABLE_MAXNAMELEN),
                ('valid_hooks', c_uint),
                ('hook_entry', c_uint * NF_INET_NUMHOOKS),
                ('underflow', c_uint * NF_INET_NUMHOOKS),
                ('num_entries', c_uint),
                ('size', c_uint)]

    " Because we want inheritance, let's avoid setting a default family. "
    family = None
    
    ' This is true for IPv4 and IPv6, ARP overrides this.'
    base_ctl = None
    
    ' Share our sockets between all tables. '
    _socks = {}

    def __init__(self, table):
        ''' We try to maintain references to a minimal set of sockets only,
        meaning if a socket of our family already exists that's the one we want
        to use. '''
        if self.family not in self._socks.keys():
            self._socks[self.family] = socket(self.family, SOCK_RAW,
                                              IPPROTO_RAW)
            
        Structure.__init__(self, table)
        self.getsockopt(SO_GET_INFO, self)

        entries = Entries(self.name, self.size)
        self.getsockopt(SO_GET_ENTRIES, entries, sizeof(entries) + self.size)

        addr = addressof(entries.entrytable)

        for entry in xt_generator(Entry, 'next_offset', addr, entries.size):
            print repr(entry)
            
            for match in xt_generator(Match, 'match_size', addr,
                                      entry.target_offset, sizeof(entry)):
                print repr(match)
        
    def getsockopt(self, opt, value, buflen=None):
        if buflen is None:
            buflen = sizeof(value)

        size = c_int(buflen)

        if getattr(value, '_fields_', False) and sizeof(value) < buflen:
            resize(value, buflen)

        libc_handle.getsockopt(self._socks[self.family].fileno(), IPPROTO_IP,
                self.base_ctl + opt, byref(value), byref(size))

        return size

    def setsockopt(self, opt, value):
        return self._socks[self.family].setsockopt(IPPROTO_IP, self.base_ctl + opt,
                                               value)

if __name__ == '__main__':
    import IPv4
    
    IPv4.Table('filter')