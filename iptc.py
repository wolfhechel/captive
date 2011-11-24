import socket, struct
from ctypes import *

''' References:
http://git.netfilter.org/cgi-bin/gitweb.cgi?p=iptables.git;a=blob;f=libiptc/libiptc.c
http://www.faqs.org/docs/Linux-HOWTO/Querying-libiptc-HOWTO.html
http://www.deadloop.com/2010/11/getting-exotic-socket-options-in-python.html

linux/netfilter_ipv4/ip_tables.h
linux/netfilter/x_tables.h '''

class ipt_getinfo(Structure):
    _fields_ = [("name", c_char * 32),
                ("valid_hooks", c_uint),
                ("hook_entry", c_uint * 5),
                ("underflow", c_uint * 5),
                ("num_entries", c_uint),
                ("size", c_uint)]
    
ipt_getinfo_len = c_int32(84)

ipt = ipt_getinfo("filter")

sock = socket.socket(socket.AF_INET, 
                     socket.SOCK_RAW,
                     socket.IPPROTO_RAW)

print cdll.LoadLibrary('libc.so.6').getsockopt(c_int(sock.fileno()),
                                               socket.IPPROTO_IP,
                                               64,
                                               pointer(ipt),
                                               pointer(ipt_getinfo_len))

print ipt.num_entries