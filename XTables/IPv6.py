'''
Created on Dec 7, 2011

@author: root_op
'''
from XTables import BaseTable
from socket import AF_INET6

class IPv6(BaseTable):
    family = AF_INET6
    base_ctl = 64