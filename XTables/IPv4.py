'''
Created on Dec 7, 2011

@author: root_op
'''
from socket import AF_INET
from XTables import BaseTable

class Table(BaseTable):
    family = AF_INET
    base_ctl = 64