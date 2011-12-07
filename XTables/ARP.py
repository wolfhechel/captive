'''
Created on Dec 7, 2011

@author: root_op
'''
from XTables import BaseTable, AF_INET

class Table(BaseTable):
    family = AF_INET
    base_ctl = 96