#coding:utf8

import nmap
import sys
import time
import threading
from xml.dom import minidom

if __name__ == '__main__':
    
    nm = nmap.PortScanner()
    nm.scan('192.168.1.154',arguments='-sS -O -F -sU')
    
    print nm['192.168.1.154']
    print nm['192.168.1.154']['osmatch']