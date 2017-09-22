#coding: utf8

'''
Created on 2016年6月8日

@author: silenove
'''

#扫描整个网段，找到活跃IP；对每个活跃的IP地址，扫描活跃端口；探测操作系统信息；探测端口监听程序及版本；其他功能。

import nmap
import sys
import time
import threading
from xml.dom import minidom

class Scanner(object):
    
    def __init__(self,ipscan):
        
        #nmap模块对象
        self.nm = nmap.PortScanner();
        
        #iplist存储要扫描的IP地址
        self.iplist = []
        
        #创建线程互斥锁
        self.mutex = threading.Lock()
        
        #扫描的IP地址段
        self.ipscan = ipscan
        
        #时间格式
        self.ISOTIMEFORMAT = '%Y-%m-%d %X'
        
        #开始时间
        self.startTime = 0
        
        #结束时间
        self.endTime = 0
        
        #创建一个document对象，代表内存中的DOM树
        self.doc = minidom.Document()
        rootNode = self.doc.createElement('NmapScanner_Result xml')
        self.doc.appendChild(rootNode)
        self.scanResult = self.doc.createElement('scanResult')
        rootNode.appendChild(self.scanResult)
        
        
        
        
        
    def startScan(self):
        
        self.startTime = time.time()
        
        #快速浏览网段，获取网段信息
        self.nm.scan(self.ipscan,arguments='-sP ')
        
        #找出活跃IP
        self.scanActiveIP()
        
        for ip in self.iplist:
            print self.nm[ip]
            print '\n'
            
        #创建多线程获取
        self.createThread()
        
        self.endTime = time.time()
        
        usingtime = int(self.endTime - self.startTime);
        
        self.scanResult.setAttribute('beginTime', time.strftime(self.ISOTIMEFORMAT,time.localtime(self.startTime)))  
        self.scanResult.setAttribute('endTime', time.strftime(self.ISOTIMEFORMAT,time.localtime(self.endTime)))   
        self.scanResult.setAttribute('usingTime', str(usingtime)+'s')
        
        fhandle = open('result.xml','w')
        fhandle.write(self.doc.toprettyxml(indent='\t', newl='\n', encoding='utf-8'))
        fhandle.close()
    
    
    #扫描活跃IP        
    def scanActiveIP(self):
        for ip in self.nm.all_hosts():
            self.iplist.append(ip)  
        self.iplist.sort()    
        
    #将扫描获取的IP信息填入xml
    def add_xml(self,result,tcp_ports,udp_ports):
        
        ip = self.doc.createElement('ip')
        ip.setAttribute('address',result['address'])
        ip.setAttribute('state',result['state'])
        
        osclass = self.doc.createElement('OperateSystem')
        osclass.appendChild(self.doc.createTextNode(result['osclass']))
        ip.appendChild(osclass)
        
        oscpe = self.doc.createElement('osCPE')
        oscpe.appendChild(self.doc.createTextNode(result['oscpe']))
        ip.appendChild(oscpe)
        
        ports =  self.doc.createElement('port')
        
        tcp = self.doc.createElement('tcp')
        
        for port in tcp_ports:
            portNode = self.doc.createElement(str(port))
            portNode.setAttribute('state', result[str(port)+'state'])
            portNode.setAttribute('name', result[str(port)+'name'])
            portNode.setAttribute('version', result[str(port)+'version'])
            tcp.appendChild(portNode)
            
        ports.appendChild(tcp)
        
        udp = self.doc.createElement('udp')
        
        for port in udp_ports:
            portNode = self.doc.createElement(str(port))
            portNode.setAttribute('state', result[str(port)+'state'])
            portNode.setAttribute('name', result[str(port)+'name'])
            portNode.setAttribute('version', result[str(port)+'version'])
            udp.appendChild(portNode)
            
        ports.appendChild(udp)
        
        ip.appendChild(ports)
        self.scanResult.appendChild(ip)
        
        
       
    #创建多线程扫描IP
    def createThread(self):
        threads = []
        amount_thread = 0
        
        if len(self.iplist) >= 20:
            amount_thread = 20
        else:
            amount_thread = len(self.iplist)
        
        for n in range(20):
            threads.append(threading.Thread(target=self.looper()))
            
        for thread in threads:
            thread.start()
            
        for thread in threads:
            thread.join()
                
               
        
    def looper(self):
        while 1:
            
            #线程互斥的操作活跃IP列表
            self.mutex.acquire()
            
            if len(self.iplist) <= 0:
                self.mutex.release()
                break
            ip = self.iplist[0]
            self.iplist.remove(self.iplist[0])
            
            #释放锁
            self.mutex.release()
            
            self.scanIP(ip)
   
            
    #对IP地址列表中的IP地址进行扫描        
    def scanIP(self,ip):
        self.nm.scan(ip,arguments='-sS -sU -O -osscan-guess -F ')
        print self.nm[ip]
        
        #result = {'address':ip,'osclass':str(self.nm[ip]['osmatch']['osclass'])[1:-1],'state':str(self.nm[ip]['status']['state'])}
        
        #保存扫描结果信息
        result = {}
        result['address'] = ip
        
        if len(self.nm[ip]['osmatch'])> 0:
            result['oscpe'] = str(self.nm[ip]['osmatch'][0]['osclass'][0]['cpe'])[1:-1]
            result['osclass'] = str(self.nm[ip]['osmatch'][0]['osclass'][0]['osfamily'])
        else:
            result['osclass'] = 'No exact OS matchs for host'
            result['oscpe'] = 'No exact OS CPE matchs for host'
            
        if len(result['osclass']) == 0:
            result['osclass'] = 'No exact OS matchs for host'
            
        result['state'] = str(self.nm[ip]['status']['state'])

        
        tcp_ports = self.nm[ip].all_tcp()
        
        for port in tcp_ports:
            result[str(port)+'state'] = str(self.nm[ip]['tcp'][port]['state'])
            result[str(port)+'version'] = str(self.nm[ip]['tcp'][port]['version'])
            result[str(port)+'name'] = str(self.nm[ip]['tcp'][port]['name'])
            
        udp_ports = self.nm[ip].all_udp()
        
        for port in udp_ports:
            result[str(port)+'state'] = str(self.nm[ip]['udp'][port]['state'])
            result[str(port)+'version'] = str(self.nm[ip]['udp'][port]['version'])
            result[str(port)+'name'] = str(self.nm[ip]['udp'][port]['name'])
            
            
        self.add_xml(result, tcp_ports, udp_ports)
        
        
        
        
                
                     

if __name__ == '__main__':
    
    s = Scanner('192.168.1.154')
    s.startScan()
            
        
        
        