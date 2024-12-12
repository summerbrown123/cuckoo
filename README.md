基于P4的网络安全防护和攻击检测
==
项目简介
-
本项目利用P4语言和Mininet仿真平台，构建了一个支持多种网络攻击检测的实验环境。项目涵盖了DDoS攻击检测、SQL注入攻击、XSS攻击以及UDP、ICMP等常见攻击方式的模拟与防护。通过使用可编程交换机和P4Runtime接口，实现了对网络流量的精细控制与管理。

项目文件
-
#1. P4 配置文件

  demo.p4 / demo.p4i / demo.p4bak / demo1.p4：

包含P4程序的实现，用于定义数据包的解析、匹配与动作。

示例功能包括流量分类、计数器管理、QoS支持等。


#2. Mininet 拓扑与运行脚本

run_exercise.py / demo.py / test.py：

通过Mininet生成拓扑结构。

配置交换机、主机，并绑定控制器，支持P4Runtime接口。

支持单交换机与多交换机拓扑。

p4runtime_switch.py：

定义P4Runtime交换机类，支持gRPC协议。

实现了交换机的启动与配置。

p4_mininet.py：

提供P4交换机与主机的Mininet接口支持。

runtime_CLI.py：

提供了P4Runtime的CLI接口，用于动态管理P4程序的表项。


#3. 攻击模拟脚本

常见攻击模拟

icmp.py：ICMP Flood攻击。

udp.py：UDP Flood攻击。

syn2.py：TCP SYN Flood攻击。

dns.py：DNS Flood攻击。

httpddos.py：HTTP Flood攻击。

ssdp.py：SSDP Flood攻击。

Web攻击模拟

SQL注入.py：模拟SQL注入攻击。

xss攻击.py：模拟XSS攻击。


#4. 流量分析与检测脚本

ddos3.py：

基于Scapy库对网络流量进行分析。

检测SYN Flood、UDP Flood、HTTP Flood等攻击。

提供攻击日志记录到MySQL数据库的功能。

send.py / receive.py：

数据包的发送与接收工具，用于模拟和捕获流量。


#5. 辅助工具

netstat.py：

检查网络端口状态，用于确保程序运行的端口未被占用。

环境要求
--
Python 3.6+

Mininet

P4编译器与BMv2模拟器

Scapy库

MySQL数据库


安装依赖
--

pip install scapy mysql-connector-python

运行Mininet拓扑
--

sudo python3 run_exercise.py \
  --behavioral-exe <path_to_behavioral_model> \
  --json <path_to_p4_json>

运行攻击脚本
--
启动Mininet后，在攻击主机上运行攻击脚本，例如：

` ``
python3 udp.py
` ``

查看日志

检查MySQL数据库中的攻击记录。

# cuckoo
cuckoo hash
