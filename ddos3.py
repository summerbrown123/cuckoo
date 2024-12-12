from scapy.all import *
import mysql.connector
from scapy.layers.http import HTTP
import datetime


'''
id: 整数类型，作为主键，并自动递增。
source_ip: 字符串类型，用于记录攻击来源IP地址。
destination_ip: 字符串类型，用于记录攻击目标IP地址。
source_port: 整数类型，用于记录攻击来源端口。
destination_port: 整数类型，用于记录攻击目标端口。
protocol: 字符串类型，用于记录攻击使用的协议。
type: 字符串类型，用于记录攻击类型。
payload: 文本类型，用于记录攻击载荷信息。
grade: 字符串类型，用于记录攻击评级信息。
addtime: 时间戳类型，记录日志的时间戳，默认为当前时间。
'''

threshold_low = 10
threshold_middle = 30
threshold_high = 60
def check_isattck(attack_dic):
    payload = str(attack_dic)
    print("payload is ",payload)
    sqlpayloadchecklst = ["select", "delete", "insert", " and ", " or "]
    xsspayloadchecklst = ["script", "document", "innerHTML", ]
    for payloadstr in sqlpayloadchecklst:
        if payloadstr in payload:
            return "是"
    for payloadstr in xsspayloadchecklst:
        if payloadstr in payload:
            return "是"
    return '否'


def check_attck_type(attack_dic):
    payload = str(attack_dic)
    sqlpayloadchecklst = ["select", "delete", "insert", " and ", " or "]
    xsspayloadchecklst = ["script", "document", "innerHTML",]
    for payloadstr in sqlpayloadchecklst:
        if payloadstr in payload:
            return "SQL注入"
    for payloadstr in xsspayloadchecklst:
        if payloadstr in payload:
            return "XSS Flood"
    return '否'

def check_grade(num):
    grade = ""
    if num < threshold_middle:
        grade = "Low"
    elif num < threshold_high:
        grade = "Middle"
    else:
        grade = "High"
    return grade
conn = mysql.connector.connect(
        host="127.0.0.1",
        user="root",
        password="root",
        database="djangop4det1"
    )

    # 将攻击日志数据存入数据库

cursor = conn.cursor()
cursor.execute("select * from white_list")
print(cursor.fetchall())
cursor.close()
conn.close()
def add_attack(log):
    conn = mysql.connector.connect(
        host="192.168.159.130",
        user="root",
        password="root",
        database="djangop4det1"
    )

    # 将攻击日志数据存入数据库

    cursor = conn.cursor()
    # cursor.execute("select * from white_list")
    # whitelist = []
    # for wl in list(cursor.fetchall()):
    #     whitelist.append(wl[0])
    # if log["source_ip"] in whitelist:
    #     return
    query = "INSERT INTO attack (source_ip, destination_ip, source_port, destination_port, protocol, type, payload, grade, addtime,isattack) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s,%s)"
    values = (log["source_ip"], log["destination_ip"], log["source_port"], log["destination_port"],
              log["protocol"], log["type"], log["payload"], log["grade"], log["addtime"], log["isattack"])
    cursor.execute(query, values)
    conn.commit()
    cursor.close()
    conn.close()
def detect_syn_flood(attack_counter, src_ip, threshold, packet):
    """
    检测SYN Flood（SYN洪泛）攻击
    Args:
        attack_counter (dict): 攻击计数器字典，记录不同类型攻击的计数
        src_ip (str): 攻击流量的源IP地址
        threshold (int): 阈值，表示允许的最大攻击次数
        packet (scapy.layers.inet.TCP): 攻击的TCP包
    Returns:
        bool: True表示攻击次数超过阈值，False表示攻击次数未超过阈值
    """
    if src_ip in attack_counter and attack_counter[src_ip] > threshold:
        # 获取TCP包的相关信息
        destination_ip = "192.168.2.200"
        # destination_ip = packet.dst
        destination_port = packet.dport #被攻击的端口
        protocol = "TCP"
        type = "SYN Flood"
        payload = packet.payload
        grade = check_grade(attack_counter[src_ip])
        isattack = check_isattck(attack_counter)
        addtime = datetime.datetime.now() #获取当前时间

        # 构建攻击日志数据
        log = {
            "source_ip": src_ip,
            "destination_ip": destination_ip,
            "source_port": packet.sport,
            "destination_port": destination_port,
            "protocol": protocol,
            "type": type,
            "payload": payload,
            "grade": grade,
            "addtime": addtime,
            "isattack":isattack
        }
        print(log)
        add_attack(log)

        return True
    else:
        return False


def detect_udp_flood(attack_counter, src_ip, threshold, packet):
    """
    检测UDP Flood（UDP洪泛）攻击
    Args:
        attack_counter (dict): 攻击计数器字典，记录不同类型攻击的计数
        src_ip (str): 攻击流量的源IP地址
        threshold (int): 阈值，表示允许的最大攻击次数
        packet (scapy.layers.inet.UDP): 攻击的UDP包
    Returns:
        bool: True表示攻击次数超过阈值，False表示攻击次数未超过阈值
    """
    if src_ip in attack_counter and attack_counter[src_ip] > threshold:
        # 获取UDP包的相关信息
        destination_ip = packet[IP].dst
        destination_port = packet.dport
        protocol = "UDP"
        type = "UDP Flood"
        payload = packet.payload
        grade = check_grade(attack_counter[src_ip])
        isattack = check_isattck(attack_counter)
        addtime = datetime.datetime.now()

        print(destination_ip, destination_port, protocol, type)

        # 构建攻击日志数据
        log = {
            "source_ip": src_ip,
            "destination_ip": destination_ip,
            "source_port": packet.sport,
            "destination_port": destination_port,
            "protocol": protocol,
            "type": type,
            "payload": payload,
            "grade": grade,
            "addtime": addtime,
            "isattack":isattack
        }
        add_attack(log)

        return True
    else:
        return False


def detect_http_flood(attack_counter, src_ip, threshold, packet):
    """
    检测HTTP Flood（HTTP洪泛）攻击
    Args:
        attack_counter (dict): 攻击计数器字典，记录不同类型攻击的计数
        src_ip (str): 攻击流量的源IP地址
        threshold (int): 阈值，表示允许的最大攻击次数
        packet (scapy.packet): 攻击的HTTP请求的scapy packet对象
    Returns:
        bool: True表示攻击次数超过阈值，False表示攻击次数未超过阈值
    """
    if src_ip in attack_counter and attack_counter[src_ip] > threshold:
        # 解析HTTP请求，获取相关信息
        destination_ip = "192.168.2.200"
        destination_ip = packet[IP].dst
        destination_port = 80
        protocol = "HTTP"
        type = "HTTP Flood"
        payload = str(packet.payload)   #转化为字符类型
        grade = check_grade(attack_counter[src_ip])
        isattack = check_isattck(attack_counter)
        addtime = datetime.datetime.now()

        if isattack!='否':
            type = check_attck_type(attack_counter)

        # 构建攻击日志数据
        log = {
            "source_ip": src_ip,
            "destination_ip": destination_ip,
            "source_port": 0,
            "destination_port": destination_port,
            "protocol": protocol,
            "type": type,
            "payload": payload,
            "grade": grade,
            "addtime": addtime,
            "isattack":isattack
        }

        add_attack(log)

        return True
    else:
        return False


def detect_icmp_flood(attack_counter, src_ip, threshold, packet):
    """
    检测ICMP Flood（ICMP洪泛）攻击
    Args:
        attack_counter (dict): 攻击计数器字典，记录不同类型攻击的计数
        src_ip (str): 攻击流量的源IP地址
        threshold (int): 阈值，表示允许的最大攻击次数
        packet (scapy.packet.Packet): 攻击的Scapy协议包
    Returns:
        bool: True表示攻击次数超过阈值，False表示攻击次数未超过阈值
    """
    
    if src_ip in attack_counter and attack_counter[src_ip] > threshold:
        # 解析ICMP协议包，获取相关信息
        destination_ip = packet[IP].dst #packet[IP]表示数据包中的IP层，dst属性表示目标IP地址。
        type = "ICMP Flood"
        payload = str(packet)
        grade = check_grade(attack_counter[src_ip])
        isattack = check_isattck(attack_counter)
        addtime = datetime.datetime.now()

        print(destination_ip, type)

        # 构建攻击日志数据
        log = {
            "source_ip": src_ip,
            "destination_ip": destination_ip,
            "source_port": 0,
            "destination_port": 0,
            "protocol": "ICMP",
            "type": type,
            "payload": payload,
            "grade": grade,
            "addtime": addtime,
            "isattack":isattack
        }
        
        add_attack(log)

        return True
    else:
        return False


def detect_dns_flood(attack_counter, src_ip, threshold, packet):
    """
    检测DNS Flood（DNS洪泛）攻击
    Args:
        attack_counter (dict): 攻击计数器字典，记录不同类型攻击的计数
        src_ip (str): 攻击流量的源IP地址
        threshold (int): 阈值，表示允许的最大攻击次数
        packet (scapy.packet.Packet): 攻击的Scapy协议包
    Returns:
        bool: True表示攻击次数超过阈值，False表示攻击次数未超过阈值
    """
    if src_ip in attack_counter and attack_counter[src_ip] > threshold:
        # 解析DNS协议包，获取相关信息
        destination_ip = packet[IP].dst
        try:    # 尝试获取UDP数据包的源端口号
            source_port = packet[UDP].sport
        except Exception as f:
            source_port = "null"
        destination_port = packet[UDP].dport
        protocol = "UDP"
        type = "DNS Flood"
        payload = str(packet)
        grade = check_grade(attack_counter[src_ip])
        isattack = check_isattck(attack_counter)

        addtime = datetime.datetime.now()
        print(destination_ip, destination_port, protocol, type)

        # 构建攻击日志数据
        log = {
            "source_ip": src_ip,
            "destination_ip": destination_ip,
            "source_port": source_port,
            "destination_port": destination_port,
            "protocol": protocol,
            "type": type,
            "payload": payload,
            "grade": grade,
            "addtime": addtime,
            "isattack":isattack
        }
        
        add_attack(log)

        return True
    else:
        return False


def detect_ntp_amplification(attack_counter, src_ip, threshold, packet):
    """
    检测NTP（网络时间协议）放大攻击
    Args:
        attack_counter (dict): 攻击计数器字典，记录不同类型攻击的计数
        src_ip (str): 攻击流量的源IP地址
        threshold (int): 阈值，表示允许的最大攻击次数
        packet (scapy.packet.Packet): 攻击的Scapy协议包
    Returns:
        bool: True表示攻击次数超过阈值，False表示攻击次数未超过阈值
    """
    if src_ip in attack_counter and attack_counter[src_ip] > threshold:
        # 解析NTP协议包，获取相关信息
        destination_ip = packet[IP].dst
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport
        protocol = "UDP"
        type = "NTP Amplification"
        payload = str(packet)
        grade = check_grade(attack_counter[src_ip])
        isattack = check_isattck(attack_counter)

        addtime = datetime.datetime.now()
        print(destination_ip, destination_port, protocol, type)

        # 构建攻击日志数据
        log = {
            "source_ip": src_ip,
            "destination_ip": destination_ip,
            "source_port": source_port,
            "destination_port": destination_port,
            "protocol": protocol,
            "type": type,
            "payload": payload,
            "grade": grade,
            "addtime": addtime,
            "isattack":isattack
        }
        
        add_attack(log)

        return True
    else:
        return False


def detect_ssdp_flood(attack_counter, src_ip, threshold, packet):
    """
    检测SSDP（简单服务发现协议）攻击
    Args:
        attack_counter (dict): 攻击计数器字典，记录不同类型攻击的计数
        src_ip (str): 攻击流量的源IP地址
        threshold (int): 阈值，表示允许的最大攻击次数
        packet (scapy.packet.Packet): 攻击的Scapy协议包
    Returns:
        bool: True表示攻击次数超过阈值，False表示攻击次数未超过阈值
    """

    if src_ip in attack_counter and attack_counter[src_ip] > threshold:
        # 解析SSDP协议包，获取相关信息
        destination_ip = packet[IP].dst
        source_port = packet[UDP].sport
        destination_port = packet[UDP].dport
        protocol = "UDP"
        type = "SSDP Flood"
        payload = str(packet)

        grade = check_grade(attack_counter[src_ip])
        isattack = check_isattck(attack_counter)

        addtime = datetime.datetime.now()


        # 构建攻击日志数据
        log = {
            "source_ip": src_ip,
            "destination_ip": destination_ip,
            "source_port": source_port,
            "destination_port": destination_port,
            "protocol": protocol,
            "type": type,
            "payload": payload,
            "grade": grade,
            "addtime": addtime,
            "isattack":isattack
        }
        print("log is",log)
        add_attack(log)

        return True
    else:
        return False


# 初始化攻击计数字典
syn_flood_counter = {}
udp_flood_counter = {}
http_flood_counter = {}
icmp_flood_counter = {}
dns_flood_counter = {}
ntp_amplification_counter = {}
ssdp_attack_counter = {}
integrity_attack_counter = {}
unknown_attack_counter = {}

begintime=0
def analyze_traffic(packet):
    global begintime
    print(packet)
    if begintime==0:
        begintime = time.time()
    packetstr = str({"data":packet})
    #print(packetstr)
    # 解决有的协议没有src_ip
    src_ip = None
    # time.sleep(1)
    # 检测SYN Flood攻击
    # packet[TCP].flags.S//检查TCP头部中的标志位，确保该数据包不是一个SYN（同步）包。
    # not packet[TCP].flags.A //检查TCP头部中的标志位，确保该数据包不是一个ACK（确认）包。
    if packet.haslayer(TCP) and packet[TCP].flags.S and not packet[TCP].flags.A and packet[TCP].dport == 80:
        src_ip = packet[IP].src
        if src_ip not in syn_flood_counter:
            syn_flood_counter[src_ip] = 0   #若该IP不在SYN攻击字典内
        syn_flood_counter[src_ip] += 1
        syn_flood_counter["packet"] = packet

    # 检测UDP Flood攻击
    if packet.haslayer(UDP) and packet[UDP].dport == 53:

        src_ip = packet[IP].src
        if src_ip not in udp_flood_counter:
            udp_flood_counter[src_ip] = 0
        udp_flood_counter[src_ip] += 1
        udp_flood_counter["packet"] = packet

    # 检测HTTP Flood攻击
    print(packet.haslayer(HTTP))
    #print(http_flood_counter)
    if packet.haslayer(HTTP):
        src_ip = packet[IP].src
        if src_ip not in http_flood_counter:
            http_flood_counter[src_ip] = 0
        http_flood_counter[src_ip] += 1
        http_flood_counter["packet"] = packet

    # 检测ICMP Flood攻击
    if packet.haslayer(ICMP) and packet[ICMP].type == 8:
        src_ip = packet[IP].src
        if src_ip not in icmp_flood_counter:
            icmp_flood_counter[src_ip] = 0
        icmp_flood_counter[src_ip] += 1
        ssdp_attack_counter["packet"] = packet

    # 检测DNS Flood攻击
    if packet.haslayer(IP) and packet.haslayer(DNS):
        ip_layer = packet[IP]
        dns_layer = packet[DNS]
        if dns_layer.qr == 0:
            src_ip = ip_layer.src
            if src_ip not in dns_flood_counter:
                dns_flood_counter[src_ip] = 0
            dns_flood_counter[src_ip] += 1
            dns_flood_counter["packet"] = packet

    # 检测NTP Amplification攻击
    if packet.haslayer(NTP) and packet[NTP].mode == 7:
        src_ip = packet[IP].src
        if src_ip not in ntp_amplification_counter:
            ntp_amplification_counter[src_ip] = 0
        ntp_amplification_counter[src_ip] += 1
        ntp_amplification_counter["packet"] = packet

    # 检测SSDP（简单服务发现协议）攻击
    if packet.haslayer(UDP) and packet[UDP].dport == 1900:

        src_ip = packet[IP].src
        if src_ip not in ssdp_attack_counter:
            ssdp_attack_counter[src_ip] = 0
        ssdp_attack_counter[src_ip] += 1
        ssdp_attack_counter["packet"] = packet


    # 检测其他未知类型的攻击
    # else:
    #     src_ip = packet[IP].src
    #     if src_ip not in unknown_attack_counter:
    #         unknown_attack_counter[src_ip] = 0
    #     unknown_attack_counter[src_ip] += 1
    # ddos类型检测函数
    print(time.time()-begintime,time.time(),begintime)
    if time.time()-begintime>1:
        # print(time.ctime(), time.time() - begintime,ssdp_attack_counter,packet)
        begintime=time.time()
        try:
            if detect_syn_flood(syn_flood_counter, syn_flood_counter["packet"][IP].src, 10, syn_flood_counter["packet"]):
                syn_flood_counter.clear()
        except:
            pass
        try:
            if detect_udp_flood(udp_flood_counter, udp_flood_counter["packet"][IP].src, 10, udp_flood_counter["packet"]):
                udp_flood_counter.clear()
        except:
            pass
        try:
            if detect_http_flood(http_flood_counter, http_flood_counter["packet"][IP].src, 2, http_flood_counter["packet"]):
                http_flood_counter.clear()
        except:
            pass
        try:
            if detect_icmp_flood(icmp_flood_counter, icmp_flood_counter["packet"][IP].src, 10, icmp_flood_counter["packet"]):
                icmp_flood_counter.clear()
        except:
            pass
        try:
            if detect_dns_flood(dns_flood_counter, dns_flood_counter["packet"][IP].src, 10, dns_flood_counter["packet"]):
                dns_flood_counter.clear()
        except:
            pass
        try:
            if detect_ntp_amplification(ntp_amplification_counter, ntp_amplification_counter["packet"][IP].src, 10, ntp_amplification_counter["packet"]):
                ntp_amplification_counter.clear()
        except:
            pass
        try:
            if detect_ssdp_flood(ssdp_attack_counter, ssdp_attack_counter["packet"][IP].src, 10, ssdp_attack_counter["packet"]):
                ssdp_attack_counter.clear()
        except:
            pass


def main():
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    print(ifaces)
    iface = ifaces[0]
    print(iface)
    sys.stdout.flush()
    # 使用sniff函数进行数据包嗅探
    # sniff()函数是一个常见的网络数据包捕获函数，用于从网络中捕获数据包

    for iface in ifaces:
        sniff(iface=iface, prn=lambda x: analyze_traffic(x))

if __name__ == '__main__':
    show_interfaces()  # 显示网卡
    while(1):
        # main()
        try:
            main()
        except Exception as e:
            print("error is ",e)

