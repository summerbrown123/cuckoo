/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4  = 0x800;
const bit<16> TYPE_PROBE = 0x812;

#define MAX_HOPS 10
#define MAX_SIZE 1024
#define BUCKET_SIZE 8

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

typedef bit<48> time_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header probe_t {
    bit<8> hop_cnt;
}

header probe_data_t {
    bit<1>    bos;
    bit<7>    swid;
    bit<8>    port;
    bit<32>   byte_cnt;
    time_t    last_time;
    time_t    cur_time;
}

header probe_fwd_t {
    bit<8> egress_spec;
}

struct parser_metadata_t {
    bit<8> remaining;
}

struct cuckoo_metadata {
    bit<32> hash_table[MAX_SIZE][BUCKET_SIZE]; // 哈希桶数组
    bit<1> occupied[MAX_SIZE]; // 占用状态
    bit<32> current_size; // 当前哈希表大小
}

struct metadata {
    bit<8> egress_spec;
    parser_metadata_t parser_metadata;
    cuckoo_metadata cuckoo_md; // 使用我们的新结构
    bit<32> flow_counter;
}

struct headers {
    ethernet_t              ethernet;
    ipv4_t                  ipv4;
    probe_t                 probe;
    probe_data_t[MAX_HOPS]  probe_data;
    probe_fwd_t[MAX_HOPS]   probe_fwd;
}
//布谷鸟哈希表
bit<32> cuckoo_hash(bit<32> key, bit<32> index) {
    return (key ^ (index + 1)) % MAX_SIZE; // 使用异或生成两个哈希位置
}

action add_entry(bit<32> key) {
    // 将新条目添加到哈希表中的第一个空位
    for (int i = 0; i < BUCKET_SIZE; i++) {
        if (meta.cuckoo_md.hash_table[index][i] == 0) { // 找到空桶
            meta.cuckoo_md.hash_table[index][i] = key;
            return;
        }
    }
}

bit<32> cuckoo_hash(bit<32> key, bit<32> index) {
    return (key ^ (index + 1)) % MAX_SIZE; // 使用异或生成索引
}

//动态调整哈希表
void resize_table(cuckoo_metadata md) {
    // 根据当前元素数量计算新的哈希表大小
    int new_size = md.current_size * 2; // 示例：将大小翻倍
    bit<32> new_hash_table[new_size][BUCKET_SIZE];
    bit<1> new_occupied[new_size];

    // 将新哈希表初始化为0
    for (int i = 0; i < new_size; i++) {
        for (int j = 0; j < BUCKET_SIZE; j++) {
            new_hash_table[i][j] = 0;
        }
        new_occupied[i] = 0;
    }

    // 移动现有的条目到新哈希表
    for (int i = 0; i < md.current_size; i++) {
        for (int j = 0; j < BUCKET_SIZE; j++) {
            bit<32> key = md.hash_table[i][j];
            if (key != 0) {
                bit<32> index = cuckoo_hash(key, 0);
                add_entry(key, new_hash_table, new_occupied); // 添加到新表
            }
        }
    }

    // 更新元数据
    md.hash_table = new_hash_table;
    md.occupied = new_occupied;
    md.current_size = new_size;
}

void handle_collision(bit<32> index, bit<32> key) {
    for (int attempts = 0; attempts < 10; attempts++) { // 最多重试10次
        bit<32> current_key = meta.cuckoo_md.hash_table[index][0]; // 获取现有键
        meta.cuckoo_md.hash_table[index][0] = key; // 将新键放入
        // 尝试将现有键放入下一个哈希位置
        bit<32> new_index = cuckoo_hash(current_key, attempts);
        if (meta.cuckoo_md.occupied[new_index] == 0) {
            add_entry(current_key); // 如果找到一个空位，添加现有键
            meta.cuckoo_md.occupied[new_index] = 1;
            return;
        } else {
            key = current_key; // 拿回被踢出的键作为新的插入键
            index = new_index; // 更新索引
        }
    }
    // 超过最大尝试次数，返回错误或其它处理逻辑
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_PROBE: parse_probe;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

    state parse_probe {
        packet.extract(hdr.probe);
        meta.parser_metadata.remaining = hdr.probe.hop_cnt + 1;
        transition select(hdr.probe.hop_cnt) {
            0: parse_probe_fwd;
            default: parse_probe_data;
        }
    }

    state parse_probe_data {
        packet.extract(hdr.probe_data[next]);
        transition select(hdr.probe_data[last].bos) {
            1: parse_probe_fwd;
            default: parse_probe_data;
        }
    }

    state parse_probe_fwd {
        packet.extract(hdr.probe_fwd[next]);
        meta.parser_metadata.remaining = meta.parser_metadata.remaining - 1;
        meta.egress_spec = hdr.probe_fwd[last].egress_spec;
        transition select(meta.parser_metadata.remaining) {
            0: accept;
            default: parse_probe_fwd;
        }
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
//布谷鸟哈希的压缩过滤器
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    action increment_flow_counter(bit<32> key) {
        // 增加当前流的计数
        meta.flow_counter = meta.flow_counter + 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            increment_flow_counter;
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
            
            // 实施缓存攻击逻辑
            bit<32> key = hdr.ipv4.dstAddr;
            bit<32> index = cuckoo_hash(key, 0);
            if (meta.cuckoo_md.occupied[index] == 0) {
                add_entry(key);
                meta.cuckoo_md.occupied[index] = 1; // 标记为占用
            } else {
                handle_collision(index, key);
            }
        } else if (hdr.probe.isValid()) {
            standard_metadata.egress_spec = (bit<9>)meta.egress_spec;
            hdr.probe.hop_cnt += 1;
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   ********************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    register<bit<32>>(MAX_PORTS) byte_cnt_reg;

    action set_swid(bit<7> swid) {
        hdr.probe_data[0].swid = swid;
    }

    table swid {
        actions = {
            set_swid;
            NoAction;
        }
        default_action = NoAction();
    }

    apply {
        if (hdr.probe.isValid()) {
            hdr.probe_data.push_front(1);
            hdr.probe_data[0].setValid();
            swid.apply();
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   ***************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.probe);
        packet.emit(hdr.probe_data);
        packet.emit(hdr.probe_fwd);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;