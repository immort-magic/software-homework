/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "include/headers.p4"
#include "include/parsers.p4"

/* CONSTANTS */
#define NUM_PORTS 2
#define NUM_BATCHES 2

#define REGISTER_SIZE_TOTAL 2048 
#define REGISTER_BATCH_SIZE REGISTER_SIZE_TOTAL/NUM_BATCHES //1024
#define REGISTER_PORT_SIZE REGISTER_BATCH_SIZE/NUM_PORTS //512

#define REGISTER_CELL_WIDTH 64

#define LOSS_CHANGE_OF_BATCH 0x1234

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register<bit<16>>(1) last_batch_id;

    //# TODO 5 define the 8 registers. 4 for the um and 4 for the dm
    register<bit<REGISTER_CELL_WIDTH>>(REGISTER_SIZE_TOTAL) um_ip_src;
    register<bit<REGISTER_CELL_WIDTH>>(REGISTER_SIZE_TOTAL) um_ip_dst;
    register<bit<REGISTER_CELL_WIDTH>>(REGISTER_SIZE_TOTAL) um_ports_proto_id;
    register<bit<REGISTER_CELL_WIDTH>>(REGISTER_SIZE_TOTAL) um_counter;

    register<bit<REGISTER_CELL_WIDTH>>(REGISTER_SIZE_TOTAL) dm_ip_src;
    register<bit<REGISTER_CELL_WIDTH>>(REGISTER_SIZE_TOTAL) dm_ip_dst;
    register<bit<REGISTER_CELL_WIDTH>>(REGISTER_SIZE_TOTAL) dm_ports_proto_id;
    register<bit<REGISTER_CELL_WIDTH>>(REGISTER_SIZE_TOTAL) dm_counter;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action compute_hash_indexes(){
       // TODO 6 define the 6 custom32 hash functions
    //    计算上游meter的hash indexes
        hash(meta.um_h1, 
            HashAlgorithm.crc32_custom, 
            ((meta.batch_id * REGISTER_BATCH_SIZE) + ((((bit<16>)standard_metadata.egress_spec-1) * REGISTER_PORT_SIZE))), 
            {hdr.ipv4.srcAddr, 
            hdr.ipv4.dstAddr, 
            meta.tmp_src_port, 
            meta.tmp_dst_port, 
            hdr.loss.nextProtocol, 
            hdr.ipv4.identification}, 
            (bit<16>)REGISTER_PORT_SIZE);

        
        hash(meta.um_h2, 
            HashAlgorithm.crc32_custom, 
            ((meta.batch_id * REGISTER_BATCH_SIZE) + ((((bit<16>)standard_metadata.egress_spec-1) * REGISTER_PORT_SIZE))), 
            {hdr.ipv4.srcAddr, 
            hdr.ipv4.dstAddr, 
            meta.tmp_src_port, 
            meta.tmp_dst_port, 
            hdr.loss.nextProtocol, 
            hdr.ipv4.identification}, 
            (bit<16>)REGISTER_PORT_SIZE);

        hash(meta.um_h3, 
            HashAlgorithm.crc32_custom, 
            ((meta.batch_id * REGISTER_BATCH_SIZE) + ((((bit<16>)standard_metadata.egress_spec-1) * REGISTER_PORT_SIZE))), 
            {hdr.ipv4.srcAddr, 
            hdr.ipv4.dstAddr, 
            meta.tmp_src_port, 
            meta.tmp_dst_port, 
            hdr.loss.nextProtocol, 
            hdr.ipv4.identification}, 
            (bit<16>)REGISTER_PORT_SIZE);

        // 计算下游meter 的 hash indexes
        hash(meta.dm_h1, 
            HashAlgorithm.crc32_custom, 
            ((meta.previous_batch_id * REGISTER_BATCH_SIZE) + ((((bit<16>)standard_metadata.ingress_port-1) * REGISTER_PORT_SIZE))), 
            {hdr.ipv4.srcAddr, 
            hdr.ipv4.dstAddr, 
            meta.tmp_src_port, 
            meta.tmp_dst_port, 
            hdr.loss.nextProtocol, 
            hdr.ipv4.identification}, 
            (bit<16>)REGISTER_PORT_SIZE);

        hash(meta.dm_h2, 
            HashAlgorithm.crc32_custom, 
            ((meta.previous_batch_id * REGISTER_BATCH_SIZE) + ((((bit<16>)standard_metadata.ingress_port-1) * REGISTER_PORT_SIZE))), 
            {hdr.ipv4.srcAddr, 
            hdr.ipv4.dstAddr, 
            meta.tmp_src_port, 
            meta.tmp_dst_port, 
            hdr.loss.nextProtocol, 
            hdr.ipv4.identification}, 
            (bit<16>)REGISTER_PORT_SIZE);

        hash(meta.dm_h3, 
            HashAlgorithm.crc32_custom, 
            ((meta.previous_batch_id * REGISTER_BATCH_SIZE) + ((((bit<16>)standard_metadata.ingress_port-1) * REGISTER_PORT_SIZE))), 
            {hdr.ipv4.srcAddr, 
            hdr.ipv4.dstAddr, 
            meta.tmp_src_port, 
            meta.tmp_dst_port, 
            hdr.loss.nextProtocol, 
            hdr.ipv4.identification}, 
            (bit<16>)REGISTER_PORT_SIZE);
    }

    action apply_um_meter(){

        // TODO 7 implement the insertion of a packet into the um meter
        //ip src
        bit<64> tmp = (bit<64>)hdr.ipv4.srcAddr;
        um_ip_src.read(meta.tmp_ip_src, (bit<32>)meta.um_h1);
        meta.tmp_ip_src = meta.tmp_ip_src ^ (tmp);
        um_ip_src.write((bit<32>)meta.um_h1, meta.tmp_ip_src);

        um_ip_src.read(meta.tmp_ip_src, (bit<32>)meta.um_h2);
        meta.tmp_ip_src = meta.tmp_ip_src ^ (tmp);
        um_ip_src.write((bit<32>)meta.um_h2, meta.tmp_ip_src);

        um_ip_src.read(meta.tmp_ip_src, (bit<32>)meta.um_h3);
        meta.tmp_ip_src = meta.tmp_ip_src ^ (tmp);
        um_ip_src.write((bit<32>)meta.um_h3, meta.tmp_ip_src);

        // ip dst
        tmp = (bit<64>)hdr.ipv4.dstAddr;
        um_ip_dst.read(meta.tmp_ip_dst, (bit<32>)meta.um_h1);
        meta.tmp_ip_dst = meta.tmp_ip_dst ^ (tmp);
        um_ip_dst.write((bit<32>)meta.um_h1, meta.tmp_ip_dst);

        um_ip_dst.read(meta.tmp_ip_dst, (bit<32>)meta.um_h2);
        meta.tmp_ip_dst = meta.tmp_ip_dst ^ (tmp);
        um_ip_dst.write((bit<32>)meta.um_h2, meta.tmp_ip_dst);

        um_ip_dst.read(meta.tmp_ip_dst, (bit<32>)meta.um_h3);
        meta.tmp_ip_dst = meta.tmp_ip_dst ^ (tmp);
        um_ip_dst.write((bit<32>)meta.um_h3, meta.tmp_ip_dst);

        // misc fields
        // hash1
        tmp = (bit<8>)0 ++ meta.tmp_src_port ++ meta.tmp_dst_port ++ hdr.loss.nextProtocol ++ hdr.ipv4.identification;
        um_ports_proto_id.read(meta.tmp_ports_proto_id, (bit<32>)meta.um_h1);
        meta.tmp_ports_proto_id = meta.tmp_ports_proto_id ^ (tmp);
        um_ports_proto_id.write((bit<32>)meta.um_h1, meta.tmp_ports_proto_id);

        um_ports_proto_id.read(meta.tmp_ports_proto_id, (bit<32>)meta.um_h2);
        meta.tmp_ports_proto_id = meta.tmp_ports_proto_id ^ (tmp);
        um_ports_proto_id.write((bit<32>)meta.um_h2, meta.tmp_ports_proto_id);

        um_ports_proto_id.read(meta.tmp_ports_proto_id, (bit<32>)meta.um_h3);
        meta.tmp_ports_proto_id = meta.tmp_ports_proto_id ^ (tmp);
        um_ports_proto_id.write((bit<32>)meta.um_h3, meta.tmp_ports_proto_id);


        //counter
        //hash1
        um_counter.read(meta.tmp_counter, (bit<32>)meta.um_h1);
        meta.tmp_counter = meta.tmp_counter + 1;
        um_counter.write((bit<32>)meta.um_h1, meta.tmp_counter);

        um_counter.read(meta.tmp_counter, (bit<32>)meta.um_h2);
        meta.tmp_counter = meta.tmp_counter + 1;
        um_counter.write((bit<32>)meta.um_h2, meta.tmp_counter);

        um_counter.read(meta.tmp_counter, (bit<32>)meta.um_h3);
        meta.tmp_counter = meta.tmp_counter + 1;
        um_counter.write((bit<32>)meta.um_h3, meta.tmp_counter);
    }

    action apply_dm_meter(){

        // TODO 8 impelement the insertion of a packet into the dm meter

        bit<64> tmp = (bit<64>)hdr.ipv4.srcAddr;
        dm_ip_src.read(meta.tmp_ip_src, (bit<32>)meta.dm_h1);
        meta.tmp_ip_src = meta.tmp_ip_src ^ (tmp);
        dm_ip_src.write((bit<32>)meta.dm_h1, meta.tmp_ip_src);

        dm_ip_src.read(meta.tmp_ip_src, (bit<32>)meta.dm_h2);
        meta.tmp_ip_src = meta.tmp_ip_src ^ (tmp);
        dm_ip_src.write((bit<32>)meta.dm_h2, meta.tmp_ip_src);

        dm_ip_src.read(meta.tmp_ip_src, (bit<32>)meta.dm_h3);
        meta.tmp_ip_src = meta.tmp_ip_src ^ (tmp);
        dm_ip_src.write((bit<32>)meta.dm_h3, meta.tmp_ip_src);

        // ip dst
        tmp = (bit<64>)hdr.ipv4.dstAddr;
        dm_ip_dst.read(meta.tmp_ip_dst, (bit<32>)meta.dm_h1);
        meta.tmp_ip_dst = meta.tmp_ip_dst ^ (tmp);
        dm_ip_dst.write((bit<32>)meta.dm_h1, meta.tmp_ip_dst);

        dm_ip_dst.read(meta.tmp_ip_dst, (bit<32>)meta.dm_h2);
        meta.tmp_ip_dst = meta.tmp_ip_dst ^ (tmp);
        dm_ip_dst.write((bit<32>)meta.dm_h2, meta.tmp_ip_dst);

        dm_ip_dst.read(meta.tmp_ip_dst, (bit<32>)meta.dm_h3);
        meta.tmp_ip_dst = meta.tmp_ip_dst ^ (tmp);
        dm_ip_dst.write((bit<32>)meta.dm_h3, meta.tmp_ip_dst);

        // misc fields
        // hash1
        tmp = (bit<8>)0 ++ meta.tmp_src_port ++ meta.tmp_dst_port ++ hdr.loss.nextProtocol ++ hdr.ipv4.identification;
        dm_ports_proto_id.read(meta.tmp_ports_proto_id, (bit<32>)meta.dm_h1);
        meta.tmp_ports_proto_id = meta.tmp_ports_proto_id ^ (tmp);
        dm_ports_proto_id.write((bit<32>)meta.dm_h1, meta.tmp_ports_proto_id);

        dm_ports_proto_id.read(meta.tmp_ports_proto_id, (bit<32>)meta.dm_h2);
        meta.tmp_ports_proto_id = meta.tmp_ports_proto_id ^ (tmp);
        dm_ports_proto_id.write((bit<32>)meta.dm_h2, meta.tmp_ports_proto_id);

        dm_ports_proto_id.read(meta.tmp_ports_proto_id, (bit<32>)meta.dm_h3);
        meta.tmp_ports_proto_id = meta.tmp_ports_proto_id ^ (tmp);
        dm_ports_proto_id.write((bit<32>)meta.dm_h3, meta.tmp_ports_proto_id);


        //counter
        //hash1
        dm_counter.read(meta.tmp_counter, (bit<32>)meta.dm_h1);
        meta.tmp_counter = meta.tmp_counter + 1;
        dm_counter.write((bit<32>)meta.dm_h1, meta.tmp_counter);

        dm_counter.read(meta.tmp_counter, (bit<32>)meta.dm_h2);
        meta.tmp_counter = meta.tmp_counter + 1;
        dm_counter.write((bit<32>)meta.dm_h2, meta.tmp_counter);

        dm_counter.read(meta.tmp_counter, (bit<32>)meta.dm_h3);
        meta.tmp_counter = meta.tmp_counter + 1;
        dm_counter.write((bit<32>)meta.dm_h3, meta.tmp_counter);
    }

    action set_egress_port(bit<9> egress_port){
        standard_metadata.egress_spec = egress_port;
    }

    table forwarding {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            set_egress_port;
            drop;
            NoAction;
        }
        size = 64;
        default_action = drop;
    }

    // TODO 4 implement the remove_header action
    action remove_header(){
        bit<8> protocol = hdr.loss.nextProtocol;
        hdr.loss.setInvalid();
        hdr.ipv4.protocol = protocol;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - 2;

        //表示下一个是主机，当前交换机的 um 不需要再执行，dm 需要执行
        meta.dont_execute_um = 1;
    }
    // TODO 3 Define the remove_loss_header table
    table remove_loss_header{
        key = {
            standard_metadata.egress_spec: exact;
        }
        actions = {
            remove_header;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }


    apply {

        // TODO 9: Understand the ingres pipeline
        // 是否满足 ipv4 的转发
        if (hdr.ipv4.isValid())
        {
            // Set the tcp/udp ports to a metadata field so we can hash them without
            // having to duplicate the hash functions
            // 将 tcp 和 udp 的 srcPort 和 dstPort 保存起来
            if (hdr.tcp.isValid())
            {
                meta.tmp_src_port = hdr.tcp.srcPort;
                meta.tmp_dst_port = hdr.tcp.dstPort;
            }
            else if (hdr.udp.isValid())
            {
                meta.tmp_src_port = hdr.udp.srcPort;
                meta.tmp_dst_port = hdr.udp.dstPort;
            }

            // Sets egress port 1->2 2->1
            // 当前主机从哪个端口出去，1->2，还是 2->1
            forwarding.apply();

            // Assumes that the comunication is not host -- switch -- host, otherwise we
            // would have to check that too
            // 第一个交换机，loss是无效的，添加loss头字段
            if (!hdr.loss.isValid())
            {
               hdr.loss.setValid();
               hdr.loss.nextProtocol = hdr.ipv4.protocol;
               hdr.ipv4.totalLen = hdr.ipv4.totalLen + 2;
               hdr.ipv4.protocol = TYPE_LOSS;

                //第一个交换机不需要执行 dm
               meta.dont_execute_dm = 1;
            }
            else{
                // 更新batch_id
               meta.previous_batch_id = (bit<16>)hdr.loss.batch_id;
            }

            // Compute local batch
            //获取当前的batch_id
            meta.batch_id = (bit<16>)((standard_metadata.ingress_global_timestamp >> 21) % 2);

            //将当前的batch_id存在meta中
            last_batch_id.read(meta.last_local_batch_id, (bit<32>)0);
            last_batch_id.write((bit<32>)0, meta.batch_id);
            // Only works if there is enough traffic. For example
            // if there is 1 packet every 1 second it can happen
            // that the batch id never changes
            //如果上一个batch_id和当前的batch_id不一样，则需要收集loss包了
            if (meta.batch_id != meta.last_local_batch_id)
            {
                //克隆数据包
                //携带所有meta数据
                // clone3(CloneType.I2E, 100, meta);
                clone_preserving_field_list(CloneType.I2E, 100, 1);
            }

            // Update the header batch id with the current one
            //更新当前的batch_id值
            hdr.loss.batch_id = (bit<1>)meta.batch_id;

            // Compute the hash indexes before we apply the meters
            // 更新hash索引值，
            compute_hash_indexes();
            //判断是否移除loss字段
            remove_loss_header.apply();

            //判断是否是第一个交换机或最后一个交换机，
            if (meta.dont_execute_um == 0)
            {
               apply_um_meter();
            }

            if (meta.dont_execute_dm == 0)
            {
               apply_dm_meter();
            }

            // Drop the packet if ttl=1
            if (hdr.ipv4.ttl == 1)
            {
                drop();
            }
            else
            {
                hdr.ipv4.ttl = hdr.ipv4.ttl -1;
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    apply {
        // If ingress clone
        // TODO 10
        if (standard_metadata.instance_type == 1){
            hdr.loss.setValid();
            hdr.ipv4.setInvalid();
            hdr.loss.batch_id = (bit<1>)meta.last_local_batch_id;
            hdr.loss.padding = (bit<7>)0;
            hdr.loss.nextProtocol = (bit<8>)0;
            hdr.ethernet.etherType = LOSS_CHANGE_OF_BATCH;
            truncate((bit<32>)16); //ether+loss header
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
     	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	          hdr.ipv4.ihl,
              hdr.ipv4.dscp,
              hdr.ipv4.ecn,
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
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;