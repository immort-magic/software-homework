from p4utils.utils.helper import load_topo
from p4utils.utils.sswitch_thrift_API import *
from crc import Crc
import socket, struct, pickle, os, time

from scapy.all import Ether, sniff, Packet, BitField, raw


class LossHeader(Packet):
    name = 'LossHeader'
    fields_desc = [BitField('batch_id',0,8), BitField('next_protocol', 0, 8)]


crc32_polinomials = [0x04C11DB7, 0xEDB88320, 0xDB710641, 0x82608EDB, 0x741B8CD7, 0xEB31D82E,
                     0xD663B05, 0xBA0DC66B, 0x32583499, 0x992C1A4C, 0x32583499, 0x992C1A4C]

NUM_PORTS = 2
NUM_BATCHES = 2

REGISTER_SIZE_TOTAL = 2048
REGISTER_BATCH_SIZE  = int(REGISTER_SIZE_TOTAL/NUM_BATCHES) # It must be an integer
REGISTER_PORT_SIZE = int(REGISTER_BATCH_SIZE/NUM_PORTS)     # It must be an integer


class PacketLossController(object):

    def __init__(self, num_hashes=3):

        self.topo = load_topo('topology.json')
        self.controllers = {}
        self.num_hashes = num_hashes

        # gets a controller API for each switch: {"s1": controller, "s2": controller...}
        self.connect_to_switches()
        # creates the 3 hashes that will use the p4 switch
        self.create_local_hashes()

        # initializes the switch
        # resets all registers, configures the 3 x 2 hash functions
        # reads the registers
        # populates the tables and mirroring id
        self.init()
        self.registers = {}

    def init(self):
        self.reset_all_registers()
        self.set_crc_custom_hashes_all()
        self.read_registers()
        self.configure_switches()

    def connect_to_switches(self):
        for p4switch in self.topo.get_p4switches():
            thrift_port = self.topo.get_thrift_port(p4switch)
            self.controllers[p4switch] = SimpleSwitchThriftAPI(thrift_port)

    def configure_switches(self):

        for sw, controller in self.controllers.items():
            # ads cpu port
            controller.mirroring_add(100, 3)

            # set the basic forwarding rules
            controller.table_add("forwarding", "set_egress_port", ["1"], ["2"])
            controller.table_add("forwarding", "set_egress_port", ["2"], ["1"])

            # set the remove header rules when there is a host in a port
            direct_hosts = self.topo.get_hosts_connected_to(sw)
            for host in direct_hosts:
                port = self.topo.node_to_node_port_num(sw,host)
                controller.table_add("remove_loss_header", "remove_header", [str(port)], [])

    def set_crc_custom_hashes_all(self):
        for sw_name in self.controllers:
            self.set_crc_custom_hashes(sw_name)

    def set_crc_custom_hashes(self, sw_name):
        custom_calcs = sorted(self.controllers[sw_name].get_custom_crc_calcs().items())
        i = 0
        # Set the first 3 hashes for the um
        for custom_crc32, width in custom_calcs[:self.num_hashes]:
            self.controllers[sw_name].set_crc32_parameters(custom_crc32, crc32_polinomials[i], 0xffffffff, 0xffffffff, True,
                                                           True)
            i += 1

        i = 0
        # Sets the 3 hashes for the dm, they have to be the same, thus we use the same index
        for custom_crc32, width in custom_calcs[self.num_hashes:]:
            self.controllers[sw_name].set_crc32_parameters(custom_crc32, crc32_polinomials[i], 0xffffffff, 0xffffffff,
                                                           True, True)
            i += 1

    def create_local_hashes(self):
        self.hashes = []
        for i in range(self.num_hashes):
            self.hashes.append(Crc(32, crc32_polinomials[i], True, 0xffffffff, True, 0xffffffff))

    def reset_all_registers(self):
        for sw, controller in self.controllers.items():
            for register in controller.get_register_arrays():
                controller.register_reset(register)

    def reset_registers(self, sw, stream, port, batch_id):
        start = (batch_id * REGISTER_BATCH_SIZE) + ((port-1) * REGISTER_PORT_SIZE)
        end = start + REGISTER_PORT_SIZE

        for register in self.controllers[sw].get_register_arrays():
            if stream in register:
                self.controllers[sw].register_write(register, [start, end], 0)

    def flow_to_bytestream(self, flow):
        # flow fields are: srcip , dstip, srcport, dstport, protocol, ip id
        return socket.inet_aton(flow[0]) + socket.inet_aton(flow[1]) + struct.pack(">HHBH",flow[2], flow[3], flow[4], flow[5])

    def read_registers(self):
        # reads all the registers
        self.registers = {sw: {} for sw in self.controllers.keys()}
        for sw, controller in self.controllers.items():
            for register in controller.get_register_arrays():
                self.registers[sw][register] = (controller.register_read(register))

    def extract_register_information(self, sw, stream, port, batch_id):
        # reads the region of a um or dm register: uses port, batch id.
        start = (batch_id * REGISTER_BATCH_SIZE) + ((port-1) * REGISTER_PORT_SIZE)
        end = start + REGISTER_PORT_SIZE
        res = {}
        for name, values in self.registers[sw].items():
            if stream in name:
                res[name] = values[start:end]
        return res

    def decode_meter_pair(self, um_registers, dm_registers):
        # TODO 3
        counters = [x - y for x, y in zip(um_registers['MyIngress.um_counter'], dm_registers['MyIngress.dm_counter'])]
        ip_src = [x ^ y for x, y in zip(um_registers['MyIngress.um_ip_src'], dm_registers['MyIngress.dm_ip_src'])]
        ip_dst = [x ^ y for x, y in zip(um_registers['MyIngress.um_ip_dst'], dm_registers['MyIngress.dm_ip_dst'])]
        ports_proto_id = [x ^ y for x, y in zip(um_registers['MyIngress.um_ports_proto_id'], dm_registers['MyIngress.dm_ports_proto_id'])]
        dropped_packets = set()
        # 当前列表中存在元素1时进行循环，即找纯桶
        while 1 in counters:
            # 获取元素为1的数据的索引
            i = counters.index(1)
            tmp_src = ip_src[i]
            tmp_dst = ip_dst[i]
            src = socket.inet_ntoa(struct.pack("!I", tmp_src))
            dst = socket.inet_ntoa(struct.pack("!I", tmp_dst))
            misc = ports_proto_id[i]
            # id为1个字节
            id = misc & 0xffff
            # proto为1个字节
            proto = misc >> 16 & 0xff
            # port为2个字节
            dst_port = misc >> 24 & 0xffff
            # port为2个字节
            src_port = misc >> 40 & 0xffff
            # 创建对应的流
            flow = (src, dst, src_port, dst_port, proto, id)

            # 获取三个索引，将流转换为字节流
            flow_stream = self.flow_to_bytestream(flow)
            # 根据当前的流找到其对应的索引值，
            index0 = self.hashes[0].bit_by_bit_fast(flow_stream) % REGISTER_PORT_SIZE
            index1 = self.hashes[1].bit_by_bit_fast(flow_stream) % REGISTER_PORT_SIZE
            index2 = self.hashes[2].bit_by_bit_fast(flow_stream) % REGISTER_PORT_SIZE

            # 清除count=1的表项
            counters[index0] -= 1
            counters[index1] -= 1
            counters[index2] -= 1

            ip_src[index0] ^= tmp_src
            ip_src[index1] ^= tmp_src
            ip_src[index2] ^= tmp_src

            ip_dst[index0] ^= tmp_dst
            ip_dst[index1] ^= tmp_dst
            ip_dst[index2] ^= tmp_dst

            ports_proto_id[index0] ^= misc
            ports_proto_id[index1] ^= misc
            ports_proto_id[index2] ^= misc

            # 表示当前的同步不正确
            # 无法全部变成纯桶后归零，有部分计数不为0
            if any(x < 0 for x in counters):
                return dropped_packets
            
            dropped_packets.add(flow)

        return dropped_packets
        # pass
    
    # 检查两个交换机在batch_id下发生丢包没有
    def verify_link(self, sw1, sw2, batch_id):
        # TODO 2
        # 返回交换机1和交换机1连接的端口号
        sw1_to_sw2_interface = self.topo.node_to_node_port_num(sw1, sw2)
        # 返回交换机2和交换机1连接的端口号
        sw2_to_sw1_interface = self.topo.node_to_node_port_num(sw2, sw1)

        # 提取交换机1在端口 sw1_to_sw2_interface 上对应 batch_id 的寄存器信息
        sw1_um = self.extract_register_information(sw1, 'um', sw1_to_sw2_interface, batch_id)
        # 提取交换机2在端口 sw2_to_sw1_interface 上对应 batch_id 的寄存器信息 
        sw2_dm = self.extract_register_information(sw2, 'dm', sw2_to_sw1_interface, batch_id)

        # 根据获取到的两个上游和下游寄存器，计算出L，得出丢失数据包信息
        dropped_packets = self.decode_meter_pair(sw1_um, sw2_dm)

        # 清理寄存器中batch_id为多少的um，dm寄存器上的数据
        # 计算完毕之后，清理掉上一次的数据信息
        self.reset_registers(sw1, 'um', sw1_to_sw2_interface, batch_id)
        self.reset_registers(sw2, 'dm', sw2_to_sw1_interface, batch_id)

        # 如果存在丢失数据包
        if dropped_packets:
            # 打印出丢失数据包
            print("Packets dropped: {} at link {}->{}:".format(len(dropped_packets), sw1, sw2))
            print("Details:")
            for packet in dropped_packets:
                print(packet)
        # pass

    # 检查当前交换机在batch_id下发生丢包没有
    def check_sw_links(self, sw, batch_id):
        # TODO 1
        # pass
        # 根据batch timing的时间进行相应的更改
        time.sleep(0.25)

        # 读取当前交换机上所有的寄存器上的数据
        self.read_registers()

        # 处理正确的连接并且清理寄存器，获取当前交换机连接的寄存器
        # 判断当前交换机的邻居是否是topo中的交换机
        neighboring_p4_switches = [x for x in self.topo.get_neighbors(sw) if
                                   x in self.topo.get_p4switches()]
        # 判断当前链路是否发生丢包现象
        for neighboring_switch in neighboring_p4_switches:
            self.verify_link(sw, neighboring_switch, batch_id)

    # When a batch_id changes the controller gets triggered
    def recv_msg_cpu(self, pkt):
        interface = pkt.sniffed_on
        print(interface)
        switch_name = interface.split("-")[0]
        packet = Ether(raw(pkt))
        if packet.type == 0x1234:
            loss_header = LossHeader(packet.load)
            batch_id = loss_header.batch_id >> 7
            print(switch_name, batch_id)
            # 某个交换机发送batch_id信息
            self.check_sw_links(switch_name, batch_id)

    def run_cpu_port_loop(self):
        cpu_interfaces = [str(self.topo.get_cpu_port_intf(sw_name).replace("eth0", "eth1")) for sw_name in self.controllers]
        sniff(iface=cpu_interfaces, prn=self.recv_msg_cpu)

if __name__ == "__main__":

    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--option', help="", type=str, required=False, default="run")
    args = parser.parse_args()

    controller = PacketLossController()
    if args.option == "run":
        controller.run_cpu_port_loop()



