from FuxuanTracer.utils.dataPackCatcher import DataPackCatcher
from FuxuanTracer.dependecy.needModules import struct
from FuxuanTracer.utils.Protocol import IpProtocol
from FuxuanTracer.utils.logger import logger


class DataPackAnalyzer:
    def __init__(self):
        self.logger = logger
        self.cacher = DataPackCatcher()
        self.deviceAvaliable = self.cacher.deviceDict
        self.cached_dataPaks = []
        self.result = []

    def getAvaliableDevice(self):
        return self.deviceAvaliable

    def catchDataPak(self, use_device: str, num_paks: int = 10):
        self.logger.info(f"开始捕获 {num_paks} 个数据包")
        if use_device not in self.deviceAvaliable:
            self.logger.error(f"设备 {use_device} 不存在")
            return
        if use_device:
            self.logger.info(f"使用设备 {use_device}")
            try:
                handler = self.cacher.open_device(use_device)
                result = self.cacher.capture_packets(handler, num_paks)  # 返回的是一个包含十六进制字符串的列表
                self.cached_dataPaks = result
                self.cacher.close_device(handler)
                self.logger.info("抓获完成,现在可以开始进行分析")
            except Exception as e:
                self.logger.error(f"捕获数据包时出错: {str(e)}")

    def __parse_ethernet_frame(self, frame):
        """
        解析以太网帧
        """
        dst_mac = frame[0:6]
        src_mac = frame[6:12]
        etherType = struct.unpack('!H', frame[12:14])[0]
        return dst_mac, src_mac, etherType, frame[14:]

    def __parse_IPV4_header(self, header):
        """
        解析IPv4头部
        """
        ipv4_header = {
            'version': (header[0] >> 4),
            'ihl': header[0] & 0x0F,
            'dscp': ((header[1] & 0xFC) >> 2),
            'ecn': (header[1] & 0x3),
            'total_length': struct.unpack('!H', header[2:4])[0],
            'identification': struct.unpack('!H', header[4:6])[0],
            'flags': ((header[6] & 0xE0) >> 5),
            'fragment_offset': struct.unpack('!H', header[6:8])[0] & 0x1FFF,
            'ttl': header[8],
            'protocol': header[9],
            'header_checksum': struct.unpack('!H', header[10:12])[0],
            'source_address': self.__format_ipv4_address(header[12:16]),
            'destination_address': self.__format_ipv4_address(header[16:20])
        }
        return ipv4_header

    def __parse_IPV6_header(self, header):
        """
        解析IPv6头部
        """
        unpacked_data = struct.unpack('!4sHBB16s16s', header[:40])
        ipv6_header = {
            'version': (unpacked_data[0][0] >> 4),
            'traffic_class': ((unpacked_data[0][0] & 0x0F) << 4) | (unpacked_data[0][1] >> 12),
            'flow_label': unpacked_data[0][1] & 0xFFF,
            'payload_length': unpacked_data[1],
            'next_header': unpacked_data[2],
            'hop_limit': unpacked_data[3],
            'source_address': self.__format_ipv6_address(unpacked_data[4]),
            'destination_address': self.__format_ipv6_address(unpacked_data[5])
        }
        return ipv6_header

    def __format_ipv4_address(self, address):
        """
        格式化IPv4地址
        """
        return '.'.join(map(str, address))

    def __format_ipv6_address(self, address):
        """
        格式化IPv6地址
        """
        return ':'.join(f'{address[i]:02x}{address[i+1]:02x}' for i in range(0, 16, 2))

    def parse_tcp_header(self, header):
        """
        解析TCP头部
        """
        src_port, dst_port = struct.unpack('!HH', header[0:4])
        seq_num = struct.unpack('!I', header[4:8])[0]
        ack_num = struct.unpack('!I', header[8:12])[0]
        data_offset = (header[12] & 0xf0) >> 4
        flags = header[13]
        window_size = struct.unpack('!H', header[14:16])[0]
        return src_port, dst_port, seq_num, ack_num, data_offset, flags, window_size, header[data_offset * 4:]

    def parse_udp_header(self, header):
        """
        解析UDP头部
        """
        src_port, dst_port, length, checksum = struct.unpack('!HHHH', header[:8])
        return src_port, dst_port, length, checksum

    def hex_to_bytes(self, hex_str):
        return bytes.fromhex(hex_str.replace(' ', ''))

    def analyze_packet(self, packet_hex):
        """
        分析单个数据包
        """
        try:
            packet_bytes = self.hex_to_bytes(packet_hex)
            dst_mac, src_mac, etherType, payload = self.__parse_ethernet_frame(packet_bytes)
            result_string = f"以太网帧: \n目的MAC: {self.__format_mac(dst_mac)}\n源MAC: {self.__format_mac(src_mac)}\n以太类型: {hex(etherType)}\n"

            if etherType == IpProtocol.IPV4:
                ipv4_header = self.__parse_IPV4_header(payload[:20])
                result_string += f"IPv4头部: {ipv4_header}\n"
                result_string += f"源IP: {ipv4_header['source_address']}\n"
                result_string += f"目的IP: {ipv4_header['destination_address']}\n"
                if ipv4_header['protocol'] == IpProtocol.TCP:
                    tcp_header = self.parse_tcp_header(payload[ipv4_header['ihl']*4:])
                    result_string += f"TCP头部: {tcp_header}\n"
                elif ipv4_header['protocol'] == IpProtocol.UDP:
                    udp_header = self.parse_udp_header(payload[ipv4_header['ihl']*4:])
                    result_string += f"UDP头部: {udp_header}\n"
            elif etherType == IpProtocol.IPV6:
                ipv6_header = self.__parse_IPV6_header(payload[:40])
                result_string += f"IPv6头部: {ipv6_header}\n"
                result_string += f"源IP: {ipv6_header['source_address']}\n"
                result_string += f"目的IP: {ipv6_header['destination_address']}\n"
                if ipv6_header['next_header'] == IpProtocol.TCP:
                    tcp_header = self.parse_tcp_header(payload[40:])
                    result_string += f"TCP头部: {tcp_header}\n"
                elif ipv6_header['next_header'] == IpProtocol.UDP:
                    udp_header = self.parse_udp_header(payload[40:])
                    result_string += f"UDP头部: {udp_header}\n"

            return result_string
        except Exception as e:
            self.logger.error(f"分析数据包时出错: {str(e)}")
            return ""

    def __format_mac(self, mac):
        """
        格式化MAC地址
        """
        return ':'.join(f'{b:02x}' for b in mac)

    def analyze_packets(self, write_to_file: bool = False, file_path: str = "result.txt"):
        """
        分析已捕获的数据包
        """
        self.logger.info("开始分析数据包")
        self.result.clear()  # 清除之前的分析结果
        for packet in self.cached_dataPaks:
            packet_analysis = self.analyze_packet(packet)
            self.result.append(packet_analysis)

        if write_to_file:
            with open(file_path, "w", encoding='utf-8') as file:
                for index, analysis in enumerate(self.result, start=1):
                    file.write(f"抓获的第 {index} 个数据包\n")
                    file.write(analysis)
                    file.write("\n-------------------------------------------\n")

        self.logger.info("数据包分析完成")

if __name__ == "__main__":
    try:
        analyzer = DataPackAnalyzer()
        devices = analyzer.getAvaliableDevice()
        print("可用设备:", devices)
        if devices:
            first_device = list(devices.keys())[1]  # 选择第一个网络设备
            analyzer.catchDataPak(first_device, 10)
            analyzer.analyze_packets(write_to_file=True, file_path="result.log")
    except Exception as e:
        logger.error(f"运行时出错: {str(e)}")
