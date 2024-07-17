import json

class DatapackResult:
    """
    数据包的返回结果类
    """

    def __init__(self, ether_frame=None, ip_header=None, transport_header=None):
        self.ether_frame = ether_frame if ether_frame else {}
        self.ip_header = ip_header if ip_header else {}
        self.transport_header = transport_header if transport_header else {}
        self.WebProtocol = None

    def set_ether_frame(self, dst_mac, src_mac, ether_type):
        self.ether_frame = {
            'destination_mac': dst_mac,
            'source_mac': src_mac,
            'ether_type': ether_type
        }

    def set_ip_header(self, version, ihl, dscp, ecn, total_length, identification, flags, fragment_offset, ttl, protocol, header_checksum, source_address, destination_address):
        self.ip_header = {
            'version': version,
            'ihl': ihl,
            'dscp': dscp,
            'ecn': ecn,
            'total_length': total_length,
            'identification': identification,
            'flags': flags,
            'fragment_offset': fragment_offset,
            'ttl': ttl,
            'protocol': protocol,
            'header_checksum': header_checksum,
            'source_address': source_address,
            'destination_address': destination_address
        }

    def set_webProtocol(self, WebProtocol: str):
        self.WebProtocol = WebProtocol

    def set_transport_header(self, protocol, header):
        self.transport_header = {
            'protocol': protocol,
            'header': header
        }

    def payload_to_hex_list(self, payload, line_length=16):
        if isinstance(payload, bytes):
            hex_list = [f"{byte:02x}" for byte in payload]

            # Truncate to nearest multiple of line_length
            remainder = len(hex_list) % line_length
            if remainder != 0:
                hex_list = hex_list[:-remainder]

            # Create list of lines with line_length elements each
            lines = [hex_list[i:i + line_length] for i in range(0, len(hex_list), line_length)]

            # Convert each line to a single string
            formatted_lines = [' '.join(line) for line in lines]

            return formatted_lines
        return []


    def to_json(self):
        result_dict = {
            'ether_frame': self.ether_frame,
            'ip_header': self.ip_header,
            'transport_header': self.transport_header,
            'WebProtocol': self.WebProtocol
        }
        return json.dumps(result_dict,default=self.payload_to_hex_list, indent=4)

    def __str__(self):
        result_str = ""
        if self.ether_frame:
            result_str += f"以太网帧:\n目的MAC: {self.ether_frame['destination_mac']}\n源MAC: {self.ether_frame['source_mac']}\n以太类型: {hex(self.ether_frame['ether_type'])}\n\n"

        if self.ip_header:
            result_str += f"IP头部:\n版本: {self.ip_header['version']}\nIHL: {self.ip_header['ihl']}\nDSCP: {self.ip_header['dscp']}\nECN: {self.ip_header['ecn']}\n"
            result_str += f"总长度: {self.ip_header['total_length']}\n标识: {self.ip_header['identification']}\n"
            result_str += f"标志: {self.ip_header['flags']}\n片偏移: {self.ip_header['fragment_offset']}\nTTL: {self.ip_header['ttl']}\n"
            result_str += f"协议: {self.ip_header['protocol']}\n头部校验和: {self.ip_header['header_checksum']}\n"
            result_str += f"源IP地址: {self.ip_header['source_address']}\n目的IP地址: {self.ip_header['destination_address']}\n"
            result_str += f"网络端口协议: {self.WebProtocol}\n\n"

        if self.transport_header:
            result_str += f"传输层头部:\n协议: {self.transport_header['protocol']}\n头部内容: {self.transport_header['header']}\n"

        return result_str.strip()