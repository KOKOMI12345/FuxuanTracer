from FuxuanTracer.utils.dataPackCatcher import DataPackCatcher
from FuxuanTracer.dependecy.needModules import (struct ,
    sys , 
    Union , 
    Optional , 
    asyncio , 
    Callable , datetime , aiofiles
    )
from FuxuanTracer.utils.Protocol import IpProtocol , PortProtocol
from FuxuanTracer.utils.excformat import ExtractException
from FuxuanTracer.utils.dataPakResult import DatapackResult
from FuxuanTracer.utils.logger import logger


class DataPackAnalyzer:
    def __init__(self):
        self.logger = logger
        self.cacher = DataPackCatcher()
        self.deviceAvaliable = self.cacher.deviceDict
        self.cached_dataPaks = []
        self.result: list[str] = []
        self.async_result: asyncio.Queue = asyncio.Queue()
        self.async_lock = asyncio.Lock()
        self.filterd_result = []
        self.filter_rules: dict[str, Union[str,range,Union[list[int],list[str]]]] = {
            "WebProtocol": "all",
            "Port": "all",
            "StreamProtocol": "all"
        }

    def setFilter(self,WebProtocol: str = "all", Port: Union[str,range,list[int]] = "all", StreamProtocol: str = "all", **kwargs):
        self.filter_rules["WebProtocol"] = WebProtocol # 比如 HTTP , HTTPS 之类的
        if isinstance(Port, range): self.filter_rules["Port"] = Port
        elif isinstance(Port, list): self.filter_rules["Port"] = Port
        elif isinstance(Port, str): self.filter_rules["Port"] = Port
        else: self.logger.error(f"端口过滤器格式错误,请检查")
        self.filter_rules["StreamProtocol"] = StreamProtocol # 定义流协议，比如TCP, UDP 之类的
        if kwargs:
            for key, value in kwargs.items():
                self.filter_rules[key] = value

    def __applayFilter(self, result: DatapackResult,json_fmt: bool = False) -> Optional[str]:
        # 这里判断条件满不满足,满足就原封不动的返回,不满足就reutrn
        if result.WebProtocol and result.transport_header and result.ether_frame and result.ip_header:
            if self.filter_rules["WebProtocol"] != "all" and result.WebProtocol != self.filter_rules["WebProtocol"]:return "filted"
            elif self.filter_rules["StreamProtocol"] != "all" and result.transport_header["protocol"] not in self.filter_rules["StreamProtocol"]:return "filted"
            elif self.filter_rules["Port"] != "all" and (result.transport_header["header"]["dst_port"] not in self.filter_rules["Port"] and result.transport_header["header"]["src_port"] not in self.filter_rules["Port"]):return "filted"
            else:return str(result) if not json_fmt else result.to_json()

    def getAvaliableDevice(self):
        return self.deviceAvaliable
    
    async def __asyncAnylazer(self, packet: str, json_fmt: bool = False, use_filter: bool = True):
        """ 异步分析数据包 """
        return await asyncio.to_thread(self.analyze_packet,packet,json_fmt,use_filter)
    
    async def __AsyncCatch(self, use_device: str = "", callback: Optional[Callable] = None, *callbackArgs) -> None:
        """
        异步捕获数据包
        """
        self.logger.info(f"开始捕获数据包")
        
        if use_device not in self.deviceAvaliable:
            self.logger.error(f"设备 {use_device} 不存在")
            return
        
        self.logger.info(f"使用设备 {use_device}")
        
        handler = self.cacher.open_device(use_device)
        last_result = None
        
        try:
            while True:
                result = await asyncio.to_thread(self.cacher.capture_packets, handler, 1)
                current_result = result[0]
                
                if current_result != last_result:
                    if callback and current_result:
                        await callback(current_result, *callbackArgs)
                    last_result = current_result
                else:self.logger.debug("过滤重复数据包")
                
        except Exception as e:
            self.logger.error(f"捕获数据包时出错: {str(e)}")
            
        except asyncio.exceptions.CancelledError:
            self.logger.info("捕获数据包被终止")
            
        finally:
            self.cacher.close_device(handler)

    async def __AsyncWrite(self,
        result: str,
        write_to_file: bool = True,
        file_path: str = "result.log",
        enqueueMode: bool = True,
        json_fmt: bool = False,
        use_filter: bool = True,
        ):
            if write_to_file:
                async with self.async_lock:
                    with open(file_path,"a+",encoding="utf-8") as file:
                        if enqueueMode == False:
                            extract_packet = await self.__asyncAnylazer(result,json_fmt,use_filter)
                            if extract_packet == "filted" and use_filter:return
                            if extract_packet and extract_packet != "filted":
                                file.write(f"数据包: {datetime.now()}\n")
                                file.write(extract_packet) # type: ignore
                                file.write("\n-------------------------------------------\n")
                        elif result:file.write(result)
            else:print(result)
               

    async def AsyncProcess(self, 
        use_device: str = "",
        write_to_file:bool = True,
        file_path: str = "result.log",
        json_fmt: bool = False, 
        use_filter: bool = True,
        enqueue: bool = False
    ):
        """
        异步循环用于无限抓数据包,适合那种不愿意指定数据包数量,但是又想抓取全部数据包的场景
        """
        # 异步循环捕获数据包,直到用户按下ctrl+c
        if enqueue:
            await self.__AsyncCatch(use_device,self.async_result.put)
            while self.async_result.qsize():
                try:
                    packet = self.async_result.get_nowait()
                    result = await self.__asyncAnylazer(packet,json_fmt,use_filter)
                    if result and result != "filted":await self.__AsyncWrite(result,write_to_file,file_path,enqueue,json_fmt,use_filter) # type: ignore
                except asyncio.QueueEmpty:pass
        else:await self.__AsyncCatch(use_device,self.__AsyncWrite,write_to_file,file_path,enqueue,json_fmt,use_filter)


    def catchDataPak(self, use_device: str, num_paks: int = None): # type: ignore
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

    def __parse_IPV4_header(self, header)-> dict[str,str]:
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
    
    def __isWhatProtocol(self, content: tuple[int,int]) -> str:
        """
        判断是什么协议
        """
        constants = {key: value for key, value in PortProtocol.__dict__.items() if not callable(value)}
        keys = list(constants.keys()) # 协议名
        values = list(constants.values()) # 协议端口
        if content[0] in values: return keys[values.index(content[0])]
        elif content[1] in values: return keys[values.index(content[1])]
        else: return "UNKNOW"

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

    def analyze_packet(self, packet_hex: str,json_fmt: bool = False,use_filter: bool = False):
        """
        分析单个数据包
        """
        try:
            packet_bytes = self.hex_to_bytes(packet_hex)
            dst_mac, src_mac, etherType, payload = self.__parse_ethernet_frame(packet_bytes)
            result = DatapackResult()
            # 设置以太网帧信息
            result.set_ether_frame(self.__format_mac(dst_mac),self.__format_mac(src_mac),etherType)

            if etherType == IpProtocol.IPV4:
                ipv_header_length = (payload[0] & 0x0F) * 4
                ipv4_header = self.__parse_IPV4_header(payload[:ipv_header_length])
                result.set_ip_header(
                    ipv4_header['version'],
                    ipv4_header['ihl'],
                    ipv4_header['dscp'],
                    ipv4_header['ecn'],
                    ipv4_header['total_length'],
                    ipv4_header['identification'],
                    ipv4_header['flags'],
                    ipv4_header['fragment_offset'],
                    ipv4_header['ttl'],
                    ipv4_header['protocol'],
                    ipv4_header['header_checksum'],
                    ipv4_header['source_address'],
                    ipv4_header['destination_address']
                )
                protocol = ipv4_header['protocol']

            elif etherType == IpProtocol.IPV6:
                ipv6_header = self.__parse_IPV6_header(payload[:40])
                result.set_ip_header(
                    ipv6_header['version'],
                    None,  # IPv6没有IHL字段
                    None,  # IPv6没有DSCP字段
                    None,  # IPv6没有ECN字段
                    None,  # IPv6没有总长度字段
                    None,  # IPv6没有标识字段
                    None,  # IPv6没有标志字段
                    None,  # IPv6没有片偏移字段
                    ipv6_header['hop_limit'],  # IPv6使用TTL字段
                    ipv6_header['next_header'],  # IPv6使用next_header字段
                    None,  # IPv6没有头部校验和字段
                    ipv6_header['source_address'],
                    ipv6_header['destination_address']
                )
                protocol = ipv6_header['next_header']

            else:
                result.set_ip_header(None, None, None, None, None, None, None, None, None, None, None, None, None)
                protocol = None

            if etherType in [IpProtocol.IPV4, IpProtocol.IPV6] and protocol is not None:
                if protocol == IpProtocol.TCP:
                    header_length = ipv_header_length if etherType == IpProtocol.IPV4 else 40
                    tcp_payload = payload[header_length:]
                    src_port, dst_port, seq_num, ack_num, data_offset, flags, window_size, tcp_payload = self.parse_tcp_header(tcp_payload)
                    result.set_webProtocol(self.__isWhatProtocol((src_port, dst_port)))
                    result.set_transport_header("TCP", {
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'seq_num': seq_num,
                        'ack_num': ack_num,
                        'data_offset': data_offset,
                        'flags': flags,
                        'window_size': window_size,
                        'tcp_payload': tcp_payload
                    })
                elif protocol == IpProtocol.UDP:
                    header_length = ipv_header_length if etherType == IpProtocol.IPV4 else 40
                    udp_payload = payload[header_length:]
                    src_port, dst_port, length, checksum = self.parse_udp_header(udp_payload)
                    result.set_webProtocol(self.__isWhatProtocol((src_port, dst_port)))
                    result.set_transport_header("UDP", {
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'length': length,
                        'checksum': checksum
                    })
                if use_filter:
                    packet_result = self.__applayFilter(result,json_fmt)
                    if packet_result != "filted":return packet_result
                    else:return "filted"
                else:return str(result) if not json_fmt else result.to_json()

        except Exception as e:
            exctype , value , tb = sys.exc_info()
            errno_stack = ExtractException(exctype, value, tb)
            logger.error(f"解析数据包异常：{errno_stack}")
            return ""

    def __format_mac(self, mac: bytes):
        """
        格式化MAC地址
        """
        return ':'.join(f'{b:02x}' for b in mac)

    def analyze_packets(self, write_to_file: bool = False, file_path: str = "result.txt", json_fmt: bool = False, use_filter: bool = True):
        """
        分析已捕获的数据包
        """
        if use_filter:
            self.logger.info("开始分析数据包(使用过滤器)")
            result_to_analyze = self.filterd_result  # 使用筛选结果容器
        else:
            self.logger.info("开始分析数据包")
            result_to_analyze = self.result  # 使用普通结果容器

        result_to_analyze.clear()  # 清除之前的分析结果

        for packet in self.cached_dataPaks:
            packet_analysis = self.analyze_packet(packet, json_fmt, use_filter=use_filter)

            # 添加到对应的结果容器中
            if isinstance(packet_analysis, str):
                result_to_analyze.append(packet_analysis)

        # 将结果写入文件，如果写入文件模式启用
        if write_to_file:
            with open(file_path, "w", encoding='utf-8') as file:
                for index, analysis in enumerate(result_to_analyze, start=1):
                    if use_filter:file.write(f"符合条件的第 {index} 个数据包\n")
                    else:file.write(f"抓获的第 {index} 个数据包\n")

                    file.write(analysis)
                    file.write("\n-------------------------------------------\n")
        else:
            for index, analysis in enumerate(result_to_analyze, start=1):
                if use_filter:print(f"符合条件的第 {index} 个数据包")
                else:print(f"抓获的第 {index} 个数据包")

                print(analysis)
                print("-------------------------------------------\n")
        self.logger.info("数据包分析完成")