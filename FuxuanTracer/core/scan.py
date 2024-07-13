from FuxuanTracer.dependecy.needModules import (
    socket,
    track as ProcessTrack
)
from FuxuanTracer.utils.Protocol import (
    WebProtocol
)
from FuxuanTracer.utils.logger import (
    logger
)

class PortScanner:
    """
    端口扫描器类，用于扫描指定范围的端口。
    """
    def __init__(self, ranges: range, useProtocol: str = "TCP", timeout: int = 10):
        """
        初始化端口扫描器。

        :param ranges: 要扫描的端口范围。
        :param useProtocol: 使用的协议（TCP、UDP、ICMP、IGMP）。
        :param timeout: 超时时间，单位为秒。
        """
        self.ranges = ranges
        self.logger = logger
        self.protocol = useProtocol
        self.timeout = timeout
        self.ava_protocol: set = {"TCP", "UDP", "ICMP", "IGMP"}
        self._protocol = self._set_protocol(useProtocol)
        self.result = {}
        self.socket = self._get_socket()
        self.socket.settimeout(self.timeout)

    def _set_protocol(self, protocol: str):
        """
        设置协议类型。

        :param protocol: 协议名称。
        :return: 协议类型元组。
        """
        protocols = {
            "TCP": WebProtocol.TCP,
            "UDP": WebProtocol.UDP,
            "ICMP": WebProtocol.ICMP,
            "IGMP": WebProtocol.IGMP
        }
        if protocol not in protocols:
            raise ValueError(f"不支持的协议：{protocol}")
        return protocols[protocol]

    def _get_socket(self):
        """
        获取 socket 对象。

        :return: socket 对象。
        """
        protocolType, protocol = self._protocol
        if self.protocol in self.ava_protocol:
            return socket.socket(socket.AF_INET, protocolType)
        else:
            raise ValueError(f"不支持的协议：{self._protocol}")

    def _send_test_msg(self, host: str, port: int = 80):
        """
        发送测试消息。

        :param host: 目标主机。
        :param port: 目标端口。
        """
        msg = b"test"
        if self.protocol in {"TCP", "UDP", "ICMP", "IGMP"}:
            self.socket.sendto(msg, (host, port))
        else:
            raise ValueError(f"不支持的协议：{self._protocol}")

    def scan(self, host: str):
        """
        扫描指定范围的端口。

        :param host: 目标主机。
        """
        self.result["host"] = host
        self.logger.info(f"开始扫描端口范围：{self.ranges}")
        self.logger.info(f"使用协议：{self.protocol}")
        self.logger.info(f"耐心等待扫描完成...")

        for port in ProcessTrack(self.ranges, description="扫描端口中..."):
            try:
                self.socket.connect((host, port))
                self._send_test_msg(host, port)
                self.result[port] = "open"
            except socket.error:
                self.result[port] = "closed"

        self.logger.success(f"扫描完成")

    def check(self, need_what: str = "closed") -> str:
        """
        检查指定状态的端口。

        :param need_what: 要检查的端口状态（open 或 closed）。
        :return: 符合条件的端口列表。
        """
        result = {port for port, status in self.result.items() if status == need_what}
        self.logger.info(f"检查端口是否{need_what}")
        return f"{need_what}:{result}"

    def scan_as_target(self, host: str, ports: list[int] = [80, 443, 22]):
        """
        扫描指定的目标端口。

        :param host: 目标主机。
        :param ports: 要扫描的端口列表。
        """
        self.result["host"] = host
        self.logger.info(f"开始扫描目标端口：{ports}")

        for port in ProcessTrack(ports, description="扫描端口中..."):
            try:
                self.socket.connect((host, port))
                self.result[port] = "open"
            except (socket.timeout, socket.error):
                self.result[port] = "closed"

        self.logger.success(f"扫描完成")

# 示例用法
if __name__ == '__main__':
    scanner = PortScanner(range(80, 85), useProtocol="TCP")
    scanner.scan("192.168.1.1")
    print(scanner.check("open"))
    print(scanner.check("closed"))
