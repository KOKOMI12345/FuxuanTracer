
from FuxuanTracer.dependecy.needModules import (
    socket
)

class WebProtocol:
    """
    网络传输协议
    """
    TCP = (socket.SOCK_STREAM, socket.IPPROTO_TCP)
    UDP = (socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    ICMP = (socket.SOCK_RAW, socket.IPPROTO_ICMP)
    IGMP = (socket.SOCK_RAW, socket.IPPROTO_IGMP)

class IpProtocol:
    """
    IP协议类型
    """
    IPV4 = 0x0800
    IPV6 = 0x86DD
    ARP = 0x0806
    MPLS = 0x8847
    VLAN = 0x8100
    # IP协议中的协议号
    TCP = 6
    UDP = 17


class PortProtocol:
    """
    端口协议
    """
    HTTP = 80
    HTTPS = 443
    FTP = 21
    MYSQL = 3306
    SSL = 443
    SSH = 22
    SMTP = 25
    REDIS = 6379
    MONGODB = 27017
    RABBITMQ = 5672
    KAFKA = 9092
    ELASTICSEARCH = 9200
    SYSTEM_PORT_RANGE = range(0, 1024)

    @classmethod
    def is_system_port(cls, port):
        """
        检查端口是否在系统端口范围内
        :param port: 端口号
        :return: bool
        """
        return port in cls.SYSTEM_PORT_RANGE

    @classmethod
    def get_protocol_by_port(cls, port):
        """
        根据端口号获取协议名称
        :param port: 端口号
        :return: str or None
        """
        for name, value in cls.__dict__.items():
            if isinstance(value, int) and value == port:
                return name
        return None