from FuxuanTracer.utils.Device import Device
from FuxuanTracer.utils.logger import logger
from FuxuanTracer.dependecy.needModules import ctypes , Union
from FuxuanTracer.utils._usePointer import pcap_pkthdr

class DataPackCatcher:
    def __init__(self) -> None:
        self.device = Device()
        self.deviceDict = self.device.get_device_list()
        self.dll = self.device.dll

    @logger.catch
    def open_device(self, device_name: str, snaplen: int = 65535, promisc: int = 1, timeout_ms: int = 1000):
        errbuf = ctypes.create_string_buffer(256)
        self.dll.pcap_open_live.restype = ctypes.POINTER(ctypes.c_void_p)
        self.dll.pcap_open_live.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_char_p]
        pcap_handle = self.dll.pcap_open_live(device_name.encode(), snaplen, promisc, timeout_ms, errbuf)

        if not pcap_handle or pcap_handle.contents is None:
            error_message = errbuf.value.decode('latin1', errors='ignore')
            raise RuntimeError(f"Failed to open device {device_name}: {error_message}")
        return pcap_handle
    
    @logger.catch
    def capture_packets(self, pcap_handle, packet_count: int = 10) -> list[str]:
        result = []
        def packet_handler(userdata, pkthdr_ptr, pkt_data_ptr):
            pkthdr = pkthdr_ptr.contents
            pkt_data = ctypes.string_at(pkt_data_ptr, pkthdr.caplen)
            logger.info(f"Packet captured: length={pkthdr.len}, captured length={pkthdr.caplen}")
            result.append(pkt_data.hex())

        PACKET_HANDLER = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.POINTER(pcap_pkthdr), ctypes.POINTER(ctypes.c_ubyte))
        packet_handler_cb = PACKET_HANDLER(packet_handler)

        self.dll.pcap_loop.restype = ctypes.c_int
        self.dll.pcap_loop.argtypes = [ctypes.c_void_p, ctypes.c_int, PACKET_HANDLER, ctypes.c_void_p]

        if self.dll.pcap_loop(pcap_handle, packet_count, packet_handler_cb, None) == -1:
            raise RuntimeError("Error occurred during packet capture")
        
        return result
    
    @logger.catch(message="an error has occurred during closing device")
    def close_device(self, pcap_handle):
        self.dll.pcap_close(pcap_handle)

if __name__ == "__main__":
    try:
        dataCatcher = DataPackCatcher()
        devices = dataCatcher.deviceDict
        print("Available devices:", devices)
        if devices:
            first_device = list(devices.keys())[1]  # Choose the first network device
            handler = dataCatcher.open_device(first_device)
            print(f"Capturing packets on {first_device}...")
            dataCatcher.capture_packets(handler)
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")