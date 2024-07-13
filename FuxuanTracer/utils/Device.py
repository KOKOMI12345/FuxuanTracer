
from FuxuanTracer.utils._usePointer import pcap_if
from FuxuanTracer.dependecy.needModules import (
    ctypes,
    platform,
    os, subprocess
)

def get_system():
    return platform.system().lower()

def find_wpcap_path():
    paths = {
        "windows": [
            "C:\\Program Files\\Wireshark\\wpcap.dll",
            "C:\\Windows\\System32\\wpcap.dll"
        ],
        "linux": [
            "/usr/lib/x86_64-linux-gnu/libwpcap.so",
            "/usr/lib32/libwpcap.so"
        ]
    }
    
    system = get_system()
    for path in paths.get(system, []):
        if os.path.exists(path):
            return path

    if system == "windows":
        try:
            result = subprocess.check_output(['where', 'wpcap.dll'], stderr=subprocess.STDOUT)
            return result.decode().strip()
        except subprocess.CalledProcessError:
            raise RuntimeError("Failed to locate wpcap.dll")
    elif system == "linux":
        try:
            result = subprocess.check_output(['locate', 'libwpcap.so'], stderr=subprocess.STDOUT)
            return result.decode().strip().split('\n')[0]
        except subprocess.CalledProcessError:
            raise RuntimeError("Failed to locate libwpcap.so")
    else:
        raise RuntimeError("Unsupported system")

dll_path = find_wpcap_path()
if dll_path and get_system() == "windows":
    wpcap = ctypes.WinDLL(dll_path)
elif dll_path and get_system() == "linux":
    wpcap = ctypes.CDLL(dll_path)
else:
    raise RuntimeError("Failed to locate wpcap library")

class Device:
    def __init__(self):
        self.dll = wpcap

    def get_device_list(self):
        """
        获取网络中的所有设备。
        :return: 以设备名称为键、描述为值的字典。
        """
        # 定义 pcap_findalldevs 函数的签名
        self.dll.pcap_findalldevs.restype = ctypes.c_int
        self.dll.pcap_findalldevs.argtypes = [ctypes.POINTER(ctypes.POINTER(pcap_if)), ctypes.POINTER(ctypes.c_char_p)]

        # 初始化变量
        errbuf = ctypes.create_string_buffer(256)
        alldevs_ptr = ctypes.POINTER(pcap_if)()
        c_char_p_ptr = ctypes.c_char_p()

        # 调用 pcap_findalldevs 获取设备列表
        result = self.dll.pcap_findalldevs(ctypes.byref(alldevs_ptr), ctypes.byref(c_char_p_ptr))
        if result == -1:
            err_msg = ctypes.string_at(c_char_p_ptr).decode()
            raise RuntimeError(f"Failed to retrieve devices: {err_msg}")

        devices = {"system": get_system()}
        dev = alldevs_ptr
        while dev and dev.contents:
            name = dev.contents.name.decode() if dev.contents.name else "Unknown"
            description = dev.contents.description.decode() if dev.contents.description else "Unknown"
            devices[name] = description
            dev = dev.contents.next

        # 释放设备列表
        self.dll.pcap_freealldevs(alldevs_ptr)

        return devices

if __name__ == "__main__":
    try:
        device = Device()
        devices = device.get_device_list()
        for name, description in devices.items():
            print(f"{name}: {description}")
    except Exception as e:
        print(f"An error occurred: {str(e)}")
