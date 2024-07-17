from FuxuanTracer.dependecy.needModules import ctypes


class pcap_if(ctypes.Structure):
    pass

pcap_if._fields_ = [
    ("next", ctypes.POINTER(pcap_if)),
    ("name", ctypes.c_char_p),
    ("description", ctypes.c_char_p),
    ("addresses", ctypes.c_void_p),
    ("flags", ctypes.c_uint)
]

class pcap_pkthdr(ctypes.Structure):
    _fields_ = [("ts", ctypes.c_long * 2), ("caplen", ctypes.c_uint), ("len", ctypes.c_uint)]