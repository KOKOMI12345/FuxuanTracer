
from FuxuanTracer import DataPackAnalyzer

ins = DataPackAnalyzer()

devices = list(ins.getAvaliableDevice().keys())

# 我们选择第4个，因为那个是我的以太网设备
choose_divice =  devices[4]

# 抓取10个包
ins.catchDataPak(choose_divice, 10)

# 解析抓取的包
ins.analyze_packets(True,"result.log")