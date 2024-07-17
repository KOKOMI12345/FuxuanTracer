
from FuxuanTracer import DataPackAnalyzer
import asyncio


# 同步抓取数据包
"""
ins = DataPackAnalyzer()

devices = list(ins.getAvaliableDevice().keys())

# 我们选择第4个，因为那个是我的以太网设备
choose_divice =  devices[4]

# 设置过滤器, 注意: 每次调用 setFilter 都会重置过滤规则
ins.setFilter(WebProtocol="HTTPS", Port=[443])

# 抓取100个包
ins.catchDataPak(choose_divice, 100)

# 解析抓取的包
ins.analyze_packets(True,"result.log",False,True)
"""

# 异步抓取数据包

ins = DataPackAnalyzer()

devices = list(ins.getAvaliableDevice().keys())
choose_divice =  devices[4]
ins.setFilter(WebProtocol="HTTP", Port=[80],StreamProtocol="TCP")

# 定义一个main函数，异步执行
async def main(ins=ins, choose_divice=choose_divice):
    await ins.AsyncProcess(
        use_device=choose_divice,
        write_to_file=True,
        file_path="result.log",
        json_fmt=True,
        enqueue=False
    )

# 异步执行main函数
asyncio.run(main())