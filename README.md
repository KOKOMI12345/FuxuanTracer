
# FuxuanTracer

FuxuanTracer是一个基于Python的开源网络流量监控工具，它能够抓取网络数据包，并解析出网络连接的IP地址, 端口等信息, 方便用户进行网络流量监控。

## 安装

```bash
pip install FuxuanTracer
```

## Get Started

```python
from FuxuanTracer import DataPackAnalyzer

ins = DataPackAnalyzer()

devices = list(ins.getAvaliableDevice().keys())

# 我们选择第4个，因为那个是我的以太网设备
choose_divice =  devices[4]

# 设置过滤器, 注意: 每次调用 setFilter 都会重置过滤规则
ins.setFilter(WebProtocol="HTTPS", Port=[443])

# 抓取10个包
ins.catchDataPak(choose_divice, 100)

# 解析抓取的包
ins.analyze_packets(True,"result.log",False,True)
```

## 参数说明(analyze_packets)

- 1. True ,代表写入文件
- 2. result.log , 写入文件的文件名
- 3. False , 代表不用json格式写入文件
- 4. True , 代表应用过滤器
