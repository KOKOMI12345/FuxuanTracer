
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

# 抓取10个包
ins.catchDataPak(choose_divice, 10)

# 解析抓取的包
ins.analyze_packets(True,"result.log")
```
