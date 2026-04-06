# URMA通信链路时延分析工具

基于eBPF的URMA（Unified Remote Memory Access）通信链路时延分析工具，用于采集和分析URMA关键函数的调用时延，并生成火焰图进行可视化。

## 目录结构

```
URMATEST/
├── rules/
│   └── urma_functions.json    # 函数采集规则
├── src/
│   ├── urma_latency_collector.py  # eBPF数据采集器
│   └── urma_flamegraph.py         # 火焰图生成器
└── output/                    # 采集输出目录
```

## 功能特性

1. **关键函数规则化**: 使用JSON格式定义待采集的函数及其入参
2. **函数时延采集**: 基于eBPF探针采集函数执行时延和入参值
3. **可配置采集**: 支持设置采集时长、输入目录、规则文件
4. **火焰图生成**: 独立的Python脚本生成可视化火焰图

## 核心函数

工具针对URMA的5个核心函数进行时延分析：

| 函数名 | 描述 | 类别 |
|--------|------|------|
| urma_write | RDMA远程写操作 | 数据通路 |
| urma_read | RDMA远程读操作 | 数据通路 |
| urma_send | 发送数据到远程节点 | 数据通路 |
| urma_recv | 从远程节点接收数据 | 数据通路 |
| urma_poll_jfc | 轮询完成队列 | 控制通路 |

## 依赖

- Python 3.6+
- python3-bpfcc
- bpfcc-tools
- root权限（eBPF探针需要）

## 安装依赖

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y bpfcc-tools python3-bpfcc

# CentOS/RHEL
sudo yum install -y bpfcc-tools python3-bpfcc
```

## 使用方法

### 1. 采集数据

```bash
sudo python3 src/urma_latency_collector.py \
    -r rules/urma_functions.json \
    -o output \
    -d 60
```

参数说明：
- `-r, --rules`: 函数规则JSON文件路径
- `-o, --output`: 输出目录路径
- `-d, --duration`: 采集时长（秒）

### 2. 生成火焰图

```bash
python3 src/urma_flamegraph.py \
    -i output/urma_stacks_20240101_120000.txt \
    -o output
```

参数说明：
- `-i, --input`: 采集数据文件
- `-o, --output`: 输出目录路径

## 规则文件格式

```json
{
  "version": "1.0",
  "description": "URMA函数时延采集规则",
  "functions": [
    {
      "name": "urma_write",
      "description": "RDMA远程写操作",
      "category": "data_path",
      "params": [
        {"name": "jfs", "type": "pointer", "required": true, "description": "JFS句柄"},
        {"name": "dst", "type": "uint64", "required": true, "description": "目标地址"},
        {"name": "src", "type": "uint64", "required": true, "description": "源地址"},
        {"name": "len", "type": "uint32", "required": true, "description": "数据长度"}
      ]
    }
  ]
}
```

## 输出文件

1. **原始数据**: `urma_latency_YYYYMMDD_HHMMSS.json` - 完整的事件记录
2. **统计数据**: `urma_stats_YYYYMMDD_HHMMSS.json` - 统计摘要
3. **栈数据**: `urma_stacks_YYYYMMDD_HHMMSS.txt` - 用于火焰图生成
4. **火焰图**: 
   - `urma_flamegraph_YYYYMMDD_HHMMSS.svg` - SVG格式火焰图
   - `urma_flamegraph_YYYYMMDD_HHMMSS.html` - HTML格式火焰图
5. **分析报告**: `urma_analysis_YYYYMMDD_HHMMSS.json` - JSON格式分析报告

## URMA简介

URMA（Unified Remote Memory Access）是openEuler提供的高性能分布式通信软件库，基于UB（Unified Bus）协议提供低时延、高带宽的远程内存访问接口。主要用于：

- 数据中心网络通信
- 超级节点内部通信
- 服务器内部卡间通信

## 参考资料

- [URMA内核驱动](https://atomgit.com/openeuler/kernel/tree/OLK-6.6/drivers/ub/urma)
- [URMA用户态库](https://atomgit.com/openeuler/umdk/tree/master/src/urma/lib/urma/)
- [UMDK项目](https://github.com/openeuler-mirror/umdk)
