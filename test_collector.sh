#!/bin/bash
set -e
cd /root/URMATEST/src

# 清理
pkill -9 tcp_server 2>/dev/null || true
sleep 1

# 启动TCP服务器
./tcp_server &
SERVER_PID=$!
echo "Server started: PID $SERVER_PID"
sleep 1

# 运行采集器 (5秒)
python3 /root/URMATEST/src/urma_latency_collector.py \
    -r /root/URMATEST/rules/glibc_functions.json \
    -o /root/URMATEST/output \
    -d 5 &
COLLECTOR_PID=$!
echo "Collector started: PID $COLLECTOR_PID"

sleep 1

# 运行客户端
./tcp_client 128 10

# 等待采集结束
sleep 4
wait $COLLECTOR_PID 2>/dev/null || true

# 停止服务器
kill $SERVER_PID 2>/dev/null || true

echo ""
echo "=== 采集结果 ==="
ls -la /root/URMATEST/output/
