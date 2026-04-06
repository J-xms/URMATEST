#!/bin/bash
# URMA时延采集启动脚本

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULES="${SCRIPT_DIR}/rules/urma_functions.json"
OUTPUT="${SCRIPT_DIR}/output"
DURATION=60

usage() {
    echo "Usage: $0 [-r rules.json] [-o output_dir] [-d duration]"
    echo "  -r: 规则文件路径 (默认: ${RULES})"
    echo "  -o: 输出目录路径 (默认: ${OUTPUT})"
    echo "  -d: 采集时长(秒) (默认: ${DURATION})"
    exit 1
}

while getopts "r:o:d:h" opt; do
    case $opt in
        r) RULES="$OPTARG" ;;
        o) OUTPUT="$OPTARG" ;;
        d) DURATION="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

echo "=========================================="
echo "URMA通信链路时延采集"
echo "=========================================="
echo "规则文件: ${RULES}"
echo "输出目录: ${OUTPUT}"
echo "采集时长: ${DURATION}秒"
echo "=========================================="

sudo python3 "${SCRIPT_DIR}/src/urma_latency_collector.py" \
    --rules "${RULES}" \
    --output "${OUTPUT}" \
    --duration "${DURATION}"

echo ""
echo "采集完成!"
echo ""
echo "生成火焰图命令:"
echo "  python3 ${SCRIPT_DIR}/src/urma_flamegraph.py \\"
echo "    -i ${OUTPUT}/urma_stacks_*.txt \\"
echo "    -o ${OUTPUT}"
