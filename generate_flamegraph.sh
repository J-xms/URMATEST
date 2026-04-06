#!/bin/bash
# URMA火焰图生成脚本

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT="${SCRIPT_DIR}/output"

usage() {
    echo "Usage: $0 [-i input_file] [-o output_dir]"
    echo "  -i: 采集数据文件路径 (必填)"
    echo "  -o: 输出目录路径 (默认: ${OUTPUT})"
    exit 1
}

INPUT=""

while getopts "i:o:h" opt; do
    case $opt in
        i) INPUT="$OPTARG" ;;
        o) OUTPUT="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [ -z "$INPUT" ]; then
    echo "错误: 请指定输入文件"
    usage
fi

if [ ! -f "$INPUT" ]; then
    echo "错误: 输入文件不存在: $INPUT"
    exit 1
fi

echo "=========================================="
echo "URMA火焰图生成"
echo "=========================================="
echo "输入文件: ${INPUT}"
echo "输出目录: ${OUTPUT}"
echo "=========================================="

python3 "${SCRIPT_DIR}/src/urma_flamegraph.py" \
    --input "${INPUT}" \
    --output "${OUTPUT}"

echo ""
echo "生成完成!"
