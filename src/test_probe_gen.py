#!/usr/bin/env python3
"""测试动态探针生成器"""
import json
import sys
sys.path.insert(0, '/root/URMATEST/src')

with open('/root/URMATEST/rules/glibc_functions.json') as f:
    rules = json.load(f)

# 导入
from urma_latency_collector import DynamicProbeGenerator

# 生成探针
gen = DynamicProbeGenerator(rules)
program = gen.build_bpf_program()

print("=" * 70)
print("生成的eBPF程序 (前3000字符)")
print("=" * 70)
print(program[:3000])
print("\n... [truncated] ...\n")
print("=" * 70)
print("生成的eBPF程序 (最后1000字符)")
print("=" * 70)
print(program[-1000:])
print(f"\n总程序长度: {len(program)} 字符")
print(f"生成的函数数量: {len(gen.functions)}")
print(f"生成的探针数量: {len(gen.entry_probes) + len(gen.return_probes)}")
