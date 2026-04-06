#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
URMA通信链路时延分析工具 - 动态eBPF采集器
根据规则文件动态生成探针，采集函数时延和入参值
"""

import argparse
import json
import os
import sys
import time
import signal
from datetime import datetime
from collections import defaultdict

from bcc import BPF


class DynamicProbeGenerator:
    """根据规则动态生成eBPF探针"""
    
    def __init__(self, rules):
        self.rules = rules
        self.functions = rules.get('functions', [])
        self.entry_probes = []
        self.return_probes = []
        self._generate()
    
    def _generate(self):
        self._generate_probes()
    
    def _get_param_accessor(self, param_index, param_type):
        if param_type == 'int':
            return "(int)PT_REGS_PARM%d(ctx)" % (param_index + 1)
        elif param_type == 'size_t':
            return "(size_t)PT_REGS_PARM%d(ctx)" % (param_index + 1)
        elif param_type == 'socklen_t':
            return "(u32)PT_REGS_PARM%d(ctx)" % (param_index + 1)
        else:
            return "PT_REGS_PARM%d(ctx)" % (param_index + 1)
    
    def _generate_entry_probe(self, func_name, params):
        """生成entry探针"""
        func_id = self.functions.index(next(f for f in self.functions if f['name'] == func_name))
        code = "int trace_%s_entry(struct pt_regs *ctx) {" % func_name
        code += """
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    
    struct urma_call_ctx_t call = {};
    call.func_id = %d;
    call.enter_time = bpf_ktime_get_ns();
    call.pid = pid;
    call.tid = tid;
""" % func_id
        for i, p in enumerate(params):
            if i < 6:
                accessor = self._get_param_accessor(i, p.get('type', 'pointer'))
                code += "    call.arg%d = (u64)%s;\n" % (i, accessor)
        
        code += """
    u64 key = pid_tgid;
    urma_active_calls.update(&key, &call);
    return 0;
}
"""
        return code
    
    def _generate_return_probe(self, func_name, params):
        """生成return探针"""
        func_id = self.functions.index(next(f for f in self.functions if f['name'] == func_name))
        code = "int trace_%s_return(struct pt_regs *ctx) {" % func_name
        code += """
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    
    u64 key = pid_tgid;
    struct urma_call_ctx_t *call = urma_active_calls.lookup(&key);
    if (!call) return 0;
    
    u64 now = bpf_ktime_get_ns();
    u64 duration_ns = now - call->enter_time;
    
    struct urma_event_t event = {};
    event.func_id = %d;
    event.timestamp = now;
    event.duration_us = duration_ns / 1000;
    event.pid = pid;
    event.tid = tid;
    event.arg0 = call->arg0;
    event.arg1 = call->arg1;
    event.arg2 = call->arg2;
    event.arg3 = call->arg3;
    event.arg4 = call->arg4;
    event.arg5 = call->arg5;
    event.return_val = (int)PT_REGS_RC(ctx);
    
    urma_events.perf_submit(ctx, &event, sizeof(event));
    urma_active_calls.delete(&key);
    return 0;
}
""" % func_id
        return code
    
    def _generate_probes(self):
        for func in self.functions:
            fname = func['name']
            params = [p for p in func.get('params', []) if p.get('required', False)]
            self.entry_probes.append(self._generate_entry_probe(fname, params))
            self.return_probes.append(self._generate_return_probe(fname, params))
    
    def build_bpf_program(self):
        program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct urma_call_ctx_t {
    u32 func_id;
    u64 enter_time;
    u32 pid;
    u32 tid;
    u64 arg0;
    u64 arg1;
    u64 arg2;
    u64 arg3;
    u64 arg4;
    u64 arg5;
};

struct urma_event_t {
    u32 func_id;
    u64 timestamp;
    u64 duration_us;
    u32 pid;
    u32 tid;
    u64 arg0;
    u64 arg1;
    u64 arg2;
    u64 arg3;
    u64 arg4;
    u64 arg5;
    int return_val;
};

BPF_HASH(urma_active_calls, u64, struct urma_call_ctx_t);
BPF_PERF_OUTPUT(urma_events);
"""
        for e in self.entry_probes:
            program += e
        for r in self.return_probes:
            program += r
        return program


class URMALatencyCollector:
    def __init__(self, rules_file, output_dir, duration=60):
        self.rules_file = rules_file
        self.output_dir = output_dir
        self.duration = duration
        self.rules = None
        self.bpf = None
        self.running = True
        self.events = []
        self.stats = defaultdict(lambda: {'count': 0, 'total_us': 0, 'min_us': float('inf'), 'max_us': 0})
        
        os.makedirs(output_dir, exist_ok=True)
        self._load_rules()
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        print("\n\n接收到退出信号，正在停止采集...")
        self.running = False
    
    def _load_rules(self):
        try:
            with open(self.rules_file, 'r') as f:
                self.rules = json.load(f)
            print("成功加载规则文件: %s" % self.rules_file)
            print("包含 %d 个函数:" % len(self.rules.get('functions', [])))
            for func in self.rules.get('functions', []):
                params = [p['name'] for p in func.get('params', []) if p.get('required')]
                print("  - %s: %s" % (func['name'], ', '.join(params) if params else '无必选参数'))
        except Exception as e:
            print("加载规则文件失败: %s" % e)
            sys.exit(1)
    
    def _init_bpf(self):
        try:
            generator = DynamicProbeGenerator(self.rules)
            bpf_program = generator.build_bpf_program()
            self.bpf = BPF(text=bpf_program)
            
            lib_path = self._find_library()
            print("\n库路径: %s" % lib_path)
            
            for func in self.rules.get('functions', []):
                fname = func['name']
                try:
                    self.bpf.attach_uprobe(name=lib_path, sym=fname, fn_name="trace_%s_entry" % fname)
                    self.bpf.attach_uretprobe(name=lib_path, sym=fname, fn_name="trace_%s_return" % fname)
                    print("✓ 已附加探针: %s" % fname)
                except Exception as e:
                    print("✗ 附加探针 %s 失败: %s" % (fname, e))
            
            self.bpf["urma_events"].open_perf_buffer(self._process_event)
            
        except Exception as e:
            print("初始化BPF失败: %s" % e)
            import traceback
            traceback.print_exc()
            sys.exit(1)
    
    def _find_library(self):
        glibc_funcs = ['send', 'recv', 'connect', 'accept', 'close', 'socket']
        functions = [f.get('name', '') for f in self.rules.get('functions', [])]
        
        if any(fn in glibc_funcs for fn in functions):
            for path in ['/lib/x86_64-linux-gnu/libc.so.6', '/lib64/libc.so.6', 'libc.so.6']:
                if os.path.exists(path):
                    return path
            return 'libc.so.6'
        
        for path in ['/usr/lib/x86_64-linux-gnu/liburma.so', '/usr/lib64/liburma.so', 'liburma.so']:
            if os.path.exists(path) if not path.startswith('lib') else True:
                return path
        return 'liburma.so'
    
    def _process_event(self, cpu, data, size):
        try:
            event = self.bpf["urma_events"].event(data)
            func_id = event.func_id
            func_name = self.rules['functions'][func_id]['name'] if func_id < len(self.rules.get('functions', [])) else 'unknown'
            
            record = {
                'timestamp': event.timestamp,
                'func_name': func_name,
                'duration_us': event.duration_us,
                'pid': event.pid,
                'tid': event.tid,
                'args': [event.arg0, event.arg1, event.arg2, event.arg3, event.arg4, event.arg5],
                'return_val': event.return_val
            }
            self.events.append(record)
            
            stats = self.stats[func_name]
            stats['count'] += 1
            stats['total_us'] += event.duration_us
            stats['min_us'] = min(stats['min_us'], event.duration_us)
            stats['max_us'] = max(stats['max_us'], event.duration_us)
        except Exception as e:
            print("\n处理事件失败: %s" % e)
    
    def _print_stats(self):
        print("\n" + "="*70)
        print("函数时延统计")
        print("="*70)
        print("%-18s %8s %14s %10s %10s" % ('函数名', '调用次数', '平均时延(us)', '最小(us)', '最大(us)'))
        print("-"*70)
        for func_name, stats in sorted(self.stats.items()):
            if stats['count'] > 0:
                avg_us = stats['total_us'] / stats['count']
                min_us = stats['min_us'] if stats['min_us'] != float('inf') else 0
                print("%-18s %8d %14.2f %10d %10d" % (func_name, stats['count'], avg_us, min_us, stats['max_us']))
        print("="*70)
    
    def _save_results(self):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        raw_file = os.path.join(self.output_dir, 'urma_latency_%s.json' % timestamp)
        with open(raw_file, 'w') as f:
            json.dump({'rules_version': self.rules.get('version', 'unknown'), 'total_events': len(self.events), 'events': self.events}, f, indent=2)
        print("\n原始数据: %s" % raw_file)
        
        stats_file = os.path.join(self.output_dir, 'urma_stats_%s.json' % timestamp)
        stats_data = {'timestamp': timestamp, 'total_events': len(self.events), 'functions': {}}
        for func_name, stats in self.stats.items():
            if stats['count'] > 0:
                stats_data['functions'][func_name] = {
                    'count': stats['count'],
                    'avg_latency_us': stats['total_us'] / stats['count'],
                    'min_latency_us': stats['min_us'] if stats['min_us'] != float('inf') else 0,
                    'max_latency_us': stats['max_us']
                }
        with open(stats_file, 'w') as f:
            json.dump(stats_data, f, indent=2)
        print("统计数据: %s" % stats_file)
        
        stack_file = os.path.join(self.output_dir, 'urma_stacks_%s.txt' % timestamp)
        with open(stack_file, 'w') as f:
            for event in self.events:
                f.write("func %d %d %d\n" % (event['pid'], event['tid'], event['duration_us']))
        print("栈数据: %s" % stack_file)
        return stack_file
    
    def collect(self):
        print("="*70)
        print("URMA通信链路时延分析 - 动态eBPF采集器")
        print("="*70)
        print("规则文件: %s" % self.rules_file)
        print("输出目录: %s" % self.output_dir)
        print("采集时长: %d秒" % self.duration)
        print("-"*70)
        
        self._init_bpf()
        
        start_time = time.time()
        last_print = start_time
        
        print("\n开始采集... (按Ctrl+C停止)")
        print("-"*70)
        
        try:
            while self.running and (time.time() - start_time) < self.duration:
                self.bpf.perf_buffer_poll(timeout=100)
                current_time = time.time()
                if current_time - last_print >= 2.0:
                    elapsed = int(current_time - start_time)
                    total_events = len(self.events)
                    print("\r采集进度: %d/%d秒 | 事件数: %d" % (elapsed, self.duration, total_events), end='', flush=True)
                    last_print = current_time
        except Exception as e:
            print("\n采集过程出错: %s" % e)
        
        print("\n\n采集完成!")
        self._print_stats()
        return self._save_results()


def main():
    parser = argparse.ArgumentParser(description='URMA通信链路时延分析 - 动态eBPF采集器')
    parser.add_argument('-r', '--rules', default='/root/URMATEST/rules/urma_functions.json', help='函数规则JSON文件路径')
    parser.add_argument('-o', '--output', default='/root/URMATEST/output', help='输出目录路径')
    parser.add_argument('-d', '--duration', type=int, default=60, help='采集时长(秒)')
    args = parser.parse_args()
    
    if os.geteuid() != 0:
        print("错误: 此工具需要root权限运行")
        sys.exit(1)
    
    collector = URMALatencyCollector(rules_file=args.rules, output_dir=args.output, duration=args.duration)
    stack_file = collector.collect()
    print("\n\n火焰图生成:")
    print("  python3 /root/URMATEST/src/urma_flamegraph.py -i %s -o %s" % (stack_file, args.output))


if __name__ == '__main__':
    main()
