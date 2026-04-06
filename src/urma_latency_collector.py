#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
URMA通信链路时延分析工具 - eBPF数据采集器
基于python3-bpfcc开发，采集URMA关键函数的时延和入参信息
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
from bcc.utils import printb

# eBPF程序代码 - USDT探针模式
URMA_EBPF_PROGRAM = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

// URMA函数时延记录结构
struct urma_latency_key_t {
    char func_name[64];
    uint64_t timestamp;
    uint64_t duration_us;
    uint32_t pid;
    uint32_t tid;
    uint64_t arg0;
    uint64_t arg1;
    uint64_t arg2;
    uint64_t arg3;
    uint64_t arg4;
    uint64_t arg5;
    uint32_t data_len;
    int return_val;
};

// 函数调用记录
struct urma_func_call_t {
    char func_name[64];
    uint64_t enter_time;
    uint32_t pid;
    uint32_t tid;
    uint64_t args[6];
    uint32_t data_len;
};

// 存储活跃的函数调用
BPF_HASH(urma_active_calls, uint64_t, struct urma_func_call_t);

// 输出到用户空间的事件
BPF_PERF_OUTPUT(urma_events);

// urma_write探针
int trace_urma_write_entry(struct pt_regs *ctx) {
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    uint32_t pid = pid_tgid >> 32;
    uint32_t tid = pid_tgid & 0xFFFFFFFF;
    
    struct urma_func_call_t call = {};
    bpf_probe_read_user(&call.func_name, sizeof(call.func_name), "urma_write");
    call.enter_time = bpf_ktime_get_ns();
    call.pid = pid;
    call.tid = tid;
    call.args[0] = PT_REGS_PARM1(ctx);  // jfs
    call.args[1] = PT_REGS_PARM2(ctx);  // target_jfr
    call.args[2] = PT_REGS_PARM3(ctx);  // dst_tseg
    call.args[3] = PT_REGS_PARM4(ctx);  // dst
    call.args[4] = PT_REGS_PARM5(ctx);  // src
    call.args[5] = PT_REGS_PARM6(ctx);  // len
    
    // 获取数据长度参数 (第6个参数)
    uint32_t len = (uint32_t)PT_REGS_PARM6(ctx);
    call.data_len = len;
    
    uint64_t key = pid_tgid;
    urma_active_calls.update(&key, &call);
    return 0;
}

int trace_urma_write_return(struct pt_regs *ctx) {
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    uint32_t pid = pid_tgid >> 32;
    uint32_t tid = pid_tgid & 0xFFFFFFFF;
    
    uint64_t key = pid_tgid;
    struct urma_func_call_t *call = urma_active_calls.lookup(&key);
    if (call == NULL) {
        return 0;
    }
    
    uint64_t now = bpf_ktime_get_ns();
    uint64_t duration_ns = now - call->enter_time;
    
    struct urma_latency_key_t event = {};
    bpf_probe_read_user_str(&event.func_name, sizeof(event.func_name), call->func_name);
    event.timestamp = now;
    event.duration_us = duration_ns / 1000;
    event.pid = pid;
    event.tid = tid;
    event.arg0 = call->args[0];
    event.arg1 = call->args[1];
    event.arg2 = call->args[2];
    event.arg3 = call->args[3];
    event.arg4 = call->args[4];
    event.arg5 = call->args[5];
    event.data_len = call->data_len;
    event.return_val = (int)PT_REGS_RC(ctx);
    
    urma_events.perf_submit(ctx, &event, sizeof(event));
    urma_active_calls.delete(&key);
    return 0;
}

// urma_read探针
int trace_urma_read_entry(struct pt_regs *ctx) {
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    uint32_t pid = pid_tgid >> 32;
    uint32_t tid = pid_tgid & 0xFFFFFFFF;
    
    struct urma_func_call_t call = {};
    bpf_probe_read_user(&call.func_name, sizeof(call.func_name), "urma_read");
    call.enter_time = bpf_ktime_get_ns();
    call.pid = pid;
    call.tid = tid;
    call.args[0] = PT_REGS_PARM1(ctx);
    call.args[1] = PT_REGS_PARM2(ctx);
    call.args[2] = PT_REGS_PARM3(ctx);
    call.args[3] = PT_REGS_PARM4(ctx);
    call.args[4] = PT_REGS_PARM5(ctx);
    call.args[5] = PT_REGS_PARM6(ctx);
    
    uint32_t len = (uint32_t)PT_REGS_PARM6(ctx);
    call.data_len = len;
    
    uint64_t key = pid_tgid;
    urma_active_calls.update(&key, &call);
    return 0;
}

int trace_urma_read_return(struct pt_regs *ctx) {
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    uint32_t pid = pid_tgid >> 32;
    uint32_t tid = pid_tgid & 0xFFFFFFFF;
    
    uint64_t key = pid_tgid;
    struct urma_func_call_t *call = urma_active_calls.lookup(&key);
    if (call == NULL) {
        return 0;
    }
    
    uint64_t now = bpf_ktime_get_ns();
    uint64_t duration_ns = now - call->enter_time;
    
    struct urma_latency_key_t event = {};
    bpf_probe_read_user_str(&event.func_name, sizeof(event.func_name), call->func_name);
    event.timestamp = now;
    event.duration_us = duration_ns / 1000;
    event.pid = pid;
    event.tid = tid;
    event.arg0 = call->args[0];
    event.arg1 = call->args[1];
    event.arg2 = call->args[2];
    event.arg3 = call->args[3];
    event.arg4 = call->args[4];
    event.arg5 = call->args[5];
    event.data_len = call->data_len;
    event.return_val = (int)PT_REGS_RC(ctx);
    
    urma_events.perf_submit(ctx, &event, sizeof(event));
    urma_active_calls.delete(&key);
    return 0;
}

// urma_send探针
int trace_urma_send_entry(struct pt_regs *ctx) {
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    uint32_t pid = pid_tgid >> 32;
    uint32_t tid = pid_tgid & 0xFFFFFFFF;
    
    struct urma_func_call_t call = {};
    bpf_probe_read_user(&call.func_name, sizeof(call.func_name), "urma_send");
    call.enter_time = bpf_ktime_get_ns();
    call.pid = pid;
    call.tid = tid;
    call.args[0] = PT_REGS_PARM1(ctx);
    call.args[1] = PT_REGS_PARM2(ctx);
    call.args[2] = PT_REGS_PARM3(ctx);
    call.args[3] = PT_REGS_PARM4(ctx);
    call.args[4] = PT_REGS_PARM5(ctx);
    
    uint32_t len = (uint32_t)PT_REGS_PARM5(ctx);
    call.data_len = len;
    
    uint64_t key = pid_tgid;
    urma_active_calls.update(&key, &call);
    return 0;
}

int trace_urma_send_return(struct pt_regs *ctx) {
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    uint32_t pid = pid_tgid >> 32;
    uint32_t tid = pid_tgid & 0xFFFFFFFF;
    
    uint64_t key = pid_tgid;
    struct urma_func_call_t *call = urma_active_calls.lookup(&key);
    if (call == NULL) {
        return 0;
    }
    
    uint64_t now = bpf_ktime_get_ns();
    uint64_t duration_ns = now - call->enter_time;
    
    struct urma_latency_key_t event = {};
    bpf_probe_read_user_str(&event.func_name, sizeof(event.func_name), call->func_name);
    event.timestamp = now;
    event.duration_us = duration_ns / 1000;
    event.pid = pid;
    event.tid = tid;
    event.arg0 = call->args[0];
    event.arg1 = call->args[1];
    event.arg2 = call->args[2];
    event.arg3 = call->args[3];
    event.arg4 = call->args[4];
    event.arg5 = call->args[5];
    event.data_len = call->data_len;
    event.return_val = (int)PT_REGS_RC(ctx);
    
    urma_events.perf_submit(ctx, &event, sizeof(event));
    urma_active_calls.delete(&key);
    return 0;
}

// urma_recv探针
int trace_urma_recv_entry(struct pt_regs *ctx) {
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    uint32_t pid = pid_tgid >> 32;
    uint32_t tid = pid_tgid & 0xFFFFFFFF;
    
    struct urma_func_call_t call = {};
    bpf_probe_read_user(&call.func_name, sizeof(call.func_name), "urma_recv");
    call.enter_time = bpf_ktime_get_ns();
    call.pid = pid;
    call.tid = tid;
    call.args[0] = PT_REGS_PARM1(ctx);
    call.args[1] = PT_REGS_PARM2(ctx);
    call.args[2] = PT_REGS_PARM3(ctx);
    call.args[3] = PT_REGS_PARM4(ctx);
    
    uint32_t len = (uint32_t)PT_REGS_PARM4(ctx);
    call.data_len = len;
    
    uint64_t key = pid_tgid;
    urma_active_calls.update(&key, &call);
    return 0;
}

int trace_urma_recv_return(struct pt_regs *ctx) {
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    uint32_t pid = pid_tgid >> 32;
    uint32_t tid = pid_tgid & 0xFFFFFFFF;
    
    uint64_t key = pid_tgid;
    struct urma_func_call_t *call = urma_active_calls.lookup(&key);
    if (call == NULL) {
        return 0;
    }
    
    uint64_t now = bpf_ktime_get_ns();
    uint64_t duration_ns = now - call->enter_time;
    
    struct urma_latency_key_t event = {};
    bpf_probe_read_user_str(&event.func_name, sizeof(event.func_name), call->func_name);
    event.timestamp = now;
    event.duration_us = duration_ns / 1000;
    event.pid = pid;
    event.tid = tid;
    event.arg0 = call->args[0];
    event.arg1 = call->args[1];
    event.arg2 = call->args[2];
    event.arg3 = call->args[3];
    event.arg4 = call->args[4];
    event.arg5 = call->args[5];
    event.data_len = call->data_len;
    event.return_val = (int)PT_REGS_RC(ctx);
    
    urma_events.perf_submit(ctx, &event, sizeof(event));
    urma_active_calls.delete(&key);
    return 0;
}

// urma_poll_jfc探针
int trace_urma_poll_jfc_entry(struct pt_regs *ctx) {
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    uint32_t pid = pid_tgid >> 32;
    uint32_t tid = pid_tgid & 0xFFFFFFFF;
    
    struct urma_func_call_t call = {};
    bpf_probe_read_user(&call.func_name, sizeof(call.func_name), "urma_poll_jfc");
    call.enter_time = bpf_ktime_get_ns();
    call.pid = pid;
    call.tid = tid;
    call.args[0] = PT_REGS_PARM1(ctx);
    call.args[1] = PT_REGS_PARM2(ctx);
    call.args[2] = PT_REGS_PARM3(ctx);
    
    uint64_t key = pid_tgid;
    urma_active_calls.update(&key, &call);
    return 0;
}

int trace_urma_poll_jfc_return(struct pt_regs *ctx) {
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    uint32_t pid = pid_tgid >> 32;
    uint32_t tid = pid_tgid & 0xFFFFFFFF;
    
    uint64_t key = pid_tgid;
    struct urma_func_call_t *call = urma_active_calls.lookup(&key);
    if (call == NULL) {
        return 0;
    }
    
    uint64_t now = bpf_ktime_get_ns();
    uint64_t duration_ns = now - call->enter_time;
    
    struct urma_latency_key_t event = {};
    bpf_probe_read_user_str(&event.func_name, sizeof(event.func_name), call->func_name);
    event.timestamp = now;
    event.duration_us = duration_ns / 1000;
    event.pid = pid;
    event.tid = tid;
    event.arg0 = call->args[0];
    event.arg1 = call->args[1];
    event.arg2 = call->args[2];
    event.return_val = (int)PT_REGS_RC(ctx);
    
    urma_events.perf_submit(ctx, &event, sizeof(event));
    urma_active_calls.delete(&key);
    return 0;
}
"""


class URMALatencyCollector:
    """URMA时延采集器"""
    
    def __init__(self, rules_file, output_dir, duration=60):
        self.rules_file = rules_file
        self.output_dir = output_dir
        self.duration = duration
        self.rules = None
        self.bpf = None
        self.running = True
        self.events = []
        
        # 统计数据
        self.stats = defaultdict(lambda: {
            'count': 0,
            'total_us': 0,
            'min_us': float('inf'),
            'max_us': 0
        })
        
        # 确保输出目录存在
        os.makedirs(output_dir, exist_ok=True)
        
        # 加载规则
        self._load_rules()
        
        # 注册信号处理器
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """处理退出信号"""
        print("\n\n接收到退出信号，正在停止采集...")
        self.running = False
    
    def _load_rules(self):
        """加载函数规则"""
        try:
            with open(self.rules_file, 'r') as f:
                self.rules = json.load(f)
            print(f"成功加载规则文件: {self.rules_file}")
            print(f"包含 {len(self.rules.get('functions', []))} 个函数")
        except Exception as e:
            print(f"加载规则文件失败: {e}")
            sys.exit(1)
    
    def _init_bpf(self):
        """初始化BPF程序"""
        try:
            self.bpf = BPF(text=URMA_EBPF_PROGRAM)
            
            # 附加探针到URMA函数
            functions = [
                ('urma_write', 'trace_urma_write_entry', 'trace_urma_write_return'),
                ('urma_read', 'trace_urma_read_entry', 'trace_urma_read_return'),
                ('urma_send', 'trace_urma_send_entry', 'trace_urma_send_return'),
                ('urma_recv', 'trace_urma_recv_entry', 'trace_urma_recv_return'),
                ('urma_poll_jfc', 'trace_urma_poll_jfc_entry', 'trace_urma_poll_jfc_return'),
            ]
            
            for func_name, entry_name, return_name in functions:
                try:
                    self.bpf.attach_uprobe(
                        name=self._find_urma_library(),
                        sym=func_name,
                        fn_name=entry_name
                    )
                    self.bpf.attach_uretprobe(
                        name=self._find_urma_library(),
                        sym=func_name,
                        fn_name=return_name
                    )
                    print(f"已附加探针: {func_name}")
                except Exception as e:
                    print(f"附加探针 {func_name} 失败: {e}")
            
            # 设置事件回调
            self.bpf["urma_events"].open_perf_buffer(self._process_event)
            
        except Exception as e:
            print(f"初始化BPF失败: {e}")
            print("提示: 确保已安装bpfcc-tools并具有root权限")
            sys.exit(1)
    
    def _find_urma_library(self):
        """查找URMA库路径"""
        # 常见的URMA库路径
        possible_paths = [
            '/usr/lib/x86_64-linux-gnu/liburma.so',
            '/usr/lib64/liburma.so',
            '/usr/local/lib/liburma.so',
            'liburma.so',  # 让bcc在系统库路径中搜索
        ]
        
        for path in possible_paths:
            if os.path.exists(path) if not path.startswith('lib') else True:
                return path
        
        # 返回默认库名，让系统搜索
        return 'liburma.so'
    
    def _process_event(self, cpu, data, size):
        """处理eBPF事件"""
        try:
            event = self.bpf["urma_events"].event(data)
            
            func_name = event.func_name.decode('utf-8', errors='replace').strip('\x00')
            
            record = {
                'timestamp': event.timestamp,
                'func_name': func_name,
                'duration_us': event.duration_us,
                'pid': event.pid,
                'tid': event.tid,
                'args': [event.arg0, event.arg1, event.arg2, event.arg3, event.arg4, event.arg5],
                'data_len': event.data_len,
                'return_val': event.return_val
            }
            
            self.events.append(record)
            
            # 更新统计
            stats = self.stats[func_name]
            stats['count'] += 1
            stats['total_us'] += event.duration_us
            stats['min_us'] = min(stats['min_us'], event.duration_us)
            stats['max_us'] = max(stats['max_us'], event.duration_us)
            
        except Exception as e:
            print(f"处理事件失败: {e}")
    
    def _print_stats(self):
        """打印统计信息"""
        print("\n" + "="*80)
        print("URMA函数时延统计")
        print("="*80)
        print(f"{'函数名':<20} {'调用次数':>10} {'平均时延(us)':>15} {'最小(us)':>12} {'最大(us)':>12}")
        print("-"*80)
        
        for func_name, stats in sorted(self.stats.items()):
            if stats['count'] > 0:
                avg_us = stats['total_us'] / stats['count']
                min_us = stats['min_us'] if stats['min_us'] != float('inf') else 0
                print(f"{func_name:<20} {stats['count']:>10} {avg_us:>15.2f} {min_us:>12} {stats['max_us']:>12}")
        
        print("="*80)
    
    def _save_results(self):
        """保存采集结果"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # 保存原始数据
        raw_file = os.path.join(self.output_dir, f'urma_latency_{timestamp}.json')
        with open(raw_file, 'w') as f:
            json.dump({
                'start_time': self.events[0]['timestamp'] if self.events else 0,
                'end_time': self.events[-1]['timestamp'] if self.events else 0,
                'total_events': len(self.events),
                'events': self.events
            }, f, indent=2)
        print(f"\n原始数据已保存: {raw_file}")
        
        # 保存统计数据
        stats_file = os.path.join(self.output_dir, f'urma_stats_{timestamp}.json')
        stats_data = {
            'timestamp': timestamp,
            'total_events': len(self.events),
            'functions': {}
        }
        
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
        print(f"统计数据已保存: {stats_file}")
        
        # 保存栈跟踪数据用于火焰图
        stack_file = os.path.join(self.output_dir, f'urma_stacks_{timestamp}.txt')
        with open(stack_file, 'w') as f:
            for event in self.events:
                # 格式: func_name pid tid duration_us
                f.write(f"{event['func_name']} {event['pid']} {event['tid']} {event['duration_us']}\n")
        print(f"栈数据已保存: {stack_file}")
        
        return stack_file
    
    def collect(self):
        """执行采集"""
        print("="*80)
        print("URMA通信链路时延分析 - eBPF采集器")
        print("="*80)
        print(f"规则文件: {self.rules_file}")
        print(f"输出目录: {self.output_dir}")
        print(f"采集时长: {self.duration}秒")
        print(f"等待URMA库加载并开始采集... (按Ctrl+C停止)")
        print("-"*80)
        
        # 初始化BPF
        self._init_bpf()
        
        start_time = time.time()
        last_print = start_time
        
        try:
            while self.running and (time.time() - start_time) < self.duration:
                self.bpf.perf_buffer_poll(timeout=100)
                
                # 每秒打印一次进度
                current_time = time.time()
                if current_time - last_print >= 1.0:
                    elapsed = int(current_time - start_time)
                    total_events = len(self.events)
                    print(f"\r采集进度: {elapsed}/{self.duration}秒 | 事件数: {total_events}", end='', flush=True)
                    last_print = current_time
                    
                    # 打印当前统计
                    if total_events > 0:
                        print("\n当前统计:")
                        for func_name, stats in sorted(self.stats.items())[:5]:
                            if stats['count'] > 0:
                                avg_us = stats['total_us'] / stats['count']
                                print(f"  {func_name}: {stats['count']}次, 平均{avg_us:.2f}us")
                        print("-" * 60, end='')
        
        except Exception as e:
            print(f"\n采集过程出错: {e}")
        
        print("\n\n采集完成!")
        
        # 打印最终统计
        self._print_stats()
        
        # 保存结果
        stack_file = self._save_results()
        
        return stack_file


def main():
    parser = argparse.ArgumentParser(
        description='URMA通信链路时延分析工具 - eBPF采集器',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  sudo %(prog)s -r rules/urma_functions.json -o output -d 60
  sudo %(prog)s --rules rules/urma_functions.json --output output --duration 30

注意:
  此工具需要root权限运行，因为eBPF探针需要特权访问。
        """
    )
    
    parser.add_argument('-r', '--rules', 
                       default='/root/URMATEST/rules/urma_functions.json',
                       help='函数规则JSON文件路径 (默认: /root/URMATEST/rules/urma_functions.json)')
    parser.add_argument('-o', '--output', 
                       default='/root/URMATEST/output',
                       help='输出目录路径 (默认: /root/URMATEST/output)')
    parser.add_argument('-d', '--duration', type=int, default=60,
                       help='采集时长(秒) (默认: 60)')
    
    args = parser.parse_args()
    
    # 检查权限
    if os.geteuid() != 0:
        print("错误: 此工具需要root权限运行")
        print("请使用: sudo python3", ' '.join(sys.argv))
        sys.exit(1)
    
    collector = URMALatencyCollector(
        rules_file=args.rules,
        output_dir=args.output,
        duration=args.duration
    )
    
    stack_file = collector.collect()
    
    print(f"\n\n下一步: 使用以下命令生成火焰图:")
    print(f"  python3 /root/URMATEST/src/urma_flamegraph.py -i {stack_file} -o /root/URMATEST/output")


if __name__ == '__main__':
    main()
