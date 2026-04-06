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
        self.includes = []
        self.global_vars = []
        self.entry_probes = []
        self.return_probes = []
        self.structs = []
        
        self._generate()
    
    def _generate(self):
        """生成完整的eBPF程序"""
        self._generate_structs()
        self._generate_global_vars()
        self._generate_probes()
    
    def _generate_structs(self):
        """生成数据结构"""
        # 活跃调用结构 - 存储entry时的上下文
        self.structs.append("""
// 活跃函数调用记录
struct urma_call_ctx_t {
    char func_name[64];
    uint64_t enter_time;
    uint32_t pid;
    uint32_t tid;
    uint64_t arg0;
    uint64_t arg1;
    uint64_t arg2;
    uint64_t arg3;
    uint64_t arg4;
    uint64_t arg5;
    uint64_t arg6;
    uint64_t arg7;
    uint32_t data_len;
};""")
        
        # 事件结构 - 输出到用户空间
        self.structs.append("""
struct urma_event_t {
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
    uint64_t arg6;
    uint64_t arg7;
    uint32_t data_len;
    int return_val;
};""")
    
    def _generate_global_vars(self):
        """生成全局变量"""
        self.global_vars.append("""
// 活跃调用存储 (key: pid_tgid -> ctx)
BPF_HASH(urma_active_calls, uint64_t, struct urma_call_ctx_t);

// 输出事件到用户空间
BPF_PERF_OUTPUT(urma_events);""")
    
    def _generate_probes(self):
        """为规则中每个函数生成entry和return探针"""
        for func in self.functions:
            fname = func['name']
            params = func.get('params', [])
            
            # 获取所有参数（仅收集required的入参）
            required_params = [p for p in params if p.get('required', False)]
            
            # 生成entry probe
            entry_code = self._generate_entry_probe(fname, required_params)
            self.entry_probes.append(entry_code)
            
            # 生成return probe
            return_code = self._generate_return_probe(fname, required_params)
            self.return_probes.append(return_code)
    
    def _get_param_accessor(self, param_index, param_type):
        """获取参数访问表达式"""
        # PT_REGS_PARM1 ~ PT_REGS_PARM8
        if param_type == 'pointer':
            return f"PT_REGS_PARM{param_index + 1}(ctx)"
        elif param_type == 'uint64':
            return f"(uint64_t)PT_REGS_PARM{param_index + 1}(ctx)"
        elif param_type == 'uint32':
            return f"(uint32_t)PT_REGS_PARM{param_index + 1}(ctx)"
        elif param_type == 'int':
            return f"(int)PT_REGS_PARM{param_index + 1}(ctx)"
        else:
            return f"PT_REGS_PARM{param_index + 1}(ctx)"
    
    def _generate_entry_probe(self, func_name, params):
        """生成entry探针代码"""
        # 参数数量
        num_params = len(params)
        
        # 生成参数读取代码
        arg_reads = []
        for i, p in enumerate(params):
            accessor = self._get_param_accessor(i, p.get('type', 'pointer'))
            arg_reads.append(f"    call->arg{i} = {accessor};")
        
        # 特殊处理数据长度参数
        len_param = None
        for p in params:
            if p.get('type') in ('uint32', 'int') and 'len' in p.get('name', '').lower():
                len_param = p
                break
        
        # 如果没有明确的长度参数，尝试从uint32类型参数中找
        if len_param is None:
            for p in params:
                if p.get('type') == 'uint32':
                    len_param = p
                    break
        
        len_read = ""
        if len_param:
            idx = params.index(len_param)
            len_read = f"\n    call->data_len = (uint32_t)PT_REGS_PARM{idx + 1}(ctx);"
        
        code = f"""
int trace_{func_name}_entry(struct pt_regs *ctx) {{
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    uint32_t pid = pid_tgid >> 32;
    uint32_t tid = pid_tgid & 0xFFFFFFFF;
    
    struct urma_call_ctx_t *call = bpf_ringbuf_reserve(&urma_events, sizeof(struct urma_call_ctx_t), 0);
    if (!call) {{
        return 0;
    }}
    
    bpf_probe_read(&call->func_name, sizeof(call->func_name), "{func_name}");
    call->enter_time = bpf_ktime_get_ns();
    call->pid = pid;
    call->tid = tid;
"""
        
        for i, p in enumerate(params):
            if i < 8:  # 最多8个参数
                accessor = self._get_param_accessor(i, p.get('type', 'pointer'))
                code += f"    call->arg{i} = {accessor};\n"
        
        if len_read:
            code += len_read
        
        code += """
    
    uint64_t key = pid_tgid;
    urma_active_calls.update(&key, call);
    bpf_ringbuf_submit(call, 0);
    return 0;
}}"""
        
        return code
    
    def _generate_return_probe(self, func_name, params):
        """生成return探针代码"""
        code = f"""
int trace_{func_name}_return(struct pt_regs *ctx) {{
    uint64_t pid_tgid = bpf_get_current_pid_tgid();
    uint32_t pid = pid_tgid >> 32;
    uint32_t tid = pid_tgid & 0xFFFFFFFF;
    
    uint64_t key = pid_tgid;
    struct urma_call_ctx_t *call = urma_active_calls.lookup(&key);
    if (call == NULL) {{
        return 0;
    }}
    
    uint64_t now = bpf_ktime_get_ns();
    uint64_t duration_ns = now - call->enter_time;
    
    struct urma_event_t *event = bpf_ringbuf_reserve(&urma_events, sizeof(struct urma_event_t), 0);
    if (!event) {{
        urma_active_calls.delete(&key);
        return 0;
    }}
    
    bpf_probe_read(&event->func_name, sizeof(event->func_name), call->func_name);
    event->timestamp = now;
    event->duration_us = duration_ns / 1000;
    event->pid = pid;
    event->tid = tid;
    event->arg0 = call->arg0;
    event->arg1 = call->arg1;
    event->arg2 = call->arg2;
    event->arg3 = call->arg3;
    event->arg4 = call->arg4;
    event->arg5 = call->arg5;
    event->arg6 = call->arg6;
    event->arg7 = call->arg7;
    event->data_len = call->data_len;
    event->return_val = (int)PT_REGS_RC(ctx);
    
    bpf_ringbuf_submit(event, 0);
    urma_active_calls.delete(&key);
    return 0;
}}"""
        
        return code
    
    def build_bpf_program(self):
        """构建完整的BPF程序"""
        program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

"""
        
        # 添加结构体定义
        for s in self.structs:
            program += s
        
        # 添加全局变量
        for g in self.global_vars:
            program += g
        
        # 添加entry探针
        for e in self.entry_probes:
            program += e
        
        # 添加return探针
        for r in self.return_probes:
            program += r
        
        return program


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
            'max_us': 0,
            'params': {}  # 入参统计
        })
        
        os.makedirs(output_dir, exist_ok=True)
        self._load_rules()
        
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        print("\n\n接收到退出信号，正在停止采集...")
        self.running = False
    
    def _load_rules(self):
        """加载函数规则"""
        try:
            with open(self.rules_file, 'r') as f:
                self.rules = json.load(f)
            print(f"成功加载规则文件: {self.rules_file}")
            print(f"包含 {len(self.rules.get('functions', []))} 个函数:")
            for func in self.rules.get('functions', []):
                params = [p['name'] for p in func.get('params', []) if p.get('required')]
                print(f"  - {func['name']}: {', '.join(params) if params else '无必选参数'}")
        except Exception as e:
            print(f"加载规则文件失败: {e}")
            sys.exit(1)
    
    def _init_bpf(self):
        """初始化BPF程序"""
        try:
            # 动态生成探针
            generator = DynamicProbeGenerator(self.rules)
            bpf_program = generator.build_bpf_program()
            
            # 调试用：打印生成的程序（注释掉以减少输出）
            # print("=== 生成的eBPF程序 ===")
            # print(bpf_program)
            # print("=" * 50)
            
            self.bpf = BPF(text=bpf_program)
            
            # 附加探针
            lib_path = self._find_urma_library()
            print(f"\nURMA库路径: {lib_path}")
            
            for func in self.rules.get('functions', []):
                fname = func['name']
                try:
                    self.bpf.attach_uprobe(
                        name=lib_path,
                        sym=fname,
                        fn_name=f"trace_{fname}_entry"
                    )
                    self.bpf.attach_uretprobe(
                        name=lib_path,
                        sym=fname,
                        fn_name=f"trace_{fname}_return"
                    )
                    print(f"✓ 已附加探针: {fname}")
                except Exception as e:
                    print(f"✗ 附加探针 {fname} 失败: {e}")
            
            # 设置事件回调 - 使用ringbuf
            self.bpf["urma_events"].open_perf_buffer(self._process_event, page_cnt=256)
            
        except Exception as e:
            print(f"初始化BPF失败: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)
    
    def _find_urma_library(self):
        """查找URMA库路径"""
        possible_paths = [
            '/usr/lib/x86_64-linux-gnu/liburma.so',
            '/usr/lib64/liburma.so',
            '/usr/local/lib/liburma.so',
            'liburma.so',
        ]
        
        for path in possible_paths:
            if os.path.exists(path) if not path.startswith('lib') else True:
                return path
        
        return 'liburma.so'
    
    def _process_event(self, cpu, data, size):
        """处理eBPF事件"""
        try:
            event = self.bpf["urma_events"].event(data)
            
            func_name = event.func_name.decode('utf-8', errors='replace').strip('\x00')
            
            # 获取入参值
            args = {
                'arg0': event.arg0,
                'arg1': event.arg1,
                'arg2': event.arg2,
                'arg3': event.arg3,
                'arg4': event.arg4,
                'arg5': event.arg5,
                'arg6': event.arg6,
                'arg7': event.arg7,
            }
            
            record = {
                'timestamp': event.timestamp,
                'func_name': func_name,
                'duration_us': event.duration_us,
                'pid': event.pid,
                'tid': event.tid,
                'args': args,
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
            
            # 入参统计（按长度分布）
            if event.data_len > 0:
                bucket = self._get_size_bucket(event.data_len)
                if bucket not in stats['params']:
                    stats['params'][bucket] = {'count': 0, 'total_us': 0}
                stats['params'][bucket]['count'] += 1
                stats['params'][bucket]['total_us'] += event.duration_us
            
        except Exception as e:
            print(f"\n处理事件失败: {e}")
    
    def _get_size_bucket(self, size):
        """获取数据大小桶"""
        if size < 64:
            return "<64B"
        elif size < 256:
            return "64-256B"
        elif size < 1024:
            return "256B-1KB"
        elif size < 4096:
            return "1-4KB"
        elif size < 16384:
            return "4-16KB"
        elif size < 65536:
            return "16-64KB"
        else:
            return ">64KB"
    
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
        
        # 入参分布
        print("\n按数据长度分布:")
        print("-"*60)
        for func_name, stats in sorted(self.stats.items()):
            if stats['count'] > 0 and stats['params']:
                print(f"\n  {func_name}:")
                for bucket in sorted(stats['params'].keys()):
                    p = stats['params'][bucket]
                    avg = p['total_us'] / p['count'] if p['count'] > 0 else 0
                    print(f"    {bucket:>10}: {p['count']:>6}次, 平均{avg:>8.2f}us")
    
    def _save_results(self):
        """保存采集结果"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # 保存原始数据
        raw_file = os.path.join(self.output_dir, f'urma_latency_{timestamp}.json')
        with open(raw_file, 'w') as f:
            json.dump({
                'rules_version': self.rules.get('version', 'unknown'),
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
                    'max_latency_us': stats['max_us'],
                    'size_distribution': stats['params']
                }
        
        with open(stats_file, 'w') as f:
            json.dump(stats_data, f, indent=2)
        print(f"统计数据已保存: {stats_file}")
        
        # 保存栈跟踪数据用于火焰图
        stack_file = os.path.join(self.output_dir, f'urma_stacks_{timestamp}.txt')
        with open(stack_file, 'w') as f:
            for event in self.events:
                f.write(f"{event['func_name']} {event['pid']} {event['tid']} {event['duration_us']}\n")
        print(f"栈数据已保存: {stack_file}")
        
        return stack_file
    
    def collect(self):
        """执行采集"""
        print("="*80)
        print("URMA通信链路时延分析 - 动态eBPF采集器")
        print("="*80)
        print(f"规则文件: {self.rules_file}")
        print(f"输出目录: {self.output_dir}")
        print(f"采集时长: {self.duration}秒")
        print("-"*80)
        
        # 初始化BPF
        self._init_bpf()
        
        start_time = time.time()
        last_print = start_time
        
        print("\n开始采集... (按Ctrl+C停止)")
        print("-"*80)
        
        try:
            while self.running and (time.time() - start_time) < self.duration:
                self.bpf.perf_buffer_poll(timeout=100)
                
                current_time = time.time()
                if current_time - last_print >= 2.0:
                    elapsed = int(current_time - start_time)
                    total_events = len(self.events)
                    print(f"\r采集进度: {elapsed}/{self.duration}秒 | 事件数: {total_events}", end='', flush=True)
                    last_print = current_time
        
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
        description='URMA通信链路时延分析 - 动态eBPF采集器',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
根据urma_functions.json规则动态生成eBPF探针，采集函数时延和入参值。

示例:
  sudo python3 urma_latency_collector.py -r rules/urma_functions.json -o output -d 60

注意:
  此工具需要root权限运行。
        """
    )
    
    parser.add_argument('-r', '--rules', 
                       default='/root/URMATEST/rules/urma_functions.json',
                       help='函数规则JSON文件路径')
    parser.add_argument('-o', '--output', 
                       default='/root/URMATEST/output',
                       help='输出目录路径')
    parser.add_argument('-d', '--duration', type=int, default=60,
                       help='采集时长(秒)')
    
    args = parser.parse_args()
    
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
