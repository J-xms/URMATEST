#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
URMA通信链路时延分析 - 火焰图生成器
支持动态规则采集的完整数据，包括函数时延和入参值
"""

import argparse
import json
import os
import sys
import subprocess
from collections import defaultdict
from datetime import datetime


class URNAFlameGraphGenerator:
    """URMA火焰图生成器"""
    
    COLORS = {
        'urma_write': '#FF6B6B',
        'urma_read': '#4ECDC4',
        'urma_send': '#45B7D1',
        'urma_recv': '#96CEB4',
        'urma_poll_jfc': '#FFEAA7',
        'default': '#DDA0DD'
    }
    
    def __init__(self, input_file, output_dir):
        self.input_file = input_file
        self.output_dir = output_dir
        self.events = []
        self.folded_stacks = defaultdict(int)
        
        os.makedirs(output_dir, exist_ok=True)
    
    def _get_color(self, func_name):
        return self.COLORS.get(func_name, self.COLORS['default'])
    
    def load_data(self):
        """加载采集数据"""
        try:
            with open(self.input_file, 'r') as f:
                data = json.load(f)
            
            if 'events' in data:
                self.events = data['events']
            else:
                self.events = data
            
            print(f"成功加载 {len(self.events)} 条事件记录")
            return True
            
        except json.JSONDecodeError:
            # 按行解析（兼容旧格式）
            try:
                with open(self.input_file, 'r') as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) >= 4:
                            self.events.append({
                                'func_name': parts[0],
                                'pid': int(parts[1]),
                                'tid': int(parts[2]),
                                'duration_us': int(parts[3])
                            })
                print(f"成功加载 {len(self.events)} 条事件记录(按行解析)")
                return True
            except Exception as e:
                print(f"加载数据文件失败: {e}")
                return False
        except Exception as e:
            print(f"加载数据文件失败: {e}")
            return False
    
    def _generate_folded_stacks(self):
        """生成折叠栈格式"""
        for event in self.events:
            func_name = event.get('func_name', 'unknown')
            pid = event.get('pid', 0)
            tid = event.get('tid', 0)
            duration = event.get('duration_us', 0)
            
            # 支持多级栈: func;caller;...
            stack = func_name
            key = f"{stack} {pid}-{tid}"
            self.folded_stacks[key] = duration
        
        return self.folded_stacks
    
    def _find_flamegraph(self):
        """查找FlameGraph脚本"""
        possible_paths = [
            '/usr/local/bin/flamegraph.pl',
            '/usr/bin/flamegraph.pl',
            './FlameGraph/flamegraph.pl',
            '../FlameGraph/flamegraph.pl',
        ]
        
        for path in possible_paths:
            if os.path.isfile(path):
                return path
        
        try:
            result = subprocess.run(['which', 'flamegraph.pl'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass
        
        return None
    
    def _generate_svg_flamegraph(self, folded_data, output_file):
        """使用FlameGraph生成SVG"""
        folded_file = output_file + '.folded'
        with open(folded_file, 'w') as f:
            for stack, count in folded_data.items():
                f.write(f"{stack} {count}\n")
        
        flamegraph_path = self._find_flamegraph()
        
        if flamegraph_path:
            try:
                cmd = [
                    'perl', flamegraph_path,
                    '--title', 'URMA Latency Flame Graph',
                    '--countname', 'us',
                    '--colors', 'hot',
                    '--width', '1200',
                    folded_file
                ]
                
                with open(output_file, 'w') as out:
                    result = subprocess.run(cmd, stdout=out, stderr=subprocess.PIPE)
                
                if result.returncode == 0:
                    print(f"SVG火焰图已生成: {output_file}")
                    return True
            except Exception as e:
                print(f"FlameGraph执行失败: {e}")
        
        return self._generate_html_flamegraph(folded_data, output_file)
    
    def _generate_html_flamegraph(self, folded_data, output_file):
        """生成HTML火焰图可视化"""
        
        # 按函数统计
        func_stats = defaultdict(lambda: {
            'count': 0, 
            'total_us': 0, 
            'max_us': 0,
            'size_dist': defaultdict(int)  # 数据长度分布
        })
        
        for event in self.events:
            func_name = event.get('func_name', 'unknown')
            duration = event.get('duration_us', 0)
            data_len = event.get('data_len', 0)
            
            func_stats[func_name]['count'] += 1
            func_stats[func_name]['total_us'] += duration
            func_stats[func_name]['max_us'] = max(func_stats[func_name]['max_us'], duration)
            
            # 数据长度分布
            bucket = self._get_size_bucket(data_len)
            func_stats[func_name]['size_dist'][bucket] += 1
        
        html_content = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>URMA Latency Flame Graph</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Arial, sans-serif; 
            background: #1a1a2e; 
            color: #eee;
            padding: 20px;
        }
        h1 { 
            text-align: center; 
            margin-bottom: 20px;
            color: #4ECDC4;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        .chart { 
            background: #16213e; 
            border-radius: 10px; 
            padding: 20px;
            margin-bottom: 20px;
        }
        .bar-container {
            display: flex;
            flex-direction: column;
            gap: 15px;
        }
        .bar-row {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        .func-name {
            width: 150px;
            font-weight: bold;
            text-align: right;
            color: #fff;
        }
        .bar-wrapper {
            flex: 1;
            background: #0f3460;
            border-radius: 5px;
            height: 40px;
            position: relative;
            overflow: hidden;
        }
        .bar {
            height: 100%;
            border-radius: 5px;
            display: flex;
            align-items: center;
            padding: 0 10px;
            color: #fff;
            font-size: 12px;
            min-width: 60px;
            transition: width 0.5s ease;
        }
        .bar-label {
            margin-left: 15px;
            color: #aaa;
            font-size: 12px;
            width: 200px;
        }
        .stats-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        .stats-table th, .stats-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #333;
        }
        .stats-table th {
            background: #0f3460;
            color: #4ECDC4;
        }
        .stats-table tr:hover { background: #1f4068; }
        .footer {
            text-align: center;
            margin-top: 20px;
            color: #666;
            font-size: 12px;
        }
        .legend {
            display: flex;
            justify-content: center;
            gap: 20px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        .legend-item {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .legend-color {
            width: 20px;
            height: 20px;
            border-radius: 3px;
        }
        .section { margin-bottom: 30px; }
        .section-title {
            color: #4ECDC4;
            font-size: 18px;
            margin-bottom: 15px;
            border-left: 4px solid #4ECDC4;
            padding-left: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔥 URMA 通信链路时延火焰图</h1>
        
        <div class="legend">
"""
        
        for func_name, color in self.COLORS.items():
            if func_name != 'default':
                html_content += f"""
            <div class="legend-item">
                <div class="legend-color" style="background: {color}"></div>
                <span>{func_name}</span>
            </div>
"""
        
        html_content += """
        </div>
        
        <div class="chart">
            <h2 class="section-title">📊 时延分布（按函数）</h2>
            <div class="bar-container">
"""
        
        max_avg = max(s['total_us'] / max(s['count'], 1) for s in func_stats.values()) if func_stats else 1
        
        for func_name in sorted(func_stats.keys(), 
                               key=lambda x: func_stats[x]['total_us'], 
                               reverse=True):
            stats = func_stats[func_name]
            color = self._get_color(func_name)
            avg_us = stats['total_us'] / max(stats['count'], 1)
            width_pct = min(100, (avg_us / max_avg) * 100)
            
            html_content += f"""
                <div class="bar-row">
                    <div class="func-name">{func_name}</div>
                    <div class="bar-wrapper">
                        <div class="bar" style="width: {width_pct}%; background: {color};">
                            {avg_us:.2f} us (avg)
                        </div>
                    </div>
                    <div class="bar-label">
                        调用: {stats['count']} | 最大: {stats['max_us']} us
                    </div>
                </div>
"""
        
        html_content += """
            </div>
        </div>
        
        <div class="chart">
            <h2 class="section-title">📈 详细统计</h2>
            <table class="stats-table">
                <thead>
                    <tr>
                        <th>函数名</th>
                        <th>调用次数</th>
                        <th>总时延 (us)</th>
                        <th>平均时延 (us)</th>
                        <th>最小时延 (us)</th>
                        <th>最大时延 (us)</th>
                    </tr>
                </thead>
                <tbody>
"""
        
        for func_name in sorted(func_stats.keys(), 
                               key=lambda x: func_stats[x]['total_us'], 
                               reverse=True):
            stats = func_stats[func_name]
            avg_us = stats['total_us'] / max(stats['count'], 1)
            color = self._get_color(func_name)
            
            html_content += f"""
                    <tr>
                        <td><span style="color: {color}; font-weight: bold;">{func_name}</span></td>
                        <td>{stats['count']}</td>
                        <td>{stats['total_us']:,.0f}</td>
                        <td>{avg_us:.2f}</td>
                        <td>-</td>
                        <td>{stats['max_us']}</td>
                    </tr>
"""
        
        html_content += """
                </tbody>
            </table>
        </div>
        
        <div class="chart">
            <h2 class="section-title">📦 数据长度分布</h2>
            <table class="stats-table">
                <thead>
                    <tr>
                        <th>函数名</th>
                        <th>&lt;64B</th>
                        <th>64-256B</th>
                        <th>256B-1KB</th>
                        <th>1-4KB</th>
                        <th>4-16KB</th>
                        <th>16-64KB</th>
                        <th>&gt;64KB</th>
                    </tr>
                </thead>
                <tbody>
"""
        
        buckets = ['<64B', '64-256B', '256B-1KB', '1-4KB', '4-16KB', '16-64KB', '>64KB']
        for func_name in sorted(func_stats.keys(), 
                               key=lambda x: func_stats[x]['count'],
                               reverse=True):
            stats = func_stats[func_name]
            color = self._get_color(func_name)
            
            html_content += f"""                    <tr>
                        <td><span style="color: {color}; font-weight: bold;">{func_name}</span></td>
"""
            for bucket in buckets:
                count = stats['size_dist'].get(bucket, 0)
                html_content += f"<td>{count}</td>"
            html_content += "</tr>\n"
        
        html_content += f"""
                </tbody>
            </table>
        </div>
        
        <div class="footer">
            <p>Generated by URMA Latency Analyzer</p>
            <p>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
    </div>
</body>
</html>
"""
        
        with open(output_file, 'w') as f:
            f.write(html_content)
        
        print(f"HTML火焰图已生成: {output_file}")
        return True
    
    def _get_size_bucket(self, size):
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
    
    def _generate_json_report(self, output_file):
        """生成JSON分析报告"""
        func_stats = defaultdict(lambda: {
            'count': 0, 
            'total_us': 0, 
            'max_us': 0, 
            'min_us': float('inf'),
            'size_dist': defaultdict(int)
        })
        
        for event in self.events:
            func_name = event.get('func_name', 'unknown')
            duration = event.get('duration_us', 0)
            data_len = event.get('data_len', 0)
            
            func_stats[func_name]['count'] += 1
            func_stats[func_name]['total_us'] += duration
            func_stats[func_name]['max_us'] = max(func_stats[func_name]['max_us'], duration)
            func_stats[func_name]['min_us'] = min(func_stats[func_name]['min_us'], duration)
            
            bucket = self._get_size_bucket(data_len)
            func_stats[func_name]['size_dist'][bucket] += 1
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_events': len(self.events),
            'functions': {}
        }
        
        for func_name, stats in func_stats.items():
            count = stats['count']
            if count > 0:
                report['functions'][func_name] = {
                    'count': count,
                    'avg_latency_us': stats['total_us'] / count,
                    'min_latency_us': stats['min_us'],
                    'max_latency_us': stats['max_us'],
                    'size_distribution': dict(stats['size_dist'])
                }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"JSON分析报告已生成: {output_file}")
        return report
    
    def generate(self):
        """生成火焰图"""
        if not self.load_data():
            return False
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        folded_data = self._generate_folded_stacks()
        
        # SVG火焰图
        svg_file = os.path.join(self.output_dir, f'urma_flamegraph_{timestamp}.svg')
        self._generate_svg_flamegraph(folded_data, svg_file)
        
        # HTML火焰图
        html_file = os.path.join(self.output_dir, f'urma_flamegraph_{timestamp}.html')
        self._generate_html_flamegraph(folded_data, html_file)
        
        # JSON报告
        json_file = os.path.join(self.output_dir, f'urma_analysis_{timestamp}.json')
        report = self._generate_json_report(json_file)
        
        # 打印摘要
        print("\n" + "="*60)
        print("URMA时延分析摘要")
        print("="*60)
        for func_name, stats in sorted(report['functions'].items(), 
                                       key=lambda x: x[1]['avg_latency_us'],
                                       reverse=True):
            print(f"\n{func_name}:")
            print(f"  调用次数: {stats['count']}")
            print(f"  平均时延: {stats['avg_latency_us']:.2f} us")
            print(f"  时延范围: {stats['min_latency_us']:.0f} - {stats['max_latency_us']:.0f} us")
            if stats['size_distribution']:
                print(f"  数据长度分布: {stats['size_distribution']}")
        
        print("\n" + "="*60)
        print("输出文件:")
        print(f"  SVG火焰图: {svg_file}")
        print(f"  HTML火焰图: {html_file}")
        print(f"  JSON报告: {json_file}")
        print("="*60)
        
        return True


def main():
    parser = argparse.ArgumentParser(
        description='URMA通信链路时延分析 - 火焰图生成器')
    
    parser.add_argument('-i', '--input', required=True,
                       help='采集数据文件(JSON或文本格式)')
    parser.add_argument('-o', '--output', 
                       default='/root/URMATEST/output',
                       help='输出目录')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.input):
        print(f"错误: 输入文件不存在: {args.input}")
        sys.exit(1)
    
    generator = URNAFlameGraphGenerator(
        input_file=args.input,
        output_dir=args.output
    )
    
    success = generator.generate()
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
