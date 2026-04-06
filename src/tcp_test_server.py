#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TCP测试程序 - 用于验证eBPF动态探针功能
通过包装TCP函数并添加标记来模拟URMA函数探针
"""

import socket
import threading
import time
import sys
import os
import ctypes
from ctypes import *

# 全局探针记录（用于验证）
probe_calls = []

# 模拟URMA风格的TCP包装函数
def __tcp_send(sock, buf, len, flags=0):
    """TCP发送包装"""
    probe_calls.append(('__tcp_send', len))
    return sock.send(buf, flags)

def __tcp_recv(sock, buf, len, flags=0):
    """TCP接收包装"""
    probe_calls.append(('__tcp_recv', len))
    return sock.recv(len, flags)

def __tcp_connect(sock, addr, addrlen):
    """TCP连接包装"""
    probe_calls.append(('__tcp_connect', 0))
    return sock.connect(addr)

def __tcp_accept(sock, addr, addrlen):
    """TCP接受连接包装"""
    probe_calls.append(('__tcp_accept', 0))
    return sock.accept()

def __tcp_close(sock):
    """TCP关闭包装"""
    probe_calls.append(('__tcp_close', 0))
    return sock.close()


def handle_client(client_sock, client_addr):
    """处理客户端连接"""
    print(f"[Server] Client connected: {client_addr}")
    
    try:
        while True:
            # 模拟 urma_recv
            data = __tcp_recv(client_sock, None, 4096)
            if not data:
                break
            
            print(f"[Server] Received {len(data)} bytes")
            
            # 模拟 urma_send - 回复数据
            response = b"ACK:" + data
            __tcp_send(client_sock, response, len(response))
            
    except Exception as e:
        print(f"[Server] Error: {e}")
    finally:
        __tcp_close(client_sock)
        print(f"[Server] Client disconnected: {client_addr}")


def run_server(port=9999):
    """运行TCP服务器"""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(('0.0.0.0', port))
    server_sock.listen(5)
    print(f"[Server] Listening on port {port}")
    
    try:
        while True:
            client_sock, client_addr = __tcp_accept(server_sock, None, None)
            thread = threading.Thread(target=handle_client, args=(client_sock, client_addr))
            thread.daemon = True
            thread.start()
    except KeyboardInterrupt:
        print("\n[Server] Shutting down...")
    finally:
        __tcp_close(server_sock)


def run_client(port=9999, data_size=1024, num_requests=10):
    """运行TCP客户端"""
    time.sleep(0.5)  # 等待服务器启动
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        __tcp_connect(sock, ('127.0.0.1', port), 16)
        print(f"[Client] Connected to server")
        
        for i in range(num_requests):
            # 模拟 urma_send - 发送数据
            data = b'X' * data_size
            __tcp_send(sock, data, len(data))
            
            # 模拟 urma_recv - 接收响应
            response = __tcp_recv(sock, None, 4096)
            print(f"[Client] Request {i+1}/{num_requests}: sent {data_size}B, received {len(response)}B")
            
            time.sleep(0.1)
        
        print(f"[Client] Completed {num_requests} requests")
        
    except Exception as e:
        print(f"[Client] Error: {e}")
    finally:
        __tcp_close(sock)


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='TCP Test for eBPF Probe')
    parser.add_argument('--mode', choices=['server', 'client', 'both'], default='both',
                       help='Run mode')
    parser.add_argument('--port', type=int, default=9999, help='Port number')
    parser.add_argument('--size', type=int, default=1024, help='Data size per request')
    parser.add_argument('--count', type=int, default=10, help='Number of requests')
    
    args = parser.parse_args()
    
    if args.mode in ['server', 'both']:
        server_thread = threading.Thread(target=run_server, args=(args.port,))
        server_thread.daemon = True
        server_thread.start()
    
    if args.mode in ['client', 'both']:
        run_client(args.port, args.size, args.count)
    
    if args.mode == 'both':
        time.sleep(2)
    
    print(f"\nTotal probe calls recorded: {len(probe_calls)}")
    for func, size in probe_calls[:10]:
        print(f"  {func}: {size} bytes")
