/*
 * TCP测试服务器 - 用于验证eBPF动态探针
 * 编译: gcc -o tcp_server tcp_server.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <signal.h>

#define PORT 9999
#define BUFFER_SIZE 4096

volatile int running = 1;

void signal_handler(int sig) {
    running = 0;
}

void handle_client(int client_fd, struct sockaddr_in *client_addr) {
    char buffer[BUFFER_SIZE];
    char response[BUFFER_SIZE];
    
    printf("[Server] Client connected: %s:%d\n", 
           inet_ntoa(client_addr->sin_addr), 
           ntohs(client_addr->sin_port));
    
    while (running) {
        // recv - 接收数据
        ssize_t n = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);
        if (n <= 0) {
            if (n < 0) {
                perror("[Server] recv error");
            }
            break;
        }
        
        buffer[n] = '\0';
        printf("[Server] Received %zd bytes: %.*s\n", n, (int)n > 64 ? 64 : (int)n, buffer);
        
        // 构造响应 - 模拟urma_send
        int resp_len = snprintf(response, BUFFER_SIZE, "ACK:%zd:%s", n, buffer);
        
        // send - 发送响应
        ssize_t sent = send(client_fd, response, resp_len, 0);
        if (sent < 0) {
            perror("[Server] send error");
            break;
        }
        printf("[Server] Sent %zd bytes response\n", sent);
    }
    
    // close - 关闭连接
    close(client_fd);
    printf("[Server] Client disconnected\n");
}

int main(int argc, char *argv[]) {
    int server_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    int opt = 1;
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // socket - 创建监听socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket error");
        exit(EXIT_FAILURE);
    }
    
    // setsockopt - 设置SO_REUSEADDR
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt SO_REUSEADDR");
        exit(EXIT_FAILURE);
    }
    
    // bind - 绑定地址
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);
    
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind error");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    
    // listen - 开始监听
    if (listen(server_fd, 10) < 0) {
        perror("listen error");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    
    printf("[Server] Listening on port %d (PID: %d)\n", PORT, getpid());
    printf("[Server] Attach eBPF probes to: send, recv, connect, accept, close\n");
    fflush(stdout);
    
    while (running) {
        // accept - 接受连接
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            if (running) {
                perror("accept error");
            }
            continue;
        }
        
        handle_client(client_fd, &client_addr);
    }
    
    // close - 关闭监听socket
    close(server_fd);
    printf("[Server] Shutdown complete\n");
    
    return 0;
}
