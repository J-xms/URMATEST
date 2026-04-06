/*
 * TCP测试客户端 - 用于验证eBPF动态探针
 * 编译: gcc -o tcp_client tcp_client.c
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
#include <time.h>

#define SERVER_IP "127.0.0.1"
#define PORT 9999
#define BUFFER_SIZE 4096

long long current_timestamp_us() {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (long long)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

int main(int argc, char *argv[]) {
    int sock_fd;
    struct sockaddr_in server_addr;
    char send_buffer[BUFFER_SIZE];
    char recv_buffer[BUFFER_SIZE];
    int data_size = 256;
    int num_requests = 20;
    int i;
    
    if (argc > 1) data_size = atoi(argv[1]);
    if (argc > 2) num_requests = atoi(argv[2]);
    
    // socket - 创建socket
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("socket error");
        exit(EXIT_FAILURE);
    }
    
    // 设置TCP_NODELAY
    int nodelay = 1;
    setsockopt(sock_fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
    
    // connect - 连接服务器
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        perror("inet_pton error");
        close(sock_fd);
        exit(EXIT_FAILURE);
    }
    
    if (connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect error");
        close(sock_fd);
        exit(EXIT_FAILURE);
    }
    
    printf("[Client] Connected to %s:%d (PID: %d)\n", SERVER_IP, PORT, getpid());
    printf("[Client] Data size: %d bytes, Requests: %d\n", data_size, num_requests);
    printf("[Client] Attach eBPF probes to: send, recv, connect, accept, close\n");
    fflush(stdout);
    
    long long total_start = current_timestamp_us();
    
    for (i = 0; i < num_requests; i++) {
        // 构造发送数据
        int len = snprintf(send_buffer, BUFFER_SIZE, "Request #%d: ", i);
        int data_len = data_size - len;
        memset(send_buffer + len, 'A' + (i % 26), data_len);
        send_buffer[data_size] = '\0';
        
        // send - 发送数据
        ssize_t sent = send(sock_fd, send_buffer, data_size, 0);
        if (sent < 0) {
            perror("send error");
            break;
        }
        
        // recv - 接收响应
        ssize_t n = recv(sock_fd, recv_buffer, BUFFER_SIZE - 1, 0);
        if (n <= 0) {
            if (n < 0) {
                perror("recv error");
            }
            break;
        }
        
        recv_buffer[n] = '\0';
        printf("[Client] Request %d/%d: sent %zd bytes, recv %zd bytes\n", 
               i + 1, num_requests, sent, n);
        
        usleep(50000);  // 50ms间隔
    }
    
    long long total_end = current_timestamp_us();
    double total_sec = (total_end - total_start) / 1000000.0;
    
    printf("\n[Client] Completed %d requests in %.2f seconds\n", i, total_sec);
    printf("[Client] Avg latency: %.2f ms per request\n", total_sec * 1000.0 / i);
    
    // close - 关闭socket
    close(sock_fd);
    printf("[Client] Disconnected\n");
    
    return 0;
}
