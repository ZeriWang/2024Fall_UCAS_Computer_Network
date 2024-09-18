#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include <pthread.h>
#include "openssl/ssl.h"
#include "openssl/bio.h"
#include "openssl/err.h"

void *handle_http_request(void *arg);
void *handle_https_request(void *arg);
void *HTTP_SERVER(void *arg);
void *HTTPS_SERVER(void *arg);

int main()
{   
    pthread_t thread1, thread2;

    if (pthread_create(&thread1, NULL, HTTP_SERVER, NULL) != 0)
    {
        perror("Thread creation failed");
        return -1;
    }
    
    if (pthread_create(&thread2, NULL, HTTPS_SERVER, NULL) != 0)
    {
        perror("Thread creation failed");
        return -1;
    }
    
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);

    return 0;
}

void *HTTP_SERVER(void *arg)
{   
    int port = 80; // 定义服务器监听的端口号为 80

    int sockfd;
    // 创建套接字，使用 IPv4 地址族(AF_INET)和面向连接的 TCP 协议(SOCK_STREAM)
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("Create socket failed"); // 创建套接字失败，输出错误信息
        exit(1); // 退出程序
    }

    struct sockaddr_in server;
    server.sin_family = AF_INET; // 设置地址族为 IPv4
    server.sin_addr.s_addr = INADDR_ANY; // 监听所有本地 IP 地址
    server.sin_port = htons(port); // 设置端口号，使用 htons 将主机字节序转换为网络字节序

    // 绑定套接字到指定的 IP 地址和端口号
    if (bind(sockfd, (struct sockaddr *)&server, sizeof(server)) < 0)
    {
        perror("bind failed"); // 绑定失败，输出错误信息
        exit(1); // 退出程序
    }

    listen(sockfd, 128); // 将套接字设置为监听模式，允许最多 128 个待处理连接

    while (1) // 无限循环，持续接受和处理客户端连接
    {
        struct sockaddr_in c_addr; // 定义客户端地址结构
        socklen_t addr_len; // 定义地址长度变量

        // 接受传入的连接请求
        int request = accept(sockfd, (struct sockaddr *)&c_addr, &addr_len);
        if (request < 0)
        {
            perror("Accept failed"); // 接受连接失败，输出错误信息
            exit(1); // 退出程序
        }

        pthread_t new_thread; // 定义新线程变量

        // 创建新线程处理客户端请求，线程函数为 handle_http_request，参数为请求套接字描述符
        if ((pthread_create(&new_thread, NULL, (void *)handle_http_request, (void *)&request)) != 0)
        {
            perror("Create handle_http_request thread failed"); // 创建线程失败，输出错误信息
            exit(1); // 退出程序
        }
    }

    close(sockfd); // 关闭套接字（这行代码在实际运行中不会被执行，因为 while(1) 是无限循环）
    return NULL; // 返回 NULL（这行代码在实际运行中不会被执行，因为 while(1) 是无限循环）
}


void *HTTPS_SERVER(void *arg)
{
    int port = 443; // 定义服务器监听的端口号为443

    // 初始化SSL库
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    // 创建SSL方法和上下文
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);

    // 加载证书和私钥
    if (SSL_CTX_use_certificate_file(ctx, "./keys/cnlab.cert", SSL_FILETYPE_PEM) <= 0)
    {
        perror("load cert failed"); // 加载证书失败
        exit(1);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "./keys/cnlab.prikey", SSL_FILETYPE_PEM) <= 0)
    {
        perror("load prikey failed"); // 加载私钥失败
        exit(1);
    }

    int sockfd;
    // 创建套接字
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("Create socket failed"); // 创建套接字失败
        exit(1);
    }

    struct sockaddr_in server;
    server.sin_family = AF_INET; // 使用IPv4地址
    server.sin_addr.s_addr = INADDR_ANY; // 绑定到所有可用的接口
    server.sin_port = htons(port); // 设置端口号

    // 绑定套接字到端口
    if (bind(sockfd, (struct sockaddr *)&server, sizeof(server)) < 0)
    {
        perror("bind failed"); // 绑定失败
        exit(1);
    }

    // 开始监听连接请求
    listen(sockfd, 10);
   
    while (1)
    {
        struct sockaddr_in c_addr;
        socklen_t addr_len;

        // 接受客户端连接请求
        int request = accept(sockfd, (struct sockaddr *)&c_addr, &addr_len);
        if (request < 0)
        {
            perror("Accept failed"); // 接受连接失败
            exit(1);
        }

        // 创建新的SSL对象并将其与请求的文件描述符关联
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, request);

        pthread_t new_thread;

        // 创建新线程处理HTTPS请求
        if ((pthread_create(&new_thread, NULL, (void *)handle_https_request, (void *)ssl)) != 0)
        {
            perror("Create handle_http_request thread failed"); // 创建线程失败
            exit(1);
        }
    }

    // 关闭套接字并释放SSL上下文
    close(sockfd);
    SSL_CTX_free(ctx);
    return NULL;
}


void *handle_http_request(void *arg)
{  
    // 将当前线程分离，使其在完成后自动回收资源
    pthread_detach(pthread_self());

    // 获取请求的文件描述符
    int request = *(int *)arg;

    // 分配接收缓冲区并初始化
    char *recv_buff = (char *)malloc(2000 * sizeof(char));
    memset(recv_buff, 0, 2000);

    // 分配发送缓冲区
    char *send_buff = (char *)malloc(6000 * sizeof(char));

    int request_len;
    // 从请求中读取数据到接收缓冲区
    request_len = recv(request, recv_buff, 2000, 0);
    if (request_len < 0)
    {
        fprintf(stderr, "recv failed\n"); // 读取失败
        exit(1);
    }

    // 检查是否为GET请求
    char *req_get = strstr(recv_buff, "GET");
    if (req_get)
    {
        char *iterator;
        iterator = req_get + 4; // 跳过 "GET "

        // 分配临时URL、HTTP版本和主机名缓冲区
        char *temp_url = (char *)malloc(50 * sizeof(char));
        char *http_version = (char *)malloc(9 * sizeof(char));
        char *host = (char *)malloc(100 * sizeof(char));
        int relative_url;

        // 检查URL是否为相对路径
        relative_url = ((*iterator) == '/');

        int i;
        // 提取URL
        for (i = 0; (*iterator) != ' '; iterator++, i++)
        {
            temp_url[i] = *iterator;
        }
        temp_url[i] = '\0';
        iterator++;
        
        // 提取HTTP版本
        for (i = 0; (*iterator) != '\r'; iterator++, i++)
        {
            http_version[i] = *iterator;
        }
        http_version[i] = '\0';
        
        // 如果是相对路径，提取主机名
        if (relative_url)
        {
            iterator = strstr(recv_buff, "Host:");
            if(!iterator){
                perror("Not found Host"); // 未找到Host头
                exit(1);
            }
            iterator += 6; // 跳过 "Host: "

            for (int i = 0; (*iterator) != '\r'; iterator++, i++)
            {
                host[i] = *iterator;
            }
            host[i] = '\0';
        }

        // 构建301重定向响应
        memset(send_buff, 0, 6000);
        strcat(send_buff, http_version);
        strcat(send_buff, " 301 Moved Permanently\r\nLocation: ");
        strcat(send_buff, "https://");

        if (relative_url)
        {
            strcat(send_buff, host);
            strcat(send_buff, temp_url);
        }
        else
        {
            strcat(send_buff, &temp_url[7]); // 跳过 "http://"
        }
        strcat(send_buff, "\r\n\r\n\r\n\r\n");

        // 发送重定向响应
        if ((send(request, send_buff, strlen(send_buff), 0)) < 0)
        {
            fprintf(stderr, "send failed"); // 发送失败
            exit(1);
        }

        // 释放临时缓冲区
        free(temp_url);
        free(http_version);
        free(host);
    }

    // 释放发送和接收缓冲区
    free(send_buff);
    free(recv_buff);

    // 关闭请求的文件描述符
    close(request);
    return NULL;
}


void *handle_https_request(void *arg)
{   
    // 将当前线程分离，使其在完成后自动回收资源
    pthread_detach(pthread_self());

    // 获取传入的 SSL 对象
    SSL *ssl = (SSL *)arg;

    // 进行 SSL 握手
    if (SSL_accept(ssl) == -1)
    {
        perror("SSL_accept failed"); // 握手失败
        exit(1);
    }

    // 分配接收和发送缓冲区
    char *recv_buff = (char *)malloc(2000 * sizeof(char));
    char *send_buff = (char *)malloc(6000 * sizeof(char));
    int keep_alive = 1; // 标记是否保持连接

    while (keep_alive)
    {
        // 清空接收缓冲区
        memset(recv_buff, 0, 2000);

        // 从 SSL 连接中读取数据
        int request_len = SSL_read(ssl, recv_buff, 2000);
        if (request_len < 0)
        {
            fprintf(stderr, "SSL_read failed\n"); // 读取失败
            exit(1);
        }

        // 如果接收缓冲区为空，退出循环
        if(recv_buff[0] == '\0')
        {
            break;
        }

        // 分配临时 URL、HTTP 版本和文件路径缓冲区
        char *temp_url = (char *)malloc(50 * sizeof(char));
        char *http_version = (char *)malloc(9 * sizeof(char));
        char *file_path = (char *)malloc(100 * sizeof(char));

        // 检查是否为 GET 请求
        char *req_get = strstr(recv_buff, "GET");
        if (req_get)
        {
            char *iterator;
            iterator = req_get + 4; // 跳过 "GET "

            int relative_url;
            int range = 0;
            int range_begin, range_end;

            // 检查 URL 是否为相对路径
            relative_url = (*(iterator) == '/');

            int i;
            // 提取 URL
            for (i = 0; *iterator != ' '; iterator++, i++)
            {
                temp_url[i] = *iterator;
            }
            temp_url[i] = '\0';
            iterator++;

            // 提取 HTTP 版本
            for (i = 0; *iterator != '\r'; iterator++, i++)
            {
                http_version[i] = *iterator;
            }
            http_version[i] = '\0';

            // 检查是否为范围请求
            if((iterator = strstr(recv_buff, "Range:")))
            {
                iterator += 13;
                range = 1;

                range_begin = 0;
                while(*iterator >= '0' && *iterator <= '9')
                {
                    range_begin = range_begin * 10 + (*iterator) - '0';
                    iterator++;
                }
                iterator++;

                if(*iterator < '0' || *iterator > '9')
                {
                    range_end = -1;
                }
                else
                {
                    range_end = 0;
                    while(*iterator >= '0' && *iterator <= '9')
                    {
                        range_end = range_end * 10 + (*iterator)-'0';
                        iterator++;
                    }
                }
            }

            // 检查连接类型
            if((iterator = strstr(recv_buff, "Connection:")))
            {
                iterator += 12;
                if(*iterator == 'k'){
                    keep_alive = 1; // 保持连接
                }
                else if(*iterator == 'c'){
                    keep_alive = 0; // 关闭连接
                }
            }

            // 构建文件路径
            file_path[0] = '.';
            file_path[1] = '\0';
            if(relative_url){
                strcat(file_path, temp_url);
            }
            else
            {
                i = 0;
                int count = 3;
                while(count){
                    if(temp_url[i] == '/'){
                        count--;
                    }
                    i++;
                }
                strcat(file_path, temp_url + i);
            }

            // 尝试打开文件
            FILE *fp = fopen(file_path, "r");
            if(fp == NULL)
            {   
                // 文件不存在，返回 404 响应
                memset(send_buff, 0, 6000);
                strcat(send_buff, http_version);
                strcat(send_buff, " 404 Not Found\r\n\r\n\r\n\r\n");
                SSL_write(ssl, send_buff, strlen(send_buff));
                
                break;
            }
            else
            {
                // 文件存在，构建响应头
                char header[200] = {0};
                strcat(header,http_version);

                if(range){
                    strcat(header, " 206 Partial Content\r\n");
                }
                else{
                    strcat(header, " 200 OK\r\n");
                }
                    
                int size,begin;
                if(range){
                    if(range_end==-1){
                        fseek(fp,0L,SEEK_END);
                        size = ftell(fp) - range_begin + 1;
                        begin = range_begin;
                    }
                    else{
                        size = range_end - range_begin + 1;
                        begin = range_begin;
                    }
                }
                else{
                    fseek(fp,0L,SEEK_END);
                    size = ftell(fp);
                    begin = 0;
                }

                // 设置内容长度
                strcat(header, "Content-Length: ");
                fseek(fp,begin,0);
            
                char str_size[64] = {0};    
                sprintf(str_size, "%d", size);

                char response[size + 200];
                memset(response,0, size + 200);
                strcat(response, header);
                strcat(response, str_size);

                strcat(response,"\r\nConnection: ");
                if(keep_alive)
                    strcat(response, "keep-alive");
                else
                    strcat(response, "close");

                strcat(response, "\r\n\r\n");
                fread(&(response[strlen(response)]), 1, size, fp);
                SSL_write(ssl,response,strlen(response));

                fclose(fp);

                if(range==1 && range_end==-1)
                    break;
            }
        }

        // 释放临时缓冲区
        free(temp_url);
        free(http_version);
        free(file_path);
        
    }

    // 释放发送和接收缓冲区
    free(send_buff);
    free(recv_buff);

    // 关闭 SSL 连接并释放 SSL 对象
    int requst = SSL_get_fd(ssl);
    SSL_free(ssl);
    close(requst);
    return NULL;
}