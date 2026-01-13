#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <sstream>
#include "../core/Config.hpp"
#include "../core/Logger.hpp"
#include "SocketIo.hpp"

namespace Network {
    
    /**
     * HTTP CONNECT 隧道客户端
     * 
     * HTTP CONNECT 协议流程：
     * 1. 客户端发送: CONNECT host:port HTTP/1.1\r\nHost: host:port\r\n\r\n
     * 2. 服务器响应: HTTP/1.1 200 Connection Established\r\n\r\n
     * 3. 之后的数据直接转发 (TCP 隧道建立完成)
     */
    class HttpConnectClient {
    public:
        /**
         * 执行 HTTP CONNECT 握手
         * @param sock 已连接到代理服务器的 socket
         * @param targetHost 目标主机 (域名或IP)
         * @param targetPort 目标端口
         * @return true 表示隧道建立成功
         */
        static bool Handshake(SOCKET sock, const std::string& targetHost, uint16_t targetPort) {
            // 构造 CONNECT 请求
            // 格式: CONNECT host:port HTTP/1.1\r\nHost: host:port\r\n\r\n
            std::string hostForHeader = targetHost;
            in6_addr addr6{};
            if (inet_pton(AF_INET6, targetHost.c_str(), &addr6) == 1) {
                // IPv6 字面量需要方括号包裹，符合 HTTP CONNECT 语法
                hostForHeader = "[" + targetHost + "]";
            }
            std::ostringstream request;
            request << "CONNECT " << hostForHeader << ":" << targetPort << " HTTP/1.1\r\n";
            request << "Host: " << hostForHeader << ":" << targetPort << "\r\n";
            request << "\r\n";
            
            std::string requestStr = request.str();
            auto& config = Core::Config::Instance();
            int recvTimeout = config.timeout.recv_ms;
            int sendTimeout = config.timeout.send_ms;
            
            // 发送 CONNECT 请求
            // 使用统一 IO 封装，兼容非阻塞套接字
            if (!SocketIo::SendAll(sock, requestStr.c_str(), (int)requestStr.length(), sendTimeout)) {
                int err = WSAGetLastError();
                Core::Logger::Error("HTTP CONNECT: 发送请求失败, WSA错误码=" + std::to_string(err));
                return false;
            }
            
            // 接收响应
            // HTTP 响应头格式: HTTP/1.x 200 ...\r\n...\r\n\r\n
            std::string response;
            if (!SocketIo::RecvUntil(sock, &response, "\r\n\r\n", recvTimeout, 1024)) {
                int err = WSAGetLastError();
                if (err == WSAEMSGSIZE) {
                    Core::Logger::Error("HTTP CONNECT: 响应头过长或不完整");
                }
                Core::Logger::Error("HTTP CONNECT: 接收响应失败, WSA错误码=" + std::to_string(err));
                return false;
            }
            
            // 解析状态码
            // 期望格式: HTTP/1.x 200 ...
            int statusCode = ParseStatusCode(response);
            if (statusCode == -1) {
                Core::Logger::Error("HTTP CONNECT: 解析响应状态码失败");
                Core::Logger::Error("HTTP CONNECT: 响应内容: " + response.substr(0, 100));
                return false;
            }
            
            if (statusCode != 200) {
                Core::Logger::Error("HTTP CONNECT: 代理返回状态码 " + std::to_string(statusCode));
                Core::Logger::Error("HTTP CONNECT: 响应内容: " + response.substr(0, 100));
                return false;
            }
            
            Core::Logger::Info("HTTP CONNECT: 隧道建立成功 目标: " + targetHost + ":" + std::to_string(targetPort));
            return true;
        }
        
    private:
        /**
         * 解析 HTTP 响应状态码
         * @param response HTTP 响应字符串
         * @return 状态码，解析失败返回 -1
         */
        static int ParseStatusCode(const std::string& response) {
            // 查找第一行: "HTTP/1.x NNN ..."
            size_t spacePos = response.find(' ');
            if (spacePos == std::string::npos || spacePos + 4 > response.length()) {
                return -1;
            }
            
            // 提取状态码 (3位数字)
            std::string codeStr = response.substr(spacePos + 1, 3);
            try {
                return std::stoi(codeStr);
            } catch (...) {
                return -1;
            }
        }
    };
}
