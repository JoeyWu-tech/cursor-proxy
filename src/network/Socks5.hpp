#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <vector>
#include "../core/Config.hpp"
#include "../core/Logger.hpp"
#include "SocketIo.hpp"

namespace Network {
    
    // SOCKS5 Protocol Constants
    namespace Socks5 {
        constexpr uint8_t VERSION = 0x05;
        constexpr uint8_t AUTH_NONE = 0x00;
        constexpr uint8_t CMD_CONNECT = 0x01;
        constexpr uint8_t ATYP_IPV4 = 0x01;
        constexpr uint8_t ATYP_DOMAIN = 0x03;
        constexpr uint8_t ATYP_IPV6 = 0x04;
        constexpr uint8_t REPLY_SUCCESS = 0x00;
    }
    
    class Socks5Client {
    private:
        // Helper to ensure exact number of bytes are read (handles TCP fragmentation)
        static bool ReadExact(SOCKET sock, uint8_t* buf, int len, int timeoutMs) {
            // 使用统一的 IO 封装，兼容非阻塞套接字
            return SocketIo::RecvExact(sock, buf, len, timeoutMs);
        }

    public:
        // Execute SOCKS5 Handshake (No Auth)
        // Returns true if tunnel is established
        static bool Handshake(SOCKET sock, const std::string& targetHost, uint16_t targetPort) {
            auto& config = Core::Config::Instance();
            int recvTimeout = config.timeout.recv_ms;
            int sendTimeout = config.timeout.send_ms;

            // 1. Auth Method Negotiation
            // +----+----------+----------+
            // |VER | NMETHODS | METHODS  |
            // +----+----------+----------+
            // | 1  |    1     | 1 to 255 |
            // +----+----------+----------+
            uint8_t authRequest[3] = { Socks5::VERSION, 0x01, Socks5::AUTH_NONE };
            if (!SocketIo::SendAll(sock, (const char*)authRequest, 3, sendTimeout)) {
                int err = WSAGetLastError();
                Core::Logger::Error("SOCKS5: 发送认证请求失败, WSA错误码=" + std::to_string(err));
                return false;
            }
            
            // Receive Auth Method Response
            uint8_t authResponse[2];
            if (!ReadExact(sock, authResponse, 2, recvTimeout)) {
                int err = WSAGetLastError();
                Core::Logger::Error("SOCKS5: 读取认证响应失败, WSA错误码=" + std::to_string(err));
                return false;
            }
            
            if (authResponse[0] != Socks5::VERSION || authResponse[1] != Socks5::AUTH_NONE) {
                Core::Logger::Error("SOCKS5: 不支持的认证方式. 版本=" + 
                    std::to_string(authResponse[0]) + ", 方法=" + std::to_string(authResponse[1]));
                return false;
            }
            
            // 2. Send Connect Request
            // +----+-----+-------+------+----------+----------+
            // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
            // +----+-----+-------+------+----------+----------+
            std::vector<uint8_t> request;
            request.push_back(Socks5::VERSION);
            request.push_back(Socks5::CMD_CONNECT);
            request.push_back(0x00); // RSV
            
            in_addr addr{};
            if (inet_pton(AF_INET, targetHost.c_str(), &addr) == 1) {
                // IPv4 地址
                request.push_back(Socks5::ATYP_IPV4);
                request.push_back((addr.s_addr >> 0) & 0xFF);
                request.push_back((addr.s_addr >> 8) & 0xFF);
                request.push_back((addr.s_addr >> 16) & 0xFF);
                request.push_back((addr.s_addr >> 24) & 0xFF);
            } else {
                in6_addr addr6{};
                if (inet_pton(AF_INET6, targetHost.c_str(), &addr6) == 1) {
                    // IPv6 地址
                    request.push_back(Socks5::ATYP_IPV6);
                    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&addr6);
                    for (int i = 0; i < 16; ++i) request.push_back(bytes[i]);
                } else {
                    // 域名
                    request.push_back(Socks5::ATYP_DOMAIN);
                    uint8_t len = static_cast<uint8_t>(targetHost.length());
                    request.push_back(len);
                    for (char c : targetHost) request.push_back(c);
                }
            }
            
            // Port (Network Byte Order)
            request.push_back((targetPort >> 8) & 0xFF);
            request.push_back(targetPort & 0xFF);
            
            if (!SocketIo::SendAll(sock, (const char*)request.data(), (int)request.size(), sendTimeout)) {
                int err = WSAGetLastError();
                Core::Logger::Error("SOCKS5: 发送连接请求失败, WSA错误码=" + std::to_string(err));
                return false;
            }
            
            // 3. Receive Connect Response
            // We need to handle variable length responses carefully
            
            // Read Header: VER, REP, RSV, ATYP
            uint8_t header[4];
            if (!ReadExact(sock, header, 4, recvTimeout)) {
                int err = WSAGetLastError();
                Core::Logger::Error("SOCKS5: 读取响应头失败, WSA错误码=" + std::to_string(err));
                return false;
            }
            
            if (header[0] != Socks5::VERSION) {
                Core::Logger::Error("SOCKS5: 响应版本无效: " + std::to_string(header[0]));
                return false;
            }
            
            if (header[1] != Socks5::REPLY_SUCCESS) {
                Core::Logger::Error("SOCKS5: 代理服务器拒绝连接. 错误码: " + std::to_string(header[1]));
                return false;
            }
            
            // Determine Address Length based on ATYP
            uint8_t atyp = header[3];
            int addrLen = 0;
            switch(atyp) {
                case Socks5::ATYP_IPV4: 
                    addrLen = 4; 
                    break;
                case Socks5::ATYP_IPV6: 
                    addrLen = 16; 
                    break;
                case Socks5::ATYP_DOMAIN: {
                    uint8_t lenByte;
                    if (!ReadExact(sock, &lenByte, 1, recvTimeout)) {
                        int err = WSAGetLastError();
                        Core::Logger::Error("SOCKS5: 读取域名长度失败, WSA错误码=" + std::to_string(err));
                        return false;
                    }
                    addrLen = lenByte;
                    break;
                }
                default:
                    Core::Logger::Error("SOCKS5: 未知的地址类型: " + std::to_string(atyp));
                    return false;
            }
            
            // Consume Address Bytes (Ignore actual value as we don't need the bind addr)
            if (addrLen > 0) {
                std::vector<uint8_t> trash(addrLen);
                if (!ReadExact(sock, trash.data(), addrLen, recvTimeout)) {
                    int err = WSAGetLastError();
                    Core::Logger::Error("SOCKS5: 读取绑定地址失败, WSA错误码=" + std::to_string(err));
                    return false;
                }
            }
            
            // Consume Port (2 bytes)
            uint8_t portBuf[2];
            if (!ReadExact(sock, portBuf, 2, recvTimeout)) {
                int err = WSAGetLastError();
                Core::Logger::Error("SOCKS5: 读取绑定端口失败, WSA错误码=" + std::to_string(err));
                return false;
            }
            
            Core::Logger::Info("SOCKS5: 隧道建立成功 目标: " + targetHost + ":" + std::to_string(targetPort));
            return true;
        }
    };
}
