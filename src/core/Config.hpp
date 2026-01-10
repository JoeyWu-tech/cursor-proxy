#pragma once
#include <nlohmann/json.hpp>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>
#include "Logger.hpp"

namespace Core {
    struct ProxyConfig {
        std::string host = "127.0.0.1";
        int port = 7890;
        std::string type = "socks5";
    };

    struct FakeIPConfig {
        bool enabled = true;
        std::string cidr = "198.18.0.0/15";
        // 注：max_entries 已废弃，Ring Buffer 策略下自动循环复用地址池
    };

    struct TimeoutConfig {
        int connect_ms = 5000;
        int send_ms = 5000;
        int recv_ms = 5000;
    };

    // ============= 代理路由规则 =============
    // 用于控制哪些端口走代理、DNS 53 端口的特殊处理策略
    struct ProxyRules {
        // 允许代理的目标端口白名单（为空则代理所有端口）
        // 默认: 仅代理 HTTP(80) 和 HTTPS(443)
        std::vector<uint16_t> allowed_ports = {80, 443};
        
        // DNS (Port 53) 处理策略
        // "direct" - 直连, 不经代理 (默认, 解决 DNS 超时问题)
        // "proxy"  - 走代理
        std::string dns_mode = "direct";
        
        // 快速判断端口是否在白名单中
        bool IsPortAllowed(uint16_t port) const {
            if (allowed_ports.empty()) return true; // 空白名单 = 允许所有
            return std::find(allowed_ports.begin(), allowed_ports.end(), port) 
                   != allowed_ports.end();
        }
    };

    class Config {
    private:
        // 判断路径是否为绝对路径（Windows 盘符或 UNC 路径）
        static bool IsAbsolutePath(const std::string& path) {
            if (path.size() >= 2 && std::isalpha(static_cast<unsigned char>(path[0])) && path[1] == ':') {
                return true;
            }
            if (path.size() >= 2 &&
                ((path[0] == '\\' && path[1] == '\\') || (path[0] == '/' && path[1] == '/'))) {
                return true;
            }
            return false;
        }

        // 获取当前 DLL 所在目录（用于定位与 DLL 同目录的配置文件）
        static std::string GetModuleDirectory() {
            char modulePath[MAX_PATH] = {0};
            HMODULE hModule = NULL;
            if (!GetModuleHandleExA(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCSTR>(&GetModuleDirectory),
                &hModule
            )) {
                return "";
            }
            DWORD len = GetModuleFileNameA(hModule, modulePath, MAX_PATH);
            if (len == 0 || len >= MAX_PATH) {
                return "";
            }
            for (int i = static_cast<int>(len) - 1; i >= 0; --i) {
                if (modulePath[i] == '\\' || modulePath[i] == '/') {
                    modulePath[i] = '\0';
                    break;
                }
            }
            return std::string(modulePath);
        }

    public:
        ProxyConfig proxy;
        FakeIPConfig fakeIp;
        TimeoutConfig timeout;
        ProxyRules rules;               // 代理路由规则
        bool trafficLogging = false;    // Phase 3: 是否启用流量监控日志
        bool childInjection = true;     // Phase 2: 是否自动注入子进程
        std::vector<std::string> targetProcesses; // 目标进程列表 (空=全部)

        // 检查进程名是否在目标列表中 (大小写不敏感)
        bool ShouldInject(const std::string& processName) const {
            // 如果列表为空，注入所有进程
            if (targetProcesses.empty()) return true;
            
            // 将输入转为小写进行比较
            std::string lowerName = processName;
            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), 
                [](unsigned char c) { return std::tolower(c); });
            
            for (const auto& target : targetProcesses) {
                std::string lowerTarget = target;
                std::transform(lowerTarget.begin(), lowerTarget.end(), lowerTarget.begin(),
                    [](unsigned char c) { return std::tolower(c); });
                
                // 支持完全匹配或不带扩展名匹配
                if (lowerName == lowerTarget) return true;
                // 支持类似 "language_server_windows" 匹配 "language_server_windows.exe"
                if (lowerName.find(lowerTarget) != std::string::npos) return true;
            }
            return false;
        }

        static Config& Instance() {
            static Config instance;
            return instance;
        }

        bool Load(const std::string& path = "config.json") {
            try {
                // 优先从 DLL 所在目录读取配置，避免子进程工作目录不同导致相对路径失效
                std::vector<std::string> candidates;
                if (IsAbsolutePath(path)) {
                    candidates.push_back(path);
                } else {
                    std::string dllDir = GetModuleDirectory();
                    if (!dllDir.empty()) {
                        candidates.push_back(dllDir + "\\" + path);
                    }
                    candidates.push_back(path);
                }

                std::ifstream f;
                std::string resolvedPath;
                for (const auto& candidate : candidates) {
                    f.open(candidate);
                    if (f.is_open()) {
                        resolvedPath = candidate;
                        break;
                    }
                    f.clear();
                }

                if (!f.is_open()) {
                    if (IsAbsolutePath(path)) {
                        Logger::Error("打开配置文件失败: " + path);
                    } else {
                        Logger::Error("打开配置文件失败: " + path + " (已尝试 DLL 目录与当前目录)");
                    }
                    return false;
                }
                if (!resolvedPath.empty()) {
                    Logger::Info("使用配置文件路径: " + resolvedPath);
                }
                nlohmann::json j = nlohmann::json::parse(f);
                
                if (j.contains("proxy")) {
                    auto& p = j["proxy"];
                    proxy.host = p.value("host", "127.0.0.1");
                    proxy.port = p.value("port", 7890);
                    proxy.type = p.value("type", "socks5");
                }

                if (j.contains("fake_ip")) {
                    auto& fip = j["fake_ip"];
                    fakeIp.enabled = fip.value("enabled", true);
                    fakeIp.cidr = fip.value("cidr", "198.18.0.0/15");
                    // max_entries 已废弃，Ring Buffer 策略下无需配置上限
                }

                if (j.contains("timeout")) {
                    auto& t = j["timeout"];
                    timeout.connect_ms = t.value("connect", 5000);
                    timeout.send_ms = t.value("send", 5000);
                    timeout.recv_ms = t.value("recv", 5000);
                }

                // ============= 代理路由规则解析 =============
                if (j.contains("proxy_rules")) {
                    auto& pr = j["proxy_rules"];
                    // 解析端口白名单
                    if (pr.contains("allowed_ports") && pr["allowed_ports"].is_array()) {
                        rules.allowed_ports.clear();
                        for (const auto& p : pr["allowed_ports"]) {
                            if (p.is_number_unsigned()) {
                                rules.allowed_ports.push_back(static_cast<uint16_t>(p.get<unsigned int>()));
                            }
                        }
                    }
                    // 解析 DNS 策略
                    rules.dns_mode = pr.value("dns_mode", "direct");
                    Logger::Info("路由规则: allowed_ports=" + std::to_string(rules.allowed_ports.size()) + 
                                 " 项, dns_mode=" + rules.dns_mode);
                }


                // Phase 2/3 配置项
                trafficLogging = j.value("traffic_logging", false);
                childInjection = j.value("child_injection", true);

                // 目标进程列表
                if (j.contains("target_processes") && j["target_processes"].is_array()) {
                    targetProcesses.clear();
                    for (const auto& item : j["target_processes"]) {
                        if (item.is_string()) {
                            targetProcesses.push_back(item.get<std::string>());
                        }
                    }
                    Logger::Info("已加载目标进程列表, 共 " + std::to_string(targetProcesses.size()) + " 项");
                }

                Logger::Info("配置: proxy=" + proxy.host + ":" + std::to_string(proxy.port) +
                             " type=" + proxy.type +
                             ", fake_ip=" + std::string(fakeIp.enabled ? "true" : "false") +
                             ", child_injection=" + std::string(childInjection ? "true" : "false") +
                             ", traffic_logging=" + std::string(trafficLogging ? "true" : "false"));
                Logger::Info("配置加载成功。");
                return true;
            } catch (const std::exception& e) {
                Logger::Error(std::string("配置解析失败: ") + e.what());
                return false;
            }
        }
    };
}
