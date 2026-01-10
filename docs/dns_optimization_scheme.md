# Antigravity-Proxy 网络拦截优化与端口路由方案

## 1. 背景与问题分析

### 1.1 现象
用户反馈启用代理后，应用的网络请求（特别是 DNS）出现异常。日志显示：
1.  发往 `53` 端口的连接被代理拦截。
2.  代理握手（SOCKS5/HTTP）超时或失败 (`WSA error 10060`)。
3.  应用随后尝试 IPv6 DoH 作为兜底，但被 `强制 IPv4` 策略拦截。

### 1.2 根源深度剖析
经过代码审查，核心冲突在于 **DNS 的低延迟特性** 与 **同步代理握手的耗时** 之间的不匹配。

-   **机制冲突**：当前 `Hooks.cpp` 中的 `PerformProxyConnect` 强制拦截所有 TCP 连接。对于 DNS (通常端口 53)，它会立即尝试连接本地代理并执行完整的 SOCKS5 握手。
-   **时序灾难**：
    1.  OS/App 发起 DNS 查询（期望 ms 级响应）。
    2.  Hook 劫持连接 -> 链接代理 (TCP RTT) -> 发送握手 (TCP RTT) -> 接收响应 (TCP RTT)。
    3.  此过程通常耗时 50ms - 300ms。
    4.  DNS 客户端判定超时（通常阈值极低），关闭 Socket。
    5.  代理握手虽完成后，Socket 已无效，导致“握手失败”或“连接重置”日志。

## 2. 解决方案：智能路由表 (Smart Routing Table)

为了彻底解决此问题，我们引入基于端口和策略的智能路由机制，不再“粗暴”代理所有流量。

### 2.1 架构设计

在 `Config` 中引入 `ProxyRules` 结构，支持以下策略：

1.  **端口白名单 (Port Whitelist)**：仅代理指定端口（如 80, 443），其他端口默认直连。
2.  **DNS 专用通道 (DNS Channel)**：针对 53 端口提供独立策略：
    -   **Direct (直连)**：直接透传请求，不经过代理。
    -   **Custom (重定向)**：将目标地址篡改为指定 DNS 服务器（如 8.8.8.8），然后直连。有效防止本地 DNS 污染同时规避代理高延迟。
    -   **Proxy (代理)**：走标准代理流程（仅在明确需要时使用）。

### 2.2 详细设计

#### A. 配置结构 (Config.hpp)

```cpp
struct ProxyRules {
    // 允许代理的端口白名单。为空则代理所有。
    std::vector<uint16_t> allow_ports = {80, 443}; 
    
    // DNS (Port 53) 处理策略
    // "direct": 直连 (默认，最稳健)
    // "proxy": 走代理
    // "custom": 重定向到 custom_dns
    std::string dns_mode = "direct"; 
    
    // 自定义 DNS 目标 (仅 mode="custom" 有效)
    std::string custom_dns = "8.8.8.8";
};
```

#### B. 核心逻辑 (Hooks.cpp -> PerformProxyConnect)

逻辑流程图：

```mermaid
graph TD
    A[Hook Connect] --> B{目标端口 == 53?}
    B -- Yes --> C{DNS Mode?}
    C -- "direct" --> F[直连 (Passthrough)]
    C -- "custom" --> D[修改目标为 Custom DNS]
    D --> F
    C -- "proxy" --> E[执行代理握手]
    
    B -- No --> G{端口在 Allow List?}
    G -- Yes --> E
    G -- No --> F
```

## 3. 预期效果

### 3.1 性能提升
-   **DNS 秒开**：53 端口流量不再经过 SOCKS5 握手，延迟降低 90% 以上。
-   **无阻塞**：非 Web 流量（如 P2P、游戏、后台服务）默认直连，不再占用代理带宽，且无兼容性问题。

### 3.2 稳定性
-   **兜底恢复**：即使 TCP DNS 失败，应用的 IPv6 DoH 尝试（如果是 HTTPS 443）将根据路由表决定是否代理。若 DoH 目标为 443 且在白名单，则正常代理；否则直连。避免了之前的暴力拦截。

## 4. 实施步骤

1.  **修改 `src/core/Config.hpp`**：
    -   添加 `ProxyRules` 结构体。
    -   更新 JSON 解析逻辑，支持 `proxy_rules` 字段。
    
2.  **修改 `src/hooks/Hooks.cpp`**：
    -   重构 `PerformProxyConnect`。
    -   实现上述路由逻辑。

3.  **验证**：
    -   启动后查看日志，确认 "Target Port 53 -> Strategy: Direct" 等日志输出。
