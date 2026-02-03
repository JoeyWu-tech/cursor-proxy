// 防止 windows.h 自动包含 winsock.h (避免与 winsock2.h 冲突)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include "core/Config.hpp"
#include "core/Logger.hpp"

// 前向声明
namespace Hooks {
    void Install();
    void Uninstall();
}

namespace VersionProxy {
    bool Initialize();
    void Uninitialize();
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH: {
        DisableThreadLibraryCalls(hinstDLL);
        
        // ============================================================================
        // VersionProxy 采用懒加载模式 (Lazy Initialization)
        // Initialize() 现在是空操作，真正的系统 version.dll 会在导出函数首次被调用时加载
        // 这样可以避免在 DllMain 中调用 LoadLibraryW 导致的 Loader Lock 问题
        // （可能触发 0xc0000022 STATUS_ACCESS_DENIED 错误）
        // ============================================================================
        VersionProxy::Initialize();  // 空操作，保持接口兼容
        
        Core::Logger::Info("Antigravity-Proxy DLL 已加载 (模拟 version.dll)");
        
        // 加载配置
        const bool loaded = Core::Config::Instance().Load("config.json");
        
        // WARN-4: 必须检查 Load() 返回值。若加载失败则进入 BYPASS 模式，避免“坏配置导致全局网络不可用”。
        if (!loaded) {
            Core::Logger::Error("配置加载失败：已进入 BYPASS 模式（不安装 Hooks）。请检查 config.json 与日志告警信息。");
            break;
        }

        // 安装 Hooks（必须及时安装以确保网络流量被正确拦截）
        Hooks::Install();
        break;
    }
        
    case DLL_PROCESS_DETACH: {
        Hooks::Uninstall();
        VersionProxy::Uninitialize();
        Core::Logger::Info("Antigravity-Proxy DLL 已卸载");
        break;
    }
    }
    return TRUE;
}
