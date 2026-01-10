#pragma once
#include <fstream>
#include <mutex>
#include <string>
#include <iostream>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <ctime>
#include <iomanip>
#include <sstream>

namespace Core {
    class Logger {
    private:
        // ========== 日志目录相关函数 ==========
        
        // 获取 DLL 所在目录（用于定位日志目录）
        static std::string GetDllDirectory() {
            char modulePath[MAX_PATH] = {0};
            HMODULE hModule = NULL;
            // 通过函数地址获取当前 DLL 的模块句柄
            if (!GetModuleHandleExA(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCSTR>(&GetDllDirectory),
                &hModule)) {
                return "";
            }
            DWORD len = GetModuleFileNameA(hModule, modulePath, MAX_PATH);
            if (len == 0 || len >= MAX_PATH) {
                return "";
            }
            // 截取路径，去掉文件名部分
            for (int i = static_cast<int>(len) - 1; i >= 0; --i) {
                if (modulePath[i] == '\\' || modulePath[i] == '/') {
                    modulePath[i] = '\0';
                    break;
                }
            }
            return std::string(modulePath);
        }

        // 确保目录存在，不存在则创建
        static bool EnsureLogDirectory(const std::string& dirPath) {
            DWORD attr = GetFileAttributesA(dirPath.c_str());
            if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
                return true; // 目录已存在
            }
            // 尝试创建目录
            return CreateDirectoryA(dirPath.c_str(), NULL) != 0;
        }

        // 获取系统临时目录路径
        static std::string GetSystemTempDirectory() {
            char tempPath[MAX_PATH] = {0};
            DWORD len = GetTempPathA(MAX_PATH, tempPath);
            if (len == 0 || len >= MAX_PATH) {
                return "";
            }
            // 去掉末尾的反斜杠（GetTempPathA 返回的路径末尾带 \）
            if (len > 0 && (tempPath[len - 1] == '\\' || tempPath[len - 1] == '/')) {
                tempPath[len - 1] = '\0';
            }
            return std::string(tempPath);
        }

        // 获取日志目录路径，首次调用时初始化
        // 优先级：DLL目录/logs/ → 系统TEMP目录/antigravity-proxy-logs/
        static std::string GetLogDirectory() {
            static std::string s_logDir;
            static bool s_initialized = false;
            if (!s_initialized) {
                s_initialized = true;
                // 优先尝试 DLL 目录下的 logs 子目录
                std::string dllDir = GetDllDirectory();
                if (!dllDir.empty()) {
                    std::string dllLogs = dllDir + "\\logs";
                    if (EnsureLogDirectory(dllLogs)) {
                        s_logDir = dllLogs;
                        return s_logDir;
                    }
                }
                // 回退到系统 TEMP 目录
                std::string tempDir = GetSystemTempDirectory();
                if (!tempDir.empty()) {
                    std::string tempLogs = tempDir + "\\antigravity-proxy-logs";
                    if (EnsureLogDirectory(tempLogs)) {
                        s_logDir = tempLogs;
                    }
                }
                // 如果都失败，s_logDir 保持为空，日志将写入当前目录（最后手段）
            }
            return s_logDir;
        }

        // ========== 原有辅助函数 ==========
        
        static std::string GetTimestamp() {
            auto now = std::time(nullptr);
            struct tm tm;
            localtime_s(&tm, &now);
            std::ostringstream oss;
            oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
            return oss.str();
        }

        static std::string GetPidTidPrefix() {
            // 在多进程/多线程混写同一个日志文件时，PID/TID 有助于定位来源
            DWORD pid = GetCurrentProcessId();
            DWORD tid = GetCurrentThreadId();
            return "[PID:" + std::to_string(pid) + "][TID:" + std::to_string(tid) + "]";
        }

        // 获取今日日志文件完整路径（如：C:\xxx\logs\proxy-20260111.log）
        static std::string GetTodayLogName() {
            auto now = std::time(nullptr);
            struct tm tm;
            localtime_s(&tm, &now);
            std::ostringstream oss;
            // 优先使用 DLL 目录下的 logs 子目录
            std::string logDir = GetLogDirectory();
            if (!logDir.empty()) {
                oss << logDir << "\\";
            }
            oss << "proxy-" << std::put_time(&tm, "%Y%m%d") << ".log";
            return oss.str();
        }

        static bool IsLogOverLimit(const std::string& path, ULONGLONG maxBytes) {
            WIN32_FILE_ATTRIBUTE_DATA data{};
            if (!GetFileAttributesExA(path.c_str(), GetFileExInfoStandard, &data)) {
                return false;
            }
            ULONGLONG size = (static_cast<ULONGLONG>(data.nFileSizeHigh) << 32) | data.nFileSizeLow;
            return size >= maxBytes;
        }

        // 清理旧日志文件，只保留当天的日志
        static void CleanupOldLogs(const std::string& todayLog) {
            std::string logDir = GetLogDirectory();
            // 构建搜索模式（支持有/无日志目录两种情况）
            std::string searchPattern = logDir.empty() 
                ? "proxy-*.log" 
                : (logDir + "\\proxy-*.log");
            
            WIN32_FIND_DATAA findData{};
            HANDLE hFind = FindFirstFileA(searchPattern.c_str(), &findData);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                        continue;
                    }
                    // 构建找到文件的完整路径
                    std::string fullPath = logDir.empty() 
                        ? std::string(findData.cFileName) 
                        : (logDir + "\\" + findData.cFileName);
                    
                    // 保留今天的日志，删除其他日期的
                    if (todayLog != fullPath) {
                        DeleteFileA(fullPath.c_str());
                    }
                } while (FindNextFileA(hFind, &findData));
                FindClose(hFind);
            }
            // 清理旧版日志文件（无日期后缀的遗留文件）
            std::string oldLog = logDir.empty() ? "proxy.log" : (logDir + "\\proxy.log");
            std::string oldLog1 = logDir.empty() ? "proxy.log.1" : (logDir + "\\proxy.log.1");
            if (todayLog != oldLog) {
                DeleteFileA(oldLog.c_str());
            }
            DeleteFileA(oldLog1.c_str());
        }

        static void WriteToFile(const std::string& message) {
            static std::mutex mtx;
            std::lock_guard<std::mutex> lock(mtx);
            // 按日期写日志并清理旧文件，避免历史日志堆积
            static std::string s_todayLog;
            static ULONGLONG s_lastCheckTick = 0;
            static bool s_dropForToday = false;
            static const ULONGLONG kMaxLogBytes = 100ull * 1024 * 1024; // 100MB
            static const ULONGLONG kCheckIntervalMs = 60ull * 60 * 1000; // 1 小时
            std::string todayLog = GetTodayLogName();
            if (s_todayLog != todayLog) {
                s_todayLog = todayLog;
                s_lastCheckTick = 0;
                s_dropForToday = false;
                CleanupOldLogs(s_todayLog);
            }
            if (s_dropForToday) {
                return;
            }
            ULONGLONG nowTick = GetTickCount64();
            if (s_lastCheckTick == 0 || nowTick - s_lastCheckTick >= kCheckIntervalMs) {
                s_lastCheckTick = nowTick;
                if (IsLogOverLimit(s_todayLog, kMaxLogBytes)) {
                    // 当天日志超过上限后直接丢弃，次日恢复
                    s_dropForToday = true;
                    return;
                }
            }
            std::ofstream logFile(s_todayLog, std::ios::app);
            if (logFile.is_open()) {
                logFile << message << "\n";
            }
        }

    public:
        static void Log(const std::string& message) {
            WriteToFile("[" + GetTimestamp() + "] " + GetPidTidPrefix() + " " + message);
        }

        static void Error(const std::string& message) {
            WriteToFile("[" + GetTimestamp() + "] " + GetPidTidPrefix() + " [错误] " + message);
        }

        static void Info(const std::string& message) {
            WriteToFile("[" + GetTimestamp() + "] " + GetPidTidPrefix() + " [信息] " + message);
        }

        static void Warn(const std::string& message) {
            WriteToFile("[" + GetTimestamp() + "] " + GetPidTidPrefix() + " [警告] " + message);
        }

        static void Debug(const std::string& message) {
            WriteToFile("[" + GetTimestamp() + "] " + GetPidTidPrefix() + " [调试] " + message);
        }
    };
}
