module;
#include <fmt/chrono.h>
#include <fmt/format.h>
#include <wil/result_macros.h>
#include <wil/resource.h>
#include <clocale>
#include <filesystem>
#include <fstream>
#include <functional>
#include <mutex>
#include <span>
#include <string>
#include <unordered_set>
#include <vector>
module Lanyi.Ra3Profiler.Injection;
import Lanyi.Ra3Profiler.Profiler;

using namespace std::literals;

namespace
{
    class Injection
    {
    private:
        // 注入时需要传递的自定义数据
        std::span<std::byte const> m_data;
        // 输出日志
        mutable std::mutex m_logMutex;
        std::function<void(char const*)> m_logger;
        // 已经被注入的红警3（防止重复注入）
        mutable std::mutex m_threadMutex;
        std::unordered_set<DWORD> m_set;

    public:
        static Injection& createInstance
        (
            std::span<std::byte const> data,
            std::function<void(char const*)> logger
        );
        static Injection& instance();
        // 记录日志
        template<typename... Args>
        void log
        (
            std::string_view category,
            fmt::format_string<Args...> format,
            Args&&... args
        ) const noexcept;
        void log
        (
            std::string_view category,
            std::string_view text
        ) const noexcept;
        // 记录已经被注入的红警3
        HRESULT tryAddInjectedThread(HANDLE thread);
        HRESULT tryRemoveInjectedThread(HANDLE thread);
        // 执行注入
        HRESULT injectToRa3(wil::unique_handle ra3MainThread);

    private:
        Injection
        (
            std::span<std::byte const> data,
            std::function<void(char const*)> logger,
            bool expectInstanceAlreadyCreated
        );
        static Injection& getInstance
        (
            std::span<std::byte const> data,
            std::function<void(char const*)> logger,
            bool createNew
        );
    };

    // 记录 WIL 日志
    void __stdcall wilLog(wil::FailureInfo const& information) noexcept;

    // 创建用于和注入 DLL 通讯的管道
    wil::unique_handle createPipe();
    // 尝试找到红警3的窗口句柄
    std::vector<HWND> findRa3Windows();
    // 获取红警3的主线程句柄
    wil::unique_handle getRa3MainThread(HWND ra3Window, DWORD desiredAccess);
    // 获取此 DLL 的句柄
    HMODULE getThisDll();
    // 等待管道被连上
    HRESULT waitForPipeConnection(HANDLE pipe);
    // 发送数据
    HRESULT writeFile(HANDLE file, void const* data, std::size_t size);
    // 读取数据
    HRESULT readFile(HANDLE file, void* data, std::size_t size);
    // 被注入后执行的函数
    LRESULT CALLBACK windowProcedureReturnHook(int code, WPARAM wParam, LPARAM lParam);

    auto constexpr ra3ClassName = L"41DAF790-16F5-4881-8754-59FD8CF3B8D2"sv;
    auto constexpr pipeName = L"\\\\.\\pipe\\Lanyi.Ra3Profiler";
}

void Lanyi::Ra3Profiler::inject
(
    char const* input,
    void* loggerContext,
    Lanyi::Ra3Profiler::TextWriter* logger
)
{
    try
    {
        std::setlocale(LC_ALL, ".ACP");
        auto data = std::span
        {
            reinterpret_cast<std::byte const*>(input),
            std::strlen(input)
        };
        if (logger != nullptr)
        {
            Injection::createInstance(data, [loggerContext, logger](char const* text)
            {
                return logger(loggerContext, text);
            });
        }
        else
        {
            Injection::createInstance(data, nullptr);
        }
        
        wil::SetResultLoggingCallback(&wilLog);
        Injection::instance().log("info", "Injection started");
        while (true)
        {
            for (HWND ra3Window : findRa3Windows())
            {
                wil::unique_handle ra3MainThread;
                try
                {

                    auto constexpr desiredAccess = SYNCHRONIZE | THREAD_QUERY_LIMITED_INFORMATION;
                    ra3MainThread = getRa3MainThread(ra3Window, desiredAccess);
                }
                CATCH_LOG_MSG("Failed to retrieve RA3 main thread from window");
                if (not ra3MainThread.is_valid())
                {
                    continue;
                }
                if (Injection::instance().tryAddInjectedThread(ra3MainThread.get()) != S_OK)
                {
                    // 已经被注入过了，或者出现了错误
                    continue;
                }
                Injection::instance().log("info", "Found RA3 process {}", GetProcessIdOfThread(ra3MainThread.get()));
                // 开始注入！
                auto doInject = [](wil::unique_handle ra3MainThread)
                {
                    return Injection::instance().injectToRa3(std::move(ra3MainThread));
                };
                std::thread{ doInject, std::move(ra3MainThread) }.detach();
            }
            std::this_thread::sleep_for(5s);
        }
    }
    CATCH_LOG_MSG("Injection task terminated");
}

namespace
{
    Injection& Injection::createInstance
    (
        std::span<std::byte const> data,
        std::function<void(char const*)> logger
    )
    {
        return getInstance(data, logger, true);
    }

    Injection& Injection::instance()
    {
        return getInstance({}, nullptr, false);
    }

    template<typename ...Args>
    void Injection::log
    (
        std::string_view category,
        fmt::format_string<Args...> format,
        Args&&... args
    ) const noexcept
    {
        try
        {
            log(category, fmt::format(format, std::forward<Args>(args)...));
        }
        CATCH_LOG_MSG("failed to format log message");
    }

    void Injection::log
    (
        std::string_view category,
        std::string_view text
    ) const noexcept
    {
        std::string logText = fmt::format
        (
            "[{:%Y-%m-%d %H:%M:%S}] [{}] {}",
            fmt::localtime(std::time(nullptr)),
            category,
            text
        );
        std::scoped_lock lock{ m_logMutex };
        m_logger(logText.c_str());
    }

    HRESULT Injection::tryAddInjectedThread(HANDLE thread)
    {
        DWORD threadId = GetThreadId(thread);
        RETURN_LAST_ERROR_IF_MSG(threadId == 0, "Failed to add thread id to set");
        std::scoped_lock lock{ m_threadMutex };
        auto [iterator, inserted] = m_set.emplace(threadId);
        return inserted ? S_OK : S_FALSE;
    }

    HRESULT Injection::tryRemoveInjectedThread(HANDLE thread)
    {
        DWORD threadId = GetThreadId(thread);
        RETURN_LAST_ERROR_IF_MSG(threadId == 0, "Failed to remove thread id from set");
        std::scoped_lock lock{ m_threadMutex };
        m_set.erase(threadId);
        return S_OK;
    }

    HRESULT Injection::injectToRa3(wil::unique_handle ra3MainThread)
    {
        auto waitForThreadExit = wil::scope_exit([this, &ra3MainThread]
        {
            if (ra3MainThread.is_valid())
            {
                log("info", "Start waiting for ra3 thread exit");
                LOG_LAST_ERROR_IF_MSG(WaitForSingleObject
                (
                    ra3MainThread.get(),
                    INFINITE
                ) == WAIT_FAILED, "Failed to wait for thread exit");
                log("info", "End waiting for ra3 thread exit");
                tryRemoveInjectedThread(ra3MainThread.get());
            }
        });
        try
        {
            if (not tryAddInjectedThread(ra3MainThread.get()))
            {
                // 该红警3的线程已经被注入
                return S_FALSE;
            }
            DWORD threadId = GetThreadId(ra3MainThread.get());
            RETURN_LAST_ERROR_IF_MSG(threadId == 0, "Failed to retrieve RA3 thread id");

            wil::unique_handle ipc = createPipe();
            // 挂钩
            log("info", "Attempting to hook RA3..");
            HHOOK hook = THROW_LAST_ERROR_IF_NULL_MSG(SetWindowsHookExW
            (
                WH_CALLWNDPROCRET,
                &windowProcedureReturnHook,
                getThisDll(),
                GetThreadId(ra3MainThread.get())
            ), "Failed to install windows hook");
            auto unhookOnExit = wil::scope_exit([hook] { UnhookWindowsHookEx(hook); });

            // 等待被注入的 DLL 连上管道
            RETURN_IF_FAILED(waitForPipeConnection(ipc.get()));
            log("info", "Received connection request from injected dll");

            // 发送数据
            DWORD bytesToWrite = static_cast<DWORD>(m_data.size());
            RETURN_IF_FAILED(writeFile(ipc.get(), &bytesToWrite, sizeof(bytesToWrite)));
            RETURN_IF_FAILED(writeFile(ipc.get(), m_data.data(), m_data.size()));
            log("info", "Custom data has been sent");

            std::string buffer;
            while (true)
            {
                // 等待被注入的 DLL 发送数据
                DWORD bytesToRead = 0;
                RETURN_IF_FAILED(readFile(ipc.get(), &bytesToRead, sizeof(bytesToRead)));
                if (bytesToRead == 0)
                {
                    // 被注入的 DLL 退出了
                    log("info", "ipc connection closed");
                    break;
                }
                buffer.resize(bytesToRead);
                RETURN_IF_FAILED(readFile(ipc.get(), buffer.data(), buffer.size()));
                log("ipc", { buffer.data(), buffer.size() });
            }
            return S_OK;
        }
        CATCH_RETURN_MSG("Failed to injectToRa3");
    }

    Injection::Injection
    (
        std::span<std::byte const> data,
        std::function<void(char const*)> logger,
        bool expectInstanceAlreadyCreated
    ) :
        m_data{ data },
        m_logger{ logger != nullptr ? std::move(logger) : [](auto) {} }
    {
        THROW_HR_IF_MSG(E_UNEXPECTED, expectInstanceAlreadyCreated, "Injection instance not created yet");
    }

    Injection& Injection::getInstance
    (
        std::span<std::byte const> data,
        std::function<void(char const*)> logger,
        bool createNew
    )
    {
        static Injection singleton{ data, logger, not createNew };
        return singleton;
    }

    void __stdcall wilLog(wil::FailureInfo const& information) noexcept
    {
        std::wstring buffer;
        buffer.resize(2048);
        if (not SUCCEEDED(wil::GetFailureLogString(buffer.data(), buffer.size(), information)))
        {
            Injection::instance().log("?", "wil::GetFailureLogString failed");
        }
        std::string utf8;
        int result = WideCharToMultiByte(CP_UTF8, 0, buffer.data(), -1, nullptr, 0, nullptr, nullptr);
        if (result <= 0)
        {
            Injection::instance().log("?", "WideCharToMultiByte failed");
        }
        utf8.resize(result);
        result = WideCharToMultiByte(CP_UTF8, 0, buffer.data(), -1, utf8.data(), utf8.size(), nullptr, nullptr);
        if (result <= 0)
        {
            Injection::instance().log("?", "WideCharToMultiByte failed");
        }
        utf8.resize(result);
        Injection::instance().log("error", utf8);
    }

    wil::unique_handle createPipe()
    {
        // 为命名管道创建一个安全描述符，避免红警3没有权限与管理员模式运行的注入程序通信
        SECURITY_DESCRIPTOR securityDescriptor{};
        InitializeSecurityDescriptor(&securityDescriptor, SECURITY_DESCRIPTOR_REVISION);
        // 设置安全描述符的访问控制列表，允许所有用户访问
        SetSecurityDescriptorDacl(&securityDescriptor, true, 0, false);
        // 避免安全描述符的访问控制列表由于继承而被修改
        SetSecurityDescriptorControl(&securityDescriptor, SE_DACL_PROTECTED, SE_DACL_PROTECTED);
        SECURITY_ATTRIBUTES securityAttributes
        {
            .nLength = sizeof(SECURITY_ATTRIBUTES),
            .lpSecurityDescriptor = &securityDescriptor,
            .bInheritHandle = false
        };
        HANDLE rawPipe = CreateNamedPipeW
        (
            pipeName,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_REJECT_REMOTE_CLIENTS,
            1, // max instances
            0, // out buffer size
            0, // in buffer size
            0, // default timeout
            &securityAttributes
        );
        THROW_LAST_ERROR_IF_MSG(rawPipe == INVALID_HANDLE_VALUE, "CreateNamedPipeW failed");
        return wil::unique_handle{ rawPipe };
    }

    HMODULE getThisDll()
    {
        HMODULE thisDll = nullptr;
        THROW_IF_WIN32_BOOL_FALSE_MSG(GetModuleHandleExW
        (
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<wchar_t const*>(&getThisDll),
            &thisDll
        ), "Failed to obtain this dll handle");
        return thisDll;
    }

    std::vector<HWND> findRa3Windows()
    {
        struct Helper
        {
            static BOOL CALLBACK findRa3Window(HWND window, LPARAM data)
            {
                auto& result = *reinterpret_cast<std::vector<HWND>*>(data);
                std::wstring className;
                className.resize(ra3ClassName.size() + 1 + "\0"sv.size());
                std::size_t charactersCopied = GetClassNameW(window, className.data(), className.size());
                LOG_LAST_ERROR_IF_MSG(charactersCopied == 0, "GetClassNameW failed");
                className.resize(charactersCopied);
                className.at(0) = ra3ClassName.at(0);
                if (className == ra3ClassName)
                {
                    result.push_back(window);
                }
                return TRUE;
            }
        };
        std::vector<HWND> result;
        THROW_IF_WIN32_BOOL_FALSE_MSG(EnumWindows
        (
            Helper::findRa3Window,
            reinterpret_cast<LPARAM>(&result)
        ), "Failed to enumerate windows");
        return result;
    }

    wil::unique_handle getRa3MainThread(HWND ra3Window, DWORD desiredAccess)
    {
        DWORD ra3MainThreadId = GetWindowThreadProcessId
        (
            ra3Window,
            nullptr
        );
        THROW_LAST_ERROR_IF_MSG(ra3MainThreadId == 0, "Failed to retrieve ra3 thread id");
        HANDLE rawThread = OpenThread(desiredAccess, false, ra3MainThreadId);
        THROW_LAST_ERROR_IF_NULL_MSG(rawThread, "Failed to open ra3 thread");
        return wil::unique_handle{ rawThread };
    }

    HRESULT waitForPipeConnection(HANDLE pipe)
    {
        wil::unique_event pipeConnectedEvent;
        pipeConnectedEvent.create();
        OVERLAPPED overlapped = { .hEvent = pipeConnectedEvent.get() };
        ConnectNamedPipe(pipe, &overlapped);
        DWORD connectResult = GetLastError();
        if (connectResult != ERROR_IO_PENDING)
        {
            RETURN_LAST_ERROR_IF_MSG(connectResult != ERROR_PIPE_CONNECTED, "ConnectNamedPipe failed");
            return S_OK; // ERROR_PIPE_CONNECTED - 已连接
        }
        auto cancelIoOnExit = wil::scope_exit([&] { CancelIoEx(pipe, &overlapped); });
        auto waitSucceeded = pipeConnectedEvent.wait(30 * 1000 /* 30 seconds */);
        if (not waitSucceeded)
        {
            RETURN_HR_MSG(HRESULT_FROM_WIN32(ERROR_TIMEOUT), "timeout waiting for DLL to connect");
        }
        return S_OK;
    }

    HRESULT writeFile(HANDLE file, void const* data, std::size_t size)
    {
        static_assert(sizeof(size) == sizeof(DWORD));
        DWORD bytesWritten = 0;
        RETURN_IF_WIN32_BOOL_FALSE(WriteFile
        (
            file,
            data,
            static_cast<DWORD>(size),
            &bytesWritten,
            nullptr
        ));
        if (bytesWritten != size)
        {
            DWORD error = GetLastError();
            if (error == ERROR_SUCCESS)
            {
                error = ERROR_WRITE_FAULT;
            }
            RETURN_WIN32_MSG(error, "WriteFile failed to write all data");
        }
        return S_OK;
    }

    HRESULT readFile(HANDLE file, void* data, std::size_t size)
    {
        static_assert(sizeof(size) == sizeof(DWORD));
        DWORD bytesRead = 0;
        RETURN_IF_WIN32_BOOL_FALSE(ReadFile
        (
            file,
            data,
            static_cast<DWORD>(size),
            &bytesRead,
            nullptr
        ));
        if (bytesRead != size)
        {
            DWORD error = GetLastError();
            if (error == ERROR_SUCCESS)
            {
                error = ERROR_READ_FAULT;
            }
            RETURN_WIN32_MSG(error, "ReadFile failed to read all data");
        }
        return S_OK;
    }

    LRESULT CALLBACK windowProcedureReturnHook(int code, WPARAM wParam, LPARAM lParam)
    {
        static long initialized = false;
        if (InterlockedCompareExchange(&initialized, true, false))
        {
            return CallNextHookEx(nullptr, code, wParam, lParam);
        }
        // 初始化
        struct Ipc : Lanyi::Ra3Profiler::Ipc
        {
            std::fstream file;

            Ipc(std::filesystem::path const& path)
            {
                file.open(path, file.in | file.out | file.binary);
            }

            ~Ipc()
            {
                DWORD constexpr zero = 0;
                file.write(reinterpret_cast<char const*>(&zero), sizeof(zero));
            }

            void send(std::string_view text) override
            {
                if (text.empty())
                {
                    return;
                }
                auto size = text.size();
                static_assert(sizeof(size) == sizeof(DWORD));
                file.write(reinterpret_cast<char const*>(&size), sizeof(size));
                if (not file.good())
                {
                    return;
                }
                file.write(text.data(), size);
                file.flush();
            }

            std::string receive() override
            {
                DWORD size = 0;
                std::string result;
                file.read(reinterpret_cast<char*>(&size), sizeof(size));
                if (not file.good())
                {
                    return {};
                }
                result.resize(size);
                file.read(result.data(), result.size());
                return result;
            }
        };
        Lanyi::Ra3Profiler::initialize(std::make_shared<Ipc>(pipeName));
        return CallNextHookEx(nullptr, code, wParam, lParam);
    }
}
