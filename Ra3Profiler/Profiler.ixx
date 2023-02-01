module;
#include <Windows.h>
#include <boost/circular_buffer.hpp>
#include <array>
#include <chrono>
#include <memory>
#include <ranges>
#include <source_location>
#include <span>
#include <string>
#include <unordered_map>
export module Lanyi.Ra3Profiler.Profiler;

export namespace Lanyi::Ra3Profiler
{
    class Ipc
    {
    public:
        virtual ~Ipc() = default;
        virtual void send(std::string_view) {};
        virtual std::string receive() { return {}; };
    };
    void initialize(std::shared_ptr<Ipc> ipc);
}

module: private;
import Lanyi.Ra3Profiler.Abstractions;

using namespace Lanyi::Ra3Profiler::Abstractions;

namespace
{
    std::shared_ptr<Lanyi::Ra3Profiler::Ipc> g_ipc;
}

void Lanyi::Ra3Profiler::initialize(std::shared_ptr<Ipc> ipc)
{
    g_ipc = ipc != nullptr ? ipc : std::make_shared<Ipc>();
    std::string input = g_ipc->receive();
    g_ipc->send(std::source_location::current().function_name());
}

namespace
{
    template<typename T>
    concept FunctionData = requires
    {
        T::name;
        T::address;
        std::same_as<decltype(T::name), char const* const>;
        std::same_as<std::remove_const_t<decltype(T::address)>, std::uint32_t>;
    };

#define LANYI_ENABLE_CALL_EAX_EDX_PROFILER 1
#if LANYI_ENABLE_CALL_EAX_EDX_PROFILER
    struct JitGetCallEaxEdxKey
    {
    public:
        inline static auto jitCode = ([]
        {
            auto const memory = VirtualAlloc
            (
                nullptr,
                4096,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE
            );
        auto const pointer = static_cast<std::uint8_t*>(memory);
        std::span span{ pointer, 4096 };
        // xor eax, eax; ret
        std::ranges::copy("\x31\xC0\xC3", span.begin());
        return span;
        })();
        inline static auto hasCode = false;
        inline static std::string errorMessage;

        static void* __fastcall execute(void* argument);
        static bool tryEmitCode(std::string_view source);
        static std::uint64_t makeKey(void* f, void* ecx);
        static std::string formatKey(std::uint64_t key);
    private:
        static void doEmitCode(std::string_view source);
    };

    struct FunctionProfileData
    {
        std::chrono::nanoseconds total;
        std::uintmax_t count;
    };
#endif // LANYI_ENABLE_CALL_EAX_EDX_PROFILER

    struct Data
    {
        int frame;
        std::size_t callCount;
        std::chrono::nanoseconds sum;
        std::chrono::nanoseconds average;
#if LANYI_ENABLE_STACK_TRACE
        void* caller1;
        std::chrono::nanoseconds caller1Count;
        void* caller2;
        std::chrono::nanoseconds caller2Count;
#endif // LANYI_ENABLE_STACK_TRACE
#if LANYI_ENABLE_EXTERNAL_MIDDLE_TIME
        std::chrono::nanoseconds externalTime1;
        std::chrono::nanoseconds externalTime2;
#endif // LANYI_ENABLE_EXTERNAL_MIDDLE_TIME
#if LANYI_ENABLE_CALL_EAX_EDX_PROFILER
        std::array<std::pair<std::uint64_t, FunctionProfileData>, 4> eax;
        std::array<std::pair<std::uint64_t, FunctionProfileData>, 4> edx;
#endif // LANYI_ENABLE_CALL_EAX_EDX_PROFILER
    };

#if LANYI_ENABLE_EXTERNAL_MIDDLE_TIME
    std::chrono::high_resolution_clock::time_point externalMiddleTime{};
#endif
#if LANYI_ENABLE_CALL_EAX_EDX_PROFILER
    auto thiscallEdxData
        = std::unordered_map<std::uint64_t, FunctionProfileData>{};
    auto thiscallEaxData
        = std::unordered_map<std::uint64_t, FunctionProfileData>{};
#endif // LANYI_ENABLE_CALL_EAX_EDX_PROFILER
    template<FunctionData Function, typename... Args>
    struct Profiler
    {
    public:
        using Nanosecond = std::chrono::nanoseconds;
        static auto constexpr name = Function::name;
        inline static auto useExternalTime = false;
        inline static auto profileCallEaxEdx = false;
    private:
        inline static auto m_currentFrameNumber = -1;
        inline static std::vector<Nanosecond> m_currentStats{};
#if LANYI_ENABLE_EXTERNAL_MIDDLE_TIME
        inline static Nanosecond m_externalTime1{};
        inline static Nanosecond m_externalTime2{};
#endif // LANYI_ENABLE_EXTERNAL_MIDDLE_TIME
#if LANYI_ENABLE_STACK_TRACE
        inline static std::unordered_map<void*, std::chrono::nanoseconds> m_currentCallers{};
#endif // LANYI_ENABLE_STACK_TRACE
        inline static std::mutex m_mutex{};
        inline static boost::circular_buffer<Data> m_allStats{ 10 };

    public:
        static std::uint32_t getThiscallAddress();
        static std::uint32_t getStdcallAddress();
        static std::uint32_t getCdeclAddress();
        static void render() noexcept;
    private:
        static void* __fastcall profileThiscall(void* ecx, void*, Args... args);
        static void* __stdcall profileStdcall(Args... args);
        static void* __cdecl profileCdecl(Args... args);
        static void recordStats(Nanosecond ns, void* returnAddress);
    };

#if LANYI_ENABLE_EXTERNAL_MIDDLE_TIME
    void* middleTimeMeasurerReturnSite = nullptr;
    void measureExternalMiddleTime()
    {
        externalMiddleTime = std::chrono::high_resolution_clock::now();
    }
    void __declspec(naked) measureExternalMiddleTimeTrampoline()
    {
        __asm
        {
            pushfd;
            push eax;
            push ecx;
            push edx;
            call measureExternalMiddleTime;
            pop edx;
            pop ecx;
            pop eax;
            popfd;
            jmp middleTimeMeasurerReturnSite;
        }
    }
#endif // LANYI_ENABLE_EXTERNAL_MIDDLE_TIME
#if LANYI_ENABLE_CALL_EAX_EDX_PROFILER
    std::uint64_t callEaxAddress{};
    std::uint64_t callEdxAddress{};
    std::chrono::high_resolution_clock::time_point beginCallEax{};
    std::chrono::high_resolution_clock::time_point beginCallEdx{};
    void* callEaxReturnSite = nullptr;
    void* callEdxReturnSite = nullptr;

    void beginMeasureCallEaxTime(void* function, void* ecx)
    {
        beginCallEax = std::chrono::high_resolution_clock::now();
        callEaxAddress = JitGetCallEaxEdxKey::makeKey(function, ecx);
    }

    void beginMeasureCallEdxTime(void* function, void* ecx)
    {
        beginCallEdx = std::chrono::high_resolution_clock::now();
        callEdxAddress = JitGetCallEaxEdxKey::makeKey(function, ecx);
    }

    void* __stdcall endMeasureCallEaxTime(void* returnValue)
    {
        auto const end = std::chrono::high_resolution_clock::now();
        auto const duration = end - beginCallEax;
        auto& [total, count] = thiscallEaxData[callEaxAddress];
        total += duration;
        ++count;
        return returnValue;
    }

    void* __stdcall endMeasureCallEdxTime(void* returnValue)
    {
        auto const end = std::chrono::high_resolution_clock::now();
        auto const duration = end - beginCallEdx;
        auto& [total, count] = thiscallEdxData[callEdxAddress];
        total += duration;
        ++count;
        return returnValue;
    }

    void __declspec(naked) profileThiscallEax()
    {
        __asm
        {
            push ecx;
            push eax;
            call beginMeasureCallEaxTime;
            pop eax;
            pop ecx;
            call eax;
            push eax;
            mov eax, endMeasureCallEaxTime;
            jmp callEaxReturnSite;
        }
    }

    void __declspec(naked) profileThiscallEdx()
    {
        __asm
        {
            push ecx;
            push edx;
            call beginMeasureCallEdxTime;
            pop edx;
            pop ecx;
            call edx;
            push eax;
            mov edx, endMeasureCallEdxTime;
            jmp callEdxReturnSite;
        }
    }
#endif // LANYI_ENABLE_CALL_EAX_EDX_PROFILER
}

namespace Lanyi::RA3EngineFixer
{
    struct Data0x8AF9E0
    {
        static auto constexpr name = "AITargetManager choose AIStrategicState stats";
        inline static auto address = 0x8AF9E0U;
    };
    struct Data0x6CAA60
    {
        static auto constexpr name = "0x6CAA60 stats";
        static auto constexpr address = 0x6CAA60U;
    };
    struct Data0x504E10
    {
        static auto constexpr name = "HashTable stats";
        inline static auto address = 0x504E10U;
    };
    struct Data0x86E410
    {
        static auto constexpr name = "0x86E410 stats";
        inline static auto address = 0x86E410U;
    };
    struct Data0x6C7A90
    {
        static auto constexpr name = "0x6C7A90 stats";
        static auto constexpr address = 0x6C7A90U;
    };
    struct Data0x8C4FB0
    {
        static auto constexpr name = "AIBuilder 0x8C4FB0 stats";
        inline static auto address = 0x8C4FB0U;
    };
    struct Data0x859E10
    {
        static auto constexpr name = "Main 0x859E10 stats";
        static auto constexpr address = 0x859E10U;
    };
    struct Data0x859D50
    {
        static auto constexpr name = "Main - 0x859D50 stats";
        static auto constexpr address = 0x859D50U;
        static auto constexpr callAddress = 0x859E33U;
        static auto constexpr callNextAddress = 0x859E37U;
    };
    struct Data0x9A3AB0
    {
        static auto constexpr name = "Main - 0x9A3AB0 stats";
        static auto constexpr address = 0x9A3AB0U;
        static auto constexpr callAddress = 0x859E9FU;
        static auto constexpr callNextAddress = 0x859EA3U;
    };
    struct Data0x5570D0
    {
        static auto constexpr name = "Main - 0x5570D0 stats";
        inline static auto address = 0x5570D0U;
    };
    struct Data0x519790
    {
        static auto constexpr name = "Main - 0x519790 stats";
        inline static auto address = 0x519790U;
    };
    struct DynamicData
    {
        static auto constexpr name = "Dynamic Profiler";
        inline static auto address = 0x0U;
    };

    using Profiler0x8AF9E0 = Profiler<Data0x8AF9E0, void*>;
    using Profiler0x6CAA60 = Profiler<Data0x6CAA60, void*>;
    using Profiler0x504E10 = Profiler<Data0x504E10, void*, void*>;
    using Profiler0x86E410 = Profiler<Data0x86E410, void*, void*, void*>;
    using Profiler0x6C7A90 = Profiler<Data0x6C7A90, void*>;
    using Profiler0x8C4FB0 = Profiler<Data0x8C4FB0, void*>;
    using Profiler0x859E10 = Profiler<Data0x859E10>;
    using DynamicProfiler0 = Profiler<DynamicData>;
    using DynamicProfiler1 = Profiler<DynamicData, void*>;
    using DynamicProfiler2 = Profiler<DynamicData, void*, void*>;
    using DynamicProfiler3 = Profiler<DynamicData, void*, void*, void*>;
    using DynamicProfiler4 = Profiler<DynamicData, void*, void*, void*, void*>;
    using DynamicProfiler5 = Profiler<DynamicData, void*, void*, void*, void*, void*>;
    using DynamicProfiler8 = Profiler<DynamicData, void*, void*, void*, void*, void*, void*, void*, void*>;
    void renderDynamic() noexcept;

    void* patchedInstructionGoBack = nullptr;
    void* patchedInstructionIfSuccess = nullptr;

    void __declspec(naked) patchedInstructions()
    {
        // jnz returnSuccess -> jmp patchInstructions
        __asm
        {
            mov eax, [ebp + 6E0h];

            // get eax
            mov eax, ebx;

            mov ecx, [eax];
            test ecx, ecx;
            jnz fail;
            cmp edi, ecx;
            jnz fail;
            // jmp to inner loop
            mov edx, patchedInstructionIfSuccess;
            jmp edx;
        fail:
            // back to normal
            mov eax, [ebp + 6E0h];
            mov edx, patchedInstructionGoBack;
            jmp edx;
        }
    }
    
    struct Node
    {
        std::uint32_t key;
        void* value;
        Node* next;
    };

    void __fastcall NoOp(void* /* ecx */, void*, void*)
    {}
    
    void applyAITargetManagerBakaPosition1Fix()
    {
        {
            auto const offset = Profiler0x8AF9E0::getThiscallAddress() - 0x8BE470U;
            writeMemory(reinterpret_cast<std::uint32_t*>(0x8BE46CU), offset);
        }
        {
            auto const offset = Profiler0x859E10::getThiscallAddress();
            writeMemory(reinterpret_cast<std::uint32_t*>(0xC5B9F4), offset);
        }

        [](char const* name, Lanyi::RA3Lua::SharedFunction* function) noexcept
        {
            {
                static auto callback = Profiler0x8AF9E0::getRenderCallback();
                static auto render = callback.render;
                callback.render = []() noexcept
                {
                    if (draw(DrawCommand::beginWindow, callback.id, -1))
                    {
                        auto currentType = "new";
                        auto otherAddress = 0x8AF9E0U;
                        if (Data0x8AF9E0::address == otherAddress)
                        {
                            currentType = "original";
                            auto const pointer = &AITargetManager::getRandomStrategy;
                            otherAddress = std::bit_cast<std::uint32_t>(pointer);
                        }
                        auto const name = std::format
                        (
                            "{} {:X}",
                            currentType,
                            Data0x8AF9E0::address
                        );
                        if (draw(DrawCommand::button, name.c_str(), -1))
                        {
                            Data0x8AF9E0::address = otherAddress;
                        }
                    }
                    draw(DrawCommand::endWindow, callback.id, -1);
                    render(customData, dx9Device, draw);
                };
                function(&callback);
            }
            /* {
                auto callback = Profiler0x6CAA60::getRenderCallback();
                function(&callback);
            }
            {
                auto callback = Profiler0x504E10::getRenderCallback();
                function(&callback);
            }
            {
                auto callback = Profiler0x6C7A90::getRenderCallback();
                function(&callback);
            }
            {
                auto callback = Profiler0x8C4FB0::getRenderCallback();
                function(&callback);
            } */
            {
                auto callback = Profiler0x859E10::getRenderCallback();
                function(&callback);
            }
            {
                auto callback = Lanyi::RA3LuaOutput::RenderCallback
                {
                    .id = DynamicData::name,
                    .render = renderDynamic,
                    .destroy = [](auto...) noexcept {},
                };
                function(&callback);
            }
        };
    }

    struct Input
    {
        char const* label = "Input";
        std::array<char, 10> buffer = { 0 };
        void* value = nullptr;

        void update()
        {
            if (Gui::inputText(label, buffer.data(), buffer.size()))
            {
                void* parsed = nullptr;
                if (std::sscanf(buffer.data(), "%p", &parsed) == 1)
                {
                    value = parsed;
                }
            }
        }
    };

    Input functionInput{ .label = "Function address" };
    Input middleHookInput{ .label = "Middle hook address" };
    Input callEaxInput{ .label = "Thiscall eax address" };
    Input callEdxInput{ .label = "Thiscall edx address" };
    std::array<char, 256> jitCodeInput{};
    void* currentAddress = nullptr;
    void* currentMiddleHookAddress = nullptr;
    void* currentCallEaxAddress = nullptr;
    void* currentCallEdxAddress = nullptr;
    void* currentOriginal = nullptr;
    void* currentHook = nullptr;
    decltype(&renderDynamic) currentRender = nullptr;
    bool* pUseExternalMiddleTime = nullptr;
    bool* pProfileCallEaxEdx = nullptr;

    void unhookMiddleTimeHook()
    {
#if LANYI_ENABLE_EXTERNAL_MIDDLE_TIME
        if (middleTimeMeasurerReturnSite != nullptr)
        {
            auto& original = middleTimeMeasurerReturnSite;
            auto const hook = &measureExternalMiddleTimeTrampoline;
            initData.unhookFunction(&original, hook);
            middleTimeMeasurerReturnSite = nullptr;
        }
        if (pUseExternalMiddleTime != nullptr)
        {
            *pUseExternalMiddleTime = false;
        }
        currentMiddleHookAddress = nullptr;
#endif
    }

    void unhookThiscallEax()
    {
#if LANYI_ENABLE_CALL_EAX_EDX_PROFILER
        if (callEaxReturnSite != nullptr)
        {
            auto& original = callEaxReturnSite;
            auto const hook = &profileThiscallEax;
            unhookFunction(&original, hook);
            callEaxReturnSite = nullptr;
        }
        currentCallEaxAddress = nullptr;
        if (pProfileCallEaxEdx != nullptr)
        {
            *pProfileCallEaxEdx = false;
        }
        JitGetCallEaxEdxKey::tryEmitCode({});
#endif // LANYI_ENABLE_CALL_EAX_EDX_PROFILER
    }

    void unhookThiscallEdx()
    {
#if LANYI_ENABLE_CALL_EAX_EDX_PROFILER
        if (callEdxReturnSite != nullptr)
        {
            auto& original = callEdxReturnSite;
            auto const hook = &profileThiscallEdx;
            unhookFunction(&original, hook);
            callEdxReturnSite = nullptr;
        }
        currentCallEdxAddress = nullptr;
        if (pProfileCallEaxEdx != nullptr)
        {
            *pProfileCallEaxEdx = false;
        }
        JitGetCallEaxEdxKey::tryEmitCode({});
#endif // LANYI_ENABLE_CALL_EAX_EDX_PROFILER
    }

    void unhook()
    {
        unhookMiddleTimeHook();
        unhookThiscallEax();
        unhookThiscallEdx();
        if (currentOriginal != nullptr)
        {
            unhookFunction(&currentOriginal, currentHook);
            DynamicData::address = 0;
            currentOriginal = nullptr;
        }
        currentAddress = nullptr;
        if (pUseExternalMiddleTime != nullptr)
        {
            *pUseExternalMiddleTime = false;
        }
        pUseExternalMiddleTime = nullptr;
        if (pProfileCallEaxEdx != nullptr)
        {
            *pProfileCallEaxEdx = false;
        }
        pProfileCallEaxEdx = nullptr;
    }

    void renderDynamic() noexcept
    {
        if (Gui::begin(DynamicData::name))
        {
            functionInput.update();
#if LANYI_ENABLE_EXTERNAL_MIDDLE_TIME
            middleHookInput.update();
#endif // LANYI_ENABLE_EXTERNAL_MIDDLE_TIME
#if LANYI_ENABLE_CALL_EAX_EDX_PROFILER
            callEaxInput.update();
            callEdxInput.update();
            if (pProfileCallEaxEdx != nullptr)
            {
                auto& input = jitCodeInput;
                if (Gui::button("Compile"))
                {
                    JitGetCallEaxEdxKey::tryEmitCode(input.data());
                }
                Gui::sameLine();
                Gui::inputText("Group by", input.data(), input.size());
                if (auto const& message = JitGetCallEaxEdxKey::errorMessage;
                    not message.empty())
                {
                    Gui::text(message);
                }
            }
#endif // LANYI_ENABLE_CALL_EAX_EDX_PROFILER
            auto const description = std::format
            (
                "Function: {}"
#if LANYI_ENABLE_EXTERNAL_MIDDLE_TIME
                ", Middle hook: {}"
#endif // LANYI_ENABLE_EXTERNAL_MIDDLE_TIME
#if LANYI_ENABLE_CALL_EAX_EDX_PROFILER
                ", Call eax: {}, Call edx: {}"
#endif // LANYI_ENABLE_CALL_EAX_EDX_PROFILER
                ,
                functionInput.value
#if LANYI_ENABLE_EXTERNAL_MIDDLE_TIME
                ,
                middleHookInput.value
#endif // LANYI_ENABLE_EXTERNAL_MIDDLE_TIME
#if LANYI_ENABLE_CALL_EAX_EDX_PROFILER
                ,
                callEaxInput.value,
                callEdxInput.value
#endif // LANYI_ENABLE_CALL_EAX_EDX_PROFILER
            );
            Gui::text(description);
#if LANYI_ENABLE_EXTERNAL_MIDDLE_TIME
            if (auto const currentInput = middleHookInput.value;
                currentMiddleHookAddress != currentInput
                and draw(DrawCommand::button, "Profile in middle of function", -1))
            {
                unhookMiddleTimeHook();
                if (pUseExternalMiddleTime != nullptr
                    and currentInput != nullptr)
                {
                    middleTimeMeasurerReturnSite = currentInput;
                    auto& original = middleTimeMeasurerReturnSite;
                    auto const hook = &measureExternalMiddleTimeTrampoline;
                    initData.hookFunction(&original, hook);
                    *pUseExternalMiddleTime = true;
                }
                currentMiddleHookAddress = currentInput;
            }
#endif
#if LANYI_ENABLE_CALL_EAX_EDX_PROFILER
#define LANYI_DECLARE_CALL_REGISTER_PROFILER(reg)                       \
    if (auto const currentInput = call##reg##Input.value;               \
        currentCall##reg##Address != currentInput                       \
        and Gui::button("Profile thiscall " #reg))                      \
    {                                                                   \
        unhookThiscall##reg();                                          \
        if (pProfileCallEaxEdx != nullptr                               \
            and currentInput != nullptr)                                \
        {                                                               \
            call##reg##ReturnSite = currentInput;                       \
            auto const hook = &profileThiscall##reg;                    \
            hookFunction(&call##reg##ReturnSite, hook);                 \
            *pProfileCallEaxEdx = true;                                 \
        }                                                               \
        currentCall##reg##Address = currentInput;                       \
    }                                                                   \
    "Require semicolon"
            LANYI_DECLARE_CALL_REGISTER_PROFILER(Eax);
            LANYI_DECLARE_CALL_REGISTER_PROFILER(Edx);
#undef LANYI_DECLARE_CALL_REGISTER_PROFILER
#endif // LANYI_ENABLE_CALL_EAX_EDX_PROFILER
#define LANYI_DECLARE_BUTTON(c, n)                                      \
    if (auto const currentInput = functionInput.value;                  \
        currentAddress != currentInput                                  \
        and Gui::button(#c #n))                                         \
    {                                                                   \
        unhook();                                                       \
        DynamicData::address = 0;                                       \
        currentOriginal = currentInput;                                 \
        currentRender = nullptr;                                        \
        if (currentOriginal != nullptr)                                 \
        {                                                               \
            auto const hook = DynamicProfiler##n :: get##c##Address();  \
            currentHook = reinterpret_cast<void*>(hook);                \
            hookFunction(&currentOriginal, currentHook);                \
            DynamicData::address                                        \
                = reinterpret_cast<std::uint32_t>(currentOriginal);     \
            pUseExternalMiddleTime                                      \
                = &DynamicProfiler##n ::useExternalTime;                \
            pProfileCallEaxEdx                                          \
                = &DynamicProfiler##n ::profileCallEaxEdx;              \
        }                                                               \
        currentAddress = currentInput;                                  \
        currentRender                                                   \
                = DynamicProfiler##n ::render;                          \
    }                                                                   \
    "Require semicolon"
            LANYI_DECLARE_BUTTON(Thiscall, 0);
            LANYI_DECLARE_BUTTON(Thiscall, 1);
            LANYI_DECLARE_BUTTON(Thiscall, 2);
            LANYI_DECLARE_BUTTON(Thiscall, 3);
            LANYI_DECLARE_BUTTON(Thiscall, 4);
            LANYI_DECLARE_BUTTON(Thiscall, 5);
            LANYI_DECLARE_BUTTON(Thiscall, 8);
            LANYI_DECLARE_BUTTON(Cdecl, 0);
            LANYI_DECLARE_BUTTON(Cdecl, 1);
            LANYI_DECLARE_BUTTON(Cdecl, 2);
            LANYI_DECLARE_BUTTON(Cdecl, 3);
            LANYI_DECLARE_BUTTON(Cdecl, 4);
            LANYI_DECLARE_BUTTON(Cdecl, 5);
#undef LANYI_DECLARE_BUTTON
#undef LANYI_UNHOOK
        }
        Gui::end();
        if (currentRender != nullptr)
        {
            currentRender();
        }
    }
}

#if LANYI_ENABLE_CALL_EAX_EDX_PROFILER
void* __fastcall JitGetCallEaxEdxKey::execute(void* argument)
{
    using F = decltype(execute);
    return reinterpret_cast<F*>(jitCode.data())(argument);
}

bool JitGetCallEaxEdxKey::tryEmitCode(std::string_view source)
{
    try
    {
        doEmitCode(source);
        errorMessage = {};
        return true;
    }
    catch (std::exception const& e)
    {
        hasCode = false;
        errorMessage = "ERROR: ";
        errorMessage += e.what();
        return false;
    }
}

std::uint64_t JitGetCallEaxEdxKey::makeKey(void* f, void* ecx)
{
    auto const fValue = std::bit_cast<std::uintptr_t>(f);
    auto const f64 = static_cast<std::uint64_t>(fValue);
    if (hasCode)
    {
        auto const low = std::bit_cast<std::uintptr_t>(execute(ecx));
        return (f64 << 32) bitor low;
    }
    return f64;
}

std::string JitGetCallEaxEdxKey::formatKey(std::uint64_t key)
{
    if (hasCode)
    {
        auto const high = static_cast<std::uint32_t>(key >> 32);
        auto const low = static_cast<std::uint32_t>(key);
        return std::format("{:X}-{:X}", high, low);
    }
    return std::format("{:X}", key);
}

void JitGetCallEaxEdxKey::doEmitCode(std::string_view source)
{
    struct SyntaxError : std::invalid_argument
    {
        SyntaxError(std::string_view source, char const* location) :
            std::invalid_argument{ message(source, location) }
        {}
        static std::string message(std::string_view s, char const* p)
        {
            auto line = 1;
            auto column = 0;
            for (auto const c : s.substr(0, (p - s.data()) + 1))
            {
                column = c == '\n' ? 0 : column + 1;
                line = c == '\n' ? line + 1 : line;
            }
            auto const hint = s.substr(std::max(0, p - s.data() - 4), 8);
            auto constexpr format
                = "Syntax error at line {}, column {} (near {}...)";
            return std::format(format, line, column, hint);
        }
    };
    enum class Status
    {
        none,
        offset,
    };
    std::vector<std::uint8_t> newCode{};
    auto status = Status::none;
    std::string number{};
    for (auto const character : source)
    {
        if (std::isspace(character))
        {
            continue;
        }
        switch (status)
        {
        case Status::none:
            if (character != '[')
            {
                throw SyntaxError{ source, &character };
            }
            status = Status::offset;
            number = {};
            continue;
        case Status::offset:
            if (character == ']')
            {
                auto const offset = ([&]
                {
                    try
                {
                    return std::stol(number, nullptr, 0);
                }
                catch (...)
                {
                    throw SyntaxError{ source, &character };
                }
                })();
                static_assert(sizeof(offset) == sizeof(std::uint32_t));
                auto const isLong
                    = (static_cast<std::uint32_t>(offset) >> 8) != 0;
                using namespace std::literals;
                auto code = "\x85\xC0\x75\x01\xC3\x8B\x40"s;
                code.at(6) += isLong ? 0x40 : 0;
                auto const pointer = reinterpret_cast<char const*>(&offset);
                code.append(pointer, isLong ? 4 : 1);
                if (newCode.empty())
                {
                    newCode = { 0x89U, 0xC8U }; // mov eax, ecx
                }
                std::ranges::copy(code, std::back_inserter(newCode));
                status = Status::none;
                continue;
            }
            number += character;
        }
    }
    hasCode = not newCode.empty();
    if (newCode.empty())
    {
        newCode = { 0x31U, 0xC0U }; // xor eax, eax
    }
    newCode.push_back(0xC3U);
    if (newCode.size() > jitCode.size())
    {
        throw std::out_of_range{ "new code too large" };
    }
    std::ranges::copy(newCode, jitCode.begin());
    FlushInstructionCache(GetCurrentProcess(), nullptr, 0);
}
#endif // LANYI_ENABLE_CALL_EAX_EDX_PROFILER

template<FunctionData Function, typename... Args>
std::uint32_t Profiler<Function, Args...>::getThiscallAddress()
{
    return reinterpret_cast<std::uint32_t>(&profileThiscall);
}

template<FunctionData Function, typename... Args>
std::uint32_t Profiler<Function, Args...>::getStdcallAddress()
{
    return reinterpret_cast<std::uint32_t>(&profileStdcall);
}

template<FunctionData Function, typename... Args>
std::uint32_t Profiler<Function, Args...>::getCdeclAddress()
{
    return reinterpret_cast<std::uint32_t>(&profileCdecl);
}

template<FunctionData Function, typename... Args>
void Profiler<Function, Args...>::render() noexcept
{
    using Millisecond = std::chrono::duration<double, std::milli>;
    if (ImGui::Begin(name))
    {
        Millisecond sums{};
        Millisecond externalTime1Sum{};
        Millisecond externalTime2Sum{};
        {
            std::scoped_lock lock{ m_mutex };
            for (auto const& data : m_allStats)
            {
                sums += data.sum;
#if LANYI_ENABLE_EXTERNAL_MIDDLE_TIME
                externalTime1Sum += data.externalTime1;
                externalTime2Sum += data.externalTime2;
#endif // LANYI_ENABLE_EXTERNAL_MIDDLE_TIME
                auto text = std::format
                (
                    "Frame: {}, sum: {}, avg: {}, count: {}"
#if LANYI_ENABLE_STACK_TRACE
                    "; caller1: {} ({}), caller2: {} ({})"
#endif // LANYI_ENABLE_STACK_TRACE
                    ,
                    data.frame,
                    Millisecond{ data.sum },
                    data.average,
                    data.callCount
#if LANYI_ENABLE_STACK_TRACE
                    ,
                    data.caller1,
                    Millisecond{ data.caller1Count },
                    data.caller2,
                    Millisecond{ data.caller2Count }
#endif // LANYI_ENABLE_STACK_TRACE
                );
#if LANYI_ENABLE_EXTERNAL_MIDDLE_TIME
                if (useExternalTime)
                {
                    text += std::format
                    (
                        "; ext1: {}, ext2: {}",
                        Millisecond{ data.externalTime1 },
                        Millisecond{ data.externalTime2 }
                    );
                }
#endif // LANYI_ENABLE_EXTERNAL_MIDDLE_TIME
#if LANYI_ENABLE_CALL_EAX_EDX_PROFILER
                if (profileCallEaxEdx)
                {
#define LANYI_FORMAT_CALL_EAX_EDX_ITEM(reg, n)                          \
    JitGetCallEaxEdxKey::formatKey(data.reg[n].first),                  \
    Millisecond{ data.reg[n].second.total },                            \
    data.reg[n].second.count,                                           \
    Millisecond{ data.reg[n].second.total } / data.reg[n].second.count
                    if (callEaxReturnSite != nullptr)
                    {
                        text += std::format
                        (
                            ";\n"
                            "EAX: #1 {} {} {} avg {}, #2 {} {} {} avg {},\n"
                            "     #3 {} {} {} avg {}, #4 {} {} {} avg {}",
                            LANYI_FORMAT_CALL_EAX_EDX_ITEM(eax, 0),
                            LANYI_FORMAT_CALL_EAX_EDX_ITEM(eax, 1),
                            LANYI_FORMAT_CALL_EAX_EDX_ITEM(eax, 2),
                            LANYI_FORMAT_CALL_EAX_EDX_ITEM(eax, 3)
                        );
                    }
                    if (callEdxReturnSite != nullptr)
                    {
                        text += std::format
                        (
                            ";\n"
                            "EDX: #1 {} {} {} avg {}, #2 {} {} {} avg {},\n"
                            "     #3 {} {} {} avg {}, #4 {} {} {} avg {}",
                            LANYI_FORMAT_CALL_EAX_EDX_ITEM(edx, 0),
                            LANYI_FORMAT_CALL_EAX_EDX_ITEM(edx, 1),
                            LANYI_FORMAT_CALL_EAX_EDX_ITEM(edx, 2),
                            LANYI_FORMAT_CALL_EAX_EDX_ITEM(edx, 3)
                        );
                    }
#undef LANYI_FORMAT_CALL_EAX_EDX_ITEM
                }
#endif // LANYI_ENABLE_CALL_EAX_EDX_PROFILER
                draw(DrawCommand::text, text.c_str(), text.size());
            }
        }
        auto const averageSum = sums / m_allStats.size();
        auto averageSumText = std::format
        (
            "Total per logical frame (average): {}; ({:.3f}% of frame)",
            averageSum,
            averageSum.count() / (1000.0 / 15) * 100
        );
#if LANYI_ENABLE_EXTERNAL_MIDDLE_TIME
        if (useExternalTime)
        {
            auto const averageExternalTime1Sum = externalTime1Sum / m_allStats.size();
            auto const averageExternalTime2Sum = externalTime2Sum / m_allStats.size();
            averageSumText += std::format
            (
                "; avg ext1 {}, ext2 {}",
                averageExternalTime1Sum,
                averageExternalTime2Sum
            );
        }
#endif // LANYI_ENABLE_EXTERNAL_MIDDLE_TIME
        draw(DrawCommand::text, averageSumText.c_str(), averageSumText.size());
    }
    draw(DrawCommand::endWindow, {}, {});
}

template<FunctionData Function, typename... Args>
void* __fastcall Profiler<Function, Args...>::
profileThiscall(void* ecx, void*, Args... args)
{
    using F = decltype(profileThiscall);
    auto const begin = std::chrono::high_resolution_clock::now();
#if LANYI_ENABLE_EXTERNAL_MIDDLE_TIME
    if (useExternalTime)
    {
        externalMiddleTime = begin;
    }
#endif // LANYI_ENABLE_EXTERNAL_MIDDLE_TIME
    auto result = reinterpret_cast<F*>(Function::address)(ecx, 0, args...);
    auto const end = std::chrono::high_resolution_clock::now();
#if LANYI_ENABLE_EXTERNAL_MIDDLE_TIME
    if (useExternalTime)
    {
        m_externalTime1 += (externalMiddleTime - begin);
        m_externalTime2 += (end - externalMiddleTime);
    }
#endif // LANYI_ENABLE_EXTERNAL_MIDDLE_TIME
    recordStats(end - begin, _ReturnAddress());
    return result;
}

template<FunctionData Function, typename... Args>
void* __stdcall Profiler<Function, Args...>::
profileStdcall(Args... args)
{
    using F = decltype(profileStdcall);
    auto const begin = std::chrono::high_resolution_clock::now();
#if LANYI_ENABLE_EXTERNAL_MIDDLE_TIME
    if (useExternalTime)
    {
        externalMiddleTime = begin;
    }
#endif // LANYI_ENABLE_EXTERNAL_MIDDLE_TIME
    auto result = reinterpret_cast<F*>(Function::address)(args...);
    auto const end = std::chrono::high_resolution_clock::now();
#if LANYI_ENABLE_EXTERNAL_MIDDLE_TIME
    if (useExternalTime)
    {
        m_externalTime1 += (externalMiddleTime - begin);
        m_externalTime2 += (end - externalMiddleTime);
    }
#endif // LANYI_ENABLE_EXTERNAL_MIDDLE_TIME
    recordStats(end - begin, _ReturnAddress());
    return result;
}

template<FunctionData Function, typename... Args>
void* __cdecl Profiler<Function, Args...>::
profileCdecl(Args... args)
{
    using F = decltype(profileCdecl);
    auto const begin = std::chrono::high_resolution_clock::now();
#if LANYI_ENABLE_EXTERNAL_MIDDLE_TIME
    if (useExternalTime)
    {
        externalMiddleTime = begin;
    }
#endif // LANYI_ENABLE_EXTERNAL_MIDDLE_TIME
    auto result = reinterpret_cast<F*>(Function::address)(args...);
    auto const end = std::chrono::high_resolution_clock::now();
#if LANYI_ENABLE_EXTERNAL_MIDDLE_TIME
    if (useExternalTime)
    {
        m_externalTime1 += (externalMiddleTime - begin);
        m_externalTime2 += (end - externalMiddleTime);
    }
#endif // LANYI_ENABLE_EXTERNAL_MIDDLE_TIME
    recordStats(end - begin, _ReturnAddress());
    return result;
}

template<FunctionData Function, typename... Args>
void Profiler<Function, Args...>::
recordStats(Nanosecond ns, void* returnAddress)
{
    auto const gameLogic = reinterpret_cast<int**>(0xCD8CE4)[0];
    if (gameLogic == nullptr)
    {
        return;
    }
    auto const frameNumber = gameLogic[0x50 / sizeof(int)];
    if (m_currentFrameNumber == frameNumber)
    {
        // record stats in same frame
        m_currentStats.push_back(ns);
#if LANYI_ENABLE_STACK_TRACE
        m_currentCallers[returnAddress] += ns;
#endif // LANYI_ENABLE_STACK_TRACE
        return;
    }
    // new frame
    auto const previousFrameNumber = m_currentFrameNumber;
    m_currentFrameNumber = frameNumber;
    if (m_currentStats.empty())
    {
        return;
    }
    // save data if previous frame has data
    auto const total = std::accumulate
    (
        m_currentStats.begin(),
        m_currentStats.end(),
        Nanosecond{}
    );
    auto const callCount = m_currentStats.size();
    auto const average = total / callCount;
#if LANYI_ENABLE_STACK_TRACE
    void* firstCaller = nullptr;
    Nanosecond firstCallerCount{};
    void* secondCaller = nullptr;
    Nanosecond secondCallerCount{};
    for (auto const& [caller, count] : m_currentCallers)
    {
        if (count > firstCallerCount)
        {
            secondCaller = firstCaller;
            secondCallerCount = firstCallerCount;
            firstCaller = caller;
            firstCallerCount = count;
        }
        else if (count > secondCallerCount)
        {
            secondCaller = caller;
            secondCallerCount = count;
        }
    }
#endif // LANYI_ENABLE_STACK_TRACE
    m_currentStats.clear();
#if LANYI_ENABLE_STACK_TRACE
    m_currentCallers.clear();
#endif // LANYI_ENABLE_STACK_TRACE
    // set new frame's data
    m_currentStats.push_back(ns);
#if LANYI_ENABLE_STACK_TRACE
    ++m_currentCallers[returnAddress];
#endif // LANYI_ENABLE_STACK_TRACE
    // save previous frame's data
    auto data = Data
    {
        .frame = previousFrameNumber,
        .callCount = callCount,
        .sum = total,
        .average = average,
#if LANYI_ENABLE_STACK_TRACE
        .caller1 = firstCaller,
        .caller1Count = firstCallerCount,
        .caller2 = secondCaller,
        .caller2Count = secondCallerCount
#endif // LANYI_ENABLE_STACK_TRACE
    };
#if LANYI_ENABLE_EXTERNAL_MIDDLE_TIME
    if (useExternalTime)
    {
        data.externalTime1 = m_externalTime1;
        data.externalTime2 = m_externalTime2;
        m_externalTime1 = {};
        m_externalTime2 = {};
    }
#endif // LANYI_ENABLE_EXTERNAL_MIDDLE_TIME
#if LANYI_ENABLE_CALL_EAX_EDX_PROFILER
    if (profileCallEaxEdx)
    {
        for (auto& functionData : thiscallEaxData)
        {
            static_assert(data.eax.size() > 1);
            auto& [key, measuredData] = functionData;
            for (auto it = data.eax.begin(); it != data.eax.end(); ++it)
            {
                if (measuredData.total > it->second.total)
                {
                    std::copy_backward(it, data.eax.end() - 1, data.eax.end());
                    *it = functionData;
                    break;
                }
            }
            measuredData = {};
        }
        for (auto& functionData : thiscallEdxData)
        {
            static_assert(data.edx.size() > 1);
            auto& [key, measuredData] = functionData;
            for (auto it = data.edx.begin(); it != data.edx.end(); ++it)
            {
                if (measuredData.total > it->second.total)
                {
                    std::copy_backward(it, data.edx.end() - 1, data.edx.end());
                    *it = functionData;
                    break;
                }
            }
            measuredData = {};
        }
    }
#endif // LANYI_ENABLE_CALL_EAX_EDX_PROFILER
    std::scoped_lock lock{ m_mutex };
    m_allStats.push_back(data);
}