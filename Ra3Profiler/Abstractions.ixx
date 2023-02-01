module;
#include <Windows.h>
#include <detours/detours.h>
#include <imgui.h>
#include <cstdlib>
#include <string_view>
export module Lanyi.Ra3Profiler.Abstractions;

export namespace Lanyi::Ra3Profiler::Abstractions
{
    void writeMemory(void* data, std::size_t size);
    void hookFunction(void** target, void* replacement);
    void unhookFunction(void** hookedTarget, void* replacement);
}

export namespace Lanyi::Ra3Profiler::Abstractions::Gui
{
    bool begin(char const* label);
    void end();
    bool button(char const* label);
    bool inputText(char const* label, char* data, std::size_t size);
    void sameLine();
    void text(std::string_view text);
}