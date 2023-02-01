module;
#include <Windows.h>
#include <iostream>
export module Injector;
import Lanyi.Ra3Profiler.Injection;

export int main()
{
    // https://stackoverflow.com/a/45622802
    // Set console code page to UTF-8 so console known how to interpret string data
    SetConsoleOutputCP(CP_UTF8);
    // Enable buffering to prevent VS from chopping up UTF-8 byte sequences
    std::setvbuf(stdout, nullptr, _IOFBF, 1000);
    
    Lanyi::Ra3Profiler::inject("Test!", [](char const* text)
    {
        std::cout << text << std::endl;
    });
    return 0;
}