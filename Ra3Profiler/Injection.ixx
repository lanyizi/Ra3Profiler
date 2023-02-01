export module Lanyi.Ra3Profiler.Injection;

export namespace Lanyi::Ra3Profiler
{
    using TextWriter = void(void* context, char const* text);
    template<typename Callable>
    concept GenericTextWriter = requires(Callable callable)
    {
        callable("");
    };

#ifdef LANYI_RA3PROFILER_BUILDING_DLL
    __declspec(dllexport)
#else
    __declspec(dllimport)
#endif
        void inject
        (
            char const* input,
            void* loggerContext,
            TextWriter* logger
        );

    template<GenericTextWriter Logger>
    void inject(char const* input, Logger&& logger);
}

template<Lanyi::Ra3Profiler::GenericTextWriter Logger>
void Lanyi::Ra3Profiler::inject<Logger>(char const* input, Logger&& logger)
{
    auto wrapper = [&logger](char const* text) { return logger(text); };
    return inject(input , &wrapper, [](void* c, char const* text)
    {
        return (*static_cast<decltype(&wrapper)>(c))(text);
    });
}