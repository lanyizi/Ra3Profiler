module;
#include <memory>
#include <source_location>
#include <string>
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