# Dependencies
find_path(DETOURS_INCLUDE_DIRS "detours/detours.h")
find_library(DETOURS_LIBRARY detours REQUIRED)
# find_package(Boost REQUIRED)
find_package(fmt CONFIG REQUIRED)
find_package(wil CONFIG REQUIRED)

target_sources(Ra3Profiler PUBLIC "Injection.ixx")
target_sources(Ra3Profiler PRIVATE "Injection.cpp" "Abstractions.ixx" "Gui.ixx" "Profiler.ixx")
target_compile_definitions(Ra3Profiler PRIVATE LANYI_RA3PROFILER_BUILDING_DLL=1)
target_include_directories(Ra3Profiler PRIVATE 
	${CPP_HTTPLIB_INCLUDE_DIRS}
	${DETOURS_INCLUDE_DIRS}
)
target_link_libraries(Ra3Profiler PRIVATE
	${DETOURS_LIBRARY}
    # Boost::boost
    fmt::fmt
	WIL::WIL
)