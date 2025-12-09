cmake_minimum_required(VERSION 3.10)
project(renef_agent C)

# Agent source files
set(AGENT_SOURCES
    agent.c
    core/globals.c
    hook/hook.c
    hook/hook_java.c
    proc/proc.c
    handlers/cmd_eval.c
    handlers/cmd_inspect.c
    handlers/cmd_memscan.c
    lua/engine/lua_engine.c
    lua/hook/lua_hook.c
    lua/memory/lua_memory.c
)

# Build the agent shared library
add_library(renef_agent SHARED ${AGENT_SOURCES})

# Include directories
target_include_directories(renef_agent PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Output name
set_target_properties(renef_agent PROPERTIES OUTPUT_NAME "renef_agent")

# Link libraries
target_link_libraries(renef_agent log)
