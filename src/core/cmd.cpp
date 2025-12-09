#include "cmd.h"
#include <iostream>
#include <cstring>
#include <unistd.h>
#include "cmds/ping/ping.h"
#include "cmds/attach/attach.h"
#include "cmds/list/la.h"
#include "cmds/spawn/spawn.h"
#include "cmds/inspect/ib.h"
#include "cmds/eval/eval.h"
#include "cmds/load/load.h"
#include "cmds/watch/watch.h"
#include "cmds/memscan/memscan.h"
#include "cmds/hooks/hooks.h"
#include "cmds/sec/sec.h"
#include "cmds/memdump/memdump.h"
#include "cmds/hookgen/hookgen.h"

void CommandRegistry::register_command(std::unique_ptr<CommandDispatcher> cmd) {
    if (!cmd) {
        std::cerr << "ERROR: Trying to register null command\n";
        return;
    }

    std::string name = cmd->get_name();
    commands[name] = std::move(cmd);

}

std::vector<std::pair<std::string, std::string>> 
CommandRegistry::get_all_commands_with_descriptions() const {
    std::vector<std::pair<std::string, std::string>> result;
    
    for (const auto& [name, cmd] : commands) {
        result.push_back({
            cmd->get_name(), 
            cmd->get_description()
        });
    }
    
    return result;
}

CommandResult CommandRegistry::dispatch(int client_fd, const char* cmd_buffer, size_t cmd_size) {
    if (!cmd_buffer || cmd_size == 0) {
        return CommandResult(false, "Empty command");
    }

    std::string full_cmd(cmd_buffer, cmd_size);


    while (!full_cmd.empty() && (full_cmd.back() == '\n' || full_cmd.back() == '\r' || full_cmd.back() == ' ' || full_cmd.back() == '\0')) {
        full_cmd.pop_back();
    }


    const std::string prefix = "renef://";

    if (full_cmd.find(prefix) == 0) {
        full_cmd = full_cmd.substr(prefix.length());
    }

    std::string cmd_name;
    size_t delim_pos = full_cmd.find("//");
    if (delim_pos != std::string::npos) {
        cmd_name = full_cmd.substr(0, delim_pos);
    } else {
        size_t space_pos = full_cmd.find(' ');
        size_t tilde_pos = full_cmd.find('~');
        size_t split_pos = std::string::npos;

        if (space_pos != std::string::npos && tilde_pos != std::string::npos) {
            split_pos = std::min(space_pos, tilde_pos);
        } else if (space_pos != std::string::npos) {
            split_pos = space_pos;
        } else if (tilde_pos != std::string::npos) {
            split_pos = tilde_pos;
        }

        if (split_pos != std::string::npos) {
            cmd_name = full_cmd.substr(0, split_pos);
        } else {
            cmd_name = full_cmd;
        }
    }


    for (char c : cmd_name) {
        printf("%02x ", (unsigned char)c);
    }
    std::cout << "\n";
    for (const auto& pair : commands) {
        std::cout << "'" << pair.first << "' (len=" << pair.first.length() << ") ";
    }
    std::cout << "\n";

    auto it = commands.find(cmd_name);
    if (it == commands.end()) {
        const char* error_msg = "ERROR: Unknown command. Type 'help' for available commands.\n";
        write(client_fd, error_msg, strlen(error_msg));
        return CommandResult(false, "Unknown command: " + cmd_name);
    }

    return it->second->dispatch(client_fd, cmd_buffer, cmd_size);
}

void CommandRegistry::setup_all_commands() {

    register_command(std::make_unique<PingCommand>());
    register_command(std::make_unique<AttachCommand>());
    register_command(std::make_unique<SpawnCommand>());
    register_command(std::make_unique<ListAppsCommand>());
    register_command(std::make_unique<InspectBinary>());
    register_command(std::make_unique<Eval>());
    register_command(std::make_unique<LoadScriptCommand>());
    register_command(std::make_unique<WatchCommand>());
    register_command(std::make_unique<MemScan>());
    register_command(std::make_unique<MemScanJson>());
    register_command(std::make_unique<HooksCommand>());
    register_command(std::make_unique<UnhookCommand>());
    register_command(std::make_unique<SecCommand>());
    register_command(std::make_unique<MemDumpCommand>());
    register_command(std::make_unique<HookGen>());
}

bool CommandRegistry::is_command_exist(const std::string& name) {
    if (commands.find(name) != commands.end()) {
        return true;
    }
    return false;
}

int CommandRegistry::get_current_pid() const {
    return current_pid;
}
void CommandRegistry::set_current_pid(int pid) {
    if (current_pid > 0 && pid != current_pid) {
        sock.close_connection();
    }
    current_pid = pid;
}

SocketHelper& CommandRegistry::get_socket_helper() {
    return sock;
}