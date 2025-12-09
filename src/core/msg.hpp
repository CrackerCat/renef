#pragma once

#include <cstdint>
#include <vector>

// Framing: [magic(4)][cmd(1)][len(4)][payload...]

#pragma pack(push, 1)
struct message_header {
    char magic[4];      // 'J','R','E','V'
    std::uint8_t cmd;   // command type
    std::uint32_t len;  // payload length (network byte order)
};
#pragma pack(pop)

struct message {
    message_header hdr;
    std::vector<std::uint8_t> payload;
};

enum : std::uint8_t {
    CMD_JR_COMMAND = 0x01,
    CMD_JR_RESULT  = 0x02,
};
