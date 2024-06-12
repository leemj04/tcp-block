#pragma once

#include <arpa/inet.h>

struct TcpHdr final {
    u_int16_t sport_;
    u_int16_t dport_;
    u_int32_t seq_;
    u_int32_t ack_;
    u_int8_t hlen_;
    u_int8_t flags_;
    u_int16_t win_;
    u_int16_t sum_;
    u_int16_t urp_;

    u_int16_t sport() { return ntohs(sport_); }
    u_int16_t dport() { return ntohs(dport_); }
    u_int8_t header_len() { return (hlen_ >> 4) * 4; }

    // Flag(flags_)
    enum: u_int8_t {
        FIN = 0x01,
        SYN = 0x02,
        RST = 0x04,
        PSH = 0x08,
        ACK = 0x10,
        URG = 0x20
    };
};

struct pseudo_header final {
   unsigned int source_address;
   unsigned int dest_address;
   unsigned char placeholder;
   unsigned char protocol;
   unsigned short tcp_length;
};