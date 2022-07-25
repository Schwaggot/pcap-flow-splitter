#ifndef PCAP_FLOW_SPLITTER_PACKET_H
#define PCAP_FLOW_SPLITTER_PACKET_H

#include "FlowId.h"
#include "sole.hpp"
#include "tins/ip_address.h"
#include "tins/ipv6_address.h"
#include <chrono>
#include <variant>

class Packet {
public:
    std::chrono::microseconds timestamp;
    uint16_t length;
    bool nonIP = true;
    sole::uuid traceSource;
    std::variant<Tins::IPv4Address, Tins::IPv6Address> srcIp;
    std::variant<Tins::IPv4Address, Tins::IPv6Address> dstIp;
    uint16_t srcPort;
    uint16_t dstPort;

    struct Flags {
        bool FIN = false;
    } flags{};

    std::optional<FlowId> flowId() const {
        if (!nonIP) {
            return FlowId(traceSource, srcIp, srcPort, dstIp, dstPort);
        } else {
            return std::nullopt;
        }
    }
};

#endif // PCAP_FLOW_SPLITTER_PACKET_H
