#ifndef PCAP_FLOW_SPLITTER_PACKET_H
#define PCAP_FLOW_SPLITTER_PACKET_H

#include "FlowId.h"
#include "sole.hpp"
#include "tins/ip_address.h"
#include "tins/ipv6_address.h"
#include "tins/tcp.h"
#include <chrono>
#include <variant>

class Packet {
public:
    std::chrono::microseconds timestamp;
    uint16_t length;
    bool nonIP = true;
    bool tcp = false;
    sole::uuid traceSource;
    std::variant<Tins::IPv4Address, Tins::IPv6Address> srcIp;
    std::variant<Tins::IPv4Address, Tins::IPv6Address> dstIp;
    uint16_t srcPort;
    uint16_t dstPort;

    struct {
        bool SYN = false;
        bool ACK = false;
        bool FIN = false;
        bool RST = false;
    } tcpFlags{};

    std::optional<FlowId> flowId() const {
        if (!nonIP) {
            return FlowId(traceSource, srcIp, srcPort, dstIp, dstPort);
        } else {
            return std::nullopt;
        }
    }

    void setTCPFlags(Tins::TCP* pdu) {
        tcpFlags.SYN = pdu->get_flag(Tins::TCP::SYN);
        tcpFlags.ACK = pdu->get_flag(Tins::TCP::ACK);
        tcpFlags.FIN = pdu->get_flag(Tins::TCP::FIN);
        tcpFlags.RST = pdu->get_flag(Tins::TCP::RST);
    }
};

#endif // PCAP_FLOW_SPLITTER_PACKET_H
