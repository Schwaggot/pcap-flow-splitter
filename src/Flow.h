#ifndef PCAP_FLOW_SPLITTER_FLOW_H
#define PCAP_FLOW_SPLITTER_FLOW_H

#include "FlowId.h"
#include "Packet.h"
#include "mmpr/mmpr.h"
#include <chrono>
#include <iostream>
#include <memory>
#include <pcap/pcap.h>
#include <vector>

class Flow {
public:
    Flow(size_t index) : index(index) {}

    void onPacket(const Packet& packet) {
        assert(!packet.nonIP);

        flowId = *packet.flowId();

        if (firstTimestamp.count() == 0) {
            firstTimestamp = packet.timestamp;
        }
        lastTimestamp = packet.timestamp;

        packets += 1;
        bytes += packet.length;

        if (packet.tcp) {
            tcpFlags.SYN += packet.tcpFlags.SYN;
            tcpFlags.ACK += packet.tcpFlags.ACK;
            tcpFlags.FIN += packet.tcpFlags.FIN;
            tcpFlags.RST += packet.tcpFlags.RST;
        }
    }

    bool operator==(const Flow& rhs) const { return flowId == rhs.flowId; }
    bool operator!=(const Flow& rhs) const { return !(rhs == *this); }
    bool operator<(const Flow& rhs) const { return flowId < rhs.flowId; }

    size_t index;
    FlowId flowId;
    std::chrono::microseconds firstTimestamp = std::chrono::microseconds::zero();
    std::chrono::microseconds lastTimestamp = std::chrono::microseconds::zero();
    uint64_t packets = 0;
    uint64_t bytes = 0;

    struct {
        uint16_t SYN = 0;
        uint16_t ACK = 0;
        uint16_t FIN = 0;
        uint16_t RST = 0;
    } tcpFlags{};
};

#endif // PCAP_FLOW_SPLITTER_FLOW_H
