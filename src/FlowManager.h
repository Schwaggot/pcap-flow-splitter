#ifndef PCAP_FLOW_SPLITTER_FLOWMANAGER_H
#define PCAP_FLOW_SPLITTER_FLOWMANAGER_H

#include "Config.h"
#include "Flow.h"
#include "FlowId.h"
#include "Packet.h"
#include <chrono>
#include <cstdint>
#include <string>
#include <unordered_map>

class FlowManager {
public:
    FlowManager(const Config& config);
    ~FlowManager();

    void onPacket(const Packet& packet, const mmpr::Packet& mmprPacket);
    void emit();

    std::unordered_map<FlowId, Flow> flows;
    std::vector<Flow> timedOutFlows;
    std::vector<Flow> finishedTcpFlows;

private:
    void createOutputFile(const Flow& flow);
    void
    writePacket(const Flow& flow, const Packet& packet, const mmpr::Packet& mmprPacket);

    const Config& config;
    pcap_t* pcapHandleNonIp;
    pcap_dumper_t* pcapDumperNonIp;
    std::vector<pcap_t*> pcapHandles;
    std::vector<pcap_dumper_t*> pcapDumpers;
};

#endif // PCAP_FLOW_SPLITTER_FLOWMANAGER_H
