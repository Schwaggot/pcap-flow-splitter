#include "FlowManager.h"
#include "emitter/StdOutEmitter.h"

#include <boost/filesystem.hpp>

using namespace std;

static uint64_t counter = 0;

FlowManager::FlowManager(const Config& config) : config(config) {
    if (config.dryRun) {
        return;
    }

    if (!boost::filesystem::exists(config.outputDirectory)) {
        boost::filesystem::create_directories(config.outputDirectory);
    }

    auto filename = "non-ip_flows.pcap";
    auto filepath = boost::filesystem::path(config.outputDirectory) / filename;

    pcapHandleNonIp = pcap_open_dead(DLT_EN10MB, 1 << 16);
    pcapDumperNonIp = pcap_dump_open(pcapHandleNonIp, filepath.c_str());
}

FlowManager::~FlowManager() {
    for (const auto& pcapDumper : pcapDumpers) {
        pcap_dump_close(pcapDumper);
    }
    for (const auto& pcapHandle : pcapHandles) {
        pcap_close(pcapHandle);
    }
}

void FlowManager::onPacket(const Packet& packet, const mmpr::Packet& mmprPacket) {
    if (packet.nonIP) {
        struct pcap_pkthdr pcapPacketHeader;
        pcapPacketHeader.caplen = packet.length;
        pcapPacketHeader.len = pcapPacketHeader.caplen;
        pcapPacketHeader.ts.tv_sec = mmprPacket.timestampSeconds;
        pcapPacketHeader.ts.tv_usec = mmprPacket.timestampMicroseconds;
        if (!config.dryRun) {
            pcap_dump((u_char*)pcapDumperNonIp, &pcapPacketHeader, mmprPacket.data);
        }
        return;
    }

    FlowId flowId = *packet.flowId();

    // lookup if flow already exists
    auto it = flows.find(flowId);
    if (it != flows.end()) {
        if ((packet.timestamp - it->second.lastTimestamp) > config.flowTimeout) {
            // on access timeout
            timedOutFlows.push_back(it->second);
            flows.erase(it->first);

            Flow flow(counter++);
            createOutputFile(flow);
            writePacket(flow, packet, mmprPacket);
            flow.onPacket(packet);
            flows.insert(make_pair(flowId, flow));
        } else {
            // update flow
            Flow flow = it->second;
            flow.onPacket(packet);
            writePacket(flow, packet, mmprPacket);
            flows.insert_or_assign(flowId, flow);
        }
    } else {
        Flow flow(counter++);
        createOutputFile(flow);
        writePacket(flow, packet, mmprPacket);
        flow.onPacket(packet);
        flows.insert(make_pair(flowId, flow));
    }
}

void FlowManager::createOutputFile(const Flow& flow) {
    if (config.dryRun) {
        return;
    }

    auto filename = "flow_" + to_string(flow.index) + ".pcap";
    auto filepath = boost::filesystem::path(config.outputDirectory) / filename;

    auto pcapHandle = pcap_open_dead(DLT_EN10MB, 1 << 16);
    auto pcapDumper = pcap_dump_open(pcapHandle, filepath.c_str());
    pcapHandles.push_back(pcapHandle);
    pcapDumpers.push_back(pcapDumper);
}

void FlowManager::writePacket(const Flow& flow,
                              const Packet& packet,
                              const mmpr::Packet& mmprPacket) {
    if (config.dryRun) {
        return;
    }

    auto pcapDumper = pcapDumpers[flow.index];

    struct pcap_pkthdr pcapPacketHeader;
    pcapPacketHeader.caplen = packet.length;
    pcapPacketHeader.len = pcapPacketHeader.caplen;
    pcapPacketHeader.ts.tv_sec = mmprPacket.timestampSeconds;
    pcapPacketHeader.ts.tv_usec = mmprPacket.timestampMicroseconds;
    pcap_dump((u_char*)pcapDumper, &pcapPacketHeader, mmprPacket.data);
}

void FlowManager::emit() {
    vector<Flow> flowsVec;
    flowsVec.reserve(flows.size());
    for (const auto& kv : flows) {
        flowsVec.push_back(kv.second);
    }
    for (const auto& flow : timedOutFlows) {
        flowsVec.push_back(flow);
    }
    sort(flowsVec.begin(), flowsVec.end(),
         [](Flow a, Flow b) { return a.index < b.index; });

    StdOutEmitter stdOutEmitter;
    stdOutEmitter.emitFlows(flowsVec);
}