#ifndef PCAP_FLOW_ID_SPLITTER_FLOW_H
#define PCAP_FLOW_ID_SPLITTER_FLOW_H

#include "sole.hpp"
#include "tins/ip_address.h"
#include "tins/ipv6_address.h"
#include <boost/container_hash/hash.hpp>
#include <chrono>

class FlowId {
public:
    FlowId(){};
    FlowId(const sole::uuid& traceSource,
           std::variant<Tins::IPv4Address, Tins::IPv6Address> srcIp,
           uint16_t srcPort,
           std::variant<Tins::IPv4Address, Tins::IPv6Address> dstIp,
           uint16_t dstPort)
        : traceSource(traceSource),
          loIp(srcIp),
          loPort(srcPort),
          hiIp(dstIp),
          hiPort(dstPort) {
        if (hiIp < loIp || (hiIp == loIp && hiPort < loPort)) {
            std::swap(this->loIp, this->hiIp);
            std::swap(this->loPort, this->hiPort);
        }
    }

    sole::uuid traceSource = {0, 0};
    std::variant<Tins::IPv4Address, Tins::IPv6Address> loIp;
    uint16_t loPort = 0;
    std::variant<Tins::IPv4Address, Tins::IPv6Address> hiIp;
    uint16_t hiPort = 0;

    bool operator==(const FlowId& rhs) const {
        return traceSource == rhs.traceSource && loIp == rhs.loIp && hiIp == rhs.hiIp &&
               loPort == rhs.loPort && hiPort == rhs.hiPort;
    }
    bool operator!=(const FlowId& rhs) const { return !(rhs == *this); }
    bool operator<(const FlowId& rhs) const {
        return std::tie(traceSource, loIp, loPort, hiIp, hiPort) <
               std::tie(rhs.traceSource, rhs.loIp, rhs.loPort, rhs.hiIp, rhs.hiPort);
    }
};

template <>
struct std::hash<FlowId> {
    std::size_t operator()(FlowId const& flowId) const noexcept {
        std::size_t seed = 0;
        boost::hash_combine(seed, flowId.traceSource.ab);
        boost::hash_combine(seed, flowId.traceSource.cd);
        boost::hash_combine(seed, flowId.loPort);
        boost::hash_combine(seed, flowId.hiPort);

        if (std::holds_alternative<Tins::IPv4Address>(flowId.loIp)) {
            auto loIp = std::get<Tins::IPv4Address>(flowId.loIp);
            auto hiIp = std::get<Tins::IPv4Address>(flowId.hiIp);
            boost::hash_combine(seed, std::hash<Tins::IPv4Address>()(loIp));
            boost::hash_combine(seed, std::hash<Tins::IPv4Address>()(hiIp));
        } else {
            auto loIp = std::get<Tins::IPv6Address>(flowId.loIp);
            auto hiIp = std::get<Tins::IPv6Address>(flowId.hiIp);
            boost::hash_combine(seed, std::hash<Tins::IPv6Address>()(loIp));
            boost::hash_combine(seed, std::hash<Tins::IPv6Address>()(hiIp));
        }

        return seed;
    }
};

#endif // PCAP_FLOW_ID_SPLITTER_FLOW_H
