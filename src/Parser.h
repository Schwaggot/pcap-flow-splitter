#ifndef PCAP_FLOW_SPLITTER_PARSER_H
#define PCAP_FLOW_SPLITTER_PARSER_H

#include "Config.h"
#include "Packet.h"
#include "mmpr/mmpr.h"
#include "tins/ip_reassembler.h"
#include <memory>

class Parser {
public:
    Parser(const Config& config);

    std::unique_ptr<Packet> parse(const mmpr::Packet& mmprPacket, uint16_t dlt);

private:
    const Config& config;
    std::unique_ptr<Tins::IPv4Reassembler> ipReassembler;
};

#endif // PCAP_FLOW_SPLITTER_PARSER_H
