#ifndef PCAP_FLOW_SPLITTER_PARSER_H
#define PCAP_FLOW_SPLITTER_PARSER_H

#include "Packet.h"
#include "mmpr/mmpr.h"
#include "tins/ip_reassembler.h"
#include <memory>

class Parser {
public:
    std::unique_ptr<Packet> parse(const mmpr::Packet& mmprPacket, uint16_t dlt);

private:
    Tins::IPv4Reassembler ipReassembler;
};

#endif // PCAP_FLOW_SPLITTER_PARSER_H
