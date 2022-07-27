#include "Parser.h"

#include "pcap/pcap.h"
#include "tins/constants.h"
#include "tins/ethernetII.h"
#include "tins/ipv6.h"
#include "tins/pdu.h"
#include "tins/sll.h"
#include "tins/tcp.h"
#include "tins/timestamp.h"
#include "tins/udp.h"
#include <iostream>

using namespace std;

unique_ptr<Packet> Parser::parse(const mmpr::Packet& mmprPacket, uint16_t dlt) {
    unique_ptr<Packet> packet = make_unique<Packet>();
    packet->length = mmprPacket.captureLength;
    packet->timestamp = chrono::seconds(mmprPacket.timestampSeconds) +
                        chrono::microseconds(mmprPacket.timestampMicroseconds);

    // parse the packet according to DLT type
    unique_ptr<Tins::PDU> pdu;
    switch (dlt) {
    case DLT_LINUX_SLL: {
        // aka LINKTYPE_LINUX_SLL aka "Linux cooked capture encapsulation"
        try {
            pdu = make_unique<Tins::SLL>(mmprPacket.data, mmprPacket.captureLength);
        } catch (const Tins::malformed_packet& e) {
            return nullptr;
        }
        break;
    }
    case DLT_IEEE802_11_RADIO:
        // aka LINKTYPE_IEEE802_11_RADIOTAP aka "Radiotap"
        throw runtime_error("parser does not support Radiotap at the moment");
    case DLT_NULL:
        // undefined, fall back to EthernetII
    case DLT_EN10MB:
        // aka LINKTYPE_ETHERNET
        try {
            pdu =
                make_unique<Tins::EthernetII>(mmprPacket.data, mmprPacket.captureLength);
        } catch (const Tins::malformed_packet& e) {
            return nullptr;
        }
        break;
    default:
        cerr << "parser encountered unknown datalink type: " << to_string(dlt) << endl;
        return nullptr;
    }

    assert(pdu);

    // IP reassembly
    switch (ipReassembler.process(*pdu)) {
    case Tins::IPv4Reassembler::PacketStatus::FRAGMENTED:
        return nullptr;
    case Tins::IPv4Reassembler::PacketStatus::REASSEMBLED:
        packet->length = pdu->size();
        break;
    case Tins::IPv4Reassembler::PacketStatus::NOT_FRAGMENTED:
        break;
    }

    // retrieve IP and port information
    auto* ipv4 = pdu->find_pdu<Tins::IP>();
    if (ipv4) {
        packet->nonIP = false;
        packet->srcIp = ipv4->src_addr();
        packet->dstIp = ipv4->dst_addr();
        if (ipv4->inner_pdu()) {
            switch (ipv4->protocol()) {
            case Tins::Constants::IP::PROTO_TCP: {
                Tins::TCP* tcp = dynamic_cast<Tins::TCP*>(ipv4->inner_pdu());
                packet->srcPort = tcp->sport();
                packet->dstPort = tcp->dport();
                break;
            }
            case Tins::Constants::IP::PROTO_UDP: {
                Tins::UDP* udp = dynamic_cast<Tins::UDP*>(ipv4->inner_pdu());
                packet->srcPort = udp->sport();
                packet->dstPort = udp->dport();
                break;
            }
            default:
                cerr << "Ignoring IP protocol: " << ipv4->protocol() << endl;
                break;
            }
        }
    }

    auto* ipv6 = pdu->find_pdu<Tins::IPv6>();
    if (ipv6) {
        packet->nonIP = false;
        packet->srcIp = ipv6->src_addr();
        packet->dstIp = ipv6->dst_addr();
        if (ipv6->inner_pdu()) {
            switch (ipv6->next_header()) {
            case Tins::Constants::IP::PROTO_TCP: {
                Tins::TCP* tcp = dynamic_cast<Tins::TCP*>(ipv6->inner_pdu());
                packet->srcPort = tcp->sport();
                packet->dstPort = tcp->dport();
                break;
            }
            case Tins::Constants::IP::PROTO_UDP: {
                Tins::UDP* udp = dynamic_cast<Tins::UDP*>(ipv6->inner_pdu());
                packet->srcPort = udp->sport();
                packet->dstPort = udp->dport();
                break;
            }
            default:
                cerr << "Ignoring IP protocol: " << (unsigned int)ipv6->next_header()
                     << endl;
                break;
            }
        }
    }

    return packet;
}
