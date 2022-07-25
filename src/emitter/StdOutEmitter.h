#ifndef PCAP_FLOW_SPLITTER_STDOUTEMITTER_H
#define PCAP_FLOW_SPLITTER_STDOUTEMITTER_H

#include "Emitter.h"

class StdOutEmitter : public Emitter {
public:
    void emitFlows(const std::vector<Flow>& flows) const override;
};

#endif // PCAP_FLOW_SPLITTER_STDOUTEMITTER_H
