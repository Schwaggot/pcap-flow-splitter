#ifndef PCAP_FLOW_SPLITTER_EMITTER_H
#define PCAP_FLOW_SPLITTER_EMITTER_H

#include "../Flow.h"
#include <vector>

class Emitter {
public:
    virtual void emitFlows(const std::vector<Flow>& flows) const = 0;
};

#endif // PCAP_FLOW_SPLITTER_EMITTER_H
