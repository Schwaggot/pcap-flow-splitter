#include "StdOutEmitter.h"

#include <iostream>

using namespace std;

void StdOutEmitter::emitFlows(const std::vector<Flow>& flows) const {
    for (const auto& flow : flows) {
        cout << setw(5) << flow.index << ": ";
        if (holds_alternative<Tins::IPv4Address>(flow.flowId.loIp)) {
            cout << setw(16) << get<Tins::IPv4Address>(flow.flowId.loIp).to_string()
                 << " ";
        } else {
            cout << setw(16) << get<Tins::IPv6Address>(flow.flowId.loIp).to_string()
                 << " ";
        }
        cout << setw(5) << flow.flowId.loPort << " ";

        cout << "-> ";

        if (holds_alternative<Tins::IPv4Address>(flow.flowId.hiIp)) {
            cout << setw(16) << get<Tins::IPv4Address>(flow.flowId.hiIp).to_string()
                 << " ";
        } else {
            cout << setw(16) << get<Tins::IPv6Address>(flow.flowId.hiIp).to_string()
                 << " ";
        }
        cout << setw(5) << flow.flowId.hiPort << " ";

        cout << setw(5) << flow.packets << " ";
        cout << setw(5) << flow.bytes << endl;
    }
}
