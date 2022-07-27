#ifndef PCAP_FLOW_SPLITTER_CONFIG_H
#define PCAP_FLOW_SPLITTER_CONFIG_H

#include <chrono>
#include <string>
#include <vector>

class Config {
public:
    std::vector<std::string> pcapFiles;
    std::string outputDirectory;
    std::chrono::seconds flowTimeout = std::chrono::seconds(120);
    bool dryRun = false;
    bool ipReassembly = false;
};

#endif // PCAP_FLOW_SPLITTER_CONFIG_H
