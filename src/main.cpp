#include "Config.h"
#include "FlowManager.h"
#include "Parser.h"
#include "mmpr/mmpr.h"
#include "pcap/pcap.h"
#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>
#include <iostream>

using namespace std;
namespace po = boost::program_options;

int main(int argc, char** argv) {
    Config config;
    uint32_t flowTimeoutSeconds;

    // Declare the supported options.
    po::options_description desc("Allowed options");
    desc.add_options()("help", "produce help message");
    desc.add_options()(
        "pcap,P",
        boost::program_options::value<std::vector<std::string>>(&config.pcapFiles)
            ->multitoken(),
        "analyze packets from pcap file(s)");
    desc.add_options()(
        "output-dir,O",
        boost::program_options::value<std::string>(&config.outputDirectory),
        "output directory for pcap files");
    desc.add_options()(
        "timeout,T",
        boost::program_options::value<uint32_t>(&flowTimeoutSeconds)->default_value(120),
        "timeout for inactive flows (in seconds)");
    desc.add_options()("dry-run", po::bool_switch(&config.dryRun)->default_value(false),
                       "do not write files");
    desc.add_options()("ip-reassembly",
                       po::bool_switch(&config.ipReassembly)->default_value(false),
                       "perform IPv4 reassembly");

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    if (vm.count("help")) {
        cout << desc << "\n";
        return EXIT_SUCCESS;
    }

    // TODO replace this directly with chrono parsing
    config.flowTimeout = std::chrono::seconds(flowTimeoutSeconds);

    if (vm.count("pcap")) {
        cout << config.pcapFiles.size() << " input file(s) provided." << endl;
    } else {
        throw runtime_error("No input files specified.");
    }

    if (config.outputDirectory.empty()) {
        throw runtime_error(
            "No output directory specified, use [-O <dir> | --output-dir <dir>]");
    }

    // iterate over all input files
    for (const auto& pcapFile : config.pcapFiles) {
        if (!boost::filesystem::exists(pcapFile)) {
            throw runtime_error("Could not find file: " +
                                boost::filesystem::absolute(pcapFile).string());
        }

        auto start = chrono::high_resolution_clock::now();

        auto pcapReader = mmpr::FileReader::getReader(pcapFile);
        pcapReader->open();
        uint64_t packets = 0;
        uint64_t bytes = 0;
        mmpr::Packet mmprPacket;
        Parser parser(config);
        FlowManager flowManager(config);

        while (!pcapReader->isExhausted()) {
            if (!pcapReader->readNextPacket(mmprPacket)) {
                continue;
            }

            packets += 1;
            bytes += mmprPacket.captureLength;

            auto packet = parser.parse(mmprPacket, pcapReader->getDataLinkType());
            if (!packet) {
                continue;
            }

            flowManager.onPacket(*packet, mmprPacket);
        }

        auto end = chrono::high_resolution_clock::now();
        auto durationMs = chrono::duration_cast<chrono::milliseconds>(end - start);
        auto durationS = chrono::duration_cast<chrono::seconds>(end - start);
        auto packetsPerSecond = packets / durationS.count();
        auto gbPerSecond = (double)bytes / durationS.count() / 1000 / 1000 / 1000;

        flowManager.emit();

        cout << endl;
        cout << "Finished in " << durationMs.count() << "ms" << endl;
        cout << "Read " << packets << " packet(s) from "
             << boost::filesystem::absolute(pcapFile).string() << endl;
        cout << "Read " << bytes << " byte(s) from "
             << boost::filesystem::absolute(pcapFile).string() << endl;
        cout << "Found " << (flowManager.flows.size() + flowManager.timedOutFlows.size())
             << " flow(s)" << endl;
        cout << "Throughput: " << packetsPerSecond << " packets/s, " << gbPerSecond
             << " gb/s" << endl;
        cout << endl;
    }
}