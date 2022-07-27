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
    std::vector<std::string> pcapFiles;
    std::string outputDirectory;
    uint32_t flowTimeoutSeconds;
    bool dryRun = false;

    // Declare the supported options.
    po::options_description desc("Allowed options");
    desc.add_options()("help", "produce help message");
    desc.add_options()(
        "pcap,P",
        boost::program_options::value<std::vector<std::string>>(&pcapFiles)->multitoken(),
        "analyze packets from pcap file(s)");
    desc.add_options()("output-dir,O",
                       boost::program_options::value<std::string>(&outputDirectory),
                       "output directory for pcap files");
    desc.add_options()(
        "timeout,T",
        boost::program_options::value<uint32_t>(&flowTimeoutSeconds)->default_value(120),
        "timeout for inactive flows (in seconds)");
    desc.add_options()("dry-run", po::bool_switch(&dryRun)->default_value(false),
                       "do not write files");

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    if (vm.count("help")) {
        cout << desc << "\n";
        return EXIT_SUCCESS;
    }

    if (vm.count("pcap")) {
        cout << pcapFiles.size() << " input file(s) provided." << endl;
    } else {
        throw runtime_error("No input files specified.");
    }

    if (outputDirectory.empty()) {
        throw runtime_error(
            "No output directory specified, use [-O <dir> | --output-dir <dir>]");
    }

    chrono::seconds flowTimeout = chrono::seconds(flowTimeoutSeconds);

    // iterate over all input files
    for (const auto& pcapFile : pcapFiles) {
        if (!boost::filesystem::exists(pcapFile)) {
            throw runtime_error("Could not find file: " +
                                boost::filesystem::absolute(pcapFile).string());
        }

        auto pcapReader = mmpr::FileReader::getReader(pcapFile);
        pcapReader->open();
        uint64_t numPackets = 0;
        mmpr::Packet mmprPacket;
        Parser parser;
        FlowManager flowManager(outputDirectory, flowTimeout, dryRun);

        while (!pcapReader->isExhausted()) {
            if (!pcapReader->readNextPacket(mmprPacket)) {
                continue;
            }

            ++numPackets;

            auto packet = parser.parse(mmprPacket, pcapReader->getDataLinkType());
            if (!packet) {
                continue;
            }

            flowManager.onPacket(*packet, mmprPacket);
        }

        flowManager.emit();

        cout << endl;
        cout << "Read " << numPackets << " packet(s) from "
             << boost::filesystem::absolute(pcapFile).string() << endl;
        cout << "Found " << (flowManager.flows.size() + flowManager.timedOutFlows.size())
             << " flow(s)" << endl;
        cout << endl;
    }
}