#ifndef PCAP_OUTPUT_HPP
#define PCAP_OUTPUT_HPP

#include <string>
#include <fstream>

class Packet;

/*! Create PPI pcap file */
class PcapOutput
{
public:
    PcapOutput();
    ~PcapOutput();

    bool create_header(const std::string& p_path);
    void add_packet(Packet& p_packet);

private:

    std::ofstream m_pcapOut;
};

#endif