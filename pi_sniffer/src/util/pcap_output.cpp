#include "pcap_output.hpp"

#include <boost/cstdint.hpp>

#include "../packet.hpp"

namespace
{
    #pragma pack(push, 1)
    struct pcap_header
    {
        boost::uint32_t magic_number;
        boost::uint16_t version_major;
        boost::uint16_t version_minor;
        boost::int32_t  thiszone;
        boost::uint32_t sigfigs;
        boost::uint32_t snaplen;
        boost::uint32_t network;
    };

    struct packet_header
    {
        uint32_t ts_sec;
        uint32_t ts_usec;
        uint32_t incl_len;
        uint32_t orig_len;
    };

    #pragma pack(pop)
}

PcapOutput::PcapOutput() :
    m_pcapOut()
{
}

PcapOutput::~PcapOutput()
{
    if (m_pcapOut.is_open())
    {
        m_pcapOut.close();
    }
}

bool PcapOutput::create_header(const std::string& p_path)
{
    pcap_header newHeader = {};
    newHeader.magic_number = 0xa1b2c3d4;
    newHeader.version_major = 2;
    newHeader.version_minor = 4;
    newHeader.thiszone = 0;
    newHeader.sigfigs = 0;
    newHeader.snaplen = 0xffff;
    newHeader.network = 105; // ieee 802.11

    // create the file
    m_pcapOut.open(p_path, std::ofstream::binary);
    m_pcapOut.write(reinterpret_cast<const char*>(&newHeader), sizeof(pcap_header));

    return true;
}

void PcapOutput::add_packet(Packet& p_packet)
{
    if (!m_pcapOut.is_open())
    {
        create_header(p_packet.get_const_config().get_output_path() + "pi_sniffer_" + p_packet.m_startTime + ".pcap");
    }
    packet_header packetHeader = {};
    packetHeader.incl_len = p_packet.m_length;
    packetHeader.orig_len = p_packet.m_length;
    packetHeader.ts_sec = p_packet.m_time;
    packetHeader.ts_usec = 0;
    m_pcapOut.write(reinterpret_cast<const char*>(&packetHeader), sizeof(packet_header));
    m_pcapOut.write(reinterpret_cast<const char*>(&p_packet.m_data[0]), p_packet.m_length);
    m_pcapOut.flush();
}
