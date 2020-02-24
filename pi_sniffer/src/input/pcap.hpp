#ifndef PCAP_HPP
#define PCAP_HPP

#include <fstream>
#include <string>

#include <boost/cstdint.hpp>

class Packet;

class PCAP
{
public:

    PCAP(std::string p_filename);
    ~PCAP();

    bool initialize();
    bool eof() const;
    bool get_packet(Packet& p_packet);

private:

    bool do_radiotap(Packet& p_packet, boost::uint32_t p_length);
    bool do_ppi(Packet& p_packet, boost::uint32_t p_length);

private:

    std::ifstream m_file;
    std::size_t m_linktype;
};

#endif