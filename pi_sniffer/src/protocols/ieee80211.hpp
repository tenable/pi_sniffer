#include <cstddef>
#include <boost/scoped_ptr.hpp>
#include <boost/cstdint.hpp>

#include "llcsnap.hpp"
#include "util/pcap_output.hpp"

class AP;
class Client;

class IEEE80211
{
public:

    IEEE80211();

    ~IEEE80211();

    bool handle_packet(Packet& p_packet);

private:

    AP* get_ap(Packet& p_packet, std::size_t p_ssid_offset);

    Client* get_client(Packet& p_packet, std::size_t p_src_offset, bool p_associated);

    void do_probe_request(Packet& p_packet);
    void do_probe_response(Packet& p_packet);
    void do_beacon(Packet& p_packet);
    void do_data(Packet& p_packet);
    void do_qos(Packet& p_packet);
    void do_association(Packet& p_packet);

    void handle_data(Packet& p_packet, boost::uint32_t p_increment);
    void handle_wep(Packet& p_packet);
    void handle_wpa(Packet& p_packet);

private:

    LLCSNAP m_snap;
    PcapOutput m_pcap_out;
};
