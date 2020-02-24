#include "llcsnap.hpp"

#include <sstream>
#include <netinet/in.h>

#include "packet.hpp"

LLCSNAP::LLCSNAP() :
    m_eapol()
{
}

LLCSNAP::~LLCSNAP()
{
}

bool LLCSNAP::handle_packet(Packet& p_packet)
{
    if (p_packet.m_length < 8)
    {
        return false;
    }

    boost::uint16_t next_proto = *reinterpret_cast<const boost::uint16_t*>(p_packet.m_data + 6);
    next_proto = ntohs(next_proto);

    p_packet.m_data += 8;
    p_packet.m_length -= 8;

    if (next_proto == 0x888e)
    {
        m_eapol.handle_packet(p_packet);
    }

    return true;
}
