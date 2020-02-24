#include "eapol11.hpp"

#include "packet.hpp"
#include "ap.hpp"

#include <netinet/in.h>
#include <boost/static_assert.hpp>

namespace
{
    #pragma pack(push, 1)
    struct key_struct
    {
        boost::uint8_t type;
        boost::uint16_t key_info;
        boost::uint16_t key_length;
        boost::uint8_t replay_counter[8];
        boost::uint8_t key_nonce[32];
        boost::uint8_t key_iv[16];
        boost::uint8_t key_rsc[8];
        boost::uint8_t key_id[8];
        boost::uint8_t key_mic[16];
        boost::uint16_t key_data_length;
    };

    BOOST_STATIC_ASSERT(sizeof(key_struct) == 95);
    #pragma pack(pop)
}

EAPOL::EAPOL()
{
}

EAPOL::~EAPOL()
{
}

bool EAPOL::handle_packet(Packet& p_packet)
{
    // too short to be an eapol (or an interesting one at least)
    if (p_packet.m_length < 4)
    {
        return false;
    }

    const boost::uint16_t length =
        ntohs(*reinterpret_cast<const boost::uint16_t*>(p_packet.m_data + 2));

    if (static_cast<unsigned int>(length + 4) > p_packet.m_length)
    {
        return false;
    }

    if (p_packet.m_data[1] == 0)
    {
        return false;
    }

    p_packet.m_data += 4;
    p_packet.m_length -= 4;

    if (p_packet.m_length < sizeof(key_struct))
    {
        return false;
    }

    const struct key_struct* key_data =
        reinterpret_cast<const struct key_struct*>(p_packet.m_data);

    if (key_data->type != 1 && key_data->type != 2)
    {
        // these aren't key types we are interested in
        return false;
    }

    // Used to build HCCAPX here. However, it appears that cap2hccapx is
    // significantly better than my crap. Maybe think of a way to isolate eapol
    // and a beacon for each auth attempt? Otherwise its fine to just convert
    // to hccapx at the end of the run.
    p_packet.m_stats.increment_eapol();

    return true;
}
