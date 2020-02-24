#ifndef SNAP_HPP
#define SNAP_HPP

class Packet;

#include "eapol11.hpp"

class LLCSNAP
{
public:
    LLCSNAP();

    ~LLCSNAP();

    bool handle_packet(Packet& p_packet);

private:

    EAPOL m_eapol;
};

#endif
