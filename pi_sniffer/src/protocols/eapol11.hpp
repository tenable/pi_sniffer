#ifndef EAPOL_HPP
#define EAPOL_HPP

class Packet;

class EAPOL
{
public:

    EAPOL();

    ~EAPOL();

    bool handle_packet(Packet& p_packet);
};

#endif //EAPOL_HPP
