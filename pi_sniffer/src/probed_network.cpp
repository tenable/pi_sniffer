#include "probed_network.hpp"

Probed_Network::Probed_Network() :
    m_accesslock(),
    m_name(),
    m_clients()
{
}

Probed_Network::~Probed_Network()
{
}

void Probed_Network::set_name(const std::string& p_name)
{
    m_name.assign(p_name);
}

void Probed_Network::add_client(boost::uint64_t p_mac)
{
    m_clients.insert(p_mac);
}
