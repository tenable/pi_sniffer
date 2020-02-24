#ifndef PROBED_NETWORK_HPP
#define PROBED_NETWORK_HPP

#include <set>
#include <string>
#include <boost/cstdint.hpp>
#include <boost/thread/mutex.hpp>

/**
 * A simple object that stores an SSID that was probed and all the client macs
 * that probed it. This *can be* prob
 */
class Probed_Network
{
public:

    Probed_Network();
    
    ~Probed_Network();

    // stores the name probed for
    void set_name(const std::string& p_name);

    //  add a client to the set of STA that probed this ssid
    void add_client(boost::uint64_t p_mac);

    std::size_t get_clients_count() const
    {
        return m_clients.size();
    }

private:

    boost::mutex m_accesslock;
    std::string m_name;
    std::set<boost::uint64_t> m_clients;
};
#endif