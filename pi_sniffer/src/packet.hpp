#ifndef PACKET_HPP
#define PACKET_HPP

#include <string>
#include <vector>
#include <boost/thread.hpp>
#include <boost/cstdint.hpp>
#include <boost/ptr_container/ptr_map.hpp>
#include <boost/ptr_container/ptr_unordered_map.hpp>

#include "stats.hpp"
#include "configuration.hpp"

class Client;
class AP;
class Probed_Network;

/**
 * Packet is an unfortunate design decision. It, more or less, holds or owns all the
 * objects in the system. This is done for convience so that all protocols have access
 * to all data. It's also manipulated by both the UI thread and the packet thread.
 *
 * On the packet side, packets are read into the data member variable and the object
 * is sent down the protocol stack (80211 -> snap -> eapol).
 *
 * On the UI side, the packet's devices/client maps are queried as the user sees fit.
 *
 * As mentioned, this object (in particularly the maps) is accessed via two threads
 * so be cautious.
 */
class Packet
{
public:
    Packet();

    ~Packet();

    // resets the member variables associated with packet data
    void reset();

    // find the access point with the given mac in m_devices
    AP* find_ap(boost::uint64_t p_mac);

    // find the client with the given mac in m_clients
    Client* find_client(boost::uint64_t p_mac, bool p_associated);

    // store a probe request
    void add_probe_network(const std::string& p_network, const std::string& p_client);

    // get a const reference to the configuration
    const Configuration& get_const_config() const;

    // get the configuration
    Configuration& get_config();

    // get all access points seen in the last p_seconds seconds
    void get_recent_ap(boost::uint32_t p_seconds, std::vector<AP*>& p_routers);

    // get all clients seen in the last p_seconds seconds
    void get_recent_client(boost::uint32_t p_seconds, std::vector<Client*>& p_clients);

    // file output functions
    void write_wigle_output(const std::string& p_time);
    void write_kml_output(const std::string& p_time);
    void write_client_csv_output(const std::string& p_time);
    void write_probe_csv_output(const std::string& p_time);

private:

    Packet(const Packet& p_rhs);
    Packet& operator=(const Packet& p_rhs);

private:

    // All observered routers: mac to router mapping
    boost::ptr_unordered_map<boost::uint64_t, AP> m_devices;

    // All observed clients: mac to client mapping
    boost::ptr_unordered_map<boost::uint64_t, Client> m_clients;

    // All the probe requests seend (ssid -> Probed object)
    boost::ptr_map<std::string, Probed_Network> m_probed_networks;

    // mutex for accessing m_devices
    boost::shared_mutex m_router_mutex;

    // mutex for accessing m_clients
    boost::shared_mutex m_client_mutex;

    // mutex for accessing probes
    boost::shared_mutex m_probe_mutex;

    // holds the parsed configuration data
    Configuration m_configuration;

public:

    // Holds basic counter statistics
    Stats m_stats;

    // the below should *only* be accessed via the packet thread (except m_shudown)
    
    // packet information provided by the input method (pcap or kismet)
    const unsigned char* m_data;
    std::size_t m_length;
    boost::uint32_t m_time;  
    double m_lat;
    double m_long;
    double m_alt;
    boost::int8_t m_signal;
    bool m_gps_on;

    // cached result of the current devices we are operating on
    Client* m_current_client;
    AP* m_current_router;
    bool m_from_client;

    // created when the program starts up. largely used for output
    std::string m_startTime;
    
    // cross thread indicator that its time to shutdown
    bool m_shutdown;
    
};

#endif
