#include "packet.hpp"

#include "client.hpp"
#include "ap.hpp"
#include "probed_network.hpp"
#include "util/convert.hpp"
#include "util/kml_maker.hpp"

#include <ctime>
#include <iostream>
#include <fstream>

Packet::Packet() :
    m_devices(),
    m_clients(),
    m_probed_networks(),
    m_router_mutex(),
    m_client_mutex(),
    m_probe_mutex(),
    m_configuration(),
    m_stats(),
    m_data(NULL),
    m_length(0),
    m_time(0),
    m_lat(0),
    m_long(0),
    m_alt(0),
    m_signal(0),
    m_gps_on(false),
    m_current_client(NULL),
    m_current_router(NULL),
    m_from_client(false),
    m_startTime(),
    m_shutdown(false)
{
}

Packet::~Packet()
{
}

void Packet::reset()
{
    // note: don't zero out m_time

    m_data = NULL;
    m_length = 0;
    m_signal = 0;
    m_lat = 0;
    m_long = 0;
    m_alt = 0;
    m_gps_on = false;
}

const Configuration& Packet::get_const_config() const
{
    return m_configuration;
}

Configuration& Packet::get_config()
{
    return m_configuration;
}

void Packet::get_recent_ap(boost::uint32_t p_seconds, std::vector<AP*>& p_routers)
{
    // this approach has the short coming that we need packets to be regurlarly flowing.
    // although hopefully that's the case.
    boost::uint32_t cutoff = m_time - p_seconds;

    // loop over everything. yes there are better approaches but they require much more code
    // and I don't think the router map should ever get big enough for that to pay off
    
    // get read lock for router lookup
    boost::upgrade_lock<boost::shared_mutex> readLock(m_router_mutex);
    for (boost::ptr_unordered_map<boost::uint64_t, AP>::iterator iter = m_devices.begin();
         iter != m_devices.end(); ++iter)
    {
        if (iter->second->get_last_seen() >= cutoff)
        {
            std::vector<AP*>::iterator v_iter = p_routers.begin();
            for ( ; v_iter != p_routers.end(); ++v_iter)
            {
                if ((*v_iter)->get_last_seen() < iter->second->get_last_seen())
                {
                    break;
                }
            }
            p_routers.insert(v_iter, iter->second);
        }
    }
}

void Packet::get_recent_client(boost::uint32_t p_seconds, std::vector<Client*>& p_clients)
{
    // this approach has the short coming that we need packets to be regularly flowing.
    // although hopefully that's the case.
    boost::uint32_t cutoff = m_time - p_seconds;

    // loop over everything. yes there are better approaches but they require much more code
    // and I don't think the router map should ever get big enough for that to pay off
    
    // get read lock for router lookup
    boost::upgrade_lock<boost::shared_mutex> readLock(m_client_mutex);
    for (boost::ptr_unordered_map<boost::uint64_t, Client>::iterator iter = m_clients.begin();
         iter != m_clients.end(); ++iter)
    {
        if (iter->second->get_last_seen() >= cutoff)
        {
            std::vector<Client*>::iterator v_iter = p_clients.begin();
            for ( ; v_iter != p_clients.end(); ++v_iter)
            {
                if ((*v_iter)->get_last_seen() < iter->second->get_last_seen())
                {
                    break;
                }
            }
            p_clients.insert(v_iter, iter->second);
        }
    }
}

AP* Packet::find_ap(boost::uint64_t p_mac)
{
    {
        // get read lock for router lookup
        boost::upgrade_lock<boost::shared_mutex> readLock(m_router_mutex);

        // find the router and return it if it exists
        boost::ptr_unordered_map<boost::uint64_t, AP>::iterator iter = m_devices.find(p_mac);
        if (iter != m_devices.end())
        {
            m_current_router = (*iter).second;
            m_current_router->set_last_seen(m_time);
            if (m_gps_on)
            {
                m_current_router->set_location_info(m_signal, m_lat, m_long, m_alt, m_gps_on);
            }
            else if (m_signal != 0)
            {
                m_current_router->set_location_info(m_signal, m_lat, m_long, m_alt, m_gps_on);
            }

            return m_current_router;
        }

        // upgrade to a write lock and create the new router object
        boost::upgrade_to_unique_lock<boost::shared_mutex> writeLock(readLock);
        m_current_router = &m_devices[p_mac];
    }

    // this is a new router so update it.
    unsigned char* mac = reinterpret_cast<unsigned char*>(&p_mac);
    std::string mac_string(printable_mac(mac, 6));
    m_current_router->set_mac(mac_string);
    m_current_router->set_last_seen(m_time);
    if (m_gps_on)
    {
        m_current_router->set_location_info(m_signal, m_lat, m_long, m_alt, m_gps_on);
    }
    else if (m_signal != 0)
    {
        m_current_router->set_location_info(m_signal, m_lat, m_long, m_alt, m_gps_on);
    }

    return m_current_router;
}

Client* Packet::find_client(boost::uint64_t p_src_mac, bool p_associated)
{
    {
        // get read lock for client lookup
        boost::upgrade_lock<boost::shared_mutex> readLock(m_client_mutex);

        // if the client already exists we can simply return it
        boost::ptr_unordered_map<boost::uint64_t, Client>::iterator iter = m_clients.find(p_src_mac);
        if (iter != m_clients.end())
        {
            m_current_client = (*iter)->second;
            m_current_client->set_last_seen(m_time);
            m_current_client->set_location_info(m_signal, m_lat, m_long, m_alt, m_gps_on);

            if (m_current_router && p_associated && m_current_client->get_associated() == 0)
            {
                m_current_client->set_associated(m_current_router->get_bssid());
                m_current_router->increment_client();
            }

            return m_current_client;
        }

        // upgrade to a write lock and create the new client object
        boost::upgrade_to_unique_lock<boost::shared_mutex> writeLock(readLock);
        m_current_client = &m_clients[p_src_mac];
    }

    if (m_current_router && p_associated)
    {
        m_current_client->set_associated(m_current_router->get_bssid());
        m_current_router->increment_client();
    }

    unsigned char* mac = reinterpret_cast<unsigned char*>(&p_src_mac);
    std::string mac_address(printable_mac(mac, 6));
    m_current_client->set_mac(mac_address);
    m_current_client->set_last_seen(m_time);
    m_current_client->set_location_info(m_signal, m_lat, m_long, m_alt, m_gps_on);

    return m_current_client;
}

void Packet::write_wigle_output(const std::string& p_time)
{
    std::string filename(m_configuration.get_output_path() + "pi_sniffer_wigle_" + p_time + ".csv");

    // create the file
    std::filebuf wigle_output;
    wigle_output.open(filename, std::ios::out);
    if (!wigle_output.is_open())
    {
        std::cerr << "Failed to write " << filename << std::endl;
        return;
    }
    std::ostream os(&wigle_output);

    // header
    os << "WigleWifi-1.4\n";

    // data fields
    os << "MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type\n";

    // time
    char buffer[32] = {0};
    std::string time;

    // loop over the router
    boost::upgrade_lock<boost::shared_mutex> readLock(m_router_mutex);
    for (boost::ptr_unordered_map<boost::uint64_t, AP>::iterator it = m_devices.begin();
         it != m_devices.end(); ++it)
    {
        os << it->second->get_mac() << ",";
        if (it->second->get_ssid() == "<Unknown>")
        {
            os << ",";
        }
        else
        {
            os << it->second->get_ssid() << ",";
        }

        if (it->second->get_encryption().find("/") != std::string::npos)
        {
            os << "[WPA-PSK][WPA2-PSK]";
        }
        else if (it->second->get_encryption() == "None")
        {
            //leave it blank
        }
        else
        {
            os << "[" << it->second->get_encryption() << "]";
        }
        if (it->second->has_wps())
        {
            os << "[WPS]";
        }
        os << ",";

        time_t start = it->second->get_first_seen();
        strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", localtime(&start));
        time.assign(buffer);
        os << time << "," << (int)it->second->get_channel() << ",";
        os << static_cast<int>(it->second->get_best_signal()) << ",";
        os << it->second->get_best_latitude() << ",";
        os << it->second->get_best_longitude() << ",";
        os << it->second->get_best_altitude() << ",";
        os << ","; // don't really have accuracy info
        os << "WIFI" << "\n";
    }

    // close it
    wigle_output.close();
}

void Packet::write_kml_output(const std::string& p_time)
{
    std::string filename(m_configuration.get_output_path() + "pi_sniffer_map_" + p_time);

    KML_Maker kml_maker;
    boost::upgrade_lock<boost::shared_mutex> readLock(m_router_mutex);
    kml_maker.load_aps(m_devices);
    kml_maker.write_all(filename);
}

void Packet::write_client_csv_output(const std::string& p_time)
{
    std::string filename(m_configuration.get_output_path() + "pi_sniffer_clients_" + p_time + ".csv");

    // create the file
    std::filebuf client_output;
    client_output.open(filename, std::ios::out);
    if (!client_output.is_open())
    {
        std::cerr << "Failed to write " << filename << std::endl;
        return;
    }
    std::ostream os(&client_output);

    // data fields
    os << "MAC,BSSID,RSSI,Lat,Long,FirstSeen,LastSeen" << std::endl;

    // loop over the router
    boost::upgrade_lock<boost::shared_mutex> readLock(m_router_mutex);
    for (boost::ptr_unordered_map<boost::uint64_t, Client>::iterator it = m_clients.begin();
         it != m_clients.end(); ++it)
    {
        os << it->second->get_mac() << ",";
        os << it->second->get_associated_str() << ",";
        os << static_cast<int>(it->second->get_best_signal()) << ",";
        os << it->second->get_best_latitude() << ",";
        os << it->second->get_best_longitude() << ",";
        os << it->second->get_first_seen() << ",";
        os << it->second->get_last_seen() << std::endl;
    }

    client_output.close();
}

void Packet::write_probe_csv_output(const std::string& p_time)
{
    std::string filename(m_configuration.get_output_path() + "pi_sniffer_probes_" + p_time + ".csv");

    // create the file
    std::filebuf client_output;
    client_output.open(filename, std::ios::out);
    if (!client_output.is_open())
    {
        std::cerr << "Failed to write " << filename << std::endl;
        return;
    }
    std::ostream os(&client_output);
    os << "Probe,Count" << std::endl;

    boost::upgrade_lock<boost::shared_mutex> readLock(m_probe_mutex);

    for (boost::ptr_map<std::string, Probed_Network>::iterator it = m_probed_networks.begin();
         it != m_probed_networks.end(); ++it)
    {
        os << it->first << "," << it->second->get_clients_count() << std::endl;
    }
    client_output.close();
}

void Packet::write_ap_clients_csv_output(const std::string& p_time)
{
    std::string filename(m_configuration.get_output_path() + "pi_sniffer_ap_clients_" + p_time + ".csv");

    // create the file
    std::filebuf ap_clients_output;
    ap_clients_output.open(filename, std::ios::out);
    if (!ap_clients_output.is_open())
    {
        std::cerr << "Failed to write " << filename << std::endl;
        return;
    }
    std::ostream os(&ap_clients_output);

    // data fields
    os << "Clients,SSID,MAC,\n";

    // loop over the router
    boost::upgrade_lock<boost::shared_mutex> readLock(m_router_mutex);
    for (boost::ptr_unordered_map<boost::uint64_t, AP>::iterator it = m_devices.begin();
         it != m_devices.end(); ++it)
    {
        if (it->second->get_mac() == "00:00:00:00:00:00")
        {
            continue;
        }

        os << it->second->get_client_count() << ",";
        if (it->second->get_ssid() == "<Unknown>")
        {
            os << ",";
        }
        else
        {
            os << it->second->get_ssid() << ",";
        }

        os << it->second->get_mac() << std::endl;
    }

    // close it
    ap_clients_output.close();
}

void Packet::add_probe_network(const std::string& p_network, const std::string& p_client)
{
    if (p_network.size() < 3)
    {
        return;
    }

    // only accept ascii, I guess
    for (unsigned int i = 0; i < p_network.size(); i++)
    {
        if (p_network[i] > 0x7e || p_network[i] < 0x20)
        {
            return;
        }
    }

    {
        // get read lock for client lookup
        boost::upgrade_lock<boost::shared_mutex> readLock(m_probe_mutex);
        if (m_probed_networks.find(p_network) == m_probed_networks.end())
        {
            // upgrade to a write lock and insert the new probe network
            boost::upgrade_to_unique_lock<boost::shared_mutex> writeLock(readLock);
            Probed_Network* new_probe = &m_probed_networks[p_network];
            new_probe->set_name(p_network);
            new_probe->add_client(string_mac_to_int(p_client));
        }
        else
        {
            // upgrade to a write lock and add the client to the prexisting probe network
            boost::upgrade_to_unique_lock<boost::shared_mutex> writeLock(readLock);
            m_probed_networks[p_network].add_client(string_mac_to_int(p_client));
        }
    }
}
