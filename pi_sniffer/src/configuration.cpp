#include "configuration.hpp"

#include "util/convert.hpp"

#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>
#include <pugixml.hpp>

Configuration::Configuration() :
    m_wep_decrypter(),
    m_wpa_decrypter(),
    m_output_path(),
    m_wep_keys(),
    m_wpa_keys(),
    m_pcap(false),
    m_wigle(false),
    m_kml(false),
    m_client_csv(false),
    m_probe_csv(false),
    m_ap_clients_csv(false)
{
}

Configuration::~Configuration()
{
}

void Configuration::parse_configuration(const std::string& p_config_location)
{
    pugi::xml_document config;
    if (!config.load_file(p_config_location.c_str()))
    {
        throw std::runtime_error("Failed to load the configuration file: " + p_config_location);
    }

    const pugi::xml_node fullConfig = config.child("pi_sniffer");
    if (fullConfig.empty())
    {
        throw std::runtime_error("Failed to find the root node: <pi_sniffer>");
    }

    const pugi::xml_node wifi_decrypt = fullConfig.child("wifidecrypt");
    for (pugi::xml_node_iterator it = wifi_decrypt.begin();
         it != wifi_decrypt.end(); ++it)
    {
        parse_wifi_key(*it);
    }

    const pugi::xml_node output = fullConfig.child("output");
    for (pugi::xml_node_iterator it = output.begin();
         it != output.end(); ++it)
    {
        parse_output(*it);
    }
}

void Configuration::parse_wifi_key(const pugi::xml_node& p_key)
{
    std::string key_type(p_key.attribute("type").as_string());
    if (key_type.empty())
    {
        throw std::runtime_error("key missing the type attribute.");
    }

    std::string key(p_key.attribute("key").as_string());
    if (key.empty())
    {
        throw std::runtime_error("key missing the key attribute.");
    }

    if (key_type == "wep")
    {

        std::string bssid(p_key.attribute("bssid").as_string());
        if (bssid.empty())
        {
            throw std::runtime_error("key missing the bssid attribute.");
        }

        boost::uint64_t index = string_mac_to_int(bssid);

        // convert to actual hex
        std::string hex_key(string_to_hex(key));
        if (hex_key.size() != 5 && hex_key.size() != 13 && hex_key.size() != 16)
        {
            throw std::runtime_error("The WEP key must be 5, 13, or 16 bytes long.");
        }

        m_wep_decrypter.add_password(int_mac_to_array(index), hex_key);
        m_wep_keys.insert(bssid);
    }
    else if (key_type == "wpa")
    {
        std::string ssid(p_key.attribute("ssid").as_string());
        if (ssid.empty())
        {
            throw std::runtime_error("key missing the ssid attribute.");
        }
        m_wpa_decrypter.add_ap_data(key, ssid);
        m_wpa_keys.insert(ssid);
    }
    else
    {
        throw std::runtime_error("Unknown key type: " + key_type + ". Options are wep or wpa");
    }
}

void Configuration::parse_output(const pugi::xml_node& p_output)
{
    std::string type(p_output.attribute("type").as_string());
    std::string path(p_output.attribute("path").as_string());
    if (!type.empty())
    {
        if (type.compare("pcap") == 0)
        {
            std::string enabled(p_output.attribute("enabled").as_string());
            if (enabled.compare("true") == 0)
            {
                m_pcap = true;
            }
        }
        else if (type.compare("wigle") == 0)
        {
            std::string enabled(p_output.attribute("enabled").as_string());
            if (enabled.compare("true") == 0)
            {
                m_wigle = true;
            }
        }
        else if (type.compare("kml") == 0)
        {
            std::string enabled(p_output.attribute("enabled").as_string());
            if (enabled.compare("true") == 0)
            {
                m_kml = true;
            }
        }
        else if (type.compare("client_csv") == 0)
        {
            std::string enabled(p_output.attribute("enabled").as_string());
            if (enabled.compare("true") == 0)
            {
                m_client_csv = true;
            }
        }
        else if (type.compare("probe_csv") == 0)
        {
            std::string enabled(p_output.attribute("enabled").as_string());
            if (enabled.compare("true") == 0)
            {
                m_probe_csv = true;
            }
        }
        else if (type.compare("ap_clients_csv") == 0)
        {
            std::string enabled(p_output.attribute("enabled").as_string());
            if (enabled.compare("true") == 0)
            {
                m_ap_clients_csv = true;
            }
        }
    }
    else if (!path.empty())
    {
        m_output_path.assign(p_output.attribute("path").as_string());
        if (!boost::filesystem::exists(m_output_path))
        {
            // create directory
            try
            {
                boost::filesystem::create_directories(m_output_path);
            }
            catch (const std::exception&)
            {
                // ignore it
            }
        }

        if (!boost::filesystem::is_directory(m_output_path))
        {
            throw std::runtime_error("The output path is not a directory.");
        }
    }
}

bool Configuration::has_wep_key(const std::string& p_bssid) const
{
    return m_wep_keys.find(p_bssid) != m_wep_keys.end();
}

bool Configuration::has_wpa_key(const std::string& p_ssid) const
{
    return m_wpa_keys.find(p_ssid) != m_wpa_keys.end();
}
