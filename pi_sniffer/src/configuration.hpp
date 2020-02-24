#ifndef CONFIG_HPP
#define CONFIG_HPP

#include <boost/unordered_map.hpp>
#include <boost/cstdint.hpp>

#include <string>

#include <tins/crypto.h>

namespace pugi
{
    struct xml_node;
}

/**
 * Parses the configuration file passed on the command line. Also holds the information.
 * The configuration information is largely:
 * 
 * 1. What type of files to output.
 * 2. Where to output the files.
 * 3. Decryption keys.
 */
class Configuration
{
public:

    Configuration();

    ~Configuration();

    void parse_configuration(const std::string& p_config_location);

    const std::string& get_output_path() const
    {
        return m_output_path;
    }

    bool get_pcap() const
    {
        return m_pcap;
    }

    bool get_wigle() const
    {
        return m_wigle;
    }

    bool get_kml() const
    {
        return m_kml;
    }

    bool get_client_csv() const
    {
        return m_client_csv;
    }

    bool get_probe_csv() const
    {
        return m_probe_csv;
    }

    bool has_wep_key(const std::string& p_bssid) const;

    bool has_wpa_key(const std::string& p_ssid) const;

private:

    void parse_wifi_key(const pugi::xml_node& p_key);

    void parse_output(const pugi::xml_node& p_output);

public:

    // Note: its a touch odd that configuration holds the decryptors but here we are
    Tins::Crypto::WEPDecrypter m_wep_decrypter;

    Tins::Crypto::WPA2Decrypter m_wpa_decrypter;

private:

    //! The file path to the output directory
    std::string m_output_path;

    //! AP we have wep keys for
    std::set<std::string> m_wep_keys;

    //! AP we have wpa keys for
    std::set<std::string> m_wpa_keys;

    //! indicates if we should write ppi pcap file to disk
    bool m_pcap;

    //! indicates if we should write wigle csv to disk
    bool m_wigle;

    //! indicates if we should write out the kml information for routers
    bool m_kml;

    //! indicates if we should write out the clients to a csv file
    bool m_client_csv;

    //! indicates if we should write out the probes to a csv file
    bool m_probe_csv;
};

#endif
