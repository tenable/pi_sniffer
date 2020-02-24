#ifndef AP_HPP
#define AP_HPP

#include <string>
#include <boost/cstdint.hpp>
#include <boost/thread/mutex.hpp>

/*!
 * This object represents an access point, typically a standard router but sometimes more
 * interesting things like cars, doorbells, tablets, etc. This object attempts to track the
 * general state and location of the the AP.
 *
 * Note that this object is r/w on at least two threads. I've made the assumption that
 * int32 assignment is atomic, otherwise all other accesses require lock access.
 */
class AP
{
public:

    AP();
    ~AP();

    // Set to true if the WPS tag indicates the AP has WPS configured (0x02)
    void set_wps(bool p_wps);
    bool has_wps() const;   

    // Updated to track where we've seen the AP
    void set_last_seen(boost::uint32_t p_time);
    boost::uint32_t get_last_seen() const;
    boost::uint32_t get_first_seen() const;

    // Signal strength and GPS location information. We make no attempt to
    // triangulate the actual location of the AP. Instead, we just call the "best"
    // GPS coordinates whereever the signal strength is strongest. I think that
    // is a fine enough solution.
    void set_location_info(boost::int8_t p_signal, double p_lat, double p_long, double p_alt, bool p_gps);
    boost::int8_t get_last_signal() const;
    boost::int8_t get_best_signal() const;
    double get_latitude();
    double get_best_latitude();
    double get_longitude();
    double get_best_longitude();
    double get_altitude();
    double get_best_altitude();

    // Store the broadcasted name. Currently only accepting ascii names.
    void set_ssid(const std::string& p_ssid);
    std::string get_ssid();

    // Store the devices mac address
    void set_mac(const std::string& p_mac);
    std::string get_mac();
    boost::uint64_t get_bssid();

    // Store the channel we observed this device on
    void set_channel(boost::uint8_t p_channel);
    boost::uint8_t get_channel() const;

    // Store a string representation of the encryption used (Open, WEP, WPA-EAP/PSK, WPA2-EAP/PSK)
    void set_encryption(const std::string& p_encryption);
    std::string get_encryption();

    // Increment observed associated clients. This relies on a mechanism outside of the
    // object to ensure that duplicate clients aren't being tracked.
    void increment_client();
    boost::uint32_t get_client_count() const;

    // Track how much data we've seen go across this AP
    void increment_data_packet();
    boost::uint32_t get_data_count() const;

    // We only want to parse this devices beacon/probe response once in order to save
    // processing time. 
    void set_beacon_parsed();
    bool get_beacon_parsed() const;

private:

    AP(const AP& p_rhs);
    AP& operator=(const AP& p_rhs);

private:

    boost::uint64_t m_bssid;
    boost::uint32_t m_lastseen;
    boost::uint32_t m_firstseen;
    boost::int8_t m_lastSignal;
    boost::int8_t m_bestSignal;
    boost::uint8_t m_channel;
    bool m_wps;
    bool m_parsed_beacon;
    std::string m_ssid;
    std::string m_mac;
    std::string m_encryption;
    boost::uint32_t m_clients;
    boost::uint32_t m_data;
    boost::mutex m_accesslock;
    double m_lat;
    double m_long;
    double m_alt;
    double m_bestLat;
    double m_bestLong;
    double m_bestAlt;
};

#endif
