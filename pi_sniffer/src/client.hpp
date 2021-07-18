#ifndef CLIENT_HPP
#define CLIENT_HPP

#include <string>
#include <boost/thread.hpp>

/**
 * This object represents an observed client. Clients should only be created if
 * we observe it associated with an AP.
 *
 * Note that this object is r/w on at least two threads. I've made the assumption that
 * int32 assignment is atomic, otherwise all other accesses require lock access.
 */
class Client
{
public:

    Client();
    ~Client();

    // Updated to track where we've seen the AP
    void set_last_seen(boost::uint64_t p_epoch_time);
    boost::uint64_t get_last_seen();
    boost::uint64_t get_first_seen();

    // Signal strength and GPS location information. We make no attempt to
    // triangulate the actual location of the AP. Instead, we just call the "best"
    // GPS coordinates wherever the signal strength is strongest. I think that
    // is a fine enough solution.
    void set_location_info(boost::int8_t p_signal, double p_lat, double p_long, double p_alt, bool p_gps_on);
    boost::int8_t get_last_signal() const;
    boost::int8_t get_best_signal() const;
    double get_latitude();
    double get_best_latitude();
    double get_longitude();
    double get_best_longitude();
    double get_altitude();
    double get_best_altitude();

    // store the devices mac address
    void set_mac(const std::string& p_mac);
    std::string get_mac();

    // store the mac of the station we are associated with
    void set_associated(boost::uint64_t p_associated_mac);
    boost::uint64_t get_associated();
    std::string get_associated_str();

private:

    Client(const Client& p_rhs);
    Client& operator=(const Client& p_rhs);

private:

    boost::uint64_t m_lastseen;
    boost::uint64_t m_firstseen;
    boost::uint64_t m_associated_mac;
    boost::int8_t m_lastSignal;
    boost::int8_t m_bestSignal;
    boost::mutex m_accesslock;
    std::string m_mac;
    double m_lat;
    double m_long;
    double m_alt;
    double m_bestLat;
    double m_bestLong;
    double m_bestAlt;
};

#endif
