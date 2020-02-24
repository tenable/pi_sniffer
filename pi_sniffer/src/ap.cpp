#include "ap.hpp"
#include "util/convert.hpp"

AP::AP() :
    m_bssid(),
    m_lastseen(0),
    m_firstseen(0),
    m_lastSignal(0),
    m_bestSignal(-100),
    m_channel(0),
    m_wps(false),
    m_parsed_beacon(false),
    m_ssid(),
    m_mac(),
    m_encryption(),
    m_clients(0),
    m_data(0),
    m_accesslock(),
    m_lat(0),
    m_long(0),
    m_alt(0),
    m_bestLat(0),
    m_bestLong(0),
    m_bestAlt(0)
{
}

AP::~AP()
{
}

bool AP::has_wps() const
{
    return m_wps;
}

void AP::set_wps(bool p_wps)
{
    m_wps = p_wps;
}

void AP::set_last_seen(boost::uint32_t p_epoch_time)
{
    if (m_firstseen == 0)
    {
        m_firstseen = p_epoch_time;
    }

    m_lastseen = p_epoch_time;
}

boost::uint32_t AP::get_last_seen() const
{
    return m_lastseen;
}

boost::uint32_t AP::get_first_seen() const
{
    return m_firstseen;
}

void AP::set_location_info(boost::int8_t p_signal,
                                       double p_lat, double p_long,
                                       double p_alt, bool p_gps)
{
    if (p_signal == 0)
    {
        return;
    }

    m_lastSignal = p_signal;
    if (p_gps)
    {
        boost::mutex::scoped_lock routerLock(m_accesslock);
        m_lat = p_lat;
        m_long = p_long;
        m_alt = p_alt;

        if (m_lastSignal > m_bestSignal)
        {
            m_bestSignal = m_lastSignal;
            m_bestLat = p_lat;
            m_bestLong = p_long;
            m_bestAlt = p_alt;
        }
    }
    else
    {
        if (m_lastSignal > m_bestSignal)
        {
            m_bestSignal = m_lastSignal;
        }
    }
}

boost::int8_t AP::get_last_signal() const
{
    return m_lastSignal;
}

boost::int8_t AP::get_best_signal() const
{
    return m_bestSignal;
}

double AP::get_latitude()
{
    boost::mutex::scoped_lock routerLock(m_accesslock);
    return m_lat;
}

double AP::get_best_latitude()
{
    boost::mutex::scoped_lock routerLock(m_accesslock);
    return m_bestLat;
}

double AP::get_longitude()
{
    boost::mutex::scoped_lock routerLock(m_accesslock);
    return m_long;
}

double AP::get_best_longitude()
{
    boost::mutex::scoped_lock routerLock(m_accesslock);
    return m_bestLong;
}

double AP::get_altitude()
{
    boost::mutex::scoped_lock routerLock(m_accesslock);
    return m_alt;
}

double AP::get_best_altitude() 
{
    boost::mutex::scoped_lock routerLock(m_accesslock);
    return m_bestAlt;
}

void AP::set_ssid(const std::string& p_ssid)
{
    // only accept ascii, I guess
    for (unsigned int i = 0; i < p_ssid.size(); i++)
    {
        if (p_ssid[i] > 0x7e || p_ssid[i] < 0x20)
        {
            return;
        }
    }
    boost::mutex::scoped_lock routerLock(m_accesslock);
    m_ssid.assign(p_ssid);
}

std::string AP::get_ssid()
{
    boost::mutex::scoped_lock routerLock(m_accesslock);
    return m_ssid;
}

boost::uint64_t AP::get_bssid()
{
    boost::mutex::scoped_lock routerLock(m_accesslock);
    return m_bssid;
}

void AP::set_mac(const std::string& p_mac)
{
    boost::mutex::scoped_lock routerLock(m_accesslock);
    m_mac.assign(p_mac);
    m_bssid = string_mac_to_int(p_mac);
}

std::string AP::get_mac()
{
    boost::mutex::scoped_lock routerLock(m_accesslock);
    return m_mac;
}

void AP::set_channel(boost::uint8_t p_channel)
{
    m_channel = p_channel;
}

boost::uint8_t AP::get_channel() const
{
    return m_channel;
}

void AP::set_encryption(const std::string& p_encryption)
{
    boost::mutex::scoped_lock routerLock(m_accesslock);
    m_encryption.assign(p_encryption);
}

std::string AP::get_encryption()
{
    boost::mutex::scoped_lock routerLock(m_accesslock);
    return m_encryption;
}

void AP::increment_client()
{
    ++m_clients;
}

boost::uint32_t AP::get_client_count() const
{
    return m_clients;
}

void AP::increment_data_packet()
{
    ++m_data;
}

boost::uint32_t AP::get_data_count() const
{
    return m_data;
}


void AP::set_beacon_parsed()
{
    m_parsed_beacon = true;
}

bool AP::get_beacon_parsed() const
{
    return m_parsed_beacon;
}