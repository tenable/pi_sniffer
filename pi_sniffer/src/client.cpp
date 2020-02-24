#include "client.hpp"
#include "util/convert.hpp"

Client::Client() :
    m_lastseen(0),
    m_firstseen(0),
    m_associated_mac(0),
    m_lastSignal(0),
    m_bestSignal(-100),
    m_accesslock(),
    m_mac(),
    m_lat(0),
    m_long(0),
    m_alt(0),
    m_bestLat(0),
    m_bestLong(0),
    m_bestAlt(0)
{
}

Client::~Client()
{
}

void Client::set_last_seen(uint64_t p_epoch_time)
{
    if (m_firstseen == 0)
    {
        m_firstseen = p_epoch_time;
    }
    m_lastseen = p_epoch_time;
}

boost::uint64_t Client::get_last_seen()
{
    boost::mutex::scoped_lock clientLock(m_accesslock);
    return m_lastseen;
}

boost::uint64_t Client::get_first_seen()
{
    boost::mutex::scoped_lock clientLock(m_accesslock);
    return m_firstseen;
}

void Client::set_location_info(boost::int8_t p_signal, double p_lat, double p_long, double p_alt, bool p_gps_on)
{
    if (p_signal == 0)
    {
        return;
    }

    m_lastSignal = p_signal;
    if (p_gps_on)
    {
        m_lat = p_lat;
        m_long = p_long;
        m_alt = p_alt;

        if (m_lastSignal > m_bestSignal)
        {
            m_bestLat = p_lat;
            m_bestLong = p_long;
            m_bestAlt = p_alt;
            m_bestSignal = m_lastSignal;
        }
    }
    else if (m_lastSignal != 0)
    {
        if (m_lastSignal > m_bestSignal)
        {
            m_bestSignal = m_lastSignal;
        }
    }
}

boost::uint64_t Client::get_associated()
{
    boost::mutex::scoped_lock clientLock(m_accesslock);
    return m_associated_mac;
}

std::string Client::get_associated_str()
{
    boost::mutex::scoped_lock clientLock(m_accesslock);
    return printable_mac(reinterpret_cast<const unsigned char*>(&m_associated_mac), 6, true);
}

void Client::set_associated(boost::uint64_t p_associated_mac)
{
    boost::mutex::scoped_lock clientLock(m_accesslock);
    m_associated_mac = p_associated_mac;
}

boost::int8_t Client::get_last_signal() const
{
    return m_lastSignal;
}

boost::int8_t Client::get_best_signal() const
{
    return m_bestSignal;
}

double Client::get_latitude()
{
    boost::mutex::scoped_lock clientLock(m_accesslock);
    return m_lat;
}

double Client::get_best_latitude()
{
    boost::mutex::scoped_lock clientLock(m_accesslock);
    return m_bestLat;
}

double Client::get_longitude()
{
    boost::mutex::scoped_lock clientLock(m_accesslock);
    return m_long;
}

double Client::get_best_longitude()
{
    boost::mutex::scoped_lock clientLock(m_accesslock);
    return m_bestLong;
}

double Client::get_altitude()
{
    boost::mutex::scoped_lock clientLock(m_accesslock);
    return m_alt;
}

double Client::get_best_altitude()
{
    boost::mutex::scoped_lock clientLock(m_accesslock);
    return m_bestAlt;
}

void Client::set_mac(const std::string& p_mac)
{
    boost::mutex::scoped_lock clientLock(m_accesslock);
    m_mac.assign(p_mac);
}

std::string Client::get_mac()
{
    boost::mutex::scoped_lock clientLock(m_accesslock);
    return m_mac;
}
