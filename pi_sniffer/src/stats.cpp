#include "stats.hpp"

Stats::Stats() :
    m_accesslock(),
    m_unecrypted(0),
    m_wep(0),
    m_wpa(0),
    m_wps(0),
    m_data(0),
    m_encrypted(0),
    m_decrypted(0),
    m_failed_decrypt(0),
    m_packets(0),
    m_beacons(0),
    m_eapol(0)
{
}

Stats::~Stats()
{
}

void Stats::increment_unencrypted()
{
    ++m_unecrypted;
}

boost::uint32_t Stats::get_unencrypted() const
{
    return m_unecrypted;
}

void Stats::increment_wep()
{
    ++m_wep;
}

boost::uint32_t Stats::get_wep() const
{
    return m_wep;
}

void Stats::increment_wpa()
{
    ++m_wpa;
}

boost::uint32_t Stats::get_wpa() const
{
    return m_wpa;
}

void Stats::increment_wps()
{
    ++m_wps;
}

void Stats::increment_data_packets()
{
    ++m_data;
}

boost::uint32_t Stats::get_data_packets() const
{
    return m_data;
}

void Stats::increment_packets()
{
    ++m_packets;
}

boost::uint32_t Stats::get_packets() const
{
    return m_packets;
}

void Stats::increment_beacons()
{
    ++m_beacons;
}

boost::uint32_t Stats::get_beacons() const
{
    return m_beacons;
}

void Stats::increment_encrypted()
{
    ++m_encrypted;
}

boost::uint32_t Stats::get_encrypted() const
{
    return m_encrypted;
}

boost::uint32_t Stats::get_decrypted() const
{
    return m_decrypted;
}

void Stats::increment_decrypted()
{
    ++m_decrypted;
}

boost::uint32_t Stats::get_failed_decrypt() const
{
    return m_failed_decrypt;
}

void Stats::increment_failed_decrypt()
{
    ++m_failed_decrypt;
}

boost::uint32_t Stats::get_eapol() const
{
    return m_eapol;
}

void Stats::increment_eapol()
{
    ++m_eapol;
}
