#ifndef STATS_HPP
#define STATS_HPP

#include <boost/thread.hpp>
#include <boost/cstdint.hpp>

/**
 * Stats is a an object that is largely a wrapper simple counters. The information
 * in stats is tracked to get a high level overview of what the engine has seen.
 * Most useful in a overview type screen or shutdown stats.
 */
class Stats
{
public:

    Stats();
    ~Stats();

    void increment_unencrypted();
    boost::uint32_t get_unencrypted() const;

    void increment_wep();
    boost::uint32_t get_wep() const;

    void increment_wpa();
    boost::uint32_t get_wpa() const;

    void increment_wps();

    void increment_data_packets();
    boost::uint32_t get_data_packets() const;

    void increment_packets();
    boost::uint32_t get_packets() const;

    void increment_beacons();
    boost::uint32_t get_beacons() const;

    void increment_probe_requests();

    boost::uint32_t get_encrypted() const;
    void increment_encrypted();

    boost::uint32_t get_decrypted() const;
    void increment_decrypted();

    boost::uint32_t get_failed_decrypt() const;
    void increment_failed_decrypt();

    boost::uint32_t get_eapol() const;
    void increment_eapol();

private:

    Stats(const Stats& p_rhs);
    Stats& operator=(const Stats& p_rhs);

private:

    boost::mutex m_accesslock;

    boost::uint32_t m_unecrypted;
    boost::uint32_t m_wep;
    boost::uint32_t m_wpa;
    boost::uint32_t m_wps;
    boost::uint32_t m_data;
    boost::uint32_t m_encrypted;
    boost::uint32_t m_decrypted;
    boost::uint32_t m_failed_decrypt;
    boost::uint32_t m_packets;
    boost::uint32_t m_beacons;
    boost::uint32_t m_eapol;
};

#endif
