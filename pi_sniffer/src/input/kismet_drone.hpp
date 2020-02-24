#ifndef KISMET_DRONE_HPP
#define KISMET_DRONE_HPP

#include <cstddef>
#include <string>
#include <boost/asio.hpp>

class Packet;

class KismetDrone
{
public:
    KismetDrone(const std::string& p_address, std::size_t p_port);
    ~KismetDrone();

    bool get_packet(Packet& p_packet);
    bool connect();

private:

    bool read(boost::uint32_t p_length, std::string& p_data);
    void check_deadline();
    void close();

private:

    KismetDrone(const KismetDrone& p_rhs);
    KismetDrone& operator=(const KismetDrone& p_rhs);

private:

    // the ip address to connect to
    std::string m_ip;

    // the port to connect to
    std::string m_port;

    // the IO service associated with our blocking socket
    boost::asio::io_service m_io_service;

    // the blocking socket we use for communication
    boost::asio::ip::tcp::socket m_socket;

    // Timer to use with async socket operations
    boost::asio::deadline_timer m_deadline;
};

#endif