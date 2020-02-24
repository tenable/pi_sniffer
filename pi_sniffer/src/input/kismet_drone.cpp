#include "kismet_drone.hpp"

#include "packet.hpp"
#include "stats.hpp"

#include <iostream>
#include <boost/lambda/bind.hpp>
#include <boost/lambda/lambda.hpp>

namespace
{
    // hold the packet data that goes down to the protocols
    std::string s_drone_data;

    #pragma pack(push, 1)
    struct drone_trans_double
    {
        uint32_t mantissal;
        uint32_t mantissah;
        uint16_t exponent;
        uint16_t sign;
    };

    struct ieee_double_t
    {
        unsigned int mantissal:32;
        unsigned int mantissah:20;
        unsigned int exponent:11;
        unsigned int sign:1;
    };
    #pragma pack(pop)

    void double_conversion_drone(double& x, drone_trans_double* y)
    {
        ieee_double_t* locfl = (ieee_double_t *)&(x);
        (locfl)->mantissal = ntohl((y)->mantissal);
        (locfl)->mantissah = ntohl((y)->mantissah);
        (locfl)->exponent = ntohs((y)->exponent);
        (locfl)->sign = ntohs((y)->sign);
    }
}

KismetDrone::KismetDrone(const std::string& p_address, std::size_t p_port) :
    m_ip(p_address),
    m_port(),
    m_io_service(),
    m_socket(m_io_service),
    m_deadline(m_io_service)
{
    std::stringstream portString;
    portString << p_port;
    m_port = portString.str();

    m_deadline.expires_at(boost::posix_time::pos_infin);
    check_deadline();
}

KismetDrone::~KismetDrone()
{
    close();
}

void KismetDrone::close()
{
    try
    {
        m_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both);
        m_socket.close();
    }
    catch (...)
    {
    }
}

void KismetDrone::check_deadline()
{
    if (m_deadline.expires_at() <= boost::asio::deadline_timer::traits_type::now())
    {
      boost::system::error_code ignored_ec;
      m_socket.close(ignored_ec);
      m_deadline.expires_at(boost::posix_time::pos_infin);
    }

    m_deadline.async_wait(boost::lambda::bind(&KismetDrone::check_deadline, this));
}

bool KismetDrone::connect()
{
    std::cout << "Drone connecting..." << std::endl;
    try
    {
        boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::address::from_string(m_ip), atoi(m_port.c_str()));

        // set a 2 second deadline for the connection   
        boost::system::error_code ec = boost::asio::error::would_block;
        m_deadline.expires_from_now(boost::posix_time::seconds(5));
        m_socket.async_connect(endpoint, boost::lambda::var(ec) = boost::lambda::_1);

        do
        {
            m_io_service.run_one();
        }
        while (ec == boost::asio::error::would_block);

        if (ec || !m_socket.is_open())
        {
            return false;
        }
    }
    catch(const std::exception& e)
    {
        return false;
    }
    return true;
}

bool KismetDrone::read(boost::uint32_t p_length, std::string& p_data)
{
    boost::system::error_code ec = boost::asio::error::would_block;
    m_deadline.expires_from_now(boost::posix_time::seconds(5));

    boost::asio::streambuf response;
    boost::asio::async_read(m_socket, response, boost::asio::transfer_exactly(p_length), boost::lambda::var(ec) = boost::lambda::_1);
    do
    {
        m_io_service.run_one();
    }
    while (ec == boost::asio::error::would_block);

    if (ec)
    {
        return false;
    }

    p_data.assign(std::istreambuf_iterator<char>(&response), std::istreambuf_iterator<char>());
    response.consume(p_length);
    return true;
}

bool KismetDrone::get_packet(Packet& p_packet)
{
    boost::uint32_t type = 0;
    boost::uint32_t read_length = 0;
    boost::uint32_t offset = 0;
    boost::uint32_t bitmap = 0;
    while (type != 3)
    {
        if (!read(12, s_drone_data) || s_drone_data.size() != 12)
        {
            return false;
        }

        // check for sentinel
        if (static_cast<boost::uint8_t>(s_drone_data[0]) != 0xde ||
            static_cast<boost::uint8_t>(s_drone_data[3]) != 0xef)
        {
            return false;
        }

        // get the packet type (will indicate if we have a packet or not)
        type = *reinterpret_cast<boost::uint32_t*>(&s_drone_data[0] + 4);
        type = ntohl(type);

        // get length of the packet and read it all in
        read_length = *reinterpret_cast<boost::uint32_t*>(&s_drone_data[0] + 8);
        read_length = ntohl(read_length);

        if (!read(read_length, s_drone_data) || s_drone_data.size() != read_length)
        {
            return false;
        }

        bitmap = *reinterpret_cast<boost::uint32_t*>(&s_drone_data[0]);
        bitmap = ntohl(bitmap);
        if ((bitmap & 1) == 0)
        {
            // missing radio header.
            type = 2;
            continue;
        }

        offset = *reinterpret_cast<boost::uint32_t*>(&s_drone_data[0] + 4);
        offset = ntohl(offset) + 8;
        if (read_length == 12 || offset == 8)
        {
            // This is an empty packet.
            type = 2;
        }
    }

    if ((offset + 44) >= read_length)
    {
        // invalid packet
        return false;
    }

    if ((bitmap & 2) == 2)
    {
        // gps data present
        boost::uint16_t gps_size = *reinterpret_cast<boost::uint16_t*>(&s_drone_data[0] + 38);
        gps_size = ntohs(gps_size);
        if (gps_size == 68)
        {
            p_packet.m_gps_on = true;
            double_conversion_drone(p_packet.m_lat, reinterpret_cast<drone_trans_double*>(&s_drone_data[0] + 46));
            double_conversion_drone(p_packet.m_long, reinterpret_cast<drone_trans_double*>(&s_drone_data[0] + 46 + sizeof(drone_trans_double)));
            double_conversion_drone(p_packet.m_alt, reinterpret_cast<drone_trans_double*>(&s_drone_data[0] + 46 + (sizeof(drone_trans_double) * 2)));
        }
    }
    // grab the signal metadata
    boost::int16_t dbm = *reinterpret_cast<boost::int16_t*>(&s_drone_data[0] + 18);
    dbm = ntohs(dbm);

    // grab the metadata in the radio header
    boost::uint32_t time = *reinterpret_cast<boost::uint32_t*>(&s_drone_data[0] + (offset + 28));
    time = ntohl(time);

    // skip over the metadata
    p_packet.m_data = reinterpret_cast<const boost::uint8_t*>(&s_drone_data[0]) + (offset + 44);
    p_packet.m_length = read_length - (offset + 44);

    // update stats
    p_packet.m_stats.increment_packets();
    p_packet.m_time = time;
    p_packet.m_signal = dbm;

    return true;
}
