#include "convert.hpp"

#include <string>
#include <cassert>
#include <stdexcept>
#include <cctype>
#include <algorithm>
#include <vector>

#include <boost/foreach.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/address_v6.hpp>

#ifdef OS_WINDOWS
#include <stdlib.h>
#endif

namespace
{
    const unsigned char k_hex[] =
    {
        '0','1','2','3','4','5','6','7',
        '8','9','a','b','c','d','e','f'
    };

    const unsigned char k_hex_int[] =
    {
        0, 1, 2, 3, 4, 5, 6, 7,
        8, 9, 10, 11, 12, 13, 14, 15
    };

    const char b64_table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    static const char reverse_table[128] =
    {
        64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 62, 64, 64, 64, 63,
        52, 53, 54, 55, 56, 57, 58, 59,
        60, 61, 64, 64, 64, 64, 64, 64,
        64,  0,  1,  2,  3,  4,  5,  6,
        7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22,
        23, 24, 25, 64, 64, 64, 64, 64,
        64, 26, 27, 28, 29, 30, 31, 32,
        33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48,
        49, 50, 51, 64, 64, 64, 64, 64
    };

}

std::string printable_mac(const unsigned char* p_data, std::size_t p_length, bool p_reverse)
{
    std::string return_string;

    for(std::size_t byte = 0; byte < p_length; ++byte)
    {
        if (p_reverse)
        {
            return_string.push_back(k_hex[p_data[byte] & 0x0F]);
            return_string.push_back(k_hex[(p_data[byte] >> 4) & 0x0F]);
        }
        else
        {
            return_string.push_back(k_hex[(p_data[byte] >> 4) & 0x0F]);
            return_string.push_back(k_hex[p_data[byte] & 0x0F]);
        }

        if(byte + 1 != p_length)
        {
            return_string.push_back(':');
        }
    }

    if (p_reverse)
    {
        std::reverse(return_string.begin(), return_string.end());
    }

    return return_string;
}

boost::uint64_t string_mac_to_int(const std::string& p_mac)
{
    std::vector<std::string> octets;
    boost::algorithm::split(octets, p_mac, boost::is_any_of(":"));

    if (octets.size() != 6)
    {
        throw std::runtime_error("Malformed MAC address");
    }

    boost::uint64_t return_value = 0;
    BOOST_FOREACH(std::string& octet, octets)
    {
        unsigned int convert = 0;
        std::stringstream in;
        in << std::hex << octet;
        in >> convert;
        convert = (convert & 0xff);
        return_value = (return_value << 8);
        return_value |= (convert & 0xff);
    }

    return return_value;
}

Tins::HWAddress<6> int_mac_to_array(boost::uint64_t p_mac)
{
    boost::array<unsigned char, 6> address;
    for (int i = 5, j=0; i >= 0; --i, ++j)
    {
        address[i] = reinterpret_cast<unsigned char*>(&p_mac)[j];
    }

    Tins::HWAddress<6> return_value(address.c_array());
    return return_value;
}

std::string string_to_hex(const std::string& p_mac1)
{
    std::string p_mac(p_mac1);
    std::string return_value;
    unsigned char hex_value = 0;

    if ((p_mac.size() % 2) != 0)
    {
        throw std::runtime_error("Hex strings must have both nibbles");
    }

    // replace the a-f values
    for (std::size_t i = 0; i < p_mac.size(); ++i)
    {
        switch (p_mac[i])
        {
            case '0':
                p_mac[i] = 0x00;
                break;
            case '1':
                p_mac[i] = 0x01;
                break;
            case '2':
                p_mac[i] = 0x02;
                break;
            case '3':
                p_mac[i] = 0x03;
                break;
            case '4':
                p_mac[i] = 0x04;
                break;
            case '5':
                p_mac[i] = 0x05;
                break;
            case '6':
                p_mac[i] = 0x06;
                break;
            case '7':
                p_mac[i] = 0x07;
                break;
            case '8':
                p_mac[i] = 0x08;
                break;
            case '9':
                p_mac[i] = 0x09;
                break;
            case 'a':
                p_mac[i] = 0x0a;
                break;
            case 'b':
                p_mac[i] = 0x0b;
                break;
            case 'c':
                p_mac[i] = 0x0c;
                break;
            case 'd':
                p_mac[i] = 0x0d;
                break;
            case 'e':
                p_mac[i] = 0x0e;
                break;
            case 'f':
                p_mac[i] = 0x0f;
                break;
            default:
                std::stringstream error;
                error << "Non hex value in decrypt key: " << p_mac[i];
                throw std::runtime_error(error.str());
        }

        if ((i % 2) == 0)
        {
            hex_value = p_mac[i];
            hex_value = (hex_value << 4) & 0xf0;
        }
        else
        {
            hex_value |= (p_mac[i] & 0x0f);
            return_value.push_back(hex_value);
            hex_value = 0;
        }
    }

 
    return return_value;
}

