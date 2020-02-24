#include <string>
#include <cstddef>
#include <boost/array.hpp>
#include <boost/cstdint.hpp>
#include <tins/hw_address.h>

std::string printable_mac(const unsigned char* p_data, std::size_t p_length, bool p_reverse = true);
boost::uint64_t string_mac_to_int(const std::string& p_mac);
Tins::HWAddress<6> int_mac_to_array(boost::uint64_t p_mac);
std::string string_to_hex(const std::string& p_hex);
