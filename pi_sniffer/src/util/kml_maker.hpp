#ifndef KML_MAKER_HPP
#define KML_MAKER_HPP

#include <map>
#include <string>
#include <vector>
#include <boost/ptr_container/ptr_unordered_map.hpp>

class AP;

class KML_Maker
{
public:

    KML_Maker();
    ~KML_Maker();

    void load_aps(boost::ptr_unordered_map<boost::uint64_t, AP>& p_ap);
    void write_all(const std::string& p_filename) const;

private:

    void write_open(const std::string& p_filename) const;
    void write_wep(const std::string& p_filename) const;
    void write_wpa(const std::string& p_filename) const;

    std::string write_color(const std::string& p_color) const;
    std::string write_ap(const std::map<boost::uint64_t, AP*>& p_aps) const;

private:
    std::map<boost::uint64_t, AP*> m_open;
    std::map<boost::uint64_t, AP*> m_wep;
    std::map<boost::uint64_t, AP*> m_wpa;
};

#endif