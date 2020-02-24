#include "kml_maker.hpp"

#include <algorithm>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>

#include <boost/foreach.hpp>

#include "ap.hpp"

namespace
{
    std::string s_header("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<kml xmlns=\"http://www.opengis.net/kml/2.2\">\n\t<Document>\n");
    std::string s_footer("\t\t</Folder>\n\t</Document>\n</kml>");
}

KML_Maker::KML_Maker() :
    m_open(),
    m_wep(),
    m_wpa()
{
}

KML_Maker::~KML_Maker()
{
}

void KML_Maker::load_aps(boost::ptr_unordered_map<boost::uint64_t, AP>& p_ap)
{
    for (boost::ptr_unordered_map<boost::uint64_t, AP>::iterator current_ap = p_ap.begin();
            current_ap != p_ap.end(); ++current_ap)
    {
        if (current_ap->second->get_best_longitude() > 1.0 || current_ap->second->get_best_longitude() < -1.0)
        {
            if (current_ap->second->get_encryption() == "WEP")
            {
                m_wep[current_ap->first] = current_ap->second;
            }
            else if (current_ap->second->get_encryption().find("WPA") != std::string::npos)
            {
                m_wpa[current_ap->first] = current_ap->second;
            }
            else
            {
                m_open[current_ap->first] = current_ap->second;
            }
        }
    }
}

std::string KML_Maker::write_color(const std::string& p_color) const
{
    std::string return_value;
    return_value.append("\t\t<Style id=\"");
    return_value.append(p_color);
    return_value.append("\">\n");
    return_value.append("\t\t\t<IconStyle>\n");
    return_value.append("\t\t\t\t<Icon><href>http://maps.google.com/mapfiles/ms/icons/");
    return_value.append(p_color);
    return_value.append("-dot.png</href></Icon>\n");
    return_value.append("\t\t\t</IconStyle>\n\t\t</Style>\n");
    return_value.append("\t\t<Folder>\n");
    return return_value;
}

std::string KML_Maker::write_ap(const std::map<boost::uint64_t, AP*>& p_aps) const
{
    std::string return_value;
    for (std::map<boost::uint64_t, AP*>::const_iterator current_ap = p_aps.begin();
            current_ap != p_aps.end(); ++current_ap)
    {
        return_value.append("\t\t\t<Placemark>\n\t\t\t\t<name><![CDATA[");
        return_value.append(current_ap->second->get_ssid());
        return_value.append("]]></name>\n\t\t\t\t<description>\n\t\t\t\t\t<![CDATA[BSSID: <b>");
        return_value.append(current_ap->second->get_mac());
        return_value.append("</b><br/>RSSI: <b>");
        std::stringstream rssi;
        rssi << static_cast<int>(current_ap->second->get_best_signal());
        return_value.append(rssi.str());
        return_value.append("</b><br/>Channel: <b>");
        std::stringstream channel;
        channel << (int)current_ap->second->get_channel();
        return_value.append(channel.str());
        return_value.append("</b><br/>Encryption: <b>");
        return_value.append(current_ap->second->get_encryption());
        return_value.append("</b><br/>First Seen: <b>");
        const long int timestamp = current_ap->second->get_first_seen();
        std::tm* t = std::localtime(&timestamp);
        std::stringstream firstTime;
        firstTime << std::put_time(t, "%Y-%m-%d %I:%M:%S %p");
        return_value.append(firstTime.str());
        return_value.append("</b>]]>\n\t\t\t\t</description>\n");
        return_value.append("\t\t\t\t<styleUrl>#");
        if (current_ap->second->get_encryption() == "WEP")
        {
            return_value.append("pink");
        }
        else if (current_ap->second->get_encryption().find("WPA") != std::string::npos)
        {
            return_value.append("green");
        }
        else
        {
            return_value.append("blue");
        }
        return_value.append("</styleUrl>\n\t\t\t\t<Point>\n\t\t\t\t\t<coordinates>");
        std::stringstream longitude;
        longitude << current_ap->second->get_best_longitude();
        return_value.append(longitude.str());
        return_value.append(",");
        std::stringstream latitude;
        latitude << current_ap->second->get_best_latitude();
        return_value.append(latitude.str());
        return_value.append("</coordinates>\n");
        return_value.append("\t\t\t\t</Point>\n\t\t\t</Placemark>\n");
    }
    return return_value;
}

void KML_Maker::write_all(const std::string& p_filename) const
{
    write_open(p_filename);
    write_wep(p_filename);
    write_wpa(p_filename);
}

void KML_Maker::write_open(const std::string& p_filename) const
{
    if (m_open.empty())
    {
        return;
    }

    std::string filename(p_filename + "_open.kml");

    std::ofstream open_ap;
    open_ap.open(filename);
    if (!open_ap.is_open())
    {
        return;
    }
    open_ap << s_header;
    open_ap << write_color("blue");
    open_ap << "\t\t<name>" << filename << "</name>\n";
    open_ap << write_ap(m_open);
    open_ap << s_footer;
    open_ap.close();
}

void KML_Maker::write_wep(const std::string& p_filename) const
{
    if (m_wep.empty())
    {
        return;
    }

    std::string filename(p_filename + "_wep.kml");

    std::ofstream wep_ap;
    wep_ap.open(filename);
    if (!wep_ap.is_open())
    {
        return;
    }
    wep_ap << s_header;
    wep_ap << write_color("pink");
    wep_ap << "\t\t<name>" << filename << "</name>\n";
    wep_ap << write_ap(m_wep);
    wep_ap << s_footer;
    wep_ap.close();
}

void KML_Maker::write_wpa(const std::string& p_filename) const
{
    if (m_wpa.empty())
    {
        return;
    }

    std::string filename(p_filename + "_wpa.kml");

    std::ofstream wpa_ap;
    wpa_ap.open(filename);
    if (!wpa_ap.is_open())
    {
        return;
    }
    wpa_ap << s_header;
    wpa_ap << write_color("green");
    wpa_ap << "\t\t<name>" << filename << "</name>\n";
    wpa_ap << write_ap(m_wpa);
    wpa_ap << s_footer;
    wpa_ap.close();
}


