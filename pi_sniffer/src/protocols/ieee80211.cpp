#include "ieee80211.hpp"

#include "packet.hpp"
#include "client.hpp"
#include "ap.hpp"
#include "probed_network.hpp"
#include "util/convert.hpp"

#include <tins/dot11/dot11_data.h>

#include <boost/cstdint.hpp>
#include <boost/foreach.hpp>

#include <cctype>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <netinet/in.h>

IEEE80211::IEEE80211() :
    m_snap(),
    m_pcap_out()
{
}

IEEE80211::~IEEE80211()
{
}

bool IEEE80211::handle_packet(Packet& p_packet)
{
    if (p_packet.m_length < 8)
    {
        return false;
    }

    switch (p_packet.m_data[0])
    {
        case 0x00:
            do_association(p_packet);
            break;
        case 0x40:
            do_probe_request(p_packet);
            break;
        case 0x50:
            do_probe_response(p_packet);
            break;
        case 0x80:
            do_beacon(p_packet);
            break;
        case 0x08:
            do_data(p_packet);
            break;
        case 0x88:
            do_qos(p_packet);
            break;
        default:
            break;
    }

    return true;
}

AP* IEEE80211::get_ap(Packet& p_packet,
                                       std::size_t p_ssid_offset)
{
    boost::uint64_t bssid_mac = (*reinterpret_cast<const boost::uint64_t*>(
        p_packet.m_data + p_ssid_offset));

    bssid_mac = (bssid_mac >> 16);
    bssid_mac = (bssid_mac << 16);
    bssid_mac = be64toh(bssid_mac);
    return p_packet.find_ap(bssid_mac);
}

Client* IEEE80211::get_client(Packet& p_packet, std::size_t p_src_offset, bool p_associated)
{
    boost::uint64_t src_mac = (*reinterpret_cast<const boost::uint64_t*>(
        p_packet.m_data + p_src_offset));

    src_mac = (src_mac >> 16);
    src_mac = (src_mac << 16);
    src_mac = be64toh(src_mac);
    if (src_mac == 0x0000ffffffffffffULL)
    {
        return NULL;
    }
    return p_packet.find_client(src_mac, p_associated);
}

void IEEE80211::do_probe_request(Packet& p_packet)
{
    if (p_packet.get_const_config().get_pcap())
    {
        m_pcap_out.add_packet(p_packet);
    }

    if (p_packet.m_length <= 26)
    {
        return;
    }

    // don't want to allocate a client for this since we only track associated
    // clients. However, we want to track probbed networks, so extract the transmitter
    boost::uint64_t src_mac = (*reinterpret_cast<const boost::uint64_t*>(
        p_packet.m_data + 8));
    src_mac = (src_mac >> 16);
    src_mac = (src_mac << 16);
    src_mac = be64toh(src_mac);
    unsigned char* mac = reinterpret_cast<unsigned char*>(&src_mac);
    std::string mac_address(printable_mac(mac, 6));

    // TODO this should really reuse the tagged parameters loop
    if (p_packet.m_data[24] == 0)
    {
        if (p_packet.m_length < static_cast<std::size_t>(24 + p_packet.m_data[25]))
        {
            return;
        }

        std::string ssid(reinterpret_cast<const char*>(p_packet.m_data + 26), p_packet.m_data[25]);
        p_packet.add_probe_network(ssid, mac_address);
    }
}

void IEEE80211::do_probe_response(Packet& p_packet)
{
    do_beacon(p_packet);
}

void IEEE80211::do_beacon(Packet& p_packet)
{
    if (p_packet.get_const_config().get_pcap())
    {
        m_pcap_out.add_packet(p_packet);
    }

    AP* found = get_ap(p_packet, 14);

    p_packet.m_stats.increment_beacons();

    if (found->get_beacon_parsed())
    {
        // let's only do this once
        return;
    }

    if (p_packet.m_length < 36)
    {
        return;
    }

    const unsigned char* management_frame = p_packet.m_data + 24;
    boost::uint16_t capabilities = *reinterpret_cast<const boost::uint16_t*>(management_frame + 10);

    if ((capabilities & 0x0010) != 0)
    {
        found->set_encryption("WEP");
    }
    else
    {
        found->set_encryption("None");
        p_packet.m_stats.increment_unencrypted();
    }

    boost::uint16_t tagged_length = p_packet.m_length - 36;
    if (tagged_length == 0)
    {
        return;
    }

    bool found_ssid = false;
    bool wpa = false;
    bool wpa2 = false;
    bool psk = false;
    bool eap = false;

    const unsigned char* tagged_data = management_frame + 12;
    while (tagged_length > 2)
    {
        if (tagged_length < (tagged_data[1] + 2))
        {
            break;
        }

        boost::uint8_t tag = tagged_data[0];
        boost::uint8_t length = tagged_data[1];
        const unsigned char* value = tagged_data + 2;

        // skip over this data
        tagged_length -= (tagged_data[1] + 2);
        tagged_data += (tagged_data[1] + 2);

        switch (tag)
        {
            case 0:
                if (found_ssid)
                {
                    break;
                }
                found_ssid = true;
                if (length != 0)
                {
                    if (value[0] != 0)
                    {
                        std::string ssid(reinterpret_cast<const char*>(value), length);
                        found->set_ssid(ssid);
                    }
                }
                else
                {
                    found->set_ssid("<Unknown>");
                }
                break;
            case 3:
                found->set_channel(value[0]);
                break;
            case 0x30: // RSN
            {
                if (length <= 8)
                {
                    break;
                }
                // jump version and oui lead in
                value += 6;
                boost::uint16_t pairwise = *reinterpret_cast<const boost::uint16_t*>(value);

                if (length <= (8 + (pairwise * 4)))
                {
                    break;
                }
                value += 2;
                for (boost::uint16_t pair_loop = pairwise ; pair_loop > 0; --pair_loop)
                {

                    if (value[3] == 0x04)
                    {
                        wpa2 = true;
                    }
                    value += 4;
                }

                if (!wpa2)
                {
                    wpa = true;
                }

                boost::uint16_t auth = *reinterpret_cast<const boost::uint16_t*>(value);
                if (length <= (10 + (pairwise * 4) + (auth * 4)))
                {
                    break;
                }
                value += 2;
                for ( ; auth > 0; --auth)
                {
                    if (value[3] == 0x02)
                    {
                        psk = true;
                    }
                    else if(value[3] == 1)
                    {
                        eap = true;
                    }
                    value += 4;
                }
                break;
            }
            case 0xdd:
                if (length > 4 && memcmp(value, "\x00\x50\xf2", 3) == 0) // MS
                {
                    switch(value[3])
                    {
                        case 1: // WPA IE
                        {
                            if (length <= 12)
                            {
                                break;
                            }
                            wpa = true;

                            // jump version and oui lead in
                            value += 10;
                            boost::uint16_t pairwise = *reinterpret_cast<const boost::uint16_t*>(value);
                            if (length <= (12 + (pairwise * 4)))
                            {
                                break;
                            }

                            value += 2;
                            for (boost::uint16_t pair_loop = pairwise; pair_loop > 0; --pair_loop)
                            {
                                value += 4;
                            }

                            boost::uint16_t auth = *reinterpret_cast<const boost::uint16_t*>(value);
                            if (length <= (14 + (pairwise * 4) + (auth * 4)))
                            {
                                break;
                            }
                            for ( ; auth > 0; --auth)
                            {
                                if (value[3] == 0x02)
                                {
                                    psk = true;
                                }
                                else if (value[3] == 1)
                                {
                                    eap = true;
                                }
                                value += 4;
                            }
                            break;
                        }
                        case 4: // wps
                            // skip over oui and type
                            value += 4;
                            length -= 4;

                            while (length > 4)
                            {
                                boost::uint16_t type = ntohs(*reinterpret_cast<const boost::uint16_t*>(value));
                                value += 2;
                                length -= 2;
                                boost::uint16_t inner_length = ntohs(*reinterpret_cast<const boost::uint16_t*>(value));
                                value += 2;
                                length -= 2;

                                if (inner_length > length)
                                {
                                    break;
                                }

                                switch (type)
                                {
                                    case 0x1011:
                                        if (found->get_ssid().empty())
                                        {
                                            found->set_ssid(std::string(reinterpret_cast<const char*>(value), inner_length));
                                        }
                                        break;
                                    case 0x1044:
                                        if (*value == 0x02)
                                        {
                                            found->set_wps(true);
                                            p_packet.m_stats.increment_wps();
                                        }
                                        break;
                                    default:
                                        break;
                                }

                                value += inner_length;
                                length -= inner_length;
                            }
                            break;
                        default:
                            break;
                    }
                }
                break;
            default:
                break;
        }
    }

    // libtins wants a shot at the beacon... honestly we should just rewrite to use libtins
    if (p_packet.m_current_router &&
        p_packet.get_const_config().has_wpa_key(p_packet.m_current_router->get_ssid()))
    {
        try
        {
            boost::scoped_ptr<Tins::Dot11> tinsPacket(Tins::Dot11::from_bytes(p_packet.m_data, p_packet.m_length));
            if (tinsPacket.get() != NULL)
            {
                p_packet.get_config().m_wpa_decrypter.decrypt(*tinsPacket);
            }
        }
        catch (const std::exception&)
        {
        }
    }

    found->set_beacon_parsed();
    std::string encryption;
    if (wpa)
    {
        encryption.append("WPA");
    }

    if (wpa2)
    {
        if (!encryption.empty())
        {
            encryption.push_back('/');
        }

        encryption.append("WPA2");
    }

    if (wpa || wpa2)
    {
        p_packet.m_stats.increment_wpa();
    }
    else if (found->get_encryption() == "WEP")
    {
        p_packet.m_stats.increment_wep();
    }

    if (psk)
    {
        encryption.append("-PSK");
    }
    else if (eap)
    {
        encryption.append("-EAP");
    }

    if (!encryption.empty())
    {
        found->set_encryption(encryption);
    }
}

void IEEE80211::do_association(Packet& p_packet)
{
    if (p_packet.get_const_config().get_pcap())
    {
        m_pcap_out.add_packet(p_packet);
    }

    AP* found = get_ap(p_packet, 14);

    if (p_packet.m_length < 36)
    {
        return;
    }

    const unsigned char* management_frame = p_packet.m_data + 24;
    boost::uint16_t tagged_length = p_packet.m_length - 36;
    if (tagged_length == 0)
    {
        return;
    }

    bool found_ssid = false;
    const unsigned char* tagged_data = management_frame + 4;

    while (tagged_length > 2)
    {
        if (tagged_length < (tagged_data[1] + 2))
        {
            break;
        }

        boost::uint8_t tag = tagged_data[0];
        boost::uint8_t length = tagged_data[1];
        const unsigned char* value = tagged_data + 2;

        tagged_length -= (tagged_data[1] + 2);
        tagged_data += (tagged_data[1] + 2);

        switch (tag)
        {
            case 0:
                if (found_ssid)
                {
                    break;
                }
                found_ssid = true;
                if (length != 0)
                {
                    if (value[0] != 0)
                    {
                        std::string ssid(reinterpret_cast<const char*>(value), length);
                        found->set_ssid(ssid);
                    }
                }
                else
                {
                    found->set_ssid("<Unknown>");
                }
                break;
            case 3:
                found->set_channel(value[0]);
                break;
            default:
                break;
        }
    }
}

void IEEE80211::do_data(Packet& p_packet)
{
    AP* found = NULL;
    Client* client = NULL;
    if ((p_packet.m_data[1] & 0x03) == 0x03)
    {
        found = get_ap(p_packet, 8);
        client = get_client(p_packet, 22, true);
        if (client == NULL)
        {
            return;
        }
        p_packet.m_from_client = true;
        p_packet.m_length -= 6;
        p_packet.m_data += 6;
    }
    else if ((p_packet.m_data[1] & 0x02) == 2)
    {
        found = get_ap(p_packet, 8);
        if (memcmp(p_packet.m_data + 10, p_packet.m_data + 16, 6) != 0)
        {
            client = get_client(p_packet, 14, true);
            if (client == NULL)
            {
                return;
            }
            p_packet.m_from_client = true;
        }
        else
        {
            p_packet.m_from_client = false;
        }
    }
    else if((p_packet.m_data[1] & 0x01) == 1)
    {
        found = get_ap(p_packet, 2);
        client = get_client(p_packet, 8, true);
        if (client == NULL)
        {
            return;
        }
        p_packet.m_from_client = true;
    }
    else
    {
        found = get_ap(p_packet, 14);
        client = get_client(p_packet, 8, true);
        if (client == NULL)
        {
            return;
        }
        p_packet.m_from_client = true;
    }

    found->increment_data_packet();
    p_packet.m_stats.increment_data_packets();

    if (p_packet.m_length > 24)
    {
        handle_data(p_packet, 24);
    }
}

void IEEE80211::do_qos(Packet& p_packet)
{
    AP* found = NULL;
    Client* client = NULL;
    if ((p_packet.m_data[1] & 0x03) == 0x03)
    {
        found = get_ap(p_packet, 8);
        client = get_client(p_packet, 22, true);
        if (client == NULL)
        {
            return;
        }
        p_packet.m_from_client = true;
        p_packet.m_length -= 6;
        p_packet.m_data += 6;
    }
    else if ((p_packet.m_data[1] & 0x02) == 2)
    {
        found = get_ap(p_packet, 8);
        client = get_client(p_packet, 14, true);
        if (client == NULL)
        {
            return;
        }
        p_packet.m_from_client = false;
    }
    else if ((p_packet.m_data[1] & 0x01) == 1)
    {
        found = get_ap(p_packet, 2);
        client = get_client(p_packet, 8, true);
        if (client == NULL)
        {
            return;
        }
        p_packet.m_from_client = true;
    }
    else
    {
        found = get_ap(p_packet, 14);
        client = get_client(p_packet, 8, true);
        if (client == NULL)
        {
            return;
        }
        p_packet.m_from_client = true;
    }

    found->increment_data_packet();
    p_packet.m_stats.increment_data_packets();

    if (p_packet.m_length > 26)
    {
        handle_data(p_packet, 26);
    }
}

void IEEE80211::handle_data(Packet& p_packet, boost::uint32_t p_increment)
{
    // check if we have a snap header
    if (memcmp(p_packet.m_data + p_increment, "\xaa\xaa\x03", 3) == 0)
    {
        if (p_packet.get_const_config().get_pcap())
        {
            m_pcap_out.add_packet(p_packet);
        }

        // libtins wants a shot at the handshake... honestly we should just rewrite to use libtins
        if (p_packet.m_current_router &&
            p_packet.get_const_config().has_wpa_key(p_packet.m_current_router->get_ssid()))
        {
            try
            {
                boost::scoped_ptr<Tins::Dot11> tinsPacket(Tins::Dot11::from_bytes(p_packet.m_data, p_packet.m_length));
                if (tinsPacket.get() != NULL)
                {
                    p_packet.get_config().m_wpa_decrypter.decrypt(*tinsPacket);
                }
            }
            catch (const std::exception&)
            {
            }
        }

        p_packet.m_length -= p_increment;
        p_packet.m_data += p_increment;
        m_snap.handle_packet(p_packet);
    }
    else
    {
        // is this wep or wpa?
        const std::string& encryption(p_packet.m_current_router->get_encryption());
        if (encryption == "WEP")
        {
            p_packet.m_stats.increment_encrypted();
            handle_wep(p_packet);
        }
        else if (!encryption.empty())
        {
            p_packet.m_stats.increment_encrypted();
            handle_wpa(p_packet);
        }
        else if (p_packet.get_config().get_pcap())
        {
            // cleartext that isn't SNAP
            m_pcap_out.add_packet(p_packet);
        }
    }
}

void IEEE80211::handle_wep(Packet& p_packet)
{
    if (p_packet.m_current_router &&
        p_packet.get_const_config().has_wep_key(p_packet.m_current_router->get_mac()))
    {
        try
        {
            boost::scoped_ptr<Tins::Dot11> tinsPacket(Tins::Dot11::from_bytes(p_packet.m_data, p_packet.m_length));
            if (tinsPacket.get() != NULL)
            {
                bool return_value = p_packet.get_config().m_wep_decrypter.decrypt(*tinsPacket);
                if (return_value)
                {
                    std::vector<unsigned char> decrypted = tinsPacket->serialize();
                    if (!decrypted.empty())
                    {
                        p_packet.m_stats.increment_decrypted();
                        p_packet.m_data = &decrypted[0];
                        p_packet.m_length = decrypted.size();

                        if (p_packet.get_const_config().get_pcap())
                        {
                            // write the decrypted version to the pcap
                            m_pcap_out.add_packet(p_packet);
                        }

                        if (memcmp(p_packet.m_data, "\xaa\xaa\x03\x00\x00", 5) == 0)
                        {
                            // we only really handle snap at this point
                            m_snap.handle_packet(p_packet);
                        }
                        return;
                    }
                }

                // decryption failed for some reason
                p_packet.m_stats.increment_failed_decrypt();
            }
        }
        catch (std::exception&)
        {
        }
    }

    if (p_packet.get_const_config().get_pcap())
    {
        m_pcap_out.add_packet(p_packet);
    }

}

 void IEEE80211::handle_wpa(Packet& p_packet)
 {
    if (p_packet.m_current_router &&
        p_packet.get_const_config().has_wpa_key(p_packet.m_current_router->get_ssid()))
    {
        try
        {
            boost::scoped_ptr<Tins::Dot11> tinsPacket(Tins::Dot11::from_bytes(p_packet.m_data, p_packet.m_length));
            if (tinsPacket.get() != NULL)
            {
                bool return_value = p_packet.get_config().m_wpa_decrypter.decrypt(*tinsPacket);
                if (return_value)
                {
                    std::vector<unsigned char> decrypted = tinsPacket->serialize();
                    if (!decrypted.empty())
                    {
                        p_packet.m_stats.increment_decrypted();
                        p_packet.m_data = &decrypted[0];
                        p_packet.m_length = decrypted.size();

                        if (p_packet.get_const_config().get_pcap())
                        {
                            // write the decrypted version to the pcap
                            m_pcap_out.add_packet(p_packet);
                        }

                        if (memcmp(p_packet.m_data, "\xaa\xaa\x03\x00\x00", 5) == 0)
                        {
                            // we only really handle snap at this point
                            m_snap.handle_packet(p_packet);
                        }
                        return;
                    }
                }
                // decryption failed for some reason
                p_packet.m_stats.increment_failed_decrypt();
            }
        }
        catch (std::exception&)
        {
        }
    }

    if (p_packet.get_const_config().get_pcap())
    {
        m_pcap_out.add_packet(p_packet);
    }
 }
