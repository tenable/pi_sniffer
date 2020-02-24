#include "pcap.hpp"
#include "packet.hpp"

#include <boost/lexical_cast.hpp>
#include <boost/concept_check.hpp>
#include <boost/static_assert.hpp>

namespace
{
    unsigned char data[65535] = {0};

    #pragma pack(push, 1)
    struct pcap_header
    {
        boost::uint32_t magic_number;
        boost::uint16_t version_major;
        boost::uint16_t version_minor;
        boost::uint32_t thiszone;
        boost::uint32_t sigfigs;
        boost::uint32_t snaplen;
        boost::uint32_t network;
    };

    struct packet_header
    {
        boost::uint32_t ts_sec;
        boost::uint32_t ts_usec;
        boost::uint32_t incl_len;
        boost::uint32_t orig_len;
    };

    struct ppi_packetheader
    {
        boost::uint8_t pph_version;
        boost::uint8_t pph_flags;
        boost::uint16_t pph_len;
        boost::uint32_t pph_dlt;
    };

    struct ppi_fieldheader
    {
        boost::uint16_t pfh_type;
        boost::uint16_t pfh_datalen;
    };

    struct gps_fields
    {
        boost::uint8_t gps_revision;
        boost::uint8_t gps_pad;
        boost::uint16_t gps_length;
        boost::uint32_t gps_present;
        boost::uint32_t gps_lat;
        boost::uint32_t gps_long;
        boost::uint32_t gps_alt;
        boost::uint32_t gps_app;
    };

    struct radiotap_header
    {
        boost::uint8_t version;
        boost::uint8_t pad;
        boost::uint16_t len;
        boost::uint32_t present;
    };

    struct ppi_common
    {
        boost::uint64_t tsft;
        boost::uint16_t flags;
        boost::uint16_t rate;
        boost::uint16_t frequency;
        boost::uint16_t channel_type;
        boost::uint8_t hopset;
        boost::uint8_t pattern;
        boost::uint8_t rssi;
        boost::uint8_t noise;
    };

    #pragma pack(pop)

    // harris crap
    double fixed_3_7_to_flt(boost::uint32_t in)
    {
        boost::int32_t remapped = in - (180 * 10000000);
        return static_cast<double>(remapped) / 10000000;
    }

    double fixed_6_4_to_flt(boost::uint32_t in)
    {
        boost::int32_t remapped_in = in - (180000 * 10000);
        double ret = (double) ((double) remapped_in / 10000);
        return ret;
    }
}

PCAP::PCAP(std::string p_filename) :
    m_file(p_filename.c_str(), std::ios::binary),
    m_linktype(0)
{
}

PCAP::~PCAP()
{
}

bool PCAP::initialize()
{
    if (!m_file.is_open())
    {
        return false;
    }

    m_file.read(reinterpret_cast<char*>(&data[0]), sizeof(pcap_header));
    if (m_file.gcount() != sizeof(pcap_header))
    {
        return false;
    }

    struct pcap_header* header = reinterpret_cast<struct pcap_header*>(data);
    if (header->magic_number != 0xa1b2c3d4)
    {
        return false;
    }

    if (header->network != 192 && header->network != 127 && header->network != 105)
    {
        return false;
    }

    m_linktype = header->network;
    return true;
}

bool PCAP::eof() const
{
    return m_file.eof() && m_file.good();
}

bool PCAP::get_packet(Packet& p_packet)
{
    m_file.read(reinterpret_cast<char*>(&data[0]), sizeof(packet_header));
    if (m_file.gcount() != sizeof(packet_header))
    {
        return false;
    }

    struct packet_header* header = reinterpret_cast<struct packet_header*>(data);
    p_packet.m_time = header->ts_sec;
    p_packet.m_stats.increment_packets();

    boost::uint32_t length = header->incl_len;
    m_file.read(reinterpret_cast<char*>(&data[0]), length);
    if (m_file.gcount() != static_cast<std::streamsize>(length) ||
        length < static_cast<std::size_t>(4))
    {
        return false;
    }

    switch (m_linktype)
    {
        case 127:
            return do_radiotap(p_packet, length);
        case 192:
            return do_ppi(p_packet, length);
        default:
            //uhm... ok
            break;
    }

    p_packet.m_data = data;
    p_packet.m_length = length;
    return true;
}

bool PCAP::do_radiotap(Packet& p_packet, boost::uint32_t p_length)
{
    struct radiotap_header* radio_header = reinterpret_cast<struct radiotap_header*>(data);
    if (radio_header->version != 0)
    {
        return false;
    }

    if (p_length < radio_header->len)
    {
        return false;
    }

    bool has_fcs = false;
    unsigned char* radio_tags = data + sizeof(radiotap_header);
    if ((radio_header->present & 0x01) != 0)
    {
        // mac timestamp
        radio_tags += 8;
    }
    if ((radio_header->present & 0x02) != 0)
    {
        // flags
        unsigned char flags = radio_tags[0];
        if (flags & 0x10)
        {
            has_fcs = true;
        }
        radio_tags += 1;
    }
    if ((radio_header->present & 0x04) != 0)
    {
        // rate
        radio_tags += 1;
    }
    if ((radio_header->present & 0x08) != 0)
    {
        // channel frequency / type
        radio_tags += 4;
    }
    if ((radio_header->present & 0x10) != 0)
    {
        // fhss
        radio_tags += 2;
    }
    if ((radio_header->present & 0x20) != 0)
    {
        //signal
        p_packet.m_signal = radio_tags[0];
    }

    p_packet.m_data = data + radio_header->len;
    p_packet.m_length = p_length - radio_header->len;
    if (has_fcs)
    {
        p_packet.m_length -= 4;
    }

    return true;
}

bool PCAP::do_ppi(Packet& p_packet, boost::uint32_t p_length)
{
    struct ppi_packetheader* ppi_header = reinterpret_cast<struct ppi_packetheader*>(data);
    if (ppi_header->pph_version != 0)
    {
        return false;
    }

    if (ppi_header->pph_dlt != 105)
    {
        return false;
    }

    if (p_length < ppi_header->pph_len )
    {
        return false;
    }

    // check the next field type
    struct ppi_fieldheader* field_header = reinterpret_cast<struct ppi_fieldheader*>(data + sizeof(ppi_packetheader));
    if (field_header->pfh_type == 0x7532)
    {
        // gps info
        struct gps_fields* gps = reinterpret_cast<struct gps_fields*>(data + sizeof(ppi_packetheader) + sizeof(ppi_fieldheader));
        if (gps->gps_length == field_header->pfh_datalen)
        {
            if (gps->gps_present == 0x2000000e)
            {
                p_packet.m_gps_on = true;
                p_packet.m_lat = fixed_3_7_to_flt(gps->gps_lat);
                p_packet.m_long = fixed_3_7_to_flt(gps->gps_long);
                p_packet.m_alt = fixed_6_4_to_flt(gps->gps_alt);

                // try the next field
                field_header = reinterpret_cast<struct ppi_fieldheader*>(
                    reinterpret_cast<char*>(gps) + gps->gps_length);    
            }
        }
    }

    if (field_header->pfh_type == 0x0002)
    {
        // 802.11 common
        struct ppi_common* common = reinterpret_cast<struct ppi_common*>(reinterpret_cast<char*>(field_header) + 4);
        p_packet.m_signal = common->rssi;
    }

    p_packet.m_data = data + ppi_header->pph_len;
    p_packet.m_length = p_length - ppi_header->pph_len;
    return true;
}
