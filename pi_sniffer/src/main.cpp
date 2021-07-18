#include <cstdlib>
#include <iostream>
#include <boost/thread.hpp>
#include <boost/program_options.hpp>

#include "util/convert.hpp"
#include "ap.hpp"
#include "client.hpp"
#include "packet.hpp"
#include "protocols/ieee80211.hpp"
#include "input/kismet_drone.hpp"
#include "input/pcap.hpp"

namespace
{
    bool parseCommandLine(int p_argCount, char* p_argArray[],
        std::string& p_server_address, std::size_t& p_server_port, std::string& p_file, Configuration& p_config)
    {
        boost::program_options::options_description description("options");
        description.add_options()("help,h", "A list of command line options")
                                 ("version,v", "Display version information")
                                 ("config,c", boost::program_options::value<std::string>()->default_value(std::string("/home/pi/pi_sniffer/pi_sniffer.conf"), ""), "The path to the configuration file")
                                 ("file,f", boost::program_options::value<std::string>(),"The file to parse.")
                                 ("kismet-address,k", boost::program_options::value<std::string>(), "The address of the kismet server.")
                                 ("kismet-port,p", boost::program_options::value<std::size_t>(), "The port of the kismet server.");

        boost::program_options::variables_map argv_map;
        try
        {
            boost::program_options::store(
                boost::program_options::parse_command_line(
                    p_argCount, p_argArray, description), argv_map);
        }
        catch (const std::exception& e)
        {
            std::cerr << e.what() << "\n" << std::endl;
            std::cout << description << std::endl;
            return false;
        }

        boost::program_options::notify(argv_map);
        if (argv_map.empty() || argv_map.count("help"))
        {
            std::cout << description << std::endl;
            return false;
        }

        if (argv_map.count("version"))
        {
            std::cout << "🦞  Pi Sniffer Alpha  🦞" << std::endl;
            return false;
        }

        if (argv_map.count("config"))
        {
            try
            {
                p_config.parse_configuration(argv_map["config"].as<std::string>());
            }
            catch (const std::runtime_error& e)
            {
                std::cerr << "Failed config parsing: " << e.what() << std::endl;
                return false;
            }
        }

        if (argv_map.count("file"))
        {
            p_file = argv_map["file"].as<std::string>();
            return true;
        }

        if (argv_map.count("kismet-port") && argv_map.count("kismet-address"))
        {
            p_server_port = argv_map["kismet-port"].as<std::size_t>();
            p_server_address = argv_map["kismet-address"].as<std::string>();
            return true;
        }

        return false;
    }

    void fileThread(Packet& p_packet, const std::string& p_file)
    {
        IEEE80211 link_layer;
        PCAP file_input(p_file);
        file_input.initialize();
        
        std::cout << "Reading: " << p_file << std::endl;
        while (file_input.get_packet(p_packet))
        {
            link_layer.handle_packet(p_packet);
            p_packet.reset();
        }
    }

    void protocolThread(Packet& p_packet, const std::string& p_kismet_address, const std::size_t p_kismet_port)
    {
        try
        {
            IEEE80211 link_layer;
            while (!p_packet.m_shutdown)
            {
                KismetDrone input(p_kismet_address, p_kismet_port);
                input.connect();

                while (!p_packet.m_shutdown && input.get_packet(p_packet))
                {
                    link_layer.handle_packet(p_packet);
                    p_packet.reset();
                }

                if (!p_packet.m_shutdown)
                {
                    // for some reason we lost sync with kismet? I've seen kismet simply stop sending data as
                    // well. Which is strange, but I think not our fault. Sleep 5 seconds and let try to
                    // reconnect.
                    sleep(5);
                }
            }
        }
        catch (const std::runtime_error& e)
        {
        }
    }
}

int main(int p_argCount, char* p_argArray[])
{
    /* for better or worse, holds on global structures used by protocol
     * processing and the user interface */
    try
    {
        Packet packet;
        std::stringstream timeStream;
        boost::uint32_t start = time(NULL);
        timeStream << start;
        packet.m_startTime.assign(timeStream.str());

        std::string file;
        std::string interface;
        std::string kismet_address;
        std::size_t kismet_port = 0;
        if (!parseCommandLine(p_argCount, p_argArray, kismet_address, kismet_port, file, packet.get_config()))
        {
            return EXIT_FAILURE;
        }

        // spawn protocol thread
        boost::thread protoThread;
        if (file.empty())
        {
            protoThread = boost::thread(protocolThread, boost::ref(packet), kismet_address, kismet_port);
        }
        else
        {
            protoThread = boost::thread(fileThread, boost::ref(packet), file);
        }

        // ui server will be on the main thread
        boost::asio::io_service io_service;
        boost::asio::ip::udp::socket ui_sock(io_service, boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), 1270));
        while (packet.m_shutdown == false)
        {
            boost::array<char, 128> recv_buf;
            boost::system::error_code error;
            boost::asio::ip::udp::endpoint remote_endpoint;
            int length = ui_sock.receive_from(boost::asio::buffer(recv_buf), remote_endpoint, 0, error);
            if (error && error != boost::asio::error::message_size)
            {
                packet.m_shutdown = true;
                continue;
            }

            if (length == 2 && recv_buf.data()[0] == 's')
            {
                packet.m_shutdown = true;
                continue;
            }
            else if (length == 2 && recv_buf.data()[0] == 'o')
            {
                std::stringstream response;
                response << (time(NULL) - start) << ","
                         << (packet.m_stats.get_unencrypted() + packet.m_stats.get_wep() + packet.m_stats.get_wpa()) << ","
                         << packet.m_stats.get_unencrypted() << ","
                         << packet.m_stats.get_wep() << ","
                         << packet.m_stats.get_wpa() << ","
                         << packet.m_stats.get_packets() << ","
                         << packet.m_stats.get_beacons() << ","
                         << packet.m_stats.get_data_packets() << ","
                         << packet.m_stats.get_encrypted() << ","
                         << packet.m_stats.get_eapol() << std::endl;
                boost::system::error_code ignored_error;
                ui_sock.send_to(boost::asio::buffer(response.str()), remote_endpoint, 0, ignored_error);
            }
            else if (length == 2 && recv_buf.data()[0] == 'l')
            {
                std::stringstream response;

                std::vector<AP*> recent;
                packet.get_recent_ap(30, recent);
                for (std::vector<AP*>::iterator it = recent.begin();
                     it != recent.end(); ++it)
                {
                    response << (*it)->get_ssid() << "," << (*it)->get_mac() << std::endl;
                }

                response << std::endl;
                std::string output(response.str());
                if (output.size() == 1)
                {
                    output.push_back('\n');
                }
                boost::system::error_code ignored_error;
                ui_sock.send_to(boost::asio::buffer(output), remote_endpoint, 0, ignored_error);
            }
            else if (length == 2 && recv_buf.data()[0] == 'c')
            {
                std::stringstream response;

                std::vector<Client*> recent;
                packet.get_recent_client(30, recent);
                for (std::vector<Client*>::iterator it = recent.begin();
                     it != recent.end(); ++it)
                {
                    response << (*it)->get_mac() << std::endl;
                }
                response << std::endl;
                std::string output(response.str());
                if (output.size() == 1)
                {
                    output.push_back('\n');
                }
                boost::system::error_code ignored_error;
                ui_sock.send_to(boost::asio::buffer(output), remote_endpoint, 0, ignored_error);
            }
            else if (length == 19 && recv_buf.data()[0] == 'r')
            {
                std::string mac(recv_buf.data() + 1, 17);
                boost::uint64_t lookup_mac = string_mac_to_int(mac);
                AP* router = packet.find_ap(lookup_mac);
                if (router != NULL)
                {
                    std::stringstream result;
                    result << ((int)router->get_channel() & 0xff) << ","
                          << router->get_encryption() << ","
                          << ((int)router->get_last_signal()) << ","
                          << router->get_client_count() << std::endl << std::endl;

                    boost::system::error_code ignored_error;
                    ui_sock.send_to(boost::asio::buffer(result.str()), remote_endpoint, 0, ignored_error);
                }
            }
            else if (length == 19 && recv_buf.data()[0] == 'c')
            {
                std::string mac(recv_buf.data() + 1, 17);
                boost::uint64_t lookup_mac = string_mac_to_int(mac);
                Client* client = packet.find_client(lookup_mac, false);
                if (client != NULL)
                {
                    std::stringstream result;
                    result << ((int)client->get_last_signal()) << ","
                           << client->get_associated_str() << ","
                           << std::endl << std::endl;

                    boost::system::error_code ignored_error;
                    ui_sock.send_to(boost::asio::buffer(result.str()), remote_endpoint, 0, ignored_error);
                }
            }
            else if (length == '2' && recv_buf.data()[0] == 'f')
            {
                // flash output
                if (packet.get_const_config().get_wigle())
                {
                    packet.write_wigle_output(packet.m_startTime);
                }
                if (packet.get_const_config().get_kml())
                {
                    packet.write_kml_output(packet.m_startTime);
                }
                if (packet.get_const_config().get_client_csv())
                {
                    packet.write_client_csv_output(packet.m_startTime);
                }
                if (packet.get_const_config().get_probe_csv())
                {
                    packet.write_probe_csv_output(packet.m_startTime);
                }
                if (packet.get_const_config().get_ap_clients_csv())
                {
                    packet.write_ap_clients_csv_output(packet.m_startTime);
                }
            }
        }

        // join the protocol thread back in
        packet.m_shutdown = true;
        protoThread.interrupt();
        protoThread.join();

        if (packet.get_const_config().get_wigle())
        {
            packet.write_wigle_output(packet.m_startTime);
        }
        if (packet.get_const_config().get_kml())
        {
            packet.write_kml_output(packet.m_startTime);
        }
        if (packet.get_const_config().get_client_csv())
        {
            packet.write_client_csv_output(packet.m_startTime);
        }
        if (packet.get_const_config().get_probe_csv())
        {
            packet.write_probe_csv_output(packet.m_startTime);
        }
        if (packet.get_const_config().get_ap_clients_csv())
        {
            packet.write_ap_clients_csv_output(packet.m_startTime);
        }
    }
    catch (const std::runtime_error& e)
    {
        std::cerr << e.what() << std::endl;
        return EXIT_FAILURE;
    }
    catch (const std::exception& e)
    {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
