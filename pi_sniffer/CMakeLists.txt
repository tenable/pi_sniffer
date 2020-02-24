cmake_minimum_required(VERSION 2.8)

# Options
option(debug "Build with debug flags." Off)

set(PROJECT_NAME pi_sniffer)
project(${PROJECT_NAME})

# compiler flags
if (debug)
    set(CMAKE_CXX_FLAGS "-g -std=c++0x -Wall -Wextra -Weffc++ -Wshadow -pedantic -Wcast-align -Wcast-qual -Woverloaded-virtual -Wstrict-null-sentinel -Wswitch-default -Winit-self -Wlogical-op -Wno-deprecated-declarations")
else()
    set(CMAKE_CXX_FLAGS "-O2 -std=c++0x -Wall -Wextra -Wno-deprecated-declarations")
endif()

#package locations
find_package(Boost 1.67 COMPONENTS system thread program_options filesystem atomic REQUIRED)
find_package(OpenSSL REQUIRED)

# includes
include_directories(SYSTEM ${Boost_INCLUDE_DIR})
include_directories(SYSTEM ${OPENSSL_INCLUDE_DIR})
include_directories(SYSTEM "src/")

# compilation units
add_executable(${PROJECT_NAME} 
               src/main.cpp
               src/ap.cpp
               src/client.cpp
               src/probed_network.cpp
               src/configuration.cpp
               src/packet.cpp
               src/stats.cpp
               src/input/kismet_drone.cpp
               src/input/pcap.cpp
               src/protocols/ieee80211.cpp
               src/protocols/llcsnap.cpp
               src/protocols/eapol11.cpp
               src/util/kml_maker.cpp
               src/util/pcap_output.cpp
               src/util/convert.cpp)

# linking comp / libs
target_link_libraries(${PROJECT_NAME} ${Boost_LIBRARIES} ${OPENSSL_LIBRARIES} -lpugixml -ltins)
