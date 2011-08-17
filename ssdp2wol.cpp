// Copyright (c) 2009 - Mozy, Inc.

#include "mordor/predef.h"

#include <iostream>

#include "mordor/config.h"
#include "mordor/daemon.h"
#include "mordor/iomanager.h"
#include "mordor/main.h"
#include "mordor/socket.h"
#include "mordor/string.h"
#include "mordor/http/parser.h"

using namespace Mordor;

static ConfigVar<std::string>::ptr g_macAddress = Config::lookup("macaddress",
  std::string(), "MAC address to send WOL to");
static ConfigVar<std::string>::ptr g_interface = Config::lookup("interface",
  std::string("eth0"), "Interface to listen and send on");
static ConfigVar<std::string>::ptr g_blacklist = Config::lookup("blacklist",
  std::string(), "Semicolon separate list of IP addresses to ignore");

static void wol(Socket::ptr socket, const std::string &macAddress) {
  MORDOR_ASSERT(macAddress.size() == 6u);
  std::string message;
  message.append(6u, (char)0xff);
  for(size_t i = 0; i < 16; ++i)
      message.append(macAddress);
  socket->send(message.c_str(), message.size());
}

static int daemonMain(int argc, char *argv[])
{
    try {
        std::string macAddressString = g_macAddress->val();
        replace(macAddressString, "-", "");
        if (macAddressString.size() != 12u) {
            std::cerr << "MAC address must be 12 characters" << std::endl;
            return -1;
        }
        std::string macAddress = dataFromHexstring(macAddressString);

        std::set<Address::ptr> blacklistedAddresses;
        std::vector<std::string> blacklistedAddressesString = split(
            g_blacklist->val(), ";, ");
        for(std::vector<std::string>::const_iterator it(
            blacklistedAddressesString.begin());
            it != blacklistedAddressesString.end();
            ++it) {
            if(it->empty())
                continue;
            blacklistedAddresses.insert(IPAddress::create(it->c_str()));
        }

        std::vector<std::pair<Address::ptr, unsigned int> > addresses =
            Address::getInterfaceAddresses(g_interface->val(), AF_INET);
        if (addresses.empty()) {
            std::cerr << "Couldn't find interface " << g_interface->val()
                << std::endl;
            return -1;
        }

        IPAddress::ptr localAddress = boost::static_pointer_cast<IPAddress>(
            addresses.front().first);
        IPAddress::ptr broadcastAddress = localAddress->broadcastAddress(
            addresses.front().second);
        broadcastAddress->port(9u);
        IPv4Address multicastAddress("239.255.255.250", 1900);

        IOManager ioManager;

        Socket::ptr broadcastSocket(broadcastAddress->createSocket(ioManager,
            SOCK_DGRAM));
        broadcastSocket->setOption(SOL_SOCKET, SO_BROADCAST, 1);
        broadcastSocket->connect(broadcastAddress);

        Socket::ptr listenSocket(multicastAddress.createSocket(ioManager,
            SOCK_DGRAM));
        listenSocket->setOption(SOL_SOCKET, SO_REUSEADDR, 1);
        listenSocket->bind(IPv4Address(0u, 1900u));
        // TODO: listenSocket->joinGroup(multicastAddress, addresses.front().first);
        struct ip_mreq multicastGroup;
        memcpy(&multicastGroup.imr_multiaddr, &((sockaddr_in *)multicastAddress.name())->sin_addr, sizeof(struct in_addr));
        memcpy(&multicastGroup.imr_interface, &((sockaddr_in *)addresses.front().first->name())->sin_addr, sizeof(struct in_addr));
        listenSocket->setOption(IPPROTO_IP, IP_ADD_MEMBERSHIP, multicastGroup);

        Daemon::onTerminate.connect(boost::bind(&Socket::cancelReceive,
            listenSocket));

        try {
            IPv4Address sender;
            char buffer[4096];
            size_t size;
            while((size = listenSocket->receiveFrom(buffer, 4096, sender))) {
                IPAddress::ptr senderDuplicate = sender.clone();
                senderDuplicate->port(0u);
                if (blacklistedAddresses.find(senderDuplicate) !=
                    blacklistedAddresses.end()) {
                    MORDOR_LOG_VERBOSE(Log::root())
                        << "Skipping broadcast from " << sender;
                    continue;
                }

                HTTP::Request request;
                HTTP::RequestParser parser(request);
                parser.run(buffer, size);
                if (parser.complete() && !parser.error()) {
                    if (request.requestLine.method == "M-SEARCH") {
                        MORDOR_LOG_INFO(Log::root()) << "Relaying M-SEARCH to WOL from "
                            << sender;
                        wol(broadcastSocket, macAddress);
                    }
                } else {
                    MORDOR_LOG_WARNING(Log::root()) << "Unable to parse HTTP request from "
                        << sender << ": " << charslice(buffer, size);
                }
            }
        } catch (OperationAbortedException &) {
        } catch (...) {
            MORDOR_LOG_FATAL(Log::root())
                << boost::current_exception_diagnostic_information();
            return -1;
        }
    } catch (...) {
        std::cerr << boost::current_exception_diagnostic_information() << std::endl;
        return -1;
    }
    return 0;
}

MORDOR_MAIN(int argc, char *argv[])
{
    try {
        Config::loadFromEnvironment();
        return Daemon::run(argc, argv, &daemonMain);
    } catch (...) {
        std::cerr << boost::current_exception_diagnostic_information()
           << std::endl;
        return -1;
    }
}
