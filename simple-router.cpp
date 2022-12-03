/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router
{

  void
  SimpleRouter::processArpReply(arp_hdr *arpPacketHeader, const Interface *iface)
  {
    std::cerr << "Processing ARP reply..." << std::endl;
    // extract source hardware address
    std::vector<unsigned char> targetMacAddress(ETHER_ADDR_LEN);
    std::copy(std::begin(arpPacketHeader->arp_sha), std::end(arpPacketHeader->arp_sha), targetMacAddress.begin());

    std::cerr << "The MAC address obtained from the reply is: " << macToString(targetMacAddress) << std::endl;

    uint32_t targetIp = arpPacketHeader->arp_sip;

    auto arpRequest = m_arp.insertArpEntry(targetMacAddress, targetIp);

    if (arpRequest == nullptr)
    {
      std::cerr << "Failed to create ARP entry. " << std::endl;
      return;
    }
    std::list<PendingPacket>::iterator packetIterator;
    for (packetIterator = (arpRequest->packets).begin(); packetIterator != (arpRequest->packets).end(); packetIterator++)
    {
      std::cerr << "I'm a pending packet! " << std::endl;
      std::copy(targetMacAddress.begin(), targetMacAddress.end(), (*packetIterator).packet.begin());

      // convert the ip header of the packet to a struct
      std::vector<unsigned char> ipHeaderVec(sizeof(ip_hdr));
      std::copy((*packetIterator).packet.begin() + sizeof(ethernet_hdr), (*packetIterator).packet.begin() + sizeof(ethernet_hdr) + sizeof(ip_hdr), ipHeaderVec.begin());

      ip_hdr *ipPacketHeader = reinterpret_cast<ip_hdr *>(ipHeaderVec.data());

      // update values
      uint8_t timeToLive = ipPacketHeader->ip_ttl;
      ipPacketHeader->ip_ttl = timeToLive - 1;
      ipPacketHeader->ip_sum = 0;
      uint16_t checksum = cksum(ipPacketHeader, sizeof(ip_hdr));
      ipPacketHeader->ip_sum = checksum;

      // convert struct into a vector for sending
      auto const ipPointer = reinterpret_cast<unsigned char *>(ipPacketHeader);
      std::vector<unsigned char> ipVector(ipPointer, ipPointer + sizeof(ip_hdr));

      // copy the vector containing ip header bytes back into the packet (after the ethernet header)
      std::copy(ipVector.begin(), ipVector.end(), (*packetIterator).packet.begin() + sizeof(ethernet_hdr));

      // std::cerr << "These are the headers of a pending packet" << std::endl;
      // print_hdrs((*packetIterator).packet);

      // send the pending packet
      sendPacket((*packetIterator).packet, (*packetIterator).iface);
      std::cerr << "Pending packet sent" << std::endl;

      // Destroy the ARP Request
      m_arp.removeArpRequest(arpRequest);
      std::cerr << "ARP request removed" << std::endl;
    }
  }

  void
  SimpleRouter::processArpRequest(arp_hdr *arpPacketHeader, const Interface *iface)
  {
    std::cerr << "Processing ARP request..." << std::endl;
    /* First we need to check the IP address of the ARP packet */
    uint32_t targetIP = arpPacketHeader->arp_tip;
    std::cerr << "This is the target IP: " << ipToString(arpPacketHeader->arp_tip) << " vs " << ipToString(arpPacketHeader->arp_tip) << std::endl;

    const Interface *targetInterface = findIfaceByIp(targetIP);

    if (targetInterface != nullptr) /* target ip matches one of our router's ip's*/
    {
      std::cerr << "Responding to ARP request..." << std::endl;
      //* Create ethernet struct *//
      ethernet_hdr ethernetHeader;
      ethernet_hdr *arpEthernetHeader = &ethernetHeader;

      // copy source MAC address and add as destination hardware address
      std::copy(std::begin(arpPacketHeader->arp_sha), std::end(arpPacketHeader->arp_sha), std::begin(arpEthernetHeader->ether_dhost));

      //* copy router's MAC address as source hardware address *//
      std::copy((targetInterface->addr).begin(), (targetInterface->addr).end(), std::begin(arpEthernetHeader->ether_shost));

      //* assign ethernet struct type as ARP *//
      arpEthernetHeader->ether_type = htons(ethertype_arp);

      //* Create ARP struct *//
      arp_hdr arpResponseHeader;
      arp_hdr *arpResponseHdrPtr = &arpResponseHeader;

      //*assign extraneous details *//
      arpResponseHdrPtr->arp_hrd = arpPacketHeader->arp_hrd;
      arpResponseHdrPtr->arp_pro = arpPacketHeader->arp_pro;
      arpResponseHdrPtr->arp_hln = arpPacketHeader->arp_hln;
      arpResponseHdrPtr->arp_pln = arpPacketHeader->arp_pln;

      //* assign opcode *//
      arpResponseHdrPtr->arp_op = htons(arp_op_reply);

      //* copy router's MAC address as sender hardware address *//
      std::copy((targetInterface->addr).begin(), (targetInterface->addr).end(), std::begin(arpResponseHdrPtr->arp_sha));

      //* copy router's IP address as sender IP address *//
      arpResponseHdrPtr->arp_sip = targetInterface->ip;

      //* copy source MAC address as target hardware address *//
      std::copy(std::begin(arpPacketHeader->arp_sha), std::end(arpPacketHeader->arp_sha), std::begin(arpResponseHdrPtr->arp_tha));

      //* copy source IP address as target IP address *//
      arpResponseHdrPtr->arp_tip = arpPacketHeader->arp_sip;

      /* convert the structs into vectors for sending */
      auto const ethPtr = reinterpret_cast<unsigned char *>(&ethernetHeader);
      auto const arpPtr = reinterpret_cast<unsigned char *>(&arpResponseHeader);

      std::vector<unsigned char> ethernetVec(ethPtr, ethPtr + sizeof(ethernet_hdr));
      std::vector<unsigned char> arpVec(arpPtr, arpPtr + sizeof(arp_hdr));
      /* create a big vector to send the data in */
      std::vector<unsigned char> buffer(sizeof(ethernet_hdr) + sizeof(arp_hdr));
      /* copy necessary data into big vector */
      std::copy(ethernetVec.begin(), ethernetVec.end(), buffer.begin());
      std::copy(arpVec.begin(), arpVec.end(), buffer.begin() + sizeof(ethernet_hdr));

      // print_hdrs(buffer);
      /* send packet */
      sendPacket(buffer, (targetInterface->name));
    }
    else
      std::cerr << "ARP request received, but not for this router. Ignoring." << std::endl;
  }

  void
  SimpleRouter::processArpPacket(std::vector<unsigned char> &packet, const Interface *iface)
  {
    std::cerr << "Processing ARP packet..." << std::endl;

    std::vector<unsigned char> arpPacketVec(sizeof(arp_hdr)); /*create vector to copy ARP packet into */

    std::vector<unsigned char>::const_iterator arpIterator;
    arpIterator = packet.begin(); /*Initialize iterator to after ethernet stuff */

    /*copy ARP packet alone into the vector */
    std::copy(arpIterator + sizeof(ethernet_hdr), arpIterator + sizeof(ethernet_hdr) + sizeof(arp_hdr), arpPacketVec.begin());

    arp_hdr *arpPacketHdr = reinterpret_cast<arp_hdr *>(arpPacketVec.data());

    // If ARP request:
    // std::cerr << "ARP Packet OPcode" << ntohs(arpPacketHdr->arp_op) << "and" << arp_op_request << std::endl;
    if (ntohs(arpPacketHdr->arp_op) == arp_op_request)
    {
      std::cerr << "REACHED PROCESS ARP REQUEST" << std::endl;
      processArpRequest(arpPacketHdr, iface);
    }
    else if (ntohs(arpPacketHdr->arp_op) == arp_op_reply) /* If ARP reply */
    {
      std::cerr << "REACHED PROCESS ARP REPLY" << std::endl;
      processArpReply(arpPacketHdr, iface);
    }
    else
      std::cerr << "Unrecognized ARP packet received. Neither request nor reply, dropping!" << std::endl;
  }

  void
  SimpleRouter::sendArpRequest(uint32_t ip, const Interface *iface)
  {
    std::cerr << "Sending ARP request..." << std::endl;
    // Create ethernet struct
    ethernet_hdr ethernetHeader;
    ethernet_hdr *arpEthernetHdr = &ethernetHeader;

    // copy source MAC address
    std::copy((iface->addr).begin(), (iface->addr).end(), std::begin(arpEthernetHdr->ether_shost));

    // create broadcast vector
    std::vector<unsigned char> broadcastVec(ETHER_ADDR_LEN, 255);
    // copy to destination MAC address
    std::copy(broadcastVec.begin(), broadcastVec.end(), std::begin(arpEthernetHdr->ether_dhost));
    //* assign ethernet struct type as ARP *//
    arpEthernetHdr->ether_type = htons(ethertype_arp);

    //* Create ARP struct *//
    arp_hdr arp_request_hdr;
    arp_hdr *arpRequestHdrPtr = &arp_request_hdr;

    // extraneous details
    arpRequestHdrPtr->arp_hrd = htons(arp_hrd_ethernet);
    arpRequestHdrPtr->arp_pro = htons(ethertype_ip);
    arpRequestHdrPtr->arp_hln = 0x06;
    arpRequestHdrPtr->arp_pln = 0x04;
    // assign opcode
    arpRequestHdrPtr->arp_op = htons(arp_op_request);
    // copy router MAC address as sender hardware address
    std::copy((iface->addr).begin(), (iface->addr).end(), std::begin(arpRequestHdrPtr->arp_sha));
    // copy router's IP address as sender IP address
    arpRequestHdrPtr->arp_sip = iface->ip;
    // create zero vector
    std::vector<unsigned char> zeroVector(ETHER_ADDR_LEN, 0);
    // zero out destination hardware address since we don't know it
    std::copy(zeroVector.begin(), zeroVector.end(), std::begin(arpRequestHdrPtr->arp_tha));
    // copy ip to arp target ip
    arpRequestHdrPtr->arp_tip = ip;

    // now convert the vectors into structs
    auto const ethPtr = reinterpret_cast<unsigned char *>(&ethernetHeader);
    auto const arpPtr = reinterpret_cast<unsigned char *>(&arp_request_hdr);

    std::vector<unsigned char> ethVec(ethPtr, ethPtr + sizeof(ethernet_hdr));
    std::vector<unsigned char> arpVec(arpPtr, arpPtr + sizeof(arp_hdr));
    /* create a big vector to send the data in */
    std::vector<unsigned char> buffer(sizeof(ethernet_hdr) + sizeof(arp_hdr));
    /* copy necessary data into big vector */
    std::copy(ethVec.begin(), ethVec.end(), buffer.begin());
    std::copy(arpVec.begin(), arpVec.end(), buffer.begin() + sizeof(ethernet_hdr));

    // std::cerr << "Check to see that the ARP packet was made correctly: " << std::endl;
    // print_hdrs(buffer);

    sendPacket(buffer, (iface->name));
  }

  void
  SimpleRouter::forwardPacket(std::vector<unsigned char> &packet, uint32_t target_ip, const Interface *iface)
  {
    std::cerr << "Forwarding in progress..." << std::endl;
    try
    {
      RoutingTableEntry ip_table_entry = m_routingTable.lookup(target_ip);
      uint32_t nextHopIP = ip_table_entry.gw;

      //* Check whether nextHopIP is in the ARP cache *//
      auto nextHopMacAddress = m_arp.lookup(nextHopIP);

      const Interface *outgoingInterface = findIfaceByName(ip_table_entry.ifName);

      // debugging: when done, replace the ip with with 'nextHopIP' in 1) sendArpRequest  2) queueRequest
      // uint32_t fake_ip = nextHopIP - 38; //change a legitimate IP into something nonsensical for testing

      if (nextHopMacAddress == nullptr)
      {
        std::cerr << "Unable to find MAC address of next hop IP. Preparing ARP request..." << std::endl;
        // zero out dest hardware addr before queuing
        std::vector<unsigned char> zeroVec(ETHER_ADDR_LEN, 0);
        std::copy(zeroVec.begin(), zeroVec.end(), packet.begin());
        // update source hardware address
        std::copy((outgoingInterface->addr).begin(), (outgoingInterface->addr).end(), packet.begin() + ETHER_ADDR_LEN);

        std::cerr << "Checking whether ethernet overwrites were successful: " << std::endl;
        // print_hdrs(packet);

        // pointer to ArpRequest generated by queuing the packet
        auto arp_req = m_arp.queueArpRequest(nextHopIP, packet, (outgoingInterface->name));

        sendArpRequest(nextHopIP, outgoingInterface);
        std::cerr << "Supposed to send arp requests at this point" << std::endl;

        // Update parameters since we sent an Arp Request
        arp_req->nTimesSent = 1;
        arp_req->timeSent = steady_clock::now();
      }
      else
      {
        std::cerr << "Found MAC address of next hop IP. Handling IP packet..." << std::endl;
        // update destination MAC address
        std::copy((nextHopMacAddress->mac).begin(), (nextHopMacAddress->mac).end(), packet.begin());
        // update source MAC address
        std::copy((outgoingInterface->addr).begin(), (outgoingInterface->addr).end(), packet.begin() + ETHER_ADDR_LEN);

        // convert IP header to a struct
        std::vector<unsigned char> ipHeaderVec(sizeof(ip_hdr));
        std::copy(packet.begin() + sizeof(ethernet_hdr), packet.begin() + sizeof(ethernet_hdr) + sizeof(ip_hdr), ipHeaderVec.begin());
        ip_hdr *ipPacketHdr = reinterpret_cast<ip_hdr *>(ipHeaderVec.data());

        // update values
        uint8_t timeToLive = ipPacketHdr->ip_ttl;
        if (timeToLive == 0)
        {
          return;
        }
        ipPacketHdr->ip_ttl = timeToLive - 1;
        ipPacketHdr->ip_sum = 0;
        uint16_t checksum = cksum(ipPacketHdr, sizeof(ip_hdr));
        ipPacketHdr->ip_sum = checksum;

        // convert struct into a vector for sending
        auto const ipPtr = reinterpret_cast<unsigned char *>(ipPacketHdr);
        std::vector<unsigned char> ipVector(ipPtr, ipPtr + sizeof(ip_hdr));

        // copy the vector containing ip header bytes back into the packet (after the ethernet header)
        std::copy(ipVector.begin(), ipVector.end(), packet.begin() + sizeof(ethernet_hdr));

        std::cerr << "Checking if the ethernet frame is correct before forwarding: " << std::endl;
        // print_hdrs(packet);

        sendPacket(packet, (outgoingInterface->name));
      }
    }
    catch (std::exception &exc)
    {
      std::cerr << "Next hop IP was unable to be found: " << exc.what() << std::endl;
    }
  }

  void
  SimpleRouter::processIpPacket(std::vector<unsigned char> &packet, const Interface *iface)
  {
    std::cerr << "Processing IP packet..." << std::endl;

    std::vector<unsigned char> ipPacketVec(sizeof(ip_hdr));

    std::vector<unsigned char>::const_iterator ipIterator;
    ipIterator = packet.begin();
    std::copy(ipIterator + sizeof(ethernet_hdr), ipIterator + sizeof(ethernet_hdr) + sizeof(ip_hdr), ipPacketVec.begin());

    ip_hdr *ipPacketHdr = reinterpret_cast<ip_hdr *>(ipPacketVec.data());

    //* verify checksum *//
    uint16_t givenChecksum = ipPacketHdr->ip_sum;
    ipPacketHdr->ip_sum = 0;

    uint16_t calculatedSum = cksum(ipPacketHdr, sizeof(ip_hdr));

    if ((calculatedSum == givenChecksum) && (ipPacketHdr->ip_len > sizeof(ip_hdr)))
    {
      std::cerr << "Checksum passed!" << std::endl;

      uint32_t targetIP = ipPacketHdr->ip_dst;
      const Interface *targetInterface = findIfaceByIp(targetIP);
      if (targetInterface == nullptr)
      {
        std::cerr << "Destination IP address is not the router's, so forwarding begins..." << std::endl;
        // std::cerr << "stopping testing here" << std::endl;

        if (ipPacketHdr->ip_p != ip_protocol_icmp)
        {
          std::vector<unsigned char> src_port_vec(sizeof(tcp_src_port));
          std::vector<unsigned char> dest_port_vec(sizeof(dest_port_vec));

          // std::cerr << "Checked if condition without segfault" << std::endl;

          std::copy(ipIterator + sizeof(ethernet_hdr) + sizeof(ip_hdr), ipIterator + sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(tcp_src_port), src_port_vec.begin());

          std::copy(ipIterator + sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(tcp_src_port), ipIterator + sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(tcp_src_port) + sizeof(tcp_dest_port), dest_port_vec.begin());

          // std::cerr << "Copied into vectors without segfault" << std::endl;

          tcp_src_port *sourcePortPtr = reinterpret_cast<tcp_src_port *>(src_port_vec.data());
          tcp_dest_port *destPortPtr = reinterpret_cast<tcp_dest_port *>(dest_port_vec.data());

          // std::cerr << "Initialised port pointers without segfault" << std::endl;

          try
          {
            print_hdrs(packet);

            std::cerr << "Got to before acltable lookup without segfault" << std::endl;

            int proto_int = ipPacketHdr->ip_p;
            uint8_t proto_uint = ipPacketHdr->ip_p;

            std::cerr << "protocol argument stored in uint8 var: " << proto_uint << std::endl;

            ACLTableEntry entry = m_aclTable.lookup(ntohl(ipPacketHdr->ip_src), ntohl(ipPacketHdr->ip_dst), proto_uint, ntohs(sourcePortPtr->src_port), ntohs(destPortPtr->dest_port));
            // ACLTableEntry entry = m_aclTable.lookup(ipPacketHdr->ip_src, ipPacketHdr->ip_dst, ntohs(ipPacketHdr->ip_p), ntohs(sourcePortPtr->src_port), ntohs(destPortPtr->dest_port));

            m_aclLogFile << entry; // for logging 1 entry to acl log file

            // m_aclLogFile.close();
            std::cerr << "inserting into ACL log" << proto_int << std::endl;

            std::cerr << "Successfully executed lookup function" << std::endl;

            if (entry.action == "deny")
            {
              std::cerr << "Successfully denied packet" << std::endl;
              return;
            }
          }
          catch (std::exception &e)
          {
            std::cerr << "No ACL rule found" << e.what() << std::endl;
          }
        }

        std::cerr << "got ICMP packet !!" << std::endl;

        forwardPacket(packet, targetIP, iface);
      }
      else
        std::cerr << "This packet was addressed to the router. Ignoring." << std::endl;
    }
    else
      std::cerr << "Checksum did not match or packet is too small. Ignoring." << std::endl;
  }

  //////////////////////////////////////////////////////////////////////////
  //////////////////////////////////////////////////////////////////////////
  // IMPLEMENT THIS METHOD
  void SimpleRouter::processPacket(const Buffer &packet, const std::string &inIface)
  {
    std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

    const Interface *interface = findIfaceByName(inIface);
    if (interface == nullptr)
    {
      std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
      return;
    }

    // std::cerr << getRoutingTable() << std::endl;

    // FILL THIS IN

    ethernet_hdr *ethernetHdrPtr = (struct ethernet_hdr *)packet.data(); // get ethernet header

    const uint8_t *destMacAddr = ethernetHdrPtr->ether_dhost;    // get the mac of destination
    const uint8_t *interfaceMacAddress = interface->addr.data(); // get the mac of interface
    const uint8_t *broadcastMacAddr = BroadcastEtherAddr;        // get the mac of broadcast

    // compare destMacAddr to interface mac
    bool isAddrToInterface = true;
    for (int i = 0; i < 6; i++)
    {
      if (destMacAddr[i] != interfaceMacAddress[i])
      {
        isAddrToInterface = false;
        break;
      }
    }

    // compare destMacAddr to broadcast mac
    bool isAddrToBroadcast = true;
    for (int i = 0; i < 6; i++)
    {
      if (destMacAddr[i] != broadcastMacAddr[i])
      {
        isAddrToBroadcast = false;
        break;
      }
    }

    // std::cerr << "is addressed to interface" << isAddrToInterface << std::endl;
    // std::cerr << "is addressed to broadcast" << isAddrToBroadcast << std::endl;

    // if the packet is not addressed to interface or broadcast, then ignore
    if (isAddrToBroadcast == false && isAddrToInterface == false)
    {
      std::cerr << "Packet dropped on interface " << inIface << std::endl;
      return;
    }

    // copy packet into vector
    std::vector<unsigned char> packetVector(packet.size());
    std::copy(packet.begin(), packet.end(), packetVector.begin());

    /* debugging */
    // print_hdrs(packetVector);

    std::vector<unsigned char> ethernetHdrVec(sizeof(ethernet_hdr)); /*create a vector to copy the ethernet header into*/

    std::copy(packetVector.begin(), packetVector.begin() + sizeof(ethernet_hdr), ethernetHdrVec.begin()); /*Copy ethernet header into said vector */

    ethernet_hdr *ethernetHeader = reinterpret_cast<ethernet_hdr *>(ethernetHdrVec.data()); /* Cast vector to an actual eth_hdr struct */

    if (ntohs(ethernetHeader->ether_type) == ethertype_arp) /*If the ethernet frame is ARP*/
    {
      std::cerr << "ARP packet received." << std::endl;
      // print_hdrs(packet);
      processArpPacket(packetVector, interface);
    }
    else if (ntohs(ethernetHeader->ether_type) == ethertype_ip) /* If it's IP */
    {
      std::cerr << "IP packet received." << std::endl;
      // print_hdrs(packet);
      processIpPacket(packetVector, interface);
    }
    else
      std::cerr << "Unknown packet type received, dropped!" << std::endl;

    // print_hdrs(packet);

    std::cerr << getArp() << std::endl;
  }
  //////////////////////////////////////////////////////////////////////////
  //////////////////////////////////////////////////////////////////////////

  // You should not need to touch the rest of this code.
  SimpleRouter::SimpleRouter()
      : m_arp(*this)
  {
    m_aclLogFile.open("router-acl.log");
  }

  void SimpleRouter::sendPacket(const Buffer &packet, const std::string &outIface)
  {
    m_pox->begin_sendPacket(packet, outIface);
  }

  bool SimpleRouter::loadRoutingTable(const std::string &rtConfig)
  {
    return m_routingTable.load(rtConfig);
  }

  bool SimpleRouter::loadACLTable(const std::string &aclConfig)
  {
    return m_aclTable.load(aclConfig);
  }

  void SimpleRouter::loadIfconfig(const std::string &ifconfig)
  {
    std::ifstream iff(ifconfig.c_str());
    std::string line;
    while (std::getline(iff, line))
    {
      std::istringstream ifLine(line);
      std::string iface, ip;
      ifLine >> iface >> ip;

      in_addr ip_addr;
      if (inet_aton(ip.c_str(), &ip_addr) == 0)
      {
        throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
      }

      m_ifNameToIpMap[iface] = ip_addr.s_addr;
    }
  }

  void SimpleRouter::printIfaces(std::ostream &os)
  {
    if (m_ifaces.empty())
    {
      os << " Interface list empty " << std::endl;
      return;
    }

    for (const auto &iface : m_ifaces)
    {
      os << iface << "\n";
    }
    os.flush();
  }

  const Interface *
  SimpleRouter::findIfaceByIp(uint32_t ip) const
  {
    auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip](const Interface &iface)
                              { return iface.ip == ip; });

    if (iface == m_ifaces.end())
    {
      return nullptr;
    }

    return &*iface;
  }

  const Interface *
  SimpleRouter::findIfaceByMac(const Buffer &mac) const
  {
    auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac](const Interface &iface)
                              { return iface.addr == mac; });

    if (iface == m_ifaces.end())
    {
      return nullptr;
    }

    return &*iface;
  }

  const Interface *
  SimpleRouter::findIfaceByName(const std::string &name) const
  {
    auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name](const Interface &iface)
                              { return iface.name == name; });

    if (iface == m_ifaces.end())
    {
      return nullptr;
    }

    return &*iface;
  }

  void SimpleRouter::reset(const pox::Ifaces &ports)
  {
    std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

    m_arp.clear();
    m_ifaces.clear();

    for (const auto &iface : ports)
    {
      auto ip = m_ifNameToIpMap.find(iface.name);
      if (ip == m_ifNameToIpMap.end())
      {
        std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
        continue;
      }

      m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
    }

    printIfaces(std::cerr);
  }

} // namespace simple_router {
