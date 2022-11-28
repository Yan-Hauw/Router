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
  SimpleRouter::process_arp_request(arp_hdr *arp_packet_hdr, const Interface *iface)
  {
    std::cerr << "Processing ARP request..." << std::endl;
    /* First we need to check the IP address of the ARP packet */
    uint32_t target_ip = arp_packet_hdr->arp_tip;
    std::cerr << "This is the target IP: " << ipToString(arp_packet_hdr->arp_tip) << " vs " << ipToString(arp_packet_hdr->arp_tip) << std::endl;

    const Interface *target_iface = findIfaceByIp(target_ip);

    if (target_iface != nullptr) /* target ip matches one of our router's ip's*/
    {
      std::cerr << "Responding to ARP request..." << std::endl;
      //* Create ethernet struct *//
      ethernet_hdr ehdr;
      ethernet_hdr *arp_ehdr = &ehdr;

      // copy source MAC address and add as destination hardware address
      std::copy(std::begin(arp_packet_hdr->arp_sha), std::end(arp_packet_hdr->arp_sha), std::begin(arp_ehdr->ether_dhost));

      //* copy router's MAC address as source hardware address *//
      std::copy((target_iface->addr).begin(), (target_iface->addr).end(), std::begin(arp_ehdr->ether_shost));

      //* assign ethernet struct type as ARP *//
      arp_ehdr->ether_type = htons(ethertype_arp);

      //* Create ARP struct *//
      arp_hdr arp_response_hdr;
      arp_hdr *arp_resp_hdr = &arp_response_hdr;

      //*assign extraneous details *//
      arp_resp_hdr->arp_hrd = arp_packet_hdr->arp_hrd;
      arp_resp_hdr->arp_pro = arp_packet_hdr->arp_pro;
      arp_resp_hdr->arp_hln = arp_packet_hdr->arp_hln;
      arp_resp_hdr->arp_pln = arp_packet_hdr->arp_pln;

      //* assign opcode *//
      arp_resp_hdr->arp_op = htons(arp_op_reply);

      //* copy router's MAC address as sender hardware address *//
      std::copy((target_iface->addr).begin(), (target_iface->addr).end(), std::begin(arp_resp_hdr->arp_sha));

      //* copy router's IP address as sender IP address *//
      arp_resp_hdr->arp_sip = target_iface->ip;

      //* copy source MAC address as target hardware address *//
      std::copy(std::begin(arp_packet_hdr->arp_sha), std::end(arp_packet_hdr->arp_sha), std::begin(arp_resp_hdr->arp_tha));

      //* copy source IP address as target IP address *//
      arp_resp_hdr->arp_tip = arp_packet_hdr->arp_sip;

      /* convert the structs into vectors for sending */
      auto const eth_ptr = reinterpret_cast<unsigned char *>(&ehdr);
      auto const arp_ptr = reinterpret_cast<unsigned char *>(&arp_response_hdr);

      std::vector<unsigned char> eth_vec(eth_ptr, eth_ptr + sizeof(ethernet_hdr));
      std::vector<unsigned char> arp_vec(arp_ptr, arp_ptr + sizeof(arp_hdr));
      /* create a big vector to send the data in */
      std::vector<unsigned char> buf(sizeof(ethernet_hdr) + sizeof(arp_hdr));
      /* copy necessary data into big vector */
      std::copy(eth_vec.begin(), eth_vec.end(), buf.begin());
      std::copy(arp_vec.begin(), arp_vec.end(), buf.begin() + sizeof(ethernet_hdr));

      print_hdrs(buf);
      /* send packet */
      sendPacket(buf, (target_iface->name));
    }
    else
      std::cerr << "ARP request received, but not for this router. Ignoring." << std::endl;
  }

  void
  SimpleRouter::process_arp_packet(std::vector<unsigned char> &packet, const Interface *iface)
  {
    std::cerr << "Processing ARP packet..." << std::endl;

    std::vector<unsigned char> arp_packet_vec(sizeof(arp_hdr)); /*create vector to copy ARP packet into */

    std::vector<unsigned char>::const_iterator arp_it;
    arp_it = packet.begin(); /*Initialize iterator to after ethernet stuff */

    /*copy ARP packet alone into the vector */
    std::copy(arp_it + sizeof(ethernet_hdr), arp_it + sizeof(ethernet_hdr) + sizeof(arp_hdr), arp_packet_vec.begin());

    arp_hdr *arp_packet_hdr = reinterpret_cast<arp_hdr *>(arp_packet_vec.data());

    // If ARP request:
    // std::cerr << "ARP Packet OPcode" << ntohs(arp_packet_hdr->arp_op) << "and" << arp_op_request << std::endl;
    if (ntohs(arp_packet_hdr->arp_op) == arp_op_request)
    {
      std::cerr << "REACHED PROCESS ARP REQUEST" << std::endl;
      process_arp_request(arp_packet_hdr, iface);
    }
  }

  //////////////////////////////////////////////////////////////////////////
  //////////////////////////////////////////////////////////////////////////
  // IMPLEMENT THIS METHOD
  void
  SimpleRouter::processPacket(const Buffer &packet, const std::string &inIface)
  {
    std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

    const Interface *iface = findIfaceByName(inIface);
    if (iface == nullptr)
    {
      std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
      return;
    }

    // std::cerr << getRoutingTable() << std::endl;

    // FILL THIS IN

    // copy packet into vector
    std::vector<unsigned char> packet_vec(packet.size());
    std::copy(packet.begin(), packet.end(), packet_vec.begin());

    /* debugging */
    // print_hdrs(packet_vec);

    std::vector<unsigned char> eth_header_vec(sizeof(ethernet_hdr)); /*create a vector to copy the ethernet header into*/

    std::copy(packet_vec.begin(), packet_vec.begin() + sizeof(ethernet_hdr), eth_header_vec.begin()); /*Copy ethernet header into said vector */

    ethernet_hdr *eth_hdr = reinterpret_cast<ethernet_hdr *>(eth_header_vec.data()); /* Cast vector to an actual eth_hdr struct */

    if (ntohs(eth_hdr->ether_type) == ethertype_arp) /*If the ethernet frame is ARP*/
    {
      std::cerr << "ARP packet received." << std::endl;
      print_hdrs(packet);
      process_arp_packet(packet_vec, iface);
    }

    // print_hdrs(packet);
  }
  //////////////////////////////////////////////////////////////////////////
  //////////////////////////////////////////////////////////////////////////

  // You should not need to touch the rest of this code.
  SimpleRouter::SimpleRouter()
      : m_arp(*this)
  {
    m_aclLogFile.open("router-acl.log");
  }

  void
  SimpleRouter::sendPacket(const Buffer &packet, const std::string &outIface)
  {
    m_pox->begin_sendPacket(packet, outIface);
  }

  bool
  SimpleRouter::loadRoutingTable(const std::string &rtConfig)
  {
    return m_routingTable.load(rtConfig);
  }

  bool
  SimpleRouter::loadACLTable(const std::string &aclConfig)
  {
    return m_aclTable.load(aclConfig);
  }

  void
  SimpleRouter::loadIfconfig(const std::string &ifconfig)
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

  void
  SimpleRouter::printIfaces(std::ostream &os)
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

  void
  SimpleRouter::reset(const pox::Ifaces &ports)
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
