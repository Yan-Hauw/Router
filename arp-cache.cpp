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

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router
{

  //////////////////////////////////////////////////////////////////////////
  //////////////////////////////////////////////////////////////////////////
  // IMPLEMENT THIS METHOD
  void
  ArpCache::periodicCheckArpRequestsAndCacheEntries()
  {

    // iterate through arp requests
    std::list<std::shared_ptr<ArpRequest>>::iterator requestIterator;
    std::list<PendingPacket>::iterator packetIterator;
    for (requestIterator = m_arpRequests.begin(); requestIterator != m_arpRequests.end(); requestIterator++)
    {
      if (((*requestIterator)->nTimesSent) >= 5)
      {
        removeArpRequest((*requestIterator)); // remove request if number of times sent has exceeded 5
      }
      else
      {
        packetIterator = ((*requestIterator)->packets).begin();
        std::string outgoingInterfaceName = (*packetIterator).iface;
        uint32_t nextHopIP = (*requestIterator)->ip;
        const Interface *outgoing_iface = m_router.findIfaceByName(outgoingInterfaceName); // get the right interface to re-send from

        m_router.sendArpRequest(nextHopIP, outgoing_iface);                  // re-send arp request
        (*requestIterator)->nTimesSent = (*requestIterator)->nTimesSent + 1; // update ntimessent
        std::cerr << "Number of times this packet has been sent: " << (*requestIterator)->nTimesSent << std::endl;
        (*requestIterator)->timeSent = steady_clock::now(); // update timesent
      }
    }

    // iterate through arp cache entries
    std::list<std::shared_ptr<ArpEntry>>::iterator entryIterator;
    entryIterator = m_cacheEntries.begin();
    while (entryIterator != m_cacheEntries.end())
    {
      bool remove = false;
      if (!((*entryIterator)->isValid))
      {
        remove = true;
      }
      if (remove)
      {
        entryIterator = m_cacheEntries.erase(entryIterator);
      }
      else
        entryIterator++;
    }

    // FILL THIS IN
  }
  //////////////////////////////////////////////////////////////////////////
  //////////////////////////////////////////////////////////////////////////

  // You should not need to touch the rest of this code.

  ArpCache::ArpCache(SimpleRouter &router)
      : m_router(router), m_shouldStop(false), m_tickerThread(std::bind(&ArpCache::ticker, this))
  {
  }

  ArpCache::~ArpCache()
  {
    m_shouldStop = true;
    m_tickerThread.join();
  }

  std::shared_ptr<ArpEntry>
  ArpCache::lookup(uint32_t ip)
  {
    std::lock_guard<std::mutex> lock(m_mutex);

    for (const auto &entry : m_cacheEntries)
    {
      if (entry->isValid && entry->ip == ip)
      {
        return entry;
      }
    }

    return nullptr;
  }

  std::shared_ptr<ArpRequest>
  ArpCache::queueArpRequest(uint32_t ip, const Buffer &packet, const std::string &iface)
  {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                                [ip](const std::shared_ptr<ArpRequest> &request)
                                {
                                  return (request->ip == ip);
                                });

    if (request == m_arpRequests.end())
    {
      request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
    }

    // Add the packet to the list of packets for this request
    (*request)->packets.push_back({packet, iface});
    return *request;
  }

  void
  ArpCache::removeArpRequest(const std::shared_ptr<ArpRequest> &entry)
  {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_arpRequests.remove(entry);
  }

  std::shared_ptr<ArpRequest>
  ArpCache::insertArpEntry(const Buffer &mac, uint32_t ip)
  {
    std::lock_guard<std::mutex> lock(m_mutex);

    auto entry = std::make_shared<ArpEntry>();
    entry->mac = mac;
    entry->ip = ip;
    entry->timeAdded = steady_clock::now();
    entry->isValid = true;
    m_cacheEntries.push_back(entry);

    auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                                [ip](const std::shared_ptr<ArpRequest> &request)
                                {
                                  return (request->ip == ip);
                                });
    if (request != m_arpRequests.end())
    {
      return *request;
    }
    else
    {
      return nullptr;
    }
  }

  void
  ArpCache::clear()
  {
    std::lock_guard<std::mutex> lock(m_mutex);

    m_cacheEntries.clear();
    m_arpRequests.clear();
  }

  void
  ArpCache::ticker()
  {
    while (!m_shouldStop)
    {
      std::this_thread::sleep_for(std::chrono::seconds(1));

      {
        std::lock_guard<std::mutex> lock(m_mutex);

        auto now = steady_clock::now();

        for (auto &entry : m_cacheEntries)
        {
          if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO))
          {
            entry->isValid = false;
          }
        }

        periodicCheckArpRequestsAndCacheEntries();
      }
    }
  }

  std::ostream &
  operator<<(std::ostream &os, const ArpCache &cache)
  {
    std::lock_guard<std::mutex> lock(cache.m_mutex);

    os << "\nMAC            IP         AGE                       VALID\n"
       << "-----------------------------------------------------------\n";

    auto now = steady_clock::now();
    for (const auto &entry : cache.m_cacheEntries)
    {

      os << macToString(entry->mac) << "   "
         << ipToString(entry->ip) << "   "
         << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
         << entry->isValid
         << "\n";
    }
    os << std::endl;
    return os;
  }

} // namespace simple_router
