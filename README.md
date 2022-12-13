# Router

This repository contains the code for a router and has all the basic functionality that a simple router would have: ARP cache, routing table, ACL table, and forwarding logic based on what kinds of packets the router receives (this router supports receiving ARP packets and ARP packets)

The code for the above functionality is in the following files:
forwarding logic (sending, replying, receiving ARP and IP packets): simple-router.cpp
maintaining and updating the ARP cache: arp-cache.cpp
looking up the routing table: routing-table.cpp
Looking up the Access control list: acl-table.cpp

