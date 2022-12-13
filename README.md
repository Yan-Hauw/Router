# Router

This repository contains the code for a router and has all the basic functionality that a simple router would have: ARP cache, routing table, ACL table, and forwarding logic based on what kinds of packets the router receives (this router supports receiving and sending ARP packets and receiving and sending IP packets)

The code for the above functionality is in the following files:<br>

forwarding logic (sending, replying, receiving ARP and IP packets): simple-router.cpp<br>
maintaining and updating the ARP cache: arp-cache.cpp<br>
looking up the routing table: routing-table.cpp<br>
Looking up the Access control list: acl-table.cpp

