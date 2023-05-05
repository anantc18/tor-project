## How to run the code?

1. Run the **network1.xml** file in CORE.

2. On each of the entry, middle and exit nodes, run the **network1_config.sh** script followed by **tor_node.py**. These PCs now serve as the TOR routers for CircuitID 111.

3. On the client node, run **tor_node.py**. This program encrypts outgoing packets and decrypts incoming packets from the client.

4. Start Wireshark on eth0 interfaces for client, entry, exit, and the facebook nodes.

5. On the client, run **tcp_syn.py**. This application sends a TCP SYN packet to the facebook node.

6. Observe the TCP SYN packet and its response SYN ACK packet at various stages in the network.
