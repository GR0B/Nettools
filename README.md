# Nettools
Misc network tools created for fun or testing. 
Raw socket access requires running as root/administrator under Windows/Linux




### ArpBroadcast.py ### 
Sends an ARP broadcast packets.




### TCP_trace.py ###
Does a tracert to a TCP port under Windows. Used for troubleshooting some ZTNA issues. 




### pping.py ###
Pings a port, sends a TCP SYN and listens to the response, does not complete the 3 way handshake to open a connection. Same as nmap -sS 


### local_http_proxy.py ###
A simple proxy to overcome how Sophos ZTNA misshandles HTTP socket states, that can prevent older HTTP 1.0 and 1.1 device web interfaces from loading. This is as the Sophos ZTNA keeps the client socket open regardless of the remote web servers socket state.   

