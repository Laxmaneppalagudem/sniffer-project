Sniffer Project:

Summary:
This is a python3 project aimed at providing a packet sniffer to which users can add functionlity as they need. The current project has a NetData class defined in netdata.py whihc is the main program that decodes packets received on any socket. There are currently to programs that make use of the class, one being sniff.py which prints all decoded packet data to the console, and another the monitors for HTTP requests from the client. 

The http_monitor.py makes use of the NetData class functions to decode HTTP packets and then extract HTTP headers. It  does offer logging capabilities into a text file and also does print out the most visited website for every two minutes. The logging capabilities also include a use case where access to certain "blacklisted" IPs will be logged in a separate log file under the name 'ip_watchlist_log.txt'. You can add IPs to be blacklsted in 'ip_watchlist.txt' file. Please enter one IP for every line with no spaces or special characters.

The current implementation only decodes IPv4 data and shows HTTP data, if found.


Note: This implementation was only tested for Linux. It will not work on Windows OS.


To Run:
Please check each individual file for running instructions. Python3 needs to be installed for all functionality to work.
