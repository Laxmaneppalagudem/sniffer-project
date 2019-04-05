'''
This is a sniffer that uses the NetData class to decode all packets received and print it to the console
To Run: $python3 ./sniff
'''
import struct
import socket
import textwrap
from netdata import NetData

def main():
	conn = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))
	while True:
		packet = conn.recvfrom(65535)
		data = packet[0]
		netdata = NetData()
		dest_mac, src_mac, eth_proto = netdata.ethernet(data)
		print('Ethernet_dst_mac: {}, Ethernet_src_mac: {}, Ethernet_protocol: {}'.format(dest_mac,src_mac,eth_proto))
		
		#IPv4 Packet
		if eth_proto == 8:
			ip_proto, src_ip, dst_ip = netdata.ipv4(data)
		
			print('ip_proto: {} src_ip: {} dst_ip:{} '.format(ip_proto,src_ip,dst_ip))
			#ICMP Packet			
			if ip_proto == 1:
				packet_type,code,checksum = netdata.icmp(data)

			#TCP Packet
			elif ip_proto == 6:
				src_port,dst_port,seq,ack,data = netdata.tcp(data)
				print('TCP_src_port: {}, TCP_dst_port: {},seq: {},ack: {}'.format(src_port,dst_port,seq,ack))
				if src_port == 80 or dst_port == 80:
					try:
						http_data = str(data.decode('utf-8'))
						info = http_data.split('\n')
						print('----------HTTP DATA--------')
						for line in info:
							print(str(line))
					except:
						http_data = data
					

			#UDP Packet
			elif ip_proto == 17:
				src_port,dst_port,length = netdata.udp(data)
				print('udp_src_port: {},udp_dst_port: {},length: {}'.format(src_port,dst_port,length))
			
		#Other Protocols
		else:
			print('Other protocols')


if __name__ == "__main__":
	main()
