import struct
import socket
import textwrap

def main():
	conn = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))
	while True:
		packet = conn.recvfrom(65535)
		data = packet[0]
		dest_mac, src_mac, eth_proto, data = ethernet(data)
		print('Ethernet_dst_mac: {}, Ethernet_src_mac: {}, Ethernet_protocol: {}'.format(dest_mac,src_mac,eth_proto))
		
		#IPv4 Packet
		if eth_proto == 8:
			ip_proto, src_ip, dst_ip, data = ipv4(data)
		
			print('ip_proto: {} src_ip: {} dst_ip:{} '.format(ip_proto,src_ip,dst_ip))
			#ICMP Packet			
			if ip_proto == 1:
				packet_type,code,checksum,data=icmp(data)

			#TCP Packet
			elif ip_proto == 6:
				src_port,dst_port,seq,ack,data=tcp(data)
				print('TCP_src_port: {}, TCP_dst_port: {},seq: {},ack: {}'.format(src_port,dst_port,seq,ack))
				if src_port ==80 or dst_port ==80:
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
				src_port,dst_port,length = udp(data)
				print('udp_src_port: {},udp_dst_port: {},length: {}'.format(src_port,dst_port,length))
			
		#IPv6 Packet
		else:
			print('IPv6 Address')

def ethernet(data):	
	dest_mac, src_mac, eth_proto = struct.unpack('! 6s 6s H', data[:14])
	return get_macaddr(dest_mac), get_macaddr(src_mac),socket.htons(eth_proto), data[14:]


def get_macaddr(addr):
	bytes_str = str(addr).replace('\\x','').upper()
	mac = ''.join(c for c in bytes_str if c not in '()')
	mac = mac[1:]
	mac_addr = ':'.join(mac[i:i+2] for i in range(1,len(mac),2))
	#return ':'.join(bytes_str).upper()
	return mac_addr	


def ipv4(data):
	ip_proto, src_ip, dst_ip = struct.unpack('!9xB2x4s4s', data[:20])
	
	src_ip = socket.inet_ntoa(src_ip)
	dst_ip = socket.inet_ntoa(dst_ip)
	return ip_proto, src_ip, dst_ip, data[20:]


def icmp(data):
	icmp_type,code,checksum=struct.unpack('!BBH',data[:4])
	return icmp_type,code,checksum


def tcp(data):
	src_port,dst_port,seq,ack=struct.unpack('!BBLL10x',data[:20])
	return src_port,dst_port,seq,ack,data[20:]

def udp(data):
	src_port,dst_port,length = struct.unpack('!HH2xH',data[:8])
	return src_port,dst_port,length

main()
