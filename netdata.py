'''
This class has all the functions necessary to decode a packet received on a socket. This class is used in the other programs to work with the packets received. Please be sure to have this file in the same directory of the other programs you're trying to execute.
'''
import socket
import struct
import fcntl

class NetData(object):
	def __init__(self):
		self.eth_header_length = 14
		self.ip_header_length = 20
		self.tcp_header_length = 20
		self.icmp_header_length = 8
		self.udp_header_length = 8

	def ethernet(self, data):
		begin = 0
		end = begin + self.eth_header_length
		dest_mac, src_mac, eth_proto = struct.unpack('! 6s 6s H', data[begin:end])

		return self.get_macaddr(dest_mac), self.get_macaddr(src_mac), socket.htons(eth_proto)


	def get_macaddr(self, addr):
		'''bytes_str = str(addr).replace('\\x','').upper()
		mac = ''.join(c for c in bytes_str if c not in '()')
		mac = mac[1:]
		mac_addr = ':'.join(mac[i:i+2] for i in range(1,len(mac),2))'''
		mac_addr = '%.2x:%.2x:%.2x:%.2x:%.2x:%.2x'%(addr[0],addr[1],addr[2],addr[3],addr[4],addr[5])
		return mac_addr	


	def ipv4(self, data):
		begin = self.eth_header_length
		end = self.eth_header_length + self.ip_header_length
		ip_proto, src_ip, dst_ip = struct.unpack('!9xB2x4s4s', data[begin:end])
	
		src_ip = socket.inet_ntoa(src_ip)
		dst_ip = socket.inet_ntoa(dst_ip)
		return ip_proto, src_ip, dst_ip


	def icmp(self, data):
		begin = self.eth_header_length + self.ip_header_length
		end = begin + self.icmp_header_length
		icmp_type,code,checksum=struct.unpack('!BBH4x',data[begin:end])
		return icmp_type,code,checksum


	def tcp(self, data):
		begin = self.eth_header_length + self.ip_header_length
		end = begin + self.tcp_header_length
		src_port,dst_port,seq,ack=struct.unpack('!HHLL8x',data[begin:end])
		return src_port,dst_port,seq,ack,data[end:]

	def udp(self, data):
		begin = self.eth_header_length + self.ip_header_length
		end = begin + self.udp_header_length
		src_port,dst_port,length = struct.unpack('!HH2xH',data[:8])
		return src_port,dst_port,length
	
	def get_host_ip(self, ifname):
		sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
		#ifname = ifname
	
		ip = socket.inet_ntoa(fcntl.ioctl(sock.fileno(), 0x8915, struct.pack('256s',bytes(ifname[:15], 'utf-8')))[20:24])
		return ip
	

