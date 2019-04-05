'''
This application is used to monitoe all HTTP requests going from the local host system and creates two logs, i.e., a watchlist log (log format -> source ip, destination ip, source port, destination port, timestamp) that records client's visit to any blacklisted IPs (listed in ip_watchlist.txt), and a log that monitors any HTTP requests sent from the client (log format -> src_ip, dst_ip, host, referer, section1, section2, request_method, timestamp). The section1 and section2 in the HTTP log are URI sections seperated by /. This can be used to identify which sppecific page of a host was visited by the client.

The application makes use of the ethernet interface to retreive the client private IP. By default iface='eth0'. Please mention your interface name if it is not eth0

To Run: $python3 ./http_monitor.py [--iface]
'''

import struct
import socket
import textwrap
from datetime import datetime
import time
from netdata import NetData
from argparse import ArgumentParser
tracker = []
twominute = time.time()

def set_tracker(host, section1, section2):
	global tracker
	if section1 == 'unavailable' and section2 == 'unavailable':
		section = '/'
	elif section1 != 'unavailable' and section2 == 'unavailable':
		section = '/'+ section1
	elif section1 == 'unavailable' and section2 != 'unavailable':
		section = '/'+section2
	else:
		section = '/' + section1 + '/' + section2
	iteration_count = 0
	second_it_tracker = 0
	if len(tracker) == 0:
		tracker.append({'host': host, 'section': section, 'hits': 1})
	else:
		for i in tracker:
			if i['host'] == host and i['section'] == section:
				i.update((k, int(i['hits'])+1) for k, v in i.items() if k == "hits")
			elif i['host'] != host and i['section'] != section:
				iteration_count = iteration_count + 1
			elif i['host'] == host and i['section'] != section:
				second_it_tracker = second_it_tracker + 1
		if iteration_count == len(tracker):
			tracker.append({'host': host, 'section': section, 'hits': 1})
		if second_it_tracker == len(tracker):
			tracker.append({'host': host, 'section': section, 'hits': 1})
	print(tracker)		

#Function to print the most visited website onto the console
def show_tracker():
	max_record = []
	for i in tracker:
		if len(max_record) == 0:
			max_record = i
		else:
			if i['hits'] > max_record['hits']:
				max_record = i
	print('Most visited webiste: {} Section: {} Total hits: {} '.format(max_record['host'],max_record['section'],max_record['hits']))

#Function to track all (GET, POST) requests sent from local host i.e., dst_port=80 and src_ip=localhost
def track_host_request(http_data):
	host = 'unavailable'
	referer = 'unavailable'
	section1 = 'unavailable'
	section2 = 'unavailable'
	request_method = 'unavailable'
	info = http_data.split('\n')
	print('\nThis is Info:\n\n'+str(info))
	print('----------HTTP DATA--------')
	for line in info:
		if 'GET' in line:
			request_method = 'GET'
			sections_temp = line.split(' ')
			#print(sections_list)
			
			if len(sections_temp) > 2:
				if sections_temp[1][0] == '/':
					sections_list = sections_temp[1].split('/')
					if len(sections_list) > 1:
						if sections_list[1] != '':
							section1 = sections_list[1]
							if len(sections_list) > 2:
								section2 = sections_list[2]
					
			else:
				print('no sections')
		elif 'POST' in line:
			request_method = 'POST'
			sections_list = line.split(' ')
			print(sections_list)
			if len(sections_list) > 2:
				section1 = sections_list[1]	


		if 'Host' in line:
			host = str(line[6:])
			
			host = host.strip()

		if 'Referer' in line:
			referer = str(line[9:])
	
	return host, referer, section1, section2, request_method

#Function to work with all HTTP responses received by the host i.e., src_port=80 and dst_ip=localhost
#Note: This is still a incomplete function and needs more work
'''def external_response_decode(data):
	try:
		if 'Content-Encoding: gzip' in str(data):
			print('got encoding')
			http_d = zlib.decompress(data)
			http_data = http_d.decode('utf-8')
			info = http_data.split('\n')
			for line in info:
				print(line)
		http_data = str(data.decode('utf-8'))
		info = http_data.splint('\n')
		for line in info:
			print(line)
	except:	
		print('Decode failed')'''


#Function to log all HTTP requests sent from the client
def log_http_requests(src_ip, dst_ip, host, referer, section1, section2, request_method):
	f = open('http_log_'+str(datetime.now().strftime('%Y-%m-%d'))+'.txt','a')
	f.write('src_ip: {}, dst_ip: {}, host: {}, referer: {}, section1: {}, section2: {}, request_method: {}, timestamp: {}\n'.format(src_ip, dst_ip, host, referer, section1, section2, request_method, datetime.now()))
	f.close()
	print('logged data')


def main(iface):
	global twominute
	twominute = time.time()+20
	conn = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))
	netdata = NetData()
	host_ip = netdata.get_host_ip(iface)
	transport_protocol = 'unavailable'

	print(host_ip)

	with open('ip_watchlist.txt', 'r') as f1:
		watchlist_ips = f1.readlines()
	watchlist_ips = [i.strip() for i in watchlist_ips]


	while True:
		#Condition to view most visited host and section by calling the tracker function every two minutes
		if time.time() > twominute:
			twominute = time.time()+120
			show_tracker()
		packet = conn.recvfrom(65535)
		data = packet[0]
		
		dest_mac, src_mac, eth_proto = netdata.ethernet(data)
		
		#IPv4 Packet
		if eth_proto == 8:
			ip_proto, src_ip, dst_ip = netdata.ipv4(data)

				
			#print('src_ip: {}, dst_ip{}\n'.format(src_ip, dst_ip))
			#TCP Packet
			if ip_proto == 6:
				src_port,dst_port,seq,ack,data = netdata.tcp(data)
				#print('s: {} d: {}'.format(src_port,dst_port))
				transport_protocol = 'TCP'
				if src_ip == host_ip and dst_port == 80:
					print('\n'+'**'*30)
					print('src_ip: {}, dst_ip{}\nsrc_port: {} dst_port: {}'.format(src_ip, dst_ip, src_port,dst_port))
					try:
						http_data = str(data.decode('utf-8'))
						host, referer, section1, section2, request_method = track_host_request(http_data)
						print('HOST: {} \nREFERER: {}\nS1: {} S2: {} Req_Met: {}'.format(host, referer, section1, section2, request_method))
						if host != 'unavailable':
							log_http_requests(src_ip, dst_ip, host, referer, section1, section2, request_method)
							set_tracker(host, section1, section2)
								
					except:
						http_data = data
						#print(http_data)

				#Condition to check is client receives a server response and then call  external_response_decode() function to handle the response
				#if src_ip != host_ip and src_port == 80:
				#	external_response_decode(data)
				#	print('HTTP RESPONSE')


			#UDP Packet
			elif ip_proto == 17:
				src_port,dst_port,length = netdata.udp(data)
				transport_protocol = 'UDP'

			if (dst_ip in watchlist_ips) or (src_ip in watchlist_ips):
				f2 = open('ip_watchlist_log.txt', 'a')
				f2.write('source_ip: {}, dest_ip{}, source_port: {}, dest_port: {}, transport_protocol: {}, timestamp: {}\n'.format(src_ip, dst_ip, src_port,dst_port, transport_protocol, datetime.now()))
				f2.close()

if __name__ == "__main__":
	parser = ArgumentParser()
	parser.add_argument('--iface', default='eth0', type=str)
	args = parser.parse_args()
	main(args.iface)

