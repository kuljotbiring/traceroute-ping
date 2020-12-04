# Adapted from companion material available for the textbook Computer Networking: A Top-Down Approach, 6th Edition
# Kurose & Ross ©2013

from socket import *
import os
import sys
import struct
import time
import select
import binascii
import random


ICMP_ECHO_REQUEST = 8
MAX_HOPS = 50			# increased from 30 to 50 as OSU took 31 hops. allowing larger hops to be possible
TIMEOUT = 2.0
TRIES = 2

# array to hold rtt times
rtt_array = []

packets_sent = 0
packets_received = 0


# function to display the type code meanings. takes arguments of integer
# to look up the packet type meaning and prints it out for the user
def type_code(packet_type):
	print("ICMP Packet Info: ", end='')
	if packet_type == 11:
		print("Time Exceeded")
	elif packet_type == 3:
		print("Destination Unreachable")
	elif packet_type == 0:
		print("Echo Reply")


# function to display the error response code meanings. takes arguments of integer
# to look up the code meaning and prints it out for the user
def error_code(packet_error):
	print("\n" + "#" * 29 + " EXTRA CREDIT # 2 " + "#" * 29)

	print("ERROR RESPONSE: ", end='')
	if packet_error == 0:
		print("Net Unreachable")
	elif packet_error == 1:
		print("Host Unreachable")
	elif packet_error == 2:
		print("Protocol Unreachable")
	elif packet_error == 3:
		print("Port Unreachable")
	elif packet_error == 4:
		print("Fragmentation Needed and Don't Fragment was Set")
	elif packet_error == 5:
		print("Source Route Failed")
	elif packet_error == 6:
		print("Destination Network Unknown")
	elif packet_error == 7:
		print("Destination Host Unknown")
	elif packet_error == 8:
		print("Source Host Isolated")
	elif packet_error == 9:
		print("Communication with Destination Network is Administratively Prohibited")
	elif packet_error == 10:
		print("Communication with Destination Host is Administratively Prohibited")
	elif packet_error == 11:
		print("Destination Network Unreachable for Type of Service")
	elif packet_error == 12:
		print("Destination Host Unreachable for Type of Service")
	elif packet_error == 13:
		print("Communication Administratively Prohibited")
	elif packet_error == 14:
		print("Host Precedence Violation")
	elif packet_error == 15:
		print("Precedence cutoff in effect")


def checksum(string):
	csum = 0
	countTo = (len(string) // 2) * 2

	count = 0
	while count < countTo:
		thisVal = ord(string[count+1]) * 256 + ord(string[count])
		csum = csum + thisVal
		csum = csum & 0xffffffff
		count = count + 2

	if countTo < len(string):
		csum = csum + ord(string[len(string) - 1])
		csum = csum & 0xffffffff

	csum = (csum >> 16) + (csum & 0xffff)
	csum = csum + (csum >> 16)
	answer = ~csum
	answer = answer & 0xffff
	answer = answer >> 8 | (answer << 8 & 0xff00)
	return answer


def build_packet(data_size):
	# First, make the header of the packet, then append the checksum to the header,
	# then finally append the data

	# initialize variables
	code = 0
	chksum = 0		# clearing checksum to zero before generating checksum
	id_num = random.randint(1, 101)		# use a random number between 1 - 100 as the id
	seq_num = random.randint(1, 101)		# use a random number between 1 - 100 as the sequence number

	# fill header with necessary information. header variable will contain byte string from packing
	# using https://stackoverflow.com/questions/34614893/how-is-an-icmp-packet-constructed-in-python/34616058
	# to understand and create packet construction
	header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, code, chksum, id_num, seq_num)

	# create  data for packet using a string and encode it. Will be converted to byte string using encode
	# encoding learned from https://stackoverflow.com/questions/7585435/best-way-to-convert-string-to-bytes-in-python-3
	data_string = f"ICMP Header:  Type: {ICMP_ECHO_REQUEST}\tCode: {code}\t Checksum: {chksum}\t\
					Identifier: {id_num}\t Sequence Number: {seq_num}"
	data = data_string.encode('utf-8')

	# use variable to hold decoded header and data to be sent to checksum function as it requires strings
	string_data = header.decode() + data.decode()

	# update the chksum variable to hold the updated checksum value to be used in header
	chksum = checksum(string_data)

	# pack the header again now that the checksum has been computed
	# using https://stackoverflow.com/questions/34614893/how-is-an-icmp-packet-constructed-in-python/34616058
	# to understand and create packet construction
	header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, code, chksum, id_num, seq_num)

	# Don’t send the packet yet, just return the final packet in this function.
	# So the function ending should look like this
	# Note: padding = bytes(data_size)
	# convert padding to byte string
	padding = bytes(data_size)

	# use variable to hold all byte strings and return it
	packet = header + data + padding
	return packet


def get_route(hostname,data_size):
	timeLeft = TIMEOUT

	# display name of URL being accessed
	print(f"---------------- RUNNING TRACEROUTE ON: {hostname} ----------------\n")

	for ttl in range(1,MAX_HOPS):
		for tries in range(TRIES):

			destAddr = gethostbyname(hostname)

			# SOCK_RAW is a powerful socket type. For more details:   http://sock-raw.org/papers/sock_raw
			#Fill in start
			# Make a raw socket named mySocket
			# learned from https://www.winsocketdotnetworkprogramming.com/winsock2programming/winsock2advancedrawsocket11.html
			mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
			#Fill in end

			# setsockopt method is used to set the time-to-live field.
			mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
			mySocket.settimeout(TIMEOUT)
			try:
				# increment number of packets sent
				global packets_sent
				packets_sent += 1

				d = build_packet(data_size)
				mySocket.sendto(d, (hostname, 0))
				t= time.time()
				startedSelect = time.time()
				whatReady = select.select([mySocket], [], [], timeLeft)
				howLongInSelect = (time.time() - startedSelect)
				if whatReady[0] == []: # Timeout
					print("  *        *        *    Request timed out.")
				recvPacket, addr = mySocket.recvfrom(1024)
				timeReceived = time.time()
				timeLeft = timeLeft - howLongInSelect
				if timeLeft <= 0:
					# bug in code: added line timeLeft = 0 to avoid getting negative timeouts
					# used piazza post suggestion on post @249
					timeLeft = 0
					print("  *        *        *    Request timed out.")

			except timeout:
				continue

			else:
				# Fill in start
				# Fetch the icmp type from the IP packet
				# using https://docs.python.org/3/library/struct.html?highlight=unpack#struct.unpack
				# ICMP packet structure has header starting at Byte 20 (160 to 167 per PDF divide by 8)
				# since this data is in a Tuple, we use tuple to access the index we want (one element only)
				types = struct.unpack('B', recvPacket[20:21])[0]
				code = struct.unpack('B', recvPacket[21:22])[0]
				check_sum = struct.unpack('B', recvPacket[23:24])[0]
				packet_id = struct.unpack('B', recvPacket[25:26])[0]
				sequence_number = struct.unpack('B', recvPacket[27:28])[0]

				# display information for packet
				print("-" * 75)

				# display packet header information along with type meaning
				type_code(types)
				print(f"Type: {types}\tCode: {code}\tChecksum: {check_sum}\tIdentifier: {packet_id}\tSequence Number: {sequence_number}")

				# Fill in end

				# increment packets received
				global packets_received
				packets_received += 1

				if types == 11:
					bytes = struct.calcsize("d")
					timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
					print("  %d    rtt=%.0f ms    %s" %(ttl, (timeReceived -t)*1000, addr[0]))

					# get the RTT time for the current packet & ignore trailing numbers after decimal
					rtt_time = "{:.0f}".format((timeReceived - t)*1000)

					# save current round RTT to list cast to int since it was saved as a string
					rtt_array.append(int(rtt_time))
					print("-" * 75)

				elif types == 3:
					# display error code meaning for extra credit # 2
					error_code(code)

					bytes = struct.calcsize("d")
					timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
					print("  %d    rtt=%.0f ms    %s" %(ttl, (timeReceived-t)*1000, addr[0]))

					# get the RTT time for the current packet & ignore trailing numbers after decimal
					rtt_time = "{:.0f}".format((timeReceived - t) * 1000)

					# save current round RTT to list cast to int since it was saved as a string
					rtt_array.append(int(rtt_time))
					print("-" * 75)

				elif types == 0:
					bytes = struct.calcsize("d")
					timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
					# bug in code changed from timeReceived - timeSent to timeReceived - timeSent
					# this error was pointed out by the Professor in slack and student Ryan Sutter
					# in official slack. although not required to fix?
					print("  %d    rtt=%.0f ms    %s" %(ttl, (timeReceived - t)*1000, addr[0]))

					# get the RTT time for the current packet & ignore trailing numbers after decimal
					rtt_time = "{:.0f}".format((timeReceived - t) * 1000)

					# save current round RTT to list cast to int since it was saved as a string
					rtt_array.append(int(rtt_time))

					# destination host has been reached. display message
					print(f"\n---------------- HOST DESTINATION REACHED:  {hostname} ----------------")

					return

				else:
					print("error")
				break
			finally:
				mySocket.close()


print('Argument List: {0}'.format(str(sys.argv)))

data_size = 0
if len(sys.argv) >= 2:
	data_size = int(sys.argv[1])

# get_route("oregonstate.edu",data_size)

# get_route("gaia.cs.umass.edu",data_size)

# get_route("australia.gov.au",data_size)

get_route("bbc.co.uk",data_size)

# only use this URL to test error code
# does not finish trace never reaches host!
# get_route("my.gov.au",data_size)

# sort all the stored RTT values saved
rtt_array.sort()


print("#" * 29 + " EXTRA CREDIT # 1 " + "#" * 29)

# get & display the first value of sorted RTT array which is the smallest
print(f"Minimum RTT: {rtt_array[0]}")

# get & display the last element in sorted RTT array which is the largest
print(f"Max RTT: {rtt_array[-1]}")

# compute the average of the RTT list
ave_rtt = sum(rtt_array) / len(rtt_array)

# format the average value to ignore places after the decimal
ave_rtt = "{:.0f}".format(ave_rtt)

# display the average RTT
print(f"Average RTT: {ave_rtt}")

# use a formula to compute the packet loss rate and convert to percentage
packet_loss_rate = ((packets_sent - packets_received) / packets_sent) * 100
packet_loss_rate = "{:.2f}".format(packet_loss_rate)

# display statistics for packages sent and received and show their loss
print(f"Packet Loss Rate: {packet_loss_rate}%\tPackets sent: {packets_sent}\tPackets received: {packets_received}")
