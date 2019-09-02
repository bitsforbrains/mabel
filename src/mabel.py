import socket
import struct
import sys
import logging
import argparse


SIOCGIFADDR = 0x8915


def bind_listener(bind_ip):
    # This is for Windows only. Linux coming soon.
    prom_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    prom_socket.bind((bind_ip, 0))
    prom_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    prom_socket.ioctl(socket.SIO_RCVALL, 1)
    return prom_socket


def setup_logger(level):
    log_handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
    log_handler.setFormatter(formatter)
    logger.addHandler(log_handler)
    log_levels = {0: logging.ERROR, 1: logging.WARN, 2: logging.INFO, 3: logging.DEBUG}
    logger.setLevel(log_levels[level])


def get_cl_opts():
    protocols = {'TCP': 6, 'UDP': 17}
    try:
        parser = argparse.ArgumentParser(description='Mabel, the network gossip. '
                                                     'Listens in on conversations and shares '
                                                     'juicy messages with others.')

        parser.add_argument('-d',
                            dest='dst_port',
                            action='store',
                            default=None,
                            help='Only listen for traffic to this destination port')
        parser.add_argument('-f',
                            dest='fwd_address',
                            action='store',
                            default="127.0.0.1",
                            help='Forward packets to this destination IP')
        parser.add_argument('-i',
                            dest='bind_address',
                            action='store',
                            default="127.0.0.1",
                            help='IP address of the interface to listen in on')
        parser.add_argument('-m',
                            dest='port_maps',
                            action='store',
                            default="[]",
                            help='comma-separated list of port source/dest mappings (e.g. 139:1139,53:553)')
        parser.add_argument('-p',
                            dest='protocol',
                            action='store',
                            default="UDP",
                            help='IP protocol to listen to (TCP or UDP)')
        parser.add_argument('-s',
                            dest='src_ip',
                            action='store',
                            default=None,
                            help='Only listen for traffic from this source IP')
        parser.add_argument('-v',
                            dest='verbosity',
                            action='store',
                            default=1,
                            help='Log level 0-4 (0=SILENT, 1=ERROR, 2=WARN, 3=INFO, 4=DEBUG')
        args = parser.parse_args()
        if args.protocol not in protocols:
            print(parser.print_help())
            sys.exit(0)
        else:
            args.protocol = protocols[args.protocol]

        return args
    except:
        print('Unhandled error getting application options, exiting...\n')
        sys.exit(1)


def process_udp_packet(packet, ip_header_length, source_address, runtime_opts):
    # we are listening for UDP traffic
    # unpack UDP header
    udp_header = struct.unpack('!HHHH', packet[ip_header_length:ip_header_length + 8])
    packet_port_src = udp_header[0]
    packet_port_dst = udp_header[1]
    # need some kind of filter to avoid feedback loops
    if runtime_opts.dst_port is not None and int(packet_port_dst) != int(runtime_opts.dst_port):
        # these are not the packets you're looking for, move along
        return
    packet_data_len = udp_header[2]
    checksum = udp_header[3]
    offset = ip_header_length + 20
    udp_payload = packet[offset:offset + packet_data_len]
    # create a new packet and forward it to the receiver
    dst_port = int(packet_port_dst)
    # re-map the destination port if specified
    for entry in runtime_opts.port_maps.split(","):
        if str(packet_port_dst) in entry.split(":")[0]:
            dst_port = int(entry.split(":")[1])
    logger.debug("Forwarding UDP packet to {0}:{1}".format(runtime_opts.fwd_address, dst_port))
    send_udp_packet(dst_ip=runtime_opts.fwd_address, dst_port=dst_port, payload=udp_payload)


def send_udp_packet(dst_ip, dst_port, payload):
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.sendto(payload, (dst_ip, dst_port))


def main():
    runtime_opts = get_cl_opts()
    setup_logger(runtime_opts.verbosity)
    # bind a promiscuous listener to the source interface
    prom_socket = bind_listener(bind_ip=runtime_opts.bind_address)
    logger.info("Successfully set up promiscuous listener on {0}".format(runtime_opts.bind_address))
    while True:
        # get a packet
        packet, source_address = prom_socket.recvfrom(65565)
        if runtime_opts.src_ip is not None and source_address != runtime_opts.src_ip:
            # these are not the packets you're looking for, move along
            continue
        # unpack header
        ip_header = struct.unpack('!BBHHHBBH4s4s', packet[:20])
        ip_header_length = (ip_header[0] & 0xF) * 4
        ip_proto = ip_header[6]
        # process UDP packets only
        if ip_proto == runtime_opts.protocol:
            if ip_proto == 17:
                process_udp_packet(packet, ip_header_length, source_address[0], runtime_opts)
            if ip_proto == 6:
                # i haven't implemented TCP yet, go away!
                pass

if __name__ == "__main__":
    logger = logging.getLogger()
    main()