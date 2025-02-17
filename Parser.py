from scapy.all import *
from rich.pretty import pprint
import scapy

pkts = rdpcap("net2.pcap")

def parse_packet(packet, raw=True):
    parsed_packet = {}

    # Iterate through each layer of the packet
    for layer in packet.layers():
        if layer != scapy.packet.Raw or raw:
            parsed_layer = {}

            # Extract field names and values for each layer
            for field in packet[layer].fields_desc:
                field_name = field.name
                field_value = packet[layer].get_field(field_name).i2repr(packet[layer], packet[layer].getfieldval(field_name))

                # Handle cases where field value is another layer
                if isinstance(field_value, NoPayload):
                    field_value = parse_packet(field_value)

                parsed_layer[field_name] = field_value

            parsed_packet[layer] = parsed_layer

    return parsed_packet

for pkt in pkts:
    print(parse_packet(pkt, False))
