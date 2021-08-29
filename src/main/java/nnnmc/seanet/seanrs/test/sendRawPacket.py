import sys
import socket
from scapy.all import *
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether


class IDP(Packet):
    name = "IDP Packet"
    fields_desc = [ByteField("nextHeader", 0x10),

                   ByteField("EID_Type", 0),
                   ShortField("reserved", 1),
                   XNBytesField("sourceEID", int("0" * 40, 16), 20),
                   XNBytesField("destEID", int("a" * 40, 16), 20),
                   ]


class IDPNRS(Packet):
    name = "IDP_NRS Packet"
    fields_desc = [ByteField("nextHeader", 0x01),

                   ByteEnumField("queryType", 0x01, {0x01: "register", 0x02: "deregister", 0x03: "register_resp",
                                                     0x04: "deregister_resp", 0x05: "resolve", 0x06: "resolve_w"}),
                   ByteField("BGPType", 0),
                   ByteEnumField("source", 0, {0: "format1", 1: "format2"}),
                   XNBytesField("na", int("0" * 32, 16), 16),
                   ]


def main():
    payload_register = "6f" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" + "66666666666666666666666666666666"
    payload_deregister = "73" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" + "66666666666666666666666666666666"
    pkt_r = Ether(dst="A4:23:05:00:11:02") / IPv6(nh=0x99, src="2400:dd01:1037:9:192:168:9:201", dst="::") / IDP(
        destEID=int("0" * 40, 16)) / IDPNRS(queryType="register") / bytes.fromhex(payload_register)
    pkt_d = Ether(dst="A4:23:05:00:11:02") / IPv6(nh=0x99, src="2400:dd01:1037:9:192:168:9:201", dst="::") / IDP(
        destEID=int("0" * 40, 16)) / IDPNRS(queryType="register") / bytes.fromhex(payload_deregister)
    pkt_eq = Ether(dst="A4:23:05:00:11:02") / IPv6(nh=0x99, src="2400:dd01:1037:9:192:168:9:201",
                                                   dst="2400:dd01:1037:9:192:168:9:201") / IDP(
        destEID=int("b" * 40, 16)) / IDPNRS(queryType="resolve")
    # pkt_r = Ether() / IPv6(dst="2400:dd01:1037:201:192:168:47:198")
    pkt = pkt_eq
    pkt.show()
    hexdump(pkt)
    # sendp(pkt, iface="em4", loop=1, inter=0.2)
    # sendp(pkt, iface="em4", count=1)


if __name__ == '__main__':
    main()
