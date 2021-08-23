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
                   StrField("sourceEID", '0' * 40),
                   StrField("destEID", '0' * 40),
                   ]


class IDPNRS(Packet):
    name = "IDP_NRS Packet"
    fields_desc = [ByteField("nextHeader", 0x01),

                   ByteEnumField("queryType", 0x01, {0x01: "register", 0x02: "deregister", 0x03: "register_resp",
                                                     0x04: "deregister_resp", 0x05: "resolve", 0x06: "resolve_w"}),
                   ByteField("BGPType", 0),
                   ByteField("source", 0),
                   StrField("na", '0' * 32),
                   ]


def main():
    pkt = Ether() / IPv6(nh=0x99, src="::0", dst="2400:dd01:1037:201:192:168:47:198") / IDP(
        destEID="1" * 40) / IDPNRS(queryType="register") / "hello World"
    # pkt = Ether() / IPv6(dst="2400:dd01:1037:201:192:168:47:198")
    pkt.show()
    # sendp(pkt, loop=1, inter=0.2)
    sendp(pkt, count=10)


if __name__ == '__main__':
    main()
