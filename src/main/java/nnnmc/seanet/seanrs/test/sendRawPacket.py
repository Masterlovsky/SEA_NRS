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
    payload_register = "6f" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" + \
        "66666666666666666666666666666666"
    payload_deregister = "73" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" + \
        "66666666666666666666666666666666"
    payload_register_resp = "70" + "00" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" + \
        "66666666666666666666666666666666" + "2400dd01103700090192016800090017" + \
        "00000001" + "2400dd01103702010192016800470198"
    payload_deregister_resp = "74" + "00" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" + \
        "66666666666666666666666666666666" + "2400dd01103700090192016800090017" + \
        "00000001" + "2400dd01103702010192016800470198"
    pkt_r = Ether(dst="A4:23:05:00:11:02") / IPv6(nh=0x99, src="2400:dd01:1037:9:192:168:9:201", dst="::") / IDP(
        destEID=int("0" * 40, 16)) / IDPNRS(queryType="register") / bytes.fromhex(payload_register)
    pkt_d = Ether(dst="A4:23:05:00:11:02") / IPv6(nh=0x99, src="2400:dd01:1037:9:192:168:9:201", dst="::") / IDP(
        destEID=int("0" * 40, 16)) / IDPNRS(queryType="register") / bytes.fromhex(payload_deregister)
    pkt_eq = Ether(dst="A4:23:05:00:11:02") / IPv6(nh=0x99, src="2400:dd01:1037:9:192:168:9:201", dst="::") / IDP(
        destEID=int("b" * 40, 16)) / IDPNRS(queryType="resolve")
    pkt_rf = Ether(dst="A4:23:05:00:11:02") / IPv6(nh=0x99, src="2400:dd01:1037:201:192:168:47:198", dst="2400:dd01:1037:9:192:168:9:17") / IDP(
        destEID=int("0" * 40, 16)) / IDPNRS(queryType="register_resp", source="format2") / bytes.fromhex(payload_register_resp)
    pkt_df = Ether(dst="A4:23:05:00:11:02") / IPv6(nh=0x99, src="2400:dd01:1037:201:192:168:47:198", dst="2400:dd01:1037:9:192:168:9:17") / IDP(
        destEID=int("0" * 40, 16)) / IDPNRS(queryType="deregister_resp", source="format2") / bytes.fromhex(payload_deregister_resp)

    pkt = pkt_df
    pkt.show()
    hexdump(pkt)
    # sendp(pkt, iface="em4", loop=1, inter=0.2)
    sendp(pkt, iface="em4", count=1)


if __name__ == '__main__':
    main()

    # a42305001102 f0d4e2e8511f 86dd 6000000000409940 2400dd01103700090192016800090201 99999999999999999999999999999999 10 00 0001 0000000000000000000000000000000000000000 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 01 05 00 00 00000000000000000000000000000000
    # a42305001102 f0d4e2e8511f 86dd 6000000000899940 2400dd01103700090192016800090201 2400dd01103702010192016800470198 10 00 0001 0000000000000000000000000000000000000000 0000000000000000000000000000000000000000 01 01 00 01 00000000000000000000000000000000 6fbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb66666666666666666666666666666666 2400dd01103700090192016800090017 00000001 2400dd01103702010192016800470198
