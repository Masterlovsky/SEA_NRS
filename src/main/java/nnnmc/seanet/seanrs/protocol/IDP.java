package nnnmc.seanet.seanrs.protocol;

import nnnmc.seanet.seanrs.util.Message;
import nnnmc.seanet.seanrs.util.HexUtil;
import nnnmc.seanet.seanrs.util.SocketUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;

/**
 * |------------------------8------------------------16
 * |-------Next Header------|-S.EID Type-|-D.EID Type-|
 * |--------------------Reserved----------------------|
 * |--------------------------------------------------|
 * |                                                  |
 * |                  Source EID (20B)                |
 * |                                                  |
 * |--------------------------------------------------|
 * |                                                  |
 * |                   Dest EID (20B)                 |
 * |                                                  |
 * |--------------------------------------------------|
 */
public class IDP implements Message {
    private final Logger logger = LoggerFactory.getLogger(getClass());

    private static final short IDP_HEADER_LENGTH = 44;
    private static final short EID_LENGTH = 20;
    private static final short RESERVED_LENGTH = 2;
    public static final byte PROTOCOL_NRS = 0x10;

    protected byte nextHeader;
    protected byte sEidType;
    protected byte dEidType;
    protected String reserved;
    protected String sourceEID;
    protected String destEID;
    protected byte[] payload;
    private int totalLen;

    public IDP() {
        this.nextHeader = PROTOCOL_NRS;
        this.sEidType = 0;
        this.dEidType = 0;
        this.reserved = HexUtil.zeros(32);
        this.sourceEID = HexUtil.zeros(40);
        this.destEID = HexUtil.zeros(40);
        this.payload = null;
        this.totalLen = IDP_HEADER_LENGTH;
    }

    public IDP(byte[] packet) {
        this.nextHeader = packet[0];
        this.sEidType = (byte) (packet[1] & 0xf0 >> 4);
        this.dEidType = (byte) (packet[1] & 0x0f);
        this.reserved = SocketUtil.bytesToHexString(packet, 2, 2);
        this.sourceEID = SocketUtil.bytesToHexString(packet, 4, EID_LENGTH);
        this.destEID = SocketUtil.bytesToHexString(packet, 24, EID_LENGTH);
        System.arraycopy(packet, IDP_HEADER_LENGTH, this.payload, 0, packet.length - IDP_HEADER_LENGTH);
        this.totalLen = IDP_HEADER_LENGTH + this.payload.length;
    }

    public void setNextHeader(byte nextHeader) {
        this.nextHeader = nextHeader;
    }

    public void setPayload(byte[] payload) {
        this.payload = payload;
        this.totalLen = IDP_HEADER_LENGTH + payload.length;
    }

    public byte[] getPayload() {
        return payload;
    }

    public void setDestEID(String destEID) {
        this.destEID = destEID;
    }

    public byte getNextHeader() {
        return nextHeader;
    }

    public byte getsEidType() {
        return sEidType;
    }

    public byte getdEidType() {
        return dEidType;
    }

    public String getSourceEID() {
        return sourceEID;
    }

    public String getDestEID() {
        return destEID;
    }

    @Override
    public byte[] pack() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            baos.write(nextHeader);
            baos.write((sEidType & 0x0f << 4) | (dEidType & 0x0f));
            baos.write(SocketUtil.hexStringToBytes(reserved));
            baos.write(SocketUtil.hexStringToBytes(sourceEID));
            baos.write(SocketUtil.hexStringToBytes(destEID));
            baos.write(payload);
        } catch (Exception e) {
            logger.error(e.getMessage());
            e.printStackTrace();
            return null;
        }
        return baos.toByteArray();
    }

    @Override
    public IDP unpack(byte[] data) {
        try {
            int point = 0;
            nextHeader = data[point];
            point += 1;
            sEidType = (byte) (data[point] & 0xf0 >> 4);
            dEidType = (byte) (data[point] & 0x0f);
            point += 1;
            reserved = SocketUtil.bytesToHexString(data, point, RESERVED_LENGTH);
            point += RESERVED_LENGTH;
            sourceEID = SocketUtil.bytesToHexString(data, point, EID_LENGTH);
            point += EID_LENGTH;
            destEID = SocketUtil.bytesToHexString(data, point, EID_LENGTH);
            point += EID_LENGTH;
            if (data.length > IDP_HEADER_LENGTH) {
                payload = new byte[data.length - IDP_HEADER_LENGTH];
                System.arraycopy(data, point, payload, 0, data.length - IDP_HEADER_LENGTH);
            }
        } catch (Exception e) {
            logger.error(e.getMessage());
            e.printStackTrace();
            return null;
        }
        return this;
    }
}

