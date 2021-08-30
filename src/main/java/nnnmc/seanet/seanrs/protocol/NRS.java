package nnnmc.seanet.seanrs.protocol;

import nnnmc.seanet.seanrs.util.HexUtil;
import nnnmc.seanet.seanrs.util.Message;
import nnnmc.seanet.seanrs.util.SocketUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;

/**
 * |------------------------8------------------------16
 * |-------Next Header------|------- QueryType--------|
 * |-------- BGPType -------|-------   Source --------|
 * |--------------------------------------------------|
 * |                                                  |
 * |                      NA (16B)                    |
 * |                                                  |
 * |--------------------------------------------------|
 */
public class NRS implements Message {
    private final Logger logger = LoggerFactory.getLogger(getClass());

    private static final short NRS_HEADER_LENGTH = 20;
    private static final short NA_LENGTH = 16;
    public static final byte PROTOCOL_SEADP = 0x01;

    protected byte nextHeader;
    protected byte queryType;
    protected byte bgpType;
    protected byte source;
    protected String na;
    protected byte[] payload;
    private int totalLength;

    public NRS() {
        this.nextHeader = PROTOCOL_SEADP;
        this.queryType = 0x05;
        this.bgpType = 0;
        this.source = 0;
        this.na = HexUtil.zeros(32);
        this.payload = null;
        this.totalLength = NRS_HEADER_LENGTH;
    }

    public NRS(byte[] packet) {
        this.nextHeader = packet[0];
        this.queryType = packet[1];
        this.bgpType = packet[2];
        this.source = packet[3];
        this.na = SocketUtil.bytesToHexString(packet, 4, NA_LENGTH);
        System.arraycopy(packet, NRS_HEADER_LENGTH, this.payload, 0, packet.length - NRS_HEADER_LENGTH);
        this.totalLength = NRS_HEADER_LENGTH + this.payload.length;
    }

    public void setNextHeader(byte nextHeader) {
        this.nextHeader = nextHeader;
    }

    public byte getNextHeader() {
        return nextHeader;
    }

    public byte getQueryType() {
        return queryType;
    }

    public byte getBgpType() {
        return bgpType;
    }

    public byte getSource() {
        return source;
    }

    public String getNa() {
        return na;
    }

    public void setNa(String na) {
        this.na = na;
    }

    public byte[] getPayload() {
        return payload;
    }

    public void setPayload(byte[] payload) {
        this.payload = payload;
        this.totalLength = NRS_HEADER_LENGTH + payload.length;
    }

    public void setQueryType(byte queryType) {
        this.queryType = queryType;
    }

    public void setBgpType(byte bgpType) {
        this.bgpType = bgpType;
    }

    public void setSource(byte source) {
        this.source = source;
    }

    @Override
    public byte[] pack() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            baos.write(nextHeader);
            baos.write(queryType);
            baos.write(bgpType);
            baos.write(source);
            baos.write(SocketUtil.hexStringToBytes(na));
            baos.write(payload);
        } catch (Exception e) {
            logger.error(e.getMessage());
            e.printStackTrace();
            return null;
        }
        return baos.toByteArray();
    }

    @Override
    public NRS unpack(byte[] data) {
        try {
            int point = 0;
            nextHeader = data[point];
            point += 1;
            queryType = data[point];
            point += 1;
            bgpType = data[point];
            point += 1;
            source = data[point];
            point += 1;
            na = SocketUtil.bytesToHexString(data, point, NA_LENGTH);
            point += NA_LENGTH;
            if (data.length > NRS_HEADER_LENGTH) {
                payload = new byte[data.length - NRS_HEADER_LENGTH];
                System.arraycopy(data, point, payload, 0, data.length - NRS_HEADER_LENGTH);
            }
        } catch (Exception e) {
            logger.error(e.getMessage());
            e.printStackTrace();
            return null;
        }
        return this;
    }
}

