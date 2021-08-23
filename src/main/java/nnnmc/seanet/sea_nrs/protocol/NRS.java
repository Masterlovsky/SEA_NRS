package nnnmc.seanet.sea_nrs.protocol;

import org.onlab.packet.*;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;

import static org.onlab.packet.PacketUtils.checkInput;

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
public class NRS extends BasePacket {

    private static final short NRS_HEADER_LENGTH = 20;
    private static final short NA_LENGTH = 16;
    public static final byte PROTOCOL_NRS = 0x10;
    public static final byte PROTOCOL_SEADP = 0x01;

    protected byte nextHeader;
    protected byte queryType;
    protected byte bgpType;
    protected byte source;

    public void setNextHeader(byte nextHeader) {
        this.nextHeader = nextHeader;
    }

    protected byte[] NA = new byte[16];

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

    public byte[] getNA() {
        return NA;
    }

    public void setNA(byte[] NA) {
        this.NA = NA;
    }

    /**
     * Serializes the packet.
     */
    @Override
    public byte[] serialize() {
        byte[] payloadData = null;
        if (this.payload != null) {
            this.payload.setParent(this);
            payloadData = this.payload.serialize();
        }
        int length = 20 + (payloadData == null ? 0 : payloadData.length);
        final byte[] data = new byte[length];
        final ByteBuffer bb = ByteBuffer.wrap(data);

        if (this.parent != null && this.parent instanceof IDP) {
            ((IDP) this.parent).setNextHeader(PROTOCOL_NRS);
        }

        bb.put(this.getNextHeader());
        bb.put(this.getQueryType());
        bb.put(this.getBgpType());
        bb.put(this.getSource());
        bb.put(this.getNA());
        if (payloadData != null) {
            bb.put(payloadData);
        }
        return data;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        NRS nrs = (NRS) o;
        return nextHeader == nrs.nextHeader && queryType == nrs.queryType && bgpType == nrs.bgpType && source == nrs.source && Arrays.equals(NA, nrs.NA);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(super.hashCode(), nextHeader, queryType, bgpType, source);
        result = 31 * result + Arrays.hashCode(NA);
        return result;
    }

    /**
     * Deserializer function for NRS packets.
     *
     * @return deserializer function
     */
    public static Deserializer<NRS> deserializer() {
        return (data, offset, length) -> {
            checkInput(data, offset, length, NRS_HEADER_LENGTH);

            NRS nrs = new NRS();

            ByteBuffer bb = ByteBuffer.wrap(data, offset, length);
            nrs.nextHeader = bb.get();
            nrs.queryType = bb.get();
            nrs.bgpType = bb.get();
            nrs.source = bb.get();
            bb.get(nrs.NA, 0, NA_LENGTH);

            Deserializer<? extends IPacket> deserializer;
            deserializer = Data.deserializer();

            nrs.payload = deserializer.deserialize(data, bb.position(),
                    bb.limit() - bb.position());
            nrs.payload.setParent(nrs);
            return nrs;
        };
    }

    @Override
    public String toString() {
        return "NRS{" +
                "nextHeader=" + nextHeader +
                ", queryType=" + queryType +
                ", bgpType=" + bgpType +
                ", source=" + source +
                ", NA=" + Arrays.toString(NA) +
                '}';
    }

    public void setQueryType(byte queryType) {
        this.queryType = queryType;
    }
}

