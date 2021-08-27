package nnnmc.seanet.seanrs.protocol;

import com.google.common.collect.ImmutableMap;
import org.onlab.packet.*;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;

import static org.onlab.packet.PacketUtils.checkInput;

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
public class IDP extends BasePacket {

    private static final short IDP_HEADER_LENGTH = 44;
    private static final short EID_LENGTH = 20;
    public static final byte PROTOCOL_IDP = (byte) 0x99;
    public static final byte PROTOCOL_NRS = 0x10;
    public static final byte PROTOCOL_SEADP = 0x01;

    public static final Map<Byte, Deserializer<? extends IPacket>> PROTOCOL_DESERIALIZER_MAP =
            ImmutableMap.<Byte, Deserializer<? extends IPacket>>builder()
                    .put(IDP.PROTOCOL_NRS, NRS.deserializer())
                    .build();

    protected byte nextHeader;
    protected byte sEidType;
    protected byte dEidType;
    protected short reserved;
    protected byte[] sourceEID = new byte[EID_LENGTH];
    protected byte[] destEID = new byte[EID_LENGTH];

    public void setNextHeader(byte nextHeader) {
        this.nextHeader = nextHeader;
    }

    public void setDestEID(byte[] destEID) {
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

    public byte[] getSourceEID() {
        return sourceEID;
    }

    public byte[] getDestEID() {
        return destEID;
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
        int length = 44 + (payloadData == null ? 0 : payloadData.length);
        final byte[] data = new byte[length];
        final ByteBuffer bb = ByteBuffer.wrap(data);

        if (this.parent != null && this.parent instanceof IPv6) {
            ((IPv6) this.parent).setNextHeader(PROTOCOL_IDP);
        }

        bb.put(this.nextHeader);
        bb.put((byte) ((this.sEidType & 0xf) << 4 | this.dEidType & 0xf));
        bb.putShort(this.reserved);
        bb.put(sourceEID);
        bb.put(destEID);
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
        IDP idp = (IDP) o;
        return nextHeader == idp.nextHeader && sEidType == idp.sEidType && dEidType == idp.dEidType && reserved == idp.reserved && Arrays.equals(sourceEID, idp.sourceEID) && Arrays.equals(destEID, idp.destEID);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(super.hashCode(), nextHeader, sEidType, dEidType, reserved);
        result = 31 * result + Arrays.hashCode(sourceEID);
        result = 31 * result + Arrays.hashCode(destEID);
        return result;
    }

    /**
     * Deserializer function for IDP packets.
     * todo 这个地方不知道会不会有问题，应该呗IPv6类调用一下，但是不知道怎么加上
     * @return deserializer function
     */
    public static Deserializer<IDP> deserializer() {
        return (data, offset, length) -> {
            checkInput(data, offset, length, IDP_HEADER_LENGTH);

            IDP idp = new IDP();

            ByteBuffer bb = ByteBuffer.wrap(data, offset, length);
            idp.nextHeader = bb.get();
            byte temp = bb.get();
            idp.sEidType = (byte) ((temp >> 4) & 0xf);
            idp.dEidType = (byte) (temp & 0xf);
            idp.reserved = bb.getShort();
            bb.get(idp.sourceEID, 0, EID_LENGTH);
            bb.get(idp.destEID, 0, EID_LENGTH);

            Deserializer<? extends IPacket> deserializer;
            if (IDP.PROTOCOL_DESERIALIZER_MAP.containsKey(idp.nextHeader)) {
                deserializer = IDP.PROTOCOL_DESERIALIZER_MAP.get(idp.nextHeader);
            } else {
                deserializer = Data.deserializer();
            }

            idp.payload = deserializer.deserialize(data, bb.position(),
                    bb.limit() - bb.position());
            idp.payload.setParent(idp);
            return idp;
        };
    }

    @Override
    public String toString() {
        return "IDP{" +
                "nextHeader=" + nextHeader +
                ", sEidType=" + sEidType +
                ", dEidType=" + dEidType +
                ", reserved=" + reserved +
                ", sourceEID=" + Arrays.toString(sourceEID) +
                ", destEID=" + Arrays.toString(destEID) +
                '}';
    }
}

