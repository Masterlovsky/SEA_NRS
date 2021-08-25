package nnnmc.seanet.sea_nrs.util;

import java.util.UUID;

public class Util {
    public static String getRandomRequestID() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            long ran = Math.round(Math.random() * 10);
            sb.append(ran);
        }
        return sb.toString();
    }

    public static byte[] getRequestID() {
        String requestIDString = UUID.randomUUID().toString().substring(0, 4);
        return requestIDString.getBytes();
    }

    public static String getTimestamp() {
        String time = Long.toHexString((System.currentTimeMillis()) / 1000);
        return time.substring(time.length() - 8);
    }

    public static String msgFormat1ToIRSFormat(String payload) {
        if (payload == null) return "";
        String type = payload.substring(0, 2);
        String msg;
        if (type.equals("6f")) {
            msg = type + Util.getRandomRequestID() + payload.substring(2, 74) + "030100" + Util.getTimestamp() + "0000";
        } else if (type.equals("73")) {
            msg = type + Util.getRandomRequestID() + "00" + payload.substring(2, 74) + Util.getTimestamp();
        } else {
            msg = "";
        }
        return msg;
    }

    public static String msgFormat2ToIRSFormat(String payload) {
        if (payload == null) return "";
        String type = payload.startsWith("70") ? "73" : "6f";
        String msg;
        if (type.equals("6f")) {
            msg = type + Util.getRandomRequestID() + payload.substring(4, 76) + "030100" + Util.getTimestamp() + "0000";
        } else {
            msg = type + Util.getRandomRequestID() + "00" + payload.substring(4, 76) + Util.getTimestamp();
        }
        return msg;
    }
}
