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
}
