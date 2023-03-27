package nnnmc.seanet.seanrs.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.Inet6Address;
import java.net.UnknownHostException;

public class HexUtil {
    private static final Logger logger = LoggerFactory.getLogger(HexUtil.class);

    public static String zeros(int num) {
        return duplicates('0', num);
    }

    public static String duplicates(char c, int num) {
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < num; i++) {
            stringBuilder.append(c);
        }
        return stringBuilder.toString();
    }

    public static String byte2HexString(byte src) {
        StringBuilder stringBuilder = new StringBuilder();
        int v = src & 0xFF;
        String hv = Integer.toHexString(v);
        if (hv.length() < 2) {
            stringBuilder.append(0);
        }
        stringBuilder.append(hv);
        return stringBuilder.toString();
    }

    public static String ip2HexString(String ip, int totalLen) {
        String NA = "";
        if (ip.contains(".")) {
            NA = ipv42HexString(ip, totalLen);
        } else if (ip.contains(":")) {
            NA = ipv62HexString(ip);
        }
        return NA;
    }

    public static String ipv42HexString(String ip, int totalLen) {
        String[] ipStrings = ip.split("\\.");
        if (ipStrings.length != 4) {
            return zeros(totalLen);
        }
        StringBuilder hexIp = new StringBuilder();
        for (String ipString : ipStrings) {
            int intIp = Integer.parseInt(ipString);
            if (intIp > 255) {
                return zeros(totalLen);
            }
            String hexTemp = int2HexString(intIp, 2);
            hexIp.append(hexTemp);
        }
        return zeros(totalLen - 8) + hexIp.toString();
    }

//    public static String ipv62HexString(String ip) {
//        StringBuilder stringBuilder = new StringBuilder();
//        String[] splited = ip.split(":");
//        List<String> arr_list = new ArrayList<>();
//        if (splited.length != 8) {
//            int index = 0;
//            for (int i = 0; i < splited.length; i++) {
//                if (!splited[i].equals("")) {
//                    arr_list.add(splited[i]);
//                } else {
//                    index = i;
//                }
//            }
//            for (int i = 0; i <= 8 - splited.length; i++) {
//                arr_list.add(index, "0");
//            }
//            splited = arr_list.toArray(new String[0]);
//        }
//        for (String part : splited) {
//            int partLen = part.length();
//            if (partLen > 4) {
//                part = part.substring(0, 4);
//            }
//            stringBuilder.append(zeros(4 - partLen)).append(part);
//        }
//        return stringBuilder.toString();
//    }

    public static String ipv62HexString(String ipAddress) {
        try {
            byte[] ipv6Bytes = Inet6Address.getByName(ipAddress).getAddress();
            StringBuilder hexStringBuffer = new StringBuilder();
            for (byte b : ipv6Bytes) {
                hexStringBuffer.append(String.format("%02x", b));
            }
            return hexStringBuffer.toString();
        } catch (UnknownHostException e) {
            return null;
        }
    }


    public static String hexString2Ip(String hexString) {
        if (hexString.startsWith(HexUtil.zeros(24))) {
            //logger.info("hex str to ipv4");
            return hexString2ipv4(hexString.substring(24));
        } else {
            //logger.info("hex str to ipv6");
            return hexString2ipv6(hexString);
        }
    }

    public static String hexString2ipv4(String hexString) {
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < 4; i++) {
            stringBuilder.append(Integer.parseInt(hexString.substring(2 * i, 2 * i + 2), 16));
            if (i < 3) {
                stringBuilder.append(".");
            }
        }
        return stringBuilder.toString();
    }

    public static String hexString2ipv6(String hexString) {
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            stringBuilder.append(hexString, 4 * i, 4 * i + 4);
            if (i < 7) {
                stringBuilder.append(":");
            }
        }
        return stringBuilder.toString();
    }

    public static String int2HexString(int i, int totalLen) {
        if (i < 0) {
            return null;
        }
        //logger.info("input i is " + i + ", and totalLen is " + totalLen);
        String intHex = Integer.toHexString(i);
        int paddingLen = totalLen - intHex.length();
        if (paddingLen < 0) {
            logger.warn("The int's hex string is longer than expect.");
            logger.info(String.valueOf(intHex.length()));
            logger.info(String.valueOf(totalLen));
            return intHex.substring(intHex.length() - totalLen);
        } else {
            return zeros(paddingLen) + intHex;
        }
    }

    public static int hexString2Int(String hexString) {
        int res = 0;
        if (hexString == null || hexString.length() == 0) {
            return 0;
        }
        int weight = 1;
        char[] charArray = hexString.toLowerCase().toCharArray();
        for (int i = charArray.length - 1; i >= 0; i--) {
            res += (weight * Integer.parseInt(charArray[i] + "", 16));
            weight = weight * 16;
        }
        return res;
    }

    public static Integer byteToUnsignedInt(byte data) {
        return data & 0xff;
    }
}
