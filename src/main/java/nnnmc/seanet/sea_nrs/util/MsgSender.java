package nnnmc.seanet.sea_nrs.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.*;
import java.util.concurrent.ExecutorService;

public class MsgSender {

    private static final Logger logger = LoggerFactory.getLogger(MsgSender.class);

    public static void sendPacketBG(byte[] msgBytes, int protocol, String srcIp, String destIp, int destPort, ExecutorService es) {
        es.execute(() -> {
            try {
                if (protocol == 6) {
                    Socket socket = new Socket();
                    socket.setSoTimeout(1000);
                    socket.bind(new InetSocketAddress(HexUtil.hexString2Ip(srcIp), 0));
                    socket.connect(new InetSocketAddress(HexUtil.hexString2Ip(destIp), destPort));
                    DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                    DataInputStream in = new DataInputStream(socket.getInputStream());
                    out.write(msgBytes);
                    out.flush();
                    in.read(new byte[Message.TCP_LEN]);
                    out.close();
                    in.close();
                    socket.close();
                } else if (protocol == 17) {
                    DatagramSocket socket = new DatagramSocket(new InetSocketAddress(HexUtil.hexString2Ip(srcIp), 0));
                    socket.setSoTimeout(1000);
                    DatagramPacket packet = new DatagramPacket(msgBytes, msgBytes.length, InetAddress.getByName(HexUtil.hexString2Ip(destIp)), destPort);
                    socket.send(packet);
                    socket.close();
                } else {
                    logger.error("Unsupported protocol");
                }
                logger.debug("Send: " + SocketUtil.bytesToHexString(msgBytes) + " to " + destIp + " : " + destPort);
            } catch (Exception e) {
                e.printStackTrace();
                logger.error(e.toString());
            }
        });
    }

    public static byte[] getResp(byte[] msgBytes, int protocol, String srcIp, String destIp, int destPort) {
        byte[] resp = null;
        try {
            if (protocol == 6) {
                Socket socket = new Socket();
                socket.setSoTimeout(1000);
                socket.bind(new InetSocketAddress(HexUtil.hexString2Ip(srcIp), 0));
                socket.connect(new InetSocketAddress(HexUtil.hexString2Ip(destIp), destPort));
                DataOutputStream out = new DataOutputStream(socket.getOutputStream());
                DataInputStream in = new DataInputStream(socket.getInputStream());
                out.write(msgBytes);
                out.flush();
                resp = new byte[Message.TCP_LEN];
                in.read(resp);
                out.close();
                in.close();
                socket.close();
            } else if (protocol == 17) {
                DatagramSocket socket = new DatagramSocket(new InetSocketAddress(HexUtil.hexString2Ip(srcIp), 0));
                socket.setSoTimeout(1000);
                DatagramPacket packet = new DatagramPacket(msgBytes, msgBytes.length, InetAddress.getByName(HexUtil.hexString2Ip(destIp)), destPort);
                socket.send(packet);
                resp = new byte[Message.UDP_LEN];
                DatagramPacket response = new DatagramPacket(resp, Message.UDP_LEN);
                socket.receive(response);
                socket.close();
            } else {
                logger.error("Unsupported protocol");
            }
            logger.debug("Send: " + SocketUtil.bytesToHexString(msgBytes) + " to " + destIp + " : " + destPort);
        } catch (IOException e) {
            e.printStackTrace();
            logger.error(e.toString());
        }
        return resp;
    }

    public static void main(String[] a) {
    	getResp(SocketUtil.hexStringToBytes("1"), 6, "000000000000000000000000c0a86466", "0000000000000000000000007f000001", 10063);
    }
}
