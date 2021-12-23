package nnnmc.seanet.seanrs.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.*;


/**
 * This class provide different ways to send message and get response
 */
public class SendAndRecv extends Thread {
    private static final Logger logger = LoggerFactory.getLogger(SendAndRecv.class);
    public String na;
    public int port;
    public byte[] req;
    public int timeout;
    public int protocol;
    private static final int defaultSocketTimeout = 5000;

    public SendAndRecv(int protocol, String na, int port, byte[] req) {
        this(protocol, na, port, req, defaultSocketTimeout);
    }

    public SendAndRecv(int protocol, String na, int port, byte[] req, int timeout) {
        this.protocol = protocol;
        this.na = na;
        this.port = port;
        this.req = req;
        this.timeout = timeout;
    }

    public SendAndRecv() {
    }

    public static byte[] throughTCP(String na, int port, byte[] req) {
        return throughTCP(na, port, req, defaultSocketTimeout);
    }

    public static byte[] throughTCP(String na, int port, byte[] req, int timeout) {
        byte[] resp = new byte[Message.TCP_LEN];
        try {
            Socket socket = new Socket(HexUtil.hexString2Ip(na), port);
            socket.setSoTimeout(timeout);
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            DataInputStream in = new DataInputStream(socket.getInputStream());
            logger.debug("send: " + SocketUtil.bytesToHexString(req) + " to " + na + " : " + port);
            out.write(req);
            out.flush();
            in.read(resp);
            in.close();
            out.close();
            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
            logger.error(e.toString());
            return null;
        }
        logger.debug("recv: " + SocketUtil.bytesToHexString(resp) + " from " + na + " : " + port);
        return resp;
    }

    public static void throughTCPWithoutResp(String na, int port, byte[] req) {
        try {
            Socket socket = new Socket();
            socket.connect(new InetSocketAddress(HexUtil.hexString2Ip(na), port));
            socket.setSoTimeout(defaultSocketTimeout);
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            out.write(req);
            out.flush();
            out.close();
            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
            logger.error(e.toString());
        } finally {
            logger.debug("send: " + SocketUtil.bytesToHexString(req) + " to " + na + " : " + port);
        }
    }

    public static byte[] throughUDP(String na, int port, byte[] req) {
        return throughUDP(na, port, req, defaultSocketTimeout);
    }

    public static byte[] throughUDP(InetAddress na, int port, byte[] req) {
        return throughUDP(na, port, req, defaultSocketTimeout);
    }

    public static byte[] throughUDP(String na, int port, byte[] req, int timeout) {
        DatagramPacket packet = new DatagramPacket(new byte[Message.UDP_LEN], Message.UDP_LEN);
        DatagramSocket socket = null;
        try {
            socket = new DatagramSocket(0);
            socket.setSoTimeout(timeout);
            DatagramPacket request;
            request = new DatagramPacket(req, req.length, InetAddress.getByName(HexUtil.hexString2Ip(na)), port);
//            logger.debug("send: " + SocketUtil.bytesToHexString(req) + " to " + na + " : " + port);
            socket.send(request);
            socket.receive(packet);
            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
            logger.error(e.toString());
            return null;
        } finally {
            if (socket != null)
                socket.close();
        }
        logger.debug("recv: " + SocketUtil.bytesToHexString(packet.getData()) + " from " + na + " : " + port);
        return packet.getData();
    }

    public static byte[] throughUDP(InetAddress na, int port, byte[] req, int timeout) {
        DatagramPacket packet = new DatagramPacket(new byte[Message.UDP_LEN], Message.UDP_LEN);
        DatagramSocket socket = null;
        try {
            socket = new DatagramSocket(0);
            socket.setSoTimeout(timeout);
            DatagramPacket request;
            request = new DatagramPacket(req, req.length, na, port);
            logger.debug("send: " + SocketUtil.bytesToHexString(req) + " to " + na + " : " + port);
            socket.send(request);
            socket.receive(packet);
            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
            logger.error(e.toString());
            return null;
        } finally {
            if (socket != null)
                socket.close();
        }
        logger.debug("recv: " + SocketUtil.bytesToHexString(packet.getData()) +
                " from " + na.getHostAddress() + " : " + port);
        return packet.getData();
    }

    public static void througUDPwithoutResp(InetSocketAddress src_na, InetAddress dest_na, int port, byte[] req) {
        DatagramSocket socket = null;
        try {
            socket = new DatagramSocket(src_na);
            DatagramPacket request;
            request = new DatagramPacket(req, req.length, dest_na, port);
            logger.debug("send: " + SocketUtil.bytesToHexString(req) + " to " + dest_na + " : " + port);
            socket.send(request);
        } catch (IOException e) {
            e.printStackTrace();
            logger.error(e.toString());
        } finally {
            if (socket != null)
                socket.close();
        }
    }

    @Override
    public void run() {
        super.run();
        if (protocol == 6) {
            throughTCP(na, port, req, timeout);
        } else if (protocol == 17) {
            throughUDP(na, port, req, timeout);
        }
    }
}
