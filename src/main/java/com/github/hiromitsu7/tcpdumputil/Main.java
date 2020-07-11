package com.github.hiromitsu7.tcpdumputil;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.primitives.Bytes;

import io.pkts.PacketHandler;
import io.pkts.Pcap;
import io.pkts.buffer.Buffer;
import io.pkts.packet.IPv4Packet;
import io.pkts.packet.IPv6Packet;
import io.pkts.packet.Packet;
import io.pkts.packet.TCPPacket;
import io.pkts.packet.UDPPacket;
import io.pkts.protocol.Protocol;

public class Main {

  private static Logger logger = LoggerFactory.getLogger(Main.class);

  public static void main(String[] args) throws IOException {
    final Pcap pcap = Pcap.openStream("tcpdump.pcap");

    Map<String, String> dnsMap = new HashMap<>();

    pcap.loop(new PacketHandler() {
      @Override
      public boolean nextPacket(Packet packet) throws IOException {

        String sourceIP = null;
        String destinationIP = null;
        int sourcePort = 0;
        int destinationPort = 0;
        String protocol = null;

        if (packet.hasProtocol(Protocol.IPv4)) {
          IPv4Packet ipv4Packet = (IPv4Packet) packet.getPacket(Protocol.IPv4);
          sourceIP = ipv4Packet.getSourceIP();
          destinationIP = ipv4Packet.getDestinationIP();
        } else if (packet.hasProtocol(Protocol.IPv6)) {
          IPv6Packet ipv6Packet = (IPv6Packet) packet.getPacket(Protocol.IPv4);
          sourceIP = ipv6Packet.getSourceIP();
          destinationIP = ipv6Packet.getDestinationIP();
        } else {
          logger.warn("IP以外のプロトコル");
        }

        if (packet.hasProtocol(Protocol.TCP)) {
          TCPPacket tcpPacket = (TCPPacket) packet.getPacket(Protocol.TCP);
          sourcePort = tcpPacket.getSourcePort();
          destinationPort = tcpPacket.getDestinationPort();
          protocol = "TCP";
        } else if (packet.hasProtocol(Protocol.UDP)) {
          UDPPacket udpPacket = (UDPPacket) packet.getPacket(Protocol.UDP);
          sourcePort = udpPacket.getSourcePort();
          destinationPort = udpPacket.getDestinationPort();
          protocol = "UDP";
        }

        String sourceHost = dnsMap.get(sourceIP);
        if (sourceHost == null)
          sourceHost = "";
        String destinationHost = dnsMap.get(destinationIP);
        if (destinationHost == null)
          destinationHost = "";
        logger.info("{} {}({}):{} -> {}({}):{}", protocol, sourceHost, sourceIP, sourcePort, destinationHost,
            destinationIP, destinationPort);

        if (packet.hasProtocol(Protocol.UDP) && sourcePort == 53) {
          UDPPacket udpPacket = (UDPPacket) packet.getPacket(Protocol.UDP);
          Buffer buffer = udpPacket.getPayload();

          if (buffer != null) {
            // TODO 長さ指定は適当に済ませている
            int length = buffer.getReadableBytes();
            byte[] bytes = new byte[length];

            buffer.getBytes(bytes);

            int fromIndex = 0;
            int toIndex = 0;
            String domain = null;

            while (fromIndex < length) {
              // 0x00で区切る
              toIndex = findKey(bytes, fromIndex, length, (byte) 0x00);
              if (toIndex < fromIndex) {
                toIndex = length;
              }
              byte[] subbytes = Arrays.copyOfRange(bytes, fromIndex, toIndex);

              // ドメインだと思って変換する
              String temp = bytesToDomain(subbytes);
              // 変換してうまくいった場合のみ採用する
              if (temp != null && temp.matches("[a-zA-Z0-9\\.\\-]*")) {
                domain = temp;
                fromIndex = toIndex + 1;
                continue;
              }

              // IPアドレスと思われる場合も変換する
              if (subbytes.length > 4 && subbytes[0] == 4) {
                String ip = bytesToIP(Arrays.copyOfRange(subbytes, 1, 5));
                // 変換してうまくいった場合のみ採用する
                if (ip != null && ip.matches("[0-9\\.]*")) {
                  logger.info("domain = {}, IP = {}", domain, ip);
                  dnsMap.put(ip, domain);
                }
              }

              fromIndex = toIndex + 1;
            }
          }
        }
        return true;
      }
    });
  }

  private static String bytesToDomain(byte[] bytes) {
    if (bytes.length < 3) {
      return null;
    }
    List<String> domain = new ArrayList<>();
    int index = 0;
    while (index < bytes.length) {
      int length = bytes[index];
      if (length < 0) {
        return null;
      }
      String s = new String(Arrays.copyOfRange(bytes, index + 1, index + 1 + length), StandardCharsets.US_ASCII);
      domain.add(s);
      index = index + length + 1;
    }
    return domain.stream().collect(Collectors.joining("."));
  }

  private static int findKey(byte[] bytes, int fromIndex, int toIndex, byte key) {
    byte[] subArray = Arrays.copyOfRange(bytes, fromIndex, toIndex);
    return Bytes.indexOf(subArray, key) + fromIndex;
  }

  private static String bytesToIP(byte[] bytes) {
    char[] c = Hex.encodeHex(bytes);
    int i0 = Integer.parseInt(String.valueOf(Arrays.copyOfRange(c, 0, 2)), 16);
    int i1 = Integer.parseInt(String.valueOf(Arrays.copyOfRange(c, 2, 4)), 16);
    int i2 = Integer.parseInt(String.valueOf(Arrays.copyOfRange(c, 4, 6)), 16);
    int i3 = Integer.parseInt(String.valueOf(Arrays.copyOfRange(c, 6, 8)), 16);

    return String.format("%d.%d.%d.%d", i0, i1, i2, i3);
  }
}