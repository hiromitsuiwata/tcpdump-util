package com.github.hiromitsu7.tcpdumputil;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.pkts.PacketHandler;
import io.pkts.Pcap;
import io.pkts.buffer.Buffer;
import io.pkts.packet.Packet;
import io.pkts.packet.UDPPacket;
import io.pkts.protocol.Protocol;

public class Main {

  private static Logger logger = LoggerFactory.getLogger(Main.class);

  public static void main(String[] args) throws IOException {
    final Pcap pcap = Pcap.openStream("tcpdump.pcap");

    Map<String, String> dnsMap = new HashMap<>();

    logger.info("protocol,source host,source ip,source port,destination host,destination ip,destination port");

    pcap.loop(new PacketHandler() {
      @Override
      public boolean nextPacket(Packet packet) throws IOException {

        PacketHeader header = new PacketHeader();

        header.setIP(packet);

        header.setPortAndProtocol(packet);

        header.setDomain(dnsMap);

        header.printCsv();

        if (header.getSrcPort() == 53 && packet.hasProtocol(Protocol.UDP)) {
          extractDomain(dnsMap, packet);
        }
        return true;
      }
    });
  }

  /**
   * DNS応答パケットからドメインとIPの情報を取り出してdnsMapに格納する
   * 
   * @param dnsMap
   * @param packet
   * @throws IOException
   */
  private static void extractDomain(Map<String, String> dnsMap, Packet packet) throws IOException {
    UDPPacket udpPacket = (UDPPacket) packet.getPacket(Protocol.UDP);
    Buffer buffer = udpPacket.getPayload();

    if (buffer != null) {
      byte[] bytes = buffer.getArray();
      String domain = null;

      // 配列を0x00で区切る
      List<byte[]> list = split(bytes, (byte) 0x00);

      // 区切られた配列のそれぞれに対して、ドメイン部分、IPアドレス部分を取得する
      for (int i = 0; i < list.size(); i++) {
        byte[] b = list.get(i);
        // ドメインだと仮定して変換する
        String temp = bytesToDomain(b);
        // 変換してうまくいった場合のみ採用する
        if (temp != null && temp.matches("[a-zA-Z0-9\\.\\-]*")) {
          domain = temp;
          continue;
        }

        // IPアドレスである可能性がある場合はIPアドレスだと仮定して変換する
        if (b.length > 4 && b[0] == 4) {
          String ip = bytesToIP(Arrays.copyOfRange(b, 1, 5));
          // 変換した結果、成功したと思われる場合のみ採用する
          if (ip != null && ip.matches("[0-9\\.]*")) {
            logger.debug("domain = {}, IP = {}", domain, ip);
            dnsMap.put(ip, domain);
          }
        }
      }
    }
  }

  /**
   * バイト配列をdelimiterで区切る。連続したdelimiterがある場合は結果に含めない
   * 
   * @param bytes
   * @param delimiter
   * @return
   */
  private static List<byte[]> split(byte[] bytes, byte delimiter) {
    int length = bytes.length;

    List<byte[]> list = new ArrayList<>();
    int from = 0;
    boolean findingDelimeter = true;
    for (int i = 0; i < length; i++) {
      if (bytes[i] == delimiter && findingDelimeter) {
        list.add(Arrays.copyOfRange(bytes, from, i));
        findingDelimeter = false;
      } else if (bytes[i] != delimiter && !findingDelimeter) {
        from = i;
        findingDelimeter = true;
      }
    }
    list.add(Arrays.copyOfRange(bytes, from, length));
    return list;
  }

  /**
   * バイト配列をfoo.example.comのようなドメイン形式に変換する
   * 
   * @param bytes
   * @return
   */
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

  /**
   * バイト配列を192.168.1.1のようなIPアドレス形式に変換する
   * 
   * @param bytes
   * @return
   */
  private static String bytesToIP(byte[] bytes) {
    String[] strs = new String[4];
    for (int i = 0; i < 4; i++) {
      if (bytes[i] < 0) {
        strs[i] = String.valueOf(bytes[i] + 256);
      } else {
        strs[i] = String.valueOf(bytes[i]);
      }
    }
    return String.format("%s.%s.%s.%s", strs[0], strs[1], strs[2], strs[3]);
  }
}