package com.github.hiromitsu7.tcpdumputil;

import java.io.IOException;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.pkts.packet.IPv4Packet;
import io.pkts.packet.IPv6Packet;
import io.pkts.packet.Packet;
import io.pkts.packet.TCPPacket;
import io.pkts.packet.UDPPacket;
import io.pkts.protocol.Protocol;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class PacketHeader {

  private static Logger logger = LoggerFactory.getLogger(PacketHeader.class);

  private String srcIP;
  private String dstIP;
  private int srcPort;
  private int dstPort;
  private String protocol;
  private String srcDomain;
  private String dstDomain;

  /**
   * IPパケットの場合にIPアドレスを設定する
   * 
   * @param packet
   * @throws IOException
   */
  void setIP(Packet packet) throws IOException {
    if (packet.hasProtocol(Protocol.IPv4)) {
      IPv4Packet ipv4Packet = (IPv4Packet) packet.getPacket(Protocol.IPv4);
      srcIP = ipv4Packet.getSourceIP();
      dstIP = ipv4Packet.getDestinationIP();
    } else if (packet.hasProtocol(Protocol.IPv6)) {
      IPv6Packet ipv6Packet = (IPv6Packet) packet.getPacket(Protocol.IPv6);
      srcIP = ipv6Packet.getSourceIP();
      dstIP = ipv6Packet.getDestinationIP();
    } else {
      logger.warn("IP以外のプロトコル");
    }
  }

  /**
   * TCP/UDPの場合にプロトコル、ポートを設定する
   * 
   * @param packet
   * @throws IOException
   */
  void setPortAndProtocol(Packet packet) throws IOException {
    if (packet.hasProtocol(Protocol.UDP)) {
      UDPPacket udpPacket = (UDPPacket) packet.getPacket(Protocol.UDP);
      srcPort = udpPacket.getSourcePort();
      dstPort = udpPacket.getDestinationPort();
      protocol = "UDP";
    } else if (packet.hasProtocol(Protocol.TCP)) {
      TCPPacket tcpPacket = (TCPPacket) packet.getPacket(Protocol.TCP);
      srcPort = tcpPacket.getSourcePort();
      dstPort = tcpPacket.getDestinationPort();
      protocol = "TCP";
    } else {
      logger.warn("TCP/UDP以外のプロトコル");
    }
  }

  /**
   * IPアドレスとドメインの紐付けが格納されたdnsMapにIPアドレスが載っている場合はドメイン情報を設定する
   * 
   * @param dnsMap
   */
  void setDomain(Map<String, String> dnsMap) {
    srcDomain = dnsMap.get(srcIP);
    if (srcDomain == null)
      srcDomain = "";
    dstDomain = dnsMap.get(dstIP);
    if (dstDomain == null)
      dstDomain = "";
  }

  /**
   * CSV形式で出力する
   */
  void printCsv() {
    String line = String.format("%s,%s,%s,%s,%s,%s,%s", protocol, srcDomain, srcIP, srcPort, dstDomain, dstIP, dstPort);
    logger.info(line);
  }
}
