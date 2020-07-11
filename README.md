# tcpdump-util

tcpdump で取得した pcap ファイルを読み込んで表示する

## tcpdumpの実行

以下のパケットを選んでファイル出力することでpcapファイルサイズを削減する

- SYNフラグが立っていてACKフラグが立っていないパケット
- DNS応答であるパケット

```bash
sudo tcpdump -s 0 -i en0 -nn -w tcpdump.pcap \('(tcp[tcpflags] & tcp-syn)' != 0 and '(tcp[tcpflags] & tcp-ack) ==0'\) or src port 53
```

## pcapファイルの分析

```bash
mvn clean compile exec:java
```
