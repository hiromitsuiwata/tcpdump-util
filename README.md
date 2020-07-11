# tcpdump-util

tcpdump で取得した pcap ファイルを読み込んで表示する

```bash
sudo tcpdump -s 0 -i en0 -nn -w tcpdump.pcap \('(tcp[tcpflags] & tcp-syn)' != 0 and '(tcp[tcpflags] & tcp-ack) ==0'\) or src port 53
```
