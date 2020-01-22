# rtp-pcap-replay

Replays tcpdump capture of RTP streams.

The goal of this program is to replay tcpdump (or wireshark) captures of RTP streams at the pace they were recorded.
The program will stream the packets on a multicast group. I used it used a lot at work to stream video cameras samples.

The program will analyse the RTP packets to stream to guess the RTP time increment between RTP images and get the initial RTP sequence.
It is able to loop over the capture file and stream it forever.
It will fix the time and sequence fields of the RTP header while streaming.

Once started the program outputs an SDP but it can't guess what is the RTP payload.
It assumes that the capture contains h264 video.
The SDP needs to be fixed for other RTP payloads which is quite easy.

A few video samples are provided with the source code for testing.

The initial version of this program uses live555 for streaming, and libpcap for reading tcpdump capture files.

Another version without the live555 dependency has been coded too.

This program has been used under cygwin and linux.



