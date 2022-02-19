/*
 * MIT License
 *
 * Copyright (c) 2020 vzvca
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */



#include <Groupsock.hh>
#include <GroupsockHelper.hh>
#include <BasicUsageEnvironment.hh>

#include <iostream>
#include <cstdarg>

#include <stdio.h>
#include <pcap.h>

#include <endian.h>

#define G_LITTLE_ENDIAN 1234
#define G_BIG_ENDIAN 4321
#define G_BYTE_ORDER 1234

typedef struct _RTPHeader
{
  //first byte
#if G_BYTE_ORDER == G_LITTLE_ENDIAN
  unsigned int         CC:4;//         CC field 
  unsigned int         X:1;//         /* X field */
  unsigned int         P:1;//         /* padding flag */
  unsigned int         version:2;
#elif G_BYTE_ORDER == G_BIG_ENDIAN
  unsigned int         version:2;
  unsigned int         P:1;//         /* padding flag */
  unsigned int         X:1;//         /* X field */
  unsigned int         CC:4;//        /* CC field*/
#else
#error "G_BYTE_ORDER should be big or little endian."
#endif
  //second byte
#if G_BYTE_ORDER == G_LITTLE_ENDIAN
  unsigned int         PT:7;     /* PT field */
  unsigned int         M:1;       /* M field */
#elif G_BYTE_ORDER == G_BIG_ENDIAN
  unsigned int         M:1;         /* M field */
  unsigned int         PT:7;       /* PT field */
#else
#error "G_BYTE_ORDER should be big or little endian."
#endif
  uint16_t              seq_num;      /* length of the recovery */
  uint32_t              TS;                   /* Timestamp */
  uint32_t              ssrc;
} RTPHeader; //12 bytes

// global variables
char errbuf[PCAP_ERRBUF_SIZE];
const char*    filter = NULL;
const char*    pcapfile = "capture.pcap";
const char*    dstAddressString = "232.0.1.1";
uint16_t       rtpPortNum = 1500;
uint8_t        verbose = 0;
uint8_t        loop = 0;
// linux cooked frame offset
uint32_t       offset = 3*16-4;
// ethernet frame
//uint32_t       offset = 3*16-6;

// global constants
const uint8_t  ttl = 4;


// main live555 object 
UsageEnvironment* env          = NULL;
TaskScheduler* scheduler       = NULL;
Groupsock* rtpGroupsock        = NULL;
struct bpf_program pcapfilter;


/* --------------------------------------------------------------------------
 *   Data structure used 
 * --------------------------------------------------------------------------*/
struct todo {
  pcap_t *fp;
  struct pcap_pkthdr *header;
  const u_char *pkt_data;  
};

/* --------------------------------------------------------------------------
 *   Print an help message and leave
 * --------------------------------------------------------------------------*/
void usage( const char *progname, const char *fmt, ...)
{
  if ( fmt != NULL ) {
    char tmp[1024];
    va_list va;
    va_start(va, fmt);
    vsprintf(tmp, fmt, va);
    va_end(va);

    std::cerr << progname << " error: " << tmp << std::endl;
  }

  std::cout << "Usage: ";
  std::cout << progname << " [-v] [-a mcastaddr] [-p mcastport] [-c pcapfile]" << std::endl;
  std::cout << "\t -v           : verbose " << std::endl;
  std::cout << "\t -a mcastaddr : multicast address (default "<< dstAddressString << ")" << std::endl;
  std::cout << "\t -p mcastport : multicast port (default "<< rtpPortNum << ")" << std::endl;
  std::cout << "\t -c file      : pcap file (default "<< pcapfile << ")" << std::endl;
  std::cout << "\t -f filter    : pcap filter (default none)" << std::endl;
  std::cout << "\t -l num       : how many times to play the file, 0 means infinite looping (default " << (loop+1) << ")" << std::endl;
  std::cout << "\t -o offset    : offset of payload in pcap packet (default " << offset << " is good for linux tcpdump captures)" << std::endl;
  
  exit( (fmt != NULL) ? 1 : 0);
}


/* --------------------------------------------------------------------------
 *   Parse command line switches
 * --------------------------------------------------------------------------*/
void parse( int argc, char **argv)
{
  // decode parameters
  int c = 0;     
  while ((c = getopt (argc, argv, "hva:p:c:f:l:o:")) != -1)
    {
      switch (c)
	{
	case 'a':	dstAddressString = optarg; break;
	case 'c':	pcapfile = optarg; break;
	case 'f':	filter = optarg; break;
	case 'p':	rtpPortNum = atoi(optarg); break;
	case 'v':       verbose = 1; break;
	case 'l':       loop = atoi(optarg)-1; break;
	case 'o':       offset = atoi(optarg); break;
	case 'h':       usage(argv[0], NULL); break;
	default:        usage(argv[0], "syntax error");
	}
    }
  if ( optind < argc )
    {
      usage(argv[0], "unable to process command line.");
    }
}

/* --------------------------------------------------------------------------
 *   program initialisation
 * --------------------------------------------------------------------------*/
void live( int argc, char **argv)
{
  parse(argc, argv);
  
  scheduler = BasicTaskScheduler::createNew();
  env = BasicUsageEnvironment::createNew(*scheduler);
    
  struct in_addr dstAddress;
  dstAddress.s_addr = ::our_inet_addr(dstAddressString);
    
  rtpGroupsock  = new Groupsock(*env,dstAddress,::Port(rtpPortNum),ttl);

  if ( ::IsMulticastAddress(::our_inet_addr(dstAddressString)) ) {
    rtpGroupsock->multicastSendOnly();
  }
}

/* --------------------------------------------------------------------------
 *   Open capture and compile filter
 * --------------------------------------------------------------------------*/
void open_capture(pcap_t **pfp)
{
  int reopen = (*pfp != NULL);
  
  // open capture
  if ((*pfp = pcap_open_offline(pcapfile, errbuf)) == NULL) {
    fprintf(stderr,"\nUnable to open the file '%s'.\n", pcapfile);
    exit(1);
  }
  if ( verbose ) {
    *env << "Capture file reopened.\n";
  }

  /* compile pcap filter if given */
  if ( filter != NULL && strlen(filter) > 0 ) {
    if (reopen) {
      pcap_freecode( &pcapfilter);
    }
    if ( pcap_compile(*pfp, &pcapfilter, filter, 0, PCAP_NETMASK_UNKNOWN) == -1 ) {
      fprintf(stderr,"\nUnable to compile filter '%s'.\n", filter);
      exit(1);
    }
    if ( pcap_setfilter(*pfp, &pcapfilter) == -1) {
      fprintf(stderr,"\nUnable to install filter '%s'.\n", filter);
      exit(1);
    }
  }
}

/* --------------------------------------------------------------------------
 *   Get next packet - reopen file if needed
 * --------------------------------------------------------------------------*/
void next_packet( pcap_t **pfp, struct pcap_pkthdr **phdr, const u_char ** pdata)
{
  int res;

  res = pcap_next_ex(*pfp, phdr, pdata);
  if (res <= 0) {
    // compute remaining loop number
    // -1 means infinite loop
    if ( loop > 0 ) loop--;

    // if looping over file content and eof reached reopen
    if ( (loop != 0) && (res == -2))  {
      // close capture
      if ( filter ) {
	pcap_freecode( &pcapfilter);
      }
      pcap_close(*pfp);

      // open capture
      open_capture(pfp);

      next_packet(pfp, phdr, pdata);
      return;
    }
    else {
      // it was an error
    error:
      printf("Error reading the packets: %s\n", pcap_geterr(*pfp));
      exit(1);
    }
  }
}

/* --------------------------------------------------------------------------
 *   Single processing step
 * --------------------------------------------------------------------------*/
void step( void *clientData )
{
  static int       npkts = 0;      // tracks number of played packets
  static uint32_t  rtpts = 0;      // computed RTP timestamp - used while looping
  static int       rtpseq = 0;     // computed RTP sequence number - used for looping
  static uint32_t  lastrtpts = 0;  // remember last RTP timestamp read from file
  static int       rtptsinc = 0;   // remember RTP timestamp increment
  static int64_t   usecs = 0;      // remember last number of usec to wait
  
  struct todo *task= (struct todo*) clientData;

  struct pcap_pkthdr *header = task->header;
  const u_char *pkt_data = task->pkt_data;
  struct timeval ts, next_send_time, before_send, after_send;

  if ( header == NULL ) {
    next_packet( &task->fp, &header, &pkt_data);
  }
  
  // if looping over file content
  // we need to recompute the RTP timestamp and sequence number
  if ( loop != 0 ) {
    RTPHeader *rtph = (RTPHeader*) (pkt_data + offset);

    // compute RTP timestamp
    // RTP header used big endian integers
    uint32_t hts = rtph->TS;
    hts = be32toh(hts); 
    if ( hts != lastrtpts ) {
      if ( rtpts == 0 ) {
	rtpts = hts;
      }
      rtpts += rtptsinc;
      if ( rtptsinc == 0 && lastrtpts > 0) {
	rtptsinc = hts - lastrtpts;
      }
      lastrtpts = hts;
    }
    hts = rtpts;
    rtph->TS = htobe32(hts);

    // compute RTP sequence number
    // RTP header used big endian integers
    if ( rtpseq == 0 ) {
      rtpseq = be16toh(rtph->seq_num);
    }
    else {
      rtpseq++;
    }
    rtph->seq_num = htobe16(rtpseq);
  }
  
  // increase number of processed packets
  // and print i
  npkts = npkts + 1;
  if ( verbose ) {
    if ( (npkts % 100) == 0 ) {
      *env << "Processing packets # " << npkts << " TS: " << rtpts << " rtptsinc : " << rtptsinc << " seq: " << rtpseq << "\n";
    }
  }
  
  // remember timestamp of packet to send
  ts = header->ts;

  // Send the packet
  // Note we have to move forward !!
  // kill 00 00 01 b2
  int len = header->caplen-offset;
  gettimeofday(&before_send, NULL);
  rtpGroupsock->output(*env, (unsigned char*) (pkt_data + offset), len);

  // schedule next call
  // get next packet from capture
  next_packet(&task->fp, &task->header, &task->pkt_data);

  // compute usec delta to apply
  gettimeofday(&after_send, NULL);
  after_send.tv_usec -= before_send.tv_usec;
  after_send.tv_sec  -= before_send.tv_sec;
  if ( after_send.tv_usec < 0 ) {
    after_send.tv_sec --;
    after_send.tv_usec += 1000000;
  }
  
  // Figure out the time at which the next packet should be sent, based
  // on the duration of the payload that we just read:
  next_send_time.tv_usec = task->header->ts.tv_usec - ts.tv_usec - after_send.tv_usec;
  next_send_time.tv_sec  = task->header->ts.tv_sec - ts.tv_sec - after_send.tv_sec;
  if ( next_send_time.tv_usec < 0 ) {
    next_send_time.tv_sec --;
    next_send_time.tv_usec += 1000000;
  }

  // if next_send_time.tv_sec < 0 and looping over file
  // reuse last usecs. Note that we test the opposite
  if ( next_send_time.tv_sec == 0 || loop == 0 ) {
    usecs = next_send_time.tv_sec*1000000 + next_send_time.tv_usec;
    if ( usecs < 0 ) {
      if ( verbose ) {
	std::cerr << "being late (" << -usecs << " usec)\n";
      }
      usecs = 0;
    }
  }

  // Delay this amount of time:
  scheduler->scheduleDelayedTask(usecs, (TaskFunc*)step, clientData);
}

/* --------------------------------------------------------------------------
 *  Main program
 * --------------------------------------------------------------------------*/
int main(int argc, char **argv)
{
  pcap_t *fp = NULL;
  struct todo task;

  /* init */
  live(argc, argv);
  
  /* Open the capture file */
  open_capture(&fp);
  
  /* fill task data */
  task.fp  = fp;
  task.header = NULL;
  task.pkt_data = NULL;

  /* schedule next task */
  scheduler->scheduleDelayedTask(0, (TaskFunc*)step, &task);

  /* enter live555 event loop */
  scheduler->doEventLoop(); 

  /* cleanup and exit */
  if ( filter ) {
    pcap_freecode( &pcapfilter);
  }
  pcap_close(fp);
  return 0;
}

