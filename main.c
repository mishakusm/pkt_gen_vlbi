
#define _GNU_SOURCE	/* for CPU_SET() */
#include <arpa/inet.h>	/* ntohs */
#include <assert.h>
#include <ctype.h>	// isprint()
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>	/* getifaddrs */
#include <libnetmap.h>
#include <math.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#ifndef NO_PCAP
#include <pcap/pcap.h>
#endif
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/stat.h>
#if !defined(_WIN32) && !defined(linux)
#include <sys/sysctl.h>	/* sysctl */
#endif
#include <sys/types.h>
#include <unistd.h>	// sysconf()
#ifdef linux
#define IPV6_VERSION	0x60
#define IPV6_DEFHLIM	64
#endif

#include "ctrs.h"

static void usage(int);

#ifdef _WIN32
#define cpuset_t        DWORD_PTR   //uint64_t
static inline void CPU_ZERO(cpuset_t *p)
{
	*p = 0;
}

static inline void CPU_SET(uint32_t i, cpuset_t *p)
{
	*p |= 1<< (i & 0x3f);
}

#define pthread_setaffinity_np(a, b, c) !SetThreadAffinityMask(a, *c)    //((void)a, 0)
#define TAP_CLONEDEV	"/dev/tap"
#define AF_LINK	18	//defined in winsocks.h
#define CLOCK_REALTIME_PRECISE CLOCK_REALTIME
#include <net/if_dl.h>

/*
 * Convert an ASCII representation of an ethernet address to
 * binary form.
 */
struct ether_addr *
ether_aton(const char *a)
{
	int i;
	static struct ether_addr o;
	unsigned int o0, o1, o2, o3, o4, o5;

	i = sscanf(a, "%x:%x:%x:%x:%x:%x", &o0, &o1, &o2, &o3, &o4, &o5);

	if (i != 6)
		return (NULL);

	o.octet[0]=o0;
	o.octet[1]=o1;
	o.octet[2]=o2;
	o.octet[3]=o3;
	o.octet[4]=o4;
	o.octet[5]=o5;

	return ((struct ether_addr *)&o);
}

/*
 * Convert a binary representation of an ethernet address to
 * an ASCII string.
 */
char *
ether_ntoa(const struct ether_addr *n)
{
	int i;
	static char a[18];

	i = sprintf(a, "%02x:%02x:%02x:%02x:%02x:%02x",
	    n->octet[0], n->octet[1], n->octet[2],
	    n->octet[3], n->octet[4], n->octet[5]);
	return (i < 17 ? NULL : (char *)&a);
}
#endif /* _WIN32 */

#ifdef linux

#define cpuset_t        cpu_set_t

#define ifr_flagshigh  ifr_flags        /* only the low 16 bits here */
#define IFF_PPROMISC   IFF_PROMISC      /* IFF_PPROMISC does not exist */
#include <linux/ethtool.h>
#include <linux/sockios.h>

#define CLOCK_REALTIME_PRECISE CLOCK_REALTIME
#include <netinet/ether.h>      /* ether_aton */
#include <linux/if_packet.h>    /* sockaddr_ll */
#endif  /* linux */

#ifdef __FreeBSD__
#include <sys/endian.h> /* le64toh */
#include <machine/param.h>

#include <pthread_np.h> /* pthread w/ affinity */
#include <sys/cpuset.h> /* cpu_set */
#include <net/if_dl.h>  /* LLADDR */
#endif  /* __FreeBSD__ */

#ifdef __APPLE__

#define cpuset_t        uint64_t        // XXX
static inline void CPU_ZERO(cpuset_t *p)
{
	*p = 0;
}

static inline void CPU_SET(uint32_t i, cpuset_t *p)
{
	*p |= 1<< (i & 0x3f);
}

#define pthread_setaffinity_np(a, b, c) ((void)a, 0)

#define ifr_flagshigh  ifr_flags        // XXX
#define IFF_PPROMISC   IFF_PROMISC
#include <net/if_dl.h>  /* LLADDR */
#define clock_gettime(a,b)      \
	do {struct timespec t0 = {0,0}; *(b) = t0; } while (0)
#endif  /* __APPLE__ */

static const char *default_payload = "netmap pkt-gen DIRECT payload\n"
	"http://info.iet.unipi.it/~luigi/netmap/ ";

static const char *indirect_payload = "netmap pkt-gen indirect payload\n"
	"http://info.iet.unipi.it/~luigi/netmap/ ";

static int verbose = 0;
static int normalize = 1;

#define VIRT_HDR_1	10	/* length of a base vnet-hdr */
#define VIRT_HDR_2	12	/* length of the extenede vnet-hdr */
#define VIRT_HDR_MAX	VIRT_HDR_2
struct virt_header {
	uint8_t fields[VIRT_HDR_MAX];
};

#define MAX_BODYSIZE	65536

struct pkt {
	struct virt_header vh;
	struct ether_header eh;
	union {
		struct {
			struct ip ip;
			struct udphdr udp;
			uint8_t body[MAX_BODYSIZE];	/* hardwired */
		} ipv4;
		struct {
			struct ip6_hdr ip;
			struct udphdr udp;
			uint8_t body[MAX_BODYSIZE];	/* hardwired */
		} ipv6;
	};
} __attribute__((__packed__));



struct pkt_vlbi {
	struct virt_header vh;
	struct ether_header eh;
	union {
		struct {






			
			struct ip ip;
			struct udphdr udp;
			uint8_t body[MAX_BODYSIZE];	/* hardwired */
		} VDIF_Data_Frame_Header;
		struct {
			struct ip6_hdr ip;
			struct udphdr udp;
			uint8_t body[MAX_BODYSIZE];	/* hardwired */
		} ipv6;
	};
} __attribute__((__packed__));







#define	PKT(p, f, af)	\
    ((af) == AF_INET ? (p)->ipv4.f: (p)->ipv6.f)

/* Compute the checksum of the given ip header. */
static uint32_t
checksum(const void *data, uint16_t len, uint32_t sum)
{
	const uint8_t *addr = data;
	uint32_t i;

	/* Checksum all the pairs of bytes first... */
	for (i = 0; i < (len & ~1U); i += 2) {
		sum += (uint16_t)ntohs(*((const uint16_t *)(addr + i)));
		if (sum > 0xFFFF)
			sum -= 0xFFFF;
	}
	/*
	 * If there's a single byte left over, checksum it, too.
	 * Network byte order is big-endian, so the remaining byte is
	 * the high byte.
	 */
	if (i < len) {
		sum += addr[i] << 8;
		if (sum > 0xFFFF)
			sum -= 0xFFFF;
	}
	return sum;
}



static void
initialize_packet(struct targ *targ)
{
	struct pkt *pkt = &targ->pkt;
	struct ether_header *eh;
	struct ip6_hdr ip6;
	struct ip ip;
	struct udphdr udp;
	void *udp_ptr;
	uint16_t paylen;
	uint32_t csum = 0;
	const char *payload = targ->g->options & OPT_INDIRECT ?
		indirect_payload : default_payload;
	int i, l0 = strlen(payload);

#ifndef NO_PCAP
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *file;
	struct pcap_pkthdr *header;
	const unsigned char *packet;

	/* Read a packet from a PCAP file if asked. */
	if (targ->g->packet_file != NULL) {
		if ((file = pcap_open_offline(targ->g->packet_file,
			    errbuf)) == NULL)
			D("failed to open pcap file %s",
			    targ->g->packet_file);
		if (pcap_next_ex(file, &header, &packet) < 0)
			D("failed to read packet from %s",
			    targ->g->packet_file);
		if ((targ->frame = malloc(header->caplen)) == NULL)
			D("out of memory");
		bcopy(packet, (unsigned char *)targ->frame, header->caplen);
		targ->g->pkt_size = header->caplen;
		pcap_close(file);
		return;
	}
#endif

	paylen = targ->g->pkt_size - sizeof(*eh) -
	    (targ->g->af == AF_INET ? sizeof(ip): sizeof(ip6));

	/* create a nice NUL-terminated string */
	for (i = 0; i < paylen; i += l0) {
		if (l0 > paylen - i)
			l0 = paylen - i; // last round
		bcopy(payload, PKT(pkt, body, targ->g->af) + i, l0);
	}
	PKT(pkt, body, targ->g->af)[i - 1] = '\0';

	/* prepare the headers */
	eh = &pkt->eh;
	bcopy(&targ->g->src_mac.start, eh->ether_shost, 6);
	bcopy(&targ->g->dst_mac.start, eh->ether_dhost, 6);

	if (targ->g->af == AF_INET) {
		eh->ether_type = htons(ETHERTYPE_IP);
		memcpy(&ip, &pkt->ipv4.ip, sizeof(ip));
		udp_ptr = &pkt->ipv4.udp;
		ip.ip_v = IPVERSION;
		ip.ip_hl = sizeof(ip) >> 2;
		ip.ip_id = 0;
		ip.ip_tos = IPTOS_LOWDELAY;
		ip.ip_len = htons(targ->g->pkt_size - sizeof(*eh));
		ip.ip_id = 0;
		ip.ip_off = htons(IP_DF); /* Don't fragment */
		ip.ip_ttl = IPDEFTTL;
		ip.ip_p = IPPROTO_UDP;
		ip.ip_dst.s_addr = htonl(targ->g->dst_ip.ipv4.start);
		ip.ip_src.s_addr = htonl(targ->g->src_ip.ipv4.start);
		ip.ip_sum = wrapsum(checksum(&ip, sizeof(ip), 0));
		memcpy(&pkt->ipv4.ip, &ip, sizeof(ip));
	} else {
		eh->ether_type = htons(ETHERTYPE_IPV6);
		memcpy(&ip6, &pkt->ipv4.ip, sizeof(ip6));
		udp_ptr = &pkt->ipv6.udp;
		ip6.ip6_flow = 0;
		ip6.ip6_plen = htons(paylen);
		ip6.ip6_vfc = IPV6_VERSION;
		ip6.ip6_nxt = IPPROTO_UDP;
		ip6.ip6_hlim = IPV6_DEFHLIM;
		ip6.ip6_src = targ->g->src_ip.ipv6.start;
		ip6.ip6_dst = targ->g->dst_ip.ipv6.start;
	}
	memcpy(&udp, udp_ptr, sizeof(udp));

	udp.uh_sport = htons(targ->g->src_ip.port0);
	udp.uh_dport = htons(targ->g->dst_ip.port0);
	udp.uh_ulen = htons(paylen);
	if (targ->g->af == AF_INET) {
		/* Magic: taken from sbin/dhclient/packet.c */
		udp.uh_sum = wrapsum(
		    checksum(&udp, sizeof(udp),	/* udp header */
		    checksum(pkt->ipv4.body,	/* udp payload */
		    paylen - sizeof(udp),
		    checksum(&pkt->ipv4.ip.ip_src, /* pseudo header */
			2 * sizeof(pkt->ipv4.ip.ip_src),
			IPPROTO_UDP + (u_int32_t)ntohs(udp.uh_ulen)))));
		memcpy(&pkt->ipv4.ip, &ip, sizeof(ip));
	} else {
		/* Save part of pseudo header checksum into csum */
		csum = IPPROTO_UDP << 24;
		csum = checksum(&csum, sizeof(csum), paylen);
		udp.uh_sum = wrapsum(
		    checksum(udp_ptr, sizeof(udp),	/* udp header */
		    checksum(pkt->ipv6.body,	/* udp payload */
		    paylen - sizeof(udp),
		    checksum(&pkt->ipv6.ip.ip6_src, /* pseudo header */
			2 * sizeof(pkt->ipv6.ip.ip6_src), csum))));
		memcpy(&pkt->ipv6.ip, &ip6, sizeof(ip6));
	}
	memcpy(udp_ptr, &udp, sizeof(udp));

	bzero(&pkt->vh, sizeof(pkt->vh));
	// dump_payload((void *)pkt, targ->g->pkt_size, NULL, 0);
}