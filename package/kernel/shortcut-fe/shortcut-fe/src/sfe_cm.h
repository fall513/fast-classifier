/*
 * sfe_cm.h
 *	Shortcut forwarding engine.
 *
 * Copyright (c) 2013-2016 The Linux Foundation. All rights reserved.
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all copies.
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define ENABLE_PPPOE_RULE	1

/*
 * connection flags.
 */
#define SFE_CREATE_FLAG_NO_SEQ_CHECK BIT(0)
					/* Indicates that we should not check sequence numbers */
#define SFE_CREATE_FLAG_REMARK_PRIORITY BIT(1)
					/* Indicates that we should remark priority of skb */
#define SFE_CREATE_FLAG_REMARK_DSCP BIT(2)
					/* Indicates that we should remark DSCP of packet */

/*
 * IPv6 address structure
 */
struct sfe_ipv6_addr {
	__be32 addr[4];
};

typedef union {
	__be32			ip;
	struct sfe_ipv6_addr	ip6[1];
} sfe_ip_addr_t;

/*
 * connection creation structure.
 */
struct sfe_connection_create {
	int protocol;
	struct net_device *src_dev;
	struct net_device *dest_dev;
	u32 flags;
	u32 src_mtu;
	u32 dest_mtu;
	sfe_ip_addr_t src_ip;
	sfe_ip_addr_t src_ip_xlate;
	sfe_ip_addr_t dest_ip;
	sfe_ip_addr_t dest_ip_xlate;
	__be16 src_port;
	__be16 src_port_xlate;
	__be16 dest_port;
	__be16 dest_port_xlate;
	u8 src_mac[ETH_ALEN];
	u8 src_mac_xlate[ETH_ALEN];
	u8 dest_mac[ETH_ALEN];
	u8 dest_mac_xlate[ETH_ALEN];
	u8 src_td_window_scale;
	u32 src_td_max_window;
	u32 src_td_end;
	u32 src_td_max_end;
	u8 dest_td_window_scale;
	u32 dest_td_max_window;
	u32 dest_td_end;
	u32 dest_td_max_end;
	u32 mark;
#ifdef CONFIG_XFRM
	u32 original_accel;
	u32 reply_accel;
#endif
	u32 src_priority;
	u32 dest_priority;
	u32 src_dscp;
	u32 dest_dscp;
};

/*
 * connection destruction structure.
 */
struct sfe_connection_destroy {
	int protocol;
	sfe_ip_addr_t src_ip;
	sfe_ip_addr_t dest_ip;
	__be16 src_port;
	__be16 dest_port;
};

typedef enum sfe_sync_reason {
	SFE_SYNC_REASON_STATS,	/* Sync is to synchronize stats */
	SFE_SYNC_REASON_FLUSH,	/* Sync is to flush a entry */
	SFE_SYNC_REASON_DESTROY	/* Sync is to destroy a entry(requested by connection manager) */
} sfe_sync_reason_t;

/*
 * Structure used to sync connection stats/state back within the system.
 *
 * NOTE: The addresses here are NON-NAT addresses, i.e. the true endpoint addressing.
 * 'src' is the creator of the connection.
 */
struct sfe_connection_sync {
	struct net_device *src_dev;
	struct net_device *dest_dev;
	int is_v6;			/* Is it for ipv6? */
	int protocol;			/* IP protocol number (IPPROTO_...) */
	sfe_ip_addr_t src_ip;		/* Non-NAT source address, i.e. the creator of the connection */
	sfe_ip_addr_t src_ip_xlate;	/* NATed source address */
	__be16 src_port;		/* Non-NAT source port */
	__be16 src_port_xlate;		/* NATed source port */
	sfe_ip_addr_t dest_ip;		/* Non-NAT destination address, i.e. to whom the connection was created */
	sfe_ip_addr_t dest_ip_xlate;	/* NATed destination address */
	__be16 dest_port;		/* Non-NAT destination port */
	__be16 dest_port_xlate;		/* NATed destination port */
	u32 src_td_max_window;
	u32 src_td_end;
	u32 src_td_max_end;
	u64 src_packet_count;
	u64 src_byte_count;
	u32 src_new_packet_count;
	u32 src_new_byte_count;
	u32 dest_td_max_window;
	u32 dest_td_end;
	u32 dest_td_max_end;
	u64 dest_packet_count;
	u64 dest_byte_count;
	u32 dest_new_packet_count;
	u32 dest_new_byte_count;
	u32 reason;		/* reason for stats sync message, i.e. destroy, flush, period sync */
	u64 delta_jiffies;		/* Time to be added to the current timeout to keep the connection alive */
};

/*
 * connection mark structure
 */
struct sfe_connection_mark {
	int protocol;
	sfe_ip_addr_t src_ip;
	sfe_ip_addr_t dest_ip;
	__be16 src_port;
	__be16 dest_port;
	u32 mark;
};

/*
 * By default Linux IP header and transport layer header structures are
 * unpacked, assuming that such headers should be 32-bit aligned.
 * Unfortunately some wireless adaptors can't cope with this requirement and
 * some CPUs can't handle misaligned accesses.  For those platforms we
 * define SFE_IPV4_UNALIGNED_IP_HEADER and mark the structures as packed.
 * When we do this the compiler will generate slightly worse code than for the
 * aligned case (on most platforms) but will be much quicker than fixing
 * things up in an unaligned trap handler.
 */
#define SFE_IPV4_UNALIGNED_IP_HEADER 1
#if SFE_IPV4_UNALIGNED_IP_HEADER
#define SFE_IPV4_UNALIGNED_STRUCT __attribute__((packed, aligned(2)))
#else
#define SFE_IPV4_UNALIGNED_STRUCT
#endif

/*
 * An Ethernet header, but with an optional "packed" attribute to
 * help with performance on some platforms (see the definition of
 * SFE_IPV4_UNALIGNED_STRUCT)
 */
struct sfe_ipv4_eth_hdr {
	__be16 h_dest[ETH_ALEN / 2];
	__be16 h_source[ETH_ALEN / 2];
	__be16 h_proto;
} SFE_IPV4_UNALIGNED_STRUCT;

#define SFE_IPV4_DSCP_MASK 0x3
#define SFE_IPV4_DSCP_SHIFT 2

/*
 * An IPv4 header, but with an optional "packed" attribute to
 * help with performance on some platforms (see the definition of
 * SFE_IPV4_UNALIGNED_STRUCT)
 */
struct sfe_ipv4_ip_hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8 ihl:4,
	     version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8 version:4,
	     ihl:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__u8 tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__sum16 check;
	__be32 saddr;
	__be32 daddr;

	/*
	 * The options start here.
	 */
} SFE_IPV4_UNALIGNED_STRUCT;

/*
 * A UDP header, but with an optional "packed" attribute to
 * help with performance on some platforms (see the definition of
 * SFE_IPV4_UNALIGNED_STRUCT)
 */
struct sfe_ipv4_udp_hdr {
	__be16 source;
	__be16 dest;
	__be16 len;
	__sum16 check;
} SFE_IPV4_UNALIGNED_STRUCT;

/*
 * A TCP header, but with an optional "packed" attribute to
 * help with performance on some platforms (see the definition of
 * SFE_IPV4_UNALIGNED_STRUCT)
 */
struct sfe_ipv4_tcp_hdr {
	__be16 source;
	__be16 dest;
	__be32 seq;
	__be32 ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16 res1:4,
	      doff:4,
	      fin:1,
	      syn:1,
	      rst:1,
	      psh:1,
	      ack:1,
	      urg:1,
	      ece:1,
	      cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16 doff:4,
	      res1:4,
	      cwr:1,
	      ece:1,
	      urg:1,
	      ack:1,
	      psh:1,
	      rst:1,
	      syn:1,
	      fin:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
	__be16 window;
	__sum16	check;
	__be16 urg_ptr;
} SFE_IPV4_UNALIGNED_STRUCT;

/*
 * Specifies the lower bound on ACK numbers carried in the TCP header
 */
#define SFE_IPV4_TCP_MAX_ACK_WINDOW 65520

/*
 * IPv4 TCP connection match additional data.
 */
struct sfe_ipv4_tcp_connection_match {
	u8 win_scale;		/* Window scale */
	u32 max_win;		/* Maximum window size seen */
	u32 end;			/* Sequence number of the next byte to send (seq + segment length) */
	u32 max_end;		/* Sequence number of the last byte to ack */
};

/*
 * Expose the hook for the receive processing.
 */
extern int (*fast_nat_recv)(struct sk_buff *skb);

/*
 * Expose what should be a static flag in the TCP connection tracker.
 */
extern int nf_ct_tcp_no_window_check;

/*
 * This callback will be called in a timer
 * at 100 times per second to sync stats back to
 * Linux connection track.
 *
 * A RCU lock is taken to prevent this callback
 * from unregistering.
 */
typedef void (*sfe_sync_rule_callback_t)(struct sfe_connection_sync *);

/*
 * IPv4 APIs used by connection manager
 */
int sfe_ipv4_recv(struct net_device *dev, struct sk_buff *skb);
#if ENABLE_PPPOE_RULE
extern int sfe_pppoe_recv(struct net_device *dev, struct sk_buff *skb);
#endif
int sfe_ipv4_create_rule(struct sfe_connection_create *sic);
void sfe_ipv4_destroy_rule(struct sfe_connection_destroy *sid);
void sfe_ipv4_destroy_all_rules_for_dev(struct net_device *dev);
void sfe_ipv4_register_sync_rule_callback(sfe_sync_rule_callback_t callback);
void sfe_ipv4_update_rule(struct sfe_connection_create *sic);
void sfe_ipv4_mark_rule(struct sfe_connection_mark *mark);

#ifdef SFE_SUPPORT_IPV6
/*
 * IPv6 APIs used by connection manager
 */
int sfe_ipv6_recv(struct net_device *dev, struct sk_buff *skb);
int sfe_ipv6_create_rule(struct sfe_connection_create *sic);
void sfe_ipv6_destroy_rule(struct sfe_connection_destroy *sid);
void sfe_ipv6_destroy_all_rules_for_dev(struct net_device *dev);
void sfe_ipv6_register_sync_rule_callback(sfe_sync_rule_callback_t callback);
void sfe_ipv6_update_rule(struct sfe_connection_create *sic);
void sfe_ipv6_mark_rule(struct sfe_connection_mark *mark);
#else
static inline int sfe_ipv6_recv(struct net_device *dev, struct sk_buff *skb)
{
	return 0;
}

static inline int sfe_ipv6_create_rule(struct sfe_connection_create *sic)
{
	return 0;
}

static inline void sfe_ipv6_destroy_rule(struct sfe_connection_destroy *sid)
{
	return;
}

static inline void sfe_ipv6_destroy_all_rules_for_dev(struct net_device *dev)
{
	return;
}

static inline void sfe_ipv6_register_sync_rule_callback(sfe_sync_rule_callback_t callback)
{
	return;
}

static inline void sfe_ipv6_update_rule(struct sfe_connection_create *sic)
{
	return;
}

static inline void sfe_ipv6_mark_rule(struct sfe_connection_mark *mark)
{
	return;
}
#endif

/*
 * sfe_ipv6_addr_equal()
 *	compare ipv6 address
 *
 * return: 1, equal; 0, no equal
 */
static inline int sfe_ipv6_addr_equal(struct sfe_ipv6_addr *a,
				      struct sfe_ipv6_addr *b)
{
	return a->addr[0] == b->addr[0] &&
	       a->addr[1] == b->addr[1] &&
	       a->addr[2] == b->addr[2] &&
	       a->addr[3] == b->addr[3];
}

/*
 * sfe_ipv4_addr_equal()
 *	compare ipv4 address
 *
 * return: 1, equal; 0, no equal
 */
#define sfe_ipv4_addr_equal(a, b) ((u32)(a) == (u32)(b))

/*
 * sfe_addr_equal()
 *	compare ipv4 or ipv6 address
 *
 * return: 1, equal; 0, no equal
 */
static inline int sfe_addr_equal(sfe_ip_addr_t *a,
				 sfe_ip_addr_t *b, int is_v4)
{
	return is_v4 ? sfe_ipv4_addr_equal(a->ip, b->ip) : sfe_ipv6_addr_equal(a->ip6, b->ip6);
}

/*
 * IPv4 connection matching structure.
 */
struct sfe_ipv4_connection_match {
	/*
	 * References to other objects.
	 */
	struct sfe_ipv4_connection_match *next;
	struct sfe_ipv4_connection_match *prev;
	struct sfe_ipv4_connection *connection;
	struct sfe_ipv4_connection_match *counter_match;
					/* Matches the flow in the opposite direction as the one in *connection */
	struct sfe_ipv4_connection_match *active_next;
	struct sfe_ipv4_connection_match *active_prev;
	bool active;			/* Flag to indicate if we're on the active list */

	/*
	 * Characteristics that identify flows that match this rule.
	 */
	struct net_device *match_dev;	/* Network device */
	unsigned int match_protocol;		/* Protocol */
	__be32 match_src_ip;		/* Source IP address */
	__be32 match_dest_ip;		/* Destination IP address */
	__be16 match_src_port;		/* Source port/connection ident */
	__be16 match_dest_port;		/* Destination port/connection ident */

	/*
	 * Control the operations of the match.
	 */
	u32 flags;			/* Bit flags */
#ifdef CONFIG_XFRM
	u32 flow_accel;             /* The flow accelerated or not */
#endif

	/*
	 * Connection state that we track once we match.
	 */
	union {				/* Protocol-specific state */
		struct sfe_ipv4_tcp_connection_match tcp;
	} protocol_state;
	/*
	 * Stats recorded in a sync period. These stats will be added to
	 * rx_packet_count64/rx_byte_count64 after a sync period.
	 */
	u32 rx_packet_count;
	u32 rx_byte_count;

	/*
	 * Packet translation information.
	 */
	__be32 xlate_src_ip;		/* Address after source translation */
	__be16 xlate_src_port;	/* Port/connection ident after source translation */
	u16 xlate_src_csum_adjustment;
					/* Transport layer checksum adjustment after source translation */
	u16 xlate_src_partial_csum_adjustment;
					/* Transport layer pseudo header checksum adjustment after source translation */

	__be32 xlate_dest_ip;		/* Address after destination translation */
	__be16 xlate_dest_port;	/* Port/connection ident after destination translation */
	u16 xlate_dest_csum_adjustment;
					/* Transport layer checksum adjustment after destination translation */
	u16 xlate_dest_partial_csum_adjustment;
					/* Transport layer pseudo header checksum adjustment after destination translation */

	/*
	 * QoS information
	 */
	u32 priority;
	u32 dscp;

	/*
	 * Packet transmit information.
	 */
	struct net_device *xmit_dev;	/* Network device on which to transmit */
	unsigned short int xmit_dev_mtu;
					/* Interface MTU */

	u16 xmit_dest_mac[ETH_ALEN / 2];
					/* Destination MAC address to use when forwarding */
	u16 xmit_src_mac[ETH_ALEN / 2];
					/* Source MAC address to use when forwarding */
#if ENABLE_PPPOE_RULE
	struct sock *pppoe_sk;		/* pppoe socket for transmitting to this xmit_dev */
#endif

	/*
	 * Summary stats.
	 */
	u64 rx_packet_count64;
	u64 rx_byte_count64;
};

/*
 * Per-connection data structure.
 */
struct sfe_ipv4_connection {
	struct sfe_ipv4_connection *next;
					/* Pointer to the next entry in a hash chain */
	struct sfe_ipv4_connection *prev;
					/* Pointer to the previous entry in a hash chain */
	int protocol;			/* IP protocol number */
	__be32 src_ip;			/* Src IP addr pre-translation */
	__be32 src_ip_xlate;		/* Src IP addr post-translation */
	__be32 dest_ip;			/* Dest IP addr pre-translation */
	__be32 dest_ip_xlate;		/* Dest IP addr post-translation */
	__be16 src_port;		/* Src port pre-translation */
	__be16 src_port_xlate;		/* Src port post-translation */
	__be16 dest_port;		/* Dest port pre-translation */
	__be16 dest_port_xlate;		/* Dest port post-translation */
	struct sfe_ipv4_connection_match *original_match;
					/* Original direction matching structure */
	struct net_device *original_dev;
					/* Original direction source device */
	struct sfe_ipv4_connection_match *reply_match;
					/* Reply direction matching structure */
	struct net_device *reply_dev;	/* Reply direction source device */
	u64 last_sync_jiffies;		/* Jiffies count for the last sync */
	struct sfe_ipv4_connection *all_connections_next;
					/* Pointer to the next entry in the list of all connections */
	struct sfe_ipv4_connection *all_connections_prev;
					/* Pointer to the previous entry in the list of all connections */
	u32 mark;			/* mark for outgoing packet */
	u32 debug_read_seq;		/* sequence number for debug dump */
};

/*
 * IPv4 connections and hash table size information.
 */
#define SFE_IPV4_CONNECTION_HASH_SHIFT 12
#define SFE_IPV4_CONNECTION_HASH_SIZE (1 << SFE_IPV4_CONNECTION_HASH_SHIFT)
#define SFE_IPV4_CONNECTION_HASH_MASK (SFE_IPV4_CONNECTION_HASH_SIZE - 1)

enum sfe_ipv4_exception_events {
	SFE_IPV4_EXCEPTION_EVENT_UDP_HEADER_INCOMPLETE,
	SFE_IPV4_EXCEPTION_EVENT_UDP_NO_CONNECTION,
	SFE_IPV4_EXCEPTION_EVENT_UDP_IP_OPTIONS_OR_INITIAL_FRAGMENT,
	SFE_IPV4_EXCEPTION_EVENT_UDP_SMALL_TTL,
	SFE_IPV4_EXCEPTION_EVENT_UDP_NEEDS_FRAGMENTATION,
	SFE_IPV4_EXCEPTION_EVENT_TCP_HEADER_INCOMPLETE,
	SFE_IPV4_EXCEPTION_EVENT_TCP_NO_CONNECTION_SLOW_FLAGS,
	SFE_IPV4_EXCEPTION_EVENT_TCP_NO_CONNECTION_FAST_FLAGS,
	SFE_IPV4_EXCEPTION_EVENT_TCP_IP_OPTIONS_OR_INITIAL_FRAGMENT,
	SFE_IPV4_EXCEPTION_EVENT_TCP_SMALL_TTL,
	SFE_IPV4_EXCEPTION_EVENT_TCP_NEEDS_FRAGMENTATION,
	SFE_IPV4_EXCEPTION_EVENT_TCP_FLAGS,
	SFE_IPV4_EXCEPTION_EVENT_TCP_SEQ_EXCEEDS_RIGHT_EDGE,
	SFE_IPV4_EXCEPTION_EVENT_TCP_SMALL_DATA_OFFS,
	SFE_IPV4_EXCEPTION_EVENT_TCP_BAD_SACK,
	SFE_IPV4_EXCEPTION_EVENT_TCP_BIG_DATA_OFFS,
	SFE_IPV4_EXCEPTION_EVENT_TCP_SEQ_BEFORE_LEFT_EDGE,
	SFE_IPV4_EXCEPTION_EVENT_TCP_ACK_EXCEEDS_RIGHT_EDGE,
	SFE_IPV4_EXCEPTION_EVENT_TCP_ACK_BEFORE_LEFT_EDGE,
	SFE_IPV4_EXCEPTION_EVENT_ICMP_HEADER_INCOMPLETE,
	SFE_IPV4_EXCEPTION_EVENT_ICMP_UNHANDLED_TYPE,
	SFE_IPV4_EXCEPTION_EVENT_ICMP_IPV4_HEADER_INCOMPLETE,
	SFE_IPV4_EXCEPTION_EVENT_ICMP_IPV4_NON_V4,
	SFE_IPV4_EXCEPTION_EVENT_ICMP_IPV4_IP_OPTIONS_INCOMPLETE,
	SFE_IPV4_EXCEPTION_EVENT_ICMP_IPV4_UDP_HEADER_INCOMPLETE,
	SFE_IPV4_EXCEPTION_EVENT_ICMP_IPV4_TCP_HEADER_INCOMPLETE,
	SFE_IPV4_EXCEPTION_EVENT_ICMP_IPV4_UNHANDLED_PROTOCOL,
	SFE_IPV4_EXCEPTION_EVENT_ICMP_NO_CONNECTION,
	SFE_IPV4_EXCEPTION_EVENT_ICMP_FLUSHED_CONNECTION,
	SFE_IPV4_EXCEPTION_EVENT_HEADER_INCOMPLETE,
	SFE_IPV4_EXCEPTION_EVENT_BAD_TOTAL_LENGTH,
	SFE_IPV4_EXCEPTION_EVENT_NON_V4,
	SFE_IPV4_EXCEPTION_EVENT_NON_INITIAL_FRAGMENT,
	SFE_IPV4_EXCEPTION_EVENT_DATAGRAM_INCOMPLETE,
	SFE_IPV4_EXCEPTION_EVENT_IP_OPTIONS_INCOMPLETE,
	SFE_IPV4_EXCEPTION_EVENT_UNHANDLED_PROTOCOL,
	SFE_IPV4_EXCEPTION_EVENT_CSUM_ERROR,
	SFE_IPV4_EXCEPTION_EVENT_LAST
};

static char *sfe_ipv4_exception_events_string[SFE_IPV4_EXCEPTION_EVENT_LAST] = {
	"UDP_HEADER_INCOMPLETE",
	"UDP_NO_CONNECTION",
	"UDP_IP_OPTIONS_OR_INITIAL_FRAGMENT",
	"UDP_SMALL_TTL",
	"UDP_NEEDS_FRAGMENTATION",
	"TCP_HEADER_INCOMPLETE",
	"TCP_NO_CONNECTION_SLOW_FLAGS",
	"TCP_NO_CONNECTION_FAST_FLAGS",
	"TCP_IP_OPTIONS_OR_INITIAL_FRAGMENT",
	"TCP_SMALL_TTL",
	"TCP_NEEDS_FRAGMENTATION",
	"TCP_FLAGS",
	"TCP_SEQ_EXCEEDS_RIGHT_EDGE",
	"TCP_SMALL_DATA_OFFS",
	"TCP_BAD_SACK",
	"TCP_BIG_DATA_OFFS",
	"TCP_SEQ_BEFORE_LEFT_EDGE",
	"TCP_ACK_EXCEEDS_RIGHT_EDGE",
	"TCP_ACK_BEFORE_LEFT_EDGE",
	"ICMP_HEADER_INCOMPLETE",
	"ICMP_UNHANDLED_TYPE",
	"ICMP_IPV4_HEADER_INCOMPLETE",
	"ICMP_IPV4_NON_V4",
	"ICMP_IPV4_IP_OPTIONS_INCOMPLETE",
	"ICMP_IPV4_UDP_HEADER_INCOMPLETE",
	"ICMP_IPV4_TCP_HEADER_INCOMPLETE",
	"ICMP_IPV4_UNHANDLED_PROTOCOL",
	"ICMP_NO_CONNECTION",
	"ICMP_FLUSHED_CONNECTION",
	"HEADER_INCOMPLETE",
	"BAD_TOTAL_LENGTH",
	"NON_V4",
	"NON_INITIAL_FRAGMENT",
	"DATAGRAM_INCOMPLETE",
	"IP_OPTIONS_INCOMPLETE",
	"UNHANDLED_PROTOCOL",
	"CSUM_ERROR"
};

/*
 * Per-module structure.
 */
struct sfe_ipv4 {
	spinlock_t lock;		/* Lock for SMP correctness */
	struct sfe_ipv4_connection_match *active_head;
					/* Head of the list of recently active connections */
	struct sfe_ipv4_connection_match *active_tail;
					/* Tail of the list of recently active connections */
	struct sfe_ipv4_connection *all_connections_head;
					/* Head of the list of all connections */
	struct sfe_ipv4_connection *all_connections_tail;
					/* Tail of the list of all connections */
	unsigned int num_connections;	/* Number of connections */
	struct timer_list timer;	/* Timer used for periodic sync ops */
	sfe_sync_rule_callback_t __rcu sync_rule_callback;
					/* Callback function registered by a connection manager for stats syncing */
	struct sfe_ipv4_connection *conn_hash[SFE_IPV4_CONNECTION_HASH_SIZE];
					/* Connection hash table */
	struct sfe_ipv4_connection_match *conn_match_hash[SFE_IPV4_CONNECTION_HASH_SIZE];
					/* Connection match hash table */

	/*
	 * Stats recorded in a sync period. These stats will be added to
	 * connection_xxx64 after a sync period.
	 */
	u32 connection_create_requests;
					/* Number of IPv4 connection create requests */
	u32 connection_create_collisions;
					/* Number of IPv4 connection create requests that collided with existing hash table entries */
	u32 connection_destroy_requests;
					/* Number of IPv4 connection destroy requests */
	u32 connection_destroy_misses;
					/* Number of IPv4 connection destroy requests that missed our hash table */
	u32 connection_match_hash_hits;
					/* Number of IPv4 connection match hash hits */
	u32 connection_match_hash_reorders;
					/* Number of IPv4 connection match hash reorders */
	u32 connection_flushes;		/* Number of IPv4 connection flushes */
	u32 packets_forwarded;		/* Number of IPv4 packets forwarded */
	u32 packets_not_forwarded;	/* Number of IPv4 packets not forwarded */
	u32 exception_events[SFE_IPV4_EXCEPTION_EVENT_LAST];

	/*
	 * Summary statistics.
	 */
	u64 connection_create_requests64;
					/* Number of IPv4 connection create requests */
	u64 connection_create_collisions64;
					/* Number of IPv4 connection create requests that collided with existing hash table entries */
	u64 connection_destroy_requests64;
					/* Number of IPv4 connection destroy requests */
	u64 connection_destroy_misses64;
					/* Number of IPv4 connection destroy requests that missed our hash table */
	u64 connection_match_hash_hits64;
					/* Number of IPv4 connection match hash hits */
	u64 connection_match_hash_reorders64;
					/* Number of IPv4 connection match hash reorders */
	u64 connection_flushes64;	/* Number of IPv4 connection flushes */
	u64 packets_forwarded64;	/* Number of IPv4 packets forwarded */
	u64 packets_not_forwarded64;
					/* Number of IPv4 packets not forwarded */
	u64 exception_events64[SFE_IPV4_EXCEPTION_EVENT_LAST];

	/*
	 * Control state.
	 */
	struct kobject *sys_sfe_ipv4;	/* sysfs linkage */
	int debug_dev;			/* Major number of the debug char device */
	u32 debug_read_seq;	/* sequence number for debug dump */
};

/*
 * Enumeration of the XML output.
 */
enum sfe_ipv4_debug_xml_states {
	SFE_IPV4_DEBUG_XML_STATE_START,
	SFE_IPV4_DEBUG_XML_STATE_CONNECTIONS_START,
	SFE_IPV4_DEBUG_XML_STATE_CONNECTIONS_CONNECTION,
	SFE_IPV4_DEBUG_XML_STATE_CONNECTIONS_END,
	SFE_IPV4_DEBUG_XML_STATE_EXCEPTIONS_START,
	SFE_IPV4_DEBUG_XML_STATE_EXCEPTIONS_EXCEPTION,
	SFE_IPV4_DEBUG_XML_STATE_EXCEPTIONS_END,
	SFE_IPV4_DEBUG_XML_STATE_STATS,
	SFE_IPV4_DEBUG_XML_STATE_END,
	SFE_IPV4_DEBUG_XML_STATE_DONE
};

/*
 * XML write state.
 */
struct sfe_ipv4_debug_xml_write_state {
	enum sfe_ipv4_debug_xml_states state;
					/* XML output file state machine state */
	int iter_exception;		/* Next exception iterator */
};

struct sfe_ipv4_connection_match *sfe_ipv4_find_sfe_ipv4_connection_match(struct sfe_ipv4 *si_income,
	struct net_device *dev, unsigned int protocol, __be32 src_ip, __be16 src_port,
	__be32 dest_ip, __be16 dest_port);

