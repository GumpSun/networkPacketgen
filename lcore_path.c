#include <assert.h>
#include <stddef.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>


#include "main.h"
#include "common.h"
#include "lcore_path.h"
#include "pkt_info.h"
#include "reclaim_list.h"
#include "l2_switch.h"
#include "rule_chain.h"
#include "action.h"
#include "traffic.h"

//#define DEBUG	

/* 功能： 数据包解析
 * m: 数据包指针
 * return : 0 错误，1 直接发送(进默认channel)， 2 数据处理
 * */
static inline int
pkt_analysis(struct pkt_info *pkt_info)
{
	struct rte_mbuf *m = pkt_info->m;
	struct ether_hdr *eth = NULL;
	struct iphdr *ipv4_hdr = NULL; 
	struct tcp_hdr *tcp = NULL;
	struct udp_hdr *udp = NULL;
	unsigned int protocol;
	unsigned char *tmp;

	if (!m)
	{
		W_LOG("ERROR: can not find pkt pointer in pkt_info!\n");
		return 0;	
	}	

	eth =  rte_pktmbuf_mtod(m, struct ether_hdr *); //以太网包头
	
	//printf("src mac: %02x:%02x:%02x:%02x:%02x:%02x\n", ETH_ADDR(eth->s_addr));
	//printf("dst mac: %02x:%02x:%02x:%02x:%02x:%02x\n", ETH_ADDR(eth->d_addr));
	
	if(IS_MULTICAST_MAC(eth->d_addr))//多播地址
	{
		pkt_info->is_multicast_mac = 1;
		return 1;
	}
	
	pkt_info->eth = eth;
	rte_memcpy_func(pkt_info->src_mac, &(eth->s_addr), ETHER_ADDR_LEN);
	rte_memcpy_func(pkt_info->dst_mac, &(eth->d_addr), ETHER_ADDR_LEN);
	#ifdef MAC_LEARN
	mac_self_learn(pkt_info->lp->mac_map, pkt_info->src_mac, pkt_info->src_net_port); //MAC自学习
	#endif
	protocol = rte_be_to_cpu_16(eth->ether_type);

//	printf("protocol %x\n", protocol);	

	//获取IP包头
	switch (protocol)
	{
		case ETH_P_IP : //ip协议
			ipv4_hdr =  (struct iphdr *)(rte_pktmbuf_mtod(m, unsigned char *) + 
				sizeof(struct ether_hdr));
			 break;
		case ETH_P_8021Q : //vlan协议
			ipv4_hdr =  (struct iphdr *)(rte_pktmbuf_mtod(m, unsigned char *) + 
				sizeof(struct ether_hdr) + sizeof(struct vlan_hdr));
			break;
			//pppoe 协议
		case ETH_P_PPP_DISC : 
		case ETH_P_PPP_SES :
			tmp = (unsigned char *)((rte_pktmbuf_mtod(m, unsigned char *) + 
				sizeof(struct ether_hdr)) + 3);
			if (rte_be_to_cpu_16(*((uint16_t *)tmp)) == 0x0021)
				ipv4_hdr = (struct iphdr *)(tmp + 2);
			break;
		default : return 1;
				
	}
	
	//printf("src ip %d.%d.%d.%d\n", IP_ADDR(ipv4_hdr->saddr));
	//printf("dst ip %d.%d.%d.%d\n", IP_ADDR(ipv4_hdr->daddr));
	//printf("protocol %u\n", ipv4_hdr->protocol);

	pkt_info->ipv4_hdr = ipv4_hdr;
	protocol =  ipv4_hdr->protocol;
	pkt_info->key.tuple5.src_ip = ipv4_hdr->saddr;
	pkt_info->key.tuple5.dst_ip = ipv4_hdr->daddr;
	pkt_info->key.tuple5.protocol = protocol;
	//size = rte_be_to_cpu_16(ipv4_hdr->tot_len) + 14 + 24; 
	pkt_info->size = rte_pktmbuf_data_len(m);

	switch(protocol)
	{
		case 6: //tcp
			tcp = (struct tcp_hdr *)((unsigned char *) ipv4_hdr + (ipv4_hdr->ihl << 2));	
			pkt_info->key.tuple5.src_port = tcp->src_port;
			pkt_info->key.tuple5.dst_port = tcp->dst_port;
			return 2;
		case 17: //udp
			udp = (struct udp_hdr *)((unsigned char *) ipv4_hdr + (ipv4_hdr->ihl << 2));
			pkt_info->key.tuple5.src_port = udp->src_port;
			pkt_info->key.tuple5.dst_port = udp->dst_port;
			return 2;
		default:
			return 1;
	}

	//printf("src_port %u\n", rte_be_to_cpu_16(pkt_info->src_port));
	//printf("dst_port %u\n", rte_be_to_cpu_16(pkt_info->dst_port));

	return 1;	
}	




static inline void 
get_pkt_action_id(struct lcore_path *lp, struct pkt_info *pkt_info)
{
	struct rule *rule = NULL;

	if (!(rule = rule_chain_search(lp->rl_chain, &pkt_info->key, 1)))//需要修改 传入pkt_info->key
	{
		/*if we don't find it, so we put it into the default channel*/
		pkt_info->action_id = ENDCH;
		
	}	
	else
	{
		pkt_info->action_id = rule->action_id;
		pkt_info->r = rule;
	}	
}	

static struct rte_mbuf *
create_rte_mbuf(struct lcore_path *lp, uint8_t *pkt_buf, uint16_t pkt_len)
{
	struct rte_mbuf *m = NULL;
	struct ether_hdr *eth = NULL;
	//unsigned int protocol;
	int socketid;
	uint32_t lcore_id;
	int in_port;	

	if (pkt_len < 64)
	{
		W_LOG("share memory pkt is too small!\n");
		return NULL;
	}

	lcore_id = lp->lcore_id;
	if (numa_on)
		socketid = rte_lcore_to_socket_id(lcore_id);
	else
		socketid = 0;	
	m = rte_pktmbuf_alloc(pktmbuf_pool[socketid]);
	if (!m)
	{
		W_LOG("alloc pkt buf is error!\n");
		return NULL;
	}

	m->pkt.next = NULL;
	m->pkt.nb_segs = 1;
	m->pkt.pkt_len = pkt_len;
	m->pkt.data_len = pkt_len;

	eth = (struct ether_hdr *)pkt_buf; //以太网包头
	memcpy(m->pkt.data, eth, pkt_len);

	in_port = mac_to_net_id(lp->mac_map, eth->s_addr.addr_bytes);
	if (in_port < 0)
	{
		rte_pktmbuf_free(m);	
		return NULL;
	}
	m->pkt.in_port = in_port;
		
	//m->pkt.l2_len = sizeof(struct ether_hdr);
	//protocol = rte_be_to_cpu_16(eth->ether_type);

	//if (protocol == ETHER_TYPE_IPv4)
		//m->pkt.l3_len = sizeof(struct ipv4_hdr);

	return m;
}


static void 
free_mbuf_from_reclaim_list(void *data)
{
	rte_pktmbuf_free((struct rte_mbuf *)data);
}


static inline int 
pktmbuf_pool_full(struct rte_mempool * mp)
{
	uint32_t prod_tail = mp->ring->prod.tail;
	uint32_t cons_head = mp->ring->cons.head;
	return (prod_tail == cons_head);
}


static int
is_mbuf_in_reclaim_list(struct reclaim_list_head *head, struct reclaim_list_node *rln, struct rte_mbuf *m)
{
	return (is_in_reclaim_list(head, rln) && (void *)m == RLN_DATA(rln));
}



static inline void
fwd_shm_pkt(struct lcore_path *lp)
{
	
	int i;
	packet_t *pkt;
	struct pkt_info *pkt_info;
	struct ether_hdr *eth = NULL;
	struct reclaim_list_node *rln = NULL;
	struct rfphandle_config *rfphandle = &lp->rfphandle;
	uint8_t *frame;
	uint64_t action_type;

	
	//底层上传到共享内存中的数据包的转发
	for (i = 0; i < rfphandle ->minor; i++)
	{
		while (1)
		{
			if((pkt = rfp_recv_packet(rfphandle->handle[i])) == NULL)
				break;

			pkt_info = pktinfo_malloc(&lp->pip);
			memset(pkt_info, 0, offsetof(struct pkt_info, lp));
			
			rfp_get_frame_info(pkt, &frame, &pkt_info->size, &action_type,
				(void **)&pkt_info->m, (void **)&rln);
		#ifdef TAILQ
			if (! is_mbuf_in_reclaim_list(lp->m_rlh, rln, pkt_info->m))
			{	
				pkt_info->m = create_rte_mbuf(lp, frame, pkt_info->size);
				if (!pkt_info->m)
				{
					rfp_drop_pakcet(rfphandle->handle[i], pkt);
					continue;
				}
			}
			else
				remove_reclaim_list(lp->m_rlh, rln,NULL);
		#endif

			//获取数据包其他信息
			eth = rte_pktmbuf_mtod(pkt_info->m, struct ether_hdr *);
			rte_memcpy_func(pkt_info->src_mac, &(eth->s_addr), ETHER_ADDR_LEN);
			rte_memcpy_func(pkt_info->dst_mac, &(eth->d_addr), ETHER_ADDR_LEN);
			pkt_info->src_net_port = pkt_info->m->pkt.in_port;
			pkt_info->flag = 0;			//for temp
			pkt_info->action_id = ENDCH;

			rfp_drop_pakcet(rfphandle->handle[i], pkt);
			execute_action(&lp->actvec, pkt_info); //直接入channel
			
		}
	}
	
	

}



/* Send burst of packets on an output interface */
static inline int
send_burst(struct lcore_conf *qconf, uint16_t n, uint8_t port)
{
	struct rte_mbuf **m_table;
	int ret;
	uint16_t queueid;

	queueid = qconf->tx_queue_id[port];
	m_table = (struct rte_mbuf **)qconf->tx_mbufs[port].m_table;

	ret = rte_eth_tx_burst(port, queueid, m_table, n);
	if (unlikely(ret < n)) {
		do {
			printf("drop pkt!\n");
			rte_pktmbuf_free(m_table[ret]);
		} while (++ret < n);
	}

	return 0;
}

/* Enqueue a single packet, and send burst if queue is filled */
static inline int
send_single_packet(struct lcore_path *lp, struct rte_mbuf *m, uint8_t port)
{
	//uint32_t lcore_id;
	uint16_t len;
	struct lcore_conf *qconf;

	qconf = lp->qconf;
	len = qconf->tx_mbufs[port].len;
	qconf->tx_mbufs[port].m_table[len] = m;
	len++;

	/* enough pkts to be sent */
	if (unlikely(len == MAX_PKT_BURST)) {
		send_burst(qconf, MAX_PKT_BURST, port);
		len = 0;
	}

	qconf->tx_mbufs[port].len = len;
	return 0;
}

/* 功能：广播
 * lp: 核数据
 * m：数据包
 * dev_id: 源网口id
 * */
static inline void 
send_flood_packet(struct lcore_path *lp, struct rte_mbuf *m, uint16_t dev_id)
{
	unsigned int i;
	struct rte_mbuf *clone_m = NULL;
	struct rte_eth_link link;
	int socketid;
	
	
	if (dev_id >= nb_ports)
	{
		rte_pktmbuf_free(m);
		return ;
	}	
	
	for (i = 0; i < nb_ports; i++)
	{
		if (enabled_port_mask && (enabled_port_mask & 1 << i) == 0)
			continue;
	
		if(i == dev_id)
			continue;

		rte_eth_link_get_nowait((uint8_t) i, &link);
		if (!link.link_status) 
			continue;

	if (numa_on)
		socketid = rte_lcore_to_socket_id(lp->lcore_id);
	else
		socketid = 0;	
	
		clone_m = rte_pktmbuf_clone (m, pktmbuf_pool[socketid]);
		if (clone_m)
			send_single_packet(lp, clone_m, (uint8_t)i);	
	}
	
	rte_pktmbuf_free(m);	
}



static inline /*__attribute__((always_inline))*/
void simple_forward(struct lcore_path *lp, struct rte_mbuf *m, unsigned portid )
{
#ifdef DEBUG
	struct ether_hdr *eth;
			eth =  rte_pktmbuf_mtod(m, struct ether_hdr *); //以太网包头	
			printf("src mac: %02x:%02x:%02x:%02x:%02x:%02x\n", ETH_ADDR(eth->s_addr));
			printf("dst mac: %02x:%02x:%02x:%02x:%02x:%02x\n", ETH_ADDR(eth->d_addr));
			//printf("protocol: %x\n", ntohs(eth->ether_type));
			printf("\n");
#endif


	struct pkt_info *pkt_info;
	int ret;

	pkt_info = pktinfo_malloc(&lp->pip);
	memset(pkt_info, 0, offsetof(struct pkt_info, lp));

	
	pkt_info->m = m;
	pkt_info->src_net_port = portid;

	ret = pkt_analysis(pkt_info); //数据包解析
	switch (ret)
	{
		case 0 : 
			return ;
		case 1 :
			pkt_info->action_id = ENDCH;
			break;
		case 2 :
			#ifdef ACTION_MATCH
			get_pkt_action_id(lp, pkt_info); //获取channel id
			#endif
			#ifdef RSS_MODULE
			//get_pkt_shm_id(&pkt_info);
			#endif
			break;
		default :    //when will we come here?
			return ;
	}

	execute_action(&lp->actvec, pkt_info);
}

void 
send_lp_queue(struct pkt_info *pkt_info)
{
	struct lcore_path *lp = pkt_info->lp;
	uint8_t protocol = pkt_info->key.tuple5.protocol;
	int dst_dev_id;

	//链接速度统计
	if ((protocol == 6 || protocol == 17) && pkt_info->r)
	{
		update_rate_info(&pkt_info->r->rate, pkt_info->size);
	}
	
	#ifdef PF_RING_TEST
	#if 0
		if ((dst_dev_id = mac_to_net_id(lp->mac_map, pkt_info->dst_mac)) == (uint8_t)-1)
				dst_dev_id = 5;
	#endif
		if (pkt_info->src_net_port == 7)
			dst_dev_id = 5;
		else
			dst_dev_id = 7;
		send_single_packet(lp, pkt_info->m, dst_dev_id); //发送
		
	#else
		if (pkt_info->is_multicast_mac || (dst_dev_id = mac_to_net_id(lp->mac_map, pkt_info->dst_mac)) < 0)
				send_flood_packet(lp, pkt_info->m, pkt_info->src_net_port); //广播发送
		else	
			send_single_packet(lp, pkt_info->m, dst_dev_id); //发送
	#endif	
}


struct lcore_path *
lcore_path_create(struct lcore_conf *qconf, uint32_t lcore_id, uint16_t major, uint16_t minor)
{
	assert(qconf);
	
	struct lcore_path *lp;
	struct lcore_path_info *lp_info;
	int minor_i;
	lp = calloc(1, sizeof(*lp));
	if(!lp)
	{
		printf("malloc error!\n");
		return NULL;
	}

	lp_info = calloc(1, sizeof(struct lcore_path_info));
	if (!lp_info)
	{
		printf("malloc error!\n");
		goto error_malloc;
	}
	lp_info->lcore_id = lcore_id;
	lp_info->lp = lp;
	lp_info->lcore_path_id = major;
	lcore_paths[lcore_id] = lp_info;
	

	for(minor_i = 0; minor_i < minor; minor_i ++)
	{
		desc_t descriptor = MKDESCPTOR(major, minor_i);
		lp->rfphandle.handle[minor_i]= rfp_open(descriptor);
		if(!lp->rfphandle.handle[minor_i])
		{
			printf("rfp_open error!\n");
			goto error_rfp_open;
		}
	}
	lp->rfphandle.major = major;
	lp->rfphandle.minor = minor;
	
	lp->rl_chain= rule_chain_create();
	if(!lp->rl_chain)
	{
		printf("chain_new error!\n");
		goto error_chain_new;
	}

	lp->mac_map = mac_map_create();
	if(!lp->mac_map)
	{
		printf("mac_map_create error!\n");
		goto error_mac_map_create;
	}

	if (create_reclaim_list(&lp->m_rlh, 0))
	{
		printf("create_reclaim_list error!\n");
		goto error_create_reclaim_list;
	}

	if(channel_vector_init(lp, &lp->chnvec) == -1)
	{
		printf("channel_vector_init error!\n");
		goto error_channel_vector_init;
	}

	if(action_vector_init(&lp->actvec, &lp->chnvec) == -1)
	{
		printf("action_vector_init error!\n");
		goto error_action_vector_init;
	}

	if(pktinfo_pool_init(lp, &lp->pip, MAX_PKTINFO) < 0)
	{
		printf("pktinfo_pool_init error!\n");
		goto error_pktinfo_pool_init;
	}

	lp->qconf = qconf;
	lp->lcore_id = lcore_id;

	return lp;
		
	error_pktinfo_pool_init:
		action_vector_destroy_action(&lp->actvec);
	error_action_vector_init:	
		channle_vector_destory_channel(&lp->chnvec);
	error_channel_vector_init:
		destory_reclaim_list(lp->m_rlh);
	error_create_reclaim_list:
		mac_map_destroy(lp->mac_map);
	error_mac_map_create:
		rule_chain_destroy(lp->rl_chain);	
	error_chain_new:
		for(minor_i = 0; minor_i < RTE_MAX_LCORE; minor_i++)
		{
			if(lp->rfphandle.handle[minor_i])
				rfp_close(lp->rfphandle.handle[minor_i]);
		}
	error_rfp_open:
		free(lp_info);
	error_malloc:
		free(lp);
		return NULL;	
}






void 
lcore_path_run(struct lcore_path *lp)
{
	struct lcore_conf *qconf = lp->qconf;
	//struct rte_mbuf *m,;
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct pkt_info *pkt_info;
	uint64_t prev_tsc = 0, diff_tsc, cur_tsc;
	unsigned i, j, nb_rx;
	uint8_t portid, queueid;
	struct channel_vector *chnvec = &lp->chnvec; //we only init this once
	#ifndef CHANNEL_USE_LIST_MANAGE
	struct channel ***ch_tc = lp->chnvec.ch_tc;         //we only init this once
	#endif
 	static struct channel *ch;
	//static uint8_t dst_dev_id;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;
	int socketid;

	if (numa_on)
		socketid = rte_lcore_to_socket_id(lp->lcore_id);
	else
		socketid = 0;	
	
	qconf = lp->qconf;
	
	/*RX packet*/
	//RX packet from RX queues
	for (i = 0; i < qconf->n_rx_queue; ++i) 
	{
		portid = qconf->rx_queue_list[i].port_id;
		queueid = qconf->rx_queue_list[i].queue_id;
		nb_rx = rte_eth_rx_burst(portid, queueid, pkts_burst, MAX_PKT_BURST);

		#if 0
		/* Prefetch first packets */
		for (j = 0; j < PREFETCH_OFFSET && j < nb_rx; j++) {
			rte_prefetch0(rte_pktmbuf_mtod(
					pkts_burst[j], void *));
		}

		/* Prefetch and forward already prefetched packets */
		for (j = 0; j < (nb_rx - PREFETCH_OFFSET); j++) {
			rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[
					j + PREFETCH_OFFSET], void *));
			simple_forward(lp, pkts_burst[j], portid); //转发处理
		}

		/* Forward remaining prefetched packets */
		for (; j < nb_rx; j++) 
		{
			simple_forward(lp, pkts_burst[j], portid); //转发处理
		}
		#endif
		for (j = 0; j < nb_rx; j++)
		{
			simple_forward(lp, pkts_burst[j], portid); //转发处理
		}
	}
	//RX packet form share memory queue
	fwd_shm_pkt(lp);


	#ifdef TAILQ
	if (pktmbuf_pool_full(pktmbuf_pool[socketid]))
		remove_n_from_reclaim_list_head(lp->m_rlh, MAX_PKT_BURST * qconf->n_rx_queue, free_mbuf_from_reclaim_list);
	#endif


	
	// TX packet
	//放到核的缓冲上
	#ifdef CHANNEL_USE_LIST_MANAGE
	LIST_FOR_EACH(ch, struct channel, node, &chnvec->head)  
	#else
	for(i = 0; i < chnvec->tc_num; ++i)
	#endif
	{
		#ifndef CHANNEL_USE_LIST_MANAGE
		ch = *ch_tc[i];
		#endif
		while(ch->get(ch, &pkt_info) == 0)  //we succeed to get a packet
		{	
			#if 0
			#ifdef PF_RING_TEST
			if ((dst_dev_id = mac_to_net_id(lp->mac_map, pkt_info->dst_mac)) == (uint8_t)-1)
					dst_dev_id = 5;
			send_single_packet(lp, pkt_info->m, dst_dev_id); //发送
			#else
			if (pkt_info->is_multicast_mac || (dst_dev_id = mac_to_net_id(lp->mac_map, pkt_info->dst_mac)) < 0)
					send_flood_packet(lp, pkt_info->m, pkt_info->src_net_port); //广播发送
			else	
				send_single_packet(lp, pkt_info->m, dst_dev_id); //发送
			#endif	

			//
			pktinfo_free(pkt_info);    //Don't forget to do this
			#endif
			send_lp_queue(pkt_info);
			pktinfo_free(pkt_info); 
		}
	}
	
	//从核缓冲中发送到网卡队列上
	cur_tsc = rte_rdtsc();
	diff_tsc = cur_tsc - prev_tsc;
	if (unlikely(diff_tsc > drain_tsc)) 
	{
		/*
		 * This could be optimized (use queueid instead of
		 * portid), but it is not called so often
		 */
		for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
			if (qconf->tx_mbufs[portid].len == 0)
				continue;
			send_burst(qconf, qconf->tx_mbufs[portid].len, portid);
			qconf->tx_mbufs[portid].len = 0;
		}

		prev_tsc = cur_tsc;
	}
}




int32_t 
insert_rule_to_lcore(struct lcore_path *lp, struct rule *rule)
{
	return rule_chain_insert(lp->rl_chain, rule); 
}

int32_t remove_rule_from_lcore(struct lcore_path *lp, struct rule_key *key, uint32_t priority, int32_t strict)
{ 
	return rule_chain_remove(lp->rl_chain, key, priority, strict);
}

void clear_chain_from_lcore(struct lcore_path *lp)
{
	rule_chain_remove_expired(lp->rl_chain);
}

void clear_mac_map_from_lcore(struct lcore_path *lp)
{
	clean_mac_map(lp->mac_map);
}

uint64_t traffic_query_from_lcore(struct lcore_path *lp, struct rule_key *key)
{
	return traffic_query(lp->rl_chain, key);
}

