/* Supernode for n2n-2.x */

/* (c) 2009 Richard Andrews <andrews@ntop.org> 
 *
 * Contributions by:
 *    Lukasz Taczuk
 *    Struan Bartlett
 */

//#include <Shlwapi.h> 
//#pragma comment(lib,"Shlwapi.lib")

#include "n2n.h"

#ifdef  N2N_MULTIPLE_SUPERNODES
#include "sn_multiple.h"
#endif

#define N2N_SN_LPORT_DEFAULT 7654
#define N2N_SN_PKTBUF_SIZE   2048

#define N2N_SN_MGMT_PORT                5645


struct sn_stats
{
    size_t errors;              /* Number of errors encountered.遇到的错误数量 */
    size_t reg_super;           /* Number of REGISTER_SUPER requests received. 收到的REGISTER_SUPER请求数*/
    size_t reg_super_nak;       /* Number of REGISTER_SUPER requests declined. 拒绝的REGISTER_SUPER请求数*/
    size_t fwd;                 /* Number of messages forwarded. 转发的消息数量*/
    size_t broadcast;           /* Number of messages broadcast to a community.向社区广播的消息数量 */
    time_t last_fwd;            /* Time when last message was forwarded.最后一条消息被转发的时间 */
    time_t last_reg_super;      /* Time when last REGISTER_SUPER was received.接收到最后一个REGISTER_SUPER的时间。*/
};

typedef struct sn_stats sn_stats_t;

struct n2n_sn
{
    time_t              start_time;     /* Used to measure uptime. 用于测量正常运行时间。*/
    sn_stats_t          stats;
    int                 daemon;         /* If non-zero then daemonise. 如果非零，那么守护进程。*/
    uint16_t            lport;          /* Local UDP port to bind to.本地UDP端口绑定。 */
    int                 sock;           /* Main socket for UDP traffic with edges. 用于具有边缘的UDP流量的主要套接字。*/
    int                 mgmt_sock;      /* management socket.管理套接字 */
#ifdef N2N_MULTIPLE_SUPERNODES
    uint8_t             snm_discovery_state;
    int                 sn_port;
    int                 sn_sock;        /* multiple supernodes socket 多个超级节点套接字*/
    unsigned int        seq_num;        /* sequence number for SN communication SN通信的序列号*/
    sn_list_t           supernodes;
    comm_list_t         communities;
#endif
    struct peer_info *  edges;          /* Link list of registered edges. 注册边缘的链接列表。*/
};

typedef struct n2n_sn n2n_sn_t;


static int try_forward( n2n_sn_t * sss, 
                        const n2n_common_t * cmn,
                        const n2n_mac_t dstMac,
                        const uint8_t * pktbuf,
                        size_t pktsize );

static int try_broadcast( n2n_sn_t * sss, 
                          const n2n_common_t * cmn,
                          const n2n_mac_t srcMac,
                          const uint8_t * pktbuf,
                          size_t pktsize );



/** Initialise the supernode structure初始化超级节点结构 */
static int init_sn( n2n_sn_t * sss )
{
#ifdef WIN32
    initWin32();
#endif
    memset( sss, 0, sizeof(n2n_sn_t) );

    sss->daemon = 1; /* By defult run as a daemon.默认情况下作为守护进程运行。 */
    sss->lport = N2N_SN_LPORT_DEFAULT;
    sss->sock = -1;
    sss->mgmt_sock = -1;
    sss->edges = NULL;

#ifdef N2N_MULTIPLE_SUPERNODES
    sss->snm_discovery_state = N2N_SNM_STATE_DISCOVERY;
    sss->sn_sock = -1;
    sss->seq_num = -1;
    memset(&sss->supernodes, 0, sizeof(sn_list_t));
    memset(&sss->communities, 0, sizeof(comm_list_t));
#endif

    return 0; /* OK */
}

/** Deinitialise the supernode structure and deallocate any memory owned by
 *  it. 取消初始化超级节点的结构并释放所拥有的所有内存*/
static void deinit_sn( n2n_sn_t * sss )
{
    if (sss->sock >= 0)
    {
        closesocket(sss->sock);
    }
    sss->sock=-1;

    if ( sss->mgmt_sock >= 0 )
    {
        closesocket(sss->mgmt_sock);
    }
    sss->mgmt_sock=-1;

    purge_peer_list( &(sss->edges), 0xffffffff );

#ifdef N2N_MULTIPLE_SUPERNODES
    if (sss->sn_sock)
    {
        closesocket(sss->sn_sock);
    }
    sss->seq_num = -1;
    clear_sn_list(&sss->supernodes.list_head);
    clear_comm_list(&sss->communities.list_head);
#endif
}


/** Determine the appropriate lifetime for new registrations.
 *
 *  If the supernode has been put into a pre-shutdown phase then this lifetime
 *  should not allow registrations to continue beyond the shutdown point.
 */
static uint16_t reg_lifetime( n2n_sn_t * sss )
{
    return 120;
}


/** Update the edge table with the details of the edge which contacted the
 *  supernode.更新超级节点的边沿表 */
static int update_edge( n2n_sn_t * sss, 
                        const n2n_mac_t edgeMac,
                        const n2n_community_t community,
                        const n2n_sock_t * sender_sock,
                        time_t now)
{
    macstr_t            mac_buf;
    n2n_sock_str_t      sockbuf;
    struct peer_info *  scan;

    traceEvent( TRACE_DEBUG, "update_edge for %s [%s]",
                macaddr_str( mac_buf, edgeMac ),
                sock_to_cstr( sockbuf, sender_sock ) );

    scan = find_peer_by_mac( sss->edges, edgeMac );//在mac_addr等于mac的列表中找到对等项

    if ( NULL == scan )//没找到向列表添加
    {
        /* Not known */

        scan = (struct peer_info*)calloc(1, sizeof(struct peer_info)); /* deallocated in purge_expired_registrations */

        memcpy(scan->community_name, community, sizeof(n2n_community_t) );//社区名称
        memcpy(&(scan->mac_addr), edgeMac, sizeof(n2n_mac_t));//节点MAC地址
        memcpy(&(scan->sock), sender_sock, sizeof(n2n_sock_t));//和节点通信的套接字

        /* insert this guy at the head of the edges list 将这个人插入边缘列表的头部 */
        scan->next = sss->edges;     /* first in list首先在列表中 */
        sss->edges = scan;           /* head of list points to new scan 列表头指向新的扫描 */

        traceEvent( TRACE_INFO, "update_edge created   %s ==> %s",
                    macaddr_str( mac_buf, edgeMac ),
                    sock_to_cstr( sockbuf, sender_sock ) );
    }
    else //找到
    {
        /* Known */
        if ( (0 != memcmp(community, scan->community_name, sizeof(n2n_community_t))) ||
             (0 != sock_equal(sender_sock, &(scan->sock) )) ) //如果社区名称不同或者两个套接字不相等 
        {
            memcpy(scan->community_name, community, sizeof(n2n_community_t) );//更新社区名称
            memcpy(&(scan->sock), sender_sock, sizeof(n2n_sock_t));//更新套接字

            traceEvent( TRACE_INFO, "update_edge updated   %s ==> %s",
                        macaddr_str( mac_buf, edgeMac ),
                        sock_to_cstr( sockbuf, sender_sock ) );
        }
        else
        {
            traceEvent( TRACE_DEBUG, "update_edge unchanged %s ==> %s",
                        macaddr_str( mac_buf, edgeMac ),
                        sock_to_cstr( sockbuf, sender_sock ) );
        }

    }

    scan->last_seen = now;//更新时间
    return 0;
}


/** Send a datagram to the destination embodied in a n2n_sock_t.
 *
 *  @return -1 on error otherwise number of bytes sent
 */
static ssize_t sendto_sock(/*n2n_sn_t * sss,*/
                           int sock_fd,
                           const n2n_sock_t * sock, 
                           const uint8_t * pktbuf, 
                           size_t pktsize)
{
    n2n_sock_str_t      sockbuf;

    if ( AF_INET == sock->family )
    {
        struct sockaddr_in udpsock;

        udpsock.sin_family = AF_INET;
        udpsock.sin_port = htons( sock->port );
        memcpy( &(udpsock.sin_addr.s_addr), &(sock->addr.v4), IPV4_SIZE );

        traceEvent( TRACE_DEBUG, "sendto_sock %lu to [%s]",
                    pktsize,
                    sock_to_cstr( sockbuf, sock ) );

        return sendto( /*sss->sock*/sock_fd, pktbuf, pktsize, 0,
                       (const struct sockaddr *)&udpsock, sizeof(struct sockaddr_in) );
    }
    else
    {
        /* AF_INET6 not implemented */
        errno = EAFNOSUPPORT;
        return -1;
    }
}



/** Try to forward a message to a unicast MAC. If the MAC is unknown then
 *  broadcast to all edges in the destination community.
 */
static int try_forward( n2n_sn_t * sss, 
                        const n2n_common_t * cmn,
                        const n2n_mac_t dstMac,
                        const uint8_t * pktbuf,
                        size_t pktsize )
{
    struct peer_info *  scan;
    macstr_t            mac_buf;
    n2n_sock_str_t      sockbuf;

    scan = find_peer_by_mac( sss->edges, dstMac );

    if ( NULL != scan )
    {
        int data_sent_len;
        data_sent_len = sendto_sock( sss->sock, &(scan->sock), pktbuf, pktsize );

        if ( data_sent_len == pktsize )
        {
            ++(sss->stats.fwd);
            traceEvent(TRACE_DEBUG, "unicast %lu to [%s] %s",
                       pktsize,
                       sock_to_cstr( sockbuf, &(scan->sock) ),
                       macaddr_str(mac_buf, scan->mac_addr));
        }
        else
        {
            ++(sss->stats.errors);
            traceEvent(TRACE_ERROR, "unicast %lu to [%s] %s FAILED (%d: %s)",
                       pktsize,
                       sock_to_cstr( sockbuf, &(scan->sock) ),
                       macaddr_str(mac_buf, scan->mac_addr),
                       errno, strerror(errno) );
        }
    }
    else
    {
        traceEvent( TRACE_DEBUG, "try_forward unknown MAC" );

        /* Not a known MAC so drop. */
    }
    
    return 0;
}


/** Try and broadcast a message to all edges in the community.
 *
 *  This will send the exact same datagram to zero or more edges registered to
 *  the supernode.
 */
static int try_broadcast( n2n_sn_t * sss, 
                          const n2n_common_t * cmn,
                          const n2n_mac_t srcMac,
                          const uint8_t * pktbuf,
                          size_t pktsize )
{
    struct peer_info *  scan;
    macstr_t            mac_buf;
    n2n_sock_str_t      sockbuf;

    traceEvent( TRACE_DEBUG, "try_broadcast" );

    scan = sss->edges;
    while(scan != NULL) 
    {
        if( 0 == (memcmp(scan->community_name, cmn->community, sizeof(n2n_community_t)) )
            && (0 != memcmp(srcMac, scan->mac_addr, sizeof(n2n_mac_t)) ) )
            /* REVISIT: exclude if the destination socket is where the packet came from. */
        {
            int data_sent_len;
          
            data_sent_len = sendto_sock(sss->sock, &(scan->sock), pktbuf, pktsize);

            if(data_sent_len != pktsize)
            {
                ++(sss->stats.errors);
                traceEvent(TRACE_WARNING, "multicast %lu to [%s] %s failed %s",
                           pktsize,
                           sock_to_cstr( sockbuf, &(scan->sock) ),
                           macaddr_str(mac_buf, scan->mac_addr),
                           strerror(errno));
            }
            else 
            {
                ++(sss->stats.broadcast);
                traceEvent(TRACE_DEBUG, "multicast %lu to [%s] %s",
                           pktsize,
                           sock_to_cstr( sockbuf, &(scan->sock) ),
                           macaddr_str(mac_buf, scan->mac_addr));
            }
        }

        scan = scan->next;
    } /* while */
    
    return 0;
}


static int process_mgmt( n2n_sn_t * sss, 
                         const struct sockaddr_in * sender_sock,
                         const uint8_t * mgmt_buf, 
                         size_t mgmt_size,
                         time_t now)
{
    char resbuf[N2N_SN_PKTBUF_SIZE];
    size_t ressize=0;
    ssize_t r;

    traceEvent( TRACE_DEBUG, "process_mgmt" );

    ressize += snprintf( resbuf+ressize, N2N_SN_PKTBUF_SIZE-ressize, 
                         "----------------\n" );

    ressize += snprintf( resbuf+ressize, N2N_SN_PKTBUF_SIZE-ressize, 
                         "uptime    %lu\n", (now - sss->start_time) );

    ressize += snprintf( resbuf+ressize, N2N_SN_PKTBUF_SIZE-ressize, 
                         "edges     %u\n", 
			 (unsigned int)peer_list_size( sss->edges ) );

    ressize += snprintf( resbuf+ressize, N2N_SN_PKTBUF_SIZE-ressize, 
                         "errors    %u\n", 
			 (unsigned int)sss->stats.errors );

    ressize += snprintf( resbuf+ressize, N2N_SN_PKTBUF_SIZE-ressize, 
                         "reg_sup   %u\n", 
			 (unsigned int)sss->stats.reg_super );

    ressize += snprintf( resbuf+ressize, N2N_SN_PKTBUF_SIZE-ressize, 
                         "reg_nak   %u\n", 
			 (unsigned int)sss->stats.reg_super_nak );

    ressize += snprintf( resbuf+ressize, N2N_SN_PKTBUF_SIZE-ressize, 
                         "fwd       %u\n",
			 (unsigned int) sss->stats.fwd );

    ressize += snprintf( resbuf+ressize, N2N_SN_PKTBUF_SIZE-ressize, 
                         "broadcast %u\n",
			 (unsigned int) sss->stats.broadcast );

    ressize += snprintf( resbuf+ressize, N2N_SN_PKTBUF_SIZE-ressize, 
                         "last fwd  %lu sec ago\n", 
			 (long unsigned int)(now - sss->stats.last_fwd) );

    ressize += snprintf( resbuf+ressize, N2N_SN_PKTBUF_SIZE-ressize, 
                         "last reg  %lu sec ago\n",
			 (long unsigned int) (now - sss->stats.last_reg_super) );


    r = sendto( sss->mgmt_sock, resbuf, ressize, 0/*flags*/, 
                (struct sockaddr *)sender_sock, sizeof(struct sockaddr_in) );

    if ( r <= 0 )
    {
        ++(sss->stats.errors);
        traceEvent( TRACE_ERROR, "process_mgmt : sendto failed. %s", strerror(errno) );
    }

    return 0;
}

#ifdef N2N_MULTIPLE_SUPERNODES

static int load_snm_info(n2n_sn_t *sss)
{
    int new_ones = 0;
    struct sn_info *p = NULL;

    /* load supernodes */
    struct sn_info *cmd_line_list  = sss->supernodes.list_head;
    sss->supernodes.list_head = NULL;

    sprintf(sss->supernodes.filename, "SN_SNM_%d", sss->sn_port);
    if (read_sn_list_from_file( sss->supernodes.filename,
                               &sss->supernodes.list_head))
    {
        traceEvent(TRACE_ERROR, "Failed to open supernodes file. %s", strerror(errno));
        return -1;
    }

    /* check if we had some new supernodes before reading from file */

    p = cmd_line_list;
    while (p)
    {
        new_ones += update_supernodes(&sss->supernodes, &p->sn);
        p = p->next;
    }
    clear_sn_list(&cmd_line_list);

    if (new_ones)
    {
        write_sn_list_to_file(sss->supernodes.filename,
                              sss->supernodes.list_head);
    }

    /* load communities */
    sprintf(sss->communities.filename, "SN_COMM_%d", sss->sn_port);
    if (read_comm_list_from_file( sss->communities.filename,
                                 &sss->communities.persist))
    {
        traceEvent(TRACE_ERROR, "Failed to open communities file. %s", strerror(errno));
        return -1;
    }

    if (sn_list_size(sss->supernodes.list_head) == 0)    /* first running supernode */
    {
        sss->snm_discovery_state = N2N_SNM_STATE_READY;
    }

    return 0;
}


static void send_snm_adv(n2n_sn_t *sss, n2n_sock_t *sn, struct comm_info *comm_list);

static void advertise_all(n2n_sn_t *sss)
{
    struct sn_info *p = sss->supernodes.list_head;
    while (p && sss->communities.list_head)
    {
        send_snm_adv(sss, &p->sn, sss->communities.list_head);
        p = p->next;
    }
}

static void advertise_community_to_all(n2n_sn_t *sss, const n2n_community_t community)
{
    struct sn_info *p = NULL;
    struct comm_info ci;

    memset(&ci, 0, sizeof(struct comm_info));
    memcpy(ci.community_name, community, sizeof(n2n_community_t));

    p = sss->supernodes.list_head;

    while (p)
    {
        send_snm_adv(sss, &p->sn, &ci);
        p = p->next;
    }
}

static void communities_discovery(n2n_sn_t *sss, time_t nowTime)
{
    if (nowTime - sss->start_time < N2N_SUPER_DISCOVERY_INTERVAL)
    {
        return;
    }

    if (sss->snm_discovery_state == N2N_SNM_STATE_DISCOVERY)
    {
        struct comm_info *tmp_list = sss->communities.list_head;   /* queried communities */
        int comm_num = comm_list_size(sss->communities.persist);

        /* add new communities */
        struct comm_info *p = tmp_list;

        sss->communities.list_head = sss->communities.persist;

        while (comm_num < N2N_MAX_COMM_PER_SN && p != NULL)
        {
            if (p->sn_num < N2N_MIN_SN_PER_COMM)
            {
                /* add new community without setting supernodes */
                if (add_new_community(&sss->communities, p->community_name, NULL))
                    comm_num++;
            }

            p = p->next;
        }
        clear_comm_list(&tmp_list);

        /* send ADV to all */
        advertise_all(sss);

        sss->snm_discovery_state = N2N_SNM_STATE_READY;
    }
}

static void send_snm_req(n2n_sn_t         *sss,
                         n2n_sock_t       *sn,
                         int               req_communities,
                         snm_comm_name_t  *communities,
                         int               communities_num)
{
    uint8_t pktbuf[N2N_PKT_BUF_SIZE];
    size_t idx;
    n2n_sock_str_t sockbuf;
    snm_hdr_t hdr = { SNM_TYPE_REQ_LIST_MSG, 0, ++sss->seq_num };
    n2n_SNM_REQ_t req = { 0, NULL };

    if (sn_is_loopback(sn, sss->sn_port))
        return;

    SET_S(hdr.flags);

    if (req_communities)
    {
        SET_C(hdr.flags);
    }
    else if (communities)
    {
        SET_N(hdr.flags);
        req.comm_num = communities_num & 0xFFFF;
        req.comm_ptr = communities;
    }

    idx = 0;
    encode_SNM_REQ(pktbuf, &idx, &hdr, &req);

    traceEvent(TRACE_INFO, "send SNM_REQ to %s", sock_to_cstr(sockbuf, sn));

    sendto_sock(sss->sn_sock, sn, pktbuf, idx);
}

static void send_req_to_all_supernodes(n2n_sn_t         *sss,
                                       int               req_communities,
                                       snm_comm_name_t  *communities,
                                       int               communities_num)
{
    struct sn_info *sni = sss->supernodes.list_head;

    while (sni)
    {
        /* check what's new */
        send_snm_req(sss, &sni->sn, req_communities, communities, communities_num);
        sni = sni->next;
    }
}

static void send_snm_rsp(n2n_sn_t *sss, const n2n_sock_t *sock, snm_hdr_t *hdr, n2n_SNM_REQ_t *req)
{
    n2n_sock_str_t sock_buf;
    uint8_t pktbuf[N2N_PKT_BUF_SIZE];
    size_t  idx;
    snm_hdr_t rsp_hdr;
    n2n_SNM_INFO_t rsp;

    build_snm_info(sss->sock, &sss->supernodes, &sss->communities, hdr, req, &rsp_hdr, &rsp);

    idx = 0;
    encode_SNM_INFO(pktbuf, &idx, &rsp_hdr, &rsp);

    traceEvent(TRACE_INFO, "send SNM_RSP to %s", sock_to_cstr(sock_buf, sock));
    log_SNM_INFO(&rsp);

    clear_snm_info(&rsp);

    sendto_sock(sss->sn_sock, sock, pktbuf, idx);
}

static void send_snm_adv(n2n_sn_t *sss, n2n_sock_t *sn, struct comm_info *comm_list)
{
    uint8_t pktbuf[N2N_PKT_BUF_SIZE];
    size_t idx;
    n2n_sock_str_t sockbuf;
    snm_hdr_t hdr;
    n2n_SNM_ADV_t adv;

    if (sn_is_loopback(sn, sss->sn_port))
        return;

    build_snm_adv(sss->sock, comm_list, &hdr, &adv);

    if (sss->snm_discovery_state != N2N_SNM_STATE_READY)
        SET_A(hdr.flags);

    idx = 0;
    encode_SNM_ADV(pktbuf, &idx, &hdr, &adv);

    traceEvent(TRACE_INFO, "send ADV to %s", sock_to_cstr(sockbuf, sn));
    log_SNM_ADV(&adv);

    sendto_sock(sss->sn_sock, sn, pktbuf, idx);
}

static int process_sn_msg( n2n_sn_t *sss,
                           const struct sockaddr_in *sender_sock,
                           const uint8_t *msg_buf,
                           size_t msg_size,
                           time_t now)
{
    snm_hdr_t           hdr; /* common fields in the packet header */
    size_t              rem;
    size_t              idx;
    size_t              msg_type;
    n2n_sock_t          sender_sn;


    traceEvent( TRACE_DEBUG, "process_sn_msg(%lu)", msg_size );

    sn_cpy(&sender_sn, (const n2n_sock_t *) sender_sock);
    sender_sn.port = htons(sender_sn.port);

    rem = msg_size; /* Counts down bytes of packet to protect against buffer overruns. */
    idx = 0; /* marches through packet header as parts are decoded. */
    if (decode_SNM_hdr(&hdr, msg_buf, &rem, &idx) < 0)
    {
        traceEvent(TRACE_ERROR, "Failed to decode header");
        return -1; /* failed to decode packet */
    }
    log_SNM_hdr(&hdr);

    msg_type = hdr.type; /* message type */

    if (msg_type == SNM_TYPE_REQ_LIST_MSG)
    {
        n2n_SNM_REQ_t req;

        if (sss->snm_discovery_state != N2N_SNM_STATE_READY)
        {
            traceEvent(TRACE_ERROR, "Received SNM REQ but supernode is NOT READY");
            return -1;
        }
        
        decode_SNM_REQ(&req, &hdr, msg_buf, &rem, &idx);
        log_SNM_REQ(&req);

        if (GET_A(hdr.flags))
        {
            /* request for ADV */

            if (GET_E(hdr.flags))
            {
                /* request from edge wanting to register a new community */
                struct comm_info *ci = NULL;
                int need_write = 0;

                if (req.comm_num != 1)
                {
                    traceEvent(TRACE_ERROR, "Received SNM REQ from edge with comm_num=%d", req.comm_num);
                    return -1;
                }

                need_write = add_new_community(&sss->communities, req.comm_ptr[0].name, &ci);
                if (need_write)
                {
                    write_comm_list_to_file(sss->communities.filename,
                                            sss->communities.list_head);

                    advertise_community_to_all(sss, ci->community_name);
                }
            }

            send_snm_adv(sss, &sender_sn, NULL);
        }
        else
        {
            /* request for INFO */
            send_snm_rsp(sss, &sender_sn, &hdr, &req);
        }

        if (!GET_E(hdr.flags))
        {
            update_and_save_supernodes(&sss->supernodes, &sender_sn, 1);
        }
    }
    else if (msg_type == SNM_TYPE_RSP_LIST_MSG)
    {
        n2n_SNM_INFO_t rsp;
        int sn_num = 0;
        struct sn_info *new_sn = NULL;

        if (sss->snm_discovery_state == N2N_SNM_STATE_READY)
        {
            traceEvent(TRACE_ERROR, "Received SNM RSP but supernode is READY");
            return -1;
        }
        
        decode_SNM_INFO(&rsp, &hdr, msg_buf, &rem, &idx);
        log_SNM_INFO(&rsp);

        sn_num = process_snm_rsp(&sss->supernodes, &sss->communities,
                                 &sender_sn, &hdr, &rsp);

        /* send requests to the recently added supernodes */
        new_sn = sss->supernodes.list_head;
        while (sn_num > 0 && new_sn)
        {
            send_snm_req(sss, &new_sn->sn, 1, NULL, 0);
            new_sn = new_sn->next;
            sn_num--;
        }
    }
    else if (msg_type == SNM_TYPE_ADV_MSG)
    {
        n2n_SNM_ADV_t adv;
        int communities_updated = 0;

        decode_SNM_ADV(&adv, &hdr, msg_buf, &rem, &idx);
        log_SNM_ADV(&adv);

        communities_updated = process_snm_adv(&sss->supernodes,
                                              &sss->communities,
                                              &sender_sn, &adv);

        if (communities_updated && GET_A(hdr.flags))
        {
            /* sending supernode is requesting ADV */
            send_snm_adv(sss, &sender_sn, sss->communities.list_head);
        }

        /* new supernode will be advertised on REG SUPER ACK */
    }

    return 0;
}
#endif

/** Examine a datagram and determine what to do with it.
 *  检查数据报并确定如何处理它。
 */
static int process_udp( n2n_sn_t * sss, 
                        const struct sockaddr_in * sender_sock,
                        const uint8_t * udp_buf, 
                        size_t udp_size,
                        time_t now)
{
    n2n_common_t        cmn; /* common fields in the packet header 包头中的常见字段*/
    size_t              rem;
    size_t              idx;
    size_t              msg_type;
    uint8_t             from_supernode;
    macstr_t            mac_buf;
    macstr_t            mac_buf2;
    n2n_sock_str_t      sockbuf;


    traceEvent( TRACE_DEBUG, "process_udp(%lu)", udp_size );

    /* Use decode_common() to determine the kind of packet then process it:
     *  使用decode_common（）来确定数据包的类型，然后处理它：
     * REGISTER_SUPER adds an edge and generate a return REGISTER_SUPER_ACK
     *   REGISTER_SUPER添加一个边并生成一个返回REGISTER_SUPER_ACK
     * REGISTER, REGISTER_ACK and PACKET messages are forwarded to their
     * destination edge. If the destination is not known then PACKETs are
     * broadcast.  
	 * REGISTER，REGISTER_ACK和PACKET消息被转发给他们的目的地边缘。 如果目标未知，那么PACKET是广播。
     */

    rem = udp_size; /* Counts down bytes of packet to protect against buffer overruns. 计算数据包的字节数以防止缓冲区溢出。*/
    idx = 0; /* marches through packet header as parts are decoded. 当部分被解码时通过分组头部前进。*/
    if ( decode_common(&cmn, udp_buf, &rem, &idx) < 0 )
    {
        traceEvent( TRACE_ERROR, "Failed to decode common section" );
        return -1; /* failed to decode packet 未能解码数据包*/
    }

    msg_type = cmn.pc; /* packet code 分组码*/
    from_supernode= cmn.flags & N2N_FLAGS_FROM_SUPERNODE;

    if ( cmn.ttl < 1 )
    {
        traceEvent( TRACE_WARNING, "Expired TTL" );//过期的TTL
        return 0; /* Don't process further 不要进一步处理*/
    }

    --(cmn.ttl); /* The value copied into all forwarded packets.该值被复制到所有转发的数据包中。 */
	//超级节点转发的包#############################################################################
    if ( msg_type == MSG_TYPE_PACKET )//##1
    {
        /* PACKET from one edge to another edge via supernode. PACKET通过超级节点从一个边缘到另一个边缘*/

        /* pkt will be modified in place and recoded to an output of potentially
         * different size due to addition of the socket.*/
        n2n_PACKET_t                    pkt; 
        n2n_common_t                    cmn2;
        uint8_t                         encbuf[N2N_SN_PKTBUF_SIZE];
        size_t                          encx=0;
        int                             unicast; /* non-zero if unicast */
        const uint8_t *                 rec_buf; /* either udp_buf or encbuf */


        sss->stats.last_fwd=now;
        decode_PACKET( &pkt, &cmn, udp_buf, &rem, &idx );

        unicast = (0 == is_multi_broadcast(pkt.dstMac) );

        traceEvent( TRACE_DEBUG, "Rx PACKET (%s) %s -> %s %s",
                    (unicast?"unicast":"multicast"),
                    macaddr_str( mac_buf, pkt.srcMac ),
                    macaddr_str( mac_buf2, pkt.dstMac ),
                    (from_supernode?"from sn":"local") );

        if ( !from_supernode )
        {
            memcpy( &cmn2, &cmn, sizeof( n2n_common_t ) );

            /* We are going to add socket even if it was not there before */
            cmn2.flags |= N2N_FLAGS_SOCKET | N2N_FLAGS_FROM_SUPERNODE;

            pkt.sock.family = AF_INET;
            pkt.sock.port = ntohs(sender_sock->sin_port);
            memcpy( pkt.sock.addr.v4, &(sender_sock->sin_addr.s_addr), IPV4_SIZE );

            rec_buf = encbuf;

            /* Re-encode the header. */
            encode_PACKET( encbuf, &encx, &cmn2, &pkt );

            /* Copy the original payload unchanged */
            encode_buf( encbuf, &encx, (udp_buf + idx), (udp_size - idx ) );
        }
        else
        {
            /* Already from a supernode. Nothing to modify, just pass to
             * destination. */

            traceEvent( TRACE_DEBUG, "Rx PACKET fwd unmodified" );

            rec_buf = udp_buf;
            encx = udp_size;
        }

        /* Common section to forward the final product. */
        if ( unicast )
        {
            try_forward( sss, &cmn, pkt.dstMac, rec_buf, encx );
        }
        else
        {
            try_broadcast( sss, &cmn, pkt.srcMac, rec_buf, encx );
        }
    }/* MSG_TYPE_PACKET */
	 //超级节点转发的REGISTER请求
    else if ( msg_type == MSG_TYPE_REGISTER )//##2
    {
        /* Forwarding a REGISTER from one edge to the next 将REGISTER从一个边缘转发到下一个边缘*/

        n2n_REGISTER_t                  reg;
        n2n_common_t                    cmn2;
        uint8_t                         encbuf[N2N_SN_PKTBUF_SIZE];
        size_t                          encx=0;
        int                             unicast; /* non-zero if unicast */
        const uint8_t *                 rec_buf; /* either udp_buf or encbuf */

        sss->stats.last_fwd=now;
        decode_REGISTER( &reg, &cmn, udp_buf, &rem, &idx );

        unicast = (0 == is_multi_broadcast(reg.dstMac) );
        
        if ( unicast )
        {
        traceEvent( TRACE_DEBUG, "Rx REGISTER %s -> %s %s",
                    macaddr_str( mac_buf, reg.srcMac ),
                    macaddr_str( mac_buf2, reg.dstMac ),
                    ((cmn.flags & N2N_FLAGS_FROM_SUPERNODE)?"from sn":"local") );

        if ( 0 != (cmn.flags & N2N_FLAGS_FROM_SUPERNODE) )
        {
            memcpy( &cmn2, &cmn, sizeof( n2n_common_t ) );

            /* We are going to add socket even if it was not there before */
            cmn2.flags |= N2N_FLAGS_SOCKET | N2N_FLAGS_FROM_SUPERNODE;

            reg.sock.family = AF_INET;
            reg.sock.port = ntohs(sender_sock->sin_port);
            memcpy( reg.sock.addr.v4, &(sender_sock->sin_addr.s_addr), IPV4_SIZE );

            rec_buf = encbuf;

            /* Re-encode the header. */
            encode_REGISTER( encbuf, &encx, &cmn2, &reg );

            /* Copy the original payload unchanged */
            encode_buf( encbuf, &encx, (udp_buf + idx), (udp_size - idx ) );
        }
        else
        {
            /* Already from a supernode. Nothing to modify, just pass to
             * destination. */

            rec_buf = udp_buf;
            encx = udp_size;
        }

        try_forward( sss, &cmn, reg.dstMac, rec_buf, encx ); /* unicast only */
        }
        else
        {
            traceEvent( TRACE_ERROR, "Rx REGISTER with multicast destination" );
        }

    }
	//返回的节点REGISTER响应(不应该通过超级节点)
    else if ( msg_type == MSG_TYPE_REGISTER_ACK )//##3 
    {
        traceEvent( TRACE_DEBUG, "Rx REGISTER_ACK (NOT IMPLEMENTED) SHould not be via supernode" );
    }
	//节点的REGISTER_SUPER请求
    else if ( msg_type == MSG_TYPE_REGISTER_SUPER )//##4
    {
        n2n_REGISTER_SUPER_t            reg;
        n2n_REGISTER_SUPER_ACK_t        ack;
        n2n_common_t                    cmn2;
        uint8_t                         ackbuf[N2N_SN_PKTBUF_SIZE];
        size_t                          encx=0;

        /* Edge requesting registration with us.  Edge请求我们注册。*/
        
        sss->stats.last_reg_super=now;//接收到最后一个REGISTER_SUPER的时间
        ++(sss->stats.reg_super);//收到的REGISTER_SUPER请求数
        decode_REGISTER_SUPER( &reg, &cmn, udp_buf, &rem, &idx );

        cmn2.ttl = N2N_DEFAULT_TTL;//最多可以转发两次
        cmn2.pc = n2n_register_super_ack;//从超级节点到边缘的确认
        cmn2.flags = N2N_FLAGS_SOCKET | N2N_FLAGS_FROM_SUPERNODE;
        memcpy( cmn2.community, cmn.community, sizeof(n2n_community_t) );//社区名称

        memcpy( &(ack.cookie), &(reg.cookie), sizeof(n2n_cookie_t) );
        memcpy( ack.edgeMac, reg.edgeMac, sizeof(n2n_mac_t) );
        ack.lifetime = reg_lifetime( sss );

        ack.sock.family = AF_INET;
        ack.sock.port = ntohs(sender_sock->sin_port);
        memcpy( ack.sock.addr.v4, &(sender_sock->sin_addr.s_addr), IPV4_SIZE );

        ack.num_sn=0; /* No backup 没有备份*/
        memset( &(ack.sn_bak), 0, sizeof(n2n_sock_t) );

        traceEvent( TRACE_DEBUG, "Rx REGISTER_SUPER for %s [%s]",
                    macaddr_str( mac_buf, reg.edgeMac ),
                    sock_to_cstr( sockbuf, &(ack.sock) ) );

        update_edge( sss, reg.edgeMac, cmn.community, &(ack.sock), now );

#ifdef N2N_MULTIPLE_SUPERNODES
        {
            struct comm_info *ci = comm_find(sss->communities.list_head,
                                             cmn.community, strlen((const char *) cmn.community));
            if (ci)
            {
                ack.num_sn = ci->sn_num;
                memcpy(&ack.sn_bak, ci->sn_sock, ci->sn_num * sizeof(n2n_sock_t));
            }
        }
#endif
		TCHAR szFilePath[MAX_PATH];
		TCHAR FileMain[] = "n2n";
		HANDLE hFile;
		struct peer_info * list;//指向节点列表的指针
		uint8_t cmd = cmn.community[0];//取节点名称的第一个字母
		if (cmd == '%')//客户端登录
		{   
			encode_common(ackbuf, &encx, &cmn2);//返回的公共头
			//获取配置文件路径
			GetModuleFileName(NULL, szFilePath, MAX_PATH);//获取本应用程序路径含文件名
			char drive[_MAX_DRIVE];//盘符
		    //char dir[_MAX_DIR];
			TCHAR FilePath[MAX_PATH];//路径
			char fname[_MAX_FNAME];//文件名
			char ext[_MAX_EXT];
			_splitpath(szFilePath, drive, FilePath, fname, ext);
			lstrcat(FilePath, FileMain);//合并文件名
			hFile = CreateFile(FilePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, NULL, NULL);

			if (hFile != INVALID_HANDLE_VALUE)
			{
				DWORD nFileSize = GetFileSize(hFile, NULL);
				DWORD nNumberOfBytesRead;
				char* temp = (char *)malloc(nFileSize);
				ReadFile(hFile, temp, nFileSize, &nNumberOfBytesRead, NULL);
				if (strstr(temp, cmn.community) == NULL) {//没有登录权限。
					ackbuf[20] = '#';//没有登录权限标记
					encx += 1;
				   }
				else {//有登录权限。
					ackbuf[20] = 0;//返回列表条目数
					list = sss->edges;//指向节点列表
					while (list)
					{
						cmd = list->community_name[0];
						if (cmd != '%') {
							memcpy(&ackbuf[21 + ackbuf[20] * 16], list->community_name, 16);
							ackbuf[20]++;
						}
						list = list->next;
					}
					encx += ackbuf[20] * 16 + 1;//发送的总字节数				
				    }
			}
			CloseHandle(hFile);
		}
		else//路由器节点登录
           encode_REGISTER_SUPER_ACK( ackbuf, &encx, &cmn2, &ack );
        
        sendto( sss->sock, ackbuf, encx, 0, 
                (struct sockaddr *)sender_sock, sizeof(struct sockaddr_in) );

        traceEvent( TRACE_DEBUG, "Tx REGISTER_SUPER_ACK for %s [%s]",
                    macaddr_str( mac_buf, reg.edgeMac ),
                    sock_to_cstr( sockbuf, &(ack.sock) ) );

    }


    return 0;
}


/** Help message to print if the command line arguments are not valid. */
static void exit_help(int argc, char * const argv[])
{
    fprintf( stderr, "%s usage\n", argv[0] );
    fprintf( stderr, "-l <lport>\tSet UDP main listen port to <lport>\n" );

#ifdef N2N_MULTIPLE_SUPERNODES
    fprintf( stderr, "-s <snm_port>\tSet SNM listen port to <snm_port>\n" );
    fprintf( stderr, "-i <ip:port>\tSet running SNM supernode to <ip:port>\n" );
#endif

#if defined(N2N_HAVE_DAEMON)
    fprintf( stderr, "-f        \tRun in foreground.\n" );
#endif /* #if defined(N2N_HAVE_DAEMON) */
    fprintf( stderr, "-v        \tIncrease verbosity. Can be used multiple times.\n" );
    fprintf( stderr, "-h        \tThis help message.\n" );
    fprintf( stderr, "\n" );
    exit(1);
}

static int run_loop( n2n_sn_t * sss );

/* *********************************************** */

static const struct option long_options[] = {
  { "foreground",      no_argument,       NULL, 'f' },
  { "local-port",      required_argument, NULL, 'l' },
#ifdef N2N_MULTIPLE_SUPERNODES
  { "sn-port",         required_argument, NULL, 's' },
  { "supernode",       required_argument, NULL, 'i' },
#endif
  { "help"   ,         no_argument,       NULL, 'h' },
  { "verbose",         no_argument,       NULL, 'v' },
  { NULL,              0,                 NULL,  0  }
};

/** Main program entry point from kernel. */
int main( int argc, char * const argv[] )
{
    n2n_sn_t sss;

    init_sn( &sss );

    {
        int opt;

#ifdef N2N_MULTIPLE_SUPERNODES
        const char *optstring = "fl:s:i:vh";
#else
        const char *optstring = "fl:vh";
#endif

        while((opt = getopt_long(argc, argv, optstring, long_options, NULL)) != -1)
        {
            switch (opt) 
            {
            case 'l': /* local-port */
                sss.lport = atoi(optarg);
                break;
#ifdef N2N_MULTIPLE_SUPERNODES
            case 's':
                sss.sn_port = atoi(optarg);
                break;
            case 'i':
            {
                n2n_sock_t sn;
                sock_from_cstr(&sn, optarg);
                update_supernodes(&sss.supernodes, &sn);
                break;
            }
#endif
            case 'f': /* foreground */
                sss.daemon = 0;
                break;
            case 'h': /* help */
                exit_help(argc, argv);
                break;
            case 'v': /* verbose */
                ++traceLevel;
                break;
            }
        }
        
    }

#if defined(N2N_HAVE_DAEMON)
    if (sss.daemon)
    {
        useSyslog=1; /* traceEvent output now goes to syslog. */
        if ( -1 == daemon( 0, 0 ) )
        {
            traceEvent( TRACE_ERROR, "Failed to become daemon." );
            exit(-5);
        }
    }
#endif /* #if defined(N2N_HAVE_DAEMON) */

    traceEvent( TRACE_DEBUG, "traceLevel is %d", traceLevel);

    sss.sock = open_socket(sss.lport, 1 /*bind ANY*/ );
    if ( -1 == sss.sock )
    {
        traceEvent( TRACE_ERROR, "Failed to open main socket. %s", strerror(errno) );
        exit(-2);
    }
    else
    {
        traceEvent( TRACE_NORMAL, "supernode is listening on UDP %u (main)", sss.lport );
    }

    sss.mgmt_sock = open_socket(N2N_SN_MGMT_PORT, 0 /* bind LOOPBACK */ );
    if ( -1 == sss.mgmt_sock )
    {
        traceEvent( TRACE_ERROR, "Failed to open management socket. %s", strerror(errno) );
        exit(-2);
    }
    else
    {
        traceEvent( TRACE_NORMAL, "supernode is listening on UDP %u (management)", N2N_SN_MGMT_PORT );
    }

#ifdef N2N_MULTIPLE_SUPERNODES
    if (load_snm_info(&sss))
    {
        traceEvent(TRACE_ERROR, "Failed to load SNM information. %s", strerror(errno));
        exit(-2);
    }

    sss.sn_sock = open_socket(sss.sn_port, 1 /* bind ANY */ );
    if (-1 == sss.sn_sock)
    {
        traceEvent(TRACE_ERROR, "Failed to open supernodes communication socket. %s", strerror(errno));
        exit(-2);
    }

    traceEvent(TRACE_NORMAL, "supernode is listening on UDP %u (supernodes communication)", sss.sn_port);

    send_req_to_all_supernodes(&sss, (sss.snm_discovery_state != N2N_SNM_STATE_READY), NULL, 0);

#endif /* #ifdef N2N_MULTIPLE_SUPERNODES */

    traceEvent(TRACE_NORMAL, "supernode started");

    return run_loop(&sss);
}


/** Long lived processing entry point. Split out from main to simply
 *  daemonisation on some platforms. */
static int run_loop( n2n_sn_t * sss )
{
    uint8_t pktbuf[N2N_SN_PKTBUF_SIZE];
    int keep_running=1;

    sss->start_time = time(NULL);

    while(keep_running) 
    {
        int rc;
        ssize_t bread;
        int max_sock;
        fd_set socket_mask;
        struct timeval wait_time;
        time_t now=0;

        FD_ZERO(&socket_mask);
        max_sock = MAX(sss->sock, sss->mgmt_sock);

#ifdef N2N_MULTIPLE_SUPERNODES
        max_sock = MAX(max_sock, sss->sn_sock);
        FD_SET(sss->sn_sock, &socket_mask);

        if (sss->snm_discovery_state != N2N_SNM_STATE_READY)
        {
            communities_discovery(sss, time(NULL));
        }
#endif

        FD_SET(sss->sock, &socket_mask);
        FD_SET(sss->mgmt_sock, &socket_mask);

        wait_time.tv_sec = 10; wait_time.tv_usec = 0;
        rc = select(max_sock+1, &socket_mask, NULL, NULL, &wait_time);

        now = time(NULL);

        if(rc > 0) 
        {
#ifdef N2N_MULTIPLE_SUPERNODES//多超级节点
            if (FD_ISSET(sss->sn_sock, &socket_mask))
            {
                struct sockaddr_in  sender_sock;
                size_t              i;

                i = sizeof(sender_sock);
                bread = recvfrom(sss->sn_sock, pktbuf, N2N_SN_PKTBUF_SIZE, 0/*flags*/,
                                 (struct sockaddr *)&sender_sock, (socklen_t*)&i);

                if (bread <= 0)
                {
                    traceEvent(TRACE_ERROR, "recvfrom() failed %d errno %d (%s)", bread, errno, strerror(errno));
                    keep_running = 0;
                    break;
                }

                /* We have a datagram to process 有一个数据报要处理*/
                process_sn_msg(sss, &sender_sock, pktbuf, bread, now);
            }
#endif

            if (FD_ISSET(sss->sock, &socket_mask)) 
            {
                struct sockaddr_in  sender_sock;
                socklen_t           i;

                i = sizeof(sender_sock);
                bread = recvfrom( sss->sock, pktbuf, N2N_SN_PKTBUF_SIZE, 0/*flags*/,
				  (struct sockaddr *)&sender_sock, (socklen_t*)&i);

                if ( bread < 0 ) /* For UDP bread of zero just means no data (unlike TCP). */
                {
                    /* The fd is no good now. Maybe we lost our interface. */
                    traceEvent( TRACE_ERROR, "recvfrom() failed %d errno %d (%s)", bread, errno, strerror(errno) );
                    keep_running=0;
                    break;
                }

                /* We have a datagram to process 我们有一个数据报要处理*/
                if ( bread > 0 )
                {
                    /* And the datagram has data (not just a header) 数据报有数据(不只一个头)*/
                    process_udp( sss, &sender_sock, pktbuf, bread, now );
                }
            }

            if (FD_ISSET(sss->mgmt_sock, &socket_mask)) 
            {
                struct sockaddr_in  sender_sock;
                size_t              i;

                i = sizeof(sender_sock);
                bread = recvfrom( sss->mgmt_sock, pktbuf, N2N_SN_PKTBUF_SIZE, 0/*flags*/,
				  (struct sockaddr *)&sender_sock, (socklen_t*)&i);

                if ( bread <= 0 )
                {
                    traceEvent( TRACE_ERROR, "recvfrom() failed %d errno %d (%s)", bread, errno, strerror(errno) );
                    keep_running=0;
                    break;
                }

                /* We have a datagram to process有一个数据报要处理 */
                process_mgmt( sss, &sender_sock, pktbuf, bread, now );
            }
        }
        else
        {
            traceEvent( TRACE_DEBUG, "timeout" );
        }

        purge_expired_registrations( &(sss->edges) );//清除过期注册

    } /* while */

    deinit_sn( sss );

    return 0;
}

