#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <netinet/in.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>

#include <libmnl/libmnl.h>
#include <libnftnl/table.h>
#include <libnftnl/chain.h>
#include <libnftnl/rule.h>
#include <libnftnl/expr.h>
#include <libnftnl/batch.h>



// int create_simple_table() {
//     char buf[MNL_SOCKET_BUFFER_SIZE];
//     struct mnl_socket *nl = mnl_socket_open(NETLINK_NETFILTER);
//     if (!nl) { perror("mnl_socket_open"); return 1; }
//     if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) { perror("bind"); return 1; }

//     // 创建表对象
//     struct nftnl_table *t = nftnl_table_alloc();
//     nftnl_table_set_str(t, NFTNL_TABLE_NAME, "mytable");
//     nftnl_table_set_u32(t, NFTNL_TABLE_FLAGS, 0);
//     nftnl_table_set_u32(t, NFTNL_TABLE_FAMILY, NFPROTO_IPV4); // AF_INET

//     // 构建 netlink 消息
//     struct nlmsghdr *nlh = nftnl_table_nlmsg_build_hdr(buf,
//                                                        NFT_MSG_NEWTABLE,
//                                                        NFPROTO_IPV4,
//                                                        NLM_F_CREATE | NLM_F_ACK,
//                                                        1);
//     nftnl_table_nlmsg_build_payload(nlh, t);

//     // 发送
//     if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) { perror("sendto"); return 1; }

//     // 接收 ACK
//     int ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
//     if (ret < 0) { perror("recvfrom"); return 1; }

//     printf("Table 'mytable' created successfully!\n");

//     nftnl_table_free(t);
//     mnl_socket_close(nl);
//     return 0;
// }
int nft_create_table_fixed()
{
    struct nftnl_table *t = nftnl_table_alloc();
    if (!t) {
        perror("OOM");
        return -1;
    }

    nftnl_table_set_u32(t, NFTNL_TABLE_FAMILY, NFPROTO_IPV4);
    nftnl_table_set_str(t, NFTNL_TABLE_NAME, "mytable");

    int batching = nftnl_batch_is_supported();
    if (batching < 0) {
        perror("cannot talk to nfnetlink");
        nftnl_table_free(t);
        return -1;
    }

    char buf[MNL_SOCKET_BUFFER_SIZE];
    uint32_t seq = time(NULL);  // C++里time是全局函数，不加 std::
    struct mnl_nlmsg_batch *batch = mnl_nlmsg_batch_start(buf, sizeof(buf));

    if (batching) {
        nftnl_batch_begin((char *)mnl_nlmsg_batch_current(batch), seq++);
        mnl_nlmsg_batch_next(batch);
    }

    uint32_t table_seq = seq;
    struct nlmsghdr *nlh = nftnl_table_nlmsg_build_hdr(
        (char *)mnl_nlmsg_batch_current(batch),
        NFT_MSG_NEWTABLE,
        NFPROTO_IPV4,
        NLM_F_CREATE | NLM_F_ACK,
        seq++
    );

    nftnl_table_nlmsg_build_payload(nlh, t);
    nftnl_table_free(t);
    mnl_nlmsg_batch_next(batch);

    if (batching) {
        nftnl_batch_end((char *)mnl_nlmsg_batch_current(batch), seq++);
        mnl_nlmsg_batch_next(batch);
    }

    struct mnl_socket *nl = mnl_socket_open(NETLINK_NETFILTER);
    if (!nl) {
        perror("mnl_socket_open");
        mnl_nlmsg_batch_stop(batch);
        return -1;
    }
    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        perror("mnl_socket_bind");
        mnl_socket_close(nl);
        mnl_nlmsg_batch_stop(batch);
        return -1;
    }

    uint32_t portid = mnl_socket_get_portid(nl);

    if (mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch), mnl_nlmsg_batch_size(batch)) < 0) {
        perror("mnl_socket_sendto");
        mnl_socket_close(nl);
        mnl_nlmsg_batch_stop(batch);
        return -1;
    }

    mnl_nlmsg_batch_stop(batch);

    int ret = 0;
    int r = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    while (r > 0) {
        if (mnl_cb_run(buf, r, table_seq, portid, nl_cb, &ret) <= 0)
            break;
        r = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    }

    if (r == -1) {
        perror("mnl_socket_recvfrom");
        ret = -1;
    }

    mnl_socket_close(nl);
    return ret;
}

#define CHAIN_TABLE_NAME "mytable"
#define CHAIN_NAME       "prerouting"
#define CHAIN_FAMILY     NFPROTO_IPV4
#define CHAIN_HOOKNUM    NF_INET_PRE_ROUTING
#define CHAIN_PRIO       0

int nft_create_chain_fixed()
{
    struct nftnl_chain *c = nftnl_chain_alloc();
    if (!c) {
        perror("OOM");
        return -1;
    }

    nftnl_chain_set_str(c, NFTNL_CHAIN_TABLE, CHAIN_TABLE_NAME);
    nftnl_chain_set_str(c, NFTNL_CHAIN_NAME, CHAIN_NAME);
    nftnl_chain_set_u32(c, NFTNL_CHAIN_HOOKNUM, CHAIN_HOOKNUM);
    nftnl_chain_set_s32(c, NFTNL_CHAIN_PRIO, CHAIN_PRIO);
    nftnl_chain_set_str(c, NFTNL_CHAIN_TYPE, "nat");

    int batching = nftnl_batch_is_supported();
    if (batching < 0) {
        perror("cannot talk to nfnetlink");
        nftnl_chain_free(c);
        return -1;
    }

    char buf[MNL_SOCKET_BUFFER_SIZE];
    uint32_t seq = time(nullptr);
    struct mnl_nlmsg_batch *batch = mnl_nlmsg_batch_start(buf, sizeof(buf));

    if (batching) {
        nftnl_batch_begin(reinterpret_cast<char*>(mnl_nlmsg_batch_current(batch)), seq++);
        mnl_nlmsg_batch_next(batch);
    }

    uint32_t chain_seq = seq;
    struct nlmsghdr *nlh = nftnl_chain_nlmsg_build_hdr(
        reinterpret_cast<char*>(mnl_nlmsg_batch_current(batch)),
        NFT_MSG_NEWCHAIN,
        CHAIN_FAMILY,
        NLM_F_CREATE | NLM_F_ACK,
        seq++
    );
    nftnl_chain_nlmsg_build_payload(nlh, c);
    nftnl_chain_free(c);
    mnl_nlmsg_batch_next(batch);

    if (batching) {
        nftnl_batch_end(reinterpret_cast<char*>(mnl_nlmsg_batch_current(batch)), seq++);
        mnl_nlmsg_batch_next(batch);
    }

    struct mnl_socket *nl = mnl_socket_open(NETLINK_NETFILTER);
    if (!nl) {
        perror("mnl_socket_open");
        mnl_nlmsg_batch_stop(batch);
        return -1;
    }

    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        perror("mnl_socket_bind");
        mnl_socket_close(nl);
        mnl_nlmsg_batch_stop(batch);
        return -1;
    }

    uint32_t portid = mnl_socket_get_portid(nl);

    if (mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch),
                          mnl_nlmsg_batch_size(batch)) < 0) {
        perror("mnl_socket_sendto");
        mnl_socket_close(nl);
        mnl_nlmsg_batch_stop(batch);
        return -1;
    }

    mnl_nlmsg_batch_stop(batch);

    int ret = 0;
    int r = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    while (r > 0) {
        if (mnl_cb_run(buf, r, chain_seq, portid, nl_cb, &ret) <= 0)
            break;
        r = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    }

    if (r == -1) {
        perror("mnl_socket_recvfrom");
        ret = -1;
    }

    mnl_socket_close(nl);
    return ret;
}
int nft_create_rule_fixed()
{
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct mnl_socket *nl;
    struct nlmsghdr *nlh;
    struct mnl_nlmsg_batch *batch;
    uint32_t seq = static_cast<uint32_t>(time(nullptr));
    uint32_t rule_seq;
    int ret = 0;
    ssize_t r;

    int batching = nftnl_batch_is_supported();
    if (batching < 0) {
        perror("cannot talk to nfnetlink");
        return -1;
    }

    batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
    if (!batch) { perror("mnl_nlmsg_batch_start"); return -1; }

    if (batching) {
        nftnl_batch_begin(reinterpret_cast<char*>(mnl_nlmsg_batch_current(batch)), seq++);
        mnl_nlmsg_batch_next(batch);
    }

    /* === 构造 rule === */
    struct nftnl_rule *rule = nftnl_rule_alloc();
    if (!rule) { perror("nftnl_rule_alloc"); mnl_nlmsg_batch_stop(batch); return -1; }

    nftnl_rule_set_str(rule, NFTNL_RULE_TABLE, TABLE_NAME);
    nftnl_rule_set_str(rule, NFTNL_RULE_CHAIN, CHAIN_NAME);
    nftnl_rule_set_u32(rule, NFTNL_RULE_FAMILY, FAMILY);

    /* 1) iifname -> reg1, cmp reg1 == "eth0" */
    struct nftnl_expr *expr = nftnl_expr_alloc("meta");
    nftnl_expr_set_u32(expr, NFTNL_EXPR_META_KEY, NFT_META_IIFNAME);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_META_DREG, NFT_REG_1);
    nftnl_rule_add_expr(rule, expr);

    expr = nftnl_expr_alloc("cmp");
    nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_SREG, NFT_REG_1);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_OP, NFT_CMP_EQ);
    const char *iface = "eth0";
    nftnl_expr_set(expr, NFTNL_EXPR_CMP_DATA, iface, strlen(iface) + 1);
    nftnl_rule_add_expr(rule, expr);

    /* 2) payload: network header offset 9 (protocol) -> reg2 ; cmp reg2 == IPPROTO_ICMP */
    expr = nftnl_expr_alloc("payload");
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_OFFSET, 9);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_LEN, 1);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_DREG, NFT_REG_2);
    nftnl_rule_add_expr(rule, expr);

    uint8_t proto = IPPROTO_ICMP;
    expr = nftnl_expr_alloc("cmp");
    nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_SREG, NFT_REG_2);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_OP, NFT_CMP_EQ);
    nftnl_expr_set(expr, NFTNL_EXPR_CMP_DATA, &proto, sizeof(proto));
    nftnl_rule_add_expr(rule, expr);

expr = nftnl_expr_alloc("payload");
nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_BASE, NFT_PAYLOAD_LL_HEADER);
nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_OFFSET, offsetof(struct ethhdr, h_source));
nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_LEN, 6);
nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_DREG, NFT_REG_1);
nftnl_rule_add_expr(rule, expr);

expr = nftnl_expr_alloc("cmp");
nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_SREG, NFT_REG_1);
nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_OP, NFT_CMP_EQ);
nftnl_expr_set(expr, NFTNL_EXPR_CMP_DATA, mac, 6);
nftnl_rule_add_expr(rule, expr);

/* payload -> reg1 ; cmp reg1 == saddr_be */
expr = nftnl_expr_alloc("payload");
nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER);
nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_OFFSET, offsetof(struct iphdr, saddr));
nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_LEN, 4);
nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_DREG, NFT_REG_1);
nftnl_rule_add_expr(rule, expr);

expr = nftnl_expr_alloc("cmp");
nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_SREG, NFT_REG_1);
nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_OP, NFT_CMP_EQ);
nftnl_expr_set(expr, NFTNL_EXPR_CMP_DATA, &saddr_be, 4);
nftnl_rule_add_expr(rule, expr);

    /* 3) payload: network header offset 12 (saddr) -> reg3 ; cmp reg3 == 192.168.1.1 */
    expr = nftnl_expr_alloc("payload");
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_OFFSET, 12);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_LEN, 4);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_DREG, NFT_REG_3);
    nftnl_rule_add_expr(rule, expr);

    uint32_t saddr = htonl(0xc0a80101);
    expr = nftnl_expr_alloc("cmp");
    nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_SREG, NFT_REG_3);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_OP, NFT_CMP_EQ);
    nftnl_expr_set(expr, NFTNL_EXPR_CMP_DATA, &saddr, sizeof(saddr));
    nftnl_rule_add_expr(rule, expr);

    /* 4) payload: transport header offset 0 (ICMP type) -> reg4 ; cmp reg4 == 8 (echo-request) */
    expr = nftnl_expr_alloc("payload");
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_BASE, NFT_PAYLOAD_TRANSPORT_HEADER);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_OFFSET, 0);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_LEN, 1);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_PAYLOAD_DREG, NFT_REG_4);
    nftnl_rule_add_expr(rule, expr);

    uint8_t icmp_type = 8; /* echo-request */
    expr = nftnl_expr_alloc("cmp");
    nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_SREG, NFT_REG_4);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_CMP_OP, NFT_CMP_EQ);
    nftnl_expr_set(expr, NFTNL_EXPR_CMP_DATA, &icmp_type, sizeof(icmp_type));
    nftnl_rule_add_expr(rule, expr);

    /* 5) immediate DROP */
    expr = nftnl_expr_alloc("immediate");
    nftnl_expr_set_u32(expr, NFTNL_EXPR_IMM_DREG, NFT_REG_VERDICT);
    nftnl_expr_set_u32(expr, NFTNL_EXPR_IMM_VERDICT, NF_DROP);
    nftnl_rule_add_expr(rule, expr);

    /* === 构建 batch 消息 === */
    rule_seq = seq;
    nlh = nftnl_rule_nlmsg_build_hdr(
        reinterpret_cast<char*>(mnl_nlmsg_batch_current(batch)),
        NFT_MSG_NEWRULE,
        FAMILY,
        NLM_F_CREATE | NLM_F_APPEND | NLM_F_ACK,
        seq++
    );
    nftnl_rule_nlmsg_build_payload(nlh, rule);
    nftnl_rule_free(rule); /* 释放所有 expr */
    mnl_nlmsg_batch_next(batch);

    if (batching) {
        nftnl_batch_end(reinterpret_cast<char*>(mnl_nlmsg_batch_current(batch)), seq++);
        mnl_nlmsg_batch_next(batch);
    }

    /* === 发送并等待 ACK（使用你已有的 nl_cb 打印错误） === */
    nl = mnl_socket_open(NETLINK_NETFILTER);
    if (!nl) { perror("mnl_socket_open"); mnl_nlmsg_batch_stop(batch); return -1; }
    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        perror("mnl_socket_bind"); mnl_socket_close(nl); mnl_nlmsg_batch_stop(batch); return -1;
    }
    uint32_t portid = mnl_socket_get_portid(nl);

    if (mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch), mnl_nlmsg_batch_size(batch)) < 0) {
        perror("mnl_socket_sendto"); mnl_socket_close(nl); mnl_nlmsg_batch_stop(batch); return -1;
    }
    mnl_nlmsg_batch_stop(batch);

    r = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    printf("send rule seq=%u portid=%u\n", seq, portid);
    while (r > 0) {
        /* 使用你之前定义的 nl_cb（打印 ACK/ERROR），不要传 NULL */
        if (mnl_cb_run(buf, static_cast<size_t>(r), rule_seq, portid, nl_cb, &ret) <= 0)
            break;
        r = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    }
    if (r == -1) { perror("mnl_socket_recvfrom"); ret = -1; }

    mnl_socket_close(nl);
    return ret;
}