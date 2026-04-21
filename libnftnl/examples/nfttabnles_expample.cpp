int
PicaConfigNetlinkSocket::nft_netlink_talk(void* buf, size_t send_len,
                                          size_t buf_size, uint32_t seq,
                                          void* data) {
    struct mnl_socket* nl = nullptr;
    if (nls_netfilter_alloc(nl) != 0) {
        return -1;
    }

    uint32_t portid = mnl_socket_get_portid(nl);
    int ret = mnl_socket_sendto(nl, buf, send_len);
    if (ret == -1) {
        PNLS_LOG_ERROR("[%s]mnl_socket_sendto failed: %s",
                       _MODULE, strerror(errno));
        nls_netfilter_release(nl);
        return -1;
    }

    ret = mnl_socket_recvfrom(nl, buf, buf_size);
    while (ret > 0) {
        if (data) {
            ret = mnl_cb_run(buf, ret, seq, portid, nft_netlink_echo_callback, data);
        } else {
            ret = mnl_cb_run(buf, ret, seq, portid, nullptr, nullptr);
        }
        if (ret <= 0) {
            break;
        }
        ret = mnl_socket_recvfrom(nl, buf, buf_size);
    }
    nls_netfilter_release(nl);

    if (ret < 0) {
        PNLS_LOG_ERROR("[%s]mnl_socket_recvfrom failed: %s",
                       _MODULE, strerror(errno));
    }
    return ret;
}

int
PicaConfigNetlinkSocket::nft_operate_table(uint16_t type, uint16_t flags,
                                           uint32_t family,
                                           const string& table_name,
                                           void* data) {
    struct nlmsghdr* nlh;
    struct mnl_nlmsg_batch* batch;
    char buf[256];
    int ret;

    uint32_t seq = nls_request_seq(10);
    batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
    (void)nftnl_batch_begin((char*)mnl_nlmsg_batch_current(batch), seq++);
    (void)mnl_nlmsg_batch_next(batch);
    uint32_t table_seq = seq;
    nlh = nftnl_table_nlmsg_build_hdr((char*)mnl_nlmsg_batch_current(batch),
                                      type, family, flags, seq++);
    mnl_attr_put_strz(nlh, NFTA_TABLE_NAME, table_name.c_str());
    (void)mnl_nlmsg_batch_next(batch);
    (void)nftnl_batch_end((char*)mnl_nlmsg_batch_current(batch), seq++);
    (void)mnl_nlmsg_batch_next(batch);

    ret = nft_netlink_talk(mnl_nlmsg_batch_head(batch),
                           mnl_nlmsg_batch_size(batch),
                           sizeof(buf), table_seq, data);
    mnl_nlmsg_batch_stop(batch);
    return ret;
}

int
PicaConfigNetlinkSocket::nft_add_table(uint32_t family,
                                       const string& table_name) {
    return nft_operate_table(NFT_MSG_NEWTABLE, NLM_F_CREATE | NLM_F_ACK,
                             family, table_name, nullptr);
}

int
PicaConfigNetlinkSocket::nft_del_table(uint32_t family,
                                       const string& table_name) {
    return nft_operate_table(NFT_MSG_DELTABLE, NLM_F_ACK,
                             family, table_name, nullptr);
}

int
PicaConfigNetlinkSocket::nft_operate_chain(uint16_t type, uint16_t flags,
                                           struct nftnl_chain* chain,
                                           void* data) {
    struct nlmsghdr* nlh;
    struct mnl_nlmsg_batch* batch;
    char buf[256];
    uint32_t family;
    int ret;

    uint32_t seq = nls_request_seq(10);
    batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
    (void)nftnl_batch_begin((char*)mnl_nlmsg_batch_current(batch), seq++);
    (void)mnl_nlmsg_batch_next(batch);

    uint32_t chain_seq = seq;
    family = nftnl_chain_get_u32(chain, NFTNL_CHAIN_FAMILY);
    nlh = nftnl_chain_nlmsg_build_hdr((char*)mnl_nlmsg_batch_current(batch),
                                      type, family, flags, seq++);
    nftnl_chain_nlmsg_build_payload(nlh, chain);
    (void)mnl_nlmsg_batch_next(batch);

    (void)nftnl_batch_end((char*)mnl_nlmsg_batch_current(batch), seq++);
    (void)mnl_nlmsg_batch_next(batch);

    ret = nft_netlink_talk(mnl_nlmsg_batch_head(batch),
                           mnl_nlmsg_batch_size(batch),
                           sizeof(buf), chain_seq, data);
    mnl_nlmsg_batch_stop(batch);
    return ret;
}

int
PicaConfigNetlinkSocket::nft_add_chain(uint32_t family,
                                       const string& table_name,
                                       const string& chain_name,
                                       const string& chain_type,
                                       uint32_t hook, int priority) {
    int ret;
    struct nftnl_chain* chain = nftnl_chain_alloc();
    if (!chain) {
        return -1;
    }

    nftnl_chain_set_u32(chain, NFTNL_CHAIN_FAMILY, family);
    nftnl_chain_set_str(chain, NFTNL_CHAIN_TABLE, table_name.c_str());
    nftnl_chain_set_str(chain, NFTNL_CHAIN_NAME, chain_name.c_str());
    nftnl_chain_set_str(chain, NFTNL_CHAIN_TYPE, chain_type.c_str());
    nftnl_chain_set_u32(chain, NFTNL_CHAIN_HOOKNUM, hook);
    nftnl_chain_set_u32(chain, NFTNL_CHAIN_PRIO, priority);

    ret = nft_operate_chain(NFT_MSG_NEWCHAIN, NLM_F_CREATE | NLM_F_ACK,
                            chain, nullptr);
    nftnl_chain_free(chain);
    return ret;
}

int
PicaConfigNetlinkSocket::nft_add_chain(uint32_t family,
                                       const string& table_name,
                                       const string& chain_name) {
    int ret;
    struct nftnl_chain* chain = nftnl_chain_alloc();
    if (!chain) {
        return -1;
    }

    nftnl_chain_set_u32(chain, NFTNL_CHAIN_FAMILY, family);
    nftnl_chain_set_str(chain, NFTNL_CHAIN_TABLE, table_name.c_str());
    nftnl_chain_set_str(chain, NFTNL_CHAIN_NAME, chain_name.c_str());

    ret = nft_operate_chain(NFT_MSG_NEWCHAIN, NLM_F_CREATE | NLM_F_ACK,
                            chain, nullptr);
    nftnl_chain_free(chain);
    return ret;
}

int
PicaConfigNetlinkSocket::nft_del_chain(uint32_t family,
                                       const string& table_name,
                                       const string& chain_name) {
    struct nftnl_chain* chain = nftnl_chain_alloc();
    if (!chain) {
        return -1;
    }

    nftnl_chain_set_u32(chain, NFTNL_CHAIN_FAMILY, family);
    nftnl_chain_set_str(chain, NFTNL_CHAIN_TABLE, table_name.c_str());
    nftnl_chain_set_str(chain, NFTNL_CHAIN_NAME, chain_name.c_str());

    int ret = nft_operate_chain(NFT_MSG_DELCHAIN, NLM_F_ACK, chain, nullptr);
    nftnl_chain_free(chain);
    return ret;
}

int
PicaConfigNetlinkSocket::nft_operate_rule(uint16_t type, uint16_t flags,
                                          struct nftnl_rule* rule,
                                          void* data) {
    struct nlmsghdr* nlh;
    struct mnl_nlmsg_batch* batch;
    vector<char> buf(MNL_SOCKET_BUFFER_SIZE);
    uint32_t family;
    int ret;

#if 0
    char ctx[4096] = {0};
    nftnl_rule_snprintf(ctx, sizeof(ctx), rule, 0, 0);
    PVP_LOG_INFO("nft_operate_rule:\n%s", ctx);
#endif

    uint32_t seq = nls_request_seq(10);
    batch = mnl_nlmsg_batch_start(buf.data(), buf.size());
    (void)nftnl_batch_begin((char*)mnl_nlmsg_batch_current(batch), seq++);
    (void)mnl_nlmsg_batch_next(batch);

    uint32_t rule_seq = seq;
    family = nftnl_rule_get_u32(rule, NFTNL_RULE_FAMILY);
    nlh = nftnl_rule_nlmsg_build_hdr((char*)mnl_nlmsg_batch_current(batch),
                                     type, family, flags, seq++);
    nftnl_rule_nlmsg_build_payload(nlh, rule);
    (void)mnl_nlmsg_batch_next(batch);

    (void)nftnl_batch_end((char*)mnl_nlmsg_batch_current(batch), seq++);
    (void)mnl_nlmsg_batch_next(batch);

    ret = nft_netlink_talk(mnl_nlmsg_batch_head(batch),
                           mnl_nlmsg_batch_size(batch),
                           buf.size(), rule_seq, data);
    mnl_nlmsg_batch_stop(batch);
    return ret;
}

struct nftnl_rule*
PicaConfigNetlinkSocket::nft_alloc_rule(NftRule& rule) {
    struct nftnl_rule* r = nftnl_rule_alloc();
    if (!r) {
        return nullptr;
    }

    const NftChain& chain = rule.chain();
    const NftTable& table = chain.table();
    (void)nftnl_rule_set_str(r, NFTNL_RULE_TABLE, table.table_name().c_str());
    (void)nftnl_rule_set_str(r, NFTNL_RULE_CHAIN, chain.chain_name().c_str());
    nftnl_rule_set_u32(r, NFTNL_RULE_FAMILY, table.family());
    if (rule.handle() != 0) {
        nftnl_rule_set_u64(r, NFTNL_RULE_HANDLE, rule.handle());
    }

    // build match
    const NftRuleMatch& match = rule.match();
    const FilterFlowerKey& key = match.flow.key;
    const FilterFlowerKey& mask = match.flow.mask;
    uint32_t xor_zero = 0;
    ipv6_addr_t ipv6_zero_addr = {0};

    if (match.iif > 0) {
        nftnl_rule_add_meta(r, NFT_REG_1, NFT_META_IIF);
        nftnl_rule_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &match.iif, sizeof(match.iif));
    }
    if (match.oif > 0) {
        nftnl_rule_add_meta(r, NFT_REG_1, NFT_META_OIF);
        nftnl_rule_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &match.oif, sizeof(match.oif));
    }
    if (match.mark_mask) {
        nftnl_rule_add_meta(r, NFT_REG_1, NFT_META_MARK);
        nftnl_rule_add_bitwise(r, NFT_REG_1, &match.mark_mask, &xor_zero, sizeof(uint32_t));
        uint32_t op = match.mark_cmp_op ? NFT_CMP_NEQ : NFT_CMP_EQ;
        nftnl_rule_add_cmp(r, NFT_REG_1, op, &xor_zero, sizeof(uint32_t));
    }

    if (!mac_t_same(mask.dst_mac, empty_mac_addr)) {
        nftnl_rule_add_payload(r, NFT_PAYLOAD_LL_HEADER, NFT_REG_1,
                               offsetof(struct ethhdr, h_dest), ETH_ALEN);
        if (!mac_t_same(mask.dst_mac, bcast_mac_addr)) {
            mac_t result;
            BpfSyntax::mac_and_mask(key.dst_mac, mask.dst_mac, result);
            nftnl_rule_add_bitwise(r, NFT_REG_1, mask.dst_mac, empty_mac_addr, ETH_ALEN);
            nftnl_rule_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, result, ETH_ALEN);
        } else {
            nftnl_rule_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, key.dst_mac, ETH_ALEN);
        }
    }
    if (!mac_t_same(mask.src_mac, empty_mac_addr)) {
        nftnl_rule_add_payload(r, NFT_PAYLOAD_LL_HEADER, NFT_REG_1,
                               offsetof(struct ethhdr, h_source), ETH_ALEN);
        if (!mac_t_same(mask.src_mac, bcast_mac_addr)) {
            mac_t result;
            BpfSyntax::mac_and_mask(key.src_mac, mask.src_mac, result);
            nftnl_rule_add_bitwise(r, NFT_REG_1, mask.src_mac, empty_mac_addr, ETH_ALEN);
            nftnl_rule_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, result, ETH_ALEN);
        } else {
            nftnl_rule_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, key.src_mac, ETH_ALEN);
        }
    }
    if (mask.vlan_id || mask.vlan_prio || key.eth_type) {
        uint16_t eth_type = htons(ETH_P_8021Q);
        nftnl_rule_add_payload(r, NFT_PAYLOAD_LL_HEADER, NFT_REG_1,
                               offsetof(struct ethhdr, h_proto), sizeof(eth_type));
        nftnl_rule_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &eth_type, sizeof(eth_type));

        if (mask.vlan_id || mask.vlan_prio) {
            uint16_t vlan_tci_mask = htons(((uint16_t)mask.vlan_prio) << 12 | mask.vlan_id);
            nftnl_rule_add_payload(r, NFT_PAYLOAD_LL_HEADER, NFT_REG_1, 14, sizeof(uint16_t));
            nftnl_rule_add_bitwise(r, NFT_REG_1, &vlan_tci_mask, &xor_zero, sizeof(uint16_t));

            auto iter = match.lookup_set.find(NftRuleMatch::LOOKUP_SET_VLAN_TCI);
            if (iter != match.lookup_set.end()) {
                nftnl_rule_add_lookup_set(r, NFT_REG_1, iter->second.c_str());
            } else {
                uint16_t vlan_tci = htons(((uint16_t)key.vlan_prio) << 12 | key.vlan_id) & vlan_tci_mask;
                nftnl_rule_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &vlan_tci, sizeof(uint16_t));
            }
        }

        if (key.eth_type) {
            eth_type = htons(key.eth_type);
            nftnl_rule_add_payload(r, NFT_PAYLOAD_LL_HEADER, NFT_REG_1, 16, sizeof(eth_type));
            nftnl_rule_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &eth_type, sizeof(eth_type));
        }
    }
    if (key.ip_proto) {
        nftnl_rule_add_meta(r, NFT_REG_1, NFT_META_L4PROTO);
        nftnl_rule_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &key.ip_proto, sizeof(uint8_t));
    }
    if (mask.ipv4_src) {
        uint32_t saddr = htonl(key.ipv4_src & mask.ipv4_src);
        nftnl_rule_add_payload(r, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
                               offsetof(struct iphdr, saddr), sizeof(uint32_t));
        if (mask.ipv4_src != 0xFFFFFFFF) {
            uint32_t saddr_mask = htonl(mask.ipv4_src);
            nftnl_rule_add_bitwise(r, NFT_REG_1, &saddr_mask, &xor_zero, sizeof(uint32_t));
        }
        nftnl_rule_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &saddr, sizeof(uint32_t));
    }
    if (mask.ipv4_dst) {
        uint32_t daddr = htonl(key.ipv4_dst & mask.ipv4_dst);
        nftnl_rule_add_payload(r, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1,
                               offsetof(struct iphdr, daddr), sizeof(uint32_t));
        if (mask.ipv4_dst != 0xFFFFFFFF) {
            uint32_t daddr_mask = htonl(mask.ipv4_dst);
            nftnl_rule_add_bitwise(r, NFT_REG_1, &daddr_mask, &xor_zero, sizeof(uint32_t));
        }
        nftnl_rule_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &daddr, sizeof(uint32_t));
    }
    if (!is_all_zeros(mask.ipv6_src, sizeof(ipv6_addr_t))) {
        nftnl_rule_add_payload(r, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1, 8, sizeof(ipv6_addr_t));
        if (!is_all_ones(mask.ipv6_src, sizeof(ipv6_addr_t))) {
            ipv6_addr_t result;
            BpfSyntax::ip6_and_mask(key.ipv6_src, mask.ipv6_src, result);
            nftnl_rule_add_bitwise(r, NFT_REG_1, mask.ipv6_src, ipv6_zero_addr, sizeof(ipv6_addr_t));
            nftnl_rule_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, result, sizeof(ipv6_addr_t));
        } else {
            nftnl_rule_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, key.ipv6_src, sizeof(ipv6_addr_t));
        }
    }
    if (!is_all_zeros(mask.ipv6_dst, sizeof(ipv6_addr_t))) {
        nftnl_rule_add_payload(r, NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1, 24, sizeof(ipv6_addr_t));
        if (!is_all_ones(mask.ipv6_dst, sizeof(ipv6_addr_t))) {
            ipv6_addr_t result;
            BpfSyntax::ip6_and_mask(key.ipv6_dst, mask.ipv6_dst, result);
            nftnl_rule_add_bitwise(r, NFT_REG_1, mask.ipv6_dst, ipv6_zero_addr, sizeof(ipv6_addr_t));
            nftnl_rule_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, result, sizeof(ipv6_addr_t));
        } else {
            nftnl_rule_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, key.ipv6_dst, sizeof(ipv6_addr_t));
        }
    }
    if (mask.l4_sport) {
        nftnl_rule_add_payload(r, NFT_PAYLOAD_TRANSPORT_HEADER, NFT_REG_1, 0, sizeof(uint16_t));
        if (mask.l4_sport != 0xFFFF) {
            uint16_t sport_mask = htons(mask.l4_sport);
            nftnl_rule_add_bitwise(r, NFT_REG_1, &sport_mask, &xor_zero, sizeof(uint16_t));
        }
        auto iter = match.lookup_set.find(NftRuleMatch::LOOKUP_SET_L4_SPORT);
        if (iter != match.lookup_set.end()) {
            nftnl_rule_add_lookup_set(r, NFT_REG_1, iter->second.c_str());
        } else {
            uint16_t sport = htons(key.l4_sport & mask.l4_sport);
            nftnl_rule_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &sport, sizeof(uint16_t));
        }
    }
    if (mask.l4_dport) {
        nftnl_rule_add_payload(r, NFT_PAYLOAD_TRANSPORT_HEADER, NFT_REG_1, 2, sizeof(uint16_t));
        if (mask.l4_dport != 0xFFFF) {
            uint16_t dport_mask = htons(mask.l4_dport);
            nftnl_rule_add_bitwise(r, NFT_REG_1, &dport_mask, &xor_zero, sizeof(uint16_t));
        }
        auto iter = match.lookup_set.find(NftRuleMatch::LOOKUP_SET_L4_DPORT);
        if (iter != match.lookup_set.end()) {
            nftnl_rule_add_lookup_set(r, NFT_REG_1, iter->second.c_str());
        } else {
            uint16_t dport = htons(key.l4_dport & mask.l4_dport);
            nftnl_rule_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &dport, sizeof(uint16_t));
        }
    }
    if (mask.icmp_type) {
        nftnl_rule_add_payload(r, NFT_PAYLOAD_TRANSPORT_HEADER, NFT_REG_1, 0, sizeof(uint8_t));
        if (mask.icmp_type != 0xFF) {
            uint8_t icmp_type = key.icmp_type & mask.icmp_type;
            nftnl_rule_add_bitwise(r, NFT_REG_1, &mask.icmp_type, &xor_zero, sizeof(uint8_t));
            nftnl_rule_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &icmp_type, sizeof(uint8_t));
        } else {
            nftnl_rule_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &key.icmp_type, sizeof(uint8_t));
        }
    }
    if (mask.icmp_code) {
        nftnl_rule_add_payload(r, NFT_PAYLOAD_TRANSPORT_HEADER, NFT_REG_1, 1, sizeof(uint8_t));
        if (mask.icmp_code != 0xFF) {
            uint8_t icmp_code = key.icmp_code & mask.icmp_code;
            nftnl_rule_add_bitwise(r, NFT_REG_1, &mask.icmp_code, &xor_zero, sizeof(uint8_t));
            nftnl_rule_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &icmp_code, sizeof(uint8_t));
        } else {
            nftnl_rule_add_cmp(r, NFT_REG_1, NFT_CMP_EQ, &key.icmp_code, sizeof(uint8_t));
        }
    }

    // build action
    const NftRuleAction& action = rule.action();
    if (action.counter) {
        nftnl_rule_add_counter(r);
    }
    if (action.mark != 0xFFFFFFFF) {
        nftnl_rule_add_meta_stmt(r, NFT_REG_1, NFT_META_MARK, action.mark);
    }
    if (action.dup_ifindex > 0) {
        nftnl_rule_add_dup(r, NFT_REG_1, action.dup_ifindex);
    } else if (action.fwd_ifindex > 0) {
        nftnl_rule_add_fwd(r, NFT_REG_1, action.fwd_ifindex);
    }
    if (action.verdict >= 0) {
        nftnl_rule_add_verdict(r, action.verdict);
    }

    return r;
}

int
PicaConfigNetlinkSocket::nft_add_rule(NftRule& rule) {
    struct nftnl_rule* r = nft_alloc_rule(rule);
    if (!r) {
        return -1;
    }

#if 0
    char buf[2048] = {0};
    nftnl_rule_snprintf(buf, sizeof buf, r, 0, 0);
    PNLS_CONFIG_LOG_TRACE("[%s]%s: %s", _MODULE, __FUNCTION__, buf);
#endif

    uint64_t handle;
    int ret = nft_operate_rule(NFT_MSG_NEWRULE,
                               NLM_F_APPEND | NLM_F_CREATE | NLM_F_ACK | NLM_F_ECHO,
                               r, &handle);
    if (ret == 0) {
        rule.set_handle(handle);
    }
    nftnl_rule_free(r);
    return ret;
}

int
PicaConfigNetlinkSocket::nft_replace_rule(NftRule& rule) {
    struct nftnl_rule* r = nft_alloc_rule(rule);
    if (!r) {
        return -1;
    }

#if 0
    char buf[2048] = {0};
    nftnl_rule_snprintf(buf, sizeof buf, r, 0, 0);
    PNLS_CONFIG_LOG_TRACE("[%s]%s: %s", _MODULE, __FUNCTION__, buf);
#endif

    int ret = nft_operate_rule(NFT_MSG_NEWRULE,
                               NLM_F_REPLACE | NLM_F_ACK,
                               r, nullptr);
    nftnl_rule_free(r);
    return ret;
}

int
PicaConfigNetlinkSocket::nft_del_rule(uint32_t family, const string& table_name,
                                      const string& chain_name, uint64_t handle) {
    struct nftnl_rule* rule = nftnl_rule_alloc();
    if (!rule) {
        return -1;
    }

    (void)nftnl_rule_set_str(rule, NFTNL_RULE_TABLE, table_name.c_str());
    (void)nftnl_rule_set_str(rule, NFTNL_RULE_CHAIN, chain_name.c_str());
    nftnl_rule_set_u32(rule, NFTNL_RULE_FAMILY, family);
    nftnl_rule_set_u64(rule, NFTNL_RULE_HANDLE, handle);

    int ret = nft_operate_rule(NFT_MSG_DELRULE, NLM_F_ACK, rule, nullptr);
    nftnl_rule_free(rule);
    return ret;
}

int
PicaConfigNetlinkSocket::nft_del_rule(const NftRule& rule) {
    const NftChain& chain = rule.chain();
    const NftTable& table = chain.table();
    return nft_del_rule(table.family(), table.table_name(),
                        chain.chain_name(), rule.handle());
}

void
PicaConfigNetlinkSocket::nftnl_rule_add_immediate(struct nftnl_rule* r,
                                                  uint32_t dreg,
                                                  const void* data,
                                                  uint32_t data_len) {
    struct nftnl_expr* e = nftnl_expr_alloc("immediate");
    nftnl_expr_set_u32(e, NFTNL_EXPR_IMM_DREG, dreg);
    if (dreg == NFT_REG_VERDICT && data_len == sizeof(uint32_t)) {
        uint32_t verdict = *(static_cast<const uint32_t*>(data));
        nftnl_expr_set_u32(e, NFTNL_EXPR_IMM_VERDICT, verdict);
    } else {
        nftnl_expr_set_data(e, NFTNL_EXPR_IMM_DATA, data, data_len);
    }
    nftnl_rule_add_expr(r, e);
}

void
PicaConfigNetlinkSocket::nftnl_rule_add_verdict(struct nftnl_rule* r,
                                                int verdict) {
    nftnl_rule_add_immediate(r, NFT_REG_VERDICT, &verdict, sizeof(verdict));
}

void
PicaConfigNetlinkSocket::nftnl_rule_add_bitwise(struct nftnl_rule* r,
                                                uint32_t dreg,
                                                const void* mask,
                                                const void* xor_,
                                                uint32_t len) {
    struct nftnl_expr* e = nftnl_expr_alloc("bitwise");
    nftnl_expr_set_u32(e, NFTNL_EXPR_BITWISE_SREG, dreg);
    nftnl_expr_set_u32(e, NFTNL_EXPR_BITWISE_DREG, dreg);
    // nftnl_expr_set_u32(e, NFTNL_EXPR_BITWISE_OP, NFT_BITWISE_BOOL);
    nftnl_expr_set_u32(e, NFTNL_EXPR_BITWISE_LEN, len);
    (void)nftnl_expr_set(e, NFTNL_EXPR_BITWISE_MASK, mask, len);
    (void)nftnl_expr_set(e, NFTNL_EXPR_BITWISE_XOR, xor_, len);
    nftnl_rule_add_expr(r, e);
}

void
PicaConfigNetlinkSocket::nftnl_rule_add_meta(struct nftnl_rule* r,
                                             uint32_t dreg,
                                             uint32_t meta_key) {
    struct nftnl_expr* e = nftnl_expr_alloc("meta");
    nftnl_expr_set_u32(e, NFTNL_EXPR_META_DREG, dreg);
    nftnl_expr_set_u32(e, NFTNL_EXPR_META_KEY, meta_key);
    nftnl_rule_add_expr(r, e);
}

void
PicaConfigNetlinkSocket::nftnl_rule_add_meta_stmt(struct nftnl_rule* r,
                                                  uint32_t sreg,
                                                  uint32_t meta_key,
                                                  uint32_t data) {
    nftnl_rule_add_immediate(r, NFTNL_EXPR_IMM_DREG, &data, sizeof(data));
    struct nftnl_expr* e = nftnl_expr_alloc("meta");
    nftnl_expr_set_u32(e, NFTNL_EXPR_META_SREG, sreg);
    nftnl_expr_set_u32(e, NFTNL_EXPR_META_KEY, meta_key);
    nftnl_rule_add_expr(r, e);
}

void
PicaConfigNetlinkSocket::nftnl_rule_add_payload(struct nftnl_rule* r,
                                                uint32_t base,
                                                uint32_t dreg,
                                                uint32_t offset,
                                                uint32_t len) {
    struct nftnl_expr* e = nftnl_expr_alloc("payload");
    nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_BASE, base);
    nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_DREG, dreg);
    nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_OFFSET, offset);
    nftnl_expr_set_u32(e, NFTNL_EXPR_PAYLOAD_LEN, len);
    nftnl_rule_add_expr(r, e);
}

void
PicaConfigNetlinkSocket::nftnl_rule_add_cmp(struct nftnl_rule* r,
                                            uint32_t sreg,
                                            uint32_t op,
                                            const void* data,
                                            uint32_t data_len) {
    struct nftnl_expr* e = nftnl_expr_alloc("cmp");
    nftnl_expr_set_u32(e, NFTNL_EXPR_CMP_SREG, sreg);
    nftnl_expr_set_u32(e, NFTNL_EXPR_CMP_OP, op);
    (void)nftnl_expr_set(e, NFTNL_EXPR_CMP_DATA, data, data_len);
    nftnl_rule_add_expr(r, e);
}

void
PicaConfigNetlinkSocket::nftnl_rule_add_counter(struct nftnl_rule* r) {
    struct nftnl_expr* e = nftnl_expr_alloc("counter");
    nftnl_rule_add_expr(r, e);
}

void
PicaConfigNetlinkSocket::nftnl_rule_add_dup(struct nftnl_rule* r,
                                            uint32_t dreg, uint32_t oif) {
    nftnl_rule_add_immediate(r, NFTNL_EXPR_IMM_DREG, &oif, sizeof(oif));
    struct nftnl_expr* e = nftnl_expr_alloc("dup");
    nftnl_expr_set_u32(e, NFTNL_EXPR_DUP_SREG_DEV, dreg);
    nftnl_rule_add_expr(r, e);
}

void
PicaConfigNetlinkSocket::nftnl_rule_add_fwd(struct nftnl_rule* r,
                                            uint32_t dreg, uint32_t oif) {
    nftnl_rule_add_immediate(r, NFTNL_EXPR_IMM_DREG, &oif, sizeof(oif));
    struct nftnl_expr* e = nftnl_expr_alloc("fwd");
    nftnl_expr_set_u32(e, NFTNL_EXPR_FWD_SREG_DEV, dreg);
    nftnl_rule_add_expr(r, e);
}

void
PicaConfigNetlinkSocket::nftnl_rule_add_lookup_set(struct nftnl_rule* r,
                                                   uint32_t sreg,
                                                   const char* set_name) {
    struct nftnl_expr* e = nftnl_expr_alloc("lookup");
    nftnl_expr_set_u32(e, NFTNL_EXPR_LOOKUP_SREG, sreg);
    (void)nftnl_expr_set_str(e, NFTNL_EXPR_LOOKUP_SET, set_name);
    nftnl_rule_add_expr(r, e);
}

int
PicaConfigNetlinkSocket::nft_operate_set(uint16_t type, uint16_t flags,
                                         struct nftnl_set* s, void* data) {
    struct nlmsghdr* nlh;
    struct mnl_nlmsg_batch* batch;
    vector<char> buf(MNL_SOCKET_BUFFER_SIZE);
    int ret;

    uint32_t seq = nls_request_seq(10);
    batch = mnl_nlmsg_batch_start(buf.data(), buf.size());
    (void)nftnl_batch_begin((char*)mnl_nlmsg_batch_current(batch), seq++);
    (void)mnl_nlmsg_batch_next(batch);

    uint32_t set_seq = seq;
    uint32_t family = nftnl_set_get_u32(s, NFTNL_SET_FAMILY);
    nlh = nftnl_set_nlmsg_build_hdr((char*)mnl_nlmsg_batch_current(batch),
                                    type, family, flags, seq++);
    if (type == NFT_MSG_NEWSETELEM || type == NFT_MSG_DELSETELEM) {
        nftnl_set_elems_nlmsg_build_payload(nlh, s);
    } else {
        nftnl_set_nlmsg_build_payload(nlh, s);
    }
    (void)mnl_nlmsg_batch_next(batch);

    (void)nftnl_batch_end((char*)mnl_nlmsg_batch_current(batch), seq++);
    (void)mnl_nlmsg_batch_next(batch);

    ret = nft_netlink_talk(mnl_nlmsg_batch_head(batch),
                           mnl_nlmsg_batch_size(batch),
                           buf.size(), set_seq, data);
    mnl_nlmsg_batch_stop(batch);
    return ret;
}

int
PicaConfigNetlinkSocket::nft_add_set(NftSet& nftset) {
    struct nftnl_set* s = nftnl_set_alloc();
    if (!s) {
        return -ENOMEM;
    }

    (void)nftnl_set_set_str(s, NFTNL_SET_TABLE, nftset.table().table_name().c_str());
    (void)nftnl_set_set_str(s, NFTNL_SET_NAME, nftset.name().c_str());
    nftnl_set_set_u32(s, NFTNL_SET_FAMILY, nftset.table().family());
    nftnl_set_set_u32(s, NFTNL_SET_KEY_LEN, nftset.key_len());
    nftnl_set_set_u32(s, NFTNL_SET_KEY_TYPE, nftset.key_type());
    nftnl_set_set_u32(s, NFTNL_SET_ID, nftset.id());

    uint64_t handle;
    int ret = nft_operate_set(NFT_MSG_NEWSET, NLM_F_CREATE | NLM_F_ACK | NLM_F_ECHO,
                              s, &handle);
    if (ret == 0) {
        nftset.set_handle(handle);
    }
    nftnl_set_free(s);
    return ret;
}

int
PicaConfigNetlinkSocket::nft_del_set(const NftSet& nftset) {
    struct nftnl_set* s = nftnl_set_alloc();
    if (!s) {
        return -ENOMEM;
    }

    (void)nftnl_set_set_str(s, NFTNL_SET_TABLE, nftset.table().table_name().c_str());
    nftnl_set_set_u32(s, NFTNL_SET_FAMILY, nftset.table().family());
    if (nftset.handle() > 0) {
        nftnl_set_set_u64(s, NFTNL_SET_HANDLE, nftset.handle());
    } else {
        (void)nftnl_set_set_str(s, NFTNL_SET_NAME, nftset.name().c_str());
    }

    int ret = nft_operate_set(NFT_MSG_DELSET, NLM_F_ACK, s, nullptr);
    nftnl_set_free(s);
    return ret;
}

int
PicaConfigNetlinkSocket::nft_set_add_elem_keys(const NftSet& nftset,
                                               const list<NftSetElemKey>& keys) {
    struct nftnl_set* s = nftnl_set_alloc();
    if (!s) {
        return -ENOMEM;
    }
    (void)nftnl_set_set_str(s, NFTNL_SET_TABLE, nftset.table().table_name().c_str());
    (void)nftnl_set_set_str(s, NFTNL_SET_NAME, nftset.name().c_str());
    nftnl_set_set_u32(s, NFTNL_SET_FAMILY, nftset.table().family());
    nftnl_set_set_u32(s, NFTNL_SET_ID, nftset.id());
    for (auto& key : keys) {
        struct nftnl_set_elem* e = nftnl_set_elem_alloc();
        if (!e) {
            nftnl_set_free(s);
            return -ENOMEM;
        }
        nftnl_set_elem_set(e, NFTNL_SET_ELEM_KEY, key.data(), key.data_len());
        nftnl_set_elem_add(s, e);
    }
    int ret = nft_operate_set(NFT_MSG_NEWSETELEM, NLM_F_CREATE | NLM_F_ACK,
                              s, nullptr);
    nftnl_set_free(s);
    return ret;
}

int
PicaConfigNetlinkSocket::nft_set_del_elem_keys(const NftSet& nftset,
                                               const list<NftSetElemKey>& keys) {
    struct nftnl_set* s = nftnl_set_alloc();
    if (!s) {
        return -ENOMEM;
    }
    (void)nftnl_set_set_str(s, NFTNL_SET_TABLE, nftset.table().table_name().c_str());
    (void)nftnl_set_set_str(s, NFTNL_SET_NAME, nftset.name().c_str());
    nftnl_set_set_u32(s, NFTNL_SET_FAMILY, nftset.table().family());
    for (auto& key : keys) {
        struct nftnl_set_elem* e = nftnl_set_elem_alloc();
        if (!e) {
            nftnl_set_free(s);
            return -ENOMEM;
        }
        nftnl_set_elem_set(e, NFTNL_SET_ELEM_KEY, key.data(), key.data_len());
        nftnl_set_elem_add(s, e);
    }
    int ret = nft_operate_set(NFT_MSG_DELSETELEM, NLM_F_ACK, s, nullptr);
    nftnl_set_free(s);
    return ret;
}

int
PicaConfigNetlinkSocket::tc_add_clsact_qdisc(int ifindex,
                                             uint32_t ingress_block,
                                             uint32_t egress_block) {
    struct nlmsghdr* nlh;
    vector<char> buf(MNL_SOCKET_BUFFER_SIZE);
    struct tcmsg* tcm;

    uint32_t seq = nls_request_seq(1);
    nlh = mnl_nlmsg_put_header(buf.data());
    nlh->nlmsg_type = RTM_NEWQDISC;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    nlh->nlmsg_seq = seq;

    tcm = (struct tcmsg*)mnl_nlmsg_put_extra_header(nlh, sizeof(*tcm));
    tcm->tcm_family = AF_UNSPEC;
    tcm->tcm_ifindex = ifindex;
    tcm->tcm_parent = TC_H_CLSACT;
    tcm->tcm_handle = TC_H_MAKE(TC_H_CLSACT, 0);

    mnl_attr_put_strz(nlh, TCA_KIND, "clsact");
    if (ingress_block) {
        mnl_attr_put_u32(nlh, TCA_INGRESS_BLOCK, ingress_block);
    }
    if (egress_block) {
        mnl_attr_put_u32(nlh, TCA_EGRESS_BLOCK, egress_block);
    }

    int ret = nls_route_talk(buf.data(), nlh->nlmsg_len, buf.size(), seq, nullptr);
    return ret;
}

