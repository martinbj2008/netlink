/*
 * Martin netlink module
 */

#include <linux/module.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <net/genetlink.h>

#include <net/ip.h>
#include <net/tcp.h>
#include <net/netfilter/nf_conntrack.h>
#include "martin_netlink.h"

#define MODULE_NAME "MartinNetlink"

static struct sk_buff_head martin_skb_list;
static struct work_struct martin_netlink_work;


struct genl_multicast_group grp = {
		.name	= MARTIN_NETLINK_NL_GRP_NAME,
};

struct genl_ops ops = {
	.cmd	= MARTIN_NETLINK_CMD_SKB_DUMP,
	.flags	= 0,
	.policy	= NULL,
	.doit	= NULL,
	.dumpit	= NULL,
	.done	= NULL,
};

struct genl_family family = {
	.id	= GENL_ID_GENERATE,
	.name	= MARTIN_NETLINK_NL_FAMILY_NAME,
	.version = 1,
	.maxattr = MARTIN_NETLINK_ATTR_MAX,
};

static void martin_netlink_notify(struct genl_multicast_group *nl_grp,
	struct sk_buff *orig_skb)
{
	int ret;
	int len;
	void	*hdr;
	struct sk_buff	*skb;

	skb = nlmsg_new(256 + orig_skb->len, GFP_KERNEL);
	if (!skb)
		return;

	hdr = genlmsg_put(skb, 0, 0, &family, 0, MARTIN_NETLINK_CMD_SKB_DUMP);
	if (!hdr)
		goto fail_fill;

	/* todo unlinear */
	len = skb_tailroom(skb);
	if (len > orig_skb->len)
		len = orig_skb->len;
	else
		printk(KERN_DEBUG "%s: skb tailroom is no enough(%d) !!\n",
			__func__, orig_skb->len);

	if (nla_put(skb, MARTIN_NETLINK_TYPE_HTTP_DATA,
	    orig_skb->len, orig_skb->data))
		goto fail_fill;

	if (genlmsg_end(skb, hdr) < 0)
		goto fail_fill;

	ret = genlmsg_multicast_allns(skb, 0, nl_grp->id, GFP_KERNEL);

	if (ret && ret != -ESRCH) {
		printk(KERN_DEBUG "%s: Error notifying group (%d)\n",
			__func__, ret);
		nlmsg_free(skb);
	}
	return;

fail_fill:
	printk(KERN_DEBUG "%s: Failed to fill nl_attr.\n", 	__func__);
	nlmsg_free(skb);
	return;
}

void martin_netlink_broadcast(char* data, uint16_t len)
{
	uint16_t size = (len + 255) & 0xFF00;
	struct sk_buff *new_skb = alloc_skb(size, GFP_ATOMIC);

	if (!new_skb)
		return;
	skb_put(new_skb, len);
	memcpy(new_skb->data, data, len);
	printk(KERN_DEBUG "%s: send:%d bytes\n", __func__, len);

	local_bh_disable();
	skb_queue_tail(&martin_skb_list, new_skb);
	local_bh_enable();
	schedule_work(&martin_netlink_work);

	return;
}
EXPORT_SYMBOL(martin_netlink_broadcast);

static void martin_netlink_task(struct work_struct *work)
{
	struct sk_buff *skb;

	do {
		local_bh_disable();
		skb = skb_dequeue(&martin_skb_list);
		local_bh_enable();
		if (skb) {
			martin_netlink_notify(&grp, skb);
			kfree_skb(skb);
		}
	} while (skb != NULL);

	return;
}

#define  HTTP_GET_SIZE	4
#define  HTTP_HOST_PREFIX   "Host: "
#define HTTP_HOST_PREFIX_LEN	6
static unsigned int martin_test_hook(unsigned int hooknum,
	struct sk_buff *skb, const struct net_device *in,
	const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	struct iphdr *iph;
	struct tcphdr *th;
	uint8_t *http;
	int pos;
	char *data;

	int len;
	uint8_t http_get_str[HTTP_GET_SIZE] = {'G', 'E', 'T', ' '};

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP)
		return NF_ACCEPT;

	if (!pskb_may_pull(skb, iph->ihl*4 + sizeof(struct tcphdr)))
		return NF_ACCEPT;

	th = (struct tcphdr *) ((uint8_t *)iph + iph->ihl*4);
	if (th->dest != htons(80))
		return NF_ACCEPT;

	http = (uint8_t *)th + th->doff*4;
	if (skb->len <= http + HTTP_GET_SIZE - (uint8_t *)iph)
		return NF_ACCEPT;
	if (memcmp(http, http_get_str, HTTP_GET_SIZE))
		return NF_ACCEPT;
	//assume 256 is enough
	len = skb->len < 256 ? skb->len : 256;
	if (!pskb_may_pull(skb, len))
		return NF_ACCEPT;

	data = skb->data;
	pos = 0;
	len -= HTTP_HOST_PREFIX_LEN;
	while (pos < len) {
		if (memcmp(data + pos, HTTP_HOST_PREFIX, HTTP_HOST_PREFIX_LEN)) {
			pos++;
			continue;
		}
		break;
	}

	if (pos >= len)
		return NF_ACCEPT;
	data += pos + HTTP_HOST_PREFIX_LEN;
	len -= pos;
	pos = 0;
	while (pos < len - 1) {
		if (data[pos] == 0x0d) {
			martin_netlink_broadcast(data, pos);
			break;
		}
		pos++;
	}

	return NF_ACCEPT;
}

static struct nf_hook_ops martin_netlink_test_ops[] __read_mostly = {
	{
		.hook     = martin_test_hook,
		.owner    = THIS_MODULE,
		.pf       = NFPROTO_IPV4,
		.hooknum  = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_FIRST, //NF_IP_PRI_CONNTRACK_CONFIRM - 1,
	},
	{
		.hook     = martin_test_hook,
		.owner    = THIS_MODULE,
		.pf       = NFPROTO_IPV4,
		.hooknum  = NF_INET_LOCAL_OUT,
		.priority = NF_IP_PRI_FIRST, //NF_IP_PRI_CONNTRACK_CONFIRM - 1,
	},

};

static int __init martin_netlink_init(void)
{
	int ret;

	skb_queue_head_init(&martin_skb_list);

	/* register the new family and all opertations but the first one */
	ret = __genl_register_family(&family);
	if (ret) {
		printk(KERN_CRIT "%s: Could not register netlink family (%d)\n",
				__func__, ret);
		return ret;
	}

	ret = genl_register_ops(&family, &ops);
	if (ret) {
		printk(KERN_CRIT "%s: Could not register netlink ops (%d)\n",
				__func__, ret);
	}
	ret = genl_register_mc_group(&family, &grp);
	if (ret) {
		printk(KERN_CRIT "%s: Could not register netlink grp (%d)\n",
				__func__, ret);
	}

	INIT_WORK(&martin_netlink_work, martin_netlink_task);

	nf_register_hooks(martin_netlink_test_ops, ARRAY_SIZE(martin_netlink_test_ops));

	printk(KERN_DEBUG "Module %s initialized\n", MODULE_NAME);

	return 0;
}

static void __exit martin_netlink_exit(void)
{
	nf_unregister_hooks(martin_netlink_test_ops, ARRAY_SIZE(martin_netlink_test_ops));

	skb_queue_purge(&martin_skb_list);
	flush_work(&martin_netlink_work);
	genl_unregister_family(&family);
	printk(KERN_DEBUG "Module %s exit\n", MODULE_NAME);
}

module_init(martin_netlink_init);
module_exit(martin_netlink_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Zhangjunwei");
MODULE_DESCRIPTION("Netlink kernel module for Linux");
