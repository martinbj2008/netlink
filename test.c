/**
	Done by zhangjunwei
*/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <linux/genetlink.h>

#include "module/martin_netlink.h"

#define GENLMSG_DATA(glh)	((void *)(NLMSG_DATA(glh) + GENL_HDRLEN))
#define GENLMSG_PAYLOAD(glh)	(NLMSG_PAYLOAD(glh, 0) - GENL_HDRLEN)
#define NLA_DATA(na)		((void *)((char*)(na) + NLA_HDRLEN))
#define NLA_PAYLOAD_LEN(len)	(len - NLA_HDRLEN)

/* Maximum size of response requested or message sent */
#define MAX_MSG_SIZE	2048

int		nl_sd;
uint32_t	pid;
uint32_t	nl_grp_id;
uint16_t	nl_family_id;

struct msgtemplate {
	struct nlmsghdr n __attribute__ ((aligned(NLMSG_ALIGNTO)));
	union {
		struct {
			struct genlmsghdr g __attribute__
						((aligned(NLMSG_ALIGNTO)));
			char buf[MAX_MSG_SIZE];
		};
		struct nlmsgerr nlerr;
	};
};

int send_cmd(int sd, __u16 nlmsg_type, __u8 genl_cmd, __u16 nla_type,
	void *nla_data, int nla_len, uint16_t flags)
{
	struct nlattr *na;
	struct sockaddr_nl nladdr;
	int r, buflen;
	char *buf;

	struct msgtemplate msg;

	msg.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	msg.n.nlmsg_type = nlmsg_type;
	msg.n.nlmsg_flags = flags;
	msg.n.nlmsg_seq = 0;
	msg.n.nlmsg_pid = pid;
	msg.g.cmd = genl_cmd;
	msg.g.version = 0x1;
	na = (struct nlattr *) GENLMSG_DATA(&msg);
	na->nla_type = nla_type;
	na->nla_len = nla_len + NLA_HDRLEN;
	memcpy(NLA_DATA(na), nla_data, nla_len);
	msg.n.nlmsg_len += NLMSG_ALIGN(na->nla_len);

	buf = (char *) &msg;
	buflen = msg.n.nlmsg_len ;
	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;

	while ((r = sendto(sd, buf, buflen, 0, (struct sockaddr *) &nladdr,
			   sizeof(nladdr))) < buflen) {
		printf("sending (r=%d)\n", r);
		if (r > 0) {
			buf += r;
			buflen -= r;
		} else if (errno != EAGAIN)
			return r;
	}
	printf("msg sent (r=%d)\n", r);

	return 0;
}

static void
parse_groups(struct nlattr *na, int tot_len)
{
	int	len;
	int	grp_len;
	int	aggr_len;
	struct nlattr *grp_na;

	len = 0;
	while (len < tot_len) {
		len += NLA_ALIGN(na->nla_len);
		printf("grp #%02d\n", na->nla_type);
		if (na->nla_type > 1) {
		       	/* only one group supported for now */
			na = (struct nlattr *) ((char *) na + len);
			continue;
		}

		aggr_len = NLA_PAYLOAD_LEN(na->nla_len);
		grp_na = (struct nlattr *) NLA_DATA(na);
		grp_len = 0;
		while (grp_len < aggr_len) {
			grp_len += NLA_ALIGN(grp_na->nla_len);
			switch (grp_na->nla_type) {
			case CTRL_ATTR_MCAST_GRP_ID:
				nl_grp_id = *(uint32_t *) NLA_DATA(grp_na);
					printf("grp id = %d\n",
						nl_grp_id);

				break;
			case CTRL_ATTR_MCAST_GRP_NAME:
				printf("grp name %s\n", (char *)NLA_DATA(grp_na));
				break;
			default:
				printf("Unknown grp nested attr %d\n", 	grp_na->nla_type);
				break;
			}
			grp_na = (struct nlattr *) ((char *) grp_na + grp_len);
		}
		na = (struct nlattr *) ((char *) na + len);
	}
}

int get_family_id(int sd)
{
	struct msgtemplate msg;
	int	len;
	int	recv_len;
	int	rc;
	struct nlattr *na;

	rc = send_cmd(sd, GENL_ID_CTRL, CTRL_CMD_GETFAMILY,
			CTRL_ATTR_FAMILY_NAME, MARTIN_NETLINK_NL_FAMILY_NAME,
			strlen(MARTIN_NETLINK_NL_FAMILY_NAME)+1, NLM_F_REQUEST);
	if (rc < 0) {
		printf("Error sending family cmd (%d:%s)\n",
			errno, strerror(errno));
		return -1;
	}
	recv_len = recv(sd, &msg, sizeof(msg), 0);
	if (msg.n.nlmsg_type == NLMSG_ERROR) {
		printf("Error: recv family error msg\n");
		return -1;
	}
	if (recv_len < 0) {
		printf("Error: recv family (%d)\n", recv_len);
		return -1;
	}
	if (!NLMSG_OK((&msg.n), recv_len)) {
		printf("Error: recv family msg nok\n");
		return -1;
	}

	len = 0;
	recv_len = GENLMSG_PAYLOAD(&msg.n);
	na = (struct nlattr *) GENLMSG_DATA(&msg);
	while (len < recv_len) {
		len += NLA_ALIGN(na->nla_len);
		switch (na->nla_type) {
		case CTRL_ATTR_FAMILY_ID:
			nl_family_id = *(uint16_t *) NLA_DATA(na);
			printf("family id:%d\n", nl_family_id);
			break;
		case CTRL_ATTR_MCAST_GROUPS:
			parse_groups(NLA_DATA(na),
					NLA_PAYLOAD_LEN(na->nla_len));
			break;
		case CTRL_ATTR_FAMILY_NAME:
		case CTRL_ATTR_VERSION:
		case CTRL_ATTR_HDRSIZE:
		case CTRL_ATTR_MAXATTR:
		case CTRL_ATTR_OPS:
			printf("Unused family attr %d\n", na->nla_type);
			break;
		default:
			printf("Unknown family attr %d\n", na->nla_type);
			break;
		}
		na = (struct nlattr *) (GENLMSG_DATA(&msg) + len);
	}

	return nl_family_id;
}

int open_nl_socket(void)
{
	int fd;
	struct sockaddr_nl local;

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (fd < 0) {
		printf("Error opening socket (%d)\n", errno);
		return -1;
	}
	printf("fd:%d\n", fd);

	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;

	if (bind(fd, (struct sockaddr *) &local, sizeof(local)) < 0) {
		printf("Error binding socket (%d)\n", errno);
		close(fd);
		return -1;
	}
	printf("bind done\n");

	/* Retrieve netlink family Id */
	nl_family_id = get_family_id(fd);
	if (nl_family_id < 0) {
		printf("Error: Could not retreive netlink family id\n");
		close(fd);
		return -1;
	}

	return fd;
}

int wait_packets(int sd)
{
	int flags;
	int ret;
	int recv_len;
	int len;
	int err;
	fd_set rfds;
	struct nlmsgerr *nl_err;
	struct timeval tv;
	struct nlattr *na;
	struct msgtemplate msg;
	char *skb_data;

	flags = fcntl(sd, F_GETFL);
	fcntl(sd, F_SETFL, flags | O_NONBLOCK);

	err = 0;
	do {
		FD_ZERO(&rfds);
		FD_SET(sd, &rfds);

		/* Monitoring, no timeout */
		ret = select(sd+1, &rfds, NULL, NULL, NULL);

		if (ret < 0) {
			if (errno == EINTR)
				continue;
			perror("select()");
			err = ret;
			break;
		} else if (ret == 0) {
			printf("No answer within %lu seconds.\n", tv.tv_sec);
			err = -ETIMEDOUT;
			break;
		}
		if (!FD_ISSET(sd, &rfds))
			continue;

		recv_len = recv(nl_sd, &msg, sizeof(msg), 0);
		printf("received %d bytes\n", recv_len);
		if (recv_len < 0) {
			printf("nonfatal reply error: errno %d\n", errno);
			err = errno;
			break;
		}
		if (msg.n.nlmsg_type == NLMSG_ERROR ||
		    !NLMSG_OK((&msg.n), recv_len)) {
			nl_err = NLMSG_DATA(&msg);
			printf("fatal reply error,  errno %d\n", nl_err->error);
			err = nl_err->error;
			break;
		}

		printf("nlmsghdr size=%zu, nlmsg_len=%d, recv_len=%d\n",
			sizeof(struct nlmsghdr), msg.n.nlmsg_len, recv_len);

		recv_len = GENLMSG_PAYLOAD(&msg.n);

		na = (struct nlattr *) GENLMSG_DATA(&msg);

		len = 0;
		while (len < recv_len) {
			len += NLA_ALIGN(na->nla_len);
			switch (na->nla_type) {
			case MARTIN_NETLINK_TYPE_HTTP_DATA:
				skb_data = NLA_DATA(na);
				printf("skb_data:%s, len:%d\n", skb_data, len);
				break;
			default:
				printf("Unknown nla_type %d\n", na->nla_type);
				break;
			}
			na = (struct nlattr *) (GENLMSG_DATA(&msg) + len);
		}
		printf("\n");
	} while (1);

	/* restore previous attributes */
	fcntl(sd, F_SETFL, flags);
	return err;
}

int main(int argc, char *argv[])
{
	pid = getpid();
	nl_sd = open_nl_socket();
	if (nl_sd < 0) {
		printf("%s: failed to create nl socket\n", __func__);
		exit(EXIT_FAILURE);
	}

#ifndef SOL_NETLINK
/* normally defined in bits/socket.h but not available in some
 * toolchains.
 */
#define SOL_NETLINK 270
#endif
	/* Monitor netlink socket, we should never return from this */
	setsockopt(nl_sd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
		&nl_grp_id, sizeof(nl_grp_id));
	wait_packets(nl_sd);

	close(nl_sd);
	return 0;
}
