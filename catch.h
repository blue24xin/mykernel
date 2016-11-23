#ifndef SOCKFILTER_H_H
#define SOCKFILTER_H_H

struct check_packet
{
	int		saddr;
	short	dport;
	char	flags;
	int		len;
	char	*buf;
};

#endif
