#include <linux/module.h>
#include <linux/init.h>
#include <net/netlink.h>
#include <linux/netfilter_ipv4.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/tcp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/delay.h>
#include <linux/workqueue.h>
#include <linux/kthread.h>
#include <linux/err.h>
#include <linux/icmp.h>
#include <linux/netfilter.h>
MODULE_LICENSE("Dual BSD/GPL");

	
#define ETH "eth1"

unsigned char SMAC[ETH_ALEN];
unsigned char DMAC[ETH_ALEN];

static char *mod_name = "module";
module_param(mod_name,charp,0);

char	*ipaddr	= NULL;
char	*nextip = NULL;
char 	*nextmac = NULL;
unsigned char mark[20] = {0x01,0x23,0x45,0x98,0x00,0x00,0x00,0x00,
				   0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D};
#pragma pack(1)
struct net_icmp_t
{
	struct ethhdr	eth;
	struct iphdr	iph;
	struct icmphdr	icmph;
};
#pragma pack(1)
struct net_tcp_t
{
	struct ethhdr	eth;
	struct iphdr	iph;
	struct tcphdr 	tcph;
};

unsigned short cal_chksum(unsigned short *add, int len)
{
	int nleft=len;
	int sum=0;
	unsigned short *w=add;
	unsigned short answer=0;
	
	while(nleft>1)
	{
		sum+=*w++;
		nleft-=2;
	}
	if( nleft==1)
	{
		*(unsigned char *)(&answer)=*(unsigned char *)w;
		sum+=answer;
	}
	sum=(sum>>16)+(sum&0xffff);
	sum+=(sum>>16);
	answer=~sum;
	return answer;

}
//read file
int readicmpfile(char * read_buf, int *len)
{
#define MY_FILE		"/opt/webcatch/ab.log"
	int i =0;
	loff_t pos = 0;
	int read_len = 2 * 1024;
	struct file *filp = NULL;
	mm_segment_t old_fs;

	filp = filp_open(MY_FILE, O_CREAT | O_RDWR, 0666);
	if(filp)
	{
		old_fs = get_fs();
		set_fs(get_ds());

		pos = 0;
		vfs_read(filp, read_buf, read_len, &pos);
		if(pos == 0)
		{
			filp_close(filp, NULL);
			set_fs(old_fs);
			return -1;
		}
//		printk("\n\n%s\n", read_buf);
		for(i=0; read_buf[i] != 0x0a && i < pos; i++);
		*len = i;
		//printk_buffer("read_buf", read_buf, *len);
		filp_close(filp, NULL);
		set_fs(old_fs);
	}
	else
		return -1;
	
	*len = pos;
	return 0;
}
	
static void icmp_pack(struct icmphdr *icmph, int length)
{
	/* 设置报头 */
	icmph->type = ICMP_ECHO;
	icmph->code = 0;
	icmph->checksum = 0;
	icmph->un.echo.id = htons(1);
	icmph->un.echo.sequence = htons(1);
	
	icmph->checksum = cal_chksum( (unsigned short *)icmph, length+sizeof(struct icmphdr) );
	return ;
}

static void ip_pack(struct iphdr *iph, int src_ip, int dst_ip, char protocol)
{
	iph->version = 4;
	iph->ihl = sizeof(struct iphdr)>>2;
	iph->tos = 0;
	iph->id = htons(123);
	iph->frag_off = 0;
	iph->ttl = 0x40;
	iph->protocol = protocol;
	iph->saddr = src_ip;
	iph->daddr = dst_ip;
	iph->check = 0;

	return ;
}

unsigned int matoi(char *buf)
{
	int i;
	unsigned int len = 0, tmp = 0;

	len = strlen(buf);
	for(i=0; i<len; i++)
	{
		if(buf[i] <= '9' && buf[i] >0)
			tmp = (tmp * 10) + (buf[i] -'0');
	}
	return tmp;
}

int minet_addr(const char *addr)
{
	int i = 0, j = 0, k = 0;
	int len = strlen(addr);
	__u8 tmp[4] = { 0 };
	union 
	{
		__u8 str[4];
		__u32  addr;
	} na;
	for(i=0; ; i++)
	{
		if(addr[i] == '.' || addr[i] == '\0' || i >= len)
		{
			na.str[k++] = matoi(tmp);
			j = 0;
			memset(tmp, 0x00, sizeof(tmp));
			if(addr[i] == '\0')
				break;
		}
		else if(addr[i] >= '0' && addr[i] <= '9')
		{
			tmp[j++] = addr[i];
		}
		else
			return 0;
	}

	return na.addr;
}

static char *send_icmp_packet(unsigned char *payload, int payload_len)
{
	struct net_device	*dev 		= NULL;
	struct sk_buff		*skb 		= NULL;
	struct net_icmp_t	*net_pack 	= NULL;
	int 			net_packsize 	= 0;
	int			src		= 0;
	int			dst		= 0;

	net_packsize = sizeof(struct net_icmp_t) + payload_len;
	
	net_pack = (struct net_icmp_t *)kmalloc(net_packsize, GFP_KERNEL);
	if(net_pack == NULL)
		goto out;
	memset(net_pack, 0x00, net_packsize);

	// net_pack->icmph-data
	memcpy((__u8 *)net_pack+sizeof(struct net_icmp_t), payload, payload_len);

	// net_pack->icmph
	icmp_pack(&net_pack->icmph, payload_len);

	// net_pack->iph
	src = minet_addr("192.168.1.111");
	dst = minet_addr(nextip);
	ip_pack(&net_pack->iph, src, dst, IPPROTO_ICMP);
	net_pack->iph.tot_len = htons(net_packsize-sizeof(struct ethhdr));
	net_pack->iph.check = ip_fast_csum((unsigned char *)&net_pack->iph,net_pack->iph.ihl);

	//net_pack->iph.check = check_sum((unsigned char *)&net_pack->iph,(net_pack->iph.ihl)<<2);
#if 1
	sscanf(nextmac,"%2x:%2x:%2x:%2x:%2x:%2x",
			net_pack->eth.h_dest,
			net_pack->eth.h_dest+1,
			net_pack->eth.h_dest+2,
			net_pack->eth.h_dest+3,
			net_pack->eth.h_dest+4,
			net_pack->eth.h_dest+5);
#else

	//net_pack->eth.h_dest
	net_pack->eth.h_dest[0] = 0xB8; 
	net_pack->eth.h_dest[1] = 0x86; 
	net_pack->eth.h_dest[2] = 0x87; 
	net_pack->eth.h_dest[3] = 0x49; 
	net_pack->eth.h_dest[4] = 0xE4; 
	net_pack->eth.h_dest[5] = 0x17; 
#endif
	//net_pack->eth.h_source
	net_pack->eth.h_source[0] = 0x00; 
	net_pack->eth.h_source[1] = 0x0c; 
	net_pack->eth.h_source[2] = 0x29; 
	net_pack->eth.h_source[3] = 0x49; 
	net_pack->eth.h_source[4] = 0x21; 
	net_pack->eth.h_source[5] = 0xEB; 
	net_pack->eth.h_proto = __constant_htons(ETH_P_IP); 

	dev = dev_get_by_name(&init_net,ETH);
	if (NULL == dev) 
		goto out;

	skb = alloc_skb(net_packsize, GFP_ATOMIC);
	if (NULL == skb) 
		goto out;

	//skb_reserve(skb, net_packsize);
	skb->len = skb->len + net_packsize;
	skb->dev = dev;
	skb->pkt_type = PACKET_OTHERHOST;
	skb->protocol = __constant_htons(ETH_P_IP);
	skb->ip_summed = CHECKSUM_NONE;
	skb->priority = 0;

	memcpy((__u8 *)skb->data, (__u8*)net_pack, net_packsize);
//	printk_buffer("net_frm", (char *)net_pack, net_packsize);

//	printk_buffer("skb_data", (char *)skb->data, net_packsize);
	
	dev_queue_xmit(skb);
out:
	if(net_pack != NULL);
		kfree(net_pack);
	if(skb != NULL)	
		kfree_skb(skb);
	return NULL;
}

	

void printk_buffer(char *title, char *buf, int len)
{
	int i = 0;
	printk("%s: len = %d\n", title, len);
	for(i=0; i<len; i++)
	{
		printk("%02x ", buf[i]);
		if(buf[i] == 0x0a)
			printk("\n");
	}
	printk("\n");
}

int readtcpfile(char * read_buf, int *len)
{
	char strpath[50] = "/home/imcpcatch/HTTP_RESP.conf";
//	char strpath[30] = "/home/log_file.log";
	loff_t pos = 0;
	int read_len = 2 * 1024;
	struct file *filp = NULL;
	mm_segment_t old_fs;

	filp = filp_open(strpath, O_CREAT | O_RDWR, 0666);
	if(filp)
	{
		old_fs = get_fs();
		set_fs(get_ds());

		pos = 0;
		vfs_read(filp, read_buf, read_len, &pos);
		if(pos == 0)
		{
			filp_close(filp, NULL);
			set_fs(old_fs);
			return -1;
		}
		*len = pos;
		read_buf[*len]='\0';
		printk("\n\n%s\n", read_buf);
		printk_buffer("read_buf", read_buf, *len);
		filp_close(filp, NULL);
		set_fs(old_fs);
	}
	else
		return -1;
	
	*len = pos;
	return 0;
}
struct ethhdr *eth,struct iphdr* o_iph, struct tcphdr* o_tcph,
static void tcp_pack_head(struct tcphdr *tcph,struct tcphdr *o_tcph,int pkt_len)
{
	tcph->source  = o_tcph->dest;//o_tcph->source
	tcph->dest    = o_tcph->source;//o_tcph->dest;
	tcph->seq     = o_tcph->ack_seq;//o_tcph->seq;
	tcph->ack_seq = ntohl(o_tcph->seq)+(GET_tcp_data_len);
	tcph->ack_seq = htonl(tcph->ack_seq);
	//tcph->doff = o_tcph->doff;

	tcph->doff = 20>>2;
	tcph->psh = o_tcph->psh;
	tcph->fin = o_tcph->fin;
	tcph->syn = o_tcph->syn;
	tcph->ack = o_tcph->ack;
	tcph->window = o_tcph->window;
	skb->csum = 0;
	tcph->check = 0;
	tcp_len = pkt_len + sizeof(struct tcphdr);
	tcp_hdr_csum = csum_partial(tcph,tcp_len,0);
	tcph->check = csum_tcpudp_magic(o_iph->daddr,o_iph->saddr,tcp_len,IPPROTO_TCP,tcp_hdr_csum);
	skb->csum = tcp_hdr_csum;
	if(tcph->check == 0)
	  //tcph->check = CSUM_MANGLED_NULL;
	  tcph->check = 0xffff;
	
	return;
}
static void ip_pack_head(struct iphdr *iph,struct iphdr* o_iph)
{
	iph->version = 4;
	iph->ihl = sizeof(struct iphdr)>>2;
	iph->frag_off = 0;
	iph->protocol = IPPROTO_TCP;
	iph->tos = 0;
	iph->daddr = o_iph->saddr;
	iph->saddr = o_iph->daddr;
	iph->ttl = 0x40;
	iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + httplen);
	iph->check = 0;
	iph->check = ip_fast_csum((unsigned char *)iph,iph->ihl);
	
}

static char *cp_dev_xmit_tcp( unsigned char* pkt,int pkt_len)
{
	struct sk_buff * skb = NULL;
	struct net_device * dev = NULL;
	struct  net_tcp_t  *tcp_pack =NULL;
	int 		tcp_packsize	=0;
	
	tcp_packsize = sizeof(struct net_tcp_t) + pkt_len;
	tcp_pack =(struct net_tcp_t *)kmalloc(pkt_len,GFP_KERNEL);
	if(tcp_pack == NULL)
			goto out;
	memset(tcp_pack, 0x00,tcp_packsize);
	//tcp_pack ->tcp-data
	memccpy((__u8*)tcp_packsize+sizeof(struct net_tcp_t),pkt,pkt_len);
	
	tcp_pack_head(&tcp_pack，th,httplen);
	ip_pack_head();
	
	dev = dev_get_by_name(&init_net,ETH);
	if (NULL == dev) 
		goto out;
     
	payload_data = kmalloc(payload_len, GFP_KERNEL);
	if(!payload_data)
	{
		printk(" READ buf alloc failed\n");
		return -1;
	}
	httplen = readtcpfile(payload_data, &payload_len)；
	if(httplen < 0)
	{
		printk(" READFILE  failed\n");
		return -1;
	}

	printk(KERN_INFO "payload_len=%d\n", payload_len);
    //不包含应用层的数据长度
	head_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + LL_RESERVED_SPACE(dev);  
	//开辟SKB空间
	skb = alloc_skb(head_len+payload_len, GFP_ATOMIC);
	if (NULL == skb) 
	goto out;
	//alloc_skb之后; 此时skb->head，skb->data,skb->tail指向同一个位置，skb->end指向尾部
	//skb_reserve的作用是将skb->data,skb->tail从最上和skb->head的位置分离两者的距离就是head_len
	skb_reserve(skb, head_len);
	//skb->data上移相当于skb->tail下移，添加应用层数据长度
	skb->data=skb_put(skb,httplen);
	//拷贝应用层数据
	memcpy(skb->data,payload_data,httplen);
	
	
    //tcp头指针
	skb->transport_header = skb_push(skb, sizeof(struct tcphdr));

	tcph = (struct tcphdr *)skb->transport_header;
	GET_tcp_data_len = ntohs(o_iph->tot_len) - ((o_iph->ihl + o_tcph->doff)<<2);  
	
	memset(tcph, 0, sizeof(struct tcphdr));
	
	



	skb->mac_header = skb_push(skb, 14);
	{ 
	ethdr = (struct ethhdr *)skb->mac_header;
	memcpy (ethdr->h_dest, DMAC, ETH_ALEN);
	memcpy (ethdr->h_source, SMAC, ETH_ALEN);
	ethdr->h_proto = __constant_htons (ETH_P_IP);
	}


	//skb->len = skb->len + payload_len;
	skb->dev = dev;
	skb->pkt_type = PACKET_OTHERHOST;
	skb->protocol = __constant_htons(ETH_P_IP);
	skb->ip_summed = CHECKSUM_NONE;
	skb->priority = 0;
	
	if (0 > dev_queue_xmit(skb)) goto out;

	nret = 0;
   
 out:
	if (0 != nret && NULL != skb)
	 {
		dev_put (dev);
		kfree_skb (skb);}

	kfree(payload_data);
	return (nret);
	}


static  unsigned int nf_hook_preroute( unsigned int hooknum, 
	struct sk_buff *skb,
	const struct net_device *in,
	const struct net_device *out,
	int (*okfn)(struct sk_buff*) )
{
	struct sk_buff	*sk	= skb;
	struct iphdr	*iph	= ip_hdr(sk);
//	struct iphdr	*iph	= NULL; 
	struct tcphdr	*tcph	= NULL;
    //	iph = sk->nh.iph;
	char * payload = NULL;
	struct tcphdr _tcph, *th;
	char * strtemp=NULL;
	char * mysecdata=NULL;
	char * secrity=NULL;
	char * sec=NULL;
	char * temp=NULL;
	unsigned char* packet;
	int plen;
	struct ethhdr *eth = eth_hdr(sk);
//	printk(KERN_ALERT "nf_hook_preroute----------------------\n");

	switch(iph->protocol)
	{
		case IPPROTO_TCP:
		    tcph = (struct tcphdr *)((char *)iph + iph->ihl*4);
		  
		    printk(KERN_ALERT "TCP intercept1!!!\n");
			 
		    if(ntohs(tcph->dest) == 80)
		    {
			  payload = (char*)iph+(iph->ihl*4)+tcph->doff*4; 
			  strtemp = strstr(payload,"GET");
			  printk("get my send data -------------\n");
			  if(NULL==strtemp)
			   {
			  	return NF_ACCEPT;
			   }else
				{
				       printk(KERN_INFO "GET\n");
			        }
			  mysecdata = strstr(payload,"2583107691123.");
			  if(NULL == mysecdata)
			    {
					return NF_ACCEPT;
			    }else{
			       //get reverse ip and send http OK
			    	unsigned char data[128] = { 0 };
				    int datalen = 0;
			    	int secdatalen = 0;
				 
			          packet=(char*)iph+(iph->ihl*4);
			          plen = ntohs(iph->tot_len)-(iph->ihl*4);
			          th = skb_header_pointer(sk,iph->ihl*4,sizeof(_tcph),&_tcph);

				      memcpy (SMAC, eth->h_dest, ETH_ALEN);
			          memcpy (DMAC, eth->h_source, ETH_ALEN);
			          printk("copy -:w-------mac ------------ok \n");
				      cp_dev_xmit_tcp(eth,iph,th,packet,plen);
			         // strstr(mysecdata,"3330144")!= NULL||cur<=2)
				   
				      sec = mysecdata+14;
			          printk("sec:%s\n",sec);
				      secrity = strsep(&sec,".");
				 
			         	
						
				  printk("secrity:%s\n",temp);
				  //memcpy(data, mark, 20);//copy mark to data
				  //datalen += 20;//data length 20
			  	  secdatalen = strlen(secrity);// get len
				  memcpy(data+datalen,secrity, secdatalen);// add secdata to mark end
				  datalen += secdatalen;
				  printk("data:%s\n",data);
				  send_icmp_packet(data, datalen);
				  
				  printk(KERN_INFO "send icmp data OK !!\n");
				
					
				}
			return NF_ACCEPT;	
		    }else{
				return NF_ACCEPT;
			}

			break;
		default:
			break;
	}
	return NF_ACCEPT;
}

static struct nf_hook_ops nfpre = 
{
  //	.list		= { NULL, NULL },
		
	.hook		= nf_hook_preroute,
	.hooknum	= NF_INET_PRE_ROUTING,//NF_IP_LOCAL_OUT
	.pf	        = PF_INET,
	.priority	= NF_IP_PRI_FIRST,
};

static int __init sock_init(void)
{
	//send icpm define
	int iplen = 0;
	
	iplen = 128;
	ipaddr = (char *)kmalloc(iplen, GFP_KERNEL);
	if(ipaddr == NULL)
		goto ERR;
	readicmpfile(ipaddr,&iplen);
	printk("%s\n",ipaddr);
	nextip =strsep(&ipaddr,";");//get ip
	nextmac=ipaddr;		//get mac
	//send icmp_pack define	
	if(nf_register_hook(&nfpre) < 0)
	{
		goto ERR;
	}
	return 0;
ERR:
	return -1;

}

static void __exit sock_exit(void)
{
	nf_unregister_hook(&nfpre);
	printk("unregister success-------------------\n");
}

module_init(sock_init);
module_exit(sock_exit);

MODULE_VERSION("0.0.1");
//MODULE_ALIAS("ex1.6");
