//内核编程需要的头文件
#include <linux/module.h>
#include <linux/kernel.h>
//Netfilter需要的头文件
//#include <linux/version.h>
//#include <linux/kmod.h>
//#include <linux/vmalloc.h>
//#include <linux/workqueue.h>
//#include <linux/socket.h>
//#include <linux/net.h>
//#include <linux/in.h>
//#include <asm/uaccess.h>
//#include <asm/unistd.h>


#include <linux/init.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>//ip_route_me_harder
#include <linux/icmp.h>
#include <linux/inet.h>//in_aton()function
#include <net/ip.h>//ip_local_out
//netlink需要的头文件
#include <net/sock.h>
#include <net/net_namespace.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/netlink.h>
#include "netfilter_server.h"
//slab
#include <linux/slab.h>
//NIPQUAD宏便于把数字IP地址输出
#define NIPQUAD(addr) \
((unsigned char *)&addr)[0], \
((unsigned char *)&addr)[1], \
((unsigned char *)&addr)[2], \
((unsigned char *)&addr)[3]

#define NETLINK_TEST 17         //用于自定义协议
#define MAX_PAYLOAD 1024        //最大载荷容量
#define ROUTING_INFO_LEN 512    //单个路由信息的容量

//slab
#define MYSLAB "dockerSlab"
static struct kmem_cache *myslab;
//函数声明
unsigned int kern_inet_addr(char *ip_str);
void kern_inet_ntoa(char *ip_str , unsigned int ip_num);
unsigned int nf_hook_out(void *priv, struct sk_buff *skb, const struct net_device *in,
                         const struct net_device *out,const struct nf_hook_state *state);
unsigned int nf_hook_in(void *priv, struct sk_buff *skb, const struct net_device *in,
                        const struct net_device *out,const struct nf_hook_state *state);
unsigned int nf_hook_preIn(void *priv, struct sk_buff *skb, const struct net_device *in,
                        const struct net_device *out,const struct nf_hook_state *state);
unsigned int nf_hook_postOut(void *priv, struct sk_buff *skb, const struct net_device *in,
                        const struct net_device *out,const struct nf_hook_state *state);
static void nl_data_ready(struct sk_buff *skb);
int netlink_to_user(char *msg, int len);

//用于描述钩子函数信息
static struct nf_hook_ops nf_out = {
    .hook = nf_hook_out,
    .pf = PF_INET,
    .owner=NULL,
    .hooknum =NF_INET_LOCAL_OUT ,  
    .priority = NF_IP_PRI_FIRST,
};
static struct nf_hook_ops nf_in =
{
    .hook = nf_hook_in,
    .pf = PF_INET,
    .owner=NULL,
    .hooknum = NF_INET_LOCAL_IN,
    .priority = NF_IP_PRI_FIRST
};
static struct nf_hook_ops nf_preIn =
{
    .hook = nf_hook_preIn,
    .pf = PF_INET,
    .owner=NULL,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST
};
static struct nf_hook_ops nf_postOut = {
        .hook = nf_hook_postOut,
        .pf = PF_INET,
        .owner=NULL,
        .hooknum =NF_INET_POST_ROUTING ,
        .priority = NF_IP_PRI_FIRST,
};
//用于描述Netlink处理函数信息
struct netlink_kernel_cfg cfg = {
    .input = nl_data_ready,
};
spinlock_t spinlock;
static struct sock *nl_sk = NULL;   //用于标记netlink
static int userpid = -1;            //用于存储用户程序的pid
char ip[10][32]={'\0'};              //ip data in message
char use[10][32]={'\0'};              //
char type[10][32]={'\0'};
char modifyAddr[10][32]={'\0'};
int num=0;//get rule num
struct dst_entry *output_dst = NULL; //出口设备指针
int destIp[16]={0};
char *sourceIp[16]={
        "172.17.0.1",
        "172.17.0.2",
        "172.17.0.3",
        "172.17.0.4",
        "172.17.0.5",
        "172.17.0.6",
        "172.17.0.7",
        "172.17.0.8",
        "172.17.0.9",
        "172.17.0.10",
        "172.17.0.11",
        "172.17.0.12",
        "172.17.0.13",
        "172.17.0.14",
        "172.17.0.15",
        "172.17.0.16",
};
int tcpTrueSourceIp[16]={0};
int icmpTrueSourceIp[16]={0};
int tcpSourcePort[16]={0};
int udpSourcePort[16]={0};
int icmpId[16]={0};
int icmpSeq[16]={0};
// 申请内存时调用的构造函数
static void ctor(void* obj)
{
    printk(KERN_ALERT "constructor is running....\n");
}
//record docker flow
struct DockerFlow
{
    int flow[16];
};
struct DockerFlow *dockerFlow;
//复制报文并添加新的头域发送到指定的接收地址
int capture_send(const struct sk_buff *skb, int output)
{
    struct ethhdr  *oldethh = NULL;
    struct iphdr   *oldiph  = NULL;
    struct iphdr   *newiph  = NULL;
    struct icmphdr  *newicmph = NULL;
    struct sk_buff *skb_cp  = NULL;
    struct net *net = NULL;
    unsigned int headlen = 0;
    unsigned short len;
    headlen = 60;    // mac + ip + icmp = 14 + 20 + 8 = 42, 这里分配大一点
    //如果报文头部不够大，在复制的时候顺便扩展一下头部空间，够大的话直接复制
    if(skb_headroom(skb) < headlen){
        skb_cp = skb_copy_expand(skb,headlen,0,GFP_ATOMIC);
        if(!skb_cp){
            printk(" realloc skb fail \r\n");
            return -1;
        }
    }else{
        skb_cp = skb_copy(skb, GFP_ATOMIC);
        if(!skb_cp){
            printk(" copy skb fail \r\n");
            return -1;
        }
    }

    oldiph = ip_hdr(skb);
    if(!oldiph){
        printk("ip header null \r\n");
        kfree_skb(skb_cp);
        return -1;
    }

    /*
    * 抓包报文格式
     ---------------------------------------------------------------------
     | new mac | new ip | new icmp | old mac | old ip| old tcp/udp | data |
     ---------------------------------------------------------------------
     |        new header          |            new data                  |
     ---------------------------------------------------------------------
    */

    //如果是出去的报文，因为是在IP层捕获，MAC层尚未填充，这里将MAC端置零，并填写协议字段
    if(output){
        skb_push(skb_cp,sizeof(struct ethhdr));
        skb_reset_mac_header(skb_cp);
        oldethh = eth_hdr(skb_cp);
        oldethh->h_proto = htons(ETH_P_IP);
        memset(oldethh->h_source,0,ETH_ALEN);
        memset(oldethh->h_dest,0,ETH_ALEN);
        if(skb_cp->dev != NULL)
            memcpy(oldethh->h_source,skb_cp->dev->dev_addr,ETH_ALEN);
    }else{
        //如果是进来的报文，MAC层已经存在，不做任何处理，直接封装
        skb_push(skb_cp,sizeof(struct ethhdr));
        skb_reset_mac_header(skb_cp);
        oldethh = eth_hdr(skb_cp);
        oldethh->h_proto = htons(ETH_P_IP);
    }

    //添加IP, ICMP头部
    skb_push(skb_cp, sizeof(struct iphdr) + sizeof(struct udphdr));
    skb_reset_network_header(skb_cp);
    skb_set_transport_header(skb_cp,sizeof(struct iphdr));
    newiph = ip_hdr(skb_cp);
    newicmph = icmp_hdr(skb_cp);

    if((newiph == NULL) || (newicmph == NULL)){
        printk("new ip icmp header null \r\n");
        kfree_skb(skb_cp);
        return -1;
    }

    /* 抓包的报文发送的时候是调用协议栈函数发送的，所以output钩子函数会捕获到抓包报文，
     * 这里我们要把抓包报文和正常报文区分开，区分方式就是判断协议，
     * 我们抓到的报文在送出去的时候协议是icmp,所以根据是否是icmp进行判断是否copy
     *  在送出去的时候填写的是icmp，如果钩子函数遇到这样的报文就会直接let go
     * 防止重复抓包，这一点在测试的时候很重要，一旦重复抓包，系统就直接挂了...
     */
    memcpy((unsigned char*)newiph,(unsigned char*)oldiph,sizeof(struct iphdr));
    if(output)                                    //request
    {
        newicmph->type = 8;
        newicmph->code = 0;
        newiph->saddr = oldiph->saddr;
        newiph->daddr = oldiph->daddr; //抓包服务器地址
    } else{                                       //response
        newicmph->type = 0;
        newicmph->code = 8;
        newiph->daddr = oldiph->daddr;
        newiph->saddr = oldiph->saddr; //抓包服务器地址
    }
    newiph->ihl = 5;
    newiph->protocol = IPPROTO_ICMP;
    newiph->tot_len =  htons(ntohs(oldiph->tot_len) + sizeof(struct icmphdr) + sizeof(struct ethhdr)+ sizeof(struct iphdr));

    len=htons(ntohs(oldiph->tot_len) + sizeof(struct icmphdr) + sizeof(struct ethhdr));
    /* disable gso_segment */
    skb_shinfo(skb_cp)->gso_size = htons(0);

    //计算校验和
    newicmph->checksum = 0;
    newiph->check= 0;
    newicmph->checksum=ip_compute_csum(newicmph, htons(len));
    skb_cp->ip_summed = CHECKSUM_NONE;
    newiph->check = ip_fast_csum((unsigned char*)newiph, newiph->ihl);

    //设置出口设备
    if(skb_dst(skb_cp) == NULL){
        if(output_dst == NULL){
            kfree_skb(skb_cp);
            return -1;
        }else{
            dst_hold(output_dst);
            skb_dst_set(skb_cp, output_dst);
        }
    }

    //路由查找
    if(ip_route_me_harder(skb_cp, RTN_UNSPEC)){
        kfree_skb(skb_cp);
        printk("ip route failed \r\n");
        return -1;
    }

    //发送
    ip_local_out(skb_cp);
    return 0;
}
//modify docker source ip
unsigned int nf_hook_postOut(void *priv,
                         struct sk_buff *skb,
                         const struct net_device *in,
                         const struct net_device *out,
                         const struct nf_hook_state *state)
{
    struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *tcph = tcp_hdr(skb);
    struct udphdr *udph = udp_hdr(skb);
    struct icmphdr *icmph = icmp_hdr(skb);
    int i;
    int ipFlag=-1;//check docker ip
    if(strcmp(out->name,"ens33")==0)
    {
        for(i=0;i<16;i++)
        {
            if(iph->saddr==in_aton(sourceIp[i]))
            {
                ipFlag=i;//docker ip
                if(iph->protocol==IPPROTO_TCP)
                {
                    spin_lock(&spinlock);
                    tcpSourcePort[i]=ntohs(tcph->source);//record source port
                    spin_unlock(&spinlock);
                }
                if(iph->protocol==IPPROTO_UDP)
                {
                    spin_lock(&spinlock);
                    udpSourcePort[i]=ntohs(udph->source);
                    spin_unlock(&spinlock);
                }
                if(iph->protocol==IPPROTO_ICMP)
                {
                    spin_lock(&spinlock);
                    icmpSeq[i]=icmph->un.echo.sequence;
                    icmpId[i]=icmph->un.echo.id;
                    spin_unlock(&spinlock);
                }
                destIp[i]=iph->daddr;
                printk("````destIp=%d\n````",destIp[i]);
                break;
            }
        }
        if (ipFlag!=-1) {
            dockerFlow->flow[ipFlag]+=skb->len;
            if (likely(iph->protocol == IPPROTO_UDP)) {
                iph->saddr = in_aton("192.168.0.104");
                udph->check = 0;
                iph->check = 0;
                skb->csum = 0;
                skb->csum = csum_partial(skb_transport_header(skb), (ntohs(iph->tot_len) - iph->ihl * 4), 0);
                udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, (ntohs(iph->tot_len) - iph->ihl * 4), IPPROTO_UDP,
                                                skb->csum);
                skb->ip_summed = CHECKSUM_NONE;
                if (0 == udph->check) {
                    udph->check = CSUM_MANGLED_0;
                }
                iph->check = 0;
                iph->check = ip_fast_csum((unsigned char *) iph, iph->ihl);
                printk("request UDP\n");
                return NF_ACCEPT;
            }
            if (likely(iph->protocol == IPPROTO_ICMP)) {
                printk(KERN_INFO
                "source IP is %pI4\n", &iph->saddr);
                printk(KERN_INFO
                "dest IP is %pI4\n", &iph->daddr);
                iph->saddr = in_aton("192.168.0.104");
                iph->check = 0;
                iph->check = ip_fast_csum((unsigned char *) iph, iph->ihl);
                return NF_ACCEPT;
            }
            printk("request tcp\n");
            printk(KERN_INFO
            "source IP is %pI4\n", &iph->saddr);
            printk(KERN_INFO
            "dest IP is %pI4\n", &iph->daddr);
            iph->saddr = in_aton("192.168.0.104");
            tcph->check = 0;
            iph->check = 0;
            skb->csum = 0;
            skb->csum = csum_partial(skb_transport_header(skb), (ntohs(iph->tot_len) - iph->ihl * 4), 0);
            tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, (ntohs(iph->tot_len) - iph->ihl * 4), IPPROTO_TCP,
                                            skb->csum);
            skb->ip_summed = CHECKSUM_NONE;
            if (0 == tcph->check) {
                tcph->check = CSUM_MANGLED_0;
            }
            iph->check = 0;
            iph->check = ip_fast_csum((unsigned char *) iph, iph->ihl);
        }
    }
    return NF_ACCEPT;
}
unsigned int nf_hook_preIn(void *priv,
                         struct sk_buff *skb,
                         const struct net_device *in,
                         const struct net_device *out,
                         const struct nf_hook_state *state) {
    struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *tcph = tcp_hdr(skb);
    struct udphdr *udph = udp_hdr(skb);
    struct icmphdr *icmph = icmp_hdr(skb);
    int ipFlag=-1;
    int i;
    if(iph->daddr==in_aton("192.168.0.104")&&strcmp(in->name,"ens33")==0)
    {
        /*printk("response udp port=%d\n",ntohs(udph->dest));
        printk("response tcp port=%d\n",ntohs(tcph->dest));*/
        for(i=0;i<16;i++)
        {
            if(ntohs(tcph->dest)==tcpSourcePort[i]&&iph->protocol==IPPROTO_TCP)
            {
                ipFlag=i;
                break;
            }
            if(ntohs(udph->dest)==udpSourcePort[i]&&iph->protocol==IPPROTO_UDP)
            {
                ipFlag=i;
                break;
            }
            if(iph->protocol==IPPROTO_ICMP&&icmph->un.echo.id==icmpId[i]&&icmph->un.echo.sequence==icmpSeq[i])
            {
                ipFlag=i;
                break;
            }
        }
        //docker data
        if(ipFlag!=-1)
        {
            dockerFlow->flow[ipFlag]+=skb->len;
            if(likely(iph->protocol==IPPROTO_UDP))
            {
                printk("Response UDP\n");
                iph->daddr=in_aton(sourceIp[ipFlag]);
                udph->check = 0;
                iph->check = 0;
                skb->csum = 0;
                skb->csum = csum_partial(skb_transport_header(skb), (ntohs(iph->tot_len) - iph->ihl * 4), 0);
                udph->check = csum_tcpudp_magic(iph->saddr,iph->daddr, (ntohs(iph->tot_len) - iph->ihl * 4), IPPROTO_UDP, skb->csum);
                skb->ip_summed = CHECKSUM_NONE;
                if (0 == udph->check){
                    udph->check = CSUM_MANGLED_0;
                }
                iph->check=0;
                iph->check=ip_fast_csum((unsigned char*)iph, iph->ihl);
                return NF_ACCEPT;
            }
            if(likely(iph->protocol==IPPROTO_ICMP))
            {
                printk("response ICMP\n");
                printk(KERN_INFO"response source IP is %pI4\n", &iph->saddr);
                printk(KERN_INFO"dest IP is %pI4\n", &iph->daddr);
                iph->daddr=in_aton(sourceIp[ipFlag]);
                iph->check=0;
                iph->check=ip_fast_csum((unsigned char*)iph, iph->ihl);
                return NF_ACCEPT;
            }
            printk(KERN_INFO"source IP is %pI4\n", &iph->saddr);
            printk(KERN_INFO"dest IP is %pI4\n", &iph->daddr);
            iph->daddr=in_aton(sourceIp[ipFlag]);
            tcph->check = 0;
            iph->check = 0;
            skb->csum = 0;
            skb->csum = csum_partial(skb_transport_header(skb), (ntohs(iph->tot_len) - iph->ihl * 4), 0);
            tcph->check = csum_tcpudp_magic(iph->saddr,iph->daddr, (ntohs(iph->tot_len) - iph->ihl * 4), IPPROTO_TCP, skb->csum);
            skb->ip_summed = CHECKSUM_NONE;
            if (0 == tcph->check){
                tcph->check = CSUM_MANGLED_0;
            }
            iph->check=0;
            iph->check=ip_fast_csum((unsigned char*)iph, iph->ihl);
        }
    }
    return NF_ACCEPT;
}
//request
unsigned int nf_hook_out(void *priv,
                     struct sk_buff *skb,
                     const struct net_device *in,
                     const struct net_device *out,
                     const struct nf_hook_state *state){
    struct iphdr *iph=ip_hdr(skb);  //指向struct iphdr结构体
    struct tcphdr *tcph;            //指向struct tcphdr结构体
    struct udphdr *udph;            //指向struct udphdr结构体
    struct icmphdr *icmph=icmp_hdr(skb);
    int header=0;
    int i;//for loop elem to get host
    char *p=NULL;//get Host
    int http_flag=0;//is or not http data
    char host[128]={'\0'};
    unsigned char *data=NULL;//HTTP datas
    int flag=-1;//match ip position
    int ipFlag=-1;
    char routingInfo[ROUTING_INFO_LEN] = {0};//用于存储路由信息
    tcph=tcp_hdr(skb);
    //printk("saddr=%d\n",ntohl(iph->saddr));
    if(strcmp(out->name,"eth0")==0)
    {          //get docker data

        //ip match
        for(i=0;i<num;i++)
        {
            //also can use in_aton() function
            if(kern_inet_addr(ip[i])==ntohl(iph->daddr))
            {
                flag=i;
                break;
            }
        }
        //printk("------------out name1=%s\n",out->name);
        //if match ip rule
        if(flag!=-1&&use[flag][0]!='0'){
            //drop data
            if(type[flag][0]=='3')
            {
                /*if(iph->protocol==IPPROTO_TCP||iph->protocol==IPPROTO_ICMP)
                {*/
                    printk("----------drop\n");
                    sprintf(routingInfo,"0000000000000000000000000000");
                    netlink_to_user(routingInfo, ROUTING_INFO_LEN);
                    return NF_DROP;
                //}
            }
            if(type[flag][0]=='2')
            {
                printk("----------copy\n");
                //zhi zhen dui udp huo tcp
                if(iph->protocol == IPPROTO_UDP||iph->protocol == IPPROTO_TCP)
                {
                    if(output_dst == NULL){
                        if(skb_dst(skb) != NULL){
                            output_dst = skb_dst(skb);
                            dst_hold(output_dst);
                            printk("dst get success \r\n");
                        }
                    }
                    capture_send(skb, 1);
                }
            }
            if(type[flag][0]=='1'&&likely(iph->protocol!=IPPROTO_UDP)) {
                printk("----------modify\n");
                for(i=0;i<16;i++)
                {
                    if(iph->saddr==in_aton(sourceIp[i]))
                    {
                        ipFlag=i;//docker ip
                        if(iph->protocol==IPPROTO_TCP)
                        {
                            spin_lock(&spinlock);
                            tcpSourcePort[i]=ntohs(tcph->source);//record source port
                            tcpTrueSourceIp[i]=iph->daddr;
                            spin_unlock(&spinlock);
                        }
                        if(iph->protocol==IPPROTO_ICMP)
                        {
                            spin_lock(&spinlock);
                            icmpSeq[i]=icmph->un.echo.sequence;
                            icmpId[i]=icmph->un.echo.id;
                            icmpTrueSourceIp[i]=iph->daddr;
                            spin_unlock(&spinlock);
                        }
                        break;
                    }
                }
                //trueSourceIp[flag]=iph->saddr;
                //check
                //tcp
                iph->daddr = in_aton(modifyAddr[flag]);
                if (likely(iph->protocol==IPPROTO_TCP))
                {
                    tcph->check = 0;
                    iph->check = 0;
                    skb->csum = 0;
                    skb->csum = csum_partial(skb_transport_header(skb), (ntohs(iph->tot_len) - iph->ihl * 4), 0);
                    tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, (ntohs(iph->tot_len) - iph->ihl * 4),
                                                    IPPROTO_TCP, skb->csum);
                    skb->ip_summed = CHECKSUM_NONE;
                    if (0 == tcph->check) {
                        tcph->check = CSUM_MANGLED_0;
                    }
                }
                //tcp+icmp
                iph->check=0;
                iph->check=ip_fast_csum((unsigned char*)iph, iph->ihl);
            }

            /*printk("=======equal========\n");
            printk("srcIP: %u.%u.%u.%u\n", NIPQUAD(iph->saddr));
            printk("dstIP: %u.%u.%u.%u\n", NIPQUAD(iph->daddr));*/
            if(likely(iph->protocol==IPPROTO_TCP)){
                if(skb->len-header>0){
                   /* printk("srcPORT:%d\n", ntohs(tcph->source));
                    printk("dstPORT:%d\n", ntohs(tcph->dest));
                    printk("PROTOCOL:TCP");*/
                    data=skb->data+iph->ihl*4+tcph->doff*4;//get http data
                    if((p=strstr(data,"Host"))!=NULL)
                    {
                        http_flag=1;
                        for( i=0;i<1024;i++)
                        {
                            if(*(p+i)=='\r'&&*(p+i+1)=='\n')
                            {
                                break;
                            }
                            else
                            {
                                host[i]=*(p+i);
                                printk("%c",*(p+i));
                            }
                        }
                        printk("\n");
                    }
                    if(http_flag)
                    {
                        if(type[flag][0]=='1')
                        {
                            sprintf(routingInfo,
                                    "Request Data => srcIP:%u.%u.%u.%u dstIP:%s srcPORT:%d dstPORT:%d PROTOCOL:%s Request URL:%s",
                                    NIPQUAD(iph->saddr),
                                    ip[flag],
                                    ntohs(tcph->source),
                                    ntohs(tcph->dest),
                                    "TCP",
                                    host);
                        }else{
                            sprintf(routingInfo,
                                    "Request Data => srcIP:%u.%u.%u.%u dstIP:%u.%u.%u.%u srcPORT:%d dstPORT:%d PROTOCOL:%s Request URL:%s",
                                    NIPQUAD(iph->saddr),
                                    NIPQUAD(iph->daddr),
                                    ntohs(tcph->source),
                                    ntohs(tcph->dest),
                                    "TCP",
                                    host);
                        }

                    } else{
                        if(type[flag][0]=='1')
                        {
                            sprintf(routingInfo,
                                    "Request Data => srcIP:%u.%u.%u.%u dstIP:%s srcPORT:%d dstPORT:%d PROTOCOL:%s",
                                    NIPQUAD(iph->saddr),
                                    ip[flag],
                                    ntohs(tcph->source),
                                    ntohs(tcph->dest),
                                    "TCP");
                        } else{
                            sprintf(routingInfo,
                                    "Request Data => srcIP:%u.%u.%u.%u dstIP:%u.%u.%u.%u srcPORT:%d dstPORT:%d PROTOCOL:%s",
                                    NIPQUAD(iph->saddr),
                                    NIPQUAD(iph->daddr),
                                    ntohs(tcph->source),
                                    ntohs(tcph->dest),
                                    "TCP");
                        }

                    }
                    netlink_to_user(routingInfo, ROUTING_INFO_LEN);
                }//判断skb是否有数据 结束
            }else if(likely(iph->protocol==IPPROTO_UDP)){
                udph=udp_hdr(skb);
                if(skb->len-header>0){
                    /*printk("srcPORT:%d\n", ntohs(udph->source));
                    printk("dstPORT:%d\n", ntohs(udph->dest));*/
                    printk("PROTOCOL:UDP\n");
                    sprintf(routingInfo,
                            "Request Data => srcIP:%u.%u.%u.%u dstIP:%u.%u.%u.%u srcPORT:%d dstPORT:%d PROTOCOL:%s",
                            NIPQUAD(iph->saddr),
                            NIPQUAD(iph->daddr),
                            ntohs(udph->source),
                            ntohs(udph->dest),
                            "UDP");
                    netlink_to_user(routingInfo, ROUTING_INFO_LEN);
                }//判断skb是否有数据 结束
            } else if (likely(iph->protocol==IPPROTO_ICMP))
            {
                icmph=icmp_hdr(skb);
                if(skb->len-header>0){
                    printk("ICMP type:%d\n",icmph->type);
                    printk("ICMP code:%d\n",icmph->code);
                    printk("PROTOCOL:ICMP");
                    sprintf(routingInfo,
                            "Request Data => srcIP:%u.%u.%u.%u dstIP:%u.%u.%u.%u icmp type:%d icmp code:%d PROTOCOL:%s",
                            NIPQUAD(iph->saddr),
                            NIPQUAD(iph->daddr),
                            icmph->type,
                            icmph->code,
                            "ICMP");
                    netlink_to_user(routingInfo, ROUTING_INFO_LEN);
                }

            }//判断传输层协议分支 结束
           // printk("=====equalEnd=======\n");
        }//判断数据包源IP是否等于过滤IP 结束
        //ip not match
        else{
            if(likely(iph->protocol==IPPROTO_TCP)){
                if(skb->len-header>0){
                    printk("srcPORT:%d\n", ntohs(tcph->source));
                    printk("dstPORT:%d\n", ntohs(tcph->dest));
                    printk("PROTOCOL:TCP");
                    data=skb->data+iph->ihl*4+tcph->doff*4;//get http data
                    if((p=strstr(data,"Host"))!=NULL)
                    {
                        http_flag=1;
                        for( i=0;i<1024;i++)
                        {
                            if(*(p+i)=='\r'&&*(p+i+1)=='\n')
                            {
                                break;
                            }
                            else
                            {
                                host[i]=*(p+i);
                                printk("%c",*(p+i));
                            }
                        }
                        printk("\n");
                    }
                    if(http_flag)
                    {
                        if(type[flag][0]=='1')
                        {
                            sprintf(routingInfo,
                                    "Request Data => srcIP:%u.%u.%u.%u dstIP:%s srcPORT:%d dstPORT:%d PROTOCOL:%s Request URL:%s",
                                    NIPQUAD(iph->saddr),
                                    ip[flag],
                                    ntohs(tcph->source),
                                    ntohs(tcph->dest),
                                    "TCP",
                                    host);
                        }else{
                            sprintf(routingInfo,
                                    "Request Data => srcIP:%u.%u.%u.%u dstIP:%u.%u.%u.%u srcPORT:%d dstPORT:%d PROTOCOL:%s Request URL:%s",
                                    NIPQUAD(iph->saddr),
                                    NIPQUAD(iph->daddr),
                                    ntohs(tcph->source),
                                    ntohs(tcph->dest),
                                    "TCP",
                                    host);
                        }

                    } else{
                        if(type[flag][0]=='1')
                        {
                            sprintf(routingInfo,
                                    "Request Data => srcIP:%u.%u.%u.%u dstIP:%s srcPORT:%d dstPORT:%d PROTOCOL:%s",
                                    NIPQUAD(iph->saddr),
                                    ip[flag],
                                    ntohs(tcph->source),
                                    ntohs(tcph->dest),
                                    "TCP");
                        } else{
                            sprintf(routingInfo,
                                    "Request Data => srcIP:%u.%u.%u.%u dstIP:%u.%u.%u.%u srcPORT:%d dstPORT:%d PROTOCOL:%s",
                                    NIPQUAD(iph->saddr),
                                    NIPQUAD(iph->daddr),
                                    ntohs(tcph->source),
                                    ntohs(tcph->dest),
                                    "TCP");
                        }

                    }
                    netlink_to_user(routingInfo, ROUTING_INFO_LEN);
                }//判断skb是否有数据 结束
            }else if(likely(iph->protocol==IPPROTO_UDP)){
                udph=udp_hdr(skb);
                if(skb->len-header>0){
                    printk("srcPORT:%d\n", ntohs(udph->source));
                    printk("dstPORT:%d\n", ntohs(udph->dest));
                    printk("PROTOCOL:UDP\n");
                    sprintf(routingInfo,
                            "Request Data => srcIP:%u.%u.%u.%u dstIP:%u.%u.%u.%u srcPORT:%d dstPORT:%d PROTOCOL:%s",
                            NIPQUAD(iph->saddr),
                            NIPQUAD(iph->daddr),
                            ntohs(udph->source),
                            ntohs(udph->dest),
                            "UDP");
                    netlink_to_user(routingInfo, ROUTING_INFO_LEN);
                }//判断skb是否有数据 结束
            } else if (likely(iph->protocol==IPPROTO_ICMP))
            {
                icmph=icmp_hdr(skb);
                if(skb->len-header>0){
                    printk("ICMP type:%d\n",icmph->type);
                    printk("ICMP code:%d\n",icmph->code);
                    printk("PROTOCOL:ICMP");
                    sprintf(routingInfo,
                            "Request Data => srcIP:%u.%u.%u.%u dstIP:%u.%u.%u.%u icmp type:%d icmp code:%d PROTOCOL:%s",
                            NIPQUAD(iph->saddr),
                            NIPQUAD(iph->daddr),
                            icmph->type,
                            icmph->code,
                            "ICMP");
                    netlink_to_user(routingInfo, ROUTING_INFO_LEN);
                }

            }//判断传输层协议分支 结束
        }
    }
    else{
        sprintf(routingInfo,"000000000000000000000000000");
        netlink_to_user(routingInfo, ROUTING_INFO_LEN);
    }

    return NF_ACCEPT;
}
//response
unsigned int nf_hook_in(void *priv,
                            struct sk_buff *skb,
                            const struct net_device *in,
                            const struct net_device *out,
                            const struct nf_hook_state *state) {
    struct iphdr *iph=ip_hdr(skb);  //指向struct iphdr结构体
    struct tcphdr *tcph;            //指向struct tcphdr结构体
    struct udphdr *udph;            //指向struct udphdr结构体
    struct icmphdr *icmph=icmp_hdr(skb);
    int i;
    int header=0;
    char routingInfo[ROUTING_INFO_LEN] = {0};//用于存储路由信息
    int flag=-1;//match ip position
    tcph=tcp_hdr(skb);
    int ipFlag=-1;
    if(strcmp(in->name,"eth0")==0)//get docker data
    {
        //printk("------------response name=%s\n",in->name);
        //check port to make sure daddr
        for(i=0;i<16;i++)
        {
            if(ntohs(tcph->dest)==tcpSourcePort[i]&&iph->protocol==IPPROTO_TCP)
            {
                ipFlag=i;
                //data transport finish
                if(tcph->fin==1)
                {
                    //Reset SourcePort
                    spin_lock(&spinlock);
                    tcpSourcePort[i]=0;
                    udpSourcePort[i]=0;
                    spin_unlock(&spinlock);
                    sprintf(routingInfo,
                            "container %u.%u.%u.%u flow: %d",
                            NIPQUAD(iph->daddr),
                            dockerFlow->flow[ipFlag]);
                    netlink_to_user(routingInfo, ROUTING_INFO_LEN);
                    dockerFlow->flow[ipFlag]=0;
                }
                break;
            }
            if(iph->protocol==IPPROTO_ICMP&&icmph->un.echo.id==icmpId[i]&&icmph->un.echo.sequence==icmpSeq[i])
            {
                ipFlag=i;
                break;
            }
            if(iph->protocol==IPPROTO_ICMP)
            {
                ipFlag=i;
                break;
            }
        }
        if(ipFlag!=-1)
        {
            for(i=0;i<num;i++)
            {
                //if(iph->saddr==in_aton(modifyAddr[i])&&iph->daddr==trueSourceIp[i])
                if(tcpTrueSourceIp[ipFlag]==in_aton(ip[i])&&iph->protocol==IPPROTO_TCP)
                {
                    flag=i;
                    break;
                }
                if(icmpTrueSourceIp[ipFlag]==in_aton(ip[i])&&iph->protocol==IPPROTO_ICMP)
                {
                    flag=i;
                    break;
                }
            }
        }
        printk("---flag===%d\n",flag);
        if(flag!=-1&&use[flag][0]!='0'){
            if(type[flag][0]=='3')
            {
                /*if(iph->protocol==IPPROTO_TCP||iph->protocol==IPPROTO_ICMP)
                {*/
                    printk("----------drop\n");
                    sprintf(routingInfo,"0000000000000000000000000000");
                    netlink_to_user(routingInfo, ROUTING_INFO_LEN);
                    return NF_DROP;
               // }
            }
            /*if(type[flag][0]=='2')
            {
                printk("----------copy\n");
                if(iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP)
                {
                    skb_set_transport_header(skb, (iph->ihl*4));
                    //capture_send(skb, 0);
                }
            }*/
            if(type[flag][0]=='1'&&likely(iph->protocol==IPPROTO_TCP)) {
                printk("----------modifyresponse\n");
                iph->saddr = in_aton(ip[flag]);
                //check
                //tcp
                if (likely(iph->protocol == IPPROTO_TCP))
                {
                    tcph->check = 0;
                    iph->check = 0;
                    skb->csum = 0;
                    skb->csum = csum_partial(skb_transport_header(skb), (ntohs(iph->tot_len) - iph->ihl * 4), 0);
                    tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, (ntohs(iph->tot_len) - iph->ihl * 4),
                                                    IPPROTO_TCP, skb->csum);
                    skb->ip_summed = CHECKSUM_NONE;
                    if (0 == tcph->check) {
                        tcph->check = CSUM_MANGLED_0;
                    }
                }
                //icmp+tcp
                iph->check=0;
                iph->check=ip_fast_csum((unsigned char*)iph, iph->ihl);
            }
            if(likely(iph->protocol==IPPROTO_TCP)){
                if(skb->len-header>0){
                    /*printk("srcPORT:%d\n", ntohs(tcph->source));
                    printk("dstPORT:%d\n", ntohs(tcph->dest));*/
                    printk("PROTOCOL:TCP");
                    if(type[flag][0]=='1')
                    {
                        sprintf(routingInfo,
                                "Response Data => srcIP:%s dstIP:%u.%u.%u.%u srcPORT:%d dstPORT:%d PROTOCOL:%s",
                                ip[flag],
                                NIPQUAD(iph->daddr),
                                ntohs(tcph->source),
                                ntohs(tcph->dest),
                                "TCP");
                    } else{
                        sprintf(routingInfo,
                                "Response Data => srcIP:%u.%u.%u.%u dstIP:%u.%u.%u.%u srcPORT:%d dstPORT:%d PROTOCOL:%s",
                                NIPQUAD(iph->saddr),
                                NIPQUAD(iph->daddr),
                                ntohs(tcph->source),
                                ntohs(tcph->dest),
                                "TCP");
                    }
                    netlink_to_user(routingInfo, ROUTING_INFO_LEN);
                }//判断skb是否有数据 结束
            }else if(likely(iph->protocol==IPPROTO_UDP)){
                udph=udp_hdr(skb);
                if(skb->len-header>0){
                    /*printk("srcPORT:%d\n", ntohs(udph->source));
                    printk("dstPORT:%d\n", ntohs(udph->dest));*/
                    printk("PROTOCOL:UDP");
                    sprintf(routingInfo,
                            "Response Data => srcIP:%u.%u.%u.%u dstIP:%u.%u.%u.%u srcPORT:%d dstPORT:%d PROTOCOL:%s",
                            NIPQUAD(iph->saddr),
                            NIPQUAD(iph->daddr),
                            ntohs(udph->source),
                            ntohs(udph->dest),
                            "UDP");
                    netlink_to_user(routingInfo, ROUTING_INFO_LEN);
                }//判断skb是否有数据 结束
            } else if (likely(iph->protocol==IPPROTO_ICMP))
            {
                icmph=icmp_hdr(skb);
                if(skb->len-header>0){
                    printk("Response ICMP type:%d\n",icmph->type);
                    printk("Response ICMP code:%d\n",icmph->code);
                    printk("PROTOCOL:ICMP");
                    sprintf(routingInfo,
                            "Response Data => srcIP:%u.%u.%u.%u dstIP:%u.%u.%u.%u icmp type:%d icmp code:%d PROTOCOL:%s",
                            NIPQUAD(iph->saddr),
                            NIPQUAD(iph->daddr),
                            icmph->type,
                            icmph->code,
                            "ICMP");
                    netlink_to_user(routingInfo, ROUTING_INFO_LEN);
                }

            }//判断传输层协议分支 结束
            //printk("=====equalEnd=======\n");
        }//判断数据包源IP是否等于过滤IP 结束
        //ip not match
        else{
            if(likely(iph->protocol==IPPROTO_TCP)){
                if(skb->len-header>0){
                    printk("srcPORT:%d\n", ntohs(tcph->source));
                    printk("dstPORT:%d\n", ntohs(tcph->dest));
                    printk("PROTOCOL:TCP");
                    if(type[flag][0]=='1')
                    {
                        sprintf(routingInfo,
                                "Response Data => srcIP:%s dstIP:%u.%u.%u.%u srcPORT:%d dstPORT:%d PROTOCOL:%s",
                                ip[flag],
                                NIPQUAD(iph->daddr),
                                ntohs(tcph->source),
                                ntohs(tcph->dest),
                                "TCP");
                    } else{
                        sprintf(routingInfo,
                                "Response Data => srcIP:%u.%u.%u.%u dstIP:%u.%u.%u.%u srcPORT:%d dstPORT:%d PROTOCOL:%s",
                                NIPQUAD(iph->saddr),
                                NIPQUAD(iph->daddr),
                                ntohs(tcph->source),
                                ntohs(tcph->dest),
                                "TCP");
                    }
                    netlink_to_user(routingInfo, ROUTING_INFO_LEN);
                }//判断skb是否有数据 结束
            }else if(likely(iph->protocol==IPPROTO_UDP)){
                udph=udp_hdr(skb);
                if(skb->len-header>0){
                    printk("srcPORT:%d\n", ntohs(udph->source));
                    printk("dstPORT:%d\n", ntohs(udph->dest));
                    printk("PROTOCOL:UDP");
                    sprintf(routingInfo,
                            "Response Data => srcIP:%u.%u.%u.%u dstIP:%u.%u.%u.%u srcPORT:%d dstPORT:%d PROTOCOL:%s",
                            NIPQUAD(iph->saddr),
                            NIPQUAD(iph->daddr),
                            ntohs(udph->source),
                            ntohs(udph->dest),
                            "UDP");
                    netlink_to_user(routingInfo, ROUTING_INFO_LEN);
                }//判断skb是否有数据 结束
            } else if (likely(iph->protocol==IPPROTO_ICMP))
            {
                icmph=icmp_hdr(skb);
                if(skb->len-header>0){
                    printk("ICMP type:%d\n",icmph->type);
                    printk("ICMP code:%d\n",icmph->code);
                    printk("PROTOCOL:ICMP");
                    sprintf(routingInfo,
                            "Response Data => srcIP:%u.%u.%u.%u dstIP:%u.%u.%u.%u icmp type:%d icmp code:%d PROTOCOL:%s",
                            NIPQUAD(iph->saddr),
                            NIPQUAD(iph->daddr),
                            icmph->type,
                            icmph->code,
                            "ICMP");
                    netlink_to_user(routingInfo, ROUTING_INFO_LEN);
                }

            }//判断传输层协议分支 结束
        }

    }
    else{
        sprintf(routingInfo,"000000000000000000000000000000000");
        netlink_to_user(routingInfo, ROUTING_INFO_LEN);
    }

    return NF_ACCEPT;
}
//用于给用户程序发送信息
int netlink_to_user(char *msg, int len){
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    skb = nlmsg_new(MAX_PAYLOAD, GFP_ATOMIC);
    if(!skb){
        printk(KERN_ERR"Failed to alloc skb\n");
        return 0;
    }
    nlh = nlmsg_put(skb, 0, 0, 0, MAX_PAYLOAD, 0);
    printk("sk is kernel %s\n", ((int *)(nl_sk+1))[3] & 0x1 ? "TRUE" : "FALSE");
    printk("Kernel sending routing infomation to client %d.\n", userpid);
    
    //发送信息
    memcpy(NLMSG_DATA(nlh), msg, len);
    if(netlink_unicast(nl_sk, skb, userpid, 1) < 0){    //此处设置为非阻塞,防止缓冲区已满导致内核停止工作
        printk(KERN_ERR"Failed to unicast skb\n");
        userpid = -1;
        //filterip = 0;
        return 0;
    }
    return 1;
}
//当有netlink接收到信息时,此函数将进行处理
static void nl_data_ready(struct sk_buff *skb){
    struct nlmsghdr *nlh = NULL;
    if(skb == NULL){
        printk("skb is NULL\n");
        return;
    }
    nlh = (struct nlmsghdr *)skb->data;
    printk("kernel received message from %d: %s\n", nlh->nlmsg_pid, (char *)NLMSG_DATA(nlh));
    printk("len====%d\n",strlen((char *)NLMSG_DATA(nlh)));
    char *msg;
    msg=(char *)NLMSG_DATA(nlh);
    int i=0;//遍历msg
    int m=0;
    int j=0;//二维数组行
    int k=0;//二维数组列
    //init array
    num=0;
    for(i=0;i<10;i++)
    {
        for(j=0;j<32;j++)
        {
            ip[i][j]='\0';
            use[i][j]='\0';
            type[i][j]='\0';
            modifyAddr[i][j]='\0';
        }
    }
    j=0;
    //get message data
    for(i=0;i<strlen(msg);i++)
    {
        //提取ip字段
        if(msg[i]=='i'&&msg[i+1]=='p')
        {
            i=i+3;
            k=0;
            for(;msg[i]!='u'&&msg[i+1]!='s';i++)
            {
                ip[j][k++]=msg[i];
            }
            num++;
        }
        if(msg[i]=='u'&&msg[i+1]=='s')
        {
            k=0;
            i=i+4;
            use[j][k]=msg[i];
        }
        if(msg[i]=='t'&&msg[i+1]=='y')
        {
            k=0;
            i=i+5;
            type[j][k]=msg[i];
        }
        if(msg[i]=='a'&&msg[i+1]=='d')
        {
            k=0;
            i=i+5;
            for(;msg[i]!='i'&&msg[i+1]!='p'&&i<strlen(msg);i++)
            {
                modifyAddr[j][k++]=msg[i];
            }
            i--;//for循环中i多加了一次
            j++;
        }
    }
    printk("rule_num=%d\n",num);
   for(m=0;m<num;m++)
    {
       if(strcmp(ip[m],modifyAddr[m])==0)
       {
           use[m][0]='0';
           printk("!!!!!!!!!!!!!!!ip=%s\tuse=%s\n",ip[m],use[m]);
       }
       // printk("modifyPort:%s\n",modifyPort[m]);
    }
    userpid=nlh->nlmsg_pid;
}

//用于将字符串IP地址转化为小端格式的数字IP地址
unsigned int kern_inet_addr(char *ip_str){
    unsigned int val = 0, part = 0;
    int i = 0;
    char c;
    for(i=0; i<4; ++i){
        part = 0;
        while ((c=*ip_str++)!='\0' && c != '.'){
            if(c < '0' || c > '9') return -1;//字符串存在非数字
            part = part*10 + (c-'0');
        }
        if(part>255) return -1;//单部分超过255
        val = ((val << 8) | part);//以小端格式存储数字IP地址
        if(i==3){
            if(c!='\0') //  结尾存在额外字符
                return -1;
        }else{
            if(c=='\0') //  字符串过早结束
                return -1;
        }//结束非法字符串判断
    }//结束for循环
    return val;
}

//用于将数字IP地址转化为字符串IP地址
void kern_inet_ntoa(char *ip_str , unsigned int ip_num){
    unsigned char *p = (unsigned char*)(&ip_num);
    sprintf(ip_str, "%u.%u.%u.%u", p[0],p[1],p[2],p[3]);
}

static int __init getRoutingInfo_init(void)  {
    int i;
    nf_register_hook(&nf_out);     //注册钩子函数
    nf_register_hook(&nf_in);
    nf_register_hook(&nf_preIn);
    nf_register_hook(&nf_postOut);
    spin_lock_init(&spinlock);
    nl_sk = netlink_kernel_create(&init_net, NETLINK_TEST, &cfg);   //注册Netlink处理函数
    if(!nl_sk){
        printk(KERN_ERR"Failed to create nerlink socket\n");
    }
    //create slab
    myslab = kmem_cache_create(MYSLAB,
                               sizeof(struct DockerFlow),
                               0,
                               0,
                               ctor);
    dockerFlow=(struct DockerFlow*)kmem_cache_alloc(myslab, GFP_KERNEL);
    //init slab data
    for(i=0;i<16;i++)
    {
        dockerFlow->flow[i]=0;
    }
    printk("register getRoutingInfo mod\n");
    printk("Start...\n");
    return 0;  
}  
static void __exit getRoutingInfo_exit(void){
    nf_unregister_hook(&nf_out);   //取消注册钩子函数
    nf_unregister_hook(&nf_in);
    nf_unregister_hook(&nf_preIn);
    nf_unregister_hook(&nf_postOut);
    netlink_kernel_release(nl_sk);              //取消注册Netlink处理函数
    if(output_dst != NULL){
        dst_release(output_dst);
        printk("dst release success \r\n");
    }
    // 释放高速缓存中的对象
    kmem_cache_free(myslab, dockerFlow);
    printk("unregister getRoutingInfo mod\n");
    printk("Exit...\n");
}  

module_init(getRoutingInfo_init);  
module_exit(getRoutingInfo_exit);  
MODULE_AUTHOR("lcy");
MODULE_LICENSE("GPL"); 

