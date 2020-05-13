/*
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/init.h>
#include <linux/inet.h>///in_aton()function
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/skbuff.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/kmod.h>
#include <linux/workqueue.h>
#include <uapi/linux/netfilter_ipv4.h>
#include <linux/mm.h>
#include <net/ip.h>

#include <linux/netfilter_ipv4.h>//ip_route_me_harder

unsigned short source_sport = 0;
struct dst_entry *output_dst = NULL; //出口设备指针
unsigned short capture_get_port(const struct sk_buff *skb,int dir) {
    struct iphdr *iph = NULL;
    struct tcphdr *tcph = NULL;
    struct udphdr *udph = NULL;
    unsigned short port = 0;

    iph = ip_hdr(skb);
    if (!iph) {
        printk("ip header null \r\n");
        return 0;
    }

    if (iph->protocol == IPPROTO_TCP) {
        tcph = tcp_hdr(skb);
        if (!tcph) {
            printk("tcp header null \r\n");
            return 0;
        }

        if (dir == 0) {
            port = ntohs(tcph->dest);
            tcph = NULL;
            return port;
        } else {
            port = ntohs(tcph->source);
            tcph = NULL;
            return port;
        }
    } else if (iph->protocol == IPPROTO_UDP) {
        udph = udp_hdr(skb);
        if (!udph) {
            printk("udp header null \r\n");
            return 0;
        }
        if (dir == 0) {
            port = ntohs(udph->dest);
            udph = NULL;
            return port;
        } else {
            port = ntohs(udph->source);
            udph = NULL;
            return port;
        }
    } else
        return 0;
}
static void send_skb(struct sk_buff *skb)
{
    int ret;
    struct sk_buff *skb_cp  = NULL;
    skb_cp = skb_copy(skb, GFP_ATOMIC);
    if(!skb_cp){
        printk(" copy skb fail \r\n");
        return ;
    }
    struct iphdr *iph = ip_hdr(skb_cp);
    struct tcphdr *tcph = tcp_hdr(skb_cp);
    printk(KERN_INFO"source IP is %pI4\n", &iph->saddr);
    printk(KERN_INFO"dest IP is %pI4\n", &iph->daddr);
    //设置出口设备
    if(skb_dst(skb_cp) == NULL){
        if(output_dst == NULL){
            kfree_skb(skb_cp);
            return;
        }else{
            dst_hold(output_dst);
            skb_dst_set(skb_cp, output_dst);
        }
    }
    iph->daddr=in_aton("218.7.43.8");
    source_sport=  ntohs(tcph->source);
    printk("true sport=%d\n",source_sport);
    tcph->source = htons(0);
    iph->check = 0;
    tcph->check = 0;
    skb_cp->csum = 0;
    skb_cp->csum = csum_partial(skb_transport_header(skb_cp), (ntohs(iph->tot_len) - iph->ihl * 4), 0);
    tcph->check = csum_tcpudp_magic(iph->saddr,iph->daddr, (ntohs(iph->tot_len) - iph->ihl * 4), IPPROTO_TCP, skb_cp->csum);
    skb_cp->ip_summed = CHECKSUM_NONE;
    if (0 == tcph->check){
        tcph->check = CSUM_MANGLED_0;
    }
    iph->check=0;
    iph->check=ip_fast_csum((unsigned char*)iph, iph->ihl);
    //路由查找
    if(ip_route_me_harder(skb_cp, RTN_UNSPEC)){
        kfree_skb(skb_cp);
        printk("ip route failed \r\n");
        return ;
    }

    //发送
    ip_local_out(skb_cp);
}
unsigned int my_hookout(unsigned int hooknum,struct sk_buff *skb,
                        const struct net_device *in,
                        const struct net_device *out,
                        int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *tcph = tcp_hdr(skb);
    struct udphdr *udph = udp_hdr(skb);
    unsigned short sport = 0;
    if(iph->saddr==in_aton("172.17.0.2"))
    {
        if(likely(iph->protocol==IPPROTO_UDP))
        {
            printk("request UDP\n");
            return NF_ACCEPT;
        }
        sport = capture_get_port(skb,1);
        if(output_dst == NULL) {
            if (skb_dst(skb) != NULL) {
                output_dst = skb_dst(skb);
                dst_hold(output_dst);
                printk("dst get success \r\n");
            }
        }
        if(sport!=0)
            send_skb(skb);
        if(iph->daddr==in_aton("210.30.199.4"))
            return NF_STOLEN;
    }
    return NF_ACCEPT;
}
unsigned int my_hookin(unsigned int hooknum,struct sk_buff *skb,
                        const struct net_device *in,
                        const struct net_device *out,
                        int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph=ip_hdr(skb);
    struct tcphdr *tcph=tcp_hdr(skb);
    if(iph->daddr==in_aton("172.17.0.2"))
    {
        if(iph->protocol==IPPROTO_UDP)
        {
            printk("response UDP\n");
            return NF_ACCEPT;
        }
        if(tcph->dest==htons(0))
        {
            printk("dest port=%d\n",ntohs(tcph->dest));
            printk(KERN_INFO"source IP is %pI4\n", &iph->saddr);
            iph->saddr=in_aton("210.30.199.4");
            tcph->dest=htons(source_sport);
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
static struct nf_hook_ops nh_out = {
        .hook = my_hookout,
        .pf = PF_INET,
        .hooknum = NF_INET_LOCAL_OUT,
        .priority = NF_IP_PRI_FIRST,
        .owner = THIS_MODULE,
};
static struct nf_hook_ops nh_in = {
        .hook = my_hookin,
        .pf = PF_INET,
        .hooknum = NF_INET_LOCAL_IN,
        .priority = NF_IP_PRI_FIRST,
        .owner = THIS_MODULE,
};
static int __init http_init(void)
{
    //注册钩子函数
    nf_register_hook(&nh_out);
    nf_register_hook(&nh_in);
    printk("register getRoutingInfo mod\n");
    printk("Start...\n");
    return 0;
}

static void __exit http_exit(void)
{
    nf_unregister_hook(&nh_out);
    nf_unregister_hook(&nh_in);
    if(output_dst != NULL){
        dst_release(output_dst);
        printk("dst release success \r\n");
    }
    printk(KERN_INFO"removed\n");
}

module_init(http_init);
module_exit(http_exit);
MODULE_LICENSE("GPL");
*/
/*
 *  Description : 内核抓包模块demo，内核版本3.4.39
 *  Date        : 20180701
 *  Author      : fuyuande
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/socket.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_arp.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/skbuff.h>
#include <linux/inet.h>
#include <linux/icmp.h>
#include "testCopy.h"

struct dst_entry *output_dst = NULL; //出口设备指针

//查询报文源端口或者目的端口
unsigned short capture_get_port(const struct sk_buff *skb,int dir)
{
    struct iphdr  *iph  = NULL;
    struct tcphdr *tcph = NULL;
    struct udphdr *udph = NULL;
    unsigned short port = 0;

    iph = ip_hdr(skb);
    if(!iph){
        printk("ip header null \r\n");
        return 0;
    }

    if(iph->protocol == IPPROTO_TCP){
        tcph = tcp_hdr(skb);
        if(!tcph){
            printk("tcp header null \r\n");
            return 0;
        }

        if(dir == 0){
            port = ntohs(tcph->dest);
            tcph = NULL;
            return port;
        }else{
            port = ntohs(tcph->source);
            tcph = NULL;
            return port;
        }
    }
    else if(iph->protocol == IPPROTO_UDP){
        udph = udp_hdr(skb);
        if(!udph){
            printk("udp header null \r\n");
            return 0;
        }
        if(dir == 0){
            port = ntohs(udph->dest);
            udph = NULL;
            return port;
        }else{
            port = ntohs(udph->source);
            udph = NULL;
            return port;
        }
    }
    else
        return 0;
}

//查询传输层协议 TCP/UDP/ICMP
unsigned int capture_get_transport_protocol(const struct sk_buff *skb){
    struct iphdr *iph = NULL;
    iph = ip_hdr(skb);
    if(!iph)
        return 0;

    if(iph->protocol == IPPROTO_TCP)
        return (CAPTURE_TCP);

    if(iph->protocol == IPPROTO_UDP)
        return (CAPTURE_UDP);

    return 0;
}

//复制报文并添加新的头域发送到指定的接收地址
int capture_send(const struct sk_buff *skb, int output)
{
    struct ethhdr  *oldethh = NULL;
    struct iphdr   *oldiph  = NULL;
    struct iphdr   *newiph  = NULL;
    struct udphdr  *newudph = NULL;
    struct icmphdr  *newicmph = NULL;
    struct sk_buff *skb_cp  = NULL;
    struct net *net = NULL;
    unsigned int headlen = 0;
    unsigned short len;
    headlen = 60;    // mac + ip + udp = 14 + 20 + 8 = 42, 这里分配大一点

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

    //添加IP, UDP头部
    skb_push(skb_cp, sizeof(struct iphdr) + sizeof(struct udphdr));
    skb_reset_network_header(skb_cp);
    skb_set_transport_header(skb_cp,sizeof(struct iphdr));
    newiph = ip_hdr(skb_cp);
    newicmph = icmp_hdr(skb_cp);

    if((newiph == NULL) || (newicmph == NULL)){
        printk("new ip udp header null \r\n");
        kfree_skb(skb_cp);
        return -1;
    }

    /* 抓包的报文发送的时候是调用协议栈函数发送的，所以output钩子函数会捕获到抓包报文，
     * 这里我们要把抓包报文和正常报文区分开，区分方式就是判断源端口，我们抓到的报文
     *  在送出去的时候填写的是保留端口0，如果钩子函数遇到这样的报文就会直接let go
     * 防止重复抓包，这一点在测试的时候很重要，一旦重复抓包，系统就直接挂了...
     */
    memcpy((unsigned char*)newiph,(unsigned char*)oldiph,sizeof(struct iphdr));
    if(output)                                    //request
    {
        newicmph->type = 8;
        newicmph->code = 0;
        newiph->saddr = in_aton("172.17.0.2");
        newiph->daddr = in_aton("192.168.0.106"); //抓包服务器地址
    } else{                                       //response
        newicmph->type = 0;
        newicmph->code = 8;
        newiph->daddr = in_aton("172.17.0.2");
        newiph->saddr = in_aton("192.168.0.106"); //抓包服务器地址
    }
    newiph->ihl = 5;
    newiph->protocol = IPPROTO_ICMP;
    //newicmph->len = htons(ntohs(oldiph->tot_len) + sizeof(struct icmphdr) + sizeof(struct ethhdr));
    newiph->tot_len =  htons(ntohs(oldiph->tot_len) + sizeof(struct icmphdr) + sizeof(struct ethhdr)+ sizeof(struct iphdr));

    len=htons(ntohs(oldiph->tot_len) + sizeof(struct icmphdr) + sizeof(struct ethhdr));
    /* disable gso_segment */
    skb_shinfo(skb_cp)->gso_size = htons(0);

    //计算校验和
    newicmph->checksum = 0;
    newiph->check= 0;
    /*skb_cp->csum = 0;
    skb_cp->csum = csum_partial(skb_transport_header(skb_cp), htons(len), 0);*/
    //newudph->check = csum_tcpudp_magic(newiph->saddr, newiph->daddr, htons(newudph->len), IPPROTO_UDP, skb_cp->csum);
    newicmph->checksum=ip_compute_csum(newicmph, htons(len));
    skb_cp->ip_summed = CHECKSUM_NONE;
    /*if (0 == newudph->check){
        newudph->check = CSUM_MANGLED_0;
    }*/
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


//输入钩子函数
static unsigned int capture_input_hook(unsigned int hooknum,
                                       struct sk_buff *skb,
                                       const struct net_device *in,
                                       const struct net_device *out,
                                       int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph = NULL;
    struct icmphdr *icmph = NULL;
    unsigned short sport = 0;

    iph = ip_hdr(skb);
    icmph = icmp_hdr(skb);
    if(unlikely(!iph))
        return NF_ACCEPT;

    //只处理TCP和UDP
    if(iph->protocol==IPPROTO_ICMP)
    {
        printk("ICMP type:%d\n",icmph->type);
        printk("ICMP code:%d\n",icmph->code);
        printk(KERN_INFO"source IP is %pI4\n", &iph->saddr);
        printk(KERN_INFO"dest IP is %pI4\n", &iph->daddr);
    }
    if(iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
        return NF_ACCEPT;

    //源地址和目的地址相同，只抓一次，在output钩子上处理一遍就够了
    if(iph->saddr == iph->daddr)
        return NF_ACCEPT;

    //设置传输层首部指针
    skb_set_transport_header(skb, (iph->ihl*4));

    //检查端口，端口为0的let go
    sport = capture_get_port(skb,1);
    if(sport == 0)
        return NF_ACCEPT;

    //复制一份报文并发送出去
    capture_send(skb, 0);

    //返回accept，让系统正常处理
    return NF_ACCEPT;
}


//输出钩子函数
static unsigned int capture_output_hook(unsigned int hooknum,
                                        struct sk_buff *skb,
                                        const struct net_device *in,
                                        const struct net_device *out,
                                        int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph;
    struct icmphdr *icmph;
    unsigned short sport = 0;
    iph = ip_hdr(skb);
    icmph = icmp_hdr(skb);

    if(unlikely(!iph))
        return NF_ACCEPT;

    //只处理TCP或UDP
    if(iph->protocol==IPPROTO_ICMP)
    {
        printk("ICMP type:%d\n",icmph->type);
        printk("ICMP code:%d\n",icmph->code);
        printk(KERN_INFO"source IP is %pI4\n", &iph->saddr);
        printk(KERN_INFO"dest IP is %pI4\n", &iph->daddr);
    }
    if(iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)
        return NF_ACCEPT;

    //如果源端口为0，是抓包报文，直接let it go, 否则进行抓包
    sport = capture_get_port(skb,1);

    if(output_dst == NULL){
        if(skb_dst(skb) != NULL){

            output_dst = skb_dst(skb);
            dst_hold(output_dst);
            printk("dst get success \r\n");
        }
    }

    if(sport != 0)
        capture_send(skb, 1);

    return NF_ACCEPT;
}

struct nf_hook_ops capture_hook_ops[] = {
        {
                .hook=capture_input_hook,       //输入钩子处理函数
                .pf=NFPROTO_IPV4,
                .hooknum=NF_INET_LOCAL_IN,   //hook点
                .priority=NF_IP_PRI_FIRST + 10, //优先级
        },
        {
                .hook=capture_output_hook,      //输出钩子处理函数
                .pf=NFPROTO_IPV4,
                .hooknum=NF_INET_LOCAL_OUT,  //hook点
                .priority=0,                    //优先级
        },
        {}
};


static int __init capture_init(void)
{
    //注册钩子函数
    if(nf_register_hooks(capture_hook_ops,ARRAY_SIZE(capture_hook_ops))!=0)
    {
        printk("netfilter register fail");
        return -1;
    }
    printk("capture module init \r\n");
    return 0;
}

static void __exit capture_exit(void)
{
    //注销钩子函数
    nf_unregister_hooks(capture_hook_ops,ARRAY_SIZE(capture_hook_ops));
    if(output_dst != NULL){
        dst_release(output_dst);
        printk("dst release success \r\n");
    }
    printk("capture module exit \r\n");
    return ;
}

module_init(capture_init)
module_exit(capture_exit)

MODULE_ALIAS("capture");
MODULE_AUTHOR("fuyuande");
MODULE_DESCRIPTION("capture module");
MODULE_LICENSE("GPL");