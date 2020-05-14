//内核编程需要的头文件
#include <linux/module.h>
#include <linux/kernel.h>
//Netfilter需要的头文件
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/kmod.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/icmp.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <linux/inet.h>///in_aton()function
//netlink需要的头文件
#include <net/sock.h>
#include <net/net_namespace.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/netlink.h>

//NIPQUAD宏便于把数字IP地址输出
#define NIPQUAD(addr) \
((unsigned char *)&addr)[0], \
((unsigned char *)&addr)[1], \
((unsigned char *)&addr)[2], \
((unsigned char *)&addr)[3]

#define NETLINK_TEST 17         //用于自定义协议
#define MAX_PAYLOAD 1024        //最大载荷容量
#define ROUTING_INFO_LEN 512    //单个路由信息的容量

//函数声明
unsigned int kern_inet_addr(char *ip_str);
void kern_inet_ntoa(char *ip_str , unsigned int ip_num);
unsigned int nf_hook_out(void *priv, struct sk_buff *skb, const struct net_device *in,
                         const struct net_device *out,const struct nf_hook_state *state);
unsigned int nf_hook_in(void *priv, struct sk_buff *skb, const struct net_device *in,
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
//用于描述Netlink处理函数信息
struct netlink_kernel_cfg cfg = {
    .input = nl_data_ready,
};

static struct sock *nl_sk = NULL;   //用于标记netlink
static int userpid = -1;            //用于存储用户程序的pid
//static unsigned int filterip = 0;   //用于存储需要过滤的源IP，小端格式
char ip[10][32]={'\0'};              //ip data in message
char use[10][32]={'\0'};              //
char type[10][32]={'\0'};
char modifyAddr[10][32]={'\0'};
char modifyPort[10][32]={'\0'};
int num=0;//get rule num
int flag=-1;//match ip position
//request
unsigned int nf_hook_out(void *priv,
                     struct sk_buff *skb,
                     const struct net_device *in,
                     const struct net_device *out,
                     const struct nf_hook_state *state){
    struct iphdr *iph=ip_hdr(skb);  //指向struct iphdr结构体
    struct tcphdr *tcph;            //指向struct tcphdr结构体
    struct udphdr *udph;            //指向struct udphdr结构体
    struct icmphdr *icmph;
    int header=0;
    //int flag=-1;//match ip position
    int i;//for loop elem to get host
    char *p=NULL;//get Host
    int http_flag=0;//is or not http data
    char host[128]={'\0'};
    //char mm[10]="hello";
    unsigned char *data=NULL;//HTTP data
    char routingInfo[ROUTING_INFO_LEN] = {0};//用于存储路由信息
    tcph=tcp_hdr(skb);
    //printk("request out name: %s\n",out->name);
    //printk("request out bieming: %s\n",out->ifalias);
    printk("saddr=%d\n",ntohl(iph->saddr));
    if(strcmp(out->name,"eth0")==0)
    {          //get docker data
        printk("------------out name=%s\n",out->name);
        for(i=0;i<num;i++)
        {
            if(kern_inet_addr(ip[i])==ntohl(iph->saddr)||kern_inet_addr(ip[i])==ntohl(iph->daddr))
            {
                flag=i;
                break;
            }
        }
        //match ip rule
        if(flag!=-1&&use[flag][0]!='0'){
            //drop data
            if(type[flag][0]=='3')
            {
                printk("----------drop\n");
                sprintf(routingInfo,"0000000000000000000000000000");
                netlink_to_user(routingInfo, ROUTING_INFO_LEN);
                return NF_DROP;
            }
            if(type[flag][0]=='1'&&likely(iph->protocol!=IPPROTO_UDP)) {
                printk("----------modify\n");
                iph->daddr = in_aton(modifyAddr[flag]);
                //check
                //tcp
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
            printk("=======equal========\n");
            printk("srcIP: %u.%u.%u.%u\n", NIPQUAD(iph->saddr));
            printk("dstIP: %u.%u.%u.%u\n", NIPQUAD(iph->daddr));
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
                        sprintf(routingInfo,
                                "Request Data => srcIP:%u.%u.%u.%u dstIP:%s srcPORT:%d dstPORT:%d PROTOCOL:%s Request URL:%s",
                                NIPQUAD(iph->saddr),
                                ip[flag],
                                ntohs(tcph->source),
                                ntohs(tcph->dest),
                                "TCP",
                                host);
                    } else{
                        sprintf(routingInfo,
                                "Request Data => srcIP:%u.%u.%u.%u dstIP:%s srcPORT:%d dstPORT:%d PROTOCOL:%s",
                                NIPQUAD(iph->saddr),
                                ip[flag],
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
            printk("=====equalEnd=======\n");
        }//判断数据包源IP是否等于过滤IP 结束
        else{
            sprintf(routingInfo,"0000000000000000000000000000");
            netlink_to_user(routingInfo, ROUTING_INFO_LEN);
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
    struct icmphdr *icmph;
    int i;

    int header=0;
    char routingInfo[ROUTING_INFO_LEN] = {0};//用于存储路由信息
    tcph=tcp_hdr(skb);
    if(strcmp(in->name,"eth0")==0)//get docker data
    {
        printk("------------response name=%s\n",in->name);
        if(flag!=-1&&use[flag][0]!='0'){
            if(type[flag][0]=='3')
            {
                printk("----------drop\n");
                sprintf(routingInfo,"0000000000000000000000000000");
                netlink_to_user(routingInfo, ROUTING_INFO_LEN);
                return NF_DROP;
            }
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
            printk("=======equal========");
            printk("srcIP: %u.%u.%u.%u\n", NIPQUAD(iph->saddr));
            printk("dstIP: %u.%u.%u.%u\n", NIPQUAD(iph->daddr));
            if(likely(iph->protocol==IPPROTO_TCP)){
                if(skb->len-header>0){
                    printk("srcPORT:%d\n", ntohs(tcph->source));
                    printk("dstPORT:%d\n", ntohs(tcph->dest));
                    printk("PROTOCOL:TCP");
                    sprintf(routingInfo,
                            "Response Data => srcIP:%s dstIP:%u.%u.%u.%u srcPORT:%d dstPORT:%d PROTOCOL:%s",
                            ip[flag],
                            NIPQUAD(iph->daddr),
                            ntohs(tcph->source),
                            ntohs(tcph->dest),
                            "TCP");
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
            printk("=====equalEnd=======\n");
        }//判断数据包源IP是否等于过滤IP 结束
        else{
            sprintf(routingInfo,"000000000000000000000000000000000");
            netlink_to_user(routingInfo, ROUTING_INFO_LEN);
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
            modifyPort[i][j]='\0';
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
            for(;msg[i]!='m'&&msg[i+1]!='o';i++)
            {
                modifyAddr[j][k++]=msg[i];
            }
        }
        if(msg[i]=='p'&&msg[i+1]=='o')
        {
            k=0;
            i=i+5;
            for(;msg[i]!='i'&&msg[i+1]!='p'&&i<strlen(msg);i++)
            {
                modifyPort[j][k++]=msg[i];
            }
            i--;//for循环中i多加了一次
            j++;
        }
    }
    printk("rule_num=%d\n",num);
    for(m=0;m<num;m++)
    {
        printk("ip:%s\t",ip[m]);
        printk("use:%s\t",use[m]);
        printk("type:%s\t",type[m]);
        printk("modifyAddr:%s\t",modifyAddr[m]);
        printk("modifyPort:%s\n",modifyPort[m]);
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
    nf_register_hook(&nf_out);     //注册钩子函数
    nf_register_hook(&nf_in);
    nl_sk = netlink_kernel_create(&init_net, NETLINK_TEST, &cfg);   //注册Netlink处理函数
    if(!nl_sk){
        printk(KERN_ERR"Failed to create nerlink socket\n");
    }
    printk("register getRoutingInfo mod\n");
    printk("Start...\n");
    return 0;  
}  
static void __exit getRoutingInfo_exit(void){
    nf_unregister_hook(&nf_out);   //取消注册钩子函数
    nf_unregister_hook(&nf_in);
    netlink_kernel_release(nl_sk);              //取消注册Netlink处理函数
    printk("unregister getRoutingInfo mod\n");
    printk("Exit...\n");
}  

module_init(getRoutingInfo_init);  
module_exit(getRoutingInfo_exit);  
MODULE_AUTHOR("lcy");
MODULE_LICENSE("GPL"); 

