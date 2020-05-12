#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pthread.h>
#define NETLINK_TEST 17         //用于自定义协议
#define MAX_PAYLOAD 1024        //最大载荷容量
#define RECEIVE_CNT 10          //接受路由信息的数量
#define MAX_LINE 20
int n = RECEIVE_CNT;                    //接受路由信息的数量
int sock_fd, store_fd;                   //套接字描述符, 文件描述符
struct iovec iov;                       //
struct msghdr msg;                      //存储发送的信息
struct nlmsghdr *nlh = NULL;            //用于封装信息的头部
struct sockaddr_nl src_addr, dest_addr; //源地址,目的地址(此处地址实际上就是pid)
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
time_t file_time;//record file modified time
void receive_msg()
{
    int flag=1;
    //receive message
    while(flag) {
        // 从kernel接受信息
        memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
        //pthread_mutex_lock(&mutex);
        recvmsg(sock_fd, &msg, 0);
        pthread_testcancel();
        //pthread_mutex_unlock(&mutex);
        if(((char *) NLMSG_DATA(nlh))[0]!='0')
        {
            printf("%s\n", (char *) NLMSG_DATA(nlh));
        }


    }
}
int main()
{
    char buf[MAX_LINE];  /*缓冲区*/
    FILE *fp;            /*文件指针*/
    int len;             /*行字符个数*/
    struct stat buff;
    pthread_t thread_receive;
    //build socket connection
    memset(buf,0,MAX_LINE*(sizeof(char)));
    sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_TEST);
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;        //协议族
    src_addr.nl_pid = getpid();             //本进程pid
    src_addr.nl_groups = 0;                 //多播组,0表示不加入多播组
    bind(sock_fd, (struct sockaddr *) &src_addr, sizeof(src_addr));
    memset(&dest_addr, 0, sizeof(dest_addr));
    out:
    dest_addr.nl_family = AF_NETLINK;       //协议族
    dest_addr.nl_pid = 0;                   //0表示kernel的pid
    dest_addr.nl_groups = 0;                //多播组,0表示不加入多播组
    nlh = (struct nlmsghdr *) malloc(NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);  //设置缓存空间
    nlh->nlmsg_pid = getpid();                  //本进程pid
    nlh->nlmsg_flags = 0;                       //额外说明信息

    if((fp = fopen("ip.txt","a+")) == NULL)
    {
        perror("fail to read");
        exit (1) ;
    }
    while(fgets(buf,MAX_LINE,fp) != NULL)
    {
        len = strlen(buf);
        if(buf[len-1]=='\n')
        {
            buf[--len] = '\0';  //去掉换行符
        }
        else
        {
            buf[len] = '\0';    //最后一行数据没有换行符
        }
        strcat(NLMSG_DATA(nlh), buf);//将需要捞取的路由信息源地址
    }
    //printf("mesg=%s\n",mesg);
    fclose(fp);
    printf("NLSG=%s\n",NLMSG_DATA(nlh));
    iov.iov_base = (void *) nlh;
    iov.iov_len = nlh->nlmsg_len;
    msg.msg_name = (void *) &dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    //pthread_mutex_lock(&mutex);
    sendmsg(sock_fd, &msg, 0);  // 发送信息到kernel
    int thread2=pthread_create(&thread_receive,NULL,(void *)&receive_msg,NULL);
    if (thread2 != 0)
    {
        printf("线程创建失败\n");
    }
    else
    {
        printf("线程创建成功\n");
    }
    //Check if the file has been modified
    //get file last modified time
    stat( "ip.txt", &buff );
    file_time=buff.st_mtime;
    printf("messages are sent\n");
    while(1)
    {
        if( stat( "ip.txt", &buff ) != -1 ) {
            if(file_time!=buff.st_mtime)
            {
                printf("rules are modified\n");
                pthread_cancel(thread_receive);
                goto out;
            }
        }
    }
    //when all thread have done,exit process
    pthread_exit(NULL);
    return 0;
}
