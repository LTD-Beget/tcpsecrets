#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/ftrace.h>
#include <linux/version.h>
#include <net/tcp.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
#define SIPHASH_SYNCOOKIES
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#define USE_KPROBES
#endif

#ifdef SIPHASH_SYNCOOKIES
#include <linux/siphash.h>
#else
#include <linux/cryptohash.h>
#endif

#ifdef USE_KPROBES
#include <linux/kprobes.h>
#else
#include <linux/kallsyms.h>
#endif

static void *cookie_v4_check_ptr;

#ifdef SIPHASH_SYNCOOKIES
static siphash_key_t (*syncookie_secret_ptr)[2];
#else
static u32 (*syncookie_secret_ptr)[2][16-4+SHA_DIGEST_WORDS];
#endif

static struct proc_dir_entry *proc_entry;

static int tcp_secrets_show(struct seq_file *m, void *v)
{
	int i, j;
	seq_printf(m, "%lu %lu %d\n", (unsigned long) jiffies, (unsigned long)tcp_cookie_time(), HZ);
	for(i = 0; i < 2; i++) {
#ifdef SIPHASH_SYNCOOKIES
		for(j = 0; j < 2; j++) {
			seq_printf(m, "%.16llx.", (*syncookie_secret_ptr)[i].key[j]);
		}
#else
		for(j = 0; j < 16-4+SHA_DIGEST_WORDS; j++) {
			seq_printf(m, "%.8x.", (*syncookie_secret_ptr)[i][j]);
		}
#endif
        seq_printf(m, "\n");
	}
	return 0;
}

static int tcp_secrets_open(struct inode *inode, struct file *file)
{
	return single_open(file, tcp_secrets_show, NULL);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
static const struct proc_ops tcp_secrets_fops = {
	.proc_open		= tcp_secrets_open,
	.proc_read		= seq_read,
	.proc_lseek		= seq_lseek,
	.proc_release	= single_release,
};
#else
static const struct file_operations tcp_secrets_fops = {
	.open		= tcp_secrets_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};
#endif

static int symbol_walk_callback(void *data, const char *name,
				struct module *mod, unsigned long addr) {
	if (mod)
		return 0;

	if (strcmp(name, "cookie_v4_check") == 0) {
		cookie_v4_check_ptr = (void *)addr;
	}
	if (strcmp(name, "syncookie_secret") == 0) {
		syncookie_secret_ptr = (void *)addr;
	}
	return 0;
}

#ifdef USE_KPROBES
static int (*kallsyms_on_each_symbol_ptr)(int (*fn)(void *, const char *,
                                                 struct module *,
                                                 unsigned long),
                                       void *data);

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

static int dummy_kprobe_handler(struct kprobe *p, struct pt_regs *regs) {
	return 0;
}

static kallsyms_lookup_name_t get_kallsyms_lookup_name_ptr(void) {
	struct kprobe probe;
	int ret;
	kallsyms_lookup_name_t addr;

	memset(&probe, 0, sizeof(probe));
	probe.pre_handler = dummy_kprobe_handler;
	probe.symbol_name = "kallsyms_lookup_name";
	ret = register_kprobe(&probe);
	if (ret)
		return NULL;
	addr = (kallsyms_lookup_name_t) probe.addr;
	unregister_kprobe(&probe);

	return addr;
}

static unsigned long lookup_name(const char *name) {
	static kallsyms_lookup_name_t func_ptr = NULL;
	if (!func_ptr)
		func_ptr = get_kallsyms_lookup_name_ptr();

	return func_ptr(name);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,18,0)
static struct sock *cookie_v4_check_wrapper(struct sock *sk,
                                            struct sk_buff *skb,
                                            struct ip_options *opt)
{
	struct sock* (*old_func)(struct sock *sk, struct sk_buff *skb, struct ip_options *opt) =
         (void*)((unsigned long)cookie_v4_check_ptr + MCOUNT_INSN_SIZE);

    extern int sysctl_tcp_syncookies;

	if (sysctl_tcp_syncookies == 2) {
		tcp_synq_overflow(sk);
	}
	return old_func(sk, skb, opt);
}
#else
static struct sock *cookie_v4_check_wrapper(struct sock *sk,
                                            struct sk_buff *skb) {
	struct sock* (*old_func)(struct sock *sk, struct sk_buff *skb) =
         (void*)((unsigned long)cookie_v4_check_ptr + MCOUNT_INSN_SIZE);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,6,0)
	extern int sysctl_tcp_syncookies;

	if (sysctl_tcp_syncookies == 2) {
#else
	if (sock_net(sk)->ipv4.sysctl_tcp_syncookies == 2) {
#endif
		tcp_synq_overflow(sk);
	}
	return old_func(sk, skb);
}
#endif

static void notrace
tcpsecrets_ftrace_handler(unsigned long ip, unsigned long parent_ip,
                      struct ftrace_ops *fops, struct pt_regs *regs)
{
	regs->ip = (unsigned long)cookie_v4_check_wrapper;
}

static struct ftrace_ops tcpsecrets_ftrace_ops __read_mostly = {
	.func = tcpsecrets_ftrace_handler,
	.flags = FTRACE_OPS_FL_SAVE_REGS,
};

static void fix_cookie_v4_check(void) {
	int ret;

	ret = ftrace_set_filter_ip(&tcpsecrets_ftrace_ops, (unsigned long)cookie_v4_check_ptr, 0, 0);
	if (ret) {
		printk("cant set ftrace filter\n");
	}
	ret = register_ftrace_function(&tcpsecrets_ftrace_ops);
	if (ret) {
		printk("cant set ftrace function\n");
	}
}

#ifdef SIPHASH_SYNCOOKIES
static void init_secrets(void)
{
	struct iphdr ip;
	struct tcphdr tcp;
	u16 mssp;

	__cookie_v4_init_sequence(&ip, &tcp, &mssp);
}
#endif

static int __init tcp_secrets_init(void)
{
	int rc;
#ifndef USE_KPROBES
	rc = kallsyms_on_each_symbol(symbol_walk_callback, NULL);
#else
	kallsyms_on_each_symbol_ptr = (void *) lookup_name("kallsyms_on_each_symbol");
	rc = kallsyms_on_each_symbol_ptr(symbol_walk_callback, NULL);
#endif
	if (rc) {
		return rc;
	}

	if (cookie_v4_check_ptr) {
		fix_cookie_v4_check();
	} else {
		printk("tcp_secrets: can't find cookie_v4_check function!\n");
		return -1;
	}
	if (!syncookie_secret_ptr) {
		printk("tcp_secrets: can't find syncookie secret!\n");
		return -2;
	}

	proc_entry = proc_create("tcp_secrets", 0, NULL, &tcp_secrets_fops);
	if (proc_entry == NULL) {
		printk("tcp_secrets: can't create proc entry!\n");
		return -3;
	}

#ifdef SIPHASH_SYNCOOKIES
	init_secrets();
#endif

	return 0;
}

module_init(tcp_secrets_init);

static void __exit tcp_secrets_exit(void)
{
	int ret;

	if (cookie_v4_check_ptr) {
		ret = unregister_ftrace_function(&tcpsecrets_ftrace_ops);
		if (ret) {
			printk("can't unregister ftrace\n");
		}
		ret = ftrace_set_filter_ip(&tcpsecrets_ftrace_ops, (unsigned long)cookie_v4_check_ptr, 1, 0);
		if (ret) {
			printk("can't unregister filter\n");
		}
        cookie_v4_check_ptr = 0;
	}
    syncookie_secret_ptr = 0;
    if (proc_entry)
        remove_proc_entry("tcp_secrets", 0);
}

module_exit(tcp_secrets_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alexander Polyakov <apolyakov@beget.ru>");
MODULE_DESCRIPTION("Provide access to tcp syncookie secrets via /proc/tcp_secrets");
MODULE_VERSION("1.2");
