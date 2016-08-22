#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kallsyms.h>
#include <linux/cryptohash.h>
#include <linux/ftrace.h>
#include <net/tcp.h>

static void *cookie_v4_check_ptr;

static u32 (*syncookie_secret_ptr)[2][16-4+SHA_DIGEST_WORDS];

static int tcp_secrets_show(struct seq_file *m, void *v)
{
	int i, j;
	seq_printf(m, "%lu %lu %d\n", (unsigned long) jiffies, (unsigned long)tcp_cookie_time(), HZ);
	for(i = 0; i < 2; i++) {
		for(j = 0; j < 16-4+SHA_DIGEST_WORDS; j++) {
			seq_printf(m, "%.8x.", (*syncookie_secret_ptr)[i][j]); 
		}
        seq_printf(m, "\n");
	}
	return 0;
}

static int tcp_secrets_open(struct inode *inode, struct file *file)
{
	return single_open(file, tcp_secrets_show, NULL);
}

static const struct file_operations tcp_secrets_fops = {
	.open		= tcp_secrets_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};
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

static struct sock *cookie_v4_check_wrapper(struct sock *sk, struct sk_buff *skb) {
	struct sock* (*old_func)(struct sock *sk, struct sk_buff *skb) = (void*)((unsigned long)cookie_v4_check_ptr + MCOUNT_INSN_SIZE);

	if (sock_net(sk)->ipv4.sysctl_tcp_syncookies == 2) {
		tcp_synq_overflow(sk);
	}
	return old_func(sk, skb);
}

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

static int __init tcp_secrets_init(void)
{
	int rc = kallsyms_on_each_symbol(symbol_walk_callback, NULL);
	if (rc)
		return rc;
	if (cookie_v4_check_ptr) {
		fix_cookie_v4_check();
	}
	return proc_create("tcp_secrets", 0, NULL, &tcp_secrets_fops) == NULL;
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
	}
	remove_proc_entry("tcp_secrets", 0);
}

module_exit(tcp_secrets_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alexander Polyakov <apolyakov@beget.ru>");
MODULE_DESCRIPTION("Provide access to tcp syncookie secrets via /proc/tcp_secrets");
MODULE_VERSION("1.0");
