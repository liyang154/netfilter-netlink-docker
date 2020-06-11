#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x28950ef1, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0xacfa5975, __VMLINUX_SYMBOL_STR(kmem_cache_destroy) },
	{ 0x19ee3d71, __VMLINUX_SYMBOL_STR(kmem_cache_free) },
	{ 0xc435ce0a, __VMLINUX_SYMBOL_STR(dst_release) },
	{ 0xa2693ca, __VMLINUX_SYMBOL_STR(netlink_kernel_release) },
	{ 0x75928e73, __VMLINUX_SYMBOL_STR(nf_unregister_hook) },
	{ 0xd11b7a3e, __VMLINUX_SYMBOL_STR(kmem_cache_alloc) },
	{ 0xaf5517a9, __VMLINUX_SYMBOL_STR(kmem_cache_create) },
	{ 0x5cacc273, __VMLINUX_SYMBOL_STR(__netlink_kernel_create) },
	{ 0x8070df92, __VMLINUX_SYMBOL_STR(init_net) },
	{ 0xb5ad25db, __VMLINUX_SYMBOL_STR(nf_register_hook) },
	{ 0x1e6d26a8, __VMLINUX_SYMBOL_STR(strstr) },
	{ 0xf0fdf6cb, __VMLINUX_SYMBOL_STR(__stack_chk_fail) },
	{ 0x91715312, __VMLINUX_SYMBOL_STR(sprintf) },
	{ 0xf50069a6, __VMLINUX_SYMBOL_STR(netlink_unicast) },
	{ 0x69acdf38, __VMLINUX_SYMBOL_STR(memcpy) },
	{ 0xfa31c478, __VMLINUX_SYMBOL_STR(__nlmsg_put) },
	{ 0xaf3f0d3e, __VMLINUX_SYMBOL_STR(__alloc_skb) },
	{ 0x195c9f2c, __VMLINUX_SYMBOL_STR(kfree_skb) },
	{ 0x12070d39, __VMLINUX_SYMBOL_STR(skb_copy) },
	{ 0xcf6b0abb, __VMLINUX_SYMBOL_STR(ip_local_out_sk) },
	{ 0x4f735e7f, __VMLINUX_SYMBOL_STR(ip_route_me_harder) },
	{ 0x20eadeb6, __VMLINUX_SYMBOL_STR(ip_compute_csum) },
	{ 0xa6862bef, __VMLINUX_SYMBOL_STR(skb_push) },
	{ 0xf631c441, __VMLINUX_SYMBOL_STR(skb_copy_expand) },
	{ 0x784213a6, __VMLINUX_SYMBOL_STR(pv_lock_ops) },
	{ 0x4b7dcf38, __VMLINUX_SYMBOL_STR(_raw_qspin_lock) },
	{ 0x4f68e5c9, __VMLINUX_SYMBOL_STR(do_gettimeofday) },
	{ 0xe113bbbc, __VMLINUX_SYMBOL_STR(csum_partial) },
	{ 0x1b6314fd, __VMLINUX_SYMBOL_STR(in_aton) },
	{ 0xe2d5255a, __VMLINUX_SYMBOL_STR(strcmp) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "F5DDD2DA1181F35125145AD");
MODULE_INFO(rhelversion, "7.8");
#ifdef RETPOLINE
	MODULE_INFO(retpoline, "Y");
#endif
#ifdef CONFIG_MPROFILE_KERNEL
	MODULE_INFO(mprofile, "Y");
#endif
