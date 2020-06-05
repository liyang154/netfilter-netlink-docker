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
	{ 0xc435ce0a, __VMLINUX_SYMBOL_STR(dst_release) },
	{ 0xf7edb41, __VMLINUX_SYMBOL_STR(nf_unregister_hooks) },
	{ 0xcfbcfea2, __VMLINUX_SYMBOL_STR(nf_register_hooks) },
	{ 0x195c9f2c, __VMLINUX_SYMBOL_STR(kfree_skb) },
	{ 0x12070d39, __VMLINUX_SYMBOL_STR(skb_copy) },
	{ 0xcf6b0abb, __VMLINUX_SYMBOL_STR(ip_local_out_sk) },
	{ 0x4f735e7f, __VMLINUX_SYMBOL_STR(ip_route_me_harder) },
	{ 0x20eadeb6, __VMLINUX_SYMBOL_STR(ip_compute_csum) },
	{ 0xa6862bef, __VMLINUX_SYMBOL_STR(skb_push) },
	{ 0xf631c441, __VMLINUX_SYMBOL_STR(skb_copy_expand) },
	{ 0x27e1a049, __VMLINUX_SYMBOL_STR(printk) },
	{ 0xbdfb6dbb, __VMLINUX_SYMBOL_STR(__fentry__) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "7DED940A9105251CE2D221B");
MODULE_INFO(rhelversion, "7.8");
#ifdef RETPOLINE
	MODULE_INFO(retpoline, "Y");
#endif
#ifdef CONFIG_MPROFILE_KERNEL
	MODULE_INFO(mprofile, "Y");
#endif
