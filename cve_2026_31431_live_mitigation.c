// SPDX-License-Identifier: GPL-2.0
/*
 * cve_2026_31431_live_mitigation.c - Live mitigation for CVE-2026-31431
 *
 * This module disables the AEAD user API by unregistering the algif_aead type.
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <crypto/if_alg.h>
#include <linux/version.h>


// borrowing from https://github.com/xcellerator/linux_kernel_hacking/blob/master/3_RootkitTechniques/3.3_set_root/ftrace_helper.h
/*
 * On Linux kernels 5.7+, kallsyms_lookup_name() is no longer exported, 
 * so we have to use kprobes to get the address.
 * Full credit to @f0lg0 for the idea.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};
#endif

static int __init cve_2026_31431_live_mitigation_init(void)
{
	void *algif_aead_init_ptr;
	void *algif_type_aead_ptr;
	int (*af_alg_unregister_type_fn)(const struct af_alg_type *type);
	int ret;

        #ifdef KPROBE_LOOKUP
        typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
        kallsyms_lookup_name_t kallsyms_lookup_name;
        register_kprobe(&kp);
        kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
        unregister_kprobe(&kp);
        #endif

	algif_aead_init_ptr = (void *)kallsyms_lookup_name("algif_aead_init");
	algif_type_aead_ptr = (void *)kallsyms_lookup_name("algif_type_aead");
	af_alg_unregister_type_fn = (void *)kallsyms_lookup_name("af_alg_unregister_type");

	if (!algif_aead_init_ptr || !algif_type_aead_ptr || !af_alg_unregister_type_fn) {
		pr_err("[CVE-2026-31431-mit] Required symbols not found.\n");
		return -ENOSYS;
	}

	pr_info("[CVE-2026-31431-mit] Attempting to unregister algif_type_aead...\n");
	ret = af_alg_unregister_type_fn((const struct af_alg_type *)algif_type_aead_ptr);
	if (ret) {
		pr_err("[CVE-2026-31431-mit] af_alg_unregister_type failed: %d\n", ret);
		return ret;
	}
	pr_info("[CVE-2026-31431-mit] algif_type_aead unregistered successfully.\n");
	return 0;
}

module_init(cve_2026_31431_live_mitigation_init);

// module_exit is not defined since this module cannot be unloaded

MODULE_LICENSE("GPL");
MODULE_AUTHOR("mgmlme");
MODULE_DESCRIPTION("Live mitigation for CVE-2026-31431 (algif_aead unregister)");
MODULE_VERSION("0.1");
