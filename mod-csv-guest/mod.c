#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>

struct csv_guest_mem{
	unsigned long va;  //user space virtual address
	int size;
};

#define HASH_LEN 32

typedef struct _hash_block_u {
	unsigned char block[HASH_LEN];
} hash_block_u;

#define CSV_GUEST_IOC_TYPE     'D'
#define GET_ATTESTATION_REPORT  _IOWR(CSV_GUEST_IOC_TYPE, 1, struct csv_guest_mem)

#define GUEST_ATTESTATION_NONCE_SIZE 16
#define GUEST_ATTESTATION_DATA_SIZE 64
#define KVM_HC_VM_ATTESTATION	100	/* Specific to Hygon platform */

static int csv_guest_open(struct inode *inode, struct file *filp)
{
	printk(KERN_INFO"csv_guest_open \n");
	return 0;
}

static int csv_guest_release(struct inode *inode, struct file *filp)
{
	return 0;
}

static long hypercall(unsigned int nr, unsigned long p1, unsigned int len)
{
	long ret = 0;

	asm volatile("vmmcall"
		: "=a"(ret)
		: "a"(nr), "b"(p1), "c"(len)
		: "memory");
	return ret;
}

static long csv_guest_ioctl(struct file* file, unsigned int cmd, unsigned long arg)
{
	int ret = 0;
	void __user* argp = (void __user*)arg;
	struct csv_guest_mem mem_para = {0};
	void *mem = NULL;
	
	// 从用户空间拷贝参数
	if (copy_from_user(&mem_para, argp, sizeof(struct csv_guest_mem))) {
		pr_err("%s copy from user failed \n", __func__);
		ret = -EFAULT;
		goto out;
	}
	
	switch (cmd) {
		case GET_ATTESTATION_REPORT:
			// 内核中分配一个与用户缓冲区同样大小的内存区域mem
			mem = kzalloc(mem_para.size, GFP_KERNEL);
			if (!mem) {
				pr_err("%s kzalloc for size 0x%x failed\n", __func__, mem_para.size);
				ret = -ENOMEM;
				goto out;
			}

			/*copy user data and mnonce to kernel buf*/
			// 拷贝用户输入数据
			if (copy_from_user(mem, (void __user*)(mem_para.va), 
				GUEST_ATTESTATION_DATA_SIZE + GUEST_ATTESTATION_NONCE_SIZE + sizeof(hash_block_u))) {
				pr_err("%s copy user data and mnonce from user failed \n", __func__);
				ret = -EFAULT;
				goto error;
			}
			
			// 调用 hypercall 获取证明报告
			ret = hypercall(KVM_HC_VM_ATTESTATION, __pa(mem), mem_para.size);
			if (ret) {
				printk("hypercall fail: %d\n", ret);
				goto error;
			}
			
			// 将结果拷贝回用户空间
			if (copy_to_user((void __user*)(mem_para.va), mem, mem_para.size)){
				pr_err("%s copy mem to user failed \n", __func__);
				ret = -EFAULT;
				goto error;
			}
			
			break;
		default:
			printk("don't support this cmd = %d\n",cmd);
			ret = -EINVAL;
			goto out;
	}
	
error:
	if(mem){
		kfree(mem);
		mem = NULL;
	}
out:
	return ret;
}

// 定义了当用户空间对设备文件进行open, ioctl, release等操作时，内核应该调用的对应函数。
static struct file_operations csv_guest_fops = {
	.owner = THIS_MODULE,
	.open  = csv_guest_open,
	.unlocked_ioctl = csv_guest_ioctl,
	.compat_ioctl = csv_guest_ioctl,
	.release = csv_guest_release,
};

// 用于注册一个"杂项设备"
static struct miscdevice csv_guest_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "csv-guest",
	.fops = &csv_guest_fops,
	.mode = 0777,
};

// 初始化函数,向内核注册csv_guest_dev设备。
static int __init csv_guest_init(void)
{
	int ret = -1;
	ret = misc_register(&csv_guest_dev);
	if(ret){
		printk(KERN_ERR"csv_guest_dev: cannot register misc device!\n");
		return ret;
	}
	printk(KERN_ALERT"Succeeded to initialize csv_guest device.\n");
	return 0;
}

static void __exit csv_guest_exit(void)
{
	misc_deregister(&csv_guest_dev);
}

// 声明模块的许可证，这是内核模块的强制要求
MODULE_LICENSE("GPL");
// 指定模块加载时调用的初始化函数是 csv_guest_init
module_init(csv_guest_init);
// 指定模块卸载时调用的清理函数是 csv_guest_exit
module_exit(csv_guest_exit);
