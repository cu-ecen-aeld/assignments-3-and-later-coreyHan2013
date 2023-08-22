/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include <linux/slab.h>
#include "aesdchar.h"

#define BUF_SIZE 16384
int aesd_major =   0; // use dynamic major
int aesd_minor =   0;
char *gbuf;
int gidx;


MODULE_AUTHOR("Your Name Here"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

static int aesd _trim(struct scull_dev *dev)
{
    for (off=0; off<AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; off++) {
        if (aesd_device.cir_buf.entry[off].buffptr != NULL)
            kfree(aesd_device.cir_buf.entry[off].buffptr);
    }
}

int aesd_open(struct inode *inode, struct file *filp)
{
    struct aesd_dev *dev;

    PDEBUG("open");
    /**
     * TODO: handle open
     */
    dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
    filp->private_data = dev;

    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    /**
     * TODO: handle release
     */
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    struct aesd_dev *dev = filp->private_data;
    size_t byte_rtn = 0;
    struct aesd_buffer_entry *entry = NULL;

    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle read
     */

    if (mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS;

    entry = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->cir_buf, *f_pos, &byte_rtn);
    if (entry == NULL)
        goto out;

    if (count > entry->size-byte_rtn)
        count =  entry->size - byte_rtn;

    if (copy_to_user(buf, entry->buffptr+byte_rtn, entry->size-byte_rtn)) {
        retval = -EFAULT;
        goto out;
    }
    *f_pos += count;
    retval = count;

out:
    mutex_unlock(&dev->lock);
    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;
    struct aesd_dev *dev = filp->private_data;
    //struct aesd_circular_buffer *cir_buf = &dev->cir_buf;
    struct aesd_buffer_entry entry;

    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle write
     */

    if (mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS;

    if (copy_from_user(&gbuf[gidx], buf, count)) {
       retval = -EFAULT;
       goto out;
    }

    PDEBUG("data has been copied to gbuf");
    gidx += count;
    if (buf[count-1] == '\n') {
        entry.size = gidx;
        entry.buffptr = kmalloc(entry.size, GFP_KERNEL);
        if (!entry.buffptr)
            goto out;
        memcpy((void *)entry.buffptr, gbuf, entry.size);
        PDEBUG("data has been copied to entry buffer");
	memset(gbuf, 0, entry.size);
	gidx = 0;

        if (dev->cir_buf.full) {
            kfree(dev->cir_buf.entry[dev->cir_buf.out_offs].buffptr);
        }
        aesd_circular_buffer_add_entry(&dev->cir_buf, &entry);
        PDEBUG("entry has been added to circular buffer");
    }
    *f_pos = 0;
    retval = count;
out:
    mutex_unlock(&dev->lock);
    return retval;
}
struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));

    /**
     * TODO: initialize the AESD specific portion of the device
     */
    mutex_init(&aesd_device.lock);
    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    } else {
        gbuf = kmalloc(BUF_SIZE, GFP_KERNEL);
        memset(gbuf, 0, BUF_SIZE);
        gidx = 0;
        PDEBUG("allocated global memory with size %d", BUF_SIZE);
    }
    PDEBUG("module is loaded");
    return result;

}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);
    int off = 0;

    cdev_del(&aesd_device.cdev);

    /**
     * TODO: cleanup AESD specific poritions here as necessary
     */

    unregister_chrdev_region(devno, 1);
    kfree(gbuf);
    PDEBUG("module is unloaded");
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
