#include <linux/module.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/init.h>
MODULE_LICENSE("GPL");

#define MYSLAB "testslab"

static struct kmem_cache *myslab;

/* 申请内存时调用的构造函数 */
static void ctor(void* obj)
{
    printk(KERN_ALERT "constructor is running....\n");
}

struct student
{
    int id;
    char* name;
};

static void print_student(struct student *);


static int testslab_init(void)
{
    struct student *stu1, *stu2;

    /* 建立slab高速缓存，名称就是宏 MYSLAB */
    myslab = kmem_cache_create(MYSLAB,
                               sizeof(struct student),
                               0,
                               0,
                               ctor);

    /* 高速缓存中分配2个对象 */
    printk(KERN_ALERT "alloc one student....\n");
    stu1 = (struct student*)kmem_cache_alloc(myslab, GFP_KERNEL);
    stu1->id = 1;
    stu1->name = "wyb1";
    print_student(stu1);

    printk(KERN_ALERT "alloc one student....\n");
    stu2 = (struct student*)kmem_cache_alloc(myslab, GFP_KERNEL);
    stu2->id = 2;
    stu2->name = "wyb2";
    print_student(stu2);
    stu1->id=5;

    /* 释放高速缓存中的对象 */
    //printk(KERN_ALERT "free one student....\n");
    kmem_cache_free(myslab, stu1);

    //printk(KERN_ALERT "free one student....\n");
    kmem_cache_free(myslab, stu2);

    /* 执行完后查看 /proc/slabinfo 文件中是否有名称为 “testslab”的缓存 */
    return 0;
}

static void testslab_exit(void)
{
    /* 删除建立的高速缓存 */
    printk(KERN_ALERT "*************************\n");
    //print_current_time(0);
    kmem_cache_destroy(myslab);
    printk(KERN_ALERT "testslab is exited!\n");
    printk(KERN_ALERT "*************************\n");

    /* 执行完后查看 /proc/slabinfo 文件中是否有名称为 “testslab”的缓存 */
}

static void print_student(struct student *stu)
{
    if (stu != NULL)
    {
        printk(KERN_ALERT "**********student info***********\n");
        printk(KERN_ALERT "student id   is: %d\n", stu->id);
        printk(KERN_ALERT "student name is: %s\n", stu->name);
        printk(KERN_ALERT "*********************************\n");
    }
    else
        printk(KERN_ALERT "the student info is null!!\n");
}

module_init(testslab_init);
module_exit(testslab_exit);