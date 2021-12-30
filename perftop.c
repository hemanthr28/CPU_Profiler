#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/jhash.h>
#include <linux/sched.h>
#include <linux/rbtree.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hemanth Ramesh");
MODULE_DESCRIPTION("CPU Profiler");

#define STR_SIZE 64
#define ARRAY_LENGTH 51
#define KPROBE_LOOKUP 1

typedef typeof(&stack_trace_save_user) stack_trace_save_user_funcpntr;
#define stack_trace_save_user (*(stack_trace_save_user_funcpntr) kallsyms_stack_trace_user_save)
void *kallsyms_stack_trace_user_save = NULL;

static struct kprobe kp0 = {
    .symbol_name = "kallsyms_lookup_name",
};

/*Defining a hash struct*/
struct hnode_pid{
    int pid;
    unsigned int SchldCnt;
    unsigned long Stacklog[ARRAY_LENGTH]; 
    unsigned int LogLength;
    u64 time_spent;
    struct hlist_node hash;
};

/*Definig a RB tree*/
struct rb_root root_node = RB_ROOT;

struct rb_entry{
	struct rb_node run_node;
	unsigned int SchldCnt;
    unsigned long Stacklog[ARRAY_LENGTH]; 
    unsigned int LogLength;
    unsigned int key;
    u64 time_spent;
};

DEFINE_SPINLOCK(myhash_table_lock);

/*Check and insert a PID to the hash tree*/
DEFINE_HASHTABLE(myhash_table,18);
    static int storehash(unsigned int key, unsigned long* st_log, unsigned int st_len, u64 time){
    struct hnode_pid *current_node, *new_node;
    int temp = key;
    bool flag = false;
    int i = 0;
    hash_for_each_possible(myhash_table, current_node, hash, temp){
        flag = true;
        current_node->SchldCnt += 1;
        current_node->time_spent += time;
    }
        if (flag == false){
	        new_node = kmalloc(sizeof(struct hnode_pid), GFP_ATOMIC);
	        if(new_node == NULL)
		        return -ENOMEM;
            new_node->SchldCnt = 1;
            new_node->time_spent = time; 
            for(i=0; (i < st_len); i++)
	            new_node->Stacklog[i] = st_log[i];
            new_node->LogLength = st_len;
	        hash_add(myhash_table, &new_node->hash, temp);
        }
    return 0;  
}

/*Remove old task entry*/
static void removeoldentry(unsigned int key,u64* time_ret,unsigned int* sch_cnt)
{       //printk("In remove\n");
        struct rb_node* temp_node;
        struct rb_entry* rem_rb_node;
        temp_node = rb_first(&root_node);
        while(temp_node)
        {       //printk("In remove while\n");
                rem_rb_node = rb_entry(temp_node, struct rb_entry, run_node);
                if(rem_rb_node->key == key)
                {
			            *sch_cnt = rem_rb_node->SchldCnt;
                        *time_ret = rem_rb_node->time_spent;
                        rb_erase(&rem_rb_node->run_node,&root_node);
                        kfree(rem_rb_node);
                        return;
                }
                temp_node = rb_next(temp_node);
        }
	*time_ret = 0;
	*sch_cnt = 0;
}

/*RB TREE INSERT IMPLEMENTATION*/
static int storeToScheduleRBTree(unsigned int key, unsigned long* st_log, unsigned int st_len, u64 time)
{   //printk("In RB tree\n");
	int i = 0;
	u64 prev_time = 0;
	unsigned int sched_count = 0;
	struct rb_entry *new_node, *attached_node;
	struct rb_node **current_rb_node, *rbparent_node = NULL;
	removeoldentry(key,&prev_time,&sched_count);
	new_node = (struct rb_entry*)kmalloc(sizeof(struct rb_entry),GFP_ATOMIC);
	if(new_node != NULL)
	{   //printk("In If\n");
		new_node->key = key;
		new_node->SchldCnt = sched_count + 1;
		new_node->LogLength = st_len;
		new_node->time_spent = time + prev_time;
		for(i=0; (i < st_len); i++){       
            //printk("In while\n");
            new_node->Stacklog[i] = *st_log;
			st_log++;
                }
		current_rb_node = &root_node.rb_node;
		while(*current_rb_node != NULL)
		{   
			rbparent_node = *current_rb_node;
			attached_node = rb_entry(rbparent_node,struct rb_entry,run_node);
			if(attached_node->time_spent < new_node->time_spent)
			{
				current_rb_node = &((*current_rb_node)->rb_right);
			}
			else
			{
				current_rb_node = &((*current_rb_node)->rb_left);
			}
		}
		rb_link_node(&new_node->run_node,rbparent_node,current_rb_node);
		rb_insert_color(&(new_node->run_node),&root_node);
		return 0;
	}
	else
	{
		return -ENOMEM;
	}
}

/*Print RB Tree*/
void printRBTreeNodes(struct seq_file *sf, int nodeCount)
{
	int i = 0, j;
	struct rb_node* curr_node;
	struct rb_entry * read_node;
	curr_node = rb_last(&root_node);
	for(i = 0; i < nodeCount; i++)
	{
		if(curr_node != NULL)
		{
			read_node = rb_entry(curr_node,struct rb_entry,run_node);
			seq_printf(sf,"Number of Schedules: %d \n",read_node->SchldCnt);
            seq_printf(sf,"----------------Stack Trace----------------------\n");
            for (j = 0; j < read_node->LogLength; j++)
            {
                seq_printf(sf,"%pB\n",(void *)read_node->Stacklog[j]);
            }
                        
			seq_printf(sf,"Time Spent: %llu\n",read_node->time_spent);
            curr_node = rb_prev(curr_node);
		}
		
	}
}

static char symbol[STR_SIZE] = "pick_next_task_fair";
module_param_string(symbol, symbol, sizeof(symbol), 0644);

static struct kprobe kp = {
    .symbol_name = symbol, 
};

int counter = 0;
unsigned long entries[ARRAY_LENGTH];
static u64 init_time; 
static bool init = true;
static int handler_pre(struct kprobe *p, struct pt_regs *regs){

    struct task_struct * task_list;
    u32 strcaeHashKey; 
    unsigned long flags;
    u64 task_time; 

    /*Skips the first insertion as init_time is not initialised*/
    if (init == true){
        init = false;
        return 0;
    }

    task_time = rdtsc() - init_time;
    task_list = ((struct task_struct *)regs->si);
    spin_lock_irqsave(&myhash_table_lock,flags);
    if ((task_list != NULL)){
        //printk("PID = %d\n", task_list->pid);
        unsigned int nr_entries;
        if (task_list->mm == NULL){
        nr_entries = stack_trace_save(entries, ARRAY_LENGTH, 0);
            /*printk("---------------Kernel Stack Trace------------------\n");
           for(counter = 0; counter < nr_entries; counter++)
                printk("%pB",(void*)entries[counter]);*/
        //else{
        //    nr_entries = stack_trace_save_user(entries, ARRAY_LENGTH);
            /*printk("---------------User Stack Trace------------------\n");
            for(counter = 0; counter < nr_entries; counter++)
                printk("%pB",(void*)entries[counter]);*/
        //}
        /*(nr_entries+1)*2 beucase of typecasting long to to u32*/
        strcaeHashKey = jhash2((u32*)entries, nr_entries*2, 0);
        //printk("Before lock in pre\n");
        //spin_lock_irqsave(&myhash_table_lock,flags);
        //storehash(strcaeHashKey, entries, nr_entries, task_time);
        //printk("Before unlock in pre\n");
        storeToScheduleRBTree(strcaeHashKey, entries, nr_entries, task_time);
        } 
    }
    spin_unlock_irqrestore(&myhash_table_lock,flags);
    return 0;
}

static void handler_post(struct kprobe *p, struct pt_regs *regs,unsigned long flags){ 
    //pr_info("<%s> p->addr = 0x%p, flags = 0x%lx\n", p->symbol_name, p->addr, regs->flags); 
    init_time = rdtsc();
    }

static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr){   
    return 0;
}

static int profl_proc_show(struct seq_file *m, void *v) {
    //seq_printf(m, "Hello World\n");
    int bkt, i = 0, j;
    struct hnode_pid *current_node;
    unsigned long flags;
	struct rb_node* curr_node;
	struct rb_entry * read_node;
	curr_node = rb_last(&root_node);
	/*Traverse through the hash nodes*/
    //printk("Before lock in show\n");
    spin_lock_irqsave(&myhash_table_lock,flags);
	/*hash_for_each(myhash_table,bkt,current_node,hash){
        seq_printf(m, "==================Stack Trace====================\n");
        for (i = 0; i < current_node->LogLength; i++)
			seq_printf(m,"%pB\n",(void*)current_node->Stacklog[i]);
		seq_printf(m, "Schedule count: %d\n", current_node->SchldCnt);
        seq_printf(m, "Time spend on CPU: %llu\n", current_node->time_spent);
	}*/
    /*Travese through RB tree - to print 20 top scheduled functions*/
    for(i = 0; i < 20; i++)
	{
		if(curr_node != NULL)
		{
			read_node = rb_entry(curr_node,struct rb_entry,run_node);
			//seq_printf(m,"Number of Schedules: %d \n",read_node->SchldCnt);
            seq_printf(m,"*******************************************\n");
            seq_printf(m,"Rank %d" " scheduled task\n",i+1);
            seq_printf(m,"Jenkin Hash: %u\n", read_node->key);
            seq_printf(m,"-------------Stack Trace------------\n");
            for (j = 0; j < read_node->LogLength; j++)
            {
                seq_printf(m,"%pB\n",(void *)read_node->Stacklog[j]);
            }
            seq_printf(m,"----------End of stack Trace---------\n");            
			seq_printf(m,"Time Spent: %llu\n",read_node->time_spent);
            curr_node = rb_prev(curr_node);
		}
	}
    //printRBTreeNodes(m,20);
    //printk("Before unlock in pre\n");
    spin_unlock_irqrestore(&myhash_table_lock,flags);
    return 0;
}

static int profl_proc_open(struct inode *inode, struct  file *file) {
    return single_open(file, profl_proc_show, NULL);
}

static const struct proc_ops profl_proc_fops = {
  .proc_open = profl_proc_open,
  .proc_read = seq_read,
  .proc_lseek = seq_lseek,
  .proc_release = single_release,
};

static int __init profl_proc_init(void) {
    int ret;
/*Extracting the Kprobe thread*/
#ifdef KPROBE_LOOKUP    
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    kallsyms_lookup_name_t kallsyms_lookup_name;
    register_kprobe(&kp0);
    //printk("Found at 0x%p \n", kp0.addr);
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp0.addr; 
    kallsyms_stack_trace_user_save = (void*)kallsyms_lookup_name("stack_trace_save_user");
    unregister_kprobe(&kp0);
#endif
    proc_create("perftop", 0, NULL, &profl_proc_fops);
    kp.pre_handler = handler_pre;
    kp.post_handler = handler_post;
    kp.fault_handler = handler_fault;
   /* kp.addr = (kprobe_opcode_t *)profl_proc_open;*/

    ret = register_kprobe(&kp);
    if (ret < 0) {
        printk("register_kprobe failed, returned %d\n", ret);
        return ret;
    }
    printk("Planted kprobe at %p\n", kp.addr);
    return 0;


  return 0;
}

static void __exit profl_proc_exit(void) {
    /*Deleting hash entry*/
    int bkt;
    struct hnode_pid *next_node;
    struct rb_entry *current_rbnode;
	struct rb_node *top_node;
	hash_for_each(myhash_table,bkt,next_node,hash){
		//printk(KERN_INFO "Deleting Hash val: %d\n", next_node->val);
		hash_del(&next_node->hash);
		kfree(next_node);
	}

    /*Deleting RB tree*/
	top_node = rb_first(&root_node);
	while(top_node != NULL){
	current_rbnode = rb_entry(top_node, struct rb_entry, run_node);
	//printk(KERN_INFO "Deleting RB val: %d\n", current_rbnode->val);
	top_node = rb_next(top_node);
	rb_erase(&current_rbnode->run_node, &root_node);
	kfree(current_rbnode);
	}

    remove_proc_entry("perftop", NULL);
    unregister_kprobe(&kp);
    printk("kprobe at %p unregistered\n", kp.addr);
}

module_init(profl_proc_init);
module_exit(profl_proc_exit);