// struct trace_event_raw_sys_enter {
// 	struct trace_entry ent;
// 	long int id;
// 	long unsigned int args[6];
// 	char __data[0];
// };

// struct trace_event_raw_sys_exit {
// 	struct trace_entry ent;
// 	long int id;
// 	long int ret;
// 	char __data[0];
// };

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "maps.bpf.h"
#include "proc_image.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";
#define MAX_NODENAME_LEN 64
const volatile pid_t ignore_tgid = -1;
// const volatile char hostname[MAX_NODENAME_LEN] = "";
const int key = 0;
pid_t pre_target_pid = -1;//上一个监测的进程；
int pre_target_tgid = -1;//上一个监测的进程组；

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct sc_ctrl);
} sc_ctrl_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1024);
	__type(key, int);
	__type(value, struct syscall_enter_t);
} syscall_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries,256 * 10240);
} syscall_rb SEC(".maps");

// struct {
// 	__uint(type, BPF_MAP_TYPE_HASH);
// 	__type(key, int);
// 	__type(value, struct syscall_count_t);
// 	__uint(max_entries, 512);
// } syscall_counts SEC(".maps");

int syscall_index = 0;

// // obj->bss
// // user later
int syscall_counts[500] = {};
__u64 syscall_time[500] = {};

SEC("tracepoint/raw_syscalls/sys_enter")
int sys_enter(struct trace_event_raw_sys_enter *args)
{
    struct sc_ctrl *syscall_ctrl;
	syscall_ctrl = bpf_map_lookup_elem(&sc_ctrl_map,&key);
    if(!syscall_ctrl || !syscall_ctrl->sc_func)
		return 0;

        // bpf_printk("proc have syscall\n");
    unsigned int id = (unsigned int)args->id;
    if(id >= 500) {
        return 0;
    }
    pid_t pid = bpf_get_current_pid_tgid();
    int target_pid = syscall_ctrl->target_pid;
    // struct task_struct *t = (struct task_struct*)bpf_get_current_task();
    // bpf_printk("[syscall]syscall pid: %d   kern proc: %s\n", pid, (BPF_CORE_READ(t, flags) & PF_KTHREAD)?"true":"false");
    if(pid != target_pid) {
        return 0;
    }

    // bpf_printk("target proc have syscall\n");
    u64 current_timestamp = bpf_ktime_get_ns();
    struct syscall_enter_t enter = {.syscall_id = id, .timestamp = current_timestamp};
    if(syscall_index < 0) {
        bpf_printk("syscall index < 0\n");
        return 0;
    }
    bpf_map_update_elem(&syscall_start, &syscall_index, &enter, BPF_ANY);
    __sync_fetch_and_add(&syscall_index, 1);


    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int sys_exit(struct trace_event_raw_sys_exit *args)
{
    struct sc_ctrl *syscall_ctrl;
	syscall_ctrl = bpf_map_lookup_elem(&sc_ctrl_map,&key);
	if(!syscall_ctrl || !syscall_ctrl->sc_func)
		return 0;
    unsigned int id = (unsigned int)args->id;
    if(id >= 500) {
        return 0;
    }
    pid_t pid = bpf_get_current_pid_tgid();
    int target_pid = syscall_ctrl->target_pid;
    if(pid != target_pid) {
        return 0;
    }
    u64 current_timestamp = bpf_ktime_get_ns();

    struct syscall_enter_t *enter = NULL;
    const int tmp_index = syscall_index-1;
    if(tmp_index < 0) {
        bpf_printk("syscall tmp index < 0\n");
        return 0;
    }
    enter = bpf_map_lookup_elem(&syscall_start, &tmp_index);
    if(!enter) {
        return 0;
    }
    __sync_fetch_and_add(&syscall_index, -1);

    if(id != enter->syscall_id) {
        return 0;
    }
    struct syscall_val_t *val = NULL;
    val = bpf_ringbuf_reserve(&syscall_rb, sizeof(*val), 0);
    if(!val) {
        return 0;
    }
    val->ret = args->ret;
    u64 delta = current_timestamp - enter->timestamp;
    val->duration = delta;
    val->timestamp = current_timestamp;
    val->syscall_id = enter->syscall_id;
    bpf_ringbuf_submit(val, 0);
//     bpf_map_delete_elem(&syscall_start, &tmp_index);
    __sync_fetch_and_add(&syscall_counts[id], 1);
    __sync_fetch_and_add(&syscall_time[id], delta);


    return 0;
}






struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1024);
	__type(key, int);
	__type(value, struct softirq_enter_t);
} softirq_start SEC(".maps");

// const int softirq_key = 0;
int softirq_index = 0;


// obj->bss
// user later
int softirq_counts[NR_SOFTIRQS] = {};
__u64 softirq_time[NR_SOFTIRQS] = {};


SEC("tp_btf/softirq_entry")
int BPF_PROG(softirq_entry_btf, unsigned int vec_nr)
{
    struct sc_ctrl *syscall_ctrl;
	syscall_ctrl = bpf_map_lookup_elem(&sc_ctrl_map,&key);
	if(!syscall_ctrl || !syscall_ctrl->sc_func)
		return 0;
	if (vec_nr >= NR_SOFTIRQS)
		return 0;
    pid_t pid = bpf_get_current_pid_tgid();
    int target_pid = syscall_ctrl->target_pid;
    if(pid != target_pid)
        return 0;
    u64 current_timestamp = bpf_ktime_get_ns();
    struct softirq_enter_t enter = {.timestamp = current_timestamp, .vec_nr = vec_nr};
    if(softirq_index < 0) {
        bpf_printk("softirq index < 0");
        return 0;
    }
    bpf_map_update_elem(&softirq_start, &softirq_index, &enter, BPF_ANY);
    __sync_fetch_and_add(&softirq_index, 1);
	return 0;
}

SEC("tp_btf/softirq_exit")
int BPF_PROG(softirq_exit_btf, unsigned int vec_nr)
{
    struct sc_ctrl *syscall_ctrl;
	syscall_ctrl = bpf_map_lookup_elem(&sc_ctrl_map,&key);
	if(!syscall_ctrl || !syscall_ctrl->sc_func)
		return 0;
	if (vec_nr >= NR_SOFTIRQS)
		return 0;
    pid_t pid = bpf_get_current_pid_tgid();
    int target_pid = syscall_ctrl->target_pid;
    // struct task_struct *t = (struct task_struct*)bpf_get_current_task();
    // bpf_printk("[softirq]exit softirq pid: %d   kern proc: %s\n", pid, (BPF_CORE_READ(t, flags) & PF_KTHREAD)?"true":"false");
    if(pid != target_pid)
        return 0;
    
    u64 current_timestamp = bpf_ktime_get_ns();
    const int tmp_index = softirq_index - 1;
    __sync_fetch_and_add(&softirq_index, -1);
    if(tmp_index < 0) {
        bpf_printk("softirq index < 0\n");
        return 0;
    }
	struct softirq_enter_t *enter = bpf_map_lookup_elem(&softirq_start, &tmp_index);
	if (!enter)
		return 0;
    if(enter->vec_nr != vec_nr) {
        return 0;
    }
    struct softirq_val_t *val;
    val = bpf_ringbuf_reserve(&syscall_rb, sizeof(*val), 0);
    if(!val) {
        return 0;
    }
    val->vec_nr = vec_nr;
    u64 delta = current_timestamp - enter->timestamp;
    val->duration = delta;
    val->timestamp = current_timestamp;
    bpf_ringbuf_submit(val, 0);
    __sync_fetch_and_add(&softirq_counts[vec_nr], 1);
    __sync_fetch_and_add(&softirq_time[vec_nr], delta);
	return 0;
}


// struct irqaction {
// 	irq_handler_t handler;
// 	void *dev_id;
// 	void *percpu_dev_id;
// 	struct irqaction *next;
// 	irq_handler_t thread_fn;
// 	struct task_struct *thread;
// 	struct irqaction *secondary;
// 	unsigned int irq;
// 	unsigned int flags;
// 	long unsigned int thread_flags;
// 	long unsigned int thread_mask;
// 	const char *name;
// 	struct proc_dir_entry *dir;
// 	long: 64;
// 	long: 64;
// 	long: 64;
// 	long: 64;
// };
//                                              // hard irq还没有被验证
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1024);
	__type(key, int);
	__type(value, struct hardirq_enter_t);
} hardirq_start SEC(".maps");

int hardirq_index = 0;


// obj->bss
// user later
#define NR_HARDIRQS 100
int hardirq_counts[NR_HARDIRQS] = {};
__u64 hardirq_time[NR_HARDIRQS] = {};

SEC("tp_btf/irq_handler_entry")
int BPF_PROG(irq_handler_entry_btf, int irq, struct irqaction *action)
{
    struct sc_ctrl *syscall_ctrl;
	syscall_ctrl = bpf_map_lookup_elem(&sc_ctrl_map,&key);
	if(!syscall_ctrl || !syscall_ctrl->sc_func) {
		return 0;
    }
    if(irq >= NR_HARDIRQS) {
        return 0;
    }
    pid_t pid = bpf_get_current_pid_tgid();
    int target_pid = syscall_ctrl->target_pid;
    // struct task_struct* t = (struct task_struct*)bpf_get_current_task();
    // bpf_printk("[hardirq]entry pid: %d   hardirq pid: %d    irq: %d   action name: %s\n", pid, BPF_CORE_READ(t, pid), irq, BPF_CORE_READ(action, name));

    // bpf_printk("entry hardirq pid: %d  hardirq: %s\n", pid, BPF_CORE_READ(action, name));
    if(pid != target_pid)
        return 0;
    u64 current_timestamp = bpf_ktime_get_ns();
    struct hardirq_enter_t enter = {.irq = irq, .timestamp = current_timestamp};
    if(hardirq_index < 0) {
        bpf_printk("hardirq index < 0\n");
        return 0;
    }
	bpf_map_update_elem(&hardirq_start, &hardirq_index, &enter, BPF_ANY);
    __sync_fetch_and_add(&hardirq_index, 1);
	return 0;
}

SEC("tp_btf/irq_handler_exit")
int BPF_PROG(irq_handler_exit_btf, int irq, struct irqaction *action)
{
    struct sc_ctrl *syscall_ctrl;
	syscall_ctrl = bpf_map_lookup_elem(&sc_ctrl_map, &key);
	if(!syscall_ctrl || !syscall_ctrl->sc_func)
		return 0;
    unsigned int irq_index = (unsigned int)irq;
    if(irq_index >= NR_HARDIRQS) {
        return 0;
    }
    pid_t pid = bpf_get_current_pid_tgid();
    int target_pid = syscall_ctrl->target_pid;
    // bpf_printk("exit hardirq pid: %d  hardirq: %s\n", pid, BPF_CORE_READ(action, name));

    if(pid != target_pid)
        return 0;

    u64 current_timestamp = bpf_ktime_get_ns();
    const int tmp_index = hardirq_index - 1;
    __sync_fetch_and_add(&hardirq_index, -1);
    if(tmp_index < 0) {
        bpf_printk("hardirq tmp_index < 0\n");
        return 0;
    }
	struct hardirq_enter_t *enter = bpf_map_lookup_elem(&hardirq_start, &tmp_index);
	if (!enter)
		return 0;
    if(enter->irq != irq_index) {
        return 0;
    }
    struct hardirq_val_t *val;
    val = bpf_ringbuf_reserve(&syscall_rb, sizeof(*val), 0);
    if(!val) {
        return 0;
    }
    val->irq = irq_index;
    u64 delta = current_timestamp - enter->timestamp;
    val->duration = delta;
    val->timestamp = current_timestamp;
    bpf_probe_read_kernel_str(&val->hardirq_name, sizeof(val->hardirq_name), BPF_CORE_READ(action, name));
    bpf_ringbuf_submit(val, 0);


    __sync_fetch_and_add(&hardirq_counts[irq_index], 1);
    __sync_fetch_and_add(&hardirq_time[irq_index], delta);


    return 0;
}



// // 从哈希表中删除退出进程的数据，防止哈希表溢出
// SEC("tracepoint/sched/sched_process_exit")
// int sched_process_exit(void *ctx)
// {
//     struct sc_ctrl *sc_ctrl;
// 	sc_ctrl = bpf_map_lookup_elem(&sc_ctrl_map,&key);
// 	if(!sc_ctrl || !sc_ctrl->sc_func)
// 		return 0;
    
//     struct task_struct *p = (struct task_struct *)bpf_get_current_task();
//     pid_t pid = BPF_CORE_READ(p,pid);

//     bpf_map_delete_elem(&proc_syscall,&pid);

//     return 0;
// }
