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
} syscall_value SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries,256 * 10240);
} syscall_rb SEC(".maps");

int syscall_index = 0;
// struct {
//     __uint(type,BPF_MAP_TYPE_HASH);
//     __uint(max_entries, 8192);
//     __type(key, pid_t);
//     __type(value,struct container_id);   
// }container_id_map SEC(".maps");

// struct container_id{
//     char container_id[20];
// };

// struct data_t {
//     char nodename[MAX_NODENAME_LEN];
// };


SEC("tracepoint/raw_syscalls/sys_enter")
int sys_enter(struct trace_event_raw_sys_enter *args)
{
    struct sc_ctrl *syscall_ctrl;
	syscall_ctrl = bpf_map_lookup_elem(&sc_ctrl_map,&key);
    if(!syscall_ctrl || !syscall_ctrl->sc_func)
		return 0;

        // bpf_printk("proc have syscall\n");

    pid_t pid = bpf_get_current_pid_tgid();
    int cpu = bpf_get_smp_processor_id();
    // // int tgid = bpf_get_current_pid_tgid() >> 32;
    int target_pid = syscall_ctrl->target_pid;
    if(pid == target_pid) {
        // bpf_printk("target proc have syscall\n");
        pid = pid == 0 ? cpu : pid;
        u64 current_time = bpf_ktime_get_ns();
        struct syscall_enter_t enter = {};
        enter.syscall_id = (int)args->id;
        enter.timestamp = current_time;
        if(syscall_index < 0) {
            return 0;
        }
        bpf_map_update_elem(&syscall_value, &syscall_index, &enter, BPF_ANY);
        __sync_fetch_and_add(&syscall_index, 1);


    //     struct syscall_seq * syscall_seq;

    //     syscall_seq = bpf_map_lookup_elem(&proc_syscall, &pid);
    //     if(!syscall_seq){
    //         struct syscall_seq syscall_seq = {};

    //         syscall_seq.pid = pid;
    //         syscall_seq.enter_time = current_time;
    //         syscall_seq.count = 1;
    //         if((sc_ctrl->target_tgid==-1 && (sc_ctrl->target_pid==-1 || pid==sc_ctrl->target_pid)) || 
    //            (sc_ctrl->target_tgid!=-1 && tgid == sc_ctrl->target_tgid)){
    //             syscall_seq.record_syscall[0] = (int)args->id;
    //         }
            
    //         bpf_map_update_elem(&proc_syscall, &pid, &syscall_seq, BPF_ANY);
    //     }else{
    //         syscall_seq->enter_time = current_time;
    //         if(syscall_seq->count == 0){
    //             if((sc_ctrl->target_tgid==-1 && (sc_ctrl->target_pid==-1 || pid==sc_ctrl->target_pid)) || (sc_ctrl->target_tgid!=-1 && tgid == sc_ctrl->target_tgid)){
    //                 syscall_seq->record_syscall[syscall_seq->count] = (int)args->id;
    //             }
    //             syscall_seq->count++;
    //         }else if (syscall_seq->count <= MAX_SYSCALL_COUNT-1 && syscall_seq->count > 0 && 
    //                   syscall_seq->record_syscall+syscall_seq->count <= syscall_seq->record_syscall+(MAX_SYSCALL_COUNT-1)){
    //             if((sc_ctrl->target_tgid==-1 && (sc_ctrl->target_pid==-1 || pid==sc_ctrl->target_pid)) || 
    //                 (sc_ctrl->target_tgid!=-1 && tgid == sc_ctrl->target_tgid)){
    //                 syscall_seq->record_syscall[syscall_seq->count] = (int)args->id;
    //             }
    //             syscall_seq->count++;
    //         }
    //     }
    }

    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int sys_exit(struct trace_event_raw_sys_exit *args)
{
    struct sc_ctrl *syscall_ctrl;
	syscall_ctrl = bpf_map_lookup_elem(&sc_ctrl_map,&key);
	if(!syscall_ctrl || !syscall_ctrl->sc_func)
		return 0;



    pid_t pid = bpf_get_current_pid_tgid();
    int cpu = bpf_get_smp_processor_id();
    int target_pid = syscall_ctrl->target_pid;
    if(pid == target_pid) {
        pid = pid==0?cpu:pid;
        u64 current_time = bpf_ktime_get_ns();
        struct syscall_val_t *val = NULL;
        struct syscall_enter_t *enter = NULL;
        const int tmp_index = syscall_index-1;

        enter = bpf_map_lookup_elem(&syscall_value, &tmp_index);
        if(!enter) {
            return 0;
        }
        bpf_map_delete_elem(&syscall_value, &tmp_index);
        __sync_fetch_and_add(&syscall_index, -1);

        if((int)args->id != enter->syscall_id) {
            return 0;
        }
        val = bpf_ringbuf_reserve(&syscall_rb, sizeof(*val), 0);
        if(!val) {
            return 0;
        }
        val->ret = args->ret;
        val->duration = current_time - enter->timestamp;
        val->timestamp = current_time;
        val->syscall_id = enter->syscall_id;
        bpf_ringbuf_submit(val, 0);
    //     bpf_map_delete_elem(&syscall_value, &tmp_index);










        // long long unsigned int this_delay;
        // struct syscall_seq * syscall_seq;

        // syscall_seq = bpf_map_lookup_elem(&proc_syscall, &pid);
        // if(!syscall_seq){
        //     return 0;
        // }
        
        // this_delay = current_time-syscall_seq->enter_time;

        // if(syscall_seq->count < syscall_ctrl->syscalls){
        //     syscall_seq->sum_delay += this_delay;
        //     if(this_delay > syscall_seq->max_delay)
        //         syscall_seq->max_delay = this_delay;
        //     if(syscall_seq->min_delay==0 || this_delay<syscall_seq->min_delay)
        //         syscall_seq->min_delay = this_delay;

        //     //bpf_map_update_elem(&proc_syscall, &pid, syscall_seq, BPF_ANY);
        // }else{
        //     syscall_seq->sum_delay += this_delay;
        //     if(this_delay > syscall_seq->max_delay)
        //         syscall_seq->max_delay = this_delay;
        //     if(syscall_seq->min_delay==0 || this_delay<syscall_seq->min_delay)
        //         syscall_seq->min_delay = this_delay;
        //     //策略切换，首次数据不记录；
        //     if(sc_ctrl->target_tgid ==-1 && sc_ctrl->target_pid ==pid && sc_ctrl->target_pid != pre_target_pid){
        //         syscall_seq->sum_delay = 0;
        //         syscall_seq->count = 0;
        //         pre_target_pid = sc_ctrl->target_pid;//更改pre_target_pid；
        //         return 0;                
        //     }
        //     if(sc_ctrl->target_tgid !=-1 && sc_ctrl->target_tgid ==tgid && sc_ctrl->target_tgid != pre_target_tgid){
        //         syscall_seq->sum_delay = 0;
        //         syscall_seq->count = 0;
        //         pre_target_tgid = sc_ctrl->target_tgid;//更改pre_target_pid；
        //         return 0;                
        //     }
            
        //     if((sc_ctrl->target_tgid==-1 && (sc_ctrl->target_pid==-1 || pid==sc_ctrl->target_pid)) || 
        //        (sc_ctrl->target_tgid!=-1 && tgid == sc_ctrl->target_tgid)){
        //         syscall_seq->proc_count += syscall_seq->count;
        //         syscall_seq->proc_sd += syscall_seq->sum_delay;
        //     }

        //     struct syscall_seq* e;
        //     e = bpf_ringbuf_reserve(&syscall_rb, sizeof(*e), 0);
        //     if(!e)
        //         return 0;
            
        //     e->pid = pid;
        //     e->tgid = tgid;
        //     e->sum_delay = syscall_seq->sum_delay;
        //     e->max_delay = syscall_seq->max_delay;
        //     e->min_delay = syscall_seq->min_delay;
        //     e->count = syscall_seq->count;
        //     for(int i=0; i<=syscall_seq->count-1 && i<=MAX_SYSCALL_COUNT-1; i++)
        //         e->record_syscall[i] = syscall_seq->record_syscall[i];
        //     if((sc_ctrl->target_tgid==-1 && (sc_ctrl->target_pid==-1 || pid==sc_ctrl->target_pid)) || 
        //        (sc_ctrl->target_tgid!=-1 && tgid == sc_ctrl->target_tgid)){
        //         e->proc_count = syscall_seq->proc_count;
        //         e->proc_sd = syscall_seq->proc_sd;
        //     }
            
        //     bpf_ringbuf_submit(e, 0);

        //     syscall_seq->sum_delay = 0;
        //     syscall_seq->count = 0;
        // }
    }

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





struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, u64);
} softirq_start SEC(".maps");

const int softirq_key = 0;

// obj->bss
// user later
__u64 counts[NR_SOFTIRQS] = {};
__u64 time[NR_SOFTIRQS] = {};


static int softirq_handle_entry(unsigned int vec_nr)
{
	u64 current_timestamp = bpf_ktime_get_ns();

	bpf_map_update_elem(&softirq_start, &softirq_key, &current_timestamp, BPF_ANY);
	return 0;
}

static int softirq_handle_exit(unsigned int vec_nr)
{
	u64 *tsp;
    u64 current_timestamp = bpf_ktime_get_ns();

	tsp = bpf_map_lookup_elem(&softirq_start, &softirq_key);
	if (!tsp)
		return 0;
    
    struct softirq_val_t *val;
    val = bpf_ringbuf_reserve(&syscall_rb, sizeof(*val), 0);
    if(!val) {
        return 0;
    }
    val->vec_nr = vec_nr;
    u64 delta = current_timestamp - *tsp;
    val->duration = delta;
    val->timestamp = current_timestamp;
    bpf_ringbuf_submit(val, 0);

    __sync_fetch_and_add(&counts[vec_nr], 1);
    __sync_fetch_and_add(&time[vec_nr], delta);

	return 0;
}

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
	return softirq_handle_entry(vec_nr);
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
    if(pid != target_pid)
        return 0;
	return softirq_handle_exit(vec_nr);
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
                                             // hard irq还没有被验证
// struct {
// 	__uint(type, BPF_MAP_TYPE_ARRAY);
// 	__uint(max_entries, 1);
// 	__type(key, int);
// 	__type(value, u64);
// } hardirq_start SEC(".maps");

// const int hardirq_key = 0;

// static int hardirq_handle_entry(int irq, struct irqaction *action)
// {
// 	// if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
// 	// 	return 0;
// 	// if (!is_target_cpu())
// 	// 	return 0;
//     u64 current_timestamp = bpf_ktime_get_ns();
// 	bpf_map_update_elem(&hardirq_start, &hardirq_key, &current_timestamp, BPF_ANY);
//     return 0;
// 	// if (do_count) {
// 	// 	struct irq_key key = {};
// 	// 	struct info *info;

// 	// 	bpf_probe_read_kernel_str(&key.name, sizeof(key.name), BPF_CORE_READ(action, name));
// 	// 	info = bpf_map_lookup_or_try_init(&infos, &key, &zero);
// 	// 	if (!info)
// 	// 		return 0;
// 	// 	info->count += 1;
// 	// 	return 0;
// 	// } else {
// 	// 	u64 ts = bpf_ktime_get_ns();
// 	// 	u32 key = 0;

// 	// 	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
// 	// 		return 0;

// 	// 	bpf_map_update_elem(&start, &key, &ts, BPF_ANY);
// 	// 	return 0;
// 	// }
// }

// static int hardirq_handle_exit(int irq, struct irqaction *action)
// {
// 	// struct irq_key ikey = {};
// 	// struct info *info;
// 	// u32 key = 0;
// 	u64 delta;
// 	u64 *tsp;

//     u64 current_timestamp = bpf_ktime_get_ns();
// 	tsp = bpf_map_lookup_elem(&hardirq_start, &hardirq_key);
// 	if (!tsp)
// 		return 0;

// 	delta = current_timestamp - *tsp;
//     struct hardirq_val_t *val;
//     val = bpf_ringbuf_reserve(&syscall_rb, sizeof(*val), 0);
//     if(!val) {
//         return 0;
//     }
// 	bpf_probe_read_kernel_str(&val->hardirq_name, sizeof(val->hardirq_name), BPF_CORE_READ(action, name));
//     val->duration = delta;
//     val->timestamp = current_timestamp;
//     bpf_ringbuf_submit(val, 0);
// 	// info = bpf_map_lookup_or_try_init(&infos, &ikey, &zero);
// 	// if (!info)
// 	// 	return 0;

// 	// if (!targ_dist) {
// 	// 	info->count += delta;
// 	// } else {
// 	// 	u64 slot;

// 	// 	slot = log2(delta);
// 	// 	if (slot >= MAX_SLOTS)
// 	// 		slot = MAX_SLOTS - 1;
// 	// 	info->slots[slot]++;
// 	// }

// 	return 0;
// }

// SEC("tp_btf/irq_handler_entry")
// int BPF_PROG(irq_handler_entry_btf, int irq, struct irqaction *action)
// {
//     struct sc_ctrl *syscall_ctrl;
// 	syscall_ctrl = bpf_map_lookup_elem(&sc_ctrl_map,&key);
// 	if(!syscall_ctrl || !syscall_ctrl->sc_func)
// 		return 0;
// 	// if (vec_nr >= NR_SOFTIRQS)
// 	// 	return 0;
//     pid_t pid = bpf_get_current_pid_tgid();
//     int target_pid = syscall_ctrl->target_pid;
//     bpf_printk("entry hardirq pid: %d  hardirq: %s\n", pid, BPF_CORE_READ(action, name));
//     if(pid != target_pid)
//         return 0;
// 	return hardirq_handle_entry(irq, action);
// }

// SEC("tp_btf/irq_handler_exit")
// int BPF_PROG(irq_handler_exit_btf, int irq, struct irqaction *action)
// {
//     struct sc_ctrl *syscall_ctrl;
// 	syscall_ctrl = bpf_map_lookup_elem(&sc_ctrl_map,&key);
// 	if(!syscall_ctrl || !syscall_ctrl->sc_func)
// 		return 0;
// 	// if (vec_nr >= NR_SOFTIRQS)
// 	// 	return 0;
//     pid_t pid = bpf_get_current_pid_tgid();
//     int target_pid = syscall_ctrl->target_pid;
//     bpf_printk("exit hardirq pid: %d  hardirq: %s\n", pid, BPF_CORE_READ(action, name));

//     if(pid != target_pid)
//         return 0;
// 	return hardirq_handle_exit(irq, action);
// }