// // Copyright 2023 The LMP Authors.
// //
// // Licensed under the Apache License, Version 2.0 (the "License");
// // you may not use this file except in compliance with the License.
// // You may obtain a copy of the License at
// //
// // https://github.com/linuxkerneltravel/lmp/blob/develop/LICENSE
// //
// // Unless required by applicable law or agreed to in writing, software
// // distributed under the License is distributed on an "AS IS" BASIS,
// // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// // See the License for the specific language governing permissions and
// // limitations under the License.
// //
// // author: zhangziheng0525@163.com
// //
// // eBPF kernel-mode code that collects process schedule information

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "proc_image.h"
#include "maps.bpf.h"
char LICENSE[] SEC("license") = "Dual BSD/GPL";

// const int key = 0;

// struct {
// 	__uint(type, BPF_MAP_TYPE_ARRAY);
// 	__uint(max_entries, 1);
// 	__type(key, int);
// 	__type(value, struct sched_ctrl);
// } sched_ctrl_map SEC(".maps");

// struct {
// 	__uint(type, BPF_MAP_TYPE_HASH);
// 	__uint(max_entries, 10240);
// 	__type(key, struct proc_id);
// 	__type(value, u64);
// } enrunq_time SEC(".maps");

// struct {
// 	__uint(type, BPF_MAP_TYPE_ARRAY);
// 	__uint(max_entries, 1);
// 	__type(key, int);
// 	__type(value, u64);
// } encpu_time SEC(".maps");

// struct {
// 	__uint(type, BPF_MAP_TYPE_HASH);
// 	__uint(max_entries, 10240);
// 	__type(key, struct proc_id);
// 	__type(value,struct schedule_event);
// } proc_schedule SEC(".maps");

// struct {
// 	__uint(type, BPF_MAP_TYPE_ARRAY);
// 	__uint(max_entries, 1);
// 	__type(key, int);
// 	__type(value,struct schedule_event);
// } target_schedule SEC(".maps");



// struct {
// 	__uint(type, BPF_MAP_TYPE_ARRAY);
// 	__uint(max_entries, 1);
// 	__type(key, int);
// 	__type(value, struct sum_schedule);
// } sys_schedule SEC(".maps");


// static int enrunqueue(struct task_struct *p, struct sched_ctrl *sched_ctrl)
// {
//     pid_t pid = BPF_CORE_READ(p,pid);
//     int cpu = bpf_get_smp_processor_id();
//     // struct schedule_event *schedule_event;
//     struct proc_id pd = CREATE_PD(pid, cpu);
//     u64 current_time = bpf_ktime_get_ns();
//     if(sched_ctrl->target_pid != -1 && sched_ctrl->target_pid != pid) {
//         return 0;
//     }
//     bpf_map_update_elem(&enrunq_time, &pd, &current_time, BPF_ANY);
//     return 0;
// }
// SEC("tp_btf/sched_wakeup")
// int BPF_PROG(sched_wakeup, struct task_struct *p)
// {
//     struct sched_ctrl *sched_ctrl;
// 	sched_ctrl = bpf_map_lookup_elem(&sched_ctrl_map,&key);
// 	if(!sched_ctrl || !sched_ctrl->sched_func)
// 		return 0;
//     return enrunqueue(p, sched_ctrl);
// }

// SEC("tp_btf/sched_wakeup_new")
// int BPF_PROG(sched_wakeup_new, struct task_struct *p)
// {
//     struct sched_ctrl *sched_ctrl;
// 	sched_ctrl = bpf_map_lookup_elem(&sched_ctrl_map,&key);
// 	if(!sched_ctrl || !sched_ctrl->sched_func)
// 		return 0;
//     return enrunqueue(p, sched_ctrl);
// }

// SEC("tp_btf/sched_switch")
// int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
// {
//     struct sched_ctrl *sched_ctrl;
// 	sched_ctrl = bpf_map_lookup_elem(&sched_ctrl_map,&key);
// 	if(!sched_ctrl || !sched_ctrl->sched_func)
// 		return 0;
    
//     pid_t prev_pid = BPF_CORE_READ(prev,pid);

//     int cpu = bpf_get_smp_processor_id();
//     unsigned int prev_state = BPF_CORE_READ(prev,__state);
//     pid_t next_pid = BPF_CORE_READ(next,pid);

//     u64 current_time = bpf_ktime_get_ns();
//     struct schedule_event *schedule_event;
//     if(prev_pid == next_pid) {
//         return 0;
//     }
//     struct proc_id next_pd = CREATE_PD(next_pid, cpu);
//     struct proc_id prev_pd = CREATE_PD(prev_pid, cpu);
//     u64 this_delay;
//     int key = 0;
//     struct schedule_event *target_event;
//     struct sum_schedule * sum_schedule;
    
//     if(sched_ctrl->target_pid == -1) {                                                // 所有进程都要操作
//         /* 记录自愿让出CPU进程的调度延迟开始时间 */
//         if(prev_state==TASK_RUNNING){
//             bpf_map_update_elem(&enrunq_time, &prev_pd, &current_time, BPF_ANY);
//         } else {
//             // wait time start
//         }
//         // next pid
//         /* 记录所有进程的调度信息 */
//         u64* start_time = bpf_map_lookup_elem(&enrunq_time, &next_pd);
//         if(!start_time || *start_time == 0) {
//             return 0;
//         }
//         this_delay = current_time-*start_time;
//         if(this_delay/1000000 > 100) {
//             bpf_printk("proc pid: %d   cpu: %d   current: %lld    start: %lld\n", next_pid, cpu, current_time, *start_time);
//         }
//         schedule_event = bpf_map_lookup_elem(&proc_schedule, &next_pd);
//         if(schedule_event) {
//             schedule_event->pid = next_pid;
//             schedule_event->count++;
//             schedule_event->prio = BPF_CORE_READ(next, prio);
//             schedule_event->sum_delay += this_delay;
//             if(this_delay > schedule_event->max_delay)
//                 schedule_event->max_delay = this_delay;
//             if(schedule_event->min_delay == 0 || this_delay < schedule_event->min_delay)
//                 schedule_event->min_delay = this_delay;
//         } else {
//             struct schedule_event schedule_event = {};
//             schedule_event.count = 1;
//             schedule_event.pid = next_pid;
//             schedule_event.prio = BPF_CORE_READ(next, prio);
//             schedule_event.sum_delay = this_delay;
//             schedule_event.max_delay = this_delay;
//             schedule_event.min_delay = this_delay;
//             bpf_map_update_elem(&proc_schedule, &next_pd, &schedule_event, BPF_ANY);
//         }

//         // /* 若指定 target 进程，则单独记录 target 进程的调度信息 */
//         // if(sched_ctrl->target_pid == next_pid){
//         //     bpf_map_update_elem(&target_schedule,&key,schedule_event,BPF_ANY);
//         // }

//         /* 记录系统的调度信息, 不将pid == 0的进程作为系统标准 */
//         if(next_pid != 0) {
//             sum_schedule = bpf_map_lookup_elem(&sys_schedule,&key);
//             if(!sum_schedule){
//                 struct sum_schedule sum_schedule = {};
//                 sum_schedule.sum_count++;
//                 sum_schedule.sum_delay += this_delay;
//                 if(this_delay > sum_schedule.max_delay)
//                     sum_schedule.max_delay = this_delay;
//                 if(sum_schedule.min_delay==0 || this_delay<sum_schedule.min_delay)
//                     sum_schedule.min_delay = this_delay;
//                 bpf_map_update_elem(&sys_schedule,&key,&sum_schedule,BPF_ANY);
//             }else{
//                 sum_schedule->sum_count++;
//                 sum_schedule->sum_delay += this_delay;
//                 if(this_delay > sum_schedule->max_delay)
//                     sum_schedule->max_delay = this_delay;
//                 if(sum_schedule->min_delay==0 || this_delay<sum_schedule->min_delay)
//                     sum_schedule->min_delay = this_delay;
//             }
//         }
//     } else if(sched_ctrl->target_pid == prev_pid) {
//         if(prev_state == TASK_RUNNING) {
//             bpf_map_update_elem(&enrunq_time, &prev_pd, &current_time, BPF_ANY);
//         }
//         u64* cpu_start_time = bpf_map_lookup_elem(&encpu_time, &key);
//         if(!cpu_start_time || current_time < *cpu_start_time) {
//             return 0;
//         }
//         u64 oncpu_time = current_time - *cpu_start_time;
//         bpf_printk("[target oncpu time]ktime: %lld   pid: %d  cpu:  %d  prio: %d  oncpu_time: %lld  states: %d", current_time, prev_pid, cpu, BPF_CORE_READ(next, prio), oncpu_time, prev_state);
//     } else if(sched_ctrl->target_pid == next_pid) {
//         // 记录占用CPU的开始时间
//         bpf_map_update_elem(&encpu_time, &key, &current_time, BPF_ANY);
//         u64* start_time = bpf_map_lookup_elem(&enrunq_time, &next_pd);
//         if(!start_time || *start_time == 0) {
//             return 0;
//         }
//         this_delay = current_time-*start_time;
//         if(this_delay/1000000 > 100) {
//             bpf_printk("target pid: %d   cpu: %d   current: %lld    start: %lld\n", next_pid, cpu, current_time, *start_time);
//         }
//         // 采用ringbuffer的方式 不使用map
//         bpf_printk("[target runq latency]ktime: %lld   pid: %d  cpu:  %d  prio: %d  this_delay: %lld", current_time, next_pid, cpu, BPF_CORE_READ(next, prio), this_delay);
//         // target_event = bpf_map_lookup_elem(&target_schedule, &key);
//         // if(target_event) {
//         //     target_event->pid = next_pid;
//         //     target_event->count++;
//         //     target_event->prio = BPF_CORE_READ(next, prio);
//         //     target_event->sum_delay += this_delay;
//         //     if(this_delay > target_event->max_delay)
//         //         target_event->max_delay = this_delay;
//         //     if(target_event->min_delay == 0 || this_delay < target_event->min_delay)
//         //         target_event->min_delay = this_delay;
//         //     // if(target_event->count < 100) {
//         //     //     bpf_printk("pid: %d   max: %lld    min: %lld    current: %lld    start: %lld    delay: %lld\n", target_event->max_delay, target_event->min_delay, current_time, *start_time, this_delay);
//         //     // }

//         // } else {
//         //     struct schedule_event target_event = {};
//         //     target_event.count = 1;
//         //     target_event.pid = next_pid;
//         //     target_event.prio = BPF_CORE_READ(next, prio);
//         //     target_event.sum_delay = this_delay;
//         //     target_event.max_delay = this_delay;
//         //     target_event.min_delay = this_delay;
//         //     bpf_map_update_elem(&target_schedule, &key, &target_event, BPF_ANY);
//         // }
//     }


//     return 0;
// }




// // SEC("tp_btf/sched_stat_sleep")
// // int BPF_PROG(sched_stat_sleep, struct task_struct *p, u64 delta)
// // {
// //     struct sched_ctrl *sched_ctrl;
// // 	sched_ctrl = bpf_map_lookup_elem(&sched_ctrl_map,&key);
// // 	if(!sched_ctrl || !sched_ctrl->sched_func)
// // 		return 0;
// //     u64 current_time = bpf_ktime_get_ns();
// //     pid_t pid = BPF_CORE_READ(p,pid);
// //     int cpu = bpf_get_smp_processor_id();
// //     // if(sched_ctrl->target_pid != pid) {
// //     //     return 0;
// //     // }
// //     bpf_printk("[target sleep latency]ktime: %lld   pid: %d   cpu: %d   prio: %d   state: %d   sleep_time: %lld", current_time, cpu, BPF_CORE_READ(p, prio), BPF_CORE_READ(p,__state), delta);
// //     return 0;
// // }
// // SEC("tp_btf/sched_stat_blocked")
// // int BPF_PROG(sched_stat_blocked, struct task_struct *p, u64 delta)
// // {
// //     struct sched_ctrl *sched_ctrl;
// // 	sched_ctrl = bpf_map_lookup_elem(&sched_ctrl_map,&key);
// // 	if(!sched_ctrl || !sched_ctrl->sched_func)
// // 		return 0;
// //     u64 current_time = bpf_ktime_get_ns();
// //     pid_t pid = BPF_CORE_READ(p,pid);
// //     int cpu = bpf_get_smp_processor_id();
// //     // if(sched_ctrl->target_pid != pid) {
// //     //     return 0;
// //     // }
// //     bpf_printk("[target blocked latency]ktime: %lld   pid: %d   cpu: %d   prio: %d   state: %d   sleep_time: %lld", current_time, cpu, BPF_CORE_READ(p, prio), BPF_CORE_READ(p,__state), delta);
// //     return 0;
// // }
// // SEC("tp_btf/sched_stat_iowait")
// // int BPF_PROG(sched_stat_iowait, struct task_struct *p, u64 delta)
// // {
// //     struct sched_ctrl *sched_ctrl;
// // 	sched_ctrl = bpf_map_lookup_elem(&sched_ctrl_map,&key);
// // 	if(!sched_ctrl || !sched_ctrl->sched_func)
// // 		return 0;
// //     u64 current_time = bpf_ktime_get_ns();
// //     pid_t pid = BPF_CORE_READ(p,pid);
// //     int cpu = bpf_get_smp_processor_id();
// //     // if(sched_ctrl->target_pid != pid) {
// //     //     return 0;
// //     // }
// //     bpf_printk("[target iowait latency]ktime: %lld   pid: %d   cpu: %d   prio: %d   state: %d   sleep_time: %lld", current_time, cpu, BPF_CORE_READ(p, prio), BPF_CORE_READ(p,__state), delta);
// //     return 0;
// // }



// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 Wenbo Zhang
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "core_fixes.bpf.h"


#define MAX_ENTRIES		10240



// const volatile bool kernel_threads_only = false;
// const volatile bool user_threads_only = false;
// const volatile __u64 max_block_ns = -1;
// const volatile __u64 min_block_ns = 1;
// const volatile bool filter_by_tgid = false;
// const volatile bool filter_by_pid = false;
// const volatile long state = -1;





// struct internal_key {
// 	u64 start_ts;
// 	struct key_t key;
// };

// ring buffer
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries,256 * 10240);
} sched_rb SEC(".maps");

// struct {
// 	__uint(type, BPF_MAP_TYPE_HASH);
// 	__uint(max_entries, MAX_ENTRIES);
// 	__type(key, int);
// 	__type(value, u64);
// } offcpu_time SEC(".maps");

// struct {
// 	__uint(type, BPF_MAP_TYPE_HASH);
// 	__uint(max_entries, MAX_ENTRIES);
// 	__type(key, int);
// 	__type(value, u64);
// } oncpu_time SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct sched_ctrl);
} sched_ctrl_map SEC(".maps");

// struct {
// 	__uint(type, BPF_MAP_TYPE_HASH);
// 	__type(key, int);
// 	__type(value, struct offcpu_val_t);
// 	__uint(max_entries, MAX_ENTRIES);
// } offcpu_value SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
} stackmap SEC(".maps");

// struct {
// 	__uint(type, BPF_MAP_TYPE_HASH);
// 	__type(key, struct offcpu_key_t);
// 	__type(value, struct offcpu_val_t);
// 	__uint(max_entries, MAX_ENTRIES);
// } offcpu_info SEC(".maps");


// BPF_NOEXIST：映射中不得存在key的条目。
// BPF_EXIST：映射中必须已存在key的条目。
// BPF_ANY：对于key的条目是否存在，没有条件。




// static __always_inline void xx()
static int timestamp_ringbuf_out(u64* timestamp, enum timestamp_type ts_type)
{
	struct timestamp_t *ts_t;
	ts_t = bpf_ringbuf_reserve(&sched_rb, sizeof(*ts_t), 0);
	if(!ts_t){
		return 1;
	}
	ts_t->timestamp = *timestamp;
	ts_t->ts_type = ts_type;
	bpf_ringbuf_submit(ts_t, 0);
	return 0;
}
const int key = 0;
static int handle_sched_switch(void *ctx, bool preempt, struct task_struct *prev, struct task_struct *next, int target_pid)
{
    // bpf_printk("start\n");
	struct offcpu_val_t *valp, *val;
	s64 delta;
	u64 timestamp = bpf_ktime_get_ns();
	int pid = BPF_CORE_READ(prev, pid);
	int cpu = bpf_get_smp_processor_id();
	if (target_pid == pid) {   // target proc switch-out
        // bpf_printk("print Kernel stack\n");
		/* To distinguish idle threads of different cores */
		pid = pid == 0? cpu : pid;
		// val.pid = pid;
		// i_key.key.tgid = BPF_CORE_READ(prev, tgid);
		// bpf_map_update_elem(&offcpu_time, &pid, &timestamp, BPF_ANY);

		if(timestamp_ringbuf_out(&timestamp, OFFCPU))
		{
			return 0;
		}


		val = bpf_ringbuf_reserve(&sched_rb, sizeof(*val), 0);
		if(!val) {
			return 0;
		}
		if (BPF_CORE_READ(prev, flags) & PF_KTHREAD)
			val->user_stack_id = -1;
		else
			val->user_stack_id = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK);
		val->kern_stack_id = bpf_get_stackid(ctx, &stackmap, 0);
		// bpf_map_update_elem(&offcpu_start, &pid, &key, BPF_ANY);
		bpf_probe_read_kernel_str(&val->next_comm, sizeof(next->comm), BPF_CORE_READ(next, comm));
		val->next_pid = BPF_CORE_READ(next, pid);
		// val->delta = 0;
		val->state = BPF_CORE_READ(prev, __state);
		val->cpu = cpu;
		val->tgid = BPF_CORE_READ(prev, tgid);
		// bpf_map_update_elem(&offcpu_value, &pid, &val, BPF_ANY);
		bpf_ringbuf_submit(val, 0);
	}

	pid = BPF_CORE_READ(next, pid);
	if(pid != target_pid)
		return 0;
	pid = pid == 0 ? cpu : pid;
    // bpf_printk("print User stack\n");
	// bpf_map_update_elem(&oncpu_time, &pid, &timestamp, BPF_ANY);  // 可有可无
	if(timestamp_ringbuf_out(&timestamp, ONCPU)) {
		return 0;
	}
	// valp = bpf_map_lookup_elem(&offcpu_value, &pid);
	// if (!valp)
	// 	return 0;
	// u64* offcpu_ns = bpf_map_lookup_elem(&offcpu_time, &pid);
	// if(!offcpu_ns) {
	// 	bpf_map_delete_elem(&offcpu_value, &pid);
	// 	return 0;
	// }


	// delta = (s64)(timestamp - *offcpu_ns);
	// if (delta < 0) {
	// 	bpf_map_delete_elem(&offcpu_value, &pid);
	// 	return 0;
	// }
	// delta /= 1000U;
	// // if (delta < min_block_ns || delta > max_block_ns)
	// // 	goto cleanup;
	// // valp = bpf_map_lookup_elem(&offcpu_info, keyp);
	// // if (!valp)
	// // 	goto cleanup;
	// // __sync_fetch_and_add(&valp->delta, delta);
	// valp->delta = (u64)delta;
	// ring buffer not used
	// bpf_printk("target_comm: %s      next comm: %s         cpu:%d    offcpu_time delta: %lld\n", BPF_CORE_READ(next, comm), valp->next_comm, valp->cpu, valp->delta);
	return 0;
}


SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
    // bpf_printk("sched_switch-tp\n");

    struct sched_ctrl *sched_ctrl;
    sched_ctrl = bpf_map_lookup_elem(&sched_ctrl_map,&key);
    if(!sched_ctrl || !sched_ctrl->sched_func)
        return 0;
    int target_pid = sched_ctrl->target_pid;
    // bpf_printk("btf-handle\n");
	handle_sched_switch(ctx, preempt, prev, next, target_pid);

	return 0;
}

// SEC("raw_tp/sched_switch")
// int BPF_PROG(sched_switch_raw, bool preempt, struct task_struct *prev, struct task_struct *next)
// {
//         // bpf_printk("sched_switch-raw-tp\n");

//     struct sched_ctrl *sched_ctrl;
//     sched_ctrl = bpf_map_lookup_elem(&sched_ctrl_map,&key);
//     if(!sched_ctrl || !sched_ctrl->sched_func)
//         return 0;
//     int target_pid = sched_ctrl->target_pid;
//     bpf_printk("raw-handle\n");
// 	handle_sched_switch(ctx, preempt, prev, next, target_pid);
// 	return 0;
// }


// struct {
// 	__uint(type, BPF_MAP_TYPE_HASH);
// 	__uint(max_entries, MAX_ENTRIES);
// 	__type(key, int);
// 	__type(value, struct wakeup_value_t);
// } wakeup_value SEC(".maps");

static int wakeup(void *ctx, struct task_struct *p, int target_pid, enum timestamp_type ts_type)
{
	int pid = BPF_CORE_READ(p, pid);
	int cpu = bpf_get_smp_processor_id();
	u64 *tsp;
	s64 delta;
	struct wakeup_value_t *val;

	if (target_pid != pid)
		return 0;
	pid = pid == 0 ? cpu : pid;
	// tsp = bpf_map_lookup_elem(&offcpu_time, &pid);
	// if (!tsp)
	// 	return 0;
	// bpf_map_delete_elem(&start, &tid);

	// delta = (s64)(bpf_ktime_get_ns() - *tsp);
	// if(delta < 0) {
	// 	// goto cleanup;
	// 	return 0;
	// }
	u64 timestamp = bpf_ktime_get_ns();
	if(timestamp_ringbuf_out(&timestamp, ts_type)) {
		return 0;
	}
	val = bpf_ringbuf_reserve(&sched_rb, sizeof(*val), 0);
	if(!val) {
		return 0;
	}
	// val->delta = (u64)delta;
	val->tgid = BPF_CORE_READ(p, tgid);
	val->cpu = cpu;
	val->wakeup_kern_stack_id = bpf_get_stackid(ctx, &stackmap, 0);
	if (BPF_CORE_READ(p, flags) & PF_KTHREAD)
		val->wakeup_user_stack_id = -1;
	else
		val->wakeup_user_stack_id = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK);
	bpf_get_current_comm(&val->waker_proc_comm, sizeof(val->waker_proc_comm));
	val->waker_pid = bpf_get_current_pid_tgid() >> 32;
	// bpf_probe_read_kernel_str(&val.target_proc_comm, sizeof(p->comm), BPF_CORE_READ(p, comm));
	bpf_ringbuf_submit(val, 0);
	// bpf_map_update_elem(&wakeup_value, &pid, &val, BPF_ANY);
	// bpf_printk("waker comm: %s   delta: %lld     stackid: %d\n", val->waker_proc_comm, val->delta, val->wakeup_kern_stack_id);
	// count_key = bpf_map_lookup_or_try_init(&wakeup_duration, &key, &zero);
	// if (count_key)
	// 	__atomic_add_fetch(count_key, (u64)delta, __ATOMIC_RELAXED);

// cleanup:
// 	bpf_map_delete_elem(&offcpu_time, &pid);
	return 0;
}

SEC("tp_btf/sched_wakeup")
int BPF_PROG(sched_wakeup, struct task_struct *p)
{
	struct sched_ctrl *sched_ctrl;
    sched_ctrl = bpf_map_lookup_elem(&sched_ctrl_map,&key);
    if(!sched_ctrl || !sched_ctrl->sched_func)
        return 0;
	int target_pid = sched_ctrl->target_pid;
	return wakeup(ctx, p, target_pid, WAKEUP);
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(sched_wakeup_new, struct task_struct *p)
{
	struct sched_ctrl *sched_ctrl;
    sched_ctrl = bpf_map_lookup_elem(&sched_ctrl_map,&key);
    if(!sched_ctrl || !sched_ctrl->sched_func)
        return 0;
	int target_pid = sched_ctrl->target_pid;
	return wakeup(ctx, p, target_pid, WAKEUPNEW);
}



SEC("kprobe/finish_task_switch.isra.0") 
int BPF_KPROBE(finish_task_switch, struct task_struct *prev) {
	struct sched_ctrl *sched_ctrl;
    sched_ctrl = bpf_map_lookup_elem(&sched_ctrl_map,&key);
    if(!sched_ctrl || !sched_ctrl->sched_func)
        return 0;
	int target_pid = sched_ctrl->target_pid;
    pid_t pid = BPF_CORE_READ(prev, pid);
	if(pid != target_pid) {
		return 0;
	}
	u64 timestamp = bpf_ktime_get_ns();
	if(timestamp_ringbuf_out(&timestamp, SWITCH)) {
		return 0;
	}
    
    return 0;
}



// SEC("tracepoint/sched/sched_process_exit")
// int sched_process_exit(void *ctx)
// {
//     struct sched_ctrl *sched_ctrl;
// 	sched_ctrl = bpf_map_lookup_elem(&sched_ctrl_map,&key);
// 	if(!sched_ctrl || !sched_ctrl->sched_func)
// 		return 0;
    
//     struct task_struct *p = (struct task_struct *)bpf_get_current_task();
//     pid_t pid = BPF_CORE_READ(p,pid);

//     int cpu = bpf_get_smp_processor_id();
//     struct proc_id pd = CREATE_PD(pid, cpu);
//     struct schedule_event *schedule_event, *target_event;



//     // 从哈希表中删除退出进程的数据，防止哈希表溢出statt
//     schedule_event = bpf_map_lookup_elem(&proc_schedule,&pd);
//     if(schedule_event){
//         bpf_map_delete_elem(&proc_schedule,&pd);
//     }


//     // 若目标进程退出，删除 target_schedule map 中的数据
//     if(sched_ctrl->target_pid == pid){
//         // target_event = bpf_map_lookup_elem(&target_schedule,&key);
//         // if(target_event){
//         //     // 将 count 设置成 0 即可实现目标进程退出标志
//         //     target_event->count = 0;
//         // }
//         sched_ctrl->sched_func = false;
//         bpf_map_update_elem(&sched_ctrl_map, &key, sched_ctrl, BPF_ANY);
//     }


//     return 0;
// }