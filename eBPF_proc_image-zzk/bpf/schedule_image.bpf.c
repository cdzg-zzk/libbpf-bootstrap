// Copyright 2023 The LMP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/linuxkerneltravel/lmp/blob/develop/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//
// eBPF kernel-mode code that collects process schedule information

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "proc_image.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const int key = 0;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct sched_ctrl);
} sched_ctrl_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, pid_t);
	__type(value,struct proc_sched_event);
} proc_schedule SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries,256 * 10240);
} target_proc_sched_rb SEC(".maps");

// struct {
// 	__uint(type, BPF_MAP_TYPE_ARRAY);
// 	__uint(max_entries, 1);
// 	__type(key, int);
// 	__type(value,struct schedule_event);
// } target_schedule SEC(".maps");

// struct {
// 	__uint(type, BPF_MAP_TYPE_HASH);
// 	__uint(max_entries, 10240);
// 	__type(key, struct proc_id);
// 	__type(value,bool);
// } enable_add SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct sys_schedule);
} sys_schedule SEC(".maps");


static void enrunqueue(struct task_struct *p)
{
    pid_t pid = BPF_CORE_READ(p,pid);
    // int cpu = bpf_get_smp_processor_id();
    struct proc_sched_event *proc_sched_event;
    u64 current_time = bpf_ktime_get_ns();

    proc_sched_event = bpf_map_lookup_elem(&proc_schedule, &pid);
    if(!proc_sched_event){
        struct proc_sched_event proc_sched_event = {};
        
        proc_sched_event.pid = pid;
        // 提前将 count 值赋值为 1，避免输出时进程还没有被调度，导致除数出现 0 的情况
        proc_sched_event.count = 0;
        proc_sched_event.enter_time = current_time;

        bpf_map_update_elem(&proc_schedule, &pid, &proc_sched_event, BPF_ANY);
    }else{
        proc_sched_event->enter_time = current_time;
    }
    return;
}
SEC("tp_btf/sched_wakeup")
int BPF_PROG(sched_wakeup, struct task_struct *p)
{
    struct sched_ctrl *sched_ctrl;
	sched_ctrl = bpf_map_lookup_elem(&sched_ctrl_map,&key);
	if(!sched_ctrl || !sched_ctrl->sched_func)
		return 0;
    
    enrunqueue(p);

    return 0;
}

SEC("tp_btf/sched_wakeup_new")
int BPF_PROG(sched_wakeup_new, struct task_struct *p)
{
    struct sched_ctrl *sched_ctrl;
	sched_ctrl = bpf_map_lookup_elem(&sched_ctrl_map,&key);
	if(!sched_ctrl || !sched_ctrl->sched_func)
		return 0;
    
    enrunqueue(p);

    return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch, bool preempt, struct task_struct *prev, struct task_struct *next)
{
    struct sched_ctrl *sched_ctrl;
	sched_ctrl = bpf_map_lookup_elem(&sched_ctrl_map,&key);
	if(!sched_ctrl || !sched_ctrl->sched_func)
		return 0;
    
    pid_t prev_pid = BPF_CORE_READ(prev,pid);
    int prev_cpu = bpf_get_smp_processor_id();
    unsigned int prev_state = BPF_CORE_READ(prev,__state);

    pid_t next_pid = BPF_CORE_READ(next,pid);
    int next_cpu = prev_cpu;

    u64 current_time = bpf_ktime_get_ns();
    struct proc_sched_event *proc_sched_event;

    u64 this_delay;

    
    /* 记录自愿让出CPU进程的调度延迟开始时间 */
    if(prev_state==TASK_RUNNING){
        proc_sched_event = bpf_map_lookup_elem(&proc_schedule,&prev_pid);
        if(!proc_sched_event){
            struct proc_sched_event proc_sched_event = {};
            bool e_add = false;
            
            proc_sched_event.pid = prev_pid;
            proc_sched_event.count = 0;
            proc_sched_event.enter_time = current_time;


            bpf_map_update_elem(&proc_schedule, &prev_pid, &proc_schedule, BPF_ANY);
        }else{
            proc_sched_event->enter_time = current_time;
        }
    }

    /* 记录所有进程的调度信息 */
    proc_sched_event = bpf_map_lookup_elem(&proc_schedule, &next_pid);
    if(!proc_sched_event)
        return 0;

    proc_sched_event->count++;

    this_delay = current_time - proc_sched_event->enter_time;

    proc_sched_event->prio = BPF_CORE_READ(next, prio);
    proc_sched_event->sum_delay += this_delay;
    if(this_delay > proc_sched_event->max_delay)
        proc_sched_event->max_delay = this_delay;
    if(proc_sched_event->min_delay==0 || this_delay<proc_sched_event->min_delay)
        proc_sched_event->min_delay = this_delay;
    
    /* 若指定 target 进程，则单独记录 target 进程的调度信息 */
    if(sched_ctrl->target_pid == next_pid){
        struct target_sched_event* e;
        e = bpf_ringbuf_reserve(&target_proc_sched_rb, sizeof(*e), 0);
        if(!e) {
            bpf_printk("target_proc_sched_rb reserve failed\n");
            return 0;
        }
        e->cpu_id = bpf_get_smp_processor_id();
        e->delay = this_delay;
        e->ktime = current_time;
        bpf_ringbuf_submit(e, 0);
    }


    /* 记录系统的调度信息 */
    struct sys_schedule * sys_schedule;
    sys_schedule = bpf_map_lookup_elem(&sys_schedule,&key);
    if(!sys_schedule){
        struct sys_schedule sys_schedule = {};

        sys_schedule.sum_count = 1;
        sys_schedule.sum_delay = this_delay;
        sys_schedule.max_delay = this_delay;
        sys_schedule.min_delay = this_delay;
        bpf_map_update_elem(&sys_schedule,&key,&sys_schedule,BPF_ANY);
    }else{
        sys_schedule->sum_count++;
        sys_schedule->sum_delay += this_delay;
        if(this_delay > sys_schedule->max_delay)
            sys_schedule->max_delay = this_delay;
        if(sys_schedule->min_delay==0 || this_delay<sys_schedule->min_delay)
            sys_schedule->min_delay = this_delay;
    }

    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int sched_process_exit(void *ctx)
{
    struct sched_ctrl *sched_ctrl;
	sched_ctrl = bpf_map_lookup_elem(&sched_ctrl_map,&key);
	if(!sched_ctrl || !sched_ctrl->sched_func)
		return 0;
    
    struct task_struct *p = (struct task_struct *)bpf_get_current_task();
    pid_t pid = BPF_CORE_READ(p,pid);

    int cpu = bpf_get_smp_processor_id();

    struct proc_sched_event *proc_sched_event;


    // 从哈希表中删除退出进程的数据，防止哈希表溢出
    proc_sched_event = bpf_map_lookup_elem(&proc_schedule,&pid);
    if(proc_sched_event){
        bpf_map_delete_elem(&proc_schedule,&pid);
    }

    // 若目标进程退出，删除 target_schedule map 中的数据
    if(sched_ctrl->target_pid == pid){
        // schedule_event = bpf_map_lookup_elem(&target_schedule,&key);
        // if(schedule_event){
        //     // 将 count 设置成 0 即可实现目标进程退出标志
        //     schedule_event->count = 0;
        // }
        sched_ctrl->sched_func = false;
    }

    return 0;
}