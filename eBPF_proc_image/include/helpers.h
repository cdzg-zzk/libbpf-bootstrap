#ifndef _HELPERS_H
#define _HELPERS_H

const char *sched_ctrl_path = "/sys/fs/bpf/proc_image_map/sched_ctrl_map";
const char *interrupt_ctrl_path = "/sys/fs/bpf/proc_image_map/interrupt_ctrl_map";



const char* schedule_out_path = "/home/zzk/libbpf-bootstrap/eBPF_proc_image/res_out/schedule_out.txt";
const char* interrupt_out_path = "/home/zzk/libbpf-bootstrap/eBPF_proc_image/res_out/interrupt.txt";



#define CHECK_ERR(cond, info)                               \
    if (cond)                                               \
    {                                                       \
        fprintf(stderr, "[%s]" info "\n", strerror(errno));                                   \
        return -1;                                          \
    }

#define warn(...) fprintf(stderr, __VA_ARGS__)

int common_pin_map(struct bpf_map **bpf_map, const struct bpf_object *obj, const char *map_name, const char *ctrl_path)
{
    printf("enter pin map");
    int ret;
    
    *bpf_map = bpf_object__find_map_by_name(obj, map_name);
    if (!*bpf_map) {
        fprintf(stderr, "Failed to find BPF map\n");
        return -1;
    }
    // 用于防止上次没有成功 unpin 掉这个 map
    bpf_map__unpin(*bpf_map, ctrl_path);
    ret = bpf_map__pin(*bpf_map, ctrl_path);
    if (ret){
        fprintf(stderr, "Failed to pin BPF map\n");
        return -1;
    }
	
    return 0;
}


int update_interrupt_ctrl_map(struct interrupt_ctrl interrupt_ctrl){
	int err,key = 0;
	int intmap_fd;
	
	intmap_fd = bpf_obj_get(interrupt_ctrl_path);
    if (intmap_fd < 0) {
        fprintf(stderr,"Failed to open interrupt_ctrl_map file\n");
        return intmap_fd;
    }
    err = bpf_map_update_elem(intmap_fd,&key,&interrupt_ctrl, 0);
    if(err < 0){
        fprintf(stderr, "Failed to update interrupt_ctrl_map elem\n");
        return err;
    }

    return 0;
}

int update_sched_ctrl_map(struct sched_ctrl sched_ctrl){
	int err,key = 0;
	int schedmap_fd;
	
	schedmap_fd = bpf_obj_get(sched_ctrl_path);
    if (schedmap_fd < 0) {
        fprintf(stderr,"Failed to open sched_ctrl_map file\n");
        return schedmap_fd;
    }
    err = bpf_map_update_elem(schedmap_fd,&key,&sched_ctrl, 0);
    if(err < 0){
        fprintf(stderr, "Failed to update sched_ctrl_map elem\n");
        return err;
    }

    return 0;
}

#endif /* _HELPERS_H */