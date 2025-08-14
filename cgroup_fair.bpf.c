#include "common.bpf.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

const volatile unsigned long long root_cgroup;  // can be 0 for no restriction
const volatile int total_cpus;

// FALLBACK_DSQ will simply be FIFO
#define FALLBACK_DSQ 0
// slice is 5ms
#define SLICE 5000000

struct cpumask_wrapper {
    struct bpf_cpumask __kptr *mask;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(map_flags, BPF_F_RDONLY_PROG);
    __type(key, u32);
    __type(value, long);
    __uint(max_entries, 1);
} enabled SEC(".maps");

// identical to `enabled` array but in a more convenient form
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, struct cpumask_wrapper);
    __uint(max_entries, 1);
} valid_cpus SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, struct cpumask_wrapper);
    __uint(max_entries, 1);
} unallocated_cpus SEC(".maps");

struct cgroup_ctx {
    // access is not racy since it is only mutated on cgroup init/exit
    struct bpf_cpumask __kptr *mask;
    // stores max scx.dsq_vtime for any process in this cgroup that has run
    // difference between any task->scx.dsq_vtime is the lag time
    // Warning: make sure to reset lag time in task init and wakeup!
    u64 max_vtime;
};

struct {
    __uint(type, BPF_MAP_TYPE_CGRP_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, u32);
    __type(value, struct cgroup_ctx);
} cgroup_ctx_array SEC(".maps");

struct cpu_ctx {
    // access to assigned_cgroup is racy, but that's OK
    // if a process is placed in the wrong queue, it will get fixed on the next dispatch
    u32 assigned_cgroup;  // 0 indicates no assigned cgroup
    // we can't read the `prev` task's cgroup inside dispatch()
    // so we store whether it has local affinity ahead of time (in running())
    bool has_local_affinity;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct cpu_ctx);
    __uint(max_entries, 1);
} cpu_ctx_array SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, u64);
} task_start_time SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u64));
    __uint(max_entries, 3); /* [switch with local affinity, re-ran prev, direct dispatch] */
} stats SEC(".maps");

static bool is_enabled(void) {
    u32 key = 0;
    bool *val = bpf_map_lookup_elem(&enabled, &key);
    if (!val) {
        return false;
    } else {
        return *val != 0;
    }
}

static struct cpu_ctx *get_cpu_ctx() {
    u32 key = 0;
    struct cpu_ctx *ctx = bpf_map_lookup_elem(&cpu_ctx_array, &key);
    if (ctx == NULL) {
        scx_bpf_error("Failed to get CPU context");
        return NULL;
    }
    return ctx;
}

static struct cgroup_ctx *get_cgroup_ctx(struct cgroup *cgrp) {
    struct cgroup_ctx *ctx = bpf_cgrp_storage_get(&cgroup_ctx_array, cgrp, NULL, 0);
    if (ctx == NULL) {
        scx_bpf_error("Failed to get cgroup context for cgroup %llu", cgrp->kn->id);
        return NULL;
    }
    if (ctx->mask == NULL) {
        scx_bpf_error("Cgroup context for cgroup %llu has no cpumask", cgrp->kn->id);
    }
    return ctx;
}

static struct bpf_cpumask *lock_unallocated_cpus(void) {
    u32 key = 0;
    struct cpumask_wrapper *value = bpf_map_lookup_elem(&unallocated_cpus, &key);
    bpf_rcu_read_lock();
    if (value == NULL) {
        scx_bpf_error("Failed to get unallocated cpumask");
        return NULL;
    }
    struct bpf_cpumask *mask = value->mask;
    if (mask == NULL) {
        scx_bpf_error("No cpumask found for unallocated CPUs");
        return NULL;
    }
    return mask;
}

static struct bpf_cpumask *get_valid_cpus(void) {
    u32 key = 0;
    struct cpumask_wrapper *value = bpf_map_lookup_elem(&valid_cpus, &key);
    if (value == NULL) {
        scx_bpf_error("Failed to get valid cpumask");
        return NULL;
    }
    struct bpf_cpumask *mask = value->mask;
    if (mask == NULL) {
        scx_bpf_error("No cpumask found for valid CPUs");
        return NULL;
    }
    return mask;
}

static u64 *get_task_start_time(struct task_struct *p) {
    u64 *stats = bpf_task_storage_get(&task_start_time, p, 0, 0);
    if (stats == NULL) {
        scx_bpf_error("Failed to get task stats for task %d", p->pid);
        return NULL;
    }
    return stats;
}

static void stat_inc(u32 idx) {
    u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
    if (cnt_p) (*cnt_p)++;
}

s32 BPF_STRUCT_OPS(cgroup_fair_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags) {
    s32 cpu = -1;
    struct cgroup *cgrp = scx_bpf_task_cgroup(p);
    struct cgroup_ctx *cgrp_ctx = get_cgroup_ctx(cgrp);
    if (cgrp_ctx != NULL) {
        // task has just woken up
        // cap lag time to 1 slice
        if (time_before(p->scx.dsq_vtime, cgrp_ctx->max_vtime - SLICE)) {
            p->scx.dsq_vtime = cgrp_ctx->max_vtime - SLICE;
        }

        if (cgrp_ctx->mask != NULL) {
            struct bpf_cpumask *mask = cgrp_ctx->mask;
            s32 idle_affinity = scx_bpf_pick_idle_cpu((cpumask_t *)mask, 0);
            if (idle_affinity >= 0) {
                bpf_cgroup_release(cgrp);
                scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SLICE, 0);
                bpf_printk("Directly dispatching to idle CPU %d", idle_affinity);
                stat_inc(2);
                return idle_affinity;
            } else {
                cpu = scx_bpf_pick_any_cpu((cpumask_t *)mask, 0);
            }
        }
    }

    struct bpf_cpumask *valid_cpus = get_valid_cpus();
    if (valid_cpus != NULL) {
        s32 idle_foreign = scx_bpf_pick_idle_cpu((cpumask_t *)valid_cpus, 0);
        if (idle_foreign >= 0) {
            bpf_cgroup_release(cgrp);
            scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SLICE, 0);
            stat_inc(2);
            return idle_foreign;
        }

        if (cpu == -1) {
            cpu = scx_bpf_pick_any_cpu((cpumask_t *)valid_cpus, 0);
        }
    }

    bpf_cgroup_release(cgrp);
    return cpu;
}

void BPF_STRUCT_OPS(cgroup_fair_enqueue, struct task_struct *p, u64 enq_flags) {
    struct cgroup *cgrp = scx_bpf_task_cgroup(p);
    struct cgroup_ctx *cgrp_ctx = get_cgroup_ctx(cgrp);
    if (cgrp_ctx == NULL) {
        scx_bpf_dsq_insert(p, FALLBACK_DSQ, SLICE, enq_flags);
    } else {
        // bpf_printk("Enqueueing, dif: %lld    max: %llu   proc time: %llu", cgrp_ctx->max_vtime -
        // p->scx.dsq_vtime, cgrp_ctx->max_vtime, p->scx.dsq_vtime);
        scx_bpf_dsq_insert_vtime(p, cgrp->kn->id, SLICE, p->scx.dsq_vtime, enq_flags);
    }
    bpf_cgroup_release(cgrp);
}

void BPF_STRUCT_OPS(cgroup_fair_dispatch, s32 cpu, struct task_struct *prev) {
    if (!is_enabled()) {
        return;
    }

    struct cpu_ctx *curr_ctx = get_cpu_ctx();
    if (curr_ctx != NULL) {
        if (curr_ctx->assigned_cgroup > 0) {
            if (scx_bpf_dsq_move_to_local(curr_ctx->assigned_cgroup)) {
                // successfully switched out `prev` with a local-affinity process
                stat_inc(0);
                return;
            } else if (prev != NULL) {
                if (curr_ctx->has_local_affinity) {
                    // `prev` is a local-affinity process, let it keep running
                    stat_inc(1);
                    return;
                }
            }
        }
    }

    // prev cannot possibly be a local-affinity process, switch it with another foreign process
    scx_bpf_dsq_move_to_local(FALLBACK_DSQ);
}

void BPF_STRUCT_OPS(cgroup_fair_running, struct task_struct *p) {
    struct cgroup *cgrp = scx_bpf_task_cgroup(p);

    struct cpu_ctx *curr_ctx = get_cpu_ctx();
    if (curr_ctx != NULL) {
        if (curr_ctx->assigned_cgroup > 0) {
            curr_ctx->has_local_affinity = cgrp->kn->id == curr_ctx->assigned_cgroup;
        }
    }

    struct cgroup_ctx *cgrp_ctx = get_cgroup_ctx(cgrp);
    if (cgrp_ctx != NULL) {
        // updating max_vtime is racy! but let's just live with it
        if (time_before(cgrp_ctx->max_vtime, p->scx.dsq_vtime)) {
            cgrp_ctx->max_vtime = p->scx.dsq_vtime;
        }
    }

    u64 *start = get_task_start_time(p);
    if (start != NULL) {
        *start = scx_bpf_now();
    }

    bpf_cgroup_release(cgrp);
}

void BPF_STRUCT_OPS(cgroup_fair_stopping, struct task_struct *p, bool runnable) {
    u64 *start = get_task_start_time(p);
    if (start != NULL) {
        u64 now = scx_bpf_now();
        p->scx.dsq_vtime += now - *start;
    }
}

s32 BPF_STRUCT_OPS(cgroup_fair_init_task, struct task_struct *p, struct scx_init_task_args *args) {
    bpf_task_storage_get(&task_start_time, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);

    // this may be called before cgroup_fair_cgroup_init()
    struct cgroup_ctx *cgrp_ctx = bpf_cgrp_storage_get(&cgroup_ctx_array, args->cgroup, NULL, 0);
    if (cgrp_ctx != NULL) {
        p->scx.dsq_vtime = cgrp_ctx->max_vtime;
    }
    return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(cgroup_fair_cgroup_init, struct cgroup *cgrp,
                             struct scx_cgroup_init_args *args) {
    if (root_cgroup != 0) {
        struct cgroup *parent = bpf_cgroup_ancestor(cgrp, cgrp->level - 1);
        if (parent == NULL) {
            // we are initializing the root cgroup, skip it
            return 0;
        } else if (parent->kn->id != root_cgroup) {
            bpf_cgroup_release(parent);
            // we are initializing unrelated cgroup, skip it
            return 0;
        } else {
            bpf_cgroup_release(parent);
        }
    }

    s32 ret = 0;

    bpf_printk("Initializing child cgroup %llu", root_cgroup, cgrp->kn->id);

    struct cgroup_ctx *state =
        bpf_cgrp_storage_get(&cgroup_ctx_array, cgrp, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (state == NULL) {
        scx_bpf_error("Failed to create cgroup state for %llu", cgrp->kn->id);
        ret = -ENOMEM;
        goto done;
    }

    int cpus_needed = div_round_up(args->weight, 100);
    if (scx_bpf_create_dsq(cgrp->kn->id, -1)) {
        scx_bpf_error("Failed to create dispatch queue for cgroup %llu", cgrp->kn->id);
        ret = -ENOMEM;
        goto done;
    }

    struct bpf_cpumask *cpumask = lock_unallocated_cpus();
    if (cpumask == NULL) {
        ret = -ENOENT;
        goto unlock;
    }

    if (bpf_cpumask_weight((cpumask_t *)cpumask) < cpus_needed) {
        scx_bpf_error("Not enough cpus available for new cgroup");
        ret = -ENOSPC;
        goto unlock;
    }

    struct bpf_cpumask *soft_pin = bpf_cpumask_create();
    if (soft_pin == NULL) {
        scx_bpf_error("Failed to allocate cpumask for new cgroup");
        ret = -ENOMEM;
        goto unlock;
    }

    bpf_printk("Allocated %d CPUs for cgroup %llu", cpus_needed, cgrp->kn->id);

    u32 key = 0;
    int i;
    bpf_for(i, 0, cpus_needed) {
        int i = bpf_cpumask_first((cpumask_t *)cpumask);
        bpf_cpumask_set_cpu(i, soft_pin);
        bpf_cpumask_clear_cpu(i, cpumask);

        struct cpu_ctx *ctx = bpf_map_lookup_percpu_elem(&cpu_ctx_array, &key, i);
        if (ctx != NULL) {
            ctx->assigned_cgroup = cgrp->kn->id;
        } else {
            scx_bpf_error("Failed to set assigned cgroup for CPU %d", i);
        }
    }
    struct bpf_cpumask *old = bpf_kptr_xchg(&state->mask, soft_pin);
    if (old) {
        bpf_cpumask_release(old);
    }

unlock:
    bpf_rcu_read_unlock();

done:
    return ret;
}

void BPF_STRUCT_OPS_SLEEPABLE(cgroup_fair_cgroup_exit, struct cgroup *cgrp) {
    struct cgroup_ctx *state = get_cgroup_ctx(cgrp);
    if (state != NULL) {
        scx_bpf_destroy_dsq(cgrp->kn->id);
        struct bpf_cpumask *soft_pinning = bpf_kptr_xchg(&state->mask, NULL);
        if (soft_pinning != NULL) {
            struct bpf_cpumask *unallocated_mask = lock_unallocated_cpus();
            if (unallocated_mask != NULL) {
                bpf_cpumask_or(unallocated_mask, (cpumask_t *)unallocated_mask,
                               (cpumask_t *)soft_pinning);
            }
            bpf_rcu_read_unlock();

            int i;
            bpf_for(i, 0, bpf_cpumask_weight((cpumask_t *)soft_pinning)) {
                u32 cpu = bpf_cpumask_first((cpumask_t *)soft_pinning);
                bpf_cpumask_clear_cpu(cpu, soft_pinning);

                u32 key = 0;
                struct cpu_ctx *ctx = bpf_map_lookup_percpu_elem(&cpu_ctx_array, &key, cpu);
                if (ctx != NULL) {
                    ctx->assigned_cgroup = 0;
                } else {
                    scx_bpf_error("Failed to clear assigned cgroup for CPU %d", cpu);
                }
            }
            bpf_cpumask_release(soft_pinning);
        }
    }
}

s32 BPF_STRUCT_OPS_SLEEPABLE(cgroup_fair_init) {
    s32 ret = scx_bpf_create_dsq(FALLBACK_DSQ, -1);
    if (ret) {
        scx_bpf_error("Failed to create fallback dispatch queue");
        return ret;
    }

    struct bpf_cpumask *new_mask = bpf_cpumask_create();
    struct bpf_cpumask *new_mask2 = bpf_cpumask_create();
    if (new_mask == NULL || new_mask2 == NULL) {
        scx_bpf_error("Failed to allocate cpumasks for managed CPUs");
        if (new_mask) bpf_cpumask_release(new_mask);
        if (new_mask2) bpf_cpumask_release(new_mask2);
        return -ENOMEM;
    }

    for (int i = 0; i < total_cpus; i++) {
        u32 key = 0;
        bool *is_enabled = bpf_map_lookup_percpu_elem(&enabled, &key, i);
        if (is_enabled != NULL && *is_enabled) {
            bpf_cpumask_set_cpu(i, new_mask);
        }
    }
    bpf_cpumask_copy(new_mask2, (cpumask_t *)new_mask);

    bpf_printk("Total CPUs enabled: %d", bpf_cpumask_weight((cpumask_t *)new_mask));

    int key = 0;
    struct cpumask_wrapper *valid = bpf_map_lookup_elem(&valid_cpus, &key);
    if (valid == NULL) {
        scx_bpf_error("Failed to set global cpumask for valid CPUs");
        bpf_cpumask_release(new_mask);
        bpf_cpumask_release(new_mask2);
        return -ENOENT;
    }
    struct bpf_cpumask *old_valid = bpf_kptr_xchg(&valid->mask, new_mask);
    if (old_valid) {
        bpf_cpumask_release(old_valid);
    }

    struct cpumask_wrapper *unallocated = bpf_map_lookup_elem(&unallocated_cpus, &key);
    if (unallocated == NULL) {
        scx_bpf_error("Failed to set global cpumask for unallocated CPUs");
        bpf_cpumask_release(new_mask2);
        return -ENOENT;
    }

    struct bpf_cpumask *old_unallocated = bpf_kptr_xchg(&unallocated->mask, new_mask2);
    if (old_unallocated) {
        bpf_cpumask_release(old_unallocated);
    }

    return 0;
}

void BPF_STRUCT_OPS(cgroup_fair_exit, struct scx_exit_info *ei) { UEI_RECORD(uei, ei); }

SEC(".struct_ops.link")
struct sched_ext_ops sched_ops = {.select_cpu = (void *)cgroup_fair_select_cpu,
                                  .enqueue = (void *)cgroup_fair_enqueue,
                                  .dispatch = (void *)cgroup_fair_dispatch,
                                  .running = (void *)cgroup_fair_running,
                                  .stopping = (void *)cgroup_fair_stopping,
                                  .init_task = (void *)cgroup_fair_init_task,
                                  .cgroup_init = (void *)cgroup_fair_cgroup_init,
                                  .cgroup_exit = (void *)cgroup_fair_cgroup_exit,
                                  .init = (void *)cgroup_fair_init,
                                  .exit = (void *)cgroup_fair_exit,
                                  .flags = SCX_OPS_SWITCH_PARTIAL,
                                  .name = "cgroup_fair"};
