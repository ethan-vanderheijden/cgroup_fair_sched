#include "common.bpf.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

const volatile unsigned long long root_cgroup;  // can be 0 for no restriction
const volatile int total_cpus;

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

// access is not racy since it is only mutated on cgroup init/exit
struct {
    __uint(type, BPF_MAP_TYPE_CGRP_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, u32);
    __type(value, struct cpumask_wrapper);
} cgroup_pinning SEC(".maps");

// access to assigned_cgroup is racy, but that's OK
// if a process is placed in the wrong queue, it will get fixed on the next dispatch
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, u32);  // 0 indicates no assigned cgroup
    __uint(max_entries, 1);
} assigned_cgroup SEC(".maps");

// we can't read the `prev` task's cgroup inside dispatch()
// so we store whether it has local affinity ahead of time (in running())
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, u32);  // 0 indicates no assigned cgroup
    __uint(max_entries, 1);
} has_local_affinity SEC(".maps");

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

static u32 get_assigned_cgroup(void) {
    u32 key = 0;
    u32 *val = bpf_map_lookup_elem(&assigned_cgroup, &key);
    if (!val) {
        return -1;
    } else {
        return *val;
    }
}

static struct bpf_cpumask *get_cgroup_cpus(struct cgroup *cgrp) {
    struct cpumask_wrapper *state = bpf_cgrp_storage_get(&cgroup_pinning, cgrp, NULL, 0);
    if (state == NULL) {
        return NULL;
    }
    return state->mask;
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

static u32 *get_local_affinity() {
    u32 key = 0;
    u32 *val = bpf_map_lookup_elem(&has_local_affinity, &key);
    if (!val) {
        scx_bpf_error("Failed to get local affinity");
        return NULL;
    }
    return val;
}

static void stat_inc(u32 idx) {
    u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
    if (cnt_p) (*cnt_p)++;
}

s32 BPF_STRUCT_OPS(cgroup_fair_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags) {
    s32 cpu = -1;
    struct cgroup *cgrp = scx_bpf_task_cgroup(p);
    struct bpf_cpumask *cpus = get_cgroup_cpus(cgrp);
    if (cpus != NULL) {
        s32 idle_affinity = scx_bpf_pick_idle_cpu(&cpus->cpumask, 0);
        if (idle_affinity >= 0) {
            bpf_cgroup_release(cgrp);
            scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SLICE, 0);
            bpf_printk("Directly dispatching to idle CPU %d", idle_affinity);
            stat_inc(2);
            return idle_affinity;
        } else {
            cpu = scx_bpf_pick_any_cpu(&cpus->cpumask, 0);
        }
    }

    struct bpf_cpumask *valid_cpus = get_valid_cpus();
    if (valid_cpus != NULL) {
        s32 idle_foreign = scx_bpf_pick_idle_cpu(&valid_cpus->cpumask, 0);
        if (idle_foreign >= 0) {
            bpf_cgroup_release(cgrp);
            scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SLICE, 0);
            stat_inc(2);
            return idle_foreign;
        }

        if (cpu == -1) {
            cpu = scx_bpf_pick_any_cpu(&valid_cpus->cpumask, 0);
        }
    }

    bpf_cgroup_release(cgrp);
    return cpu;
}

void BPF_STRUCT_OPS(cgroup_fair_enqueue, struct task_struct *p, u64 enq_flags) {
    struct cgroup *cgrp = scx_bpf_task_cgroup(p);
    struct bpf_cpumask *cpus = get_cgroup_cpus(cgrp);
    if (cpus == NULL) {
        scx_bpf_dsq_insert(p, FALLBACK_DSQ, SLICE, enq_flags);
    } else {
        scx_bpf_dsq_insert(p, cgrp->kn->id, SLICE, enq_flags);
    }
    bpf_cgroup_release(cgrp);
}

void BPF_STRUCT_OPS(cgroup_fair_dispatch, s32 cpu, struct task_struct *prev) {
    if (!is_enabled()) {
        return;
    }

    u32 assigned_cgrp = get_assigned_cgroup();
    if (assigned_cgrp > 0) {
        if (scx_bpf_dsq_move_to_local(assigned_cgrp)) {
            // successfully switched out `prev` with a local-affinity process
            stat_inc(0);
            return;
        } else if (prev != NULL) {
            u32 *local_affinity = get_local_affinity();
            if (local_affinity != NULL && *local_affinity) {
                // `prev` is a local-affinity process, let it keep running
                stat_inc(1);
                return;
            }
        }
    }

    // prev cannot possibly be a local-affinity process, switch it with another foreign process
    scx_bpf_dsq_move_to_local(FALLBACK_DSQ);
}

void BPF_STRUCT_OPS(cgroup_fair_running, struct task_struct *p) {
    u32 *local_affinity = get_local_affinity();
    u32 assigned_cgrp = get_assigned_cgroup();
    if (local_affinity != NULL && assigned_cgrp > 0) {
        struct cgroup *cgrp = scx_bpf_task_cgroup(p);
        *local_affinity = cgrp->kn->id == assigned_cgrp;
    }

    // if (time_before(vtime_now, p->scx.dsq_vtime)) vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(cgroup_fair_stopping, struct task_struct *p, bool runnable) {
    // p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;
}

void BPF_STRUCT_OPS(cgroup_fair_enable, struct task_struct *p) {
    // p->scx.dsq_vtime = vtime_now;
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

    struct cpumask_wrapper *state =
        bpf_cgrp_storage_get(&cgroup_pinning, cgrp, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
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

    if (bpf_cpumask_weight(&cpumask->cpumask) < cpus_needed) {
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
        int i = bpf_cpumask_first(&cpumask->cpumask);
        bpf_cpumask_set_cpu(i, soft_pin);
        bpf_cpumask_clear_cpu(i, cpumask);

        u32 *assigned_cgrp = bpf_map_lookup_percpu_elem(&assigned_cgroup, &key, i);
        if (assigned_cgrp != NULL) {
            *assigned_cgrp = cgrp->kn->id;
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
    struct cpumask_wrapper *state = bpf_cgrp_storage_get(&cgroup_pinning, cgrp, NULL, 0);
    if (state != NULL) {
        scx_bpf_destroy_dsq(cgrp->kn->id);
        struct bpf_cpumask *soft_pinning = bpf_kptr_xchg(&state->mask, NULL);
        if (soft_pinning != NULL) {
            struct bpf_cpumask *unallocated_mask = lock_unallocated_cpus();
            if (unallocated_mask != NULL) {
                bpf_cpumask_or(unallocated_mask, &unallocated_mask->cpumask,
                               &soft_pinning->cpumask);
            }
            bpf_rcu_read_unlock();

            int i;
            bpf_for(i, 0, bpf_cpumask_weight(&soft_pinning->cpumask)) {
                u32 cpu = bpf_cpumask_first(&soft_pinning->cpumask);
                bpf_cpumask_clear_cpu(cpu, soft_pinning);

                u32 key = 0;
                u32 *assigned_cgrp = bpf_map_lookup_percpu_elem(&assigned_cgroup, &key, cpu);
                if (assigned_cgrp != NULL) {
                    *assigned_cgrp = 0;
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
    bpf_cpumask_copy(new_mask2, &new_mask->cpumask);

    bpf_printk("Total CPUs enabled: %d", bpf_cpumask_weight(&new_mask->cpumask));

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
                                  .enable = (void *)cgroup_fair_enable,
                                  .cgroup_init = (void *)cgroup_fair_cgroup_init,
                                  .cgroup_exit = (void *)cgroup_fair_cgroup_exit,
                                  .init = (void *)cgroup_fair_init,
                                  .exit = (void *)cgroup_fair_exit,
                                  .flags = SCX_OPS_SWITCH_PARTIAL,
                                  .name = "cgroup_fair"};
