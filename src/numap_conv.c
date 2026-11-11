/*
 * Address sampling on AMD (IBS) and Arm (SPE).
 *
 * Both PMUs sample loads and stores with one hardware event. numap opens it
 * per thread, decodes its records and writes PERF_RECORD_SAMPLE records,
 * in the layout requested by the caller, into a private ring that has the
 * same header as a perf ring. Loads go to the measure that opened the event,
 * stores to its partner (the write measure of the same thread).
 *
 * IBS: records come from the perf ring (PERF_SAMPLE_RAW holds the IBS
 *      registers). The kernel only accepts ibs_op events that include the
 *      kernel, so perf_event_paranoid must be <= 1 (or CAP_PERFMON).
 * SPE: records come from the AUX area as SPE packets. Works per thread
 *      without privilege when perf_event_paranoid <= 2.
 */
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>

#include "numap.h"
#include "numap_conv.h"

#define PMU_DIR "/sys/bus/event_source/devices/"

/* One decoded memory access. */
struct conv_sample {
  uint64_t ip, addr, time, weight, cpu;
  uint32_t pid, tid;
  union perf_mem_data_src data_src;
  int is_store;
};

static long sys_perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu) {
  return syscall(SYS_perf_event_open, attr, pid, cpu, -1, 0);
}

int conv_pmu_type(const char *pmu) {
  char path[256];
  snprintf(path, sizeof(path), PMU_DIR "%s/type", pmu);
  FILE *f = fopen(path, "r");
  if (!f)
    return -1;
  int type = -1;
  if (fscanf(f, "%d", &type) != 1)
    type = -1;
  fclose(f);
  return type;
}

static const char *spe_pmu_name(void) {
  static char name[64];
  if (name[0])
    return name;
  for (int i = 0; i < 4; i++) {
    snprintf(name, sizeof(name), "arm_spe_%d", i);
    if (conv_pmu_type(name) >= 0)
      return name;
  }
  name[0] = 0;
  return NULL;
}

/* Set a named field of a PMU (sysfs format "config:33" or "config2:0-11"). */
static int set_format(struct perf_event_attr *attr, const char *pmu, const char *field, uint64_t value) {
  char path[256], spec[64];
  snprintf(path, sizeof(path), PMU_DIR "%s/format/%s", pmu, field);
  FILE *f = fopen(path, "r");
  if (!f)
    return -1;
  int ok = fscanf(f, "%63s", spec) == 1;
  fclose(f);
  if (!ok)
    return -1;
  char *colon = strchr(spec, ':');
  if (!colon)
    return -1;
  *colon = 0;
  int lo = 0, hi = 0;
  if (sscanf(colon + 1, "%d-%d", &lo, &hi) != 2)
    hi = lo;
  uint64_t mask = (hi - lo == 63) ? ~0ULL : ((1ULL << (hi - lo + 1)) - 1);
  uint64_t bits = (value & mask) << lo;
  if (!strcmp(spec, "config"))
    attr->config |= bits;
  else if (!strcmp(spec, "config1"))
    attr->config1 |= bits;
  else if (!strcmp(spec, "config2"))
    attr->config2 |= bits;
  else
    return -1;
  return 0;
}

int conv_detect_backend(int is_amd) {
  const char *forced = getenv("NUMAP_BACKEND");
  if (forced) {
    if (!strcasecmp(forced, "ibs")) return NUMAP_BACKEND_IBS;
    if (!strcasecmp(forced, "spe")) return NUMAP_BACKEND_SPE;
    if (!strcasecmp(forced, "pebs")) return NUMAP_BACKEND_PEBS;
  }
  if (spe_pmu_name())
    return NUMAP_BACKEND_SPE;
  if (is_amd && conv_pmu_type("ibs_op") >= 0)
    return NUMAP_BACKEND_IBS;
  return NUMAP_BACKEND_PEBS;
}

/* ---- Private ring --------------------------------------------------- */

static size_t pow2_at_least(size_t x) {
  size_t p = 1;
  while (p < x)
    p <<= 1;
  return p;
}

static struct perf_event_mmap_page *ring_alloc(struct numap_sampling_measure *m) {
  void *p = mmap(NULL, m->page_size + m->ring_len, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED)
    return NULL;
  struct perf_event_mmap_page *h = p;
  h->data_offset = m->page_size;
  h->data_size = m->ring_len;
  h->data_head = 0;
  h->data_tail = 0;
  return h;
}

static size_t sample_size(uint64_t type) {
  size_t s = sizeof(struct perf_event_header);
  if (type & PERF_SAMPLE_IP) s += 8;
  if (type & PERF_SAMPLE_TID) s += 8;
  if (type & PERF_SAMPLE_TIME) s += 8;
  if (type & PERF_SAMPLE_ADDR) s += 8;
  if (type & PERF_SAMPLE_CPU) s += 8;
  if (type & PERF_SAMPLE_PERIOD) s += 8;
  if (type & PERF_SAMPLE_WEIGHT) s += 8;
  if (type & PERF_SAMPLE_DATA_SRC) s += 8;
  return s;
}

/* Append one record in perf ABI order. Readers may store data_tail either
 * as a running offset or modulo data_size, so only the low bits are used. */
static void ring_push(struct numap_sampling_measure *m, int t, const struct conv_sample *s) {
  struct perf_event_mmap_page *h = m->metadata_pages_per_tid[t];
  if (!h)
    return;
  uint64_t type = m->sample_type;
  uint8_t rec[128];
  size_t n = sample_size(type);
  struct perf_event_header *hdr = (struct perf_event_header *)rec;
  hdr->type = PERF_RECORD_SAMPLE;
  hdr->misc = PERF_RECORD_MISC_USER;
  hdr->size = n;
  uint64_t *p = (uint64_t *)(hdr + 1);
  if (type & PERF_SAMPLE_IP) *p++ = s->ip;
  if (type & PERF_SAMPLE_TID) *p++ = ((uint64_t)s->tid << 32) | s->pid;
  if (type & PERF_SAMPLE_TIME) *p++ = s->time;
  if (type & PERF_SAMPLE_ADDR) *p++ = s->addr;
  if (type & PERF_SAMPLE_CPU) *p++ = s->cpu;
  if (type & PERF_SAMPLE_PERIOD) *p++ = m->sampling_rate;
  if (type & PERF_SAMPLE_WEIGHT) *p++ = s->weight;
  if (type & PERF_SAMPLE_DATA_SRC) *p++ = s->data_src.val;

  uint64_t size = h->data_size, mask = size - 1;
  uint64_t head = h->data_head, tail = h->data_tail;
  uint64_t used = (head - tail) & mask;
  if (used + n >= size) {
    m->nb_dropped++;
    return;
  }
  uint8_t *data = (uint8_t *)h + h->data_offset;
  uint64_t off = head & mask;
  size_t first = n < size - off ? n : size - off;
  memcpy(data + off, rec, first);
  memcpy(data, rec + first, n - first);
  __sync_synchronize();
  h->data_head = head + n;
  m->nb_samples++;
}

/* is_partner: 0 read measure (owns the event), 1 write measure sharing the
 * event of the read measure, 2 write measure with its own event. */
static void route(struct numap_sampling_measure *m, int t, const struct conv_sample *s) {
  if (m->is_partner == 2) {
    if (s->is_store)
      ring_push(m, t, s);
  } else if (!s->is_store) {
    ring_push(m, t, s);
  } else if (m->partner && t < (int)m->partner->nb_threads) {
    ring_push(m->partner, t, s);
  }
}

/* ---- Clock: SPE timestamps to CLOCK_MONOTONIC_RAW ------------------- */

static uint64_t now_ns(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC_RAW, &t);
  return (uint64_t)t.tv_sec * 1000000000ULL + t.tv_nsec;
}

#if defined(__aarch64__)
static uint64_t counter_ticks(void) {
  uint64_t v;
  asm volatile("isb; mrs %0, cntvct_el0" : "=r"(v) :: "memory");
  return v;
}
static uint64_t counter_freq(void) {
  uint64_t v;
  asm volatile("mrs %0, cntfrq_el0" : "=r"(v));
  return v;
}
#else
static uint64_t counter_ticks(void) { return 0; }
static uint64_t counter_freq(void) { return 0; }
#endif

/* ---- SPE ------------------------------------------------------------ */

/* Data source encodings of Neoverse cores (Arm SPE common data source). */
static union perf_mem_data_src spe_data_src(int has_ds, uint64_t ds, uint64_t events, int is_store) {
  union perf_mem_data_src d;
  d.val = 0;
  d.mem_op = is_store ? PERF_MEM_OP_STORE : PERF_MEM_OP_LOAD;
  if (!has_ds) {
    /* Stores carry no data source: fall back on the L1D refill event. */
    d.mem_lvl = PERF_MEM_LVL_L1 | ((events & (1 << 3)) ? PERF_MEM_LVL_MISS : PERF_MEM_LVL_HIT);
    return d;
  }
  switch (ds) {
  case 0x0: d.mem_lvl = PERF_MEM_LVL_L1 | PERF_MEM_LVL_HIT; break;
  case 0x8: d.mem_lvl = PERF_MEM_LVL_L2 | PERF_MEM_LVL_HIT; break;
  case 0x9:                                                  /* peer core */
  case 0xa:                                                  /* local cluster */
  case 0xb: d.mem_lvl = PERF_MEM_LVL_L3 | PERF_MEM_LVL_HIT; break; /* system cache */
  case 0xc: d.mem_lvl = PERF_MEM_LVL_REM_CCE1 | PERF_MEM_LVL_HIT; break; /* peer cluster */
  case 0xd: d.mem_lvl = PERF_MEM_LVL_REM_RAM1 | PERF_MEM_LVL_HIT; break; /* remote */
  case 0xe: d.mem_lvl = PERF_MEM_LVL_LOC_RAM | PERF_MEM_LVL_HIT; break;  /* DRAM */
  default:  d.mem_lvl = PERF_MEM_LVL_NA; break;
  }
  return d;
}

static uint64_t sign_extend56(uint64_t v) {
  v &= 0x00FFFFFFFFFFFFFFULL;
  if (v & (1ULL << 55))
    v |= 0xFF00000000000000ULL;
  return v;
}

static void spe_decode(struct numap_sampling_measure *m, int t, const uint8_t *buf, uint64_t from,
                       uint64_t to, uint64_t size, pid_t tid) {
  uint64_t mask = size - 1;
  uint64_t t_ns = now_ns(), t_ticks = counter_ticks(), freq = counter_freq();
#define BYTE(i) buf[(i) & mask]
  struct conv_sample s;
  int has_addr = 0, is_ldst = 0, has_ds = 0;
  uint64_t ds = 0, events = 0, ts = 0;
  memset(&s, 0, sizeof(s));

  uint64_t i = from;
  while (i < to) {
    unsigned h = BYTE(i++);
    if (h == 0x00) /* padding */
      continue;
    int emit = 0;
    if (h == 0x01) { /* end */
      emit = 1;
    } else {
      unsigned ext = 0;
      if ((h & 0xFC) == 0x20) {
        ext = h & 3;
        if (i >= to)
          break;
        h = BYTE(i++);
      }
      unsigned len = 1u << ((h >> 4) & 3);
      if (i + len > to)
        break;
      uint64_t v = 0;
      for (unsigned k = 0; k < len; k++)
        v |= (uint64_t)BYTE(i + k) << (8 * k);
      i += len;
      if (h == 0x71) { /* timestamp, closes the record */
        ts = v;
        emit = 1;
      } else if ((h & 0xF8) == 0xB0) { /* address */
        unsigned idx = (h & 7) | (ext << 3);
        if (idx == 0)
          s.ip = sign_extend56(v);
        else if (idx == 2) {
          s.addr = sign_extend56(v);
          has_addr = 1;
        }
      } else if ((h & 0xF8) == 0x98) { /* counter */
        unsigned idx = (h & 7) | (ext << 3);
        if (idx == 0)
          s.weight = v; /* total latency, cycles */
      } else if ((h & 0xFC) == 0x48) { /* operation type */
        if ((h & 3) == 1) {
          is_ldst = 1;
          s.is_store = v & 1;
        }
      } else if ((h & 0xCF) == 0x42) { /* events */
        events = v;
      } else if ((h & 0xCF) == 0x43) { /* data source */
        ds = v;
        has_ds = 1;
      }
    }
    if (emit) {
      if (is_ldst && has_addr) {
        s.data_src = spe_data_src(has_ds, ds, events, s.is_store);
        if (ts && freq && t_ticks >= ts)
          s.time = t_ns - (uint64_t)((double)(t_ticks - ts) * 1e9 / (double)freq);
        else
          s.time = t_ns;
        s.pid = getpid();
        s.tid = tid;
        route(m, t, &s);
      } else {
        m->nb_skipped++;
      }
      memset(&s, 0, sizeof(s));
      has_addr = is_ldst = has_ds = 0;
      ds = events = ts = 0;
    }
  }
#undef BYTE
}

static void spe_drain(struct numap_sampling_measure *m, int thread) {
  struct perf_event_mmap_page *k = m->kernel_pages_per_tid[thread];
  if (!k || !m->aux_per_tid[thread])
    return;
  uint64_t head = __atomic_load_n(&k->aux_head, __ATOMIC_ACQUIRE);
  uint64_t tail = k->aux_tail;
  if (head - tail > m->aux_len) /* overwritten data: keep the newest */
    tail = head - m->aux_len;
  spe_decode(m, thread, m->aux_per_tid[thread], tail, head, m->aux_len, m->tids[thread]);
  __atomic_store_n(&k->aux_tail, head, __ATOMIC_RELEASE);
  /* The data ring only holds AUX and LOST records: drop them. */
  uint64_t dhead = __atomic_load_n(&k->data_head, __ATOMIC_ACQUIRE);
  __atomic_store_n(&k->data_tail, dhead, __ATOMIC_RELEASE);
}

/* ---- IBS ------------------------------------------------------------ */

#define IBS_LD_OP         (1ULL << 0)
#define IBS_ST_OP         (1ULL << 1)
#define IBS_DC_MISS       (1ULL << 7)
#define IBS_LIN_ADDR_OK   (1ULL << 17)
#define IBS_KERNEL_TYPE   (PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_ADDR | \
                           PERF_SAMPLE_CPU | PERF_SAMPLE_RAW | PERF_SAMPLE_WEIGHT | PERF_SAMPLE_DATA_SRC)

static union perf_mem_data_src ibs_data_src(uint64_t data2, uint64_t data3, int is_store) {
  union perf_mem_data_src d;
  d.val = 0;
  d.mem_op = is_store ? PERF_MEM_OP_STORE : PERF_MEM_OP_LOAD;
  if (!(data3 & IBS_DC_MISS)) {
    d.mem_lvl = PERF_MEM_LVL_L1 | PERF_MEM_LVL_HIT;
    return d;
  }
  unsigned src = (data2 & 7) | (((data2 >> 6) & 3) << 3);
  int remote = (data2 >> 4) & 1;
  switch (src) {
  case 1: d.mem_lvl = PERF_MEM_LVL_L3 | PERF_MEM_LVL_HIT; break;      /* local CCX cache */
  case 2: d.mem_lvl = PERF_MEM_LVL_REM_CCE1 | PERF_MEM_LVL_HIT; break; /* other CCX cache */
  case 3: d.mem_lvl = (remote ? PERF_MEM_LVL_REM_RAM1 : PERF_MEM_LVL_LOC_RAM) | PERF_MEM_LVL_HIT; break;
  default: d.mem_lvl = PERF_MEM_LVL_NA; break;
  }
  return d;
}

static void ibs_drain(struct numap_sampling_measure *m, int thread) {
  struct perf_event_mmap_page *k = m->kernel_pages_per_tid[thread];
  if (!k)
    return;
  uint64_t size = k->data_size, mask = size - 1;
  uint8_t *data = (uint8_t *)k + k->data_offset;
  uint64_t head = __atomic_load_n(&k->data_head, __ATOMIC_ACQUIRE);
  uint64_t tail = k->data_tail;
  uint8_t rec[512];

  while (tail < head) {
    struct perf_event_header hdr;
    for (unsigned b = 0; b < sizeof(hdr); b++)
      ((uint8_t *)&hdr)[b] = data[(tail + b) & mask];
    if (hdr.size == 0)
      break;
    if (hdr.type == PERF_RECORD_SAMPLE && hdr.size <= sizeof(rec)) {
      for (unsigned b = 0; b < hdr.size; b++)
        rec[b] = data[(tail + b) & mask];
      const uint8_t *p = rec + sizeof(hdr);
      struct conv_sample s;
      memset(&s, 0, sizeof(s));
      uint64_t v;
      memcpy(&s.ip, p, 8); p += 8;
      memcpy(&v, p, 8); p += 8; s.pid = v & 0xffffffff; s.tid = v >> 32;
      memcpy(&s.time, p, 8); p += 8;
      memcpy(&s.addr, p, 8); p += 8;
      memcpy(&v, p, 8); p += 8; s.cpu = v & 0xffffffff;
      uint32_t raw_size;
      memcpy(&raw_size, p, 4);
      const uint8_t *raw = p + 4;
      p += 4 + raw_size;
      memcpy(&s.weight, p, 8); p += 8;
      memcpy(&s.data_src.val, p, 8);

      /* raw = u32 caps, then IbsOpCtl, IbsOpRip, IbsOpData, IbsOpData2,
       * IbsOpData3, IbsDcLinAd, IbsDcPhysAd, ... */
      uint64_t regs[7] = {0};
      unsigned nregs = raw_size >= 4 ? (raw_size - 4) / 8 : 0;
      if (nregs > 7)
        nregs = 7;
      memcpy(regs, raw + 4, nregs * 8);
      uint64_t data3 = regs[4];
      if (nregs >= 5 && (data3 & (IBS_LD_OP | IBS_ST_OP))) {
        s.is_store = (data3 & IBS_ST_OP) != 0;
        if (!s.addr && nregs >= 6 && (data3 & IBS_LIN_ADDR_OK))
          s.addr = regs[5];
        if (!s.weight && !s.is_store)
          s.weight = (data3 >> 32) & 0xffff; /* DC miss latency */
        if (!s.data_src.mem_lvl)
          s.data_src = ibs_data_src(regs[3], data3, s.is_store);
        if (s.addr)
          route(m, thread, &s);
        else
          m->nb_skipped++;
      } else {
        m->nb_skipped++;
      }
    }
    tail += hdr.size;
  }
  __atomic_store_n(&k->data_tail, tail, __ATOMIC_RELEASE);
}

/* ---- Measure life cycle --------------------------------------------- */

static __thread struct numap_sampling_measure *thread_primary = NULL;

static int open_event(struct numap_sampling_measure *m, int stores_only) {
  m->nb_samples = m->nb_dropped = m->nb_skipped = 0;
  m->ring_len = pow2_at_least(m->mmap_pages_count * m->page_size);

  struct perf_event_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.size = sizeof(attr);
  attr.disabled = 1;
  const char *pmu;

  if (m->backend == NUMAP_BACKEND_SPE) {
    pmu = spe_pmu_name();
    set_format(&attr, pmu, "ts_enable", 1);
    set_format(&attr, pmu, "jitter", 1);
    if (!stores_only)
      set_format(&attr, pmu, "load_filter", 1);
    set_format(&attr, pmu, "store_filter", 1);
    attr.sample_period = m->sampling_rate;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    const char *kb = getenv("NUMAP_AUX_KB");
    size_t aux = (kb ? strtoul(kb, NULL, 10) : 4096) * 1024;
    m->aux_len = pow2_at_least(aux < m->page_size ? m->page_size : aux);
  } else {
    pmu = "ibs_op";
    /* IBS periods are multiples of 16 */
    attr.sample_period = (m->sampling_rate + 15) & ~15ULL;
    if (attr.sample_period < 16)
      attr.sample_period = 16;
    attr.sample_type = IBS_KERNEL_TYPE;
    attr.use_clockid = 1;
    attr.clockid = CLOCK_MONOTONIC_RAW;
    /* IBS cannot exclude the kernel (EINVAL otherwise). */
    attr.exclude_kernel = 0;
    m->aux_len = 0;
  }
  int type = pmu ? conv_pmu_type(pmu) : -1;
  if (type < 0)
    return ERROR_NUMAP_NO_SAMPLING_PMU;
  attr.type = type;

  for (unsigned t = 0; t < m->nb_threads; t++) {
    if (m->kernel_pages_per_tid[t])
      continue;
    m->fd_per_tid[t] = sys_perf_event_open(&attr, m->tids[t], -1);
    if (m->fd_per_tid[t] == -1)
      return ERROR_PERF_EVENT_OPEN;
    void *kp = mmap(NULL, m->mmap_len, PROT_READ | PROT_WRITE, MAP_SHARED, m->fd_per_tid[t], 0);
    if (kp == MAP_FAILED)
      return ERROR_PERF_EVENT_OPEN;
    m->kernel_pages_per_tid[t] = kp;
    if (m->aux_len) {
      m->kernel_pages_per_tid[t]->aux_offset = m->mmap_len;
      m->kernel_pages_per_tid[t]->aux_size = m->aux_len;
      void *aux = mmap(NULL, m->aux_len, PROT_READ | PROT_WRITE, MAP_SHARED,
                       m->fd_per_tid[t], m->mmap_len);
      if (aux == MAP_FAILED)
        return ERROR_PERF_EVENT_OPEN;
      m->aux_per_tid[t] = aux;
    }
    m->metadata_pages_per_tid[t] = ring_alloc(m);
    if (!m->metadata_pages_per_tid[t])
      return ERROR_PERF_EVENT_OPEN;
  }
  return 0;
}

int conv_sampling_start(struct numap_sampling_measure *m, uint64_t sample_type) {
  m->sample_type = sample_type;
  m->partner = NULL;
  m->is_partner = 0;
  int err = open_event(m, 0);
  if (!err)
    thread_primary = m;
  return err;
}

/* A write measure shares the event of the read measure started on the same
 * thread (one SPE or IBS unit per core). Without one, it opens its own. */
int conv_sampling_start_partner(struct numap_sampling_measure *m, uint64_t sample_type) {
  m->sample_type = sample_type;
  m->partner = NULL;
  struct numap_sampling_measure *p = thread_primary;
  if (!p || !p->started || p->partner || p->nb_threads != m->nb_threads) {
    m->is_partner = 2;
    return open_event(m, 1);
  }
  m->is_partner = 1;
  m->nb_samples = m->nb_dropped = m->nb_skipped = 0;
  m->ring_len = pow2_at_least(m->mmap_pages_count * m->page_size);
  for (unsigned t = 0; t < m->nb_threads; t++) {
    if (!m->metadata_pages_per_tid[t])
      m->metadata_pages_per_tid[t] = ring_alloc(m);
    if (!m->metadata_pages_per_tid[t])
      return ERROR_PERF_EVENT_OPEN;
    m->fd_per_tid[t] = -1;
  }
  p->partner = m;
  return 0;
}

void conv_sampling_enable(struct numap_sampling_measure *m) {
  if (m->is_partner == 1)
    return;
  for (unsigned t = 0; t < m->nb_threads; t++)
    ioctl(m->fd_per_tid[t], PERF_EVENT_IOC_ENABLE, 0);
}

void conv_sampling_disable(struct numap_sampling_measure *m) {
  if (m->is_partner == 1)
    return;
  for (unsigned t = 0; t < m->nb_threads; t++) {
    ioctl(m->fd_per_tid[t], PERF_EVENT_IOC_DISABLE, 0);
    if (m->backend == NUMAP_BACKEND_SPE)
      spe_drain(m, t);
    else
      ibs_drain(m, t);
  }
}

void conv_sampling_end(struct numap_sampling_measure *m) {
  for (unsigned t = 0; t < m->nb_threads; t++) {
    if (m->metadata_pages_per_tid[t])
      munmap(m->metadata_pages_per_tid[t], m->page_size + m->ring_len);
    m->metadata_pages_per_tid[t] = NULL;
    if (m->is_partner == 1)
      continue;
    if (m->aux_per_tid[t])
      munmap(m->aux_per_tid[t], m->aux_len);
    if (m->kernel_pages_per_tid[t])
      munmap(m->kernel_pages_per_tid[t], m->mmap_len);
    m->aux_per_tid[t] = NULL;
    m->kernel_pages_per_tid[t] = NULL;
    close(m->fd_per_tid[t]);
  }
  if (thread_primary == m)
    thread_primary = NULL;
  else if (thread_primary && thread_primary->partner == m)
    thread_primary->partner = NULL;
  if (getenv("NUMAP_VERBOSE"))
    fprintf(stderr, "numap: %s measure: %llu samples, %llu dropped (ring full), %llu skipped\n",
            m->is_partner ? "write" : "read", (unsigned long long)m->nb_samples,
            (unsigned long long)m->nb_dropped, (unsigned long long)m->nb_skipped);
}
