#ifndef NUMAP_H
#define NUMAP_H
#include <inttypes.h>
#include <sys/types.h>
#include <perfmon/pfmlib_perf_event.h>
#include <signal.h>

#define MAX_NB_NUMA_NODES     64
#define MAX_NB_THREADS        24
#define MAX_NB_CPUS           32

#define ERROR_PERF_EVENT_OPEN  		              -3
#define ERROR_NUMAP_NOT_NUMA  			      -4
#define ERROR_NUMAP_ALREADY_STARTED	              -5
#define ERROR_NUMAP_STOP_BEFORE_START                 -6
#define ERROR_NUMAP_ARCH_NOT_SUPPORTED                -7
#define ERROR_NUMAP_READ_SAMPLING_ARCH_NOT_SUPPORTED  -9
#define ERROR_NUMAP_WRITE_SAMPLING_ARCH_NOT_SUPPORTED -10
#define ERROR_PFM                                     -11
#define ERROR_READ                                    -12
#define ERROR_NUMAP_NO_SAMPLING_PMU                   -13

/* Memory access sampling backend. */
enum numap_backend {
  NUMAP_BACKEND_PEBS, /* Intel: libpfm4 event, records read from the perf ring */
  NUMAP_BACKEND_IBS,  /* AMD: ibs_op PMU, records converted by numap */
  NUMAP_BACKEND_SPE,  /* Arm: arm_spe PMU, AUX packets decoded by numap */
};

#if defined(__x86_64__) || defined(__i386__)
#define rmb()		asm volatile("lfence" ::: "memory")
#elif defined(__aarch64__)
#define rmb()		asm volatile("dmb ishld" ::: "memory")
#else
#define rmb()		__sync_synchronize()
#endif

/**
 * Structure representing a measurement of counting the load of controlers.
 */
struct numap_counting_measure {
  char started;
  int nb_nodes;
  int is_valid[MAX_NB_NUMA_NODES];
  long fd_reads[MAX_NB_NUMA_NODES];
  long fd_writes[MAX_NB_NUMA_NODES];
  long long reads_count[MAX_NB_NUMA_NODES];
  long long writes_count[MAX_NB_NUMA_NODES];
};

/**
 * Structure representing a measurement of memory read or write sampling.
 */
struct numap_sampling_measure {

  /*
   * Fields to be written and/or read by user code.
   */
  unsigned int nb_threads;
  unsigned int sampling_rate;
  unsigned int mmap_pages_count; // Must be power of two as specified in the man page of perf_event_open (mmap size should be 1+2^n pages)
  pid_t tids[MAX_NB_THREADS];
  struct perf_event_mmap_page *metadata_pages_per_tid[MAX_NB_THREADS];

  /*
   * Fields to be written and/or read by library code.
   */
  size_t page_size;
  size_t mmap_len;
  char started;
  long fd_per_tid[MAX_NB_THREADS];
  // overflow related fields
  void (*handler)(struct numap_sampling_measure*, int); // handler called each nb_refresh samples
  int total_samples; // after record, contains the total number of samples % nb_refresh
  int nb_refresh; // default value : 1000

  /*
   * IBS and SPE backends. The kernel buffers (perf ring, and AUX area for
   * SPE) are private; metadata_pages_per_tid then points to a ring that
   * numap fills with PERF_RECORD_SAMPLE records in the layout given by
   * sample_type, so that readers of metadata_pages_per_tid work unchanged.
   * One hardware event samples loads and stores: stores go to the partner
   * measure (the write measure started on the same thread).
   */
  int backend;
  uint64_t sample_type;
  struct perf_event_mmap_page *kernel_pages_per_tid[MAX_NB_THREADS];
  void *aux_per_tid[MAX_NB_THREADS];
  size_t aux_len;
  size_t ring_len;
  struct numap_sampling_measure *partner;
  char is_partner;
  uint64_t nb_samples;     // samples written to the ring
  uint64_t nb_dropped;     // samples dropped because the ring was full
  uint64_t nb_skipped;     // records that were neither loads nor stores
};

/**
 * Structure representing a read sample gathered with the library in
 * sampling mode.
 */
struct __attribute__ ((__packed__)) sample {
  uint64_t ip;
  uint64_t addr;
  uint64_t weight;
  union perf_mem_data_src data_src;
};

/**
 * Structure representing a mmap sample gathered with the library in
 * sampling mode.
 */
struct __attribute__ ((__packed__)) mmap_sample {
  uint32_t pid;
  uint32_t tid;
  uint64_t addr;
  uint64_t len;
  uint64_t pgoff;
  char filename[100];
};

char* concat(const char *s1, const char *s2);

/**
 * Numap initialization function
 */
int numap_init(void);
int numap_backend(void);
const char *numap_backend_name(void);

/**
 * Memory counting.
 */
int numap_counting_init_measure(struct numap_counting_measure *measure);
int numap_counting_start(struct numap_counting_measure *measure);
int numap_counting_stop(struct numap_counting_measure *measure);

/**
 * Memory read and write sampling.
 */
int numap_sampling_set_measure_handler(struct numap_sampling_measure *measure, void(*)(struct numap_sampling_measure*,int), int);
int numap_sampling_init_measure(struct numap_sampling_measure *measure, int nb_threads, int sampling_rate, int mmap_pages_count);
int numap_sampling_read_start_generic(struct numap_sampling_measure *measure, uint64_t sample_type);
int numap_sampling_read_start(struct numap_sampling_measure *measure);
int numap_sampling_read_stop(struct numap_sampling_measure *measure);
int numap_sampling_read_print(struct numap_sampling_measure *measure, char print_samples);
int numap_sampling_write_supported();
int numap_sampling_write_start_generic(struct numap_sampling_measure *measure, uint64_t sample_type);
int numap_sampling_write_start(struct numap_sampling_measure *measure);
int numap_sampling_write_stop(struct numap_sampling_measure *measure);
int numap_sampling_write_print(struct numap_sampling_measure *measure, char print_samples);
int numap_sampling_print(struct numap_sampling_measure *measure, char print_samples);
int numap_sampling_end(struct numap_sampling_measure *measure);
int numap_sampling_resume(struct numap_sampling_measure *measure);

/**
 * Error handling.
 */
const char *numap_error_message(int error);

/**
 * Functions to analyse results
 */
int is_served_by_local_cache1(union perf_mem_data_src data_src);
int is_served_by_local_cache2(union perf_mem_data_src data_src);
int is_served_by_local_cache3(union perf_mem_data_src data_src);
int is_served_by_local_lfb(union perf_mem_data_src data_src);
int is_served_by_local_cache(union perf_mem_data_src data_src);
int is_served_by_local_memory(union perf_mem_data_src data_src);
int is_served_by_remote_cache_or_local_memory(union perf_mem_data_src data_src);
int is_served_by_remote_memory(union perf_mem_data_src data_src);
int is_served_by_local_NA_miss(union perf_mem_data_src data_src);
char *get_data_src_opcode(union perf_mem_data_src data_src);
char *get_data_src_level(union perf_mem_data_src data_src);
#endif
