#ifndef NUMAP_CONV_H
#define NUMAP_CONV_H
/* Internal: IBS (AMD) and SPE (Arm) sampling backends, see numap_conv.c. */
#include "numap.h"

int conv_pmu_type(const char *pmu);
int conv_detect_backend(int is_amd);
int conv_sampling_start(struct numap_sampling_measure *m, uint64_t sample_type);
int conv_sampling_start_partner(struct numap_sampling_measure *m, uint64_t sample_type);
void conv_sampling_enable(struct numap_sampling_measure *m);
void conv_sampling_disable(struct numap_sampling_measure *m);
void conv_sampling_end(struct numap_sampling_measure *m);
#endif
