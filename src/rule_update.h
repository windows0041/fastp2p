#ifndef FASTP2P_RULE_UPDATE_H
#define FASTP2P_RULE_UPDATE_H
#include "fastp2p.h"

/* Private host integration. The Android JNI adapter is a separate library. */
#if defined(__ANDROID__)
#define FP_RULE_API __attribute__((visibility("default")))
#else
#define FP_RULE_API
#endif

typedef struct fp_rule_update fp_rule_update;
/* On the owning thread, prepare reserves all new listeners without changing the
 * running rules. Finish with commit after saving the configuration, or abort.
 * Do not call step, stop or destroy on the client before finishing. */
FP_RULE_API int fp_client_rules_prepare(fastp2p_client *client, const char *json, fp_rule_update **out);
FP_RULE_API void fp_client_rules_commit(fp_rule_update *update);
FP_RULE_API void fp_client_rules_abort(fp_rule_update *update);
#undef FP_RULE_API
#endif
