#ifndef FASTP2P_CONFIG_MERGE_H
#define FASTP2P_CONFIG_MERGE_H
#include <json-c/json.h>
/* Objects merge recursively; supplied arrays/scalars/null replace that field.
 * Missing fields survive. Neither input is modified; caller owns *output. */
int fp_config_merge(json_object *base, json_object *fields, json_object **output);
#endif
