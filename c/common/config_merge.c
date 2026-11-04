#include "config_merge.h"
static int bounded(json_object *value, unsigned depth) {
    if (depth > 16) return 0;
    if (json_object_is_type(value,json_type_object)) {
        json_object_object_foreach(value,key,child) {
            (void)key; if (!bounded(child,depth+1)) return 0;
        }
    } else if (json_object_is_type(value,json_type_array)) {
        for(size_t i=0;i<json_object_array_length(value);++i)
            if(!bounded(json_object_array_get_idx(value,i),depth+1))return 0;
    }
    return 1;
}
static int merge(json_object *base,json_object *fields) {
    json_object_object_foreach(fields,key,value) {
        json_object *old=NULL,*copy=NULL;
        json_object_object_get_ex(base,key,&old);
        if(json_object_is_type(value,json_type_object)) {
            if(!json_object_is_type(old,json_type_object)) {
                old=json_object_new_object(); if(!old)return -1;
                if(json_object_object_add(base,key,old)) { json_object_put(old);return -1; }
            }
            if(merge(old,value))return -1;
        } else {
            if(value && json_object_deep_copy(value,&copy,NULL))return -1;
            if(json_object_object_add(base,key,copy)) { if(copy)json_object_put(copy);return -1; }
        }
    }
    return 0;
}
int fp_config_merge(json_object *base,json_object *fields,json_object **output) {
    *output=NULL;
    if(!json_object_is_type(base,json_type_object) || !json_object_is_type(fields,json_type_object) ||
       !bounded(base,0) || !bounded(fields,0))return -1;
    json_object *copy=NULL;
    if(json_object_deep_copy(base,&copy,NULL))return -1;
    if(merge(copy,fields)) {json_object_put(copy);return -1;}
    *output=copy;return 0;
}
