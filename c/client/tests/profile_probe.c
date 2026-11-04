/* Test-only DPAPI inspection; never installed or included in a client release. */
#include "install.h"
#include <stdio.h>
int main(int argc,char **argv) {
    if(argc!=2)return 2;
    json_object *root=fastp2p_profile_read(argv[1]);if(!root)return 1;
    puts(json_object_to_json_string_ext(root,JSON_C_TO_STRING_PLAIN));json_object_put(root);return 0;
}
