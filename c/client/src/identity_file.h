#ifndef FASTP2P_IDENTITY_FILE_H
#define FASTP2P_IDENTITY_FILE_H
#include "fastp2p.h"
int op_cli_identity(fastp2p_client *client, const char *file, const char *config,
                     const char *host, unsigned port);
int fastp2p_private_parents(const char *path);
#endif
