#include "store.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

int gw_admin_make(struct gw_admin *admin, const char *user, const char *password) {
    if (!user || !*user || strlen(user) > 256 || !password || !*password || strlen(password) > 1024)
        return -1;
    for (const unsigned char *p = (const unsigned char *)user; *p; ++p)
        if (*p < 32 || *p == 127) return -1;
    memset(admin, 0, sizeof(*admin));
    strcpy(admin->user, user);
    admin->iterations = 600000;
    unsigned char secret[32];
    if (RAND_bytes(admin->salt, sizeof(admin->salt)) != 1 || RAND_bytes(secret, sizeof(secret)) != 1 ||
        PKCS5_PBKDF2_HMAC(password, (int)strlen(password), admin->salt, sizeof(admin->salt),
            (int)admin->iterations, EVP_sha256(), sizeof(admin->hash), admin->hash) != 1)
        return -1;
    for (size_t i = 0; i < sizeof(secret); ++i) snprintf(admin->secret + 2*i, 3, "%02x", secret[i]);
    OPENSSL_cleanse(secret, sizeof(secret));
    return 0;
}
int gw_admin_verify(const struct gw_admin *admin, const char *password) {
    if (!password || strlen(password) > 1024 || admin->iterations < 100000 || admin->iterations > 10000000)
        return 0;
    unsigned char hash[32];
    int ok = PKCS5_PBKDF2_HMAC(password, (int)strlen(password), admin->salt, sizeof(admin->salt),
        (int)admin->iterations, EVP_sha256(), sizeof(hash), hash) == 1 &&
        !CRYPTO_memcmp(hash, admin->hash, sizeof(hash));
    OPENSSL_cleanse(hash, sizeof(hash));
    return ok;
}
int gw_store_admin_read(sqlite3 *db, struct gw_admin *admin) {
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, "SELECT username,salt,password_hash,iterations,jwt_secret FROM admin WHERE id=1", -1, &s, NULL) != SQLITE_OK)
        return -1;
    int result = sqlite3_step(s), status = -1;
    if (result == SQLITE_DONE) status = 1;
    else if (result == SQLITE_ROW && sqlite3_column_bytes(s, 0) > 0 && sqlite3_column_bytes(s, 0) <= 256 &&
        sqlite3_column_bytes(s, 1) == 16 && sqlite3_column_bytes(s, 2) == 32 &&
        sqlite3_column_int(s, 3) >= 100000 && sqlite3_column_int(s, 3) <= 10000000 && sqlite3_column_bytes(s, 4) == 64) {
        memset(admin, 0, sizeof(*admin));
        memcpy(admin->user, sqlite3_column_text(s, 0), (size_t)sqlite3_column_bytes(s, 0));
        memcpy(admin->salt, sqlite3_column_blob(s, 1), 16);
        memcpy(admin->hash, sqlite3_column_blob(s, 2), 32);
        admin->iterations = (unsigned)sqlite3_column_int(s, 3);
        memcpy(admin->secret, sqlite3_column_text(s, 4), 64);
        status = 0;
    }
    sqlite3_finalize(s);
    return status;
}
int gw_store_admin_write(sqlite3 *db, const struct gw_admin *admin) {
    sqlite3_stmt *s = NULL;
    int ok = sqlite3_prepare_v2(db, "INSERT INTO admin(id,username,salt,password_hash,iterations,jwt_secret) VALUES(1,?,?,?,?,?) "
        "ON CONFLICT(id) DO UPDATE SET username=excluded.username,salt=excluded.salt,password_hash=excluded.password_hash,iterations=excluded.iterations,jwt_secret=excluded.jwt_secret", -1, &s, NULL) == SQLITE_OK;
    if (ok) {
        sqlite3_bind_text(s, 1, admin->user, -1, SQLITE_TRANSIENT);
        sqlite3_bind_blob(s, 2, admin->salt, sizeof(admin->salt), SQLITE_TRANSIENT);
        sqlite3_bind_blob(s, 3, admin->hash, sizeof(admin->hash), SQLITE_TRANSIENT);
        sqlite3_bind_int(s, 4, (int)admin->iterations);
        sqlite3_bind_text(s, 5, admin->secret, -1, SQLITE_TRANSIENT);
        ok = sqlite3_step(s) == SQLITE_DONE;
    }
    sqlite3_finalize(s);
    return ok ? 0 : -1;
}
