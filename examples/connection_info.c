/* Echo the connection's transport state (TLS / ALPN / ECH / JA4 / client cert)
 * as a JSON body. Useful as a debug endpoint to confirm TLS posture from a
 * client. */
#include <zeroserve.h>

ZS_ENTRY
zs_u64 entry(void) {
  char path[64];
  zs_req_path(path, sizeof(path));
  if (zs_strcmp(path, "/conn") != 0) {
    return 0;
  }
  zs_s64 info = zs_connection_info();
  if (info < 0) {
    zs_respond(500, ZS_STR("{\"error\":\"zs_connection_info failed\"}"));
    return 0;
  }
  zs_json_respond(200, (zs_u64)info);
  zs_object_free((zs_u64)info);
  return 0;
}
