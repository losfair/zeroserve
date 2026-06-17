/*
 * acme.c — declare ACME-managed certificates.
 *
 * Exposes a single init hook, "acme_config", in the "zeroserve.init.acme_config"
 * code section. zeroserve runs it once at load time (when started with
 * --acme-dir) and reads back a JSON object describing which certificates to
 * obtain and renew automatically over ACME (TLS-ALPN-01).
 *
 * Returned object:
 *   {
 *     "domains": ["example.com", "www.example.com"],  // required
 *     "contact": "mailto:admin@example.com",          // optional
 *     "directory_url": "https://...",                 // optional (default: Let's Encrypt prod)
 *     "eab": { "kid": "...", "hmac_key": "..." }       // optional (External Account Binding)
 *   }
 *
 * The certificate storage location is NOT configurable here; it comes from the
 * --acme-dir command-line flag.
 */
#include <zeroserve.h>

ZS_INIT_ENTRY(acme_config) {
  zs_s64 cfg = zs_json_new_object();

  zs_s64 domains = zs_json_new_array();
  zs_s64 d1 = zs_json_new_object();
  zs_json_set_string(d1, ZS_STR("example.com"));
  zs_json_array_push(domains, d1);
  zs_object_free(d1);

  zs_s64 d2 = zs_json_new_object();
  zs_json_set_string(d2, ZS_STR("www.example.com"));
  zs_json_array_push(domains, d2);
  zs_object_free(d2);

  zs_json_set(cfg, ZS_STR("domains"), domains);
  zs_object_free(domains);

  zs_s64 contact = zs_json_new_object();
  zs_json_set_string(contact, ZS_STR("mailto:admin@example.com"));
  zs_json_set(cfg, ZS_STR("contact"), contact);
  zs_object_free(contact);

  return cfg;
}
