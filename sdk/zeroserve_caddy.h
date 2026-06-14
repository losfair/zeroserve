#ifndef ZEROSERVE_SDK_ZEROSERVE_CADDY_H
#define ZEROSERVE_SDK_ZEROSERVE_CADDY_H

#include <zeroserve.h>

static ZS_INLINE ZS_MAYBE_UNUSED zs_u64 zs_caddy_clamp_len(zs_s64 len, zs_u64 cap) {
  if (len <= 0 || cap == 0)
    return 0;
  if ((zs_u64)len >= cap)
    return cap - 1;
  return (zs_u64)len;
}

static ZS_INLINE ZS_MAYBE_UNUSED char zs_caddy_lower(char c) {
  if (c >= 'A' && c <= 'Z')
    return (char)(c + 32);
  return c;
}

static ZS_INLINE ZS_MAYBE_UNUSED int zs_caddy_eq(const char *a, zs_u64 alen, const char *b,
                                 zs_u64 blen) {
  if (alen != blen)
    return 0;
  for (zs_u64 i = 0; i < alen; i++)
    if (a[i] != b[i])
      return 0;
  return 1;
}

static ZS_INLINE ZS_MAYBE_UNUSED int zs_caddy_eq_fold(const char *a, zs_u64 alen,
                                      const char *b, zs_u64 blen) {
  if (alen != blen)
    return 0;
  for (zs_u64 i = 0; i < alen; i++)
    if (zs_caddy_lower(a[i]) != zs_caddy_lower(b[i]))
      return 0;
  return 1;
}

static ZS_INLINE ZS_MAYBE_UNUSED int zs_caddy_prefix(const char *a, zs_u64 alen,
                                     const char *p, zs_u64 plen) {
  if (alen < plen)
    return 0;
  for (zs_u64 i = 0; i < plen; i++)
    if (a[i] != p[i])
      return 0;
  return 1;
}

static ZS_INLINE ZS_MAYBE_UNUSED int zs_caddy_suffix(const char *a, zs_u64 alen,
                                     const char *s, zs_u64 slen) {
  if (alen < slen)
    return 0;
  zs_u64 off = alen - slen;
  for (zs_u64 i = 0; i < slen; i++)
    if (a[off + i] != s[i])
      return 0;
  return 1;
}

static ZS_INLINE ZS_MAYBE_UNUSED int zs_caddy_contains(const char *a, zs_u64 alen,
                                       const char *n, zs_u64 nlen) {
  if (nlen == 0)
    return 1;
  if (alen < nlen)
    return 0;
  for (zs_u64 i = 0; i <= alen - nlen; i++) {
    int ok = 1;
    for (zs_u64 j = 0; j < nlen; j++)
      if (a[i + j] != n[j])
        ok = 0;
    if (ok)
      return 1;
  }
  return 0;
}

static ZS_INLINE ZS_MAYBE_UNUSED int zs_caddy_header_value_match(const char *actual,
                                                 zs_u64 actual_len,
                                                 const char *allowed,
                                                 zs_u64 allowed_len) {
  if (allowed_len == 1 && allowed[0] == '*')
    return 1;
  if (allowed_len >= 2 && allowed[0] == '*' && allowed[allowed_len - 1] == '*')
    return zs_caddy_contains(actual, actual_len, allowed + 1, allowed_len - 2);
  if (allowed_len >= 1 && allowed[0] == '*')
    return zs_caddy_suffix(actual, actual_len, allowed + 1, allowed_len - 1);
  if (allowed_len >= 1 && allowed[allowed_len - 1] == '*')
    return zs_caddy_prefix(actual, actual_len, allowed, allowed_len - 1);
  return zs_caddy_eq(actual, actual_len, allowed, allowed_len);
}

static ZS_INLINE ZS_MAYBE_UNUSED int zs_caddy_glob(const char *a, zs_u64 alen,
                                   const char *pat, zs_u64 plen) {
  zs_u64 star = plen;
  for (zs_u64 i = 0; i < plen; i++)
    if (pat[i] == '*') {
      star = i;
      break;
    }
  if (star == plen)
    return zs_caddy_eq_fold(a, alen, pat, plen);
  if (star == 0 && plen > 1 && pat[plen - 1] == '*')
    return zs_caddy_contains(a, alen, pat + 1, plen - 2);
  if (star == 0)
    return zs_caddy_suffix(a, alen, pat + 1, plen - 1);
  if (star == plen - 1)
    return zs_caddy_prefix(a, alen, pat, plen - 1);
  return zs_caddy_prefix(a, alen, pat, star) &&
         zs_caddy_suffix(a, alen, pat + star + 1, plen - star - 1);
}

static ZS_INLINE ZS_MAYBE_UNUSED int zs_caddy_prefix_fold(const char *a, zs_u64 alen,
                                          const char *p, zs_u64 plen);
static ZS_INLINE ZS_MAYBE_UNUSED int zs_caddy_suffix_fold(const char *a, zs_u64 alen,
                                          const char *s, zs_u64 slen);
static ZS_INLINE ZS_MAYBE_UNUSED int zs_caddy_contains_fold(const char *a, zs_u64 alen,
                                            const char *n, zs_u64 nlen);
static ZS_INLINE ZS_MAYBE_UNUSED int zs_caddy_path_token_match_fold(const char *a,
                                                    zs_u64 alen, zs_u64 *ai,
                                                    const char *pat,
                                                    zs_u64 plen, zs_u64 *pi);
static ZS_INLINE ZS_MAYBE_UNUSED int zs_caddy_path_class_match_fold(const char *pat,
                                                    zs_u64 plen, zs_u64 *pi,
                                                    char value);

static ZS_INLINE ZS_MAYBE_UNUSED int zs_caddy_glob_fold(const char *a, zs_u64 alen,
                                        const char *pat, zs_u64 plen) {
  if (plen == 1 && pat[0] == '*')
    return 1;

  zs_u64 star_count = 0;
  for (zs_u64 i = 0; i < plen; i++)
    if (pat[i] == '*')
      star_count++;

  if (star_count == 2 && plen >= 2 && pat[0] == '*' && pat[plen - 1] == '*')
    return zs_caddy_contains_fold(a, alen, pat + 1, plen - 2);
  if (star_count == 1 && plen >= 1 && pat[0] == '*')
    return zs_caddy_suffix_fold(a, alen, pat + 1, plen - 1);
  if (star_count == 1 && plen >= 1 && pat[plen - 1] == '*')
    return zs_caddy_prefix_fold(a, alen, pat, plen - 1);

  zs_u64 ai = 0;
  zs_u64 pi = 0;
  zs_u64 star = plen;
  zs_u64 match = 0;

  while (ai < alen) {
    if (pi < plen && pat[pi] == '*') {
      star = pi++;
      match = ai;
    } else if (zs_caddy_path_token_match_fold(a, alen, &ai, pat, plen, &pi)) {
      /* token matcher advances both cursors */
    } else if (star != plen && match < alen && a[match] != '/') {
      pi = star + 1;
      ai = ++match;
    } else {
      return 0;
    }
  }

  while (pi < plen && pat[pi] == '*')
    pi++;
  return pi == plen;
}

static ZS_INLINE ZS_MAYBE_UNUSED int zs_caddy_prefix_fold(const char *a, zs_u64 alen,
                                          const char *p, zs_u64 plen) {
  if (alen < plen)
    return 0;
  for (zs_u64 i = 0; i < plen; i++)
    if (zs_caddy_lower(a[i]) != zs_caddy_lower(p[i]))
      return 0;
  return 1;
}

static ZS_INLINE ZS_MAYBE_UNUSED int zs_caddy_suffix_fold(const char *a, zs_u64 alen,
                                          const char *s, zs_u64 slen) {
  if (alen < slen)
    return 0;
  zs_u64 off = alen - slen;
  for (zs_u64 i = 0; i < slen; i++)
    if (zs_caddy_lower(a[off + i]) != zs_caddy_lower(s[i]))
      return 0;
  return 1;
}

static ZS_INLINE ZS_MAYBE_UNUSED int zs_caddy_contains_fold(const char *a, zs_u64 alen,
                                            const char *n, zs_u64 nlen) {
  if (nlen == 0)
    return 1;
  if (alen < nlen)
    return 0;
  for (zs_u64 i = 0; i <= alen - nlen; i++) {
    int ok = 1;
    for (zs_u64 j = 0; j < nlen; j++)
      if (zs_caddy_lower(a[i + j]) != zs_caddy_lower(n[j]))
        ok = 0;
    if (ok)
      return 1;
  }
  return 0;
}

static ZS_INLINE ZS_MAYBE_UNUSED int zs_caddy_path_token_match_fold(const char *a,
                                                    zs_u64 alen, zs_u64 *ai,
                                                    const char *pat,
                                                    zs_u64 plen, zs_u64 *pi) {
  if (*ai >= alen || *pi >= plen)
    return 0;
  if (pat[*pi] == '?') {
    if (a[*ai] == '/')
      return 0;
    (*ai)++;
    (*pi)++;
    return 1;
  }
  if (pat[*pi] == '[') {
    zs_u64 next = *pi + 1;
    int matched = zs_caddy_path_class_match_fold(pat, plen, &next, a[*ai]);
    if (next == *pi + 1)
      return 0;
    if (!matched || a[*ai] == '/')
      return 0;
    (*ai)++;
    *pi = next;
    return 1;
  }
  if (pat[*pi] == '\\') {
    if (*pi + 1 >= plen)
      return 0;
    if (zs_caddy_lower(a[*ai]) != zs_caddy_lower(pat[*pi + 1]))
      return 0;
    (*ai)++;
    *pi += 2;
    return 1;
  }
  if (zs_caddy_lower(a[*ai]) == zs_caddy_lower(pat[*pi])) {
    (*ai)++;
    (*pi)++;
    return 1;
  }
  return 0;
}

static ZS_INLINE ZS_MAYBE_UNUSED char zs_caddy_class_byte(const char *pat, zs_u64 plen,
                                          zs_u64 *pi) {
  if (*pi >= plen)
    return 0;
  if (pat[*pi] == '\\' && *pi + 1 < plen) {
    char c = pat[*pi + 1];
    *pi += 2;
    return c;
  }
  return pat[(*pi)++];
}

static ZS_INLINE ZS_MAYBE_UNUSED int zs_caddy_path_class_match_fold(const char *pat,
                                                    zs_u64 plen, zs_u64 *pi,
                                                    char value) {
  int negated = 0;
  int matched = 0;
  int has_term = 0;
  zs_u64 start_pi = *pi;
  if (*pi < plen && pat[*pi] == '^') {
    negated = 1;
    (*pi)++;
  }
  while (*pi < plen) {
    if (pat[*pi] == ']' && has_term) {
      (*pi)++;
      return negated ? !matched : matched;
    }
    if (pat[*pi] == '-') {
      *pi = start_pi;
      return 0;
    }
    char start = zs_caddy_class_byte(pat, plen, pi);
    has_term = 1;
    if (*pi < plen && pat[*pi] == '-') {
      if (*pi + 1 >= plen || pat[*pi + 1] == ']') {
        *pi = start_pi;
        return 0;
      }
      (*pi)++;
      char end = zs_caddy_class_byte(pat, plen, pi);
      if (zs_caddy_lower(start) <= zs_caddy_lower(value) &&
          zs_caddy_lower(value) <= zs_caddy_lower(end))
        matched = 1;
    } else if (zs_caddy_lower(value) == zs_caddy_lower(start)) {
      matched = 1;
    }
  }
  *pi = start_pi;
  return 0;
}

static ZS_INLINE ZS_MAYBE_UNUSED zs_u64 zs_caddy_host_normalize(char *host, zs_u64 host_len) {
  zs_u64 start = 0;
  zs_u64 end = host_len;

  if (host_len >= 2 && host[0] == '[') {
    start = 1;
    for (zs_u64 i = 1; i < host_len; i++) {
      if (host[i] == ']') {
        end = i;
        break;
      }
    }
  } else {
    zs_u64 colon = host_len;
    zs_u64 colon_count = 0;
    for (zs_u64 i = 0; i < host_len; i++) {
      if (host[i] == ':') {
        colon_count++;
        if (colon_count == 1)
          colon = i;
      }
    }
    if (colon_count == 1)
      end = colon;
  }

  zs_u64 out = 0;
  for (zs_u64 i = start; i < end; i++)
    host[out++] = zs_caddy_lower(host[i]);
  if (out < host_len)
    host[out] = 0;
  return out;
}

static ZS_INLINE ZS_MAYBE_UNUSED int zs_caddy_host_match(const char *host, zs_u64 host_len,
                                         const char *pat, zs_u64 pat_len) {
  zs_u64 hi = 0;
  zs_u64 pi = 0;

  while (hi <= host_len && pi <= pat_len) {
    zs_u64 hend = hi;
    while (hend < host_len && host[hend] != '.')
      hend++;
    zs_u64 pend = pi;
    while (pend < pat_len && pat[pend] != '.')
      pend++;

    zs_u64 hpart_len = hend - hi;
    zs_u64 ppart_len = pend - pi;
    if (!(ppart_len == 1 && pat[pi] == '*') &&
        !zs_caddy_eq_fold(host + hi, hpart_len, pat + pi, ppart_len))
      return 0;

    if (hend == host_len || pend == pat_len)
      return hend == host_len && pend == pat_len;
    hi = hend + 1;
    pi = pend + 1;
  }

  return host_len == 0 && pat_len == 0;
}

/* Binary search over a sorted table of NUL-terminated lowercase hostnames
 * packed into `tbl`, with `off[i]` giving the byte offset of entry i and
 * `off[n]` the total blob length (each entry includes its trailing NUL).
 * Returns the sorted index of the entry equal to host[0..host_len], or -1.
 * `host` must already be normalized (lowercased, port stripped). */
static ZS_INLINE ZS_MAYBE_UNUSED zs_s64 zs_caddy_host_table_lookup(const char *host,
                                                                   zs_u64 host_len,
                                                                   const char *tbl,
                                                                   const unsigned int *off,
                                                                   zs_u64 n) {
  zs_s64 lo = 0;
  zs_s64 hi = (zs_s64)n - 1;
  while (lo <= hi) {
    /* BPF lacks signed division; hi >= lo here, so shift the difference. */
    zs_s64 mid = lo + (zs_s64)(((zs_u64)(hi - lo)) >> 1);
    const char *cand = tbl + off[mid];
    zs_u64 cand_len = (zs_u64)(off[mid + 1] - off[mid] - 1);
    zs_u64 min_len = host_len < cand_len ? host_len : cand_len;
    int cmp = 0;
    for (zs_u64 i = 0; i < min_len; i++) {
      if (host[i] != cand[i]) {
        cmp = (unsigned char)host[i] < (unsigned char)cand[i] ? -1 : 1;
        break;
      }
    }
    if (cmp == 0 && host_len != cand_len)
      cmp = host_len < cand_len ? -1 : 1;
    if (cmp == 0)
      return mid;
    if (cmp < 0)
      hi = mid - 1;
    else
      lo = mid + 1;
  }
  return -1;
}

static ZS_INLINE ZS_MAYBE_UNUSED zs_u64 zs_caddy_copy(char *dst, zs_u64 cap, zs_u64 off,
                                      const char *src, zs_u64 len) {
  for (zs_u64 i = 0; i < len && off + 1 < cap; i++)
    dst[off++] = src[i];
  if (cap > 0)
    dst[off < cap ? off : cap - 1] = 0;
  return off;
}

static ZS_INLINE ZS_MAYBE_UNUSED zs_s64 zs_caddy_parse_u16(const char *s, zs_u64 len) {
  if (len == 0)
    return -1;
  zs_u64 value = 0;
  for (zs_u64 i = 0; i < len; i++) {
    if (s[i] < '0' || s[i] > '9')
      return -1;
    value = value * 10 + (zs_u64)(s[i] - '0');
    if (value > 65535)
      return -1;
  }
  return (zs_s64)value;
}

static ZS_INLINE ZS_MAYBE_UNUSED zs_s64
zs_caddy_response_status_value(const char *status_template,
                               zs_u64 status_template_len) {
  char status_buf[16];
  zs_s64 status_raw = zs_caddy_expand(status_template, status_template_len,
                                      status_buf, sizeof(status_buf));
  zs_u64 status_len = zs_caddy_clamp_len(status_raw, sizeof(status_buf));
  return zs_caddy_parse_u16(status_buf, status_len);
}

static ZS_INLINE ZS_MAYBE_UNUSED void zs_caddy_apply_response_status(zs_s64 status) {
  if (status < 0)
    zs_res_set_status(500);
  else if (status == 103)
    zs_res_set_status(500);
  else if (status > 0 && (status < 100 || status > 999))
    zs_res_set_status(500);
  else if (status > 0)
    zs_res_set_status((zs_u64)status);
}

static ZS_INLINE ZS_MAYBE_UNUSED void zs_caddy_set_response_status(const char *status_template,
                                                   zs_u64 status_template_len) {
  zs_caddy_apply_response_status(
      zs_caddy_response_status_value(status_template, status_template_len));
}

static ZS_INLINE ZS_MAYBE_UNUSED void zs_caddy_set_path_preserve_query(const char *path,
                                                       zs_u64 path_len) {
  char query[512];
  zs_s64 query_raw = zs_req_query(query, sizeof(query));
  zs_u64 query_len = zs_caddy_clamp_len(query_raw, sizeof(query));
  char uri[1024];
  zs_u64 n = 0;
  n = zs_caddy_copy(uri, sizeof(uri), n, path, path_len);
  if (query_len > 0) {
    n = zs_caddy_copy(uri, sizeof(uri), n, "?", 1);
    n = zs_caddy_copy(uri, sizeof(uri), n, query, query_len);
  }
  zs_req_set_uri(uri, n);
}

static ZS_INLINE ZS_MAYBE_UNUSED void zs_caddy_set_query_preserve_path(const char *query,
                                                       zs_u64 query_len) {
  char path[512];
  zs_s64 path_raw = zs_req_path(path, sizeof(path));
  zs_u64 path_len = zs_caddy_clamp_len(path_raw, sizeof(path));
  char uri[1024];
  zs_u64 n = 0;
  n = zs_caddy_copy(uri, sizeof(uri), n, path, path_len);
  if (query_len > 0) {
    n = zs_caddy_copy(uri, sizeof(uri), n, "?", 1);
    n = zs_caddy_copy(uri, sizeof(uri), n, query, query_len);
  }
  zs_req_set_uri(uri, n);
}

#endif
