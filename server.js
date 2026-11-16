// server.ts
import "dotenv/config";
import express from "express";
import { GoogleGenAI, Type } from "@google/genai";
import crypto2 from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// server/security/safeFetch.ts
import dns from "node:dns/promises";
import net from "node:net";
var ALLOWED_HTML_READER_HOSTS = [
  "planalto.gov.br",
  "alepa.pa.gov.br",
  "camara.leg.br",
  "senado.leg.br",
  "gov.br",
  "fundacaocetap.selecao.net.br",
  "cetapnet.com.br",
  "cartilha.cert.br",
  "impa.br",
  "portaldamatematica.impa.br",
  "tre-pa.jus.br",
  "tjpa.jus.br",
  "pge.pa.gov.br"
];
var BLOCKED_HOSTNAME_SUFFIXES = [
  ".local",
  ".internal",
  ".localhost",
  ".home.arpa",
  ".lan",
  ".nip.io",
  ".sslip.io",
  ".xip.io"
];
var BLOCKED_HOSTNAMES = /* @__PURE__ */ new Set([
  "localhost",
  "localhost.localdomain",
  "0.0.0.0",
  "::1",
  "metadata.google.internal",
  "metadata",
  "instance-data"
]);
function normalizeRemoteUrlInput(raw) {
  const trimmed = raw.trim();
  if (!trimmed) return "";
  if (/^https?:\/\//i.test(trimmed)) return trimmed;
  return `https://${trimmed}`;
}
function rewriteGoogleDriveDownloadUrl(rawUrl) {
  const fileMatch = rawUrl.match(/drive\.google\.com\/file\/d\/([a-zA-Z0-9_-]+)/i);
  if (fileMatch) {
    return `https://drive.google.com/uc?export=download&id=${fileMatch[1]}`;
  }
  const openIdMatch = rawUrl.match(/drive\.google\.com\/open\?[^#]*[?&]id=([a-zA-Z0-9_-]+)/i);
  if (openIdMatch) {
    return `https://drive.google.com/uc?export=download&id=${openIdMatch[1]}`;
  }
  return rawUrl;
}
function isAllowedHtmlReaderHost(hostname) {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.+$/, "");
  if (!host) return false;
  return ALLOWED_HTML_READER_HOSTS.some(
    (allowed) => host === allowed || host.endsWith(`.${allowed}`)
  );
}
function isBlockedIpv4Tuple(parts) {
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    return true;
  }
  const [a, b, c] = parts;
  if (a === 0) return true;
  if (a === 10) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 0 && c === 0) return true;
  if (a === 192 && b === 0 && c === 2) return true;
  if (a === 192 && b === 168) return true;
  if (a === 198 && (b === 18 || b === 19)) return true;
  if (a === 198 && b === 51 && c === 100) return true;
  if (a === 203 && b === 0 && c === 113) return true;
  if (a >= 224) return true;
  return false;
}
function expandIpv6ToWords(rawIp) {
  const withoutZone = rawIp.split("%")[0].toLowerCase();
  if (!withoutZone) return null;
  let ipv6Part = withoutZone;
  let embeddedIpv4Words = null;
  const lastColon = withoutZone.lastIndexOf(":");
  if (lastColon !== -1 && withoutZone.slice(lastColon + 1).includes(".")) {
    const v4Str = withoutZone.slice(lastColon + 1);
    if (net.isIPv4(v4Str)) {
      const octets = v4Str.split(".").map(Number);
      embeddedIpv4Words = [octets[0] << 8 | octets[1], octets[2] << 8 | octets[3]];
      ipv6Part = withoutZone.slice(0, lastColon);
      if (ipv6Part.endsWith(":")) {
        if (ipv6Part === ":") ipv6Part = "::";
      }
    } else {
      return null;
    }
  }
  const targetWords = embeddedIpv4Words ? 6 : 8;
  const doubleColonParts = ipv6Part.split("::");
  if (doubleColonParts.length > 2) return null;
  const parseSegment = (segment) => {
    if (!segment) return [];
    const pieces = segment.split(":");
    const out = [];
    for (const p of pieces) {
      if (!/^[0-9a-f]{1,4}$/i.test(p)) return null;
      out.push(parseInt(p, 16));
    }
    return out;
  };
  let words = [];
  if (doubleColonParts.length === 2) {
    const left = parseSegment(doubleColonParts[0]);
    const right = parseSegment(doubleColonParts[1]);
    if (!left || !right) return null;
    const missing = targetWords - (left.length + right.length);
    if (missing < 1) return null;
    words = [...left, ...new Array(missing).fill(0), ...right];
  } else {
    const exact = parseSegment(doubleColonParts[0]);
    if (!exact || exact.length !== targetWords) return null;
    words = exact;
  }
  if (embeddedIpv4Words) {
    words.push(...embeddedIpv4Words);
  }
  return words.length === 8 ? words : null;
}
function isBlockedIpAddress(ipAddress) {
  const clean = ipAddress.trim().replace(/^\[|\]$/g, "").split("%")[0];
  const version = net.isIP(clean);
  if (version === 4) {
    const parts = clean.split(".").map(Number);
    return isBlockedIpv4Tuple(parts);
  }
  if (version === 6) {
    const words = expandIpv6ToWords(clean);
    if (!words) return true;
    const isAllZero = words.every((w) => w === 0);
    if (isAllZero) return true;
    const isLoopback = words.slice(0, 7).every((w) => w === 0) && words[7] === 1;
    if (isLoopback) return true;
    const isV4Mapped = words.slice(0, 5).every((w) => w === 0) && (words[5] === 65535 || words[5] === 0);
    if (isV4Mapped) {
      const v4Parts = [
        words[6] >> 8 & 255,
        words[6] & 255,
        words[7] >> 8 & 255,
        words[7] & 255
      ];
      return isBlockedIpv4Tuple(v4Parts);
    }
    if (words[0] === 100 && words[1] === 65435 && words.slice(2, 6).every((w) => w === 0)) {
      return true;
    }
    if ((words[0] & 65024) === 64512) return true;
    if ((words[0] & 65472) === 65152) return true;
    if ((words[0] & 65472) === 65216) return true;
    if ((words[0] & 65280) === 65280) return true;
    if (words[0] === 8193 && words[1] === 3512) return true;
    return false;
  }
  return true;
}
function isBlockedHostnameSyntax(hostname) {
  const host = hostname.trim().toLowerCase().replace(/^\[|\]$/g, "").replace(/\.+$/, "");
  if (!host) return true;
  if (BLOCKED_HOSTNAMES.has(host)) return true;
  if (BLOCKED_HOSTNAME_SUFFIXES.some((suffix) => host.endsWith(suffix))) return true;
  if (/^\d+$/.test(host)) return true;
  if (/^0x[0-9a-f]+$/i.test(host)) return true;
  if (net.isIP(host)) {
    return isBlockedIpAddress(host);
  }
  return false;
}
var defaultDnsLookup = async (hostname) => {
  const results = await dns.lookup(hostname, { all: true, verbatim: true });
  return results.map((entry) => ({ address: entry.address, family: entry.family }));
};
async function assertSafeRemoteUrl(rawUrl, options) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new SsrfValidationError("URL inv\xE1lida ou malformada.", 400);
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new SsrfValidationError("Protocolo n\xE3o permitido. Utilize apenas http:// ou https://.", 400);
  }
  if (parsed.username || parsed.password) {
    throw new SsrfValidationError("Credenciais embutidas na URL n\xE3o s\xE3o permitidas.", 400);
  }
  const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.+$/, "");
  if (isBlockedHostnameSyntax(hostname)) {
    throw new SsrfValidationError("Destino local ou privado bloqueado por seguran\xE7a.", 403);
  }
  if (options?.requireHtmlAllowlist && !isAllowedHtmlReaderHost(hostname)) {
    throw new SsrfValidationError(
      "Este site n\xE3o pertence \xE0 lista de portais oficiais autorizados para leitura integrada.",
      403
    );
  }
  if (!net.isIP(hostname)) {
    const lookup = options?.lookupFn || defaultDnsLookup;
    let resolved;
    try {
      resolved = await lookup(hostname);
    } catch {
      throw new SsrfValidationError("N\xE3o foi poss\xEDvel resolver o dom\xEDnio informado com seguran\xE7a.", 502);
    }
    if (!Array.isArray(resolved) || resolved.length === 0) {
      throw new SsrfValidationError("Dom\xEDnio sem endere\xE7o p\xFAblico v\xE1lido.", 502);
    }
    for (const addr of resolved) {
      if (!addr?.address || isBlockedIpAddress(addr.address)) {
        throw new SsrfValidationError(
          "O endere\xE7o resolvido aponta para rede privada ou reservada (bloqueado por pol\xEDtica SSRF).",
          403
        );
      }
    }
  }
  return parsed;
}
var SsrfValidationError = class extends Error {
  constructor(message, status = 403, kind = "ssrf_blocked") {
    super(message);
    this.name = "SsrfValidationError";
    this.status = status;
    this.kind = kind;
  }
};
var RemoteSizeLimitError = class extends Error {
  constructor(message) {
    super(message);
    this.status = 413;
    this.kind = "too_large";
    this.name = "RemoteSizeLimitError";
  }
};
function isPdfMagicBuffer(buf) {
  if (buf.byteLength < 4) return false;
  const headerSlice = buf.subarray(0, 16).toString("utf8").replace(/^\uFEFF/, "").trimStart();
  return headerSlice.startsWith("%PDF");
}
function isZipMagicBuffer(buf) {
  if (buf.byteLength < 4) return false;
  return buf[0] === 80 && buf[1] === 75 && (buf[2] === 3 && buf[3] === 4 || buf[2] === 5 && buf[3] === 6);
}
function looksLikeHtmlBuffer(buf, contentType) {
  const ctype = contentType.toLowerCase();
  if (ctype.includes("text/html") || ctype.includes("application/xhtml+xml")) {
    return true;
  }
  const head = buf.subarray(0, 64).toString("utf8").trimStart().toLowerCase();
  return head.startsWith("<!doctype") || head.startsWith("<html") || head.startsWith("<head");
}
async function readResponseWithByteLimit(response, maxBytes) {
  const declaredLength = Number(response.headers.get("content-length") || "0");
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
    try {
      await response.body?.cancel();
    } catch {
    }
    throw new RemoteSizeLimitError(
      `O arquivo remoto ultrapassa o limite m\xE1ximo permitido (${Math.round(maxBytes / (1024 * 1024))} MB).`
    );
  }
  if (!response.body) {
    const arrBuf = await response.arrayBuffer();
    if (arrBuf.byteLength > maxBytes) {
      throw new RemoteSizeLimitError(
        `O arquivo remoto ultrapassa o limite m\xE1ximo permitido (${Math.round(maxBytes / (1024 * 1024))} MB).`
      );
    }
    return Buffer.from(arrBuf);
  }
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value && value.byteLength > 0) {
      total += value.byteLength;
      if (total > maxBytes) {
        try {
          await reader.cancel();
        } catch {
        }
        throw new RemoteSizeLimitError(
          `O arquivo remoto ultrapassa o limite m\xE1ximo permitido (${Math.round(maxBytes / (1024 * 1024))} MB).`
        );
      }
      chunks.push(Buffer.from(value));
    }
  }
  return Buffer.concat(chunks, total);
}
async function safeFetchRemoteDocument(rawUrl, options) {
  const maxBytes = options?.maxBytes ?? 45 * 1024 * 1024;
  const timeoutMs = options?.timeoutMs ?? 25e3;
  const maxRedirects = options?.maxRedirects ?? 5;
  const requireHtmlAllowlist = options?.acceptKind === "html_portal";
  const fetchFn = options?.fetchImpl ?? fetch;
  let currentUrl = rewriteGoogleDriveDownloadUrl(normalizeRemoteUrlInput(rawUrl));
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    for (let hop = 0; hop <= maxRedirects; hop++) {
      const safeParsed = await assertSafeRemoteUrl(currentUrl, {
        requireHtmlAllowlist,
        lookupFn: options?.lookupFn
      });
      const upstream = await fetchFn(safeParsed.toString(), {
        method: "GET",
        headers: options?.headers,
        redirect: "manual",
        signal: controller.signal
      });
      if (upstream.status === 301 || upstream.status === 302 || upstream.status === 303 || upstream.status === 307 || upstream.status === 308) {
        try {
          await upstream.body?.cancel();
        } catch {
        }
        const location = upstream.headers.get("location");
        if (!location) {
          throw new SsrfValidationError("Redirecionamento HTTP sem cabe\xE7alho Location.", 502, "bad_redirect");
        }
        if (hop === maxRedirects) {
          throw new SsrfValidationError("N\xFAmero m\xE1ximo de redirecionamentos excedido.", 502, "too_many_redirects");
        }
        currentUrl = new URL(location, safeParsed).toString();
        continue;
      }
      if (!upstream.ok && upstream.status !== 206) {
        try {
          await upstream.body?.cancel();
        } catch {
        }
        throw new SsrfValidationError(
          `O servidor de origem respondeu com status ${upstream.status}.`,
          upstream.status === 404 ? 404 : 502,
          "upstream_error"
        );
      }
      const buffer = await readResponseWithByteLimit(upstream, maxBytes);
      return {
        finalUrl: safeParsed.toString(),
        status: upstream.status,
        contentType: (upstream.headers.get("content-type") || "").toLowerCase(),
        acceptRanges: upstream.headers.get("accept-ranges"),
        contentRange: upstream.headers.get("content-range"),
        buffer
      };
    }
    throw new SsrfValidationError("N\xFAmero m\xE1ximo de redirecionamentos excedido.", 502, "too_many_redirects");
  } finally {
    clearTimeout(timer);
  }
}
function decodeHtmlTextEntities(input) {
  return input.replace(/&nbsp;/gi, " ").replace(/&amp;/gi, "&").replace(/&quot;/gi, '"').replace(/&#39;|&apos;/gi, "'").replace(/&lt;/gi, "<").replace(/&gt;/gi, ">").replace(/&ordm;/gi, "\xBA").replace(/&ordf;/gi, "\xAA").replace(/&sect;/gi, "\xA7").replace(/&ccedil;/g, "\xE7").replace(/&Ccedil;/g, "\xC7").replace(/&aacute;/g, "\xE1").replace(/&Aacute;/g, "\xC1").replace(/&eacute;/g, "\xE9").replace(/&Eacute;/g, "\xC9").replace(/&iacute;/g, "\xED").replace(/&Iacute;/g, "\xCD").replace(/&oacute;/g, "\xF3").replace(/&Oacute;/g, "\xD3").replace(/&uacute;/g, "\xFA").replace(/&Uacute;/g, "\xDA").replace(/&atilde;/g, "\xE3").replace(/&Atilde;/g, "\xC3").replace(/&otilde;/g, "\xF5").replace(/&Otilde;/g, "\xD5").replace(/&acirc;/g, "\xE2").replace(/&ecirc;/g, "\xEA").replace(/&ocirc;/g, "\xF4").replace(/&#(\d+);/g, (_m, code) => {
    const n = Number(code);
    return Number.isFinite(n) ? String.fromCodePoint(n) : "";
  }).replace(/&#x([0-9a-f]+);/gi, (_m, hex) => {
    const n = parseInt(hex, 16);
    return Number.isFinite(n) ? String.fromCodePoint(n) : "";
  });
}
function stripTagsAndClean(rawHtml) {
  return decodeHtmlTextEntities(
    rawHtml.replace(/<br\s*\/?>/gi, "\n").replace(/<[^>]+>/g, " ")
  ).replace(/[ \t\r\f\v]+/g, " ").replace(/\n{2,}/g, "\n").trim();
}
function decodeHtmlBuffer(buffer, contentType) {
  const sniff = buffer.subarray(0, 2048).toString("latin1").toLowerCase();
  const ctype = contentType.toLowerCase();
  const isLatin1 = ctype.includes("iso-8859-1") || ctype.includes("windows-1252") || sniff.includes("charset=iso-8859-1") || sniff.includes('charset="iso-8859-1"') || sniff.includes("charset=windows-1252");
  return buffer.toString(isLatin1 ? "latin1" : "utf8");
}
function extractStructuredHtmlPortal(html, sourceUrl) {
  const parsedUrl = new URL(sourceUrl);
  const titleMatch = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  const docTitle = titleMatch ? stripTagsAndClean(titleMatch[1]) : parsedUrl.hostname;
  const mainMatch = html.match(/<main\b[^>]*>([\s\S]*?)<\/main>/i) || html.match(/<article\b[^>]*>([\s\S]*?)<\/article>/i) || html.match(/<body\b[^>]*>([\s\S]*?)<\/body>/i);
  let working = mainMatch ? mainMatch[1] : html;
  working = working.replace(/<!--[\s\S]*?-->/g, " ").replace(/<(script|style|noscript|svg|iframe|object|embed|nav|footer|aside|form)[^>]*>[\s\S]*?<\/\1>/gi, " ");
  const blocks = [];
  const chapters = [];
  let activeChapterId;
  const elementRegex = /<(h1|h2|h3|h4|p|li|blockquote)\b[^>]*>([\s\S]*?)<\/\1>/gi;
  let match;
  let blockIdx = 0;
  while ((match = elementRegex.exec(working)) !== null) {
    const tag = match[1].toLowerCase();
    const cleaned = stripTagsAndClean(match[2]);
    if (!cleaned || cleaned.length < 2) continue;
    let kind = "p";
    if (tag === "h1") kind = "h1";
    else if (tag === "h2") kind = "h2";
    else if (tag === "h3" || tag === "h4") kind = "h3";
    else if (tag === "li") kind = "li";
    else if (tag === "blockquote") kind = "quote";
    else if (/^(Art\.?\s+\d+|T[ÍI]TULO\s+[IVXLC]+|CAP[ÍI]TULO\s+[IVXLC]+|SE[ÇC][ÃA]O\s+[IVXLC]+)/i.test(cleaned)) {
      kind = "law_article";
    }
    if (kind === "h1" || kind === "h2" || kind === "h3" || /^(T[ÍI]TULO|CAP[ÍI]TULO|LIVRO)\s+[IVXLC0-9]+/i.test(cleaned)) {
      const chapterId = `html_ch_${chapters.length + 1}`;
      activeChapterId = chapterId;
      chapters.push({
        id: chapterId,
        title: cleaned.slice(0, 140),
        level: kind === "h1" ? 1 : kind === "h2" ? 2 : 3,
        blockIndex: blocks.length
      });
    }
    blocks.push({
      id: `html_blk_${blockIdx++}`,
      kind,
      text: cleaned,
      chapterId: activeChapterId
    });
    if (blocks.length >= 1600) break;
  }
  if (blocks.length < 4) {
    const plainLines = stripTagsAndClean(
      working.replace(/<\/(div|p|tr|li|h[1-6]|section)>/gi, "\n")
    ).split("\n").map((l) => l.trim()).filter((l) => l.length >= 4);
    for (const line of plainLines.slice(0, 1600)) {
      const isHeading = /^(T[ÍI]TULO|CAP[ÍI]TULO|SE[ÇC][ÃA]O|LIVRO|LEI\s+N|CONSTITUI[ÇC][ÃA]O|REGIMENTO)/i.test(
        line
      );
      const isArticle = /^Art\.?\s+\d+/i.test(line);
      if (isHeading && line.length <= 160) {
        const chapterId = `html_ch_${chapters.length + 1}`;
        activeChapterId = chapterId;
        chapters.push({
          id: chapterId,
          title: line.slice(0, 140),
          level: 2,
          blockIndex: blocks.length
        });
      }
      blocks.push({
        id: `html_blk_${blockIdx++}`,
        kind: isHeading ? "h2" : isArticle ? "law_article" : "p",
        text: line,
        chapterId: activeChapterId
      });
    }
  }
  const plainText = blocks.map((b) => b.text).join("\n\n").slice(0, 2e5);
  return {
    title: docTitle || parsedUrl.hostname,
    url: sourceUrl,
    canonicalHost: parsedUrl.hostname.toLowerCase(),
    blocks,
    chapters,
    plainText,
    fetchedAt: (/* @__PURE__ */ new Date()).toISOString()
  };
}

// server/ai/quotaAndCache.ts
import crypto from "node:crypto";
var AI_TIER_LIMITS = {
  guest: { perMinute: 8, perDay: 24 },
  student: { perMinute: 20, perDay: 140 },
  staff: { perMinute: 45, perDay: 600 }
};
function getCurrentDayKey(nowMs) {
  return new Date(nowMs).toISOString().slice(0, 10);
}
function getNextUtcMidnightIso(nowMs) {
  const d = new Date(nowMs);
  d.setUTCHours(24, 0, 0, 0);
  return d.toISOString();
}
var AiQuotaManager = class {
  constructor(customLimits) {
    this.buckets = /* @__PURE__ */ new Map();
    this.limits = {
      guest: customLimits?.guest ?? AI_TIER_LIMITS.guest,
      student: customLimits?.student ?? AI_TIER_LIMITS.student,
      staff: customLimits?.staff ?? AI_TIER_LIMITS.staff
    };
  }
  getOrResetBucket(key, nowMs) {
    const today = getCurrentDayKey(nowMs);
    const minuteStart = nowMs - 6e4;
    let bucket = this.buckets.get(key);
    if (!bucket) {
      bucket = {
        minuteTimestamps: [],
        dayKey: today,
        dayCount: 0,
        cacheHits: 0
      };
      this.buckets.set(key, bucket);
    }
    bucket.minuteTimestamps = bucket.minuteTimestamps.filter((ts) => ts > minuteStart);
    if (bucket.dayKey !== today) {
      bucket.dayKey = today;
      bucket.dayCount = 0;
      bucket.cacheHits = 0;
    }
    return bucket;
  }
  pruneIfLarge(nowMs) {
    if (this.buckets.size <= 1e3) return;
    const today = getCurrentDayKey(nowMs);
    const minuteStart = nowMs - 6e4;
    for (const [k, b] of this.buckets.entries()) {
      if (b.dayKey !== today && b.minuteTimestamps.every((ts) => ts <= minuteStart)) {
        this.buckets.delete(k);
      }
    }
  }
  checkAndConsume(identity, nowMs = Date.now()) {
    this.pruneIfLarge(nowMs);
    const bucket = this.getOrResetBucket(identity.key, nowMs);
    const tierLimit = this.limits[identity.tier];
    const resetAtIso = getNextUtcMidnightIso(nowMs);
    if (bucket.minuteTimestamps.length >= tierLimit.perMinute) {
      const oldest = bucket.minuteTimestamps[0] ?? nowMs;
      const retryAfterSeconds = Math.max(1, Math.ceil((oldest + 6e4 - nowMs) / 1e3));
      return {
        allowed: false,
        tier: identity.tier,
        minuteUsed: bucket.minuteTimestamps.length,
        minuteLimit: tierLimit.perMinute,
        dayUsed: bucket.dayCount,
        dayLimit: tierLimit.perDay,
        retryAfterSeconds,
        resetAtIso,
        reason: "Muitas solicita\xE7\xF5es \xE0 IA em sequ\xEAncia. Aguarde alguns segundos antes de enviar outra consulta."
      };
    }
    if (bucket.dayCount >= tierLimit.perDay) {
      const retryAfterSeconds = Math.max(60, Math.ceil((Date.parse(resetAtIso) - nowMs) / 1e3));
      return {
        allowed: false,
        tier: identity.tier,
        minuteUsed: bucket.minuteTimestamps.length,
        minuteLimit: tierLimit.perMinute,
        dayUsed: bucket.dayCount,
        dayLimit: tierLimit.perDay,
        retryAfterSeconds,
        resetAtIso,
        reason: identity.tier === "guest" ? "Limite di\xE1rio para visitante atingido. Entre com sua conta Google/ALEPA para ampliar sua cota di\xE1ria." : "Cota di\xE1ria de uso de IA atingida para hoje. O saldo ser\xE1 renovado \xE0 00:00 UTC."
      };
    }
    bucket.minuteTimestamps.push(nowMs);
    bucket.dayCount += 1;
    return {
      allowed: true,
      tier: identity.tier,
      minuteUsed: bucket.minuteTimestamps.length,
      minuteLimit: tierLimit.perMinute,
      dayUsed: bucket.dayCount,
      dayLimit: tierLimit.perDay,
      retryAfterSeconds: 0,
      resetAtIso
    };
  }
  recordCacheHit(identity, nowMs = Date.now()) {
    const bucket = this.getOrResetBucket(identity.key, nowMs);
    bucket.cacheHits += 1;
  }
  getUsage(identity, nowMs = Date.now()) {
    const bucket = this.getOrResetBucket(identity.key, nowMs);
    const tierLimit = this.limits[identity.tier];
    return {
      tier: identity.tier,
      minuteUsed: bucket.minuteTimestamps.length,
      minuteLimit: tierLimit.perMinute,
      dayUsed: bucket.dayCount,
      dayLimit: tierLimit.perDay,
      dayRemaining: Math.max(0, tierLimit.perDay - bucket.dayCount),
      cacheHits: bucket.cacheHits,
      resetAtIso: getNextUtcMidnightIso(nowMs)
    };
  }
};
var AiResponseCache = class {
  constructor(maxEntries = 150, ttlMs = 30 * 60 * 1e3) {
    this.store = /* @__PURE__ */ new Map();
    this.maxEntries = maxEntries;
    this.ttlMs = ttlMs;
  }
  static buildKey(route, payload) {
    const hash = crypto.createHash("sha256").update(route).update("\n").update(JSON.stringify(payload)).digest("hex");
    return `${route}:${hash}`;
  }
  get(key, nowMs = Date.now()) {
    const entry = this.store.get(key);
    if (!entry) return null;
    if (entry.expiresAt <= nowMs) {
      this.store.delete(key);
      return null;
    }
    this.store.delete(key);
    this.store.set(key, entry);
    return entry.value;
  }
  set(key, value, nowMs = Date.now()) {
    if (this.store.has(key)) {
      this.store.delete(key);
    }
    while (this.store.size >= this.maxEntries) {
      const oldestKey = this.store.keys().next().value;
      if (!oldestKey) break;
      this.store.delete(oldestKey);
    }
    this.store.set(key, {
      value,
      expiresAt: nowMs + this.ttlMs
    });
  }
  clear() {
    this.store.clear();
  }
};
function normalizeStatementForDup(text) {
  return text.toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-z0-9\s]/g, " ").replace(/\s+/g, " ").trim();
}
function jaccardSimilarity(a, b) {
  const wordsA = new Set(a.split(" ").filter((w) => w.length >= 4));
  const wordsB = new Set(b.split(" ").filter((w) => w.length >= 4));
  if (wordsA.size === 0 || wordsB.size === 0) return 0;
  let intersection = 0;
  for (const w of wordsA) {
    if (wordsB.has(w)) intersection += 1;
  }
  const union = wordsA.size + wordsB.size - intersection;
  return union === 0 ? 0 : intersection / union;
}
function validateExtractedQuestions(candidates, options) {
  const existingNormalized = (options?.existingStatements || []).map(normalizeStatementForDup).filter((s) => s.length >= 16);
  const validPagesSet = options?.validPageNumbers && options.validPageNumbers.length > 0 ? new Set(options.validPageNumbers) : null;
  const seenInBatch = [];
  const results = [];
  for (const raw of candidates.slice(0, 15)) {
    const reviewFlags = [];
    const statement = String(raw.statement || "").trim().slice(0, 1800);
    const topicTitle = String(raw.topicTitle || "T\xF3pico Geral do Material").trim().slice(0, 160);
    const rawOpts = Array.isArray(raw.options) ? raw.options.map((o) => String(o || "").trim().slice(0, 420)).filter(Boolean) : [];
    if (statement.length < 25) {
      reviewFlags.push("short_statement");
    }
    const paddedOptions = [...rawOpts.slice(0, 5)];
    if (paddedOptions.length < 5) {
      reviewFlags.push("incomplete_options");
      while (paddedOptions.length < 5) {
        paddedOptions.push(`Alternativa ${String.fromCharCode(65 + paddedOptions.length)} (completar na revis\xE3o)`);
      }
    }
    let correctIndex = typeof raw.correctIndex === "number" && Number.isInteger(raw.correctIndex) ? raw.correctIndex : 0;
    if (correctIndex < 0 || correctIndex > 4) {
      correctIndex = 0;
      reviewFlags.push("invalid_answer_key");
    }
    const explanation = String(raw.explanation || "").trim().slice(0, 1500);
    if (explanation.length < 15) {
      reviewFlags.push("missing_explanation");
    }
    const legalBasis = raw.legalBasis ? String(raw.legalBasis).trim().slice(0, 280) : void 0;
    const sourceExcerpt = raw.sourceExcerpt ? String(raw.sourceExcerpt).trim().slice(0, 400) : void 0;
    let sourcePage;
    if (typeof raw.sourcePage === "number" && Number.isInteger(raw.sourcePage) && raw.sourcePage >= 1) {
      if (!validPagesSet || validPagesSet.has(raw.sourcePage)) {
        sourcePage = raw.sourcePage;
      } else {
        reviewFlags.push("unconfirmed_page");
      }
    } else if (validPagesSet) {
      reviewFlags.push("unconfirmed_page");
    }
    if (typeof raw.confidence === "number" && raw.confidence < 0.7) {
      reviewFlags.push("low_confidence");
    }
    const normalized = normalizeStatementForDup(statement);
    if (normalized.length >= 16) {
      const isDuplicateExisting = existingNormalized.some(
        (ex) => ex === normalized || jaccardSimilarity(ex, normalized) >= 0.78
      );
      const isDuplicateBatch = seenInBatch.some(
        (seen) => seen === normalized || jaccardSimilarity(seen, normalized) >= 0.78
      );
      if (isDuplicateExisting || isDuplicateBatch) {
        reviewFlags.push("possible_duplicate");
      }
      seenInBatch.push(normalized);
    }
    results.push({
      topicTitle,
      statement,
      options: paddedOptions,
      correctIndex,
      explanation: explanation || "Coment\xE1rio pendente de revis\xE3o editorial.",
      legalBasis,
      sourcePage,
      sourceExcerpt,
      needsReview: true,
      // Always requires human editorial review before publishing
      reviewFlags: Array.from(new Set(reviewFlags))
    });
  }
  return results;
}

// server.ts
var __filename = fileURLToPath(import.meta.url);
var __dirname = path.dirname(__filename);
var PORT = Number(process.env.PORT) || 3e3;
var GEMINI_MODEL = "gemini-4-hydrogen";
var SPOTIFY_SCOPES = [
  "user-read-private",
  "user-read-email",
  "user-library-read",
  "playlist-read-private",
  "playlist-read-collaborative",
  "user-read-recently-played"
].join(" ");
var pendingSpotifyStates = /* @__PURE__ */ new Map();
function getSpotifyCredentials() {
  return {
    clientId: process.env.SPOTIFY_CLIENT_ID?.trim() || "",
    clientSecret: process.env.SPOTIFY_CLIENT_SECRET?.trim() || ""
  };
}
function getSpotifyRedirectUri() {
  const baseUrl = (process.env.APP_URL?.trim() || `http://localhost:${PORT}`).replace(/\/+$/, "");
  return `${baseUrl}/api/spotify/callback`;
}
function cleanupExpiredSpotifyStates() {
  const now = Date.now();
  for (const [stateKey, info] of pendingSpotifyStates.entries()) {
    if (now - info.createdAt > 15 * 60 * 1e3) {
      pendingSpotifyStates.delete(stateKey);
    }
  }
}
function serializeForInlineScript(value) {
  return JSON.stringify(value).replace(/</g, "\\u003c").replace(/>/g, "\\u003e").replace(/&/g, "\\u0026").replace(/\u2028/g, "\\u2028").replace(/\u2029/g, "\\u2029");
}
function extractSpotifyBearer(req) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.toLowerCase().startsWith("bearer ")) {
    return null;
  }
  const token = authHeader.slice(7).trim();
  return token || null;
}
async function fetchSpotifyApi(endpointPath, accessToken) {
  const url = endpointPath.startsWith("http") ? endpointPath : `https://api.spotify.com/v1${endpointPath}`;
  const res = await fetch(url, {
    headers: {
      Authorization: `Bearer ${accessToken}`
    },
    signal: AbortSignal.timeout(1e4)
  });
  if (res.status === 401) {
    return { ok: false, status: 401, error: "SPOTIFY_TOKEN_EXPIRED" };
  }
  if (!res.ok) {
    let errMessage = `Erro na API do Spotify (${res.status})`;
    try {
      const errJson = await res.json();
      if (typeof errJson.error === "string") {
        errMessage = errJson.error;
      } else if (errJson.error?.message) {
        errMessage = errJson.error.message;
      }
    } catch {
    }
    return { ok: false, status: res.status, error: errMessage };
  }
  const data = await res.json();
  return { ok: true, status: res.status, data };
}
var cachedSpotifyAppToken = null;
async function getSpotifyAppToken() {
  const { clientId, clientSecret } = getSpotifyCredentials();
  if (!clientId || !clientSecret) return null;
  if (cachedSpotifyAppToken && Date.now() < cachedSpotifyAppToken.expiresAt - 3e4) {
    return cachedSpotifyAppToken.token;
  }
  try {
    const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString("base64");
    const res = await fetch("https://accounts.spotify.com/api/token", {
      method: "POST",
      headers: {
        Authorization: `Basic ${basicAuth}`,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: "grant_type=client_credentials",
      signal: AbortSignal.timeout(1e4)
    });
    if (!res.ok) return null;
    const json = await res.json();
    if (!json.access_token) return null;
    cachedSpotifyAppToken = {
      token: json.access_token,
      expiresAt: Date.now() + (json.expires_in || 3600) * 1e3
    };
    return cachedSpotifyAppToken.token;
  } catch {
    return null;
  }
}
function isValidSpotifyId(kind, id) {
  if (!id || id.length > 80 || id === "." || id === ".." || id.includes("..")) {
    return false;
  }
  if (kind === "user") {
    return /^[a-zA-Z0-9._-]+$/.test(id);
  }
  return /^[a-zA-Z0-9]+$/.test(id);
}
function parseSpotifyTarget(raw) {
  const trimmed = raw.trim();
  if (!trimmed) return { kind: "unknown", id: null, canonicalUrl: "" };
  const uriMatch = trimmed.match(/^spotify:(user|episode|show|playlist|track|album):([a-zA-Z0-9._-]+)$/i);
  if (uriMatch) {
    const kind = uriMatch[1].toLowerCase();
    const id = uriMatch[2];
    if (!isValidSpotifyId(kind, id)) {
      return { kind: "unknown", id: null, canonicalUrl: "" };
    }
    return { kind, id, canonicalUrl: `https://open.spotify.com/${kind}/${encodeURIComponent(id)}` };
  }
  const normalized = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  let parsedUrl;
  try {
    parsedUrl = new URL(normalized);
  } catch {
    return { kind: "unknown", id: null, canonicalUrl: "" };
  }
  const host = parsedUrl.hostname.toLowerCase();
  if (host !== "open.spotify.com" && host !== "play.spotify.com") {
    return { kind: "unknown", id: null, canonicalUrl: "" };
  }
  const cleanPath = parsedUrl.pathname.replace(/^\/intl-[a-z-]+(?=\/|$)/i, "");
  if (!cleanPath || cleanPath === "/") {
    return { kind: "home", id: null, canonicalUrl: "https://open.spotify.com/" };
  }
  const itemMatch = cleanPath.match(/^\/(user|episode|show|playlist|track|album)\/([a-zA-Z0-9._-]+)(?:\/)?$/i);
  if (itemMatch) {
    const kind = itemMatch[1].toLowerCase();
    const id = itemMatch[2];
    if (!isValidSpotifyId(kind, id)) {
      return { kind: "unknown", id: null, canonicalUrl: "" };
    }
    return { kind, id, canonicalUrl: `https://open.spotify.com/${kind}/${encodeURIComponent(id)}` };
  }
  return { kind: "unknown", id: null, canonicalUrl: "" };
}
async function readBoundedTextResponse(res, maxBytes = 512 * 1024) {
  const contentLength = Number(res.headers.get("content-length") || "0");
  if (contentLength > maxBytes) {
    throw new Error("Resposta excede o tamanho m\xE1ximo permitido.");
  }
  if (!res.body) {
    const txt = await res.text();
    return txt.slice(0, maxBytes);
  }
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        total += value.byteLength;
        if (total > maxBytes) {
          await reader.cancel();
          break;
        }
        chunks.push(value);
      }
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks.map((c) => Buffer.from(c))).toString("utf8");
}
function decodeHtmlEntities(text) {
  return text.replace(/&amp;/g, "&").replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">");
}
function getGeminiClient() {
  const apiKey = process.env.GEMINI_API_KEY?.trim();
  if (!apiKey) {
    throw new Error("GEMINI_KEY_MISSING");
  }
  return new GoogleGenAI({
    apiKey,
    httpOptions: {
      headers: {
        "User-Agent": "aistudio-build"
      }
    }
  });
}
function extractYouTubeId(rawUrl) {
  const url = rawUrl.trim();
  if (!url) return null;
  const watch = url.match(/[?&]v=([a-zA-Z0-9_-]{11})/);
  if (watch) return watch[1];
  const short = url.match(/youtu\.be\/([a-zA-Z0-9_-]{11})/);
  if (short) return short[1];
  const pathMatch = url.match(/youtube\.com\/(?:shorts|live|embed)\/([a-zA-Z0-9_-]{11})/);
  if (pathMatch) return pathMatch[1];
  return null;
}
var PRIMARY_ADMIN_EMAILS = /* @__PURE__ */ new Set([
  "saviobaia6@gmail.com",
  "saviobaiax5@gmail.com",
  "legcmp.dle@gmail.com",
  "alfaservicosgraficosx5@gmail.com"
]);
function loadFirebaseAppletConfig() {
  try {
    const configPath = path.join(__dirname, "firebase-applet-config.json");
    const raw = fs.readFileSync(configPath, "utf8");
    const parsed = JSON.parse(raw);
    return {
      projectId: parsed.projectId || "",
      firestoreDatabaseId: parsed.firestoreDatabaseId || "(default)",
      storageBucket: parsed.storageBucket || ""
    };
  } catch {
    return { projectId: "", firestoreDatabaseId: "(default)", storageBucket: "" };
  }
}
var FIREBASE_APPLET_CONFIG = loadFirebaseAppletConfig();
var FIREBASE_CERTS_URL = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";
var cachedFirebaseCerts = null;
async function getFirebasePublicCerts() {
  if (cachedFirebaseCerts && Date.now() < cachedFirebaseCerts.expiresAt) {
    return cachedFirebaseCerts.certs;
  }
  const res = await fetch(FIREBASE_CERTS_URL, {
    signal: AbortSignal.timeout(1e4)
  });
  if (!res.ok) {
    throw new Error(`Falha ao obter chaves p\xFAblicas do Firebase (${res.status})`);
  }
  const certs = await res.json();
  const cacheControl = res.headers.get("cache-control") || "";
  const maxAgeMatch = cacheControl.match(/max-age=(\d+)/i);
  const maxAgeSec = maxAgeMatch ? Number(maxAgeMatch[1]) : 3600;
  cachedFirebaseCerts = {
    certs,
    expiresAt: Date.now() + Math.max(60, maxAgeSec - 30) * 1e3
  };
  return certs;
}
function normalizeServerRole(rawRole, email) {
  const normalizedEmail = (email || "").trim().toLowerCase();
  if (normalizedEmail && PRIMARY_ADMIN_EMAILS.has(normalizedEmail)) {
    return rawRole === "dev" ? "dev" : "admin";
  }
  if (rawRole === "admin" || rawRole === "dev" || rawRole === "editor" || rawRole === "teacher") {
    return rawRole;
  }
  return "student";
}
async function resolveUserRoleFromFirestore(uid, idToken, email) {
  if (!FIREBASE_APPLET_CONFIG.projectId) {
    return normalizeServerRole(null, email);
  }
  try {
    const dbId = encodeURIComponent(FIREBASE_APPLET_CONFIG.firestoreDatabaseId || "(default)");
    const url = `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(FIREBASE_APPLET_CONFIG.projectId)}/databases/${dbId}/documents/users/${encodeURIComponent(uid)}`;
    const res = await fetch(url, {
      headers: {
        Authorization: `Bearer ${idToken}`
      },
      signal: AbortSignal.timeout(8e3)
    });
    if (!res.ok) {
      return normalizeServerRole(null, email);
    }
    const doc = await res.json();
    const rawRole = doc.fields?.role?.stringValue || null;
    return normalizeServerRole(rawRole, email);
  } catch {
    return normalizeServerRole(null, email);
  }
}
async function verifyFirebaseIdToken(idToken) {
  try {
    const parts = idToken.split(".");
    if (parts.length !== 3) return null;
    const [headerB64, payloadB64, signatureB64] = parts;
    const header = JSON.parse(Buffer.from(headerB64, "base64url").toString("utf8"));
    if (header.alg !== "RS256" || !header.kid) return null;
    const certs = await getFirebasePublicCerts();
    const certPem = certs[header.kid];
    if (!certPem) return null;
    const verifier = crypto2.createVerify("RSA-SHA256");
    verifier.update(`${headerB64}.${payloadB64}`);
    verifier.end();
    const isValidSig = verifier.verify(certPem, Buffer.from(signatureB64, "base64url"));
    if (!isValidSig) return null;
    const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8"));
    const projectId = FIREBASE_APPLET_CONFIG.projectId;
    if (!projectId) return null;
    const nowSec = Math.floor(Date.now() / 1e3);
    if (payload.aud !== projectId) return null;
    if (payload.iss !== `https://securetoken.google.com/${projectId}`) return null;
    if (!payload.sub || typeof payload.sub !== "string") return null;
    if (typeof payload.exp !== "number" || payload.exp <= nowSec) return null;
    if (typeof payload.iat !== "number" || payload.iat > nowSec + 300) return null;
    if (payload.email_verified !== true) return null;
    const email = typeof payload.email === "string" ? payload.email : "";
    const role = await resolveUserRoleFromFirestore(payload.sub, idToken, email);
    return {
      uid: payload.sub,
      email,
      role
    };
  } catch {
    return null;
  }
}
function requireRole(allowedRoles) {
  return async (req, res, next) => {
    const token = extractSpotifyBearer(req);
    if (!token) {
      res.status(401).json({
        error: "Autentica\xE7\xE3o obrigat\xF3ria para acessar o ambiente administrativo."
      });
      return;
    }
    const verified = await verifyFirebaseIdToken(token);
    if (!verified) {
      res.status(401).json({
        error: "Token de sess\xE3o inv\xE1lido, expirado ou com e-mail n\xE3o verificado."
      });
      return;
    }
    if (!allowedRoles.includes(verified.role)) {
      res.status(403).json({
        error: "Acesso negado. Este recurso \xE9 exclusivo para Administrador, Editor/Professor ou Desenvolvedor."
      });
      return;
    }
    req.authUser = verified;
    next();
  };
}
var aiQuotaManager = new AiQuotaManager();
var aiResponseCache = new AiResponseCache(150, 30 * 60 * 1e3);
async function attachOptionalAuth(req, _res, next) {
  const authReq = req;
  if (!authReq.authUser) {
    const token = extractSpotifyBearer(req);
    if (token) {
      const verified = await verifyFirebaseIdToken(token);
      if (verified) {
        authReq.authUser = verified;
      }
    }
  }
  next();
}
function resolveTrustProxyHops(rawValue = process.env.TRUST_PROXY_HOPS) {
  const trimmed = (rawValue ?? "").trim().toLowerCase();
  if (!trimmed) return 1;
  if (trimmed === "false" || trimmed === "off" || trimmed === "0") return 0;
  if (trimmed === "loopback" || trimmed === "uniquelocal" || trimmed === "linklocal") {
    return trimmed;
  }
  if (/^\d+$/.test(trimmed)) {
    const hops = Number(trimmed);
    if (Number.isSafeInteger(hops) && hops >= 0 && hops <= 10) {
      return hops;
    }
  }
  return 1;
}
function normalizeClientIp(rawIp) {
  const trimmed = (rawIp || "").trim();
  if (!trimmed) return "unknown";
  const withoutZone = trimmed.split("%")[0];
  const normalized = withoutZone.toLowerCase().startsWith("::ffff:") ? withoutZone.slice(7) : withoutZone;
  return (normalized || "unknown").slice(0, 64);
}
function resolveQuotaIdentity(req) {
  const authUser = req.authUser;
  if (authUser) {
    const tier = authUser.role === "admin" || authUser.role === "editor" || authUser.role === "teacher" || authUser.role === "dev" ? "staff" : "student";
    return {
      key: `uid:${authUser.uid}`,
      tier
    };
  }
  const ip = normalizeClientIp(req.ip || req.socket?.remoteAddress);
  return {
    key: `ip:${ip}`,
    tier: "guest"
  };
}
var ProxyRateLimiter = class {
  constructor(options) {
    this.buckets = /* @__PURE__ */ new Map();
    this.maxRequests = Math.max(1, Math.floor(options.maxRequests));
    this.windowMs = Math.max(1e3, Math.floor(options.windowMs));
    this.maxKeys = options.maxKeys ?? 5e3;
  }
  consume(key, now = Date.now()) {
    const cutoff = now - this.windowMs;
    const prev = this.buckets.get(key) || [];
    const recent = prev.filter((ts) => ts > cutoff);
    if (recent.length >= this.maxRequests) {
      const oldest = recent[0] ?? now;
      const retryAfterSeconds = Math.max(1, Math.ceil((oldest + this.windowMs - now) / 1e3));
      this.buckets.set(key, recent);
      return {
        allowed: false,
        remaining: 0,
        limit: this.maxRequests,
        retryAfterSeconds
      };
    }
    recent.push(now);
    if (!this.buckets.has(key) && this.buckets.size >= this.maxKeys) {
      const oldestKey = this.buckets.keys().next().value;
      if (oldestKey !== void 0) this.buckets.delete(oldestKey);
    }
    this.buckets.set(key, recent);
    return {
      allowed: true,
      remaining: Math.max(0, this.maxRequests - recent.length),
      limit: this.maxRequests,
      retryAfterSeconds: 0
    };
  }
};
function createProxyRateLimitMiddleware(limiter, message) {
  return (req, res, next) => {
    const authUser = req.authUser;
    const key = authUser ? `uid:${authUser.uid}` : `ip:${normalizeClientIp(req.ip || req.socket?.remoteAddress)}`;
    const decision = limiter.consume(key);
    res.setHeader("X-Proxy-RateLimit-Limit", String(decision.limit));
    res.setHeader("X-Proxy-RateLimit-Remaining", String(decision.remaining));
    if (!decision.allowed) {
      res.setHeader("Retry-After", String(decision.retryAfterSeconds));
      res.status(429).json({
        kind: "rate_limited",
        error: message,
        retryAfterSeconds: decision.retryAfterSeconds
      });
      return;
    }
    next();
  };
}
function buildCspHeader() {
  return [
    "default-src 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    "frame-ancestors 'self' https://aistudio.google.com https://*.google.com https://*.googleusercontent.com",
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://apis.google.com https://www.gstatic.com https://accounts.google.com blob:",
    "worker-src 'self' blob:",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' data: https://fonts.gstatic.com",
    "img-src 'self' data: blob: https:",
    "media-src 'self' blob: https:",
    "connect-src 'self' blob: data: https://*.googleapis.com https://*.firebaseio.com https://*.cloudfunctions.net https://*.firebaseapp.com https://firebasestorage.googleapis.com https://accounts.google.com https://oauth2.googleapis.com https://securetoken.googleapis.com https://identitytoolkit.googleapis.com wss://*.firebaseio.com https://open.spotify.com https://api.spotify.com",
    "frame-src 'self' https://drive.google.com https://docs.google.com https://www.youtube.com https://www.youtube-nocookie.com https://open.spotify.com https://embed.podcasts.apple.com https://player.vimeo.com https://view.officeapps.live.com https://www.instagram.com https://www.tiktok.com https://accounts.google.com https://*.firebaseapp.com",
    "form-action 'self' https://accounts.spotify.com https://accounts.google.com"
  ].join("; ");
}
function geminiRateLimiter(req, res, next) {
  const identity = resolveQuotaIdentity(req);
  const decision = aiQuotaManager.checkAndConsume(identity);
  res.setHeader("X-AI-Quota-Tier", decision.tier);
  res.setHeader("X-AI-Quota-Limit", String(decision.dayLimit));
  res.setHeader("X-AI-Quota-Remaining", String(Math.max(0, decision.dayLimit - decision.dayUsed)));
  if (!decision.allowed) {
    res.setHeader("Retry-After", String(decision.retryAfterSeconds));
    res.status(429).json({
      error: decision.reason || "Limite de uso de IA atingido. Tente novamente em instantes.",
      quota: decision
    });
    return;
  }
  next();
}
function formatGeminiError(err) {
  const rawMessage = err instanceof Error ? err.message : String(err);
  if (rawMessage === "GEMINI_KEY_MISSING") {
    return {
      status: 503,
      message: "A chave da API Gemini ainda n\xE3o est\xE1 dispon\xEDvel neste ambiente. Verifique o painel Settings > Secrets."
    };
  }
  const lower = rawMessage.toLowerCase();
  if (lower.includes("api_key_invalid") || lower.includes("api key not valid")) {
    return {
      status: 400,
      message: "A chave da API Gemini configurada est\xE1 inv\xE1lida. Verifique no painel Settings > Secrets."
    };
  }
  if (lower.includes("permission_denied") || lower.includes("403")) {
    return {
      status: 403,
      message: "Permiss\xE3o negada ao acessar o Gemini. Verifique a chave configurada em Settings > Secrets."
    };
  }
  if (lower.includes("resource_exhausted") || lower.includes("429") || lower.includes("quota")) {
    return {
      status: 429,
      message: "Limite tempor\xE1rio de uso da API Gemini atingido. Aguarde alguns instantes e tente novamente."
    };
  }
  if (lower.includes("not_found") || lower.includes("404")) {
    return {
      status: 404,
      message: "Modelo ou recurso n\xE3o encontrado no Gemini. Tente novamente em instantes."
    };
  }
  return {
    status: 500,
    message: rawMessage || "N\xE3o foi poss\xEDvel gerar o resumo com o Gemini agora."
  };
}
function extractGroundingLinks(response) {
  const res = response;
  const chunks = res?.candidates?.[0]?.groundingMetadata?.groundingChunks || [];
  const seen = /* @__PURE__ */ new Set();
  const links = [];
  for (const chunk of chunks) {
    const uri = chunk?.web?.uri;
    if (uri && !seen.has(uri)) {
      seen.add(uri);
      links.push({
        uri,
        title: chunk.web?.title || uri
      });
    }
  }
  return links;
}
var VIDEO_SYSTEM_INSTRUCTION = `Voc\xEA \xE9 um tutor especialista em concursos p\xFAblicos brasileiros (especialmente ALEPA 2026 \xB7 Banca Funda\xE7\xE3o CETAP).
Sua tarefa \xE9 resumir o conte\xFAdo de videoaulas em portugu\xEAs do Brasil claro, objetivo e did\xE1tico para estudo r\xE1pido.

Formato recomendado (use quando os tempos e t\xF3picos estiverem dispon\xEDveis no v\xEDdeo ou na transcri\xE7\xE3o):
1. Comece com um par\xE1grafo curto de abertura explicando o tema central e eventuais mnem\xF4nicos (ex.: "O v\xEDdeo explica ... (0:00-0:37).").
2. Liste os principais t\xF3picos em blocos claros no padr\xE3o:
   **Nome do T\xF3pico (MM:SS-MM:SS):** Explica\xE7\xE3o direta, precisa e focada em o que cai em prova.
3. Finalize com uma se\xE7\xE3o curta **"Pontos de Aten\xE7\xE3o \xB7 Banca CETAP"** com 3 a 5 dicas objetivas de revis\xE3o/pegadinhas.

Regras:
- Nunca invente minutagens se elas n\xE3o puderem ser observadas no v\xEDdeo ou no texto enviado; se n\xE3o houver minutagens exatas dispon\xEDveis, organize por t\xF3picos numerados sem inventar hor\xE1rios.
- Seja fiel ao conte\xFAdo jur\xEDdico/t\xE9cnico e destaque artigos constitucionais/legais citados.`;
var PDF_SYSTEM_INSTRUCTION = `Voc\xEA \xE9 um tutor especialista em concursos p\xFAblicos brasileiros (ALEPA 2026 \xB7 Banca Funda\xE7\xE3o CETAP).
Sua tarefa \xE9 resumir apostilas, editais, leis e materiais em PDF em portugu\xEAs do Brasil claro e estruturado.

Formato da resposta:
1. **Vis\xE3o Geral do Documento:** S\xEDntese em 2 a 4 linhas do tema central e objetivo do material.
2. **Resumo Estruturado por T\xF3picos / Se\xE7\xF5es:** Organize os principais conceitos, regras, prazos, artigos e defini\xE7\xF5es em t\xF3picos claros com **t\xEDtulos em negrito**.
3. **Artigos, Prazos e Exce\xE7\xF5es Importantes:** Liste n\xFAmeros, qu\xF3runs, compet\xEAncias ou exce\xE7\xF5es legais relevantes para quest\xF5es objetivas.
4. **Resumo Rel\xE2mpago para Revis\xE3o (CETAP):** 3 a 5 bullets curtos com o que mais costuma ser cobrado em prova.`;
async function createApp(options) {
  const app = express();
  app.disable("x-powered-by");
  app.set(
    "trust proxy",
    options?.trustProxyHops !== void 0 ? options.trustProxyHops : resolveTrustProxyHops()
  );
  const cspHeader = buildCspHeader();
  app.use((_req, res, next) => {
    res.setHeader("Content-Security-Policy", cspHeader);
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
    res.setHeader("X-DNS-Prefetch-Control", "off");
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin-allow-popups");
    next();
  });
  const pdfProxyLimiter = new ProxyRateLimiter({
    maxRequests: options?.proxyMaxPerMinute ?? 60,
    windowMs: 6e4
  });
  const readerProxyLimiter = new ProxyRateLimiter({
    maxRequests: options?.proxyMaxPerMinute ?? 45,
    windowMs: 6e4
  });
  const spotifyResolveLimiter = new ProxyRateLimiter({
    maxRequests: options?.proxyMaxPerMinute ?? 30,
    windowMs: 6e4
  });
  const aiJson = express.json({ limit: "28mb" });
  const smallJson = express.json({ limit: "100kb" });
  app.use("/api/gemini", attachOptionalAuth, geminiRateLimiter, aiJson);
  app.use("/api/ai", attachOptionalAuth, aiJson);
  app.use("/api/admin", aiJson);
  app.use(smallJson);
  app.use(
    "/api/materials/pdf-proxy",
    attachOptionalAuth,
    createProxyRateLimitMiddleware(
      pdfProxyLimiter,
      "Muitas solicita\xE7\xF5es de leitura de PDF em sequ\xEAncia. Aguarde alguns segundos e tente novamente."
    )
  );
  app.use(
    "/api/materials/reader-proxy",
    attachOptionalAuth,
    createProxyRateLimitMiddleware(
      readerProxyLimiter,
      "Muitas solicita\xE7\xF5es de leitura no leitor em sequ\xEAncia. Aguarde alguns segundos e tente novamente."
    )
  );
  app.use(
    "/api/spotify/resolve",
    attachOptionalAuth,
    createProxyRateLimitMiddleware(
      spotifyResolveLimiter,
      "Muitas consultas ao Spotify em sequ\xEAncia. Aguarde alguns segundos e tente novamente."
    )
  );
  app.get("/api/health", (_req, res) => {
    res.json({ ok: true, model: GEMINI_MODEL });
  });
  app.get("/api/ai/usage", (req, res) => {
    const identity = resolveQuotaIdentity(req);
    const snapshot = aiQuotaManager.getUsage(identity);
    res.json({
      authenticated: Boolean(req.authUser),
      role: req.authUser?.role || "guest",
      usage: snapshot
    });
  });
  app.get("/api/spotify/status", (_req, res) => {
    const { clientId, clientSecret } = getSpotifyCredentials();
    const redirectUri = getSpotifyRedirectUri();
    res.json({
      configured: Boolean(clientId && clientSecret),
      redirectUri,
      scopes: SPOTIFY_SCOPES.split(" ")
    });
  });
  app.get("/api/spotify/auth/url", (_req, res) => {
    const { clientId, clientSecret } = getSpotifyCredentials();
    const redirectUri = getSpotifyRedirectUri();
    if (!clientId || !clientSecret) {
      res.status(503).json({
        configured: false,
        redirectUri,
        error: "Credenciais do Spotify (SPOTIFY_CLIENT_ID e SPOTIFY_CLIENT_SECRET) ainda n\xE3o configuradas nas vari\xE1veis de ambiente."
      });
      return;
    }
    cleanupExpiredSpotifyStates();
    const state = crypto2.randomBytes(24).toString("hex");
    pendingSpotifyStates.set(state, { createdAt: Date.now(), redirectUri });
    const params = new URLSearchParams({
      response_type: "code",
      client_id: clientId,
      scope: SPOTIFY_SCOPES,
      redirect_uri: redirectUri,
      state,
      show_dialog: "true"
    });
    res.json({
      configured: true,
      redirectUri,
      url: `https://accounts.spotify.com/authorize?${params.toString()}`
    });
  });
  const handleSpotifyCallback = async (req, res) => {
    const code = typeof req.query.code === "string" ? req.query.code : "";
    const state = typeof req.query.state === "string" ? req.query.state : "";
    const oauthError = typeof req.query.error === "string" ? req.query.error : "";
    const sendPopupHtml = (messagePayload, titleText, bodyText) => {
      const serialized = serializeForInlineScript(messagePayload);
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.send(`<!doctype html>
<html lang="pt-BR">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>${titleText}</title>
    <style>
      body { font-family: system-ui, -apple-system, sans-serif; background: #f8fafc; color: #0f172a; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 24px; }
      .card { background: #fff; border: 1px solid #e2e8f0; border-radius: 16px; padding: 24px; max-width: 420px; width: 100%; text-align: center; }
      h1 { font-size: 18px; margin: 0 0 8px; color: #0b3321; }
      p { font-size: 14px; color: #475569; margin: 0 0 16px; line-height: 1.5; }
      a { display: inline-block; padding: 10px 16px; background: #0b3321; color: #fff; text-decoration: none; border-radius: 10px; font-size: 13px; font-weight: 600; }
    </style>
  </head>
  <body>
    <div class="card">
      <h1>${titleText}</h1>
      <p>${bodyText}</p>
      <a href="/">Voltar para o Concurso ALEPA 2026</a>
    </div>
    <script>
      (function () {
        var msg = ${serialized};
        try {
          if (window.opener) {
            window.opener.postMessage(msg, '*');
            window.close();
          }
        } catch (e) {}
      })();
    </script>
  </body>
</html>`);
    };
    if (oauthError) {
      sendPopupHtml(
        { type: "SPOTIFY_OAUTH_ERROR", error: oauthError },
        "Conex\xE3o Spotify cancelada",
        "A autoriza\xE7\xE3o foi cancelada ou negada no Spotify. Voc\xEA pode fechar esta janela e tentar novamente."
      );
      return;
    }
    cleanupExpiredSpotifyStates();
    const stateRecord = state ? pendingSpotifyStates.get(state) : void 0;
    if (!code || !state || !stateRecord) {
      sendPopupHtml(
        {
          type: "SPOTIFY_OAUTH_ERROR",
          error: "Sess\xE3o de autentica\xE7\xE3o expirada ou inv\xE1lida. Tente conectar novamente."
        },
        "Sess\xE3o expirada",
        'N\xE3o foi poss\xEDvel validar o retorno do Spotify. Feche esta janela e clique em "Conectar com Spotify" novamente.'
      );
      return;
    }
    pendingSpotifyStates.delete(state);
    const { clientId, clientSecret } = getSpotifyCredentials();
    if (!clientId || !clientSecret) {
      sendPopupHtml(
        { type: "SPOTIFY_OAUTH_ERROR", error: "Credenciais do Spotify n\xE3o configuradas no servidor." },
        "Configura\xE7\xE3o pendente",
        "As credenciais SPOTIFY_CLIENT_ID e SPOTIFY_CLIENT_SECRET n\xE3o foram encontradas no servidor."
      );
      return;
    }
    try {
      const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString("base64");
      const tokenBody = new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: stateRecord.redirectUri
      });
      const tokenRes = await fetch("https://accounts.spotify.com/api/token", {
        method: "POST",
        headers: {
          Authorization: `Basic ${basicAuth}`,
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: tokenBody.toString(),
        signal: AbortSignal.timeout(1e4)
      });
      const tokenJson = await tokenRes.json();
      if (!tokenRes.ok || !tokenJson.access_token) {
        sendPopupHtml(
          {
            type: "SPOTIFY_OAUTH_ERROR",
            error: tokenJson.error_description || tokenJson.error || "Falha ao trocar c\xF3digo no Spotify."
          },
          "Erro ao autenticar no Spotify",
          tokenJson.error_description || "N\xE3o foi poss\xEDvel concluir a autentica\xE7\xE3o com o Spotify."
        );
        return;
      }
      const meResult = await fetchSpotifyApi("/me", tokenJson.access_token);
      const expiresAt = Date.now() + Math.max(60, (tokenJson.expires_in || 3600) - 60) * 1e3;
      sendPopupHtml(
        {
          type: "SPOTIFY_OAUTH_SUCCESS",
          payload: {
            accessToken: tokenJson.access_token,
            refreshToken: tokenJson.refresh_token || "",
            expiresAt,
            scope: tokenJson.scope || SPOTIFY_SCOPES,
            user: meResult.ok && meResult.data ? {
              id: meResult.data.id,
              displayName: meResult.data.display_name || meResult.data.id,
              email: meResult.data.email || "",
              product: meResult.data.product || "free",
              avatarUrl: meResult.data.images?.[0]?.url || "",
              profileUrl: meResult.data.external_urls?.spotify || "https://open.spotify.com"
            } : null
          }
        },
        "Spotify conectado!",
        "Sua conta Spotify foi conectada ao Concurso ALEPA 2026. Esta janela ser\xE1 fechada automaticamente."
      );
    } catch (err) {
      sendPopupHtml(
        {
          type: "SPOTIFY_OAUTH_ERROR",
          error: err instanceof Error ? err.message : "Erro interno ao concluir OAuth do Spotify."
        },
        "Erro na conex\xE3o",
        "Ocorreu um erro inesperado ao comunicar com o Spotify. Feche esta janela e tente novamente."
      );
    }
  };
  app.get(["/api/spotify/callback", "/api/spotify/callback/"], handleSpotifyCallback);
  app.post("/api/spotify/refresh", async (req, res) => {
    try {
      const refreshToken = typeof req.body?.refreshToken === "string" ? req.body.refreshToken.trim() : "";
      if (!refreshToken) {
        res.status(400).json({ error: "Refresh token n\xE3o informado." });
        return;
      }
      const { clientId, clientSecret } = getSpotifyCredentials();
      if (!clientId || !clientSecret) {
        res.status(503).json({ error: "Credenciais do Spotify n\xE3o configuradas no servidor." });
        return;
      }
      const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString("base64");
      const tokenBody = new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: refreshToken
      });
      const tokenRes = await fetch("https://accounts.spotify.com/api/token", {
        method: "POST",
        headers: {
          Authorization: `Basic ${basicAuth}`,
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: tokenBody.toString(),
        signal: AbortSignal.timeout(1e4)
      });
      const tokenJson = await tokenRes.json();
      if (!tokenRes.ok || !tokenJson.access_token) {
        res.status(401).json({
          error: tokenJson.error_description || tokenJson.error || "Sess\xE3o Spotify expirada. Reconecte sua conta."
        });
        return;
      }
      const expiresAt = Date.now() + Math.max(60, (tokenJson.expires_in || 3600) - 60) * 1e3;
      res.json({
        accessToken: tokenJson.access_token,
        refreshToken: tokenJson.refresh_token || refreshToken,
        expiresAt
      });
    } catch (err) {
      res.status(500).json({
        error: err instanceof Error ? err.message : "Erro ao renovar token do Spotify."
      });
    }
  });
  app.get("/api/spotify/me", async (req, res) => {
    const token = extractSpotifyBearer(req);
    if (!token) {
      res.status(401).json({ error: "Token do Spotify n\xE3o enviado." });
      return;
    }
    const result = await fetchSpotifyApi("/me", token);
    if (!result.ok || !result.data) {
      res.status(result.status).json({ error: result.error });
      return;
    }
    res.json({
      id: result.data.id,
      displayName: result.data.display_name || result.data.id,
      email: result.data.email || "",
      product: result.data.product || "free",
      avatarUrl: result.data.images?.[0]?.url || "",
      profileUrl: result.data.external_urls?.spotify || "https://open.spotify.com"
    });
  });
  app.get("/api/spotify/search", async (req, res) => {
    const token = extractSpotifyBearer(req);
    if (!token) {
      res.status(401).json({ error: "Conecte sua conta Spotify para pesquisar." });
      return;
    }
    const q = typeof req.query.q === "string" ? req.query.q.trim() : "";
    const types = typeof req.query.type === "string" && req.query.type.trim() ? req.query.type.trim() : "episode,show,playlist,track";
    if (!q) {
      res.status(400).json({ error: "Informe um termo para pesquisar no Spotify." });
      return;
    }
    const params = new URLSearchParams({
      q,
      type: types,
      market: "BR",
      limit: "10"
    });
    const result = await fetchSpotifyApi(`/search?${params.toString()}`, token);
    if (!result.ok) {
      res.status(result.status).json({ error: result.error });
      return;
    }
    res.json(result.data);
  });
  app.get("/api/spotify/library", async (req, res) => {
    const token = extractSpotifyBearer(req);
    if (!token) {
      res.status(401).json({ error: "Conecte sua conta Spotify para carregar sua biblioteca." });
      return;
    }
    const [showsRes, episodesRes, playlistsRes] = await Promise.all([
      fetchSpotifyApi("/me/shows?limit=20", token),
      fetchSpotifyApi("/me/episodes?market=BR&limit=20", token),
      fetchSpotifyApi("/me/playlists?limit=20", token)
    ]);
    if (showsRes.status === 401 || episodesRes.status === 401 || playlistsRes.status === 401) {
      res.status(401).json({ error: "SPOTIFY_TOKEN_EXPIRED" });
      return;
    }
    res.json({
      shows: showsRes.ok ? showsRes.data?.items || [] : [],
      episodes: episodesRes.ok ? episodesRes.data?.items || [] : [],
      playlists: playlistsRes.ok ? playlistsRes.data?.items || [] : []
    });
  });
  app.get("/api/spotify/shows/:id/episodes", async (req, res) => {
    const token = extractSpotifyBearer(req);
    if (!token) {
      res.status(401).json({ error: "Token do Spotify n\xE3o enviado." });
      return;
    }
    const showId = encodeURIComponent(String(req.params.id || "").trim());
    const result = await fetchSpotifyApi(
      `/shows/${showId}/episodes?market=BR&limit=20`,
      token
    );
    if (!result.ok) {
      res.status(result.status).json({ error: result.error });
      return;
    }
    res.json({ items: result.data?.items || [] });
  });
  app.get("/api/spotify/users/:userId/playlists", async (req, res) => {
    const userId = String(req.params.userId || "").trim();
    if (!userId) {
      res.status(400).json({ error: "ID de usu\xE1rio do Spotify n\xE3o informado." });
      return;
    }
    const token = extractSpotifyBearer(req) || await getSpotifyAppToken();
    if (!token) {
      res.status(200).json({ items: [], requiresAuth: true });
      return;
    }
    const result = await fetchSpotifyApi(
      `/users/${encodeURIComponent(userId)}/playlists?limit=20`,
      token
    );
    if (!result.ok) {
      res.status(result.status).json({ error: result.error, items: [] });
      return;
    }
    res.json({ items: result.data?.items || [], requiresAuth: false });
  });
  app.get("/api/spotify/resolve", async (req, res) => {
    const rawUrl = typeof req.query.url === "string" ? req.query.url.trim() : "";
    if (!rawUrl) {
      res.status(400).json({ error: "Informe um link do Spotify para resolver." });
      return;
    }
    const parsed = parseSpotifyTarget(rawUrl);
    if (parsed.kind === "home") {
      res.json({
        kind: "home",
        canonicalUrl: parsed.canonicalUrl,
        title: "Spotify Web (Brasil / PT)"
      });
      return;
    }
    if (parsed.kind === "unknown" || !parsed.id) {
      res.status(400).json({
        error: "Link do Spotify n\xE3o reconhecido. Cole um link de perfil (open.spotify.com/user/...), epis\xF3dio, podcast, playlist ou faixa."
      });
      return;
    }
    const token = extractSpotifyBearer(req) || await getSpotifyAppToken();
    if (parsed.kind === "user") {
      let displayName = parsed.id;
      let avatarUrl = "";
      let playlists = [];
      if (token) {
        const [profileRes, playlistsRes] = await Promise.all([
          fetchSpotifyApi(`/users/${encodeURIComponent(parsed.id)}`, token),
          fetchSpotifyApi(
            `/users/${encodeURIComponent(parsed.id)}/playlists?limit=20`,
            token
          )
        ]);
        if (profileRes.ok && profileRes.data) {
          displayName = profileRes.data.display_name || parsed.id;
          avatarUrl = profileRes.data.images?.[0]?.url || "";
        }
        if (playlistsRes.ok && playlistsRes.data?.items) {
          playlists = playlistsRes.data.items;
        }
      } else {
        try {
          const pageRes = await fetch(parsed.canonicalUrl, {
            headers: { "User-Agent": "Mozilla/5.0" },
            redirect: "error",
            signal: AbortSignal.timeout(8e3)
          });
          if (pageRes.ok) {
            const html = await readBoundedTextResponse(pageRes, 512 * 1024);
            const ogTitle = html.match(/<meta property="og:title" content="([^"]*)"/i)?.[1];
            const ogImage = html.match(/<meta property="og:image" content="([^"]*)"/i)?.[1];
            if (ogTitle) displayName = decodeHtmlEntities(ogTitle);
            if (ogImage && /^https?:\/\//i.test(ogImage)) avatarUrl = ogImage;
          }
        } catch {
        }
      }
      res.json({
        kind: "user",
        user: {
          id: parsed.id,
          displayName,
          profileUrl: parsed.canonicalUrl,
          avatarUrl
        },
        playlists,
        hasApiPlaylists: Boolean(token)
      });
      return;
    }
    if (token) {
      const apiPathMap = {
        episode: `/episodes/${encodeURIComponent(parsed.id)}?market=BR`,
        show: `/shows/${encodeURIComponent(parsed.id)}?market=BR`,
        playlist: `/playlists/${encodeURIComponent(parsed.id)}?market=BR`,
        track: `/tracks/${encodeURIComponent(parsed.id)}?market=BR`,
        album: `/albums/${encodeURIComponent(parsed.id)}?market=BR`
      };
      const apiRes = await fetchSpotifyApi(apiPathMap[parsed.kind], token);
      if (apiRes.ok && apiRes.data) {
        const d = apiRes.data;
        const images = d.images || d.show?.images || d.album?.images;
        const subtitle = d.show?.name || d.publisher || d.owner?.display_name || d.artists?.map((a) => a.name).filter(Boolean).join(", ") || "Spotify";
        res.json({
          kind: "media",
          item: {
            id: parsed.id,
            kind: parsed.kind === "album" ? "playlist" : parsed.kind,
            title: String(d.name || "Conte\xFAdo Spotify"),
            subtitle: String(subtitle),
            description: typeof d.description === "string" ? d.description : "",
            url: parsed.canonicalUrl,
            embedUrl: `https://open.spotify.com/embed/${parsed.kind}/${parsed.id}?utm_source=generator`,
            imageUrl: images?.[0]?.url || "",
            durationMs: typeof d.duration_ms === "number" ? d.duration_ms : void 0,
            releaseDate: typeof d.release_date === "string" ? d.release_date : void 0
          }
        });
        return;
      }
    }
    try {
      const oembedRes = await fetch(
        `https://open.spotify.com/oembed?url=${encodeURIComponent(parsed.canonicalUrl)}`,
        { signal: AbortSignal.timeout(8e3) }
      );
      if (oembedRes.ok) {
        const oembed = await oembedRes.json();
        res.json({
          kind: "media",
          item: {
            id: parsed.id,
            kind: parsed.kind === "album" ? "playlist" : parsed.kind,
            title: oembed.title || `Spotify ${parsed.kind}`,
            subtitle: oembed.provider_name || "Spotify",
            url: parsed.canonicalUrl,
            embedUrl: oembed.iframe_url || `https://open.spotify.com/embed/${parsed.kind}/${parsed.id}?utm_source=generator`,
            imageUrl: oembed.thumbnail_url || ""
          }
        });
        return;
      }
    } catch {
    }
    res.json({
      kind: "media",
      item: {
        id: parsed.id,
        kind: parsed.kind === "album" ? "playlist" : parsed.kind,
        title: `Conte\xFAdo Spotify (${parsed.kind})`,
        subtitle: "Spotify",
        url: parsed.canonicalUrl,
        embedUrl: `https://open.spotify.com/embed/${parsed.kind}/${parsed.id}?utm_source=generator`
      }
    });
  });
  app.post("/api/gemini/summarize-video", async (req, res) => {
    try {
      const body = req.body || {};
      const rawUrl = typeof body.url === "string" ? normalizeRemoteUrlInput(body.url) : "";
      const title = typeof body.title === "string" ? body.title.trim() : "";
      const transcriptOrNotes = typeof body.transcriptOrNotes === "string" ? body.transcriptOrNotes.trim() : "";
      const disciplineName = typeof body.disciplineName === "string" ? body.disciplineName.trim() : "";
      const customFocus = typeof body.customFocus === "string" ? body.customFocus.trim() : "";
      if (!rawUrl && !transcriptOrNotes) {
        res.status(400).json({
          error: "Informe o link do v\xEDdeo (YouTube, Instagram, TikTok) ou cole anota\xE7\xF5es/transcri\xE7\xE3o para resumir."
        });
        return;
      }
      const videoCacheKey = AiResponseCache.buildKey("summarize-video", {
        rawUrl,
        title,
        transcriptOrNotes,
        disciplineName,
        customFocus
      });
      const cachedVideo = aiResponseCache.get(videoCacheKey);
      if (cachedVideo) {
        aiQuotaManager.recordCacheHit(resolveQuotaIdentity(req));
        res.json({ ...cachedVideo, cached: true });
        return;
      }
      const ai = getGeminiClient();
      const ytId = rawUrl ? extractYouTubeId(rawUrl) : null;
      const canonicalYtUrl = ytId ? `https://www.youtube.com/watch?v=${ytId}` : null;
      const userPromptParts = [
        title ? `T\xEDtulo informado: ${title}` : "",
        disciplineName ? `Disciplina de estudo: ${disciplineName}` : "",
        rawUrl ? `Link do v\xEDdeo: ${canonicalYtUrl || rawUrl}` : "",
        customFocus ? `Foco pedido pelo estudante: ${customFocus}` : "",
        transcriptOrNotes ? `Anota\xE7\xF5es / transcri\xE7\xE3o fornecida pelo estudante:
${transcriptOrNotes}` : "Gere um resumo did\xE1tico completo por t\xF3picos (com intervalos de tempo MM:SS-MM:SS sempre que identific\xE1veis no v\xEDdeo)."
      ].filter(Boolean);
      const userPrompt = userPromptParts.join("\n\n");
      if (canonicalYtUrl) {
        try {
          const response = await ai.models.generateContent({
            model: GEMINI_MODEL,
            contents: [
              {
                role: "user",
                parts: [
                  {
                    fileData: {
                      fileUri: canonicalYtUrl,
                      mimeType: "video/mp4"
                    }
                  },
                  { text: userPrompt }
                ]
              }
            ],
            config: {
              systemInstruction: VIDEO_SYSTEM_INSTRUCTION
            }
          });
          const text = response.text?.trim();
          if (text) {
            const payload = {
              summary: text,
              model: GEMINI_MODEL,
              sourceMode: "youtube_video",
              sources: [{ title: title || "V\xEDdeo no YouTube", uri: canonicalYtUrl }]
            };
            aiResponseCache.set(videoCacheKey, payload);
            res.json(payload);
            return;
          }
        } catch (ytErr) {
          console.warn("Fallback ap\xF3s an\xE1lise direta do YouTube:", ytErr instanceof Error ? ytErr.message : ytErr);
        }
      }
      if (rawUrl) {
        try {
          const response = await ai.models.generateContent({
            model: GEMINI_MODEL,
            contents: `${userPrompt}

Se n\xE3o for poss\xEDvel ler diretamente o \xE1udio/v\xEDdeo deste link externo, deixe claro o que p\xF4de ser obtido pela p\xE1gina/pesquisa ou pelas anota\xE7\xF5es enviadas, e ajude o estudante com uma explica\xE7\xE3o completa do tema identificado.`,
            config: {
              systemInstruction: VIDEO_SYSTEM_INSTRUCTION,
              tools: [{ urlContext: {} }, { googleSearch: {} }]
            }
          });
          const text = response.text?.trim();
          if (text) {
            const links = extractGroundingLinks(response);
            const payload = {
              summary: text,
              model: GEMINI_MODEL,
              sourceMode: "url_context",
              sources: links.length > 0 ? links : [{ title: title || "Link do v\xEDdeo", uri: rawUrl }]
            };
            aiResponseCache.set(videoCacheKey, payload);
            res.json(payload);
            return;
          }
        } catch (urlErr) {
          if (!transcriptOrNotes) {
            throw urlErr;
          }
        }
      }
      const fallbackResponse = await ai.models.generateContent({
        model: GEMINI_MODEL,
        contents: userPrompt,
        config: {
          systemInstruction: VIDEO_SYSTEM_INSTRUCTION
        }
      });
      const notesPayload = {
        summary: fallbackResponse.text?.trim() || "N\xE3o foi poss\xEDvel gerar texto para este v\xEDdeo.",
        model: GEMINI_MODEL,
        sourceMode: "notes_only",
        sources: rawUrl ? [{ title: title || "Link informado", uri: rawUrl }] : []
      };
      aiResponseCache.set(videoCacheKey, notesPayload);
      res.json(notesPayload);
    } catch (err) {
      const mapped = formatGeminiError(err);
      res.status(mapped.status).json({ error: mapped.message });
    }
  });
  app.post("/api/gemini/summarize-pdf", async (req, res) => {
    try {
      const body = req.body || {};
      const fileName = typeof body.fileName === "string" ? body.fileName.trim() : "documento.pdf";
      const title = typeof body.title === "string" ? body.title.trim() : "";
      const disciplineName = typeof body.disciplineName === "string" ? body.disciplineName.trim() : "";
      const customFocus = typeof body.customFocus === "string" ? body.customFocus.trim() : "";
      const rawPdfUrl = typeof body.pdfUrl === "string" ? normalizeRemoteUrlInput(body.pdfUrl) : "";
      let base64Data = typeof body.fileBase64 === "string" ? body.fileBase64.trim() : "";
      if (base64Data.includes(",")) {
        base64Data = base64Data.split(",")[1] || "";
      }
      if (!base64Data && !rawPdfUrl) {
        res.status(400).json({
          error: "Envie um arquivo PDF ou informe o link do PDF/material para resumir."
        });
        return;
      }
      const pdfCacheKey = !base64Data && rawPdfUrl ? AiResponseCache.buildKey("summarize-pdf-url", {
        rawPdfUrl,
        title,
        disciplineName,
        customFocus
      }) : null;
      if (pdfCacheKey) {
        const cachedPdf = aiResponseCache.get(pdfCacheKey);
        if (cachedPdf) {
          aiQuotaManager.recordCacheHit(resolveQuotaIdentity(req));
          res.json({ ...cachedPdf, cached: true });
          return;
        }
      }
      const ai = getGeminiClient();
      const promptLines = [
        title ? `T\xEDtulo do material: ${title}` : "",
        fileName ? `Arquivo: ${fileName}` : "",
        disciplineName ? `Disciplina: ${disciplineName}` : "",
        customFocus ? `Foco pedido pelo estudante: ${customFocus}` : "",
        "Fa\xE7a um resumo completo, fiel e bem organizado deste PDF para revis\xE3o de concurso."
      ].filter(Boolean);
      const promptText = promptLines.join("\n");
      let fetchedUrlMode = "pdf_inline";
      if (!base64Data && rawPdfUrl) {
        try {
          const remoteDoc = await safeFetchRemoteDocument(rawPdfUrl, {
            maxBytes: 18 * 1024 * 1024,
            timeoutMs: 15e3,
            acceptKind: "pdf",
            headers: {
              "User-Agent": "MeuCampusALEPA-GeminiSummarizer/1.0",
              Accept: "application/pdf,application/octet-stream;q=0.9,*/*;q=0.5"
            }
          });
          const looksLikePdf = remoteDoc.contentType.includes("application/pdf") || isPdfMagicBuffer(remoteDoc.buffer);
          if (looksLikePdf) {
            base64Data = remoteDoc.buffer.toString("base64");
            fetchedUrlMode = "pdf_inline";
          } else {
            fetchedUrlMode = "url_context";
          }
        } catch (err) {
          if (err instanceof SsrfValidationError && (err.status === 400 || err.status === 403)) {
            res.status(err.status).json({ error: err.message });
            return;
          }
          fetchedUrlMode = "url_context";
        }
      }
      if (base64Data) {
        const approxBytes = Math.floor(base64Data.length * 3 / 4);
        if (approxBytes > 20 * 1024 * 1024) {
          res.status(413).json({
            error: "O PDF excede o limite de 20 MB para envio direto. Divida o arquivo em partes menores."
          });
          return;
        }
        const response = await ai.models.generateContent({
          model: GEMINI_MODEL,
          contents: [
            {
              role: "user",
              parts: [
                {
                  inlineData: {
                    mimeType: "application/pdf",
                    data: base64Data
                  }
                },
                { text: promptText }
              ]
            }
          ],
          config: {
            systemInstruction: PDF_SYSTEM_INSTRUCTION
          }
        });
        const payload = {
          summary: response.text?.trim() || "N\xE3o foi poss\xEDvel extrair texto deste PDF.",
          model: GEMINI_MODEL,
          sourceMode: fetchedUrlMode,
          sources: rawPdfUrl ? [{ title: title || fileName, uri: rawPdfUrl }] : []
        };
        if (pdfCacheKey) {
          aiResponseCache.set(pdfCacheKey, payload);
        }
        res.json(payload);
        return;
      }
      const urlResponse = await ai.models.generateContent({
        model: GEMINI_MODEL,
        contents: `${promptText}

Link do material: ${rawPdfUrl}`,
        config: {
          systemInstruction: PDF_SYSTEM_INSTRUCTION,
          tools: [{ urlContext: {} }]
        }
      });
      const links = extractGroundingLinks(urlResponse);
      const urlPayload = {
        summary: urlResponse.text?.trim() || "N\xE3o foi poss\xEDvel ler o link informado.",
        model: GEMINI_MODEL,
        sourceMode: "url_context",
        sources: links.length > 0 ? links : [{ title: title || rawPdfUrl, uri: rawPdfUrl }]
      };
      if (pdfCacheKey) {
        aiResponseCache.set(pdfCacheKey, urlPayload);
      }
      res.json(urlPayload);
    } catch (err) {
      const mapped = formatGeminiError(err);
      res.status(mapped.status).json({ error: mapped.message });
    }
  });
  app.post("/api/gemini/chat", async (req, res) => {
    try {
      const body = req.body || {};
      const rawMessages = Array.isArray(body.messages) ? body.messages : [];
      const contents = rawMessages.filter((m) => typeof m?.text === "string" && m.text.trim().length > 0).slice(-16).map((m) => ({
        role: m.role === "model" ? "model" : "user",
        parts: [{ text: (m.text || "").trim() }]
      }));
      if (contents.length === 0) {
        res.status(400).json({ error: "Digite uma pergunta para conversar com o Gemini." });
        return;
      }
      const ai = getGeminiClient();
      const campusLabel = body.campus === "medio" ? "N\xEDvel M\xE9dio (Cargo 04 \u2013 Assist\xEAncia Administrativa \xB7 PL.AL.060)" : "N\xEDvel Superior (Cargo 03 \u2013 Assessoramento Legislativo \xB7 PL.AL.102)";
      const libraryItems = Array.isArray(body.libraryContext) ? body.libraryContext.filter((item) => item && typeof item.title === "string" && item.title.trim()).slice(0, 4) : [];
      const libraryBlock = libraryItems.length > 0 ? `MATERIAIS DA BIBLIOTECA SELECIONADOS PELO ESTUDANTE (priorize e cite explicitamente o t\xEDtulo/p\xE1gina quando responder):
${libraryItems.map(
        (item, idx) => `[Fonte ${idx + 1}] ${String(item.title).slice(0, 180)}${item.discipline ? ` (${String(item.discipline).slice(0, 80)})` : ""}
${String(item.excerpt || "").slice(0, 2200)}`
      ).join("\n\n")}` : "";
      const systemParts = [
        `Voc\xEA \xE9 o assistente de estudos Gemini para o Concurso ALEPA 2026 (Banca Funda\xE7\xE3o CETAP), foco em ${campusLabel}.`,
        "Responda sempre em portugu\xEAs do Brasil de forma clara, estruturada e objetiva.",
        "Jamais invente artigos de lei ou fontes n\xE3o fornecidas. Se usar materiais da biblioteca selecionados, cite o t\xEDtulo da fonte correspondente.",
        body.contextTitle ? `Material em foco: ${body.contextTitle}` : "",
        body.contextSummary ? `Use tamb\xE9m como refer\xEAncia o resumo j\xE1 gerado abaixo:
---
${body.contextSummary.slice(0, 8e3)}
---` : "",
        libraryBlock
      ].filter(Boolean);
      const response = await ai.models.generateContent({
        model: GEMINI_MODEL,
        contents,
        config: {
          systemInstruction: systemParts.join("\n\n")
        }
      });
      res.json({
        reply: response.text?.trim() || "N\xE3o consegui gerar uma resposta agora.",
        model: GEMINI_MODEL,
        citedTitles: libraryItems.map((i) => i.title)
      });
    } catch (err) {
      const mapped = formatGeminiError(err);
      res.status(mapped.status).json({ error: mapped.message });
    }
  });
  app.post("/api/gemini/professor", async (req, res) => {
    try {
      const body = req.body || {};
      const action = body.action || "explain_topic";
      const campusLabel = body.campus === "medio" ? "N\xEDvel M\xE9dio (Edital 001/2026 \u2013 Assistente Administrativo / Auxiliar T\xE9cnico Legislativo \xB7 PL.AL.060)" : "N\xEDvel Superior (Edital 002/2026 \u2013 Cargo 03 T\xE9cnico Legislativo / Analista \xB7 PL.AL.102)";
      const disciplineName = (body.disciplineName || "").trim().slice(0, 140);
      const topicTitle = (body.topicTitle || "").trim().slice(0, 220);
      const subtopics = Array.isArray(body.subtopics) ? body.subtopics.map((s) => String(s).trim()).filter(Boolean).slice(0, 20) : [];
      const studentNotes = (body.studentNotes || "").trim().slice(0, 2e3);
      const ai = getGeminiClient();
      const groundingSafetyRule = [
        `Voc\xEA \xE9 o Professor IA do MEU CAMPUS ALEPA 2026 (Banca Funda\xE7\xE3o CETAP), atuando para o edital de ${campusLabel}.`,
        "Responda sempre em portugu\xEAs do Brasil claro, did\xE1tico, direto e rigoroso.",
        "REGRA DE INTEGRIDADE JUR\xCDDICA: NUNCA invente n\xFAmeros de artigos de lei, incisos, leis inexistentes ou datas/prazos sem certeza. Caso mencione alguma norma espec\xEDfica que exija confer\xEAncia no texto atualizado (como Regimento Interno da ALEPA ou Lei Estadual), oriente explicitamente a confer\xEAncia no Banco de Leis da ALEPA ou no Planalto."
      ].join("\n");
      if (action === "generate_flashcards") {
        if (!topicTitle && !disciplineName) {
          res.status(400).json({ error: "Informe a disciplina ou assunto para gerar flashcards." });
          return;
        }
        const prompt = [
          disciplineName ? `Disciplina: ${disciplineName}` : "",
          topicTitle ? `Assunto do Edital: ${topicTitle}` : "",
          subtopics.length ? `Subt\xF3picos: ${subtopics.join("; ")}` : "",
          studentNotes ? `Notas do estudante:
${studentNotes}` : "",
          "Gere exatamente 6 flashcards de revis\xE3o ativa focados em conceitos-chave, distin\xE7\xF5es e pegadinhas cl\xE1ssicas de prova objetiva (estilo Funda\xE7\xE3o CETAP)."
        ].filter(Boolean).join("\n\n");
        const response2 = await ai.models.generateContent({
          model: GEMINI_MODEL,
          contents: prompt,
          config: {
            systemInstruction: groundingSafetyRule,
            responseMimeType: "application/json",
            responseSchema: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  front: { type: Type.STRING, description: "Pergunta curta ou conceito para memoriza\xE7\xE3o ativa" },
                  back: { type: Type.STRING, description: "Resposta objetiva, precisa e did\xE1tica" },
                  tip: { type: Type.STRING, description: "Dica r\xE1pida ou alerta de pegadinha de banca" }
                },
                required: ["front", "back"]
              }
            }
          }
        });
        const parsed = JSON.parse(response2.text || "[]");
        res.json({ action, flashcards: parsed.slice(0, 8), model: GEMINI_MODEL });
        return;
      }
      if (action === "generate_mindmap") {
        if (!topicTitle && !disciplineName) {
          res.status(400).json({ error: "Informe a disciplina ou assunto para gerar o mapa mental." });
          return;
        }
        const prompt = [
          disciplineName ? `Disciplina: ${disciplineName}` : "",
          topicTitle ? `Assunto central: ${topicTitle}` : "",
          subtopics.length ? `Subt\xF3picos do edital: ${subtopics.join("; ")}` : "",
          "Estruture um mapa mental hier\xE1rquico claro em 4 a 6 ramos principais com 3 a 5 palavras-chave/t\xF3picos pr\xE1ticos em cada ramo."
        ].filter(Boolean).join("\n\n");
        const response2 = await ai.models.generateContent({
          model: GEMINI_MODEL,
          contents: prompt,
          config: {
            systemInstruction: groundingSafetyRule,
            responseMimeType: "application/json",
            responseSchema: {
              type: Type.OBJECT,
              properties: {
                centralTopic: { type: Type.STRING },
                branches: {
                  type: Type.ARRAY,
                  items: {
                    type: Type.OBJECT,
                    properties: {
                      title: { type: Type.STRING },
                      items: {
                        type: Type.ARRAY,
                        items: { type: Type.STRING }
                      }
                    },
                    required: ["title", "items"]
                  }
                }
              },
              required: ["centralTopic", "branches"]
            }
          }
        });
        const mindMap = JSON.parse(response2.text || "{}");
        res.json({ action, mindMap, model: GEMINI_MODEL });
        return;
      }
      if (action === "generate_questions") {
        if (!topicTitle && !disciplineName) {
          res.status(400).json({ error: "Informe a disciplina ou assunto para gerar quest\xF5es in\xE9ditas." });
          return;
        }
        const count = Math.max(1, Math.min(5, Number(body.questionCount) || 3));
        const prompt = [
          disciplineName ? `Disciplina: ${disciplineName}` : "",
          topicTitle ? `Assunto do Edital: ${topicTitle}` : "",
          subtopics.length ? `Subt\xF3picos: ${subtopics.join("; ")}` : "",
          `Elabore ${count} quest\xF5es in\xE9ditas de m\xFAltipla escolha (exatamente 5 alternativas A, B, C, D e E, com apenas 1 correta), no padr\xE3o da Funda\xE7\xE3o CETAP.`,
          "Cada quest\xE3o deve conter enunciado claro, 5 alternativas distintas, \xEDndice da resposta correta (0 a 4), explica\xE7\xE3o comentada e refer\xEAncia normativa/conceitual real (sem inventar artigos)."
        ].filter(Boolean).join("\n\n");
        const response2 = await ai.models.generateContent({
          model: GEMINI_MODEL,
          contents: prompt,
          config: {
            systemInstruction: groundingSafetyRule,
            responseMimeType: "application/json",
            responseSchema: {
              type: Type.ARRAY,
              items: {
                type: Type.OBJECT,
                properties: {
                  topicTitle: { type: Type.STRING },
                  statement: { type: Type.STRING },
                  options: {
                    type: Type.ARRAY,
                    items: { type: Type.STRING }
                  },
                  correctIndex: { type: Type.INTEGER },
                  explanation: { type: Type.STRING },
                  legalBasis: { type: Type.STRING }
                },
                required: ["topicTitle", "statement", "options", "correctIndex", "explanation"]
              }
            }
          }
        });
        const rawItems = JSON.parse(response2.text || "[]");
        const questions = rawItems.filter((item) => item.statement && Array.isArray(item.options) && item.options.length === 5).slice(0, 5).map((item, idx) => ({
          id: `ai_q_${Date.now()}_${idx}`,
          topicTitle: (item.topicTitle || topicTitle || disciplineName).slice(0, 200),
          statement: String(item.statement).slice(0, 2400),
          options: item.options.slice(0, 5).map((o) => String(o).slice(0, 480)),
          correctIndex: Math.max(0, Math.min(4, Number(item.correctIndex) || 0)),
          explanation: String(item.explanation || "").slice(0, 1900),
          legalBasis: item.legalBasis ? String(item.legalBasis).slice(0, 380) : void 0,
          originType: "ai_generated",
          isOfficial: false,
          source: "Gerada por IA \xB7 Professor Gemini (Treino In\xE9dito)"
        }));
        res.json({ action, questions, model: GEMINI_MODEL });
        return;
      }
      if (action === "explain_question") {
        const statement = (body.questionStatement || "").trim().slice(0, 2500);
        const options2 = Array.isArray(body.questionOptions) ? body.questionOptions : [];
        if (!statement || options2.length < 2) {
          res.status(400).json({ error: "Envie o enunciado e as alternativas da quest\xE3o para explica\xE7\xE3o." });
          return;
        }
        const letters = ["A", "B", "C", "D", "E"];
        const formattedOptions = options2.slice(0, 5).map((opt, idx) => `${letters[idx] || idx + 1}) ${opt}`).join("\n");
        const correctIdx = typeof body.correctIndex === "number" ? body.correctIndex : 0;
        const selectedIdx = typeof body.selectedIndex === "number" ? body.selectedIndex : void 0;
        const prompt = [
          disciplineName ? `Disciplina: ${disciplineName}` : "",
          topicTitle ? `Assunto: ${topicTitle}` : "",
          `Enunciado:
${statement}`,
          `Alternativas:
${formattedOptions}`,
          `Gabarito oficial: ${letters[correctIdx] || "A"}`,
          selectedIdx !== void 0 ? `Alternativa marcada pelo aluno: ${letters[selectedIdx]}` : "",
          body.legalBasis ? `Refer\xEAncia: ${body.legalBasis}` : "",
          "Explique: (1) Por que a alternativa correta est\xE1 certa; (2) Por que cada alternativa incorreta est\xE1 errada ou traz pegadinha; (3) O ponto-chave para memorizar."
        ].filter(Boolean).join("\n\n");
        const response2 = await ai.models.generateContent({
          model: GEMINI_MODEL,
          contents: prompt,
          config: { systemInstruction: groundingSafetyRule }
        });
        res.json({ action, text: response2.text?.trim() || "", model: GEMINI_MODEL });
        return;
      }
      if (action === "revision_plan") {
        const weakSummary = (body.weakDisciplinesSummary || "").trim().slice(0, 3e3);
        const errorSummary = (body.pendingErrorsSummary || "").trim().slice(0, 3e3);
        const prompt = [
          "Monte um Plano Personalizado de Revis\xE3o para os pr\xF3ximos 7 dias com base exclusivamente nos dados reais do estudante abaixo:",
          weakSummary ? `Desempenho e cobertura por disciplina:
${weakSummary}` : "",
          errorSummary ? `Erros recentes / revis\xF5es pendentes:
${errorSummary}` : "",
          "Estruture em: (1) Diagn\xF3stico objetivo das prioridades; (2) Plano dia a dia (Dia 1 a Dia 7) alternando revis\xE3o ativa, lei seca e baterias curtas; (3) Meta pr\xE1tica mensur\xE1vel."
        ].filter(Boolean).join("\n\n");
        const response2 = await ai.models.generateContent({
          model: GEMINI_MODEL,
          contents: prompt,
          config: { systemInstruction: groundingSafetyRule }
        });
        res.json({ action, text: response2.text?.trim() || "", model: GEMINI_MODEL });
        return;
      }
      if (!topicTitle && !disciplineName) {
        res.status(400).json({ error: "Informe a disciplina ou assunto para explica\xE7\xE3o." });
        return;
      }
      const explainPrompt = [
        disciplineName ? `Disciplina: ${disciplineName}` : "",
        topicTitle ? `Assunto do Edital: ${topicTitle}` : "",
        subtopics.length ? `Subt\xF3picos cobrados no edital: ${subtopics.join("; ")}` : "",
        studentNotes ? `Anota\xE7\xF5es atuais do aluno:
${studentNotes}` : "",
        "Elabore uma aula escrita completa e objetiva com:",
        "## 1. Conceito Central e Vis\xE3o Geral",
        "## 2. Pontos-Chave e Subt\xF3picos do Edital",
        "## 3. Como a Banca Funda\xE7\xE3o CETAP costuma cobrar (Pegadinhas e Exce\xE7\xF5es)",
        "## 4. Resumo Rel\xE2mpago para Revis\xE3o"
      ].filter(Boolean).join("\n\n");
      const response = await ai.models.generateContent({
        model: GEMINI_MODEL,
        contents: explainPrompt,
        config: { systemInstruction: groundingSafetyRule }
      });
      res.json({ action: "explain_topic", text: response.text?.trim() || "", model: GEMINI_MODEL });
    } catch (err) {
      const mapped = formatGeminiError(err);
      res.status(mapped.status).json({ error: mapped.message });
    }
  });
  app.use("/api/admin", geminiRateLimiter);
  app.get(
    "/api/admin/auth-check",
    requireRole(["admin", "editor", "dev"]),
    (req, res) => {
      const authUser = req.authUser;
      res.json({
        ok: true,
        uid: authUser?.uid,
        email: authUser?.email,
        role: authUser?.role
      });
    }
  );
  app.post(
    "/api/admin/authoring",
    requireRole(["admin", "editor", "dev"]),
    async (req, res) => {
      try {
        const body = req.body || {};
        const action = body.action || "draft_question";
        const disciplineName = (body.disciplineName || "").trim().slice(0, 140);
        const campusLevel = body.campusLevel || "superior";
        const title = (body.title || "").trim().slice(0, 180);
        const topicTitle = (body.topicTitle || "").trim().slice(0, 180);
        const contextText = (body.contextText || "").trim().slice(0, 4e3);
        let safeUrl = "";
        if (body.url && body.url.trim()) {
          const normalized = normalizeRemoteUrlInput(body.url);
          try {
            const parsed = await assertSafeRemoteUrl(normalized);
            safeUrl = parsed.toString();
          } catch {
            safeUrl = "";
          }
        }
        const ai = getGeminiClient();
        const adminSystemRule = `Voc\xEA \xE9 um especialista editorial e conteudista do MEU CAMPUS ALEPA 2026 (Concurso ALEPA 2026, Banca Funda\xE7\xE3o CETAP, N\xEDvel Superior PL.AL.102 e N\xEDvel M\xE9dio PL.AL.060).
Regras obrigat\xF3rias:
- Escreva sempre em portugu\xEAs do Brasil claro, preciso e direto.
- Jamais invente n\xFAmeros de artigos, leis ou s\xFAmulas. Se n\xE3o tiver certeza da cita\xE7\xE3o exata, mantenha a refer\xEAncia gen\xE9rica \xE0 norma/conte\xFAdo.
- Todo material gerado entra primeiro como rascunho para revis\xE3o e pr\xE9-visualiza\xE7\xE3o do administrador/editor antes de publicar.`;
        if (action === "draft_material_summary") {
          if (!title && !contextText && !safeUrl) {
            res.status(400).json({ error: "Informe t\xEDtulo, link ou descri\xE7\xE3o base para gerar o rascunho." });
            return;
          }
          const prompt2 = [
            disciplineName ? `Disciplina: ${disciplineName}` : "",
            `N\xEDvel: ${campusLevel}`,
            title ? `T\xEDtulo: ${title}` : "",
            safeUrl ? `URL de refer\xEAncia: ${safeUrl}` : "",
            contextText ? `Contexto fornecido pelo editor:
${contextText}` : "",
            'Gere em JSON: description (resumo did\xE1tico de 2 a 4 linhas para o cart\xE3o do aluno), editalTopic (t\xF3pico sugerido do edital), e relevanceTier ("essencial" | "complementar" | "aprofundamento").'
          ].filter(Boolean).join("\n\n");
          const response2 = await ai.models.generateContent({
            model: GEMINI_MODEL,
            contents: prompt2,
            config: {
              systemInstruction: adminSystemRule,
              responseMimeType: "application/json",
              responseSchema: {
                type: Type.OBJECT,
                properties: {
                  description: { type: Type.STRING },
                  editalTopic: { type: Type.STRING },
                  relevanceTier: { type: Type.STRING }
                },
                required: ["description", "editalTopic", "relevanceTier"]
              }
            }
          });
          const draft = JSON.parse(response2.text || "{}");
          res.json({
            action,
            draft: {
              description: String(draft.description || "").slice(0, 950),
              editalTopic: String(draft.editalTopic || topicTitle || "").slice(0, 220),
              relevanceTier: ["essencial", "complementar", "aprofundamento"].includes(String(draft.relevanceTier)) ? draft.relevanceTier : "essencial"
            },
            model: GEMINI_MODEL
          });
          return;
        }
        if (action === "draft_topic") {
          if (!topicTitle && !disciplineName && !contextText) {
            res.status(400).json({ error: "Informe a disciplina ou tema para estruturar os subt\xF3picos do edital." });
            return;
          }
          const prompt2 = [
            disciplineName ? `Disciplina: ${disciplineName}` : "",
            `Escolaridade: ${campusLevel}`,
            topicTitle ? `T\xEDtulo do t\xF3pico: ${topicTitle}` : "",
            contextText ? `Texto/base do edital:
${contextText}` : "",
            "Estruture este t\xF3pico em JSON com: title (t\xEDtulo limpo e objetivo), subtopics (lista de 4 a 8 subt\xF3picos objetivos cobrados no edital) e highYield (booleano indicando se costuma ter alta cobran\xE7a na CETAP)."
          ].filter(Boolean).join("\n\n");
          const response2 = await ai.models.generateContent({
            model: GEMINI_MODEL,
            contents: prompt2,
            config: {
              systemInstruction: adminSystemRule,
              responseMimeType: "application/json",
              responseSchema: {
                type: Type.OBJECT,
                properties: {
                  title: { type: Type.STRING },
                  subtopics: { type: Type.ARRAY, items: { type: Type.STRING } },
                  highYield: { type: Type.BOOLEAN }
                },
                required: ["title", "subtopics", "highYield"]
              }
            }
          });
          const parsed = JSON.parse(response2.text || "{}");
          res.json({
            action,
            draft: {
              title: String(parsed.title || topicTitle || "Novo T\xF3pico do Edital").slice(0, 220),
              subtopics: Array.isArray(parsed.subtopics) ? parsed.subtopics.slice(0, 12).map((s) => String(s).trim()).filter(Boolean) : [],
              highYield: Boolean(parsed.highYield)
            },
            model: GEMINI_MODEL
          });
          return;
        }
        if (action === "draft_notice") {
          if (!title && !contextText) {
            res.status(400).json({ error: "Informe o assunto ou briefing para redigir o aviso." });
            return;
          }
          const prompt2 = [
            `Escolaridade alvo: ${campusLevel}`,
            title ? `Assunto do aviso: ${title}` : "",
            contextText ? `Informa\xE7\xF5es do aviso:
${contextText}` : "",
            'Redija em JSON um comunicado institucional claro e motivador para os candidatos: title (at\xE9 120 caracteres), body (texto claro em 2 a 4 frases), priority ("normal" | "importante" | "urgente").'
          ].filter(Boolean).join("\n\n");
          const response2 = await ai.models.generateContent({
            model: GEMINI_MODEL,
            contents: prompt2,
            config: {
              systemInstruction: adminSystemRule,
              responseMimeType: "application/json",
              responseSchema: {
                type: Type.OBJECT,
                properties: {
                  title: { type: Type.STRING },
                  body: { type: Type.STRING },
                  priority: { type: Type.STRING }
                },
                required: ["title", "body", "priority"]
              }
            }
          });
          const parsed = JSON.parse(response2.text || "{}");
          res.json({
            action,
            draft: {
              title: String(parsed.title || title || "Comunicado do Campus").slice(0, 160),
              body: String(parsed.body || "").slice(0, 1800),
              priority: ["normal", "importante", "urgente"].includes(String(parsed.priority)) ? parsed.priority : "importante"
            },
            model: GEMINI_MODEL
          });
          return;
        }
        if (!topicTitle && !disciplineName && !contextText) {
          res.status(400).json({ error: "Informe a disciplina, assunto ou texto base para elaborar a quest\xE3o." });
          return;
        }
        const prompt = [
          disciplineName ? `Disciplina: ${disciplineName}` : "",
          `Escolaridade: ${campusLevel}`,
          topicTitle ? `Assunto do edital: ${topicTitle}` : "",
          contextText ? `Texto base / diretriz do editor:
${contextText}` : "",
          "Elabore 1 quest\xE3o in\xE9dita de concurso p\xFAblico (5 alternativas A-E, apenas 1 correta) no padr\xE3o Funda\xE7\xE3o CETAP, com coment\xE1rio explicativo detalhado e refer\xEAncia normativa/conceitual segura."
        ].filter(Boolean).join("\n\n");
        const response = await ai.models.generateContent({
          model: GEMINI_MODEL,
          contents: prompt,
          config: {
            systemInstruction: adminSystemRule,
            responseMimeType: "application/json",
            responseSchema: {
              type: Type.OBJECT,
              properties: {
                topicTitle: { type: Type.STRING },
                statement: { type: Type.STRING },
                options: { type: Type.ARRAY, items: { type: Type.STRING } },
                correctIndex: { type: Type.INTEGER },
                explanation: { type: Type.STRING },
                legalBasis: { type: Type.STRING }
              },
              required: ["topicTitle", "statement", "options", "correctIndex", "explanation"]
            }
          }
        });
        const item = JSON.parse(response.text || "{}");
        const rawOpts = Array.isArray(item.options) ? item.options.slice(0, 5).map((o) => String(o).slice(0, 480)) : [];
        while (rawOpts.length < 5) {
          rawOpts.push(`Alternativa ${rawOpts.length + 1}`);
        }
        res.json({
          action: "draft_question",
          draft: {
            topicTitle: String(item.topicTitle || topicTitle || disciplineName).slice(0, 180),
            statement: String(item.statement || "").slice(0, 2400),
            options: rawOpts,
            correctIndex: Math.max(0, Math.min(4, Number(item.correctIndex) || 0)),
            explanation: String(item.explanation || "").slice(0, 1900),
            legalBasis: item.legalBasis ? String(item.legalBasis).slice(0, 380) : ""
          },
          model: GEMINI_MODEL
        });
      } catch (err) {
        const mapped = formatGeminiError(err);
        res.status(mapped.status).json({ error: mapped.message });
      }
    }
  );
  app.get(
    "/api/storage/health",
    requireRole(["admin", "dev"]),
    (_req, res) => {
      const projectId = FIREBASE_APPLET_CONFIG.projectId;
      const bucket = FIREBASE_APPLET_CONFIG.storageBucket;
      res.json({
        configured: Boolean(bucket && projectId),
        projectId,
        storageBucket: bucket,
        firestoreDatabaseId: FIREBASE_APPLET_CONFIG.firestoreDatabaseId,
        consoleUrl: projectId ? `https://console.firebase.google.com/project/${projectId}/storage` : "",
        geminiConfigured: Boolean(process.env.GEMINI_API_KEY?.trim()),
        spotifyConfigured: Boolean(process.env.SPOTIFY_CLIENT_ID?.trim() && process.env.SPOTIFY_CLIENT_SECRET?.trim()),
        checkedAt: (/* @__PURE__ */ new Date()).toISOString()
      });
    }
  );
  app.post("/api/ai/classify-document", geminiRateLimiter);
  app.post(
    "/api/ai/classify-document",
    requireRole(["admin", "editor", "teacher", "dev"]),
    async (req, res) => {
      try {
        const body = req.body || {};
        const title = (body.title || "").trim().slice(0, 200);
        const fileName = (body.fileName || "").trim().slice(0, 240);
        const sampleSnippet = (body.sampleSnippet || "").trim().slice(0, 3500);
        if (!title && !fileName && !sampleSnippet) {
          res.status(400).json({ error: "Forne\xE7a o t\xEDtulo, nome do arquivo ou trecho do PDF para classifica\xE7\xE3o." });
          return;
        }
        const ai = getGeminiClient();
        const disciplinesList = Array.isArray(body.availableDisciplines) ? body.availableDisciplines.slice(0, 40).map((d) => `${d.id}: ${d.name}`).join("\n") : "";
        const prompt = [
          "Analise os metadados e trecho abaixo para sugerir cataloga\xE7\xE3o pedag\xF3gica (sempre sujeita \xE0 revis\xE3o humana do editor/administrador):",
          title ? `T\xEDtulo atual: ${title}` : "",
          fileName ? `Arquivo: ${fileName}` : "",
          body.metadataTitle ? `T\xEDtulo interno PDF: ${body.metadataTitle}` : "",
          body.metadataAuthor ? `Autor PDF: ${body.metadataAuthor}` : "",
          body.campusLevel ? `Escolaridade informada: ${body.campusLevel}` : "",
          Array.isArray(body.outlineTitles) && body.outlineTitles.length ? `Sum\xE1rio detectado: ${body.outlineTitles.slice(0, 12).join(" | ")}` : "",
          disciplinesList ? `Disciplinas v\xE1lidas (escolha um ID exato se compat\xEDvel):
${disciplinesList}` : "",
          sampleSnippet ? `Trecho extra\xEDdo:
${sampleSnippet}` : "",
          'Retorne JSON com: suggestedTitle, suggestedDisciplineId, suggestedTopic, suggestedCampusLevel ("geral"|"superior"|"medio"), suggestedRelevanceTier ("essencial"|"complementar"|"aprofundamento"), suggestedSummary (2-3 linhas em pt-BR), suggestedKeywords (array de 3 a 8 termos).'
        ].filter(Boolean).join("\n\n");
        const response = await ai.models.generateContent({
          model: GEMINI_MODEL,
          contents: prompt,
          config: {
            systemInstruction: "Voc\xEA \xE9 um especialista de cataloga\xE7\xE3o bibliogr\xE1fica do MEU CAMPUS ALEPA 2026. Nunca invente informa\xE7\xF5es ausentes; baseie-se nos dados reais fornecidos.",
            responseMimeType: "application/json",
            responseSchema: {
              type: Type.OBJECT,
              properties: {
                suggestedTitle: { type: Type.STRING },
                suggestedDisciplineId: { type: Type.STRING },
                suggestedTopic: { type: Type.STRING },
                suggestedCampusLevel: { type: Type.STRING },
                suggestedRelevanceTier: { type: Type.STRING },
                suggestedSummary: { type: Type.STRING },
                suggestedKeywords: { type: Type.ARRAY, items: { type: Type.STRING } }
              },
              required: [
                "suggestedTitle",
                "suggestedDisciplineId",
                "suggestedTopic",
                "suggestedCampusLevel",
                "suggestedRelevanceTier",
                "suggestedSummary",
                "suggestedKeywords"
              ]
            }
          }
        });
        const parsed = JSON.parse(response.text || "{}");
        res.json({
          suggestion: {
            suggestedTitle: String(parsed.suggestedTitle || title || fileName).slice(0, 180),
            suggestedDisciplineId: String(parsed.suggestedDisciplineId || "").slice(0, 80),
            suggestedTopic: String(parsed.suggestedTopic || "").slice(0, 220),
            suggestedCampusLevel: ["geral", "superior", "medio"].includes(String(parsed.suggestedCampusLevel)) ? parsed.suggestedCampusLevel : body.campusLevel || "superior",
            suggestedRelevanceTier: ["essencial", "complementar", "aprofundamento"].includes(
              String(parsed.suggestedRelevanceTier)
            ) ? parsed.suggestedRelevanceTier : "essencial",
            suggestedSummary: String(parsed.suggestedSummary || "").slice(0, 950),
            suggestedKeywords: Array.isArray(parsed.suggestedKeywords) ? parsed.suggestedKeywords.slice(0, 10).map((k) => String(k).trim()).filter(Boolean) : []
          },
          requiresHumanReview: true,
          model: GEMINI_MODEL
        });
      } catch (err) {
        const mapped = formatGeminiError(err);
        res.status(mapped.status).json({ error: mapped.message });
      }
    }
  );
  app.post("/api/ai/split-pdf-disciplines", geminiRateLimiter);
  app.post(
    "/api/ai/split-pdf-disciplines",
    requireRole(["admin", "editor", "teacher", "dev"]),
    async (req, res) => {
      try {
        const body = req.body || {};
        const title = (body.title || "").trim().slice(0, 200);
        const pageCount = Math.max(1, Math.min(2500, Number(body.pageCount) || 100));
        const ai = getGeminiClient();
        const disciplinesList = Array.isArray(body.availableDisciplines) && body.availableDisciplines.length > 0 ? body.availableDisciplines.map((d) => `- ID "${d.id}": ${d.name}`).join("\n") : [
          '- ID "cat_01_portugues": L\xEDngua Portuguesa',
          '- ID "cat_03_informatica": No\xE7\xF5es de Inform\xE1tica',
          '- ID "cat_04_raciocinio_logico": Racioc\xEDnio L\xF3gico',
          '- ID "cat_05_constitucional_adm": Direito Constitucional e Administrativo',
          '- ID "cat_06_processo_legislativo": Processo Legislativo e Regimento Interno',
          '- ID "cat_02_legislacao_etica": Legisla\xE7\xE3o do Estado do Par\xE1 e \xC9tica'
        ].join("\n");
        const hasPageNumbers = Array.isArray(body.outlineWithPages) && body.outlineWithPages.some((o) => typeof o.page === "number" && o.page >= 1);
        const outlineList = Array.isArray(body.outlineWithPages) && body.outlineWithPages.length > 0 ? body.outlineWithPages.map((o) => `* ${o.title} (p\xE1gina ${o.page || "n\xE3o indicada"})`).join("\n") : Array.isArray(body.outlineTitles) && body.outlineTitles.length > 0 ? body.outlineTitles.map((t) => `* ${t}`).join("\n") : "";
        if (!outlineList && !body.sampleSnippet) {
          res.status(400).json({
            error: "Forne\xE7a o sum\xE1rio embutido ou uma amostra textual do PDF para que a IA sugira a divis\xE3o sem inventar n\xFAmeros de p\xE1gina."
          });
          return;
        }
        const prompt = [
          "Voc\xEA \xE9 o arquiteto pedag\xF3gico do MEU CAMPUS ALEPA 2026.",
          "Sua miss\xE3o \xE9 sugerir a organiza\xE7\xE3o de um material em se\xE7\xF5es por disciplina do Edital da ALEPA 2026.",
          `T\xEDtulo do Material: ${title || body.fileName || "Apostila Geral ALEPA 2026"}`,
          `Total de P\xE1ginas do PDF: ${pageCount}`,
          `N\xEDvel do Concurso: ${body.campusLevel || "superior"}`,
          `Disciplinas dispon\xEDveis no sistema:
${disciplinesList}`,
          outlineList ? `Sum\xE1rio / T\xF3picos identificados no documento:
${outlineList}` : "Sum\xE1rio embutido ausente.",
          body.sampleSnippet ? `Amostra de texto:
${body.sampleSnippet.slice(0, 2500)}` : "",
          "Regras estritas de integridade:",
          hasPageNumbers ? "1. Use exclusivamente as p\xE1ginas reais indicadas no sum\xE1rio extra\xEDdo (1 <= startPage <= endPage <= total de p\xE1ginas). N\xE3o invente cap\xEDtulos ausentes." : "1. Como o documento n\xE3o informou p\xE1ginas num\xE9ricas no sum\xE1rio, N\xC3O invente intervalos falsos de p\xE1gina: defina startPage=1 e endPage=1 para que o curador confirme as p\xE1ginas antes de publicar.",
          "2. Associe o disciplineId correspondente da lista de disciplinas.",
          "3. Sugira um t\xEDtulo claro, resumo objetivo e t\xF3picos do edital efetivamente presentes nas evid\xEAncias fornecidas.",
          'Retorne JSON estrito com array "sections".'
        ].filter(Boolean).join("\n\n");
        const response = await ai.models.generateContent({
          model: GEMINI_MODEL,
          contents: prompt,
          config: {
            systemInstruction: "Retorne JSON estruturado com se\xE7\xF5es baseadas apenas nas evid\xEAncias enviadas. Nunca invente p\xE1ginas ou conte\xFAdo inexistente.",
            responseMimeType: "application/json",
            responseSchema: {
              type: Type.OBJECT,
              properties: {
                sections: {
                  type: Type.ARRAY,
                  items: {
                    type: Type.OBJECT,
                    properties: {
                      id: { type: Type.STRING },
                      disciplineId: { type: Type.STRING },
                      disciplineName: { type: Type.STRING },
                      title: { type: Type.STRING },
                      startPage: { type: Type.INTEGER },
                      endPage: { type: Type.INTEGER },
                      summary: { type: Type.STRING },
                      topics: { type: Type.ARRAY, items: { type: Type.STRING } }
                    },
                    required: ["id", "disciplineId", "disciplineName", "title", "startPage", "endPage"]
                  }
                }
              },
              required: ["sections"]
            }
          }
        });
        const parsed = JSON.parse(response.text || '{"sections":[]}');
        const validatedSections = (parsed.sections || []).map((sec, idx) => {
          const sp = hasPageNumbers ? Math.max(1, Math.min(pageCount, Number(sec.startPage) || 1)) : 1;
          const ep = hasPageNumbers ? Math.max(sp, Math.min(pageCount, Number(sec.endPage) || sp)) : 1;
          return {
            id: sec.id || `sec_${idx + 1}`,
            disciplineId: sec.disciplineId || "cat_01_portugues",
            disciplineName: sec.disciplineName || "Disciplina",
            title: sec.title || `Se\xE7\xE3o ${idx + 1}`,
            startPage: sp,
            endPage: ep,
            summary: sec.summary || "",
            topics: Array.isArray(sec.topics) ? sec.topics.slice(0, 10) : [],
            publishedToLibrary: hasPageNumbers,
            requiresPageVerification: !hasPageNumbers
          };
        });
        res.json({
          sections: validatedSections,
          totalSections: validatedSections.length,
          hasVerifiedPageNumbers: hasPageNumbers,
          model: GEMINI_MODEL
        });
      } catch (err) {
        const mapped = formatGeminiError(err);
        res.status(mapped.status).json({ error: mapped.message });
      }
    }
  );
  app.post("/api/ai/organize-material", geminiRateLimiter);
  app.post(
    "/api/ai/organize-material",
    requireRole(["admin", "editor", "teacher", "dev"]),
    async (req, res) => {
      try {
        const body = req.body || {};
        const title = (body.title || "").trim().slice(0, 220);
        const fileName = (body.fileName || "").trim().slice(0, 220);
        const transcriptOrNotes = (body.transcriptOrNotes || "").trim().slice(0, 4e3);
        if (!title && !fileName && !transcriptOrNotes) {
          res.status(400).json({ error: "Informe t\xEDtulo, arquivo ou texto de apoio para organizar o conte\xFAdo." });
          return;
        }
        const ai = getGeminiClient();
        const discText = Array.isArray(body.availableDisciplines) && body.availableDisciplines.length > 0 ? body.availableDisciplines.map((d) => `- "${d.id}": ${d.name}`).join("\n") : "Mantenha o disciplineId compat\xEDvel com o edital ALEPA 2026.";
        const outlineText = Array.isArray(body.outlineWithPages) && body.outlineWithPages.length > 0 ? body.outlineWithPages.map((o) => `* ${o.title}${o.page ? ` (p\xE1g. ${o.page})` : ""}`).join("\n") : Array.isArray(body.outlineTitles) && body.outlineTitles.length > 0 ? body.outlineTitles.map((t) => `* ${t}`).join("\n") : "";
        const prompt = [
          "Voc\xEA \xE9 um curador pedag\xF3gico do MEU CAMPUS ALEPA 2026 (Banca CETAP).",
          "Organize os metadados deste conte\xFAdo para revis\xE3o humana (editor/professor).",
          `T\xEDtulo atual: ${title || "(sem t\xEDtulo)"}`,
          fileName ? `Arquivo: ${fileName}` : "",
          body.resourceType ? `Tipo: ${body.resourceType}` : "",
          `Campus: ${body.campusLevel || "superior"}`,
          body.editalTopic ? `T\xF3pico atual: ${body.editalTopic}` : "",
          body.description ? `Descri\xE7\xE3o atual: ${body.description}` : "",
          body.pageCount ? `Total de p\xE1ginas: ${body.pageCount}` : "",
          body.durationSeconds ? `Dura\xE7\xE3o (seg): ${body.durationSeconds}` : "",
          `Disciplinas dispon\xEDveis:
${discText}`,
          outlineText ? `Sum\xE1rio extra\xEDdo:
${outlineText}` : "",
          transcriptOrNotes ? `Notas / Trecho / Marca\xE7\xF5es fornecidas:
${transcriptOrNotes}` : "",
          "Regras:",
          "- Sugira subtitle (subt\xEDtulo curto), description (resumo did\xE1tico de 2-3 linhas), disciplineId, editalTopic, keywords (m\xE1x 8), studyRecommendations (3 a 5 passos pr\xE1ticos de estudo) e chapters.",
          "- NUNCA invente n\xFAmeros de p\xE1gina ou timestamps (startPage, endPage, startSeconds) se eles N\xC3O estiverem presentes no sum\xE1rio ou nas marca\xE7\xF5es fornecidas; se n\xE3o houver base num\xE9rica, omita startPage/startSeconds.",
          "- Retorne JSON estrito."
        ].filter(Boolean).join("\n\n");
        const response = await ai.models.generateContent({
          model: GEMINI_MODEL,
          contents: prompt,
          config: {
            systemInstruction: "Curador pedag\xF3gico ALEPA 2026. Retorne JSON v\xE1lido e jamais invente p\xE1ginas, leis ou tempos inexistentes.",
            responseMimeType: "application/json",
            responseSchema: {
              type: Type.OBJECT,
              properties: {
                subtitle: { type: Type.STRING },
                description: { type: Type.STRING },
                disciplineId: { type: Type.STRING },
                editalTopic: { type: Type.STRING },
                keywords: { type: Type.ARRAY, items: { type: Type.STRING } },
                studyRecommendations: { type: Type.ARRAY, items: { type: Type.STRING } },
                chapters: {
                  type: Type.ARRAY,
                  items: {
                    type: Type.OBJECT,
                    properties: {
                      title: { type: Type.STRING },
                      summary: { type: Type.STRING },
                      startPage: { type: Type.INTEGER },
                      endPage: { type: Type.INTEGER },
                      startSeconds: { type: Type.INTEGER },
                      endSeconds: { type: Type.INTEGER }
                    },
                    required: ["title"]
                  }
                }
              },
              required: ["subtitle", "description", "editalTopic", "keywords", "studyRecommendations", "chapters"]
            }
          }
        });
        const parsed = JSON.parse(response.text || "{}");
        const chapters = Array.isArray(parsed.chapters) ? parsed.chapters.slice(0, 25).map((ch, idx) => ({
          id: `ch_ai_${Date.now()}_${idx}`,
          title: String(ch.title || `Cap\xEDtulo ${idx + 1}`).slice(0, 140),
          summary: ch.summary ? String(ch.summary).slice(0, 320) : void 0,
          startPage: typeof ch.startPage === "number" && ch.startPage >= 1 ? Math.min(body.pageCount || 2500, Math.round(ch.startPage)) : void 0,
          endPage: typeof ch.endPage === "number" && ch.endPage >= 1 ? Math.min(body.pageCount || 2500, Math.round(ch.endPage)) : void 0,
          startSeconds: typeof ch.startSeconds === "number" && ch.startSeconds >= 0 ? Math.round(ch.startSeconds) : void 0,
          endSeconds: typeof ch.endSeconds === "number" && ch.endSeconds >= 0 ? Math.round(ch.endSeconds) : void 0
        })) : [];
        res.json({
          suggestion: {
            subtitle: String(parsed.subtitle || "").slice(0, 200),
            description: String(parsed.description || "").slice(0, 1200),
            disciplineId: parsed.disciplineId ? String(parsed.disciplineId).slice(0, 80) : void 0,
            editalTopic: String(parsed.editalTopic || "").slice(0, 220),
            keywords: Array.isArray(parsed.keywords) ? parsed.keywords.slice(0, 8).map((k) => String(k).trim()).filter(Boolean) : [],
            studyRecommendations: Array.isArray(parsed.studyRecommendations) ? parsed.studyRecommendations.slice(0, 5).map((r) => String(r).trim()).filter(Boolean) : [],
            chapters
          },
          requiresHumanReview: true,
          model: GEMINI_MODEL
        });
      } catch (err) {
        const mapped = formatGeminiError(err);
        res.status(mapped.status).json({ error: mapped.message });
      }
    }
  );
  app.post("/api/ai/teacher-assistant", geminiRateLimiter);
  app.post(
    "/api/ai/teacher-assistant",
    requireRole(["admin", "editor", "teacher", "dev"]),
    async (req, res) => {
      try {
        const body = req.body || {};
        const action = body.action || "draft_lesson";
        const disciplineName = (body.disciplineName || "").trim().slice(0, 140);
        const campusLevel = body.campusLevel === "medio" ? "medio" : "superior";
        const topicTitle = (body.topicTitle || "").trim().slice(0, 200);
        const contextText = (body.contextText || "").trim().slice(0, 5e3);
        const ai = getGeminiClient();
        const teacherRule = "Voc\xEA \xE9 o Assistente Pedag\xF3gico do Professor no MEU CAMPUS ALEPA 2026 (Banca CETAP). Responda em pt-BR claro e objetivo. Nunca invente artigos de lei ou s\xFAmulas. Tudo gerado entra como rascunho para revis\xE3o do professor.";
        if (action === "analyze_class_errors") {
          if (!contextText) {
            res.status(400).json({ error: "Envie o resumo dos erros ou dificuldades da turma para an\xE1lise." });
            return;
          }
          const response = await ai.models.generateContent({
            model: GEMINI_MODEL,
            contents: `Analise exclusivamente os dados reais de erros/dificuldades abaixo e proponha recomenda\xE7\xF5es de aula de refor\xE7o e lista de revis\xE3o:

${contextText}`,
            config: { systemInstruction: teacherRule }
          });
          res.json({ action, text: response.text?.trim() || "", model: GEMINI_MODEL });
          return;
        }
        if (action === "draft_activity_questions") {
          const count = Math.max(1, Math.min(5, Number(body.questionCount) || 3));
          const response = await ai.models.generateContent({
            model: GEMINI_MODEL,
            contents: [
              disciplineName ? `Disciplina: ${disciplineName}` : "",
              `N\xEDvel: ${campusLevel}`,
              topicTitle ? `Assunto: ${topicTitle}` : "",
              contextText ? `Orienta\xE7\xE3o do professor:
${contextText}` : "",
              `Elabore ${count} quest\xF5es objetivas (5 alternativas A-E, 1 correta) e 1 quest\xE3o discursiva sugerida para atividade de turma.`
            ].filter(Boolean).join("\n\n"),
            config: {
              systemInstruction: teacherRule,
              responseMimeType: "application/json",
              responseSchema: {
                type: Type.OBJECT,
                properties: {
                  questions: {
                    type: Type.ARRAY,
                    items: {
                      type: Type.OBJECT,
                      properties: {
                        topicTitle: { type: Type.STRING },
                        statement: { type: Type.STRING },
                        options: { type: Type.ARRAY, items: { type: Type.STRING } },
                        correctIndex: { type: Type.INTEGER },
                        explanation: { type: Type.STRING },
                        legalBasis: { type: Type.STRING }
                      },
                      required: ["topicTitle", "statement", "options", "correctIndex", "explanation"]
                    }
                  },
                  discursivePrompt: { type: Type.STRING }
                },
                required: ["questions", "discursivePrompt"]
              }
            }
          });
          const parsed = JSON.parse(response.text || "{}");
          res.json({
            action,
            questions: Array.isArray(parsed.questions) ? parsed.questions.slice(0, 5) : [],
            discursivePrompt: String(parsed.discursivePrompt || "").slice(0, 1500),
            model: GEMINI_MODEL
          });
          return;
        }
        if (!topicTitle && !disciplineName && !contextText) {
          res.status(400).json({ error: "Informe disciplina, tema ou roteiro base para elaborar a aula." });
          return;
        }
        const lessonResponse = await ai.models.generateContent({
          model: GEMINI_MODEL,
          contents: [
            disciplineName ? `Disciplina: ${disciplineName}` : "",
            `N\xEDvel: ${campusLevel}`,
            topicTitle ? `Tema da aula: ${topicTitle}` : "",
            contextText ? `Diretrizes do professor:
${contextText}` : "",
            "Retorne JSON com: title, summary (resumo de 2-3 linhas) e content (roteiro completo da aula em Markdown estruturado com objetivos, explica\xE7\xE3o did\xE1tica, pontos de aten\xE7\xE3o da banca e checklist de revis\xE3o)."
          ].filter(Boolean).join("\n\n"),
          config: {
            systemInstruction: teacherRule,
            responseMimeType: "application/json",
            responseSchema: {
              type: Type.OBJECT,
              properties: {
                title: { type: Type.STRING },
                summary: { type: Type.STRING },
                content: { type: Type.STRING }
              },
              required: ["title", "summary", "content"]
            }
          }
        });
        const parsedLesson = JSON.parse(lessonResponse.text || "{}");
        res.json({
          action: "draft_lesson",
          draft: {
            title: String(parsedLesson.title || topicTitle || "Nova Aula").slice(0, 190),
            summary: String(parsedLesson.summary || "").slice(0, 950),
            content: String(parsedLesson.content || "").slice(0, 11500)
          },
          model: GEMINI_MODEL
        });
      } catch (err) {
        const mapped = formatGeminiError(err);
        res.status(mapped.status).json({ error: mapped.message });
      }
    }
  );
  app.post("/api/ai/admin-assistant", geminiRateLimiter);
  app.post(
    "/api/ai/admin-assistant",
    requireRole(["admin", "editor", "dev"]),
    async (req, res) => {
      try {
        const body = req.body || {};
        const userPrompt = (body.prompt || "").trim().slice(0, 2500);
        const snapshot = (body.platformSnapshot || "").trim().slice(0, 6e3);
        if (!userPrompt) {
          res.status(400).json({ error: "Digite uma consulta para o Assistente Administrativo." });
          return;
        }
        const ai = getGeminiClient();
        const response = await ai.models.generateContent({
          model: GEMINI_MODEL,
          contents: [
            snapshot ? `DADOS REAIS ATUAIS DA PLATAFORMA:
${snapshot}` : "",
            `Solicita\xE7\xE3o administrativa:
${userPrompt}`
          ].filter(Boolean).join("\n\n"),
          config: {
            systemInstruction: "Voc\xEA \xE9 o Assistente Estrat\xE9gico Administrativo do MEU CAMPUS ALEPA 2026. Baseie-se estritamente nos dados reais fornecidos no contexto; nunca invente estat\xEDsticas, custos exatos n\xE3o informados ou a\xE7\xF5es aut\xF4nomas. Recomende passos claros para decis\xE3o humana."
          }
        });
        res.json({
          reply: response.text?.trim() || "",
          model: GEMINI_MODEL
        });
      } catch (err) {
        const mapped = formatGeminiError(err);
        res.status(mapped.status).json({ error: mapped.message });
      }
    }
  );
  app.post("/api/ai/semantic-index-search", geminiRateLimiter, async (req, res) => {
    try {
      const body = req.body || {};
      const query = (body.query || "").trim().slice(0, 300);
      const candidates = Array.isArray(body.candidates) ? body.candidates.filter((c) => c && typeof c.chunkId === "string" && typeof c.excerpt === "string").slice(0, 24) : [];
      if (!query || candidates.length === 0) {
        res.status(400).json({ error: "Informe a consulta e os trechos candidatos reais do documento." });
        return;
      }
      const semCacheKey = AiResponseCache.buildKey("semantic-index-search", {
        query,
        campus: body.campus || "superior",
        candidateIds: candidates.map((c) => c.chunkId)
      });
      const cached = aiResponseCache.get(semCacheKey);
      if (cached) {
        aiQuotaManager.recordCacheHit(resolveQuotaIdentity(req));
        res.json({ ...cached, cached: true });
        return;
      }
      const ai = getGeminiClient();
      const allowedChunkIds = new Set(candidates.map((c) => String(c.chunkId)));
      const candidateListText = candidates.map(
        (c) => `[ID:${c.chunkId}] Material: ${String(c.materialTitle || "").slice(0, 120)}${c.pageNumber ? ` | P\xE1g. ${c.pageNumber}` : ""}${c.chapterTitle ? ` | Cap.: ${String(c.chapterTitle).slice(0, 100)}` : ""}
Trecho: ${String(
          c.excerpt || ""
        ).slice(0, 550)}`
      ).join("\n\n");
      const response = await ai.models.generateContent({
        model: GEMINI_MODEL,
        contents: [
          `Consulta do edital/estudante (${body.campus === "medio" ? "N\xEDvel M\xE9dio" : "N\xEDvel Superior"}): "${query}"`,
          "Selecione e ranqueie at\xE9 6 trechos candidatos abaixo que respondam ou correspondam conceitualmente \xE0 consulta (incluindo sin\xF4nimos jur\xEDdicos e terminologia diferente do edital).",
          "REGRA ESTRITA: retorne APENAS IDs exatamente iguais aos fornecidos em [ID:...]. Jamais invente p\xE1ginas, cap\xEDtulos ou trechos.",
          candidateListText
        ].join("\n\n"),
        config: {
          systemInstruction: "Indexador sem\xE2ntico ALEPA 2026. Retorne JSON com matches [{ chunkId, relevanceScore (0-100), reason }]. Use estritamente os IDs fornecidos.",
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              matches: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    chunkId: { type: Type.STRING },
                    relevanceScore: { type: Type.INTEGER },
                    reason: { type: Type.STRING }
                  },
                  required: ["chunkId", "relevanceScore", "reason"]
                }
              }
            },
            required: ["matches"]
          }
        }
      });
      const parsed = JSON.parse(response.text || "{}");
      const validMatches = (Array.isArray(parsed.matches) ? parsed.matches : []).filter((m) => m.chunkId && allowedChunkIds.has(String(m.chunkId))).slice(0, 6).map((m) => ({
        chunkId: String(m.chunkId),
        relevanceScore: Math.max(0, Math.min(100, Math.round(Number(m.relevanceScore) || 70))),
        reason: String(m.reason || "").slice(0, 220)
      }));
      const payload = {
        matches: validMatches,
        model: GEMINI_MODEL
      };
      aiResponseCache.set(semCacheKey, payload);
      res.json(payload);
    } catch (err) {
      const mapped = formatGeminiError(err);
      res.status(mapped.status).json({ error: mapped.message });
    }
  });
  app.post("/api/ai/extract-questions", geminiRateLimiter);
  app.post(
    "/api/ai/extract-questions",
    requireRole(["admin", "editor", "teacher", "dev"]),
    async (req, res) => {
      try {
        const body = req.body || {};
        const pages = Array.isArray(body.pages) ? body.pages.filter((p) => p && typeof p.text === "string" && p.text.trim().length > 20).slice(0, 12) : [];
        if (pages.length === 0) {
          res.status(400).json({
            error: "Envie ao menos um trecho ou p\xE1gina real do material para extrair ou elaborar quest\xF5es."
          });
          return;
        }
        const requestedCount = Math.max(1, Math.min(10, Number(body.count) || 5));
        const mode = body.mode === "extract_existing" ? "extract_existing" : "generate_from_chunks";
        const validPageNumbers = pages.map((p) => p.pageNumber).filter((n) => typeof n === "number" && Number.isInteger(n) && n >= 1);
        const ai = getGeminiClient();
        const pagesText = pages.map(
          (p, idx) => `=== ${p.pageNumber ? `P\xC1GINA ${p.pageNumber}` : `BLOCO ${idx + 1}`}${p.chapterTitle ? ` \xB7 ${String(p.chapterTitle).slice(0, 100)}` : ""} ===
${String(p.text || "").slice(0, 2200)}`
        ).join("\n\n");
        const instruction = mode === "extract_existing" ? "Extraia fielmente as quest\xF5es objetivas presentes nas p\xE1ginas abaixo (convertendo ou completando para 5 alternativas A-E quando necess\xE1rio e informando o sourcePage exato onde a quest\xE3o aparece)." : `Com base EXCLUSIVA nas p\xE1ginas fornecidas abaixo, elabore ${requestedCount} quest\xF5es objetivas in\xE9ditas no estilo Funda\xE7\xE3o CETAP (5 alternativas A-E, exatamente 1 correta, gabarito comentado e refer\xEAncia real de sourcePage + sourceExcerpt).`;
        const response = await ai.models.generateContent({
          model: GEMINI_MODEL,
          contents: [
            body.materialTitle ? `Material: ${String(body.materialTitle).slice(0, 160)}` : "",
            body.disciplineName ? `Disciplina: ${String(body.disciplineName).slice(0, 120)}` : "",
            `Campus: ${body.campusLevel === "medio" ? "N\xEDvel M\xE9dio" : "N\xEDvel Superior"}`,
            instruction,
            "REGRAS INEGOCI\xC1VEIS: Use SOMENTE n\xFAmeros de p\xE1gina (sourcePage) listados nos cabe\xE7alhos === P\xC1GINA N === abaixo. Nunca invente artigos de lei ou p\xE1ginas. Se houver d\xFAvida no gabarito ou na p\xE1gina, informe confidence menor que 0.7.",
            pagesText
          ].filter(Boolean).join("\n\n"),
          config: {
            systemInstruction: "Extrator estruturado de quest\xF5es ALEPA 2026 (Banca CETAP). Retorne JSON estrito com array questions.",
            responseMimeType: "application/json",
            responseSchema: {
              type: Type.OBJECT,
              properties: {
                questions: {
                  type: Type.ARRAY,
                  items: {
                    type: Type.OBJECT,
                    properties: {
                      topicTitle: { type: Type.STRING },
                      statement: { type: Type.STRING },
                      options: { type: Type.ARRAY, items: { type: Type.STRING } },
                      correctIndex: { type: Type.INTEGER },
                      explanation: { type: Type.STRING },
                      legalBasis: { type: Type.STRING },
                      sourcePage: { type: Type.INTEGER },
                      sourceExcerpt: { type: Type.STRING },
                      confidence: { type: Type.NUMBER }
                    },
                    required: ["topicTitle", "statement", "options", "correctIndex", "explanation"]
                  }
                }
              },
              required: ["questions"]
            }
          }
        });
        const parsed = JSON.parse(response.text || "{}");
        const validated = validateExtractedQuestions(
          Array.isArray(parsed.questions) ? parsed.questions : [],
          {
            existingStatements: Array.isArray(body.existingStatements) ? body.existingStatements : [],
            validPageNumbers
          }
        );
        res.json({
          questions: validated,
          requiresHumanReview: true,
          model: GEMINI_MODEL
        });
      } catch (err) {
        const mapped = formatGeminiError(err);
        res.status(mapped.status).json({ error: mapped.message });
      }
    }
  );
  app.get("/api/materials/pdf-proxy", async (req, res) => {
    const rawParam = typeof req.query.url === "string" ? req.query.url : "";
    const normalized = normalizeRemoteUrlInput(rawParam);
    if (!normalized) {
      res.status(400).json({ error: "Informe uma URL p\xFAblica v\xE1lida (http:// ou https://) para leitura do PDF." });
      return;
    }
    try {
      const forwardHeaders = {
        "User-Agent": "MeuCampusALEPA-BookReader/1.0",
        Accept: "application/pdf,application/octet-stream;q=0.9,*/*;q=0.5"
      };
      if (typeof req.headers.range === "string" && req.headers.range.startsWith("bytes=")) {
        forwardHeaders.Range = req.headers.range;
      }
      const result = await safeFetchRemoteDocument(normalized, {
        maxBytes: 45 * 1024 * 1024,
        timeoutMs: 25e3,
        maxRedirects: 5,
        acceptKind: "pdf",
        headers: forwardHeaders
      });
      const isPdfMagic = isPdfMagicBuffer(result.buffer);
      const isRangeContinuation = result.status === 206 && result.contentType.includes("pdf");
      const looksHtml = looksLikeHtmlBuffer(result.buffer, result.contentType);
      if (looksHtml || !isPdfMagic && !isRangeContinuation && !result.contentType.includes("application/pdf")) {
        res.status(415).json({
          kind: "html_portal",
          error: "Este endere\xE7o aponta para uma p\xE1gina web/portal ou exige autentica\xE7\xE3o no Google Drive, n\xE3o um arquivo PDF direto."
        });
        return;
      }
      res.status(result.status === 206 ? 206 : 200);
      res.setHeader("Content-Type", "application/pdf");
      res.setHeader("Content-Disposition", 'inline; filename="documento.pdf"');
      res.setHeader("Cache-Control", "private, max-age=600");
      res.setHeader("X-Content-Type-Options", "nosniff");
      if (result.acceptRanges) res.setHeader("Accept-Ranges", result.acceptRanges);
      if (result.contentRange) res.setHeader("Content-Range", result.contentRange);
      res.setHeader("Content-Length", String(result.buffer.byteLength));
      res.send(result.buffer);
    } catch (err) {
      if (err instanceof RemoteSizeLimitError) {
        res.status(413).json({ kind: "too_large", error: err.message });
        return;
      }
      if (err instanceof SsrfValidationError) {
        res.status(err.status).json({ kind: err.kind, error: err.message });
        return;
      }
      const isAbort = err instanceof Error && err.name === "AbortError";
      res.status(isAbort ? 504 : 502).json({
        kind: "network_error",
        error: isAbort ? "Tempo limite excedido ao carregar o PDF remoto." : "N\xE3o foi poss\xEDvel baixar o PDF do endere\xE7o informado."
      });
    }
  });
  app.get("/api/materials/reader-proxy", async (req, res) => {
    const rawParam = typeof req.query.url === "string" ? req.query.url : "";
    const requestedKind = req.query.kind === "epub" ? "epub" : "html";
    const normalized = normalizeRemoteUrlInput(rawParam);
    if (!normalized) {
      res.status(400).json({ error: "Informe uma URL p\xFAblica v\xE1lida (http:// ou https://)." });
      return;
    }
    try {
      if (requestedKind === "epub") {
        const result2 = await safeFetchRemoteDocument(normalized, {
          maxBytes: 40 * 1024 * 1024,
          timeoutMs: 25e3,
          maxRedirects: 5,
          acceptKind: "epub",
          headers: {
            "User-Agent": "MeuCampusALEPA-EpubReader/1.0",
            Accept: "application/epub+zip,application/zip,application/octet-stream;q=0.9,*/*;q=0.5"
          }
        });
        const isEpubContent = result2.contentType.includes("epub") || result2.contentType.includes("zip") || isZipMagicBuffer(result2.buffer);
        if (!isEpubContent || looksLikeHtmlBuffer(result2.buffer, result2.contentType)) {
          res.status(415).json({
            kind: "invalid_epub",
            error: "O recurso retornado n\xE3o corresponde a um arquivo EPUB v\xE1lido."
          });
          return;
        }
        res.status(200);
        res.setHeader("Content-Type", "application/epub+zip");
        res.setHeader("Content-Disposition", 'inline; filename="livro.epub"');
        res.setHeader("Cache-Control", "private, max-age=600");
        res.setHeader("X-Content-Type-Options", "nosniff");
        res.setHeader("Content-Length", String(result2.buffer.byteLength));
        res.send(result2.buffer);
        return;
      }
      const result = await safeFetchRemoteDocument(normalized, {
        maxBytes: 6 * 1024 * 1024,
        timeoutMs: 18e3,
        maxRedirects: 5,
        acceptKind: "html_portal",
        headers: {
          "User-Agent": "MeuCampusALEPA-PortalReader/1.0",
          Accept: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5"
        }
      });
      if (isPdfMagicBuffer(result.buffer)) {
        res.status(415).json({
          kind: "is_pdf",
          error: "O link aponta diretamente para um PDF; utilize o leitor de PDF."
        });
        return;
      }
      const decodedHtml = decodeHtmlBuffer(result.buffer, result.contentType);
      const structured = extractStructuredHtmlPortal(decodedHtml, result.finalUrl);
      res.json(structured);
    } catch (err) {
      if (err instanceof RemoteSizeLimitError) {
        res.status(413).json({ kind: "too_large", error: err.message });
        return;
      }
      if (err instanceof SsrfValidationError) {
        res.status(err.status).json({ kind: err.kind, error: err.message });
        return;
      }
      const isAbort = err instanceof Error && err.name === "AbortError";
      res.status(isAbort ? 504 : 502).json({
        kind: "network_error",
        error: isAbort ? "Tempo limite excedido ao carregar o portal oficial." : "N\xE3o foi poss\xEDvel carregar o conte\xFAdo do portal autorizado."
      });
    }
  });
  app.use("/api", (_req, res) => {
    res.status(404).json({ error: "Endpoint de API n\xE3o encontrado." });
  });
  const publicAssetsDir = path.join(__dirname, "public", "assets");
  if (options?.enableVite === false) {
    app.use("/assets", (req, res) => {
      let relPath = "";
      try {
        relPath = decodeURIComponent(req.path || "").replace(/^\/+/, "");
      } catch {
        res.status(400).json({ error: "Caminho de arquivo inv\xE1lido." });
        return;
      }
      const resolved = path.resolve(publicAssetsDir, relPath);
      if (!relPath || !resolved.startsWith(publicAssetsDir + path.sep) || !fs.existsSync(resolved) || fs.statSync(resolved).isDirectory()) {
        res.status(404).json({ error: "Arquivo n\xE3o encontrado." });
        return;
      }
      res.sendFile(resolved);
    });
  } else if (process.env.NODE_ENV === "production") {
    const distDir = path.join(__dirname, "dist");
    app.use(express.static(distDir));
    app.use("/assets", (_req, res) => {
      res.status(404).json({ error: "Arquivo est\xE1tico n\xE3o encontrado." });
    });
    app.get("*", (_req, res) => {
      const indexPath = path.join(distDir, "index.html");
      if (fs.existsSync(indexPath)) {
        res.sendFile(indexPath);
      } else {
        res.status(404).send("Build not found.");
      }
    });
  } else {
    app.use("/assets", (req, res, next) => {
      let relPath = "";
      try {
        relPath = decodeURIComponent(req.path || "").replace(/^\/+/, "");
      } catch {
        res.status(400).json({ error: "Caminho de arquivo inv\xE1lido." });
        return;
      }
      const resolved = path.resolve(publicAssetsDir, relPath);
      if (!relPath || !resolved.startsWith(publicAssetsDir + path.sep) || !fs.existsSync(resolved) || fs.statSync(resolved).isDirectory()) {
        res.status(404).json({ error: "Arquivo n\xE3o encontrado." });
        return;
      }
      next();
    });
    const { createServer: createViteServer } = await import("vite");
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        hmr: false,
        ws: false
      },
      appType: "spa",
      plugins: [
        {
          name: "disable-hmr-client-ws",
          enforce: "post",
          transform(code, id) {
            if (id.includes("vite/dist/client/client.mjs")) {
              const transportBlockPattern = /const transport = normalizeModuleRunnerTransport\(\(\(\) => \{[\s\S]*?\}\)\(\)\);/;
              if (transportBlockPattern.test(code)) {
                return {
                  code: code.replace(
                    transportBlockPattern,
                    "const transport = normalizeModuleRunnerTransport({ async connect() {}, async disconnect() {}, async send() {} });"
                  ),
                  map: null
                };
              }
            }
            return null;
          }
        }
      ]
    });
    app.use(vite.middlewares);
  }
  app.use((err, req, res, next) => {
    if (res.headersSent) {
      next(err);
      return;
    }
    const errObj = err;
    const status = errObj?.type === "entity.too.large" || errObj?.name === "PayloadTooLargeError" ? 413 : typeof errObj?.status === "number" ? errObj.status : typeof errObj?.statusCode === "number" ? errObj.statusCode : 500;
    if (req.path.startsWith("/api/")) {
      res.status(status).json({
        error: status === 413 ? "O corpo da requisi\xE7\xE3o excede o limite permitido." : status === 400 ? "Requisi\xE7\xE3o JSON inv\xE1lida." : "Erro interno ao processar a solicita\xE7\xE3o."
      });
      return;
    }
    next(err);
  });
  return app;
}
var isDirectExecution = typeof process !== "undefined" && process.env.VITEST !== "true" && Boolean(process.argv[1]) && path.resolve(process.argv[1]) === path.resolve(__filename);
if (isDirectExecution) {
  createApp().then((app) => {
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`Server running on http://0.0.0.0:${PORT}`);
    });
  }).catch((err) => {
    console.error("Erro fatal ao iniciar servidor:", err);
    process.exit(1);
  });
}
export {
  ProxyRateLimiter,
  buildCspHeader,
  createApp,
  normalizeClientIp,
  parseSpotifyTarget,
  resolveQuotaIdentity,
  resolveTrustProxyHops
};
