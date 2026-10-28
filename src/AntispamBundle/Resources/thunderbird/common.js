/*
 * Shared by background.js and options.js (loaded before both).
 */

"use strict";

/**
 * Base URL of the antispam server from what the user typed or pasted: a bare
 * host ("antispam.example.pl" -> https://), the setup link
 * (https://host/plugin/setup), a download link, the panel address... Anything
 * from "/plugin/", "/api/plugin", "/panel" or "/config/" on, the query and the
 * fragment are dropped. Returns "" for an empty or unusable value.
 */
function normalizeServer(input) {
  let value = String(input || "").trim();
  if (!value) return "";
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) value = "https://" + value;
  let u;
  try {
    u = new URL(value);
  } catch (e) {
    return "";
  }
  if ((u.protocol !== "https:" && u.protocol !== "http:") || !u.hostname || u.username || u.password) return "";
  let path = u.pathname.replace(/\/(plugin|api\/plugin|panel|config|login|q)(\/.*)?$/i, "");
  path = path.replace(/\/+$/, "");
  return u.protocol + "//" + u.host + path;
}

/** Host permission pattern for a server URL (match patterns carry no port). */
function originPattern(url) {
  try {
    const u = new URL(url);
    return u.protocol + "//" + u.hostname + "/*";
  } catch (e) {
    return null;
  }
}
