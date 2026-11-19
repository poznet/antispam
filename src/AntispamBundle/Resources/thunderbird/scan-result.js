/*
 * Window of "Sprawdź tę wiadomość" (background.js scanMessage): the answer of
 * POST /api/plugin/scan - antivirus (ClamAV, VirusTotal) first, then the
 * rules. Built with DOM calls only (no innerHTML): every value comes from the
 * message or the server.
 */
"use strict";

const $ = id => document.getElementById(id);

function el(tag, props, children) {
  const e = document.createElement(tag);
  Object.assign(e, props || {});
  for (const c of children || []) if (c !== null && c !== undefined) e.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  return e;
}

function kb(n) {
  return n >= 1048576 ? (n / 1048576).toFixed(1) + " MB" : Math.max(1, Math.round(n / 1024)) + " KB";
}

const CLAM = { clean: ["czysto", "sr-ok"], infected: ["ZAINFEKOWANE", "sr-bad"], skipped: ["pominięte", "sr-muted"], error: ["błąd", "sr-warn"] };
const VT = { clean: ["czysto", "sr-ok"], malicious: ["ZŁOŚLIWY", "sr-bad"], suspicious: ["podejrzany", "sr-warn"], unknown: ["nieznany w VirusTotal", "sr-muted"], skipped: ["pominięty", "sr-muted"], error: ["błąd", "sr-warn"] };
const DECISION = { spam: "SPAM", quarantine: "podejrzana (kwarantanna)", ham: "czysta", whitelisted: "nadawca z białej listy" };

function status(map, s) {
  const [text, cls] = map[s] || [s, ""];
  return el("span", { className: cls, textContent: text });
}

function renderClam(box, clam) {
  box.appendChild(el("h3", { textContent: "ClamAV" }));
  if (!clam || !clam.enabled) {
    box.appendChild(el("p", { className: "sr-muted", textContent: "Wyłączony na serwerze antyspamu (Ustawienia → Filtr spamu → ClamAV)." }));
    return;
  }
  const rows = (clam.items || []).map(i => el("tr", {}, [
    el("td", { textContent: i.name }), el("td", { textContent: kb(i.size || 0) }),
    el("td", {}, [status(CLAM, i.status), i.signature ? " " + i.signature : "", i.error ? el("span", { className: "sr-muted", textContent: " – " + i.error }) : null]),
  ]));
  box.appendChild(el("table", { className: "sr-table" }, [el("tr", {}, [el("th", { textContent: "Sprawdzono" }), el("th", { textContent: "Rozmiar" }), el("th", { textContent: "Wynik" })]), ...rows]));
}

function renderVt(box, vt, attachments) {
  box.appendChild(el("h3", { textContent: "VirusTotal" }));
  if (!vt || !vt.enabled) {
    box.appendChild(el("p", { className: "sr-muted", textContent: "Wyłączony na serwerze antyspamu (wymaga klucza API VirusTotal)." }));
    return;
  }
  if (!(vt.items || []).length) {
    box.appendChild(el("p", { className: "sr-muted", textContent: attachments ? "Brak załączników do sprawdzenia." : "Wiadomość nie ma załączników." }));
    return;
  }
  const rows = vt.items.map(i => {
    const link = el("a", { href: i.link, textContent: "raport", target: "_blank", rel: "noopener" });
    return el("tr", {}, [
      el("td", { textContent: i.name }),
      el("td", {}, [status(VT, i.status), i.total ? " " + i.malicious + "/" + i.total + " silników" : "", i.error ? el("span", { className: "sr-muted", textContent: " – " + i.error }) : null]),
      el("td", {}, [i.status === "skipped" ? null : link]),
    ]);
  });
  box.appendChild(el("table", { className: "sr-table" }, [el("tr", {}, [el("th", { textContent: "Załącznik" }), el("th", { textContent: "Wynik" }), el("th", { textContent: "" })]), ...rows]));
  box.appendChild(el("p", { className: "sr-muted", textContent: "Do VirusTotal wysłano tylko skróty SHA-256 plików, nie same pliki." }));
}

async function main() {
  const id = new URLSearchParams(location.search).get("id");
  const entry = await messenger.runtime.sendMessage({ cmd: "scanResult", id });
  if (!entry) {
    $("msg").textContent = "Wynik wygasł - sprawdź wiadomość ponownie.";
    return;
  }
  const r = entry.result;
  const av = r.antivirus || {};
  $("msg").textContent = (entry.message.author || r.sender || "") + " · " + (entry.message.subject || r.subject || "(bez tematu)") + " · " + entry.target;

  const verdict = $("verdict");
  verdict.hidden = false;
  verdict.className = "sr-verdict " + (av.infected || r.decision === "spam" ? "bad" : r.decision === "quarantine" ? "warn" : "");
  verdict.appendChild(el("strong", { textContent: av.infected ? "Wykryto złośliwe oprogramowanie – nie otwieraj załączników" : "Wiadomość: " + (DECISION[r.decision] || r.decision) }));
  verdict.appendChild(el("span", { textContent: "Wynik " + r.score + " / próg spamu " + r.spam_threshold + (r.quarantine_threshold ? ", kwarantanny " + r.quarantine_threshold : "") }));
  if (entry.action === "move") verdict.appendChild(el("div", { textContent: "Zgodnie z ustawieniami wtyczki przeniesiono ją do Śmieci." }));
  else if (entry.action === "mark") verdict.appendChild(el("div", { textContent: "Zgodnie z ustawieniami wtyczki oznaczono ją jako śmieci." }));
  if (av.truncated) verdict.appendChild(el("div", { className: "sr-warn", textContent: "Wiadomość była za duża i wysłano tylko jej początek – część załączników mogła nie zostać sprawdzona." }));

  $("av").hidden = false;
  renderClam($("clamav"), av.clamav);
  renderVt($("virustotal"), av.virustotal, av.attachments);

  $("rules").hidden = false;
  $("score").textContent = "Decyzja: " + (DECISION[r.decision] || r.decision) + " (" + r.score + " pkt)";
  const reasons = (r.reasons || []).filter(x => x && x.rule && !/^source:/.test(x.rule));
  for (const x of reasons) {
    $("reasons").appendChild(el("li", {}, [el("code", { textContent: x.rule }), x.score ? " (" + (x.score > 0 ? "+" : "") + x.score + ")" : "", x.filename ? " – " + x.filename : ""]));
  }
  if (!reasons.length) $("reasons").appendChild(el("li", { className: "sr-muted", textContent: "Żadna reguła ani test nie zadziałał." }));

  if (entry.action !== "move" && (av.infected || r.decision === "spam" || r.decision === "quarantine")) {
    const btn = $("junk");
    btn.hidden = false;
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      const res = await messenger.runtime.sendMessage({ cmd: "scanJunk", id });
      $("actionState").textContent = res && res.ok ? "Przeniesiono do Śmieci." : "Nie udało się: " + ((res && res.error) || "?");
      if (!(res && res.ok)) btn.disabled = false;
    });
  }
}

$("close").addEventListener("click", () => window.close());
main().catch(e => { $("msg").textContent = "Błąd: " + (e && e.message ? e.message : e); });
