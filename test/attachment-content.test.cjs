"use strict";

// Runs the production getAttachmentContent with the real raw-message reader,
// encryption classifier and MIME attachment parser from direct-send's fixture.
const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { loadPreflight } = require("./direct-send-preflight.test.cjs");

const source = fs.readFileSync(path.resolve(__dirname, "../extension/mcp_server/api.js"), "utf8");

function between(startMarker, endMarker) {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + startMarker.length);
  assert.ok(start >= 0 && end > start, `Missing production marker: ${startMarker}`);
  return source.slice(start, end);
}

const b64 = text => Buffer.from(text, "latin1").toString("base64");

function message(parts, headers = "") {
  return [
    headers || 'Content-Type: multipart/mixed; boundary="b"', "MIME-Version: 1.0", "",
    ...parts.flatMap(part => ["--b", part]), "--b--", "",
  ].join("\r\n");
}

function attachment({ name, type = "application/octet-stream", body, cte = "base64", disposition = "attachment" }) {
  return [
    `Content-Type: ${type}; name="${name}"`, `Content-Disposition: ${disposition}; filename="${name}"`,
    `Content-Transfer-Encoding: ${cte}`, "", cte === "base64" ? b64(body) : body,
  ].join("\r\n");
}

const TEXT_BODY = "Content-Type: text/plain\r\n\r\nhello";

function load({ raw, allowEncrypted = false, enigmail = 0, accountOk = true, toolEnabled = true, rawLimit } = {}) {
  const h = loadPreflight({ raw });
  const { api } = h;
  const state = { accountOk, toolEnabled, allowEncrypted };
  const originalFind = api.findMessage;
  api.findMessage = (...args) => {
    if (!state.accountOk) return { error: "Account not accessible" };
    const found = originalFind(...args);
    found.msgHdr.enigmail = enigmail;
    return found;
  };
  api.isToolEnabled = () => state.toolEnabled;
  api.isPrivacyOptInEnabled = () => state.allowEncrypted;
  api.PREF_ALLOW_ENCRYPTED_MESSAGES = "allowEncrypted";
  api.hasRecordedEncryption = msgHdr => msgHdr.enigmail !== 0;
  api.console = { error() {} };
  if (typeof api.encodeByteStringToBase64 !== "function") {
    vm.runInContext("function encodeByteStringToBase64(s) { return btoa(String(s || '')); }", api);
  }
  // The same structure budget searchAttachments applies, loaded from production.
  if (typeof api.preflightAttachmentSearchSnapshot !== "function") {
    vm.runInContext([
      "const SEARCH_TIME_BUDGET_MS = 20000;",
      "function searchTimeExpired(scan) { return Date.now() >= scan.deadline; }",
      between("// BEGIN ATTACHMENT SEARCH LIMITS", "// END ATTACHMENT SEARCH LIMITS"),
      between("function preflightAttachmentSearchSnapshot(", "// Searched S24's read gate"),
    ].join("\n"), api);
  }
  let tool = between("// BEGIN ATTACHMENT CONTENT TOOL", "// END ATTACHMENT CONTENT TOOL");
  if (rawLimit !== undefined) tool = tool.replace("16 * 1024 * 1024", String(rawLimit));
  vm.runInContext(tool, api);
  const hdrCalls = { rawReads: h.calls.rawReads };
  const get = async (args = {}) => {
    const result = await api.getAttachmentContent("original@example.test", "folder", args.name, args.occurrence, args.offset, args.maxBytes);
    return JSON.parse(JSON.stringify(result));
  };
  return { get, state, api, hdrCalls, calls: h.calls };
}

describe("production getAttachmentContent", () => {
  it("returns text attachments as UTF-8 and binaries as base64, without any disk access", async () => {
    const raw = message([
      TEXT_BODY,
      attachment({ name: "notes.txt", type: "text/plain", body: "hello world" }),
      attachment({ name: "data.bin", body: "\u0000\u0001ÿþ" }),
      attachment({ name: "plain.csv", type: "text/csv", cte: "7bit", body: "a,b\r\n1,2" }),
    ]);
    const h = load({ raw });
    const text = await h.get({ name: "notes.txt" });
    assert.equal(text.encoding, "utf-8");
    assert.equal(text.truncated, false);
    assert.equal(text.totalBytes, text.returnedBytes);
    assert.equal(text.contentType, "text/plain");
    const bin = await h.get({ name: "data.bin" });
    assert.equal(bin.encoding, "base64");
    assert.equal(Buffer.from(bin.content, "base64").toString("hex"), "0001fffe");
    assert.equal(bin.totalBytes, 4);
    const csv = await h.get({ name: "plain.csv" });
    assert.equal(csv.content, "a,b\r\n1,2");
  });

  it("truncates at maxBytes, reports it, and continues from nextOffset without losing or repeating bytes", async () => {
    const body = "0123456789".repeat(10);
    const h = load({ raw: message([TEXT_BODY, attachment({ name: "big.txt", type: "text/plain", body })]) });
    const first = await h.get({ name: "big.txt", maxBytes: 30 });
    assert.deepEqual([first.returnedBytes, first.truncated, first.nextOffset, first.totalBytes], [30, true, 30, 100]);
    assert.match(first.message, /offset 30/);
    const second = await h.get({ name: "big.txt", maxBytes: 30, offset: first.nextOffset });
    const third = await h.get({ name: "big.txt", maxBytes: 60, offset: second.nextOffset });
    assert.equal(third.truncated, false);
    assert.equal(first.content + second.content + third.content, body);
  });

  it("never splits a UTF-8 character when truncating text", async () => {
    const body = Buffer.from("aé€😀b".repeat(5), "utf8").toString("latin1");
    const h = load({ raw: message([TEXT_BODY, attachment({ name: "u.txt", type: "text/plain", body })]) });
    let offset = 0;
    let rebuilt = "";
    for (let guard = 0; guard < 100; guard++) {
      const chunk = await h.get({ name: "u.txt", maxBytes: 5, offset });
      assert.ok(!chunk.content.includes("�"), `chunk at ${offset}`);
      rebuilt += chunk.content;
      if (!chunk.truncated) break;
      offset = chunk.nextOffset;
    }
    assert.equal(rebuilt, "aé€😀b".repeat(5));
  });

  it("pages binary attachments by byte and reassembles them exactly", async () => {
    const body = Array.from({ length: 300 }, (_, i) => String.fromCharCode(i % 256)).join("");
    const h = load({ raw: message([TEXT_BODY, attachment({ name: "x.bin", body })]) });
    let offset = 0;
    const chunks = [];
    for (let guard = 0; guard < 20; guard++) {
      const chunk = await h.get({ name: "x.bin", maxBytes: 128, offset });
      chunks.push(Buffer.from(chunk.content, "base64"));
      if (!chunk.truncated) break;
      offset = chunk.nextOffset;
    }
    assert.equal(Buffer.concat(chunks).toString("latin1"), body);
    assert.equal(chunks.length, 3);
  });

  it("selects among duplicate names with occurrence and reports the count", async () => {
    const h = load({ raw: message([TEXT_BODY,
      attachment({ name: "a.txt", type: "text/plain", body: "one" }),
      attachment({ name: "a.txt", type: "text/plain", body: "two" }),
    ]) });
    const first = await h.get({ name: "a.txt" });
    assert.deepEqual([first.content, first.matchCount], ["one", 2]);
    assert.equal((await h.get({ name: "a.txt", occurrence: 1 })).content, "two");
    assert.match((await h.get({ name: "a.txt", occurrence: 2 })).error, /out of range/);
  });

  it("reports unknown names with a bounded list of the available ones", async () => {
    const parts = Array.from({ length: 70 }, (_, i) => attachment({ name: `f${i}.txt`, type: "text/plain", body: "x" }));
    const h = load({ raw: message([TEXT_BODY, ...parts]) });
    const result = await h.get({ name: "missing.txt" });
    assert.match(result.error, /not found/);
    assert.equal(result.availableNames.length, 50);
    assert.equal(result.availableNames[0], "f0.txt");
  });

  it("finds an unnamed inline image by its inline_<partName> name", async () => {
    const raw = message([TEXT_BODY, [
      "Content-Type: image/png", "Content-Disposition: inline", "Content-ID: <i@x>", "Content-Transfer-Encoding: base64", "", b64("PNGDATA"),
    ].join("\r\n")]);
    const h = load({ raw });
    const listed = await h.get({ name: "nope" });
    const inline = listed.availableNames.find(name => name.startsWith("inline_"));
    assert.ok(inline, JSON.stringify(listed));
    const image = await h.get({ name: inline });
    assert.equal(Buffer.from(image.content, "base64").toString(), "PNGDATA");
  });

  it("validates its arguments before reading anything", async () => {
    const h = load({ raw: message([TEXT_BODY, attachment({ name: "a.txt", type: "text/plain", body: "x" })]) });
    for (const args of [
      { name: "" }, { name: undefined }, { name: "a.txt", occurrence: -1 }, { name: "a.txt", offset: -5 },
      { name: "a.txt", maxBytes: 0 }, { name: "a.txt", maxBytes: 524289 }, { name: "a.txt", maxBytes: 1.5 },
      { name: "a.txt", occurrence: "x" }, { name: "a.txt", offset: 1e12 },
    ]) {
      const result = await h.get(args);
      assert.ok(result.error, JSON.stringify(args));
    }
    assert.deepEqual(h.calls.rawReads, []);
    assert.match((await h.get({ name: "a.txt", offset: 99 })).error, /beyond the attachment size/);
  });

  it("defaults to 512 KiB per call and rejects a larger maxBytes", async () => {
    const body = "x".repeat(600 * 1024);
    const h = load({ raw: message([TEXT_BODY, attachment({ name: "huge.txt", type: "text/plain", body })]) });
    const result = await h.get({ name: "huge.txt" });
    assert.equal(result.returnedBytes, 512 * 1024);
    assert.equal(result.truncated, true);
    assert.equal(result.nextOffset, 512 * 1024);
    assert.match((await h.get({ name: "huge.txt", maxBytes: 524289 })).error, /maxBytes must be an integer/);
  });

  it("refuses messages above the raw size limit instead of returning partial content", async () => {
    const raw = message([TEXT_BODY, attachment({ name: "a.txt", type: "text/plain", body: "x".repeat(200) })]);
    const small = load({ raw, rawLimit: 100 });
    const result = await small.get({ name: "a.txt" });
    assert.match(result.error, /larger than/);
    assert.match(result.error, /saveAttachments/);
    assert.equal(result.content, undefined);
  });

  it("withholds encrypted and unclassifiable messages unless the opt-in is on", async () => {
    const encrypted = "Content-Type: application/pkcs7-mime; smime-type=enveloped-data\r\n\r\nYWJj";
    const unknown = "Content-Type: text/plain\r\nContent-Type: application/pkcs7-mime\r\n\r\nopaque";
    for (const raw of [encrypted, unknown]) {
      const h = load({ raw });
      const result = await h.get({ name: "a.txt" });
      assert.equal(result.encryptedContentWithheld, true);
      assert.equal(result.content, undefined);
    }
    const recorded = load({ raw: message([TEXT_BODY, attachment({ name: "a.txt", type: "text/plain", body: "secret" })]), enigmail: 0x100 });
    const withheld = await recorded.get({ name: "a.txt" });
    assert.equal(withheld.encryptedContentWithheld, true);
    assert.deepEqual(recorded.calls.rawReads, [], "recorded-encrypted is refused before the message is read");

    const allowed = load({ raw: message([TEXT_BODY, attachment({ name: "a.txt", type: "text/plain", body: "ok" })]), allowEncrypted: true, enigmail: 0x100 });
    assert.equal((await allowed.get({ name: "a.txt" })).content, "ok");
  });

  it("honors account restrictions and a disabled tool", async () => {
    const raw = message([TEXT_BODY, attachment({ name: "a.txt", type: "text/plain", body: "x" })]);
    const denied = load({ raw, accountOk: false });
    assert.match((await denied.get({ name: "a.txt" })).error, /not accessible/);
    assert.deepEqual(denied.calls.rawReads, []);

    const disabled = load({ raw, toolEnabled: false });
    const result = await disabled.get({ name: "a.txt" });
    assert.ok(result.error);
    assert.equal(result.content, undefined);
  });

  it("reports an unknown name on a message without attachments", async () => {
    const h = load({ raw: "Subject: only headers\r\n\r\nno attachments" });
    const result = await h.get({ name: "a.txt" });
    assert.match(result.error, /not found/);
    assert.deepEqual(result.availableNames, []);
  });

  it("returns a single-part message that is itself an attachment", async () => {
    const raw = [
      'Content-Type: application/pdf; name="report.pdf"', 'Content-Disposition: attachment; filename="report.pdf"',
      "Content-Transfer-Encoding: base64", "", b64("%PDF-1.4 fake"),
    ].join("\r\n");
    const h = load({ raw });
    const result = await h.get({ name: "report.pdf" });
    assert.equal(result.encoding, "base64");
    assert.equal(Buffer.from(result.content, "base64").toString(), "%PDF-1.4 fake");
    assert.equal(result.contentType, "application/pdf");
  });

  it("does not turn a plain-text single-part message into an attachment", async () => {
    const h = load({ raw: "Content-Type: text/plain\r\n\r\njust a body" });
    assert.match((await h.get({ name: "body.txt" })).error, /not found/);
  });

  it("keeps binary chunks on 3-byte boundaries so consecutive base64 strings concatenate", async () => {
    const body = Array.from({ length: 1000 }, (_, i) => String.fromCharCode((i * 7) % 256)).join("");
    const h = load({ raw: message([TEXT_BODY, attachment({ name: "x.bin", body })]) });
    let offset = 0;
    let joined = "";
    for (let guard = 0; guard < 50; guard++) {
      const chunk = await h.get({ name: "x.bin", maxBytes: 100, offset });
      if (chunk.truncated) {
        assert.equal(chunk.returnedBytes % 3, 0);
        assert.ok(!chunk.content.endsWith("="), "no padding inside the stream");
      }
      joined += chunk.content;
      if (!chunk.truncated) break;
      offset = chunk.nextOffset;
    }
    assert.equal(Buffer.from(joined, "base64").toString("latin1"), body);
  });

  it("refuses messages that exceed the MIME structure limits searchAttachments uses", async () => {
    const parts = Array.from({ length: 300 }, (_, i) => attachment({ name: `f${i}.txt`, type: "text/plain", body: "x" }));
    const h = load({ raw: message([TEXT_BODY, ...parts]) });
    const result = await h.get({ name: "f0.txt" });
    assert.match(result.error, /too complex/);
    assert.equal(result.content, undefined);
  });
});
