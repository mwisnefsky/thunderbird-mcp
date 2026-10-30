"use strict";

// Runs the production unsubscribe handler and its SSRF guards against stubbed
// Thunderbird services. Nothing here touches the network.
const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const source = fs.readFileSync(path.resolve(__dirname, "../extension/mcp_server/api.js"), "utf8");

function snippet(startMarker, endMarker) {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + startMarker.length);
  assert.ok(start >= 0, `Missing api.js marker: ${startMarker}`);
  assert.ok(end > start, `Missing api.js marker: ${endMarker}`);
  return source.slice(start, end);
}

const PUBLIC_V4 = "93.184.216.34";
const GOOD_HEADERS = [
  "To: me@example.org",
  "List-Unsubscribe: <mailto:unsub@news.example.com?subject=unsubscribe>, <https://news.example.com/u?id=1>",
  "List-Unsubscribe-Post: List-Unsubscribe=One-Click",
].join("\r\n");

function load({
  allowRequests = true, allowEncrypted = false, accountAllowed = true, sendMailEnabled = true,
  dns = () => [PUBLIC_V4], respond = (channel, listener) => {
    listener.onStartRequest(channel);
    listener.onDataAvailable(channel, {}, 0, 10);
    listener.onStopRequest(channel, 0);
  },
  remoteAddress = PUBLIC_V4, status = 200, identities = [], proxy = null, proxyStatus = 0,
} = {}) {
  const log = { dnsHosts: [], channels: [], composed: [], timers: [], streams: 0, proxyChecks: [] };
  const sandbox = {
    console,
    PREF_ALLOW_ENCRYPTED_MESSAGES: "extensions.thunderbird-mcp.allowEncryptedMessages",
    PREF_ALLOW_UNSUBSCRIBE_REQUESTS: "extensions.thunderbird-mcp.allowUnsubscribeRequests",
    Services: {
      prefs: {
        getBoolPref: (name, fallback) => {
          if (name.endsWith("allowUnsubscribeRequests")) return allowRequests;
          if (name.endsWith("allowEncryptedMessages")) return allowEncrypted || fallback;
          return fallback;
        },
      },
      tm: { mainThread: {} },
      dns: {
        asyncResolve(host, _type, _flags, _info, listener) {
          log.dnsHosts.push(host);
          let result;
          try { result = dns(host); } catch { result = null; }
          const addresses = result ? [...result] : [];
          listener.onLookupComplete(null, result ? {
            QueryInterface() { return this; },
            hasMore: () => addresses.length > 0,
            getNextAddrAsString: () => addresses.shift(),
          } : null, result ? 0 : 0x80004005);
        },
      },
    },
    ChromeUtils: { generateQI: () => function QueryInterface() { return this; } },
    Components: { isSuccessCode: code => code === 0 },
    Ci: {
      nsIDNSService: { RESOLVE_TYPE_DEFAULT: 0 },
      nsIRequest: { LOAD_ANONYMOUS: 0x1, LOAD_BYPASS_CACHE: 0x2, INHIBIT_CACHING: 0x4 },
      nsITimer: { TYPE_ONE_SHOT: 0 },
      nsIProtocolProxyService: {}, nsIStringInputStream: {}, nsIUploadChannel2: {}, nsIHttpChannel: {}, nsIHttpChannelInternal: {}, nsIDNSAddrRecord: {},
    },
    Cc: {
      "@mozilla.org/timer;1": {
        createInstance() {
          const timer = { cancelled: false, initWithCallback(cb) { this.callback = cb; }, cancel() { this.cancelled = true; } };
          log.timers.push(timer);
          return timer;
        },
      },
      "@mozilla.org/network/protocol-proxy-service;1": {
        getService: () => ({
          asyncResolve(channel, _flags, callback) {
            log.proxyChecks.push(channel.uri);
            callback.onProxyAvailable(null, channel, proxy, proxyStatus);
          },
        }),
      },
      "@mozilla.org/io/string-input-stream;1": {
        createInstance() { log.streams++; return { setUTF8Data(data) { this.data = data; } }; },
      },
    },
    NetUtil: {
      newChannel({ uri }) {
        const channel = {
          uri, loadFlags: 0, redirectionLimit: undefined, notificationCallbacks: null, cancelled: null, status: 0,
          QueryInterface() { return this; },
          cancel(code) { this.cancelled = code; },
          get remoteAddress() { return remoteAddress; },
          get responseStatus() { return status; },
          explicitSetUploadStream(stream, type, length, method, aStreamHasHeaders) {
            this.upload = { data: stream.data, type, length, method, aStreamHasHeaders };
          },
          asyncOpen(listener) { respond(this, listener); },
        };
        log.channels.push(channel);
        return channel;
      },
      readInputStreamToString: (stream, count) => (typeof stream.read === "function" ? stream.read(count) : ""),
    },
    isAccountAllowed: () => accountAllowed,
    isToolEnabled: name => (name === "sendMail" ? sendMailEnabled : true),
    findIdentity: address => identities.find(identity => identity.email === address.toLowerCase()) || null,
    composeMail: args => { log.composed.push(args); return { success: true, message: "Compose window opened" }; },
    MailServices: null,
  };
  const runtime = vm.createContext(sandbox);
  vm.runInContext(source.match(/^const UNSUBSCRIBE_REQUEST_OPTION = .*;$/m)[0], runtime);
  vm.runInContext([
    snippet("function isPrivacyOptInEnabled(", "// BEGIN CONTACT WRITE GATE"),
    snippet("function isFolderAccessible(", "function toColumnarTable("),
    snippet("function openFolder(", "function findMessage("),
    snippet("function findMessage(", "// BEGIN MESSAGE SEARCH"),
    snippet("function findRawMimeHeaderBodySplit(", "function splitRawMimeHeaderParameters("),
    snippet("const OPENPGP_ENCRYPTION_STATUS_MASK", "// The Subject header as transmitted"),
    snippet("// BEGIN UNSUBSCRIBE HEADER PARSER", "// END UNSUBSCRIBE TOOL"),
    "this.unsubscribe = unsubscribe; this.checkUnsubscribeUrl = checkUnsubscribeUrl;" +
      " this.isUnsafeUnsubscribeAddress = isUnsafeUnsubscribeAddress; this.performOneClickUnsubscribe = performOneClickUnsubscribe;",
  ].join("\n"), runtime);

  function addMessage(rawHeaders, { enigmail = 0, recipients = "me@example.org", ccList = "" } = {}) {
    const text = `${rawHeaders}\r\n\r\nbody`;
    const msgHdr = {
      messageId: "msg-1", recipients, ccList,
      getUint32Property: () => enigmail,
      folder: {
        getMsgInputStream() {
          let offset = 0;
          return {
            available: () => text.length - offset,
            read(count) { const chunk = text.slice(offset, offset + count); offset += chunk.length; return chunk; },
            close() {},
          };
        },
      },
    };
    const server = { type: "imap" };
    const folder = {
      URI: "imap://one/INBOX", server, updateFolder() {},
      msgDatabase: { getMsgHdrForMessageID: id => (id === "msg-1" ? msgHdr : null), enumerateMessages: () => [msgHdr] },
    };
    runtime.MailServices = {
      accounts: { findAccountForServer: () => ({ key: "one" }) },
      folderLookup: { getFolderForURL: uri => (uri === folder.URI ? folder : null) },
    };
    return folder;
  }
  const call = async (folder, method, messageId = "msg-1") =>
    JSON.parse(JSON.stringify(await runtime.unsubscribe(messageId, folder.URI, method)));
  // Real POSTs only: the proxy probe also opens (but never sends) a channel.
  const requests = () => log.channels.filter(channel => channel.upload);
  return { runtime, log, addMessage, call, requests };
}

describe("checkUnsubscribeUrl", () => {
  const { runtime } = load();
  const check = uri => JSON.parse(JSON.stringify(runtime.checkUnsubscribeUrl(uri)));

  it("accepts https on a public DNS name with the default port", () => {
    assert.deepEqual(check("https://News.Example.com/u?id=1"), { host: "news.example.com" });
    assert.deepEqual(check("https://news.example.com:443/u"), { host: "news.example.com" });
    assert.deepEqual(check("https://a.b-c.example.co.uk"), { host: "a.b-c.example.co.uk" });
  });

  it("refuses non-https, other ports, credentials and IP literals in every spelling", () => {
    for (const uri of [
      "http://news.example.com/u", "ftp://news.example.com/", "https://news.example.com:8443/u",
      "https://news.example.com:/u", "https://user@news.example.com/u", "https://news.example.com@evil.example/u",
      "https://127.0.0.1/u", "https://[::1]/u", "https://[2001:4860:4860::8888]/u", "https://2130706433/u",
      "https://0x7f.0.0.1/u", "https://0177.0.0.1/u", "https://10.0.0.1/u", "https://169.254.169.254/latest",
      "https://localhost/u", "https://intranet/u", "https://news.example.com./u", "https:///u", "https://",
    ]) {
      assert.ok(check(uri).reason, uri);
    }
  });

  it("refuses private and reserved name spaces", () => {
    for (const host of [
      "app.localhost", "printer.local", "db.internal", "router.lan", "nas.home.arpa", "x.corp", "x.intranet",
      "x.test", "x.invalid", "x.example", "x.onion", "1.0.0.127.in-addr.arpa",
    ]) {
      assert.ok(check(`https://${host}/u`).reason, host);
    }
  });
});

describe("isUnsafeUnsubscribeAddress", () => {
  const { runtime } = load();
  const unsafe = text => runtime.isUnsafeUnsubscribeAddress(text);

  it("blocks private, loopback, link-local, CGNAT, documentation, multicast and reserved IPv4", () => {
    for (const address of [
      "0.0.0.0", "10.1.2.3", "127.0.0.1", "127.255.255.254", "100.64.0.1", "100.127.255.255", "169.254.169.254",
      "172.16.0.1", "172.31.255.255", "192.0.0.8", "192.0.2.1", "192.168.1.1", "198.18.0.1", "198.19.255.255",
      "198.51.100.7", "203.0.113.9", "224.0.0.1", "239.1.1.1", "240.0.0.1", "255.255.255.255", "192.88.99.1",
    ]) {
      assert.equal(unsafe(address), true, address);
    }
  });

  it("allows ordinary public IPv4 including range edges", () => {
    for (const address of ["93.184.216.34", "8.8.8.8", "172.15.255.255", "172.32.0.1", "100.63.255.255", "100.128.0.1", "198.17.255.255", "198.20.0.1", "1.1.1.1"]) {
      assert.equal(unsafe(address), false, address);
    }
  });

  it("blocks non-global IPv6 and the embedded IPv4 of mapped and 6to4 forms", () => {
    for (const address of [
      "::", "::1", "fe80::1", "fe80::1%eth0", "fc00::1", "fd12:3456::1", "ff02::1", "fec0::1", "::ffff:127.0.0.1",
      "::ffff:10.0.0.1", "::ffff:7f00:1", "2001:db8::1", "2001::1", "2002:7f00:1::1", "2002:0a00:0001::", "64:ff9b::7f00:1", "::127.0.0.1",
    ]) {
      assert.equal(unsafe(address), true, address);
    }
  });

  it("allows global unicast IPv6 and mapped public IPv4", () => {
    for (const address of ["2606:4700:4700::1111", "2001:4860:4860::8888", "2a00:1450:4001:81b::200e", "::ffff:93.184.216.34", "2002:5db8:d822::1"]) {
      assert.equal(unsafe(address), false, address);
    }
  });

  it("treats anything that is not an address as unsafe", () => {
    for (const text of ["", "example.com", "1.2.3", "1.2.3.4.5", "256.1.1.1", "::g", ":::", "1::2::3", "12345::1", undefined, null, "127.0.0.1 "]) {
      assert.equal(unsafe(text), true, String(text));
    }
  });
});

describe("production unsubscribe: one-click", () => {
  it("POSTs the fixed one-click body anonymously without following redirects", async () => {
    const h = load();
    const folder = h.addMessage(GOOD_HEADERS);
    const result = await h.call(folder, "oneClick");
    assert.deepEqual(result, { success: true, method: "oneClick", target: "https://news.example.com/u?id=1", status: 200 });
    assert.deepEqual(h.log.dnsHosts, ["news.example.com"]);
    const [channel] = h.requests();
    assert.equal(channel.uri, "https://news.example.com/u?id=1");
    assert.equal(channel.redirectionLimit, 0);
    assert.equal(channel.loadFlags & 0x1, 0x1, "LOAD_ANONYMOUS: no cookies or credentials");
    assert.equal(channel.loadFlags & 0x4, 0x4, "INHIBIT_CACHING");
    assert.deepEqual(channel.upload, {
      data: "List-Unsubscribe=One-Click", type: "application/x-www-form-urlencoded", length: 26, method: "POST", aStreamHasHeaders: false,
    });
    let verdict;
    channel.notificationCallbacks.asyncOnChannelRedirect(null, null, 0, { onRedirectVerifyCallback: code => { verdict = code; } });
    assert.notEqual(verdict, 0, "redirect is vetoed");
    assert.equal(h.log.timers.every(timer => timer.cancelled), true, "timers are released");
  });

  it("is refused unless the user enabled unsubscribe requests, before any DNS or network work", async () => {
    const h = load({ allowRequests: false });
    const folder = h.addMessage(GOOD_HEADERS);
    const result = await h.call(folder, "oneClick");
    assert.match(result.error, /Allow unsubscribe requests/);
    assert.deepEqual([h.log.dnsHosts.length, h.requests().length], [0, 0]);
  });

  it("is refused when the message does not advertise one-click", async () => {
    const h = load();
    for (const headers of [
      "List-Unsubscribe: <https://news.example.com/u>",
      "List-Unsubscribe: <mailto:u@example.com>\r\nList-Unsubscribe-Post: List-Unsubscribe=One-Click",
      "List-Unsubscribe: <https://news.example.com/u>\r\nList-Unsubscribe-Post: something=else",
      "Subject: none",
    ]) {
      const result = await h.call(h.addMessage(headers), "oneClick");
      assert.match(result.error, /does not advertise one-click/, headers);
    }
    assert.equal(h.requests().length, 0);
  });

  it("refuses hostile targets without resolving or contacting them", async () => {
    for (const target of [
      "https://127.0.0.1/u", "https://localhost/u", "https://169.254.169.254/latest/meta-data", "https://[::1]/u",
      "https://news.example.com:8443/u", "https://user@news.example.com/u", "https://printer.local/u",
    ]) {
      const h = load();
      const folder = h.addMessage(`List-Unsubscribe: <${target}>\r\nList-Unsubscribe-Post: List-Unsubscribe=One-Click`);
      const result = await h.call(folder, "oneClick");
      assert.ok(result.error, target);
      assert.deepEqual([h.log.dnsHosts.length, h.requests().length], [0, 0], target);
    }
  });

  it("refuses a public-looking name that resolves to any non-public address (DNS pointing inward)", async () => {
    for (const addresses of [["10.0.0.5"], [PUBLIC_V4, "127.0.0.1"], ["::1"], ["fd00::1"], ["::ffff:192.168.1.1"], []]) {
      const h = load({ dns: () => addresses });
      const folder = h.addMessage(GOOD_HEADERS);
      const result = await h.call(folder, "oneClick");
      assert.match(result.error, /non-public/, JSON.stringify(addresses));
      assert.equal(h.requests().length, 0, JSON.stringify(addresses));
    }
  });

  it("reports an unresolvable host without a request", async () => {
    const h = load({ dns: () => null });
    const result = await h.call(h.addMessage(GOOD_HEADERS), "oneClick");
    assert.match(result.error, /could not be resolved/);
    assert.equal(h.requests().length, 0);
  });

  it("cancels and fails when the connected server address turns out non-public (DNS rebinding)", async () => {
    const h = load({ remoteAddress: "10.0.0.5" });
    const result = await h.call(h.addMessage(GOOD_HEADERS), "oneClick");
    assert.match(result.error, /not public/);
    assert.equal(result.requestMayBeSent, true);
    assert.notEqual(h.requests()[0].cancelled, null);
  });

  it("does not follow or trust a redirect response, and reports non-2xx as failure", async () => {
    for (const [status, pattern] of [[302, /redirect/], [404, /did not accept/], [500, /did not accept/]]) {
      const h = load({ status });
      const result = await h.call(h.addMessage(GOOD_HEADERS), "oneClick");
      assert.equal(result.success, false, String(status));
      assert.equal(result.status, status);
      assert.match(result.message, pattern);
      assert.equal(h.requests().length, 1, "exactly one request");
    }
  });

  it("caps how much of the response it reads", async () => {
    const h = load({
      respond(channel, listener) {
        listener.onStartRequest(channel);
        listener.onDataAvailable(channel, {}, 0, 40 * 1024);
        if (channel.cancelled === null) listener.onDataAvailable(channel, {}, 0, 40 * 1024);
        listener.onStopRequest(channel, channel.cancelled === null ? 0 : channel.cancelled);
      },
    });
    const result = await h.call(h.addMessage(GOOD_HEADERS), "oneClick");
    assert.equal(result.status, 200);
    assert.notEqual(h.requests()[0].cancelled, null, "cancelled once the 64 KiB cap was passed");
  });

  it("times out a request that never answers", async () => {
    const h = load({ respond: () => {} });
    const pending = h.call(h.addMessage(GOOD_HEADERS), "oneClick");
    await new Promise(resolve => setImmediate(resolve));
    const timer = h.log.timers.find(candidate => !candidate.cancelled);
    assert.ok(timer, "a timeout timer is armed");
    timer.callback();
    const result = await pending;
    assert.match(result.error, /timed out/);
    assert.equal(result.requestMayBeSent, true);
    assert.notEqual(h.requests()[0].cancelled, null);
  });

  it("never returns the response body or sender text, only the status", async () => {
    const h = load();
    const result = await h.call(h.addMessage(GOOD_HEADERS), "oneClick");
    assert.deepEqual(Object.keys(result).sort(), ["method", "status", "success", "target"]);
  });
});

describe("production unsubscribe: hardening", () => {
  it("is refused while a proxy is configured, before any DNS lookup or request", async () => {
    for (const proxy of [
      { type: "http", failoverProxy: null },
      { type: "direct", failoverProxy: { type: "socks", failoverProxy: null } },
    ]) {
      const h = load({ proxy });
      const result = await h.call(h.addMessage(GOOD_HEADERS), "oneClick");
      assert.match(result.error, /proxy/);
      assert.deepEqual([h.log.dnsHosts.length, h.requests().length], [0, 0]);
    }
  });

  it("treats an unresolvable proxy configuration as a proxy and refuses", async () => {
    const h = load({ proxyStatus: 0x80004005 });
    assert.match((await h.call(h.addMessage(GOOD_HEADERS), "oneClick")).error, /proxy/);
    assert.equal(h.requests().length, 0);
  });

  it("proceeds when the proxy service reports a direct connection", async () => {
    const h = load({ proxy: { type: "direct", failoverProxy: null } });
    assert.equal((await h.call(h.addMessage(GOOD_HEADERS), "oneClick")).success, true);
    assert.deepEqual(h.log.proxyChecks, ["https://news.example.com/u?id=1"]);
  });

  it("reports a connection failure as such, not as a non-public address", async () => {
    const h = load({
      remoteAddress: "",
      respond(channel, listener) {
        channel.status = 0x804b000e;
        listener.onStartRequest(channel);
        listener.onStopRequest(channel, 0x804b000e);
      },
    });
    const result = await h.call(h.addMessage(GOOD_HEADERS), "oneClick");
    assert.match(result.error, /no usable response/);
    assert.doesNotMatch(result.error, /public/);
  });

  it("does not trust a response whose server address cannot be read", async () => {
    const h = load({ remoteAddress: "" });
    const result = await h.call(h.addMessage(GOOD_HEADERS), "oneClick");
    assert.match(result.error, /could not be verified/);
    assert.equal(result.requestMayBeSent, true);
  });

  it("allows at most two unsubscribe requests at once and releases the slot afterwards", async () => {
    let opened = 0;
    const h = load({
      respond(channel, listener) {
        if (++opened <= 2) return;
        listener.onStartRequest(channel);
        listener.onStopRequest(channel, 0);
      },
    });
    const folder = h.addMessage(GOOD_HEADERS);
    const first = h.call(folder, "oneClick");
    const second = h.call(folder, "oneClick");
    await new Promise(resolve => setImmediate(resolve));
    const third = await h.call(folder, "oneClick");
    assert.match(third.error, /Too many/);
    for (const timer of h.log.timers.filter(candidate => !candidate.cancelled)) timer.callback();
    await Promise.all([first, second]);
    assert.equal((await h.call(folder, "oneClick")).success, true, "the slots were released");
  });
});

describe("production unsubscribe: mailto", () => {
  it("opens a review compose window through composeMail and never sends directly", async () => {
    const h = load({ identities: [{ email: "me@example.org", key: "id1" }] });
    const folder = h.addMessage(GOOD_HEADERS);
    const result = await h.call(folder, "mailto");
    assert.equal(result.success, true);
    assert.equal(result.target, "mailto:unsub@news.example.com?subject=unsubscribe");
    assert.match(result.message, /review and send/);
    assert.equal(h.log.composed.length, 1);
    assert.deepEqual({ ...h.log.composed[0] }, {
      to: "unsub@news.example.com", subject: "unsubscribe", body: "", skipReview: false, from: "me@example.org",
    });
    assert.deepEqual([h.log.dnsHosts.length, h.requests().length], [0, 0], "no network use");
  });

  it("warns when no identity matches the recipients", async () => {
    const h = load();
    const result = await h.call(h.addMessage(GOOD_HEADERS, { recipients: "someone@else.example" }), "mailto");
    assert.equal(result.success, true);
    assert.match(result.warning, /default identity/);
    assert.equal("from" in h.log.composed[0], false);
  });

  it("needs sendMail enabled and a usable mailto target", async () => {
    const off = load({ sendMailEnabled: false });
    assert.match((await off.call(off.addMessage(GOOD_HEADERS), "mailto")).error, /sendMail/);
    assert.equal(off.log.composed.length, 0);

    const none = load();
    const result = await none.call(none.addMessage("List-Unsubscribe: <https://news.example.com/u>"), "mailto");
    assert.match(result.error, /no usable mailto/);
    assert.equal(none.log.composed.length, 0);
  });

  it("works without the unsubscribe-requests opt-in because the user reviews the mail", async () => {
    const h = load({ allowRequests: false });
    assert.equal((await h.call(h.addMessage(GOOD_HEADERS), "mailto")).success, true);
  });

  it("does not compose hostile mailto targets", async () => {
    const h = load();
    const folder = h.addMessage("List-Unsubscribe: <mailto:a@example.com,b@example.com?subject=x>");
    assert.match((await h.call(folder, "mailto")).error, /no usable mailto/);
    assert.equal(h.log.composed.length, 0);
  });
});

describe("production unsubscribe: shared gates", () => {
  it("requires a known method", async () => {
    const h = load();
    const folder = h.addMessage(GOOD_HEADERS);
    for (const method of [undefined, "", "POST", "ONECLICK", "oneclick"]) {
      assert.match((await h.call(folder, method)).error, /method must be/, String(method));
    }
  });

  it("honors account restrictions for both methods", async () => {
    for (const method of ["oneClick", "mailto"]) {
      const h = load({ accountAllowed: false });
      const folder = h.addMessage(GOOD_HEADERS);
      assert.match((await h.call(folder, method)).error, /not accessible/, method);
      assert.deepEqual([h.log.dnsHosts.length, h.requests().length, h.log.composed.length], [0, 0, 0], method);
    }
  });

  it("withholds recorded-encrypted messages for both methods unless allowed", async () => {
    for (const method of ["oneClick", "mailto"]) {
      const h = load();
      const folder = h.addMessage(GOOD_HEADERS, { enigmail: 0x00000100 });
      const result = await h.call(folder, method);
      assert.equal(result.encryptedContentWithheld, true, method);
      assert.deepEqual([h.log.dnsHosts.length, h.requests().length, h.log.composed.length], [0, 0, 0], method);
    }
    const allowed = load({ allowEncrypted: true });
    assert.equal((await allowed.call(allowed.addMessage(GOOD_HEADERS, { enigmail: 0x00000100 }), "mailto")).success, true);
  });

  it("reports unknown messages", async () => {
    const h = load();
    const folder = h.addMessage(GOOD_HEADERS);
    assert.match((await h.call(folder, "mailto", "nope")).error, /Message not found/);
  });

  it("uses the pref name documented for the Options page", () => {
    assert.match(source, /const PREF_ALLOW_UNSUBSCRIBE_REQUESTS = "extensions\.thunderbird-mcp\.allowUnsubscribeRequests";/);
  });
});

describe("unsubscribe preference methods", () => {
  function loadOptions() {
    const prefs = new Map();
    const runtime = vm.createContext({
      PREF_ALLOW_UNSUBSCRIBE_REQUESTS: "extensions.thunderbird-mcp.allowUnsubscribeRequests",
      PREF_ALLOW_ENCRYPTED_MESSAGES: "x",
      Services: { prefs: {
        getBoolPref: (name, fallback) => (prefs.has(name) ? prefs.get(name) : fallback),
        setBoolPref: (name, value) => prefs.set(name, value),
      } },
    });
    vm.runInContext(snippet("function isPrivacyOptInEnabled(", "// BEGIN CONTACT WRITE GATE"), runtime);
    const options = vm.runInContext(
      `({${snippet("// BEGIN UNSUBSCRIBE PREFERENCE METHODS", "// END UNSUBSCRIBE PREFERENCE METHODS")}})`, runtime);
    return { options, prefs };
  }

  it("defaults to off and stores only explicit booleans", async () => {
    const { options, prefs } = loadOptions();
    assert.deepEqual({ ...await options.getAllowUnsubscribeRequests() }, { allowUnsubscribeRequests: false });
    assert.deepEqual({ ...await options.setAllowUnsubscribeRequests(true) }, { success: true, allowUnsubscribeRequests: true });
    assert.deepEqual({ ...await options.getAllowUnsubscribeRequests() }, { allowUnsubscribeRequests: true });
    for (const value of ["true", 1, null, undefined]) {
      assert.deepEqual({ ...await options.setAllowUnsubscribeRequests(value) }, { error: "allowUnsubscribeRequests must be a boolean" });
    }
    assert.equal(prefs.get("extensions.thunderbird-mcp.allowUnsubscribeRequests"), true);
  });
});
