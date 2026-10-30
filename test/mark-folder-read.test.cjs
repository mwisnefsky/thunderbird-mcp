"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { loadFolderTools } = require("./helpers/folder-tools.cjs");

const DAY_MS = 86400000;
const VIRTUAL_FLAG = 0x20;
const OUTBOX_FLAG = 0x800;

// A folder with real-shaped native surfaces: key snapshot, per-key headers
// and the folder-level markMessagesRead the production code must use.
function makeFolder(uri, server, rows, extra = {}) {
  const marked = [];
  const headers = new Map();
  for (const [key, row] of rows.entries()) {
    headers.set(key + 1, {
      messageKey: key + 1, messageId: `${uri}#${key + 1}`, isRead: false, flags: 0,
      date: (Date.now() - (row.ageDays ?? 0) * DAY_MS) * 1000, ...row,
    });
  }
  const folder = {
    URI: uri, server, hasSubFolders: false, subFolders: [], flags: 0,
    updateFolder() {},
    markMessagesRead(hdrs, value) {
      for (const hdr of hdrs) hdr.isRead = value;
      marked.push(...hdrs.map(hdr => hdr.messageKey));
    },
    msgDatabase: {
      listAllKeys: () => Array.from(headers.keys()),
      containsKey: key => headers.has(key),
      getMsgHdrForKey: key => headers.get(key),
    },
    ...extra,
  };
  return { folder, marked, headers };
}

function makeHarness({ denied = [], many = 0 } = {}) {
  const server = { type: "imap" };
  const otherServer = { type: "imap" };
  const inbox = makeFolder("imap://one/INBOX", server, [
    { ageDays: 40 }, { ageDays: 40, isRead: true }, { ageDays: 1 }, { ageDays: 90 },
    { ageDays: 40, flags: 0x8 },
  ]);
  const child = makeFolder("imap://one/INBOX/Child", server, [{ ageDays: 60 }, { ageDays: 2 }]);
  const saved = makeFolder("imap://one/Saved", server, [{ ageDays: 60 }], { flags: VIRTUAL_FLAG });
  const outbox = makeFolder("mailbox://one/Unsent%20Messages", server, [{ ageDays: 60 }],
    { isSpecialFolder: flag => flag === OUTBOX_FLAG });
  const foreign = makeFolder("imap://two/INBOX", otherServer, [{ ageDays: 60 }]);
  inbox.folder.hasSubFolders = true;
  inbox.folder.subFolders = [child.folder];
  const big = makeFolder("imap://one/Big", server, Array.from({ length: many }, () => ({ ageDays: 5 })));
  const root = { URI: "imap://one", server, isServer: true, hasSubFolders: true, subFolders: [inbox.folder, saved.folder, outbox.folder, big.folder] };
  server.rootFolder = root;
  const folders = [root, inbox.folder, child.folder, saved.folder, outbox.folder, foreign.folder, big.folder];
  const runtime = loadFolderTools({
    accounts: [{ key: "one", incomingServer: server }, { key: "two", incomingServer: otherServer }],
    folders,
    isAccountAllowed: key => !denied.includes(key),
  });
  const call = args => runtime.callTool("markFolderRead", args);
  return { call, inbox, child, saved, outbox, foreign, big, root, runtime };
}

describe("production markFolderRead", () => {
  it("marks only unread, live messages in the named folder through the folder-level API", async () => {
    const h = makeHarness();
    const result = await h.call({ folderPath: h.inbox.folder.URI });
    assert.equal(result.success, true);
    assert.equal(result.marked, 3);
    assert.deepEqual(Array.from(h.inbox.marked).sort(), [1, 3, 4]);
    assert.equal(h.inbox.headers.get(2).isRead, true, "already read is left alone");
    assert.equal(h.inbox.headers.get(5).isRead, false, "expunged header is not touched");
    assert.equal(h.child.marked.length, 0, "subfolders are excluded by default");
    assert.equal(result.truncated, undefined);
  });

  it("includes subfolders when asked", async () => {
    const h = makeHarness();
    const result = await h.call({ folderPath: h.inbox.folder.URI, includeSubfolders: true });
    assert.equal(result.marked, 5);
    assert.equal(result.folders, 2);
    assert.deepEqual(Array.from(h.child.marked).sort(), [1, 2]);
  });

  it("accepts string booleans from MCP clients", async () => {
    const h = makeHarness();
    const result = await h.call({ folderPath: h.inbox.folder.URI, includeSubfolders: "true" });
    assert.equal(result.marked, 5);
  });

  it("limits to messages older than olderThanDays", async () => {
    const h = makeHarness();
    const result = await h.call({ folderPath: h.inbox.folder.URI, includeSubfolders: true, olderThanDays: 30 });
    assert.equal(result.marked, 3);
    assert.deepEqual(Array.from(h.inbox.marked).sort(), [1, 4]);
    assert.deepEqual(Array.from(h.child.marked), [1]);
    assert.equal(h.inbox.headers.get(3).isRead, false, "recent mail stays unread");
  });

  it("rejects an invalid olderThanDays before touching anything", async () => {
    const h = makeHarness();
    for (const bad of [-1, "soon", Infinity]) {
      const result = await h.call({ folderPath: h.inbox.folder.URI, olderThanDays: bad });
      assert.match(result.error, /olderThanDays/, String(bad));
    }
    assert.equal(h.inbox.marked.length, 0);
  });

  it("requires includeSubfolders for an account root and then skips saved searches and the Outbox", async () => {
    const h = makeHarness();
    assert.match((await h.call({ folderPath: h.root.URI })).error, /includeSubfolders/);
    const result = await h.call({ folderPath: h.root.URI, includeSubfolders: true });
    assert.equal(result.success, true);
    assert.equal(result.skippedFolders, 2);
    assert.equal(h.saved.marked.length, 0);
    assert.equal(h.outbox.marked.length, 0);
    assert.equal(h.inbox.marked.length, 3);
  });

  it("refuses a folder in a restricted account and never reads it", async () => {
    const h = makeHarness({ denied: ["two"] });
    const result = await h.call({ folderPath: h.foreign.folder.URI });
    assert.match(result.error, /not accessible/);
    assert.equal(h.foreign.marked.length, 0);
  });

  it("skips subfolders that become inaccessible instead of marking them", async () => {
    const h = makeHarness();
    h.child.folder.server = { type: "imap" };
    const result = await h.call({ folderPath: h.inbox.folder.URI, includeSubfolders: true });
    assert.equal(result.marked, 3);
    assert.equal(result.skippedFolders, 1);
    assert.equal(h.child.marked.length, 0);
  });

  it("caps one call, reports truncation, and a repeat call finishes the rest", async () => {
    const h = makeHarness({ many: 10050 });
    const first = await h.call({ folderPath: h.big.folder.URI });
    assert.equal(first.marked, 10000);
    assert.equal(first.truncated, true);
    assert.match(first.message, /call again/);
    const second = await h.call({ folderPath: h.big.folder.URI });
    assert.equal(second.marked, 50);
    assert.equal(second.truncated, undefined);
  });

  it("validates folderPath", async () => {
    const h = makeHarness();
    assert.match((await h.call({ folderPath: "" })).error, /folderPath/);
    assert.match((await h.call({ folderPath: "imap://one/Missing" })).error, /Folder not found/);
  });

  it("still marks what it found when the scan used up its own time budget", async () => {
    const h = makeHarness({ many: 3000 });
    // A fake clock that advances 8 seconds at every yield to the main thread.
    const clock = { now: Date.now() };
    h.runtime.Date = class extends Date { static now() { return clock.now; } };
    h.runtime.Services.tm.dispatchToMainThread = callback => { clock.now += 8000; setImmediate(callback); };
    const first = await h.call({ folderPath: h.big.folder.URI });
    assert.equal(first.truncated, true, "the scan could not finish");
    assert.ok(first.marked > 0, "but the keys it had collected were marked");
    assert.equal(h.big.marked.length, first.marked);
  });
});
