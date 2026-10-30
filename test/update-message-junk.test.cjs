"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { loadFolderTools } = require("./helpers/folder-tools.cjs");

const JUNK_FLAG = 0x40000000; // nsMsgFolderFlags.Junk
const INBOX_FLAG = 0x1000; // nsMsgFolderFlags.Inbox

// Runs the production updateMessage with a stubbed junk plugin and folder tree.
function makeHarness({ inJunk = false, withJunkFolder = true, junkFailsFor = [], pluginMissing = false, classifyMode = "auto", extraHeaders = 0 } = {}) {
  const timers = [];
  const pending = [];
  const access = { allowed: true };
  const classifications = [];
  const props = [];
  const copies = [];
  const readCalls = [];
  const server = { type: "imap" };
  const makeHdr = (id, key, state = {}) => ({
    messageId: id, messageKey: key,
    getStringProperty: name => state[name] || "",
  });
  const headers = [
    makeHdr("one", 1),
    makeHdr("two", 2, { junkscoreorigin: "user", junkscore: "100" }),
    makeHdr("three", 3, { junkscoreorigin: "plugin", junkscore: "100" }),
  ];
  for (let i = 0; i < extraHeaders; i++) headers.push(makeHdr(`extra-${i}`, 100 + i));
  const db = {
    getMsgHdrForMessageID: id => headers.find(header => header.messageId === id),
    enumerateMessages: () => headers,
    setStringProperty: (key, name, value) => props.push([key, name, value]),
  };
  const junkFolder = { server, URI: "imap://one/Junk", hasSubFolders: false, getFlag: flag => flag === JUNK_FLAG };
  const inbox = { server, URI: "imap://one/INBOX", hasSubFolders: false, getFlag: flag => flag === INBOX_FLAG };
  const root = {
    server, URI: "imap://one", isServer: true, hasSubFolders: true,
    getFolderWithFlags: flag => ({ [JUNK_FLAG]: withJunkFolder ? junkFolder : null, [INBOX_FLAG]: inbox })[flag] || null,
  };
  server.rootFolder = root;
  const mail = {
    server, URI: "imap://one/Mail", hasSubFolders: false, getFlag: () => false,
    getUriForMsg: hdr => `imap-message://one/Mail#${hdr.messageKey}`,
    msgDatabase: db,
    markMessagesRead: (hdrs, value) => readCalls.push([hdrs, value]),
    updateFolder() {},
  };
  for (const folder of [junkFolder, inbox]) {
    folder.getUriForMsg = mail.getUriForMsg;
    folder.msgDatabase = db;
    folder.updateFolder = () => {};
  }
  const folders = [root, mail, junkFolder, inbox];
  const accounts = [{ key: "one", incomingServer: server }];
  const junk = pluginMissing ? undefined : {
    setMessageClassification(uri, oldClass, newClass, window, listener) {
      if (junkFailsFor.some(key => uri.endsWith(`#${key}`))) throw new Error("plugin failure");
      classifications.push({ uri, oldClass, newClass, window, listener });
      const report = () => listener.onMessageClassified(uri, newClass, 0);
      if (classifyMode === "auto") setImmediate(report);
      else if (classifyMode === "manual") pending.push({ uri, report });
    },
  };
  const runtime = loadFolderTools({
    accounts, folders, junk, timers,
    isAccountAllowed: () => access.allowed,
    copyMessages(...args) { copies.push(args); },
  });
  const folderPath = (inJunk ? junkFolder : mail).URI;
  const update = args => runtime.callTool("updateMessage", { folderPath, ...args });
  const flush = () => new Promise(resolve => setImmediate(resolve));
  return { update, classifications, props, copies, readCalls, junkFolder, inbox, mail, headers, timers, pending, access, flush };
}

describe("production updateMessage junk classification", () => {
  it("marks a message as junk: trains the filter, records the user verdict, and moves nothing", async () => {
    const h = makeHarness();
    const result = await h.update({ messageId: "one", junk: true });
    assert.equal(result.success, true);
    assert.deepEqual(JSON.parse(JSON.stringify(result.actions)), [{ type: "junk", value: true, classified: 1 }]);
    assert.equal(h.classifications.length, 1);
    const { listener, ...classification } = h.classifications[0];
    assert.deepEqual(classification, { uri: "imap-message://one/Mail#1", oldClass: 0, newClass: 2, window: null });
    assert.equal(typeof listener.onMessageClassified, "function");
    assert.deepEqual(h.props, [[1, "junkscoreorigin", "user"], [1, "junkscore", "100"]]);
    assert.equal(h.copies.length, 0);
  });

  it("marks not junk with the ham score", async () => {
    const h = makeHarness();
    const result = await h.update({ messageId: "one", junk: false });
    assert.equal(result.success, true);
    assert.equal(h.classifications[0].newClass, 1);
    assert.deepEqual(h.props, [[1, "junkscoreorigin", "user"], [1, "junkscore", "0"]]);
  });

  it("passes the old classification only when the earlier verdict came from the user", async () => {
    const h = makeHarness();
    const result = await h.update({ messageIds: ["two", "three"], junk: false });
    assert.equal(result.actions[0].classified, 2);
    assert.equal(h.classifications[0].oldClass, 2, "user-marked junk");
    assert.equal(h.classifications[1].oldClass, 0, "plugin-scored junk counts as unclassified");
  });

  it("accepts the string forms MCP clients send", async () => {
    const h = makeHarness();
    assert.equal((await h.update({ messageId: "one", junk: "true" })).success, true);
    assert.equal(h.classifications[0].newClass, 2);
  });

  it("reports messages the plugin failed on instead of claiming success for them", async () => {
    const h = makeHarness({ junkFailsFor: [2] });
    const result = await h.update({ messageIds: ["one", "two"], junk: true });
    assert.equal(result.success, true);
    assert.deepEqual(JSON.parse(JSON.stringify(result.actions[0])), { type: "junk", value: true, classified: 1, failed: 1 });
  });

  it("combines with read and tags, and with an explicit moveTo", async () => {
    const h = makeHarness();
    const result = await h.update({ messageId: "one", junk: true, read: true, moveTo: h.junkFolder.URI });
    assert.equal(result.success, true);
    assert.deepEqual(Array.from(result.actions, action => action.type), ["read", "junk", "move"]);
    assert.equal(h.copies.length, 1);
    assert.equal(h.copies[0][2], h.junkFolder);
  });

  it("fails before changing anything when the junk filter is unavailable", async () => {
    const h = makeHarness({ pluginMissing: true });
    const result = await h.update({ messageId: "one", junk: true, read: true });
    assert.match(result.error, /junk filter is not available/);
    assert.equal(h.readCalls.length, 0);
  });
});

describe("production updateMessage moveJunk", () => {
  it("moves junk to the account's Junk folder with the plain copy service, never a delete", async () => {
    const h = makeHarness();
    const result = await h.update({ messageId: "one", junk: true, moveJunk: true });
    assert.equal(result.success, true);
    assert.deepEqual(Array.from(result.actions, action => action.type), ["junk", "move"]);
    assert.equal(result.actions[1].to, h.junkFolder.URI);
    assert.equal(h.copies.length, 1);
    const [source, hdrs, target, isMove] = h.copies[0];
    assert.equal(source, h.mail);
    assert.equal(hdrs.length, 1);
    assert.equal(target, h.junkFolder);
    assert.equal(isMove, true);
  });

  it("moves not-junk mail from a Junk folder back to the Inbox", async () => {
    const h = makeHarness({ inJunk: true });
    const result = await h.update({ messageId: "one", junk: false, moveJunk: true });
    assert.equal(result.success, true);
    assert.equal(result.actions[1].to, h.inbox.URI);
    assert.equal(h.copies[0][2], h.inbox);
  });

  it("leaves not-junk mail outside a Junk folder, and junk already in one, where it is", async () => {
    const outside = makeHarness();
    const a = await outside.update({ messageId: "one", junk: false, moveJunk: true });
    assert.equal(a.success, true);
    assert.deepEqual(Array.from(a.actions, action => action.type), ["junk"]);
    assert.equal(outside.copies.length, 0);

    const inside = makeHarness({ inJunk: true });
    const b = await inside.update({ messageId: "one", junk: true, moveJunk: true });
    assert.deepEqual(Array.from(b.actions, action => action.type), ["junk"]);
    assert.equal(inside.copies.length, 0);
  });

  it("errors before any change when the account has no Junk folder", async () => {
    const h = makeHarness({ withJunkFolder: false });
    const result = await h.update({ messageId: "one", junk: true, moveJunk: true });
    assert.match(result.error, /Junk folder not found/);
    assert.equal(h.classifications.length, 0);
    assert.equal(h.copies.length, 0);
  });

  it("requires junk and refuses combination with other destinations", async () => {
    const h = makeHarness();
    assert.match((await h.update({ messageId: "one", moveJunk: true })).error, /requires junk/);
    for (const extra of [{ moveTo: h.inbox.URI }, { copyTo: h.inbox.URI }, { trash: true }]) {
      const result = await h.update({ messageId: "one", junk: true, moveJunk: true, ...extra });
      assert.match(result.error, /moveJunk cannot be combined/, JSON.stringify(extra));
    }
    assert.equal(h.classifications.length, 0);
    assert.equal(h.copies.length, 0);
  });
});

describe("production updateMessage junk access control", () => {
  it("still refuses a folder in a restricted account", async () => {
    const server = { type: "imap" };
    const folder = { server, URI: "imap://one/Mail", hasSubFolders: false, updateFolder() {}, msgDatabase: {} };
    const calls = [];
    const runtime = loadFolderTools({
      accounts: [{ key: "one", incomingServer: server }],
      folders: [folder],
      isAccountAllowed: () => false,
      junk: { setMessageClassification: (...args) => calls.push(args) },
    });
    const result = await runtime.callTool("updateMessage", { messageId: "one", folderPath: folder.URI, junk: true });
    assert.match(result.error, /not accessible/);
    assert.equal(calls.length, 0);
  });

});

describe("production updateMessage junk ordering", () => {
  it("does not move anything until the junk filter has reported every message back", async () => {
    const h = makeHarness({ classifyMode: "manual" });
    const done = h.update({ messageIds: ["one", "two"], junk: true, moveJunk: true });
    await h.flush();
    assert.equal(h.pending.length, 2);
    assert.equal(h.copies.length, 0, "no move while the filter is still learning");
    h.pending[0].report();
    await h.flush();
    assert.equal(h.copies.length, 0, "one message still outstanding");
    h.pending[1].report();
    const result = await done;
    assert.equal(result.success, true);
    assert.equal(h.copies.length, 1);
    assert.equal(h.copies[0][1].length, 2);
    assert.ok(h.timers.every(timer => timer.cancelled), "classification timers are released");
  });

  it("moves only the messages that finished classifying and reports the rest", async () => {
    const h = makeHarness({ classifyMode: "manual" });
    const done = h.update({ messageIds: ["one", "two"], junk: true, moveJunk: true });
    await h.flush();
    h.pending[0].report();
    await h.flush();
    h.timers.find(timer => !timer.cancelled).callback.notify();
    const result = JSON.parse(JSON.stringify(await done));
    assert.deepEqual(result.actions.map(action => action.type), ["junk", "move", "notMoved"]);
    assert.equal(result.actions[0].classified, 1);
    assert.equal(result.actions[0].failed, 1);
    assert.equal(h.copies[0][1].length, 1);
    assert.equal(result.actions[2].count, 1);
  });

  it("does not move messages whose classification threw", async () => {
    const h = makeHarness({ junkFailsFor: [1] });
    const result = JSON.parse(JSON.stringify(await h.update({ messageIds: ["one", "two"], junk: true, moveJunk: true })));
    assert.equal(h.copies.length, 1);
    assert.deepEqual(Array.from(h.copies[0][1], hdr => hdr.messageId), ["two"]);
    assert.equal(result.actions[0].failed, 1);
  });

  it("moves nothing when the filter never answers", async () => {
    const h = makeHarness({ classifyMode: "never" });
    const done = h.update({ messageId: "one", junk: true, moveJunk: true });
    await h.flush();
    h.timers.find(timer => !timer.cancelled).callback.notify();
    const result = JSON.parse(JSON.stringify(await done));
    assert.equal(h.copies.length, 0);
    assert.deepEqual(result.actions.map(action => action.type), ["junk", "notMoved"]);
  });

  it("rechecks account access after the filter finishes", async () => {
    const h = makeHarness({ classifyMode: "manual" });
    const done = h.update({ messageId: "one", junk: true, moveJunk: true });
    await h.flush();
    h.access.allowed = false;
    h.pending[0].report();
    const result = await done;
    assert.match(result.error, /access changed/);
    assert.equal(h.copies.length, 0);
  });

  it("refuses more than 500 messages per junk call before changing anything", async () => {
    const h = makeHarness({ extraHeaders: 501 });
    const ids = Array.from({ length: 501 }, (_, i) => `extra-${i}`);
    const result = await h.update({ messageIds: ids, junk: true, read: true });
    assert.match(result.error, /at most 500/);
    assert.equal(h.classifications.length, 0);
    assert.equal(h.readCalls.length, 0);
  });
});
