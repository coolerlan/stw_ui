"""共用的 frida 抓包 agent（hook recv/WSARecv/send，记录进出报文）。"""

AGENT = r"""
const w = Process.getModuleByName('ws2_32.dll');
const abi = Process.pointerSize === 4 ? 'stdcall' : 'win64';
const recs = [];
const errs = [];
const MAXLEN = 4096;

function push(dir, ptr, n, sock) {
  try {
    if (!ptr || (ptr.isNull && ptr.isNull())) return;
    if (!(n > 0) || n > MAXLEN) return;
    const b = ptr.readByteArray(n);
    if (!b) return;
    recs.push({t: Date.now(), dir: dir, sock: sock.toString(), hex:
      Array.from(new Uint8Array(b)).map(x => (x < 16 ? '0' : '') + x.toString(16)).join('')});
  } catch (e) {
    errs.push(dir + ': ' + e);
  }
}

const recvPtr = w.getExportByName('recv');
if (recvPtr) {
  Interceptor.attach(recvPtr, {
    onEnter(a) { this.buf = a[1]; this.s = a[0]; },
    onLeave(r) { push('IN', this.buf, r.toInt32(), this.s); }
  });
}
const wsaRecvPtr = w.getExportByName('WSARecv');
if (wsaRecvPtr) {
  Interceptor.attach(wsaRecvPtr, {
    onEnter(a) { this.bufs = a[1]; this.cnt = a[2].toInt32(); this.s = a[0];
                 this.nrecv = a[3]; },
    onLeave(r) {
      try {
        if (r.toInt32() !== 0) return;
        const n = this.nrecv ? this.nrecv.readU32() : 0;
        if (n > 0 && n <= MAXLEN && this.cnt > 0) {
          // WSABUF { u_long len; char FAR *buf; }
          const bufptr = this.bufs.add(Process.pointerSize).readPointer();
          push('IN', bufptr, n, this.s);
        }
      } catch (e) { errs.push('wsarecv: ' + e); }
    }
  });
}
const sendPtr = w.getExportByName('send');
if (sendPtr) {
  Interceptor.attach(sendPtr, {
    onEnter(a) { this.buf = a[1]; this.n = a[2].toInt32(); this.s = a[0]; },
    onLeave(r) { push('OUT', this.buf, r.toInt32() >= 0 ? this.n : 0, this.s); }
  });
}

rpc.exports = {
  dump() { const r = recs.slice(); recs.length = 0; return r; },
  errors() { const e = errs.slice(); errs.length = 0; return e; }
};
"""

WALK_AGENT = None  # 占位，避免误用
