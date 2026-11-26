#!/usr/bin/env python3
"""
minitail.py – ein kleiner, selbst gehosteter Tailscale-Ersatz für einen Zweck:
Dienste auf einem Rechner hinter NAT (z. B. Raspi im Labor) von woanders
erreichbar machen, ohne am Labor-Router etwas freizugeben.

Aufbau
------
  [Raspi im Labor]  --- baut ausgehend auf --->  [Hub zu Hause]
     agent                 verschlüsselt            hub (per Portfreigabe
                           (ChaCha20-Poly1305)       am Heimrouter erreichbar)

  Der Hub öffnet lokale Ports (z. B. 2222, 3389, 5900). Wer sich dorthin
  verbindet, landet über den Tunnel bei SSH/RDP/VNC auf dem Labor-Raspi.
  Mehrere Agents (mit verschiedenen Namen) können am selben Hub hängen.

Abgrenzung zu Tailscale: kein virtuelles Netz (kein TUN, keine 100.x-IPs),
kein NAT-Hole-Punching, keine Koordinationsserver. Stattdessen Port-
Weiterleitung über einen eigenen Hub – das deckt SSH, RDP und VNC vollständig ab
und läuft ohne Root-Rechte auf Linux, Windows und macOS.

Sicherheit
----------
  * Gemeinsamer 256-Bit-Schlüssel (PSK), mit "genkey" erzeugen.
  * Pro Verbindung frische Zufallswerte beider Seiten -> HKDF-SHA256 ->
    je ein Schlüssel pro Richtung; jedes Paket ChaCha20-Poly1305 mit
    Zähler-Nonce, Längenfeld als AAD authentifiziert. Wer den PSK nicht hat,
    kommt nicht über das erste Paket hinaus.
  * Der Agent verbindet nur zu Zielen aus seiner --allow-Liste.

Optional: HTTPS-Tarnung
-----------------------
  Mit TLS-Zertifikat am Hub (--tls-cert/--tls-key) und --https am Agent läuft
  der Tunnel in einer echten TLS-Verbindung mit HTTP-Upgrade – für Firewalls
  und Proxys sieht das aus wie HTTPS auf Port 443. Die innere Verschlüsselung
  bleibt zusätzlich bestehen. Wer ohne passenden Upgrade-Header anklopft
  (Browser, Scanner), bekommt eine harmlose 404-Seite.

    python3 minitail.py gencert --out hub        # hub.crt, hub.key + Fingerabdruck
    python3 minitail.py hub   ... --tls-cert hub.crt --tls-key hub.key
    python3 minitail.py agent ... --https --pin <SHA256-Fingerabdruck>
    # Labor-Proxy:  --proxy proxy.labor.de:3128   (auch user:pass@host:port)
    # Hub hinter nginx/Caddy (TLS dort):  Hub mit --http, Agent mit --https --path /minitail

Abhängigkeit: python3-cryptography  (Debian: apt install python3-cryptography,
sonst: pip install cryptography)

Beispiele
---------
  Schlüssel erzeugen (einmal, auf beide Rechner kopieren):
    python3 minitail.py genkey > minitail.key

  Hub zu Hause (Portfreigabe TCP 41700 am Heimrouter auf diesen Rechner):
    python3 minitail.py hub --key-file minitail.key --listen '*:41700' \
        --forward 2222=labor:127.0.0.1:22 \
        --forward 3389=labor:127.0.0.1:3389 \
        --forward 5900=labor:127.0.0.1:5900

  Agent auf dem Labor-Raspi:
    python3 minitail.py agent --key-file minitail.key --name labor \
        --hub meinname.myfritz.net:41700 \
        --allow 127.0.0.1:22 --allow 127.0.0.1:3389 --allow 127.0.0.1:5900

  Danach zu Hause:  ssh -p 2222 pi@localhost   bzw. RDP auf localhost:3389

  Rückrichtung (vom Labor nach Hause), z. B. SSH auf den Hub selbst:
    Hub:    ... --allow 127.0.0.1:22
    Agent:  ... --forward 2200=127.0.0.1:22
    Im Labor dann:  ssh -p 2200 pi@localhost

Mehr Projekte: https://itzwieseltal.wordpress.com
"""

import argparse
import asyncio
import base64
import json
import logging
import os
import secrets
import hashlib
import socket
import ssl
import struct
import sys
import time

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError:
    sys.exit("Fehlt: 'cryptography'  ->  sudo apt install python3-cryptography"
             "  oder  pip install cryptography")

VERSION = "1.0"
MAGIC = b"MTL1"
NONCE_LEN = 32
CHUNK = 32 * 1024
MAX_FRAME = CHUNK + 5 + 16 + 1024
PING_INTERVAL = 20
TIMEOUT = 65
OPEN_TIMEOUT = 15

# Nachrichtentypen
T_HELLO, T_WELCOME, T_OPEN, T_OPEN_OK, T_OPEN_FAIL, T_DATA, T_CLOSE, T_PING, T_PONG, T_EOF = range(1, 11)

log = logging.getLogger("minitail")


class ProtocolError(Exception):
    pass


# ---------------------------------------------------------------------------
# Verschlüsselter Kanal
# ---------------------------------------------------------------------------

class Channel:
    """Gerahmte, authentisch verschlüsselte Verbindung über einen TCP-Stream.

    Rahmen: [4 Byte Länge][ChaCha20-Poly1305(Typ|StreamID|Nutzdaten)]
    Nonce = Paketzähler je Richtung (96 Bit), Länge ist AAD.
    """

    def __init__(self, reader, writer, send_key, recv_key):
        self.r = reader
        self.w = writer
        self._tx = ChaCha20Poly1305(send_key)
        self._rx = ChaCha20Poly1305(recv_key)
        self._tx_ctr = 0
        self._rx_ctr = 0
        self._lock = asyncio.Lock()
        self.last_rx = time.monotonic()

    async def send(self, mtype, sid=0, payload=b""):
        pt = struct.pack("!BI", mtype, sid) + payload
        async with self._lock:
            nonce = self._tx_ctr.to_bytes(12, "big")
            self._tx_ctr += 1
            hdr = struct.pack("!I", len(pt) + 16)
            self.w.write(hdr + self._tx.encrypt(nonce, pt, hdr))
            await self.w.drain()

    async def recv(self):
        hdr = await self.r.readexactly(4)
        (n,) = struct.unpack("!I", hdr)
        if n < 5 + 16 or n > MAX_FRAME:
            raise ProtocolError(f"ungültige Rahmenlänge {n}")
        ct = await self.r.readexactly(n)
        nonce = self._rx_ctr.to_bytes(12, "big")
        self._rx_ctr += 1
        try:
            pt = self._rx.decrypt(nonce, ct, hdr)
        except InvalidTag:
            raise ProtocolError("Entschlüsselung fehlgeschlagen (falscher Schlüssel?)")
        self.last_rx = time.monotonic()
        mtype, sid = struct.unpack("!BI", pt[:5])
        return mtype, sid, pt[5:]

    def close(self):
        try:
            self.w.close()
        except Exception:
            pass


def derive_keys(psk, nonce_agent, nonce_hub):
    okm = HKDF(algorithm=hashes.SHA256(), length=64,
               salt=nonce_agent + nonce_hub,
               info=b"minitail v1 session").derive(psk)
    return okm[:32], okm[32:]          # agent->hub, hub->agent


async def handshake(reader, writer, psk, role):
    mine = secrets.token_bytes(NONCE_LEN)
    writer.write(MAGIC + mine)
    await writer.drain()
    data = await asyncio.wait_for(reader.readexactly(len(MAGIC) + NONCE_LEN), 10)
    if data[:4] != MAGIC:
        raise ProtocolError("kein minitail-Gegenüber")
    theirs = data[4:]
    if role == "agent":
        a2h, h2a = derive_keys(psk, mine, theirs)
        return Channel(reader, writer, a2h, h2a)
    a2h, h2a = derive_keys(psk, theirs, mine)
    return Channel(reader, writer, h2a, a2h)


def tune_socket(writer):
    sock = writer.get_extra_info("socket")
    if sock is None:
        return
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# HTTP-/TLS-Hülle (optional)
# ---------------------------------------------------------------------------

UPGRADE_TOKEN = "minitail"
NOT_FOUND = (b"HTTP/1.1 404 Not Found\r\nContent-Type: text/html; charset=utf-8\r\n"
             b"Content-Length: 49\r\nConnection: close\r\n\r\n"
             b"<html><body><h1>404 Not Found</h1></body></html>\n")


async def read_http_head(reader, limit=8192):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = await reader.read(1)          # byteweise, damit nichts danach verschluckt wird
        if not chunk:
            raise ProtocolError("Verbindung während HTTP-Kopf geschlossen")
        data += chunk
        if len(data) > limit:
            raise ProtocolError("HTTP-Kopf zu groß")
    lines = data.decode("latin-1").split("\r\n")
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return lines[0], headers


async def http_accept(reader, writer, path):
    """Hub-Seite: HTTP-Upgrade prüfen; Fremde bekommen 404."""
    first, headers = await asyncio.wait_for(read_http_head(reader), 10)
    parts = first.split()
    ok = (len(parts) == 3 and parts[0] == "GET" and parts[1] == path
          and headers.get("upgrade", "").lower() == UPGRADE_TOKEN)
    if not ok:
        writer.write(NOT_FOUND)
        await writer.drain()
        raise ProtocolError(f"kein minitail-Upgrade ({first[:60]!r})")
    writer.write(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: " + UPGRADE_TOKEN.encode()
                 + b"\r\nConnection: Upgrade\r\n\r\n")
    await writer.drain()


async def http_upgrade(reader, writer, host, path):
    """Agent-Seite: HTTP-Upgrade anfordern."""
    writer.write((f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                  f"User-Agent: minitail/{VERSION}\r\n"
                  f"Connection: Upgrade\r\nUpgrade: {UPGRADE_TOKEN}\r\n\r\n").encode())
    await writer.drain()
    first, _ = await asyncio.wait_for(read_http_head(reader), 10)
    if " 101 " not in first + " ":
        raise ProtocolError(f"Hub lehnt HTTP-Upgrade ab: {first}")


async def proxy_connect(proxy, host, port):
    """TCP-Verbindung über einen HTTP-Proxy (CONNECT) aufbauen."""
    auth = None
    if "@" in proxy:
        cred, proxy = proxy.rsplit("@", 1)
        auth = base64.b64encode(cred.encode()).decode()
    phost, pport = split_hostport(proxy)
    r, w = await asyncio.wait_for(asyncio.open_connection(phost, pport), 15)
    target = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    req = f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n"
    if auth:
        req += f"Proxy-Authorization: Basic {auth}\r\n"
    w.write((req + "\r\n").encode())
    await w.drain()
    first, _ = await asyncio.wait_for(read_http_head(r), 15)
    if len(first.split()) < 2 or first.split()[1] != "200":
        w.close()
        raise ProtocolError(f"Proxy verweigert CONNECT: {first}")
    return r, w


def cert_fingerprint(der):
    return hashlib.sha256(der).hexdigest()


def norm_pin(pin):
    return pin.replace(":", "").replace(" ", "").lower()


def make_client_ssl(pin, cafile):
    if pin:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE   # stattdessen Fingerabdruck-Prüfung (Pinning)
    else:
        ctx = ssl.create_default_context(cafile=cafile)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def check_pin(writer, pin):
    if not pin:
        return
    sslobj = writer.get_extra_info("ssl_object")
    der = sslobj.getpeercert(binary_form=True) if sslobj else None
    if not der or cert_fingerprint(der) != norm_pin(pin):
        got = cert_fingerprint(der) if der else "?"
        raise ProtocolError(f"Zertifikat passt nicht zum --pin (erhalten: {got})")


async def open_agent_transport(opts):
    """Verbindung Agent -> Hub: TCP, optional über Proxy, optional TLS + HTTP."""
    host, port = split_hostport(opts.hub)
    ctx = make_client_ssl(opts.pin, opts.ca) if opts.https else None
    sni = opts.sni or host
    if opts.proxy:
        r, w = await proxy_connect(opts.proxy, host, port)
        if ctx:
            if not hasattr(w, "start_tls"):
                raise ProtocolError("--https über --proxy braucht Python 3.11 oder neuer")
            await asyncio.wait_for(w.start_tls(ctx, server_hostname=sni), 15)
    else:
        r, w = await asyncio.wait_for(asyncio.open_connection(
            host, port, ssl=ctx, server_hostname=sni if ctx else None), 15)
    tune_socket(w)
    if ctx:
        check_pin(w, opts.pin)
    if opts.https or opts.http:
        await http_upgrade(r, w, opts.sni or host, opts.path)
    return r, w


def generate_cert(out, cn, days):
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    import datetime
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
            .sign(key, hashes.SHA256()))
    keyfile, certfile = out + ".key", out + ".crt"
    fd = os.open(keyfile, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    with open(certfile, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    fp = cert_fingerprint(cert.public_bytes(serialization.Encoding.DER))
    print(f"Zertifikat: {certfile}\nSchlüssel:  {keyfile}\nFingerabdruck (für --pin):\n{fp}")


# ---------------------------------------------------------------------------
# Gemeinsame Logik für beide Enden eines Tunnels (Stream-Multiplexing)
# ---------------------------------------------------------------------------

class Stream:
    __slots__ = ("writer", "sent_eof", "got_eof")

    def __init__(self, writer):
        self.writer = writer
        self.sent_eof = False     # lokale Seite fertig mit Senden
        self.got_eof = False      # Gegenseite fertig mit Senden


class Peer:
    def __init__(self, ch, name, allow=None, role="hub"):
        self.ch = ch
        self.name = name
        self.allow = allow            # nur Agent: erlaubte Ziele
        self.streams = {}             # sid -> Stream (lokale Seite)
        self.pending = {}             # sid -> Future (nur Hub)
        # Hub vergibt ungerade, Agent gerade Stream-IDs -> keine Kollisionen,
        # wenn beide Seiten gleichzeitig Verbindungen öffnen
        self._sid_start = 1 if role == "hub" else 2
        self._next_sid = self._sid_start
        self._tasks = set()
        self.closed = False

    def alloc_sid(self):
        sid = self._next_sid
        self._next_sid += 2
        if self._next_sid > 0xFFFFFFF0:
            self._next_sid = self._sid_start
        return sid

    def _spawn(self, coro):
        t = asyncio.create_task(coro)
        self._tasks.add(t)
        t.add_done_callback(self._tasks.discard)

    async def run(self):
        pinger = asyncio.create_task(self._keepalive())
        try:
            while True:
                mtype, sid, payload = await self.ch.recv()
                await self._dispatch(mtype, sid, payload)
        except asyncio.IncompleteReadError:
            log.info("[%s] Tunnel geschlossen", self.name)
        except (ConnectionError, OSError, ProtocolError) as e:
            log.warning("[%s] Tunnel-Fehler: %s", self.name, e)
        finally:
            pinger.cancel()
            self.close()

    async def _keepalive(self):
        try:
            while True:
                await asyncio.sleep(PING_INTERVAL)
                if time.monotonic() - self.ch.last_rx > TIMEOUT:
                    log.warning("[%s] keine Antwort seit %ds – trenne", self.name, TIMEOUT)
                    self.ch.close()
                    return
                await self.ch.send(T_PING)
        except (ConnectionError, OSError):
            self.ch.close()

    async def _dispatch(self, mtype, sid, payload):
        if mtype == T_PING:
            await self.ch.send(T_PONG)
        elif mtype == T_PONG:
            pass
        elif mtype == T_DATA:
            st = self.streams.get(sid)
            if st is None:
                return
            try:
                st.writer.write(payload)
                await st.writer.drain()
            except (ConnectionError, OSError):
                await self.end_stream(sid)
        elif mtype == T_EOF:
            st = self.streams.get(sid)
            if st is None:
                return
            st.got_eof = True
            try:
                if st.writer.can_write_eof():
                    st.writer.write_eof()
            except (ConnectionError, OSError):
                pass
            if st.sent_eof:
                self.streams.pop(sid, None)
                st.writer.close()
        elif mtype == T_CLOSE:
            st = self.streams.pop(sid, None)
            if st is not None:
                st.writer.close()
            fut = self.pending.pop(sid, None)
            if fut and not fut.done():
                fut.set_result((False, "Gegenseite hat geschlossen"))
        elif mtype == T_OPEN:
            if self.allow is None:
                await self.ch.send(T_OPEN_FAIL, sid, b"Gegenseite erlaubt keine Ziele")
            else:
                self._spawn(self._open_local(sid, payload.decode("utf-8", "replace")))
        elif mtype in (T_OPEN_OK, T_OPEN_FAIL):
            fut = self.pending.pop(sid, None)
            if fut and not fut.done():
                fut.set_result((mtype == T_OPEN_OK, payload.decode("utf-8", "replace")))
        else:
            raise ProtocolError(f"unerwarteter Nachrichtentyp {mtype}")

    async def pump(self, sid, reader):
        """Lokaler Socket -> Tunnel. Halbes Schließen wird als T_EOF weitergereicht."""
        try:
            while True:
                data = await reader.read(CHUNK)
                if not data:
                    break
                await self.ch.send(T_DATA, sid, data)
        except (ConnectionError, OSError):
            await self.end_stream(sid)
            return
        except asyncio.CancelledError:
            await self.end_stream(sid)
            raise
        st = self.streams.get(sid)
        if st is None:
            return
        st.sent_eof = True
        try:
            await self.ch.send(T_EOF, sid)
        except (ConnectionError, OSError):
            return
        if st.got_eof:
            self.streams.pop(sid, None)
            st.writer.close()

    async def end_stream(self, sid):
        st = self.streams.pop(sid, None)
        if st is None:
            return
        st.writer.close()
        if not self.closed:
            try:
                await self.ch.send(T_CLOSE, sid)
            except (ConnectionError, OSError):
                pass

    async def _open_local(self, sid, target):
        if target not in self.allow:
            log.warning("[%s] Ziel %s nicht in --allow, abgelehnt", self.name, target)
            await self.ch.send(T_OPEN_FAIL, sid, b"Ziel nicht erlaubt")
            return
        host, port = split_hostport(target)
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(host, port), 10)
        except Exception as e:
            log.warning("[%s] Verbindung zu %s fehlgeschlagen: %s", self.name, target, e)
            await self.ch.send(T_OPEN_FAIL, sid, str(e).encode()[:200])
            return
        tune_socket(w)
        self.streams[sid] = Stream(w)
        log.info("[%s] Stream %d -> %s geöffnet", self.name, sid, target)
        await self.ch.send(T_OPEN_OK, sid)
        await self.pump(sid, r)
        log.info("[%s] Stream %d beendet", self.name, sid)

    async def open_remote(self, reader, writer, target, label):
        """Lokale Verbindung über den Tunnel zu 'target' auf der Gegenseite."""
        tune_socket(writer)
        sid = self.alloc_sid()
        fut = asyncio.get_running_loop().create_future()
        self.pending[sid] = fut
        self.streams[sid] = Stream(writer)   # schon jetzt, damit frühe Daten nicht verloren gehen
        try:
            await self.ch.send(T_OPEN, sid, target.encode())
            ok, msg = await asyncio.wait_for(fut, OPEN_TIMEOUT)
        except Exception as e:
            ok, msg = False, str(e) or "Zeitüberschreitung"
        if not ok:
            self.pending.pop(sid, None)
            self.streams.pop(sid, None)
            log.warning("%s fehlgeschlagen: %s", label, msg)
            writer.close()
            return
        log.info("%s (Stream %d)", label, sid)
        await self.pump(sid, reader)

    def close(self):
        if self.closed:
            return
        self.closed = True
        for st in self.streams.values():
            st.writer.close()
        self.streams.clear()
        for fut in self.pending.values():
            if not fut.done():
                fut.set_result((False, "Tunnel getrennt"))
        self.pending.clear()
        for t in list(self._tasks):
            t.cancel()
        self.ch.close()


# ---------------------------------------------------------------------------
# Hub
# ---------------------------------------------------------------------------

class Hub:
    def __init__(self, psk, forwards, http=False, path="/minitail", ssl_ctx=None,
                 allow=None):
        self.psk = psk
        self.allow = set(allow) if allow else None     # Ziele für Rückrichtung
        self.forwards = forwards
        self.http = http or ssl_ctx is not None
        self.path = path
        self.ssl_ctx = ssl_ctx
        self.agents = {}

    async def handle_agent(self, reader, writer):
        peer_addr = writer.get_extra_info("peername")
        tune_socket(writer)
        try:
            if self.http:
                await http_accept(reader, writer, self.path)
            ch = await handshake(reader, writer, self.psk, "hub")
            mtype, _, payload = await asyncio.wait_for(ch.recv(), 10)
            if mtype != T_HELLO:
                raise ProtocolError("HELLO erwartet")
            name = str(json.loads(payload).get("name", ""))[:64]
            if not name:
                raise ProtocolError("Agent ohne Namen")
        except Exception as e:
            log.warning("Abgewiesen: %s (%s)", peer_addr, e or type(e).__name__)
            writer.close()
            return

        old = self.agents.get(name)
        if old:
            log.info("[%s] ersetzt ältere Verbindung", name)
            old.close()
        peer = Peer(ch, name, allow=self.allow, role="hub")
        self.agents[name] = peer
        await ch.send(T_WELCOME, 0, json.dumps({"version": VERSION}).encode())
        log.info("[%s] Agent verbunden von %s", name, peer_addr)
        try:
            await peer.run()
        finally:
            if self.agents.get(name) is peer:
                del self.agents[name]
            log.info("[%s] Agent getrennt", name)

    async def handle_local(self, reader, writer, fw):
        bind, lport, agent, target = fw
        peer = self.agents.get(agent)
        if peer is None or peer.closed:
            log.warning("Port %d: Agent '%s' ist nicht verbunden", lport, agent)
            writer.close()
            return
        await peer.open_remote(reader, writer, target, f"Port {lport} -> {agent}:{target}")

    async def serve(self, listen):
        host, port = split_hostport(listen)
        if host == "*":
            host = None                 # alle Adressen, IPv4 und IPv6
        servers = [await asyncio.start_server(self.handle_agent, host, port,
                                              ssl=self.ssl_ctx)]
        mode = "TLS+HTTP" if self.ssl_ctx else ("HTTP" if self.http else "TCP")
        log.info("Hub wartet auf Agents an %s (%s, Pfad %s)", listen, mode,
                 self.path if self.http else "-")
        for fw in self.forwards:
            bind, lport, agent, target = fw
            srv = await asyncio.start_server(
                lambda r, w, fw=fw: self.handle_local(r, w, fw), bind, lport)
            servers.append(srv)
            log.info("Weiterleitung %s:%d -> %s:%s", bind, lport, agent, target)
        if self.allow:
            log.info("Rückrichtung erlaubt zu: %s", ", ".join(sorted(self.allow)))
        await asyncio.gather(*(s.serve_forever() for s in servers))


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

async def run_agent(opts, psk):
    hub, name, allow = opts.hub, opts.name, opts.allow
    state = {"peer": None}

    async def on_local(reader, writer, fw):
        bind, lport, target = fw
        peer = state["peer"]
        if peer is None or peer.closed:
            log.warning("Port %d: nicht mit dem Hub verbunden", lport)
            writer.close()
            return
        await peer.open_remote(reader, writer, target, f"Port {lport} -> Hub:{target}")

    for fw in opts.forward:
        bind, lport, target = fw
        await asyncio.start_server(lambda r, w, fw=fw: on_local(r, w, fw), bind, lport)
        log.info("Rück-Weiterleitung %s:%d -> Hub:%s", bind, lport, target)

    backoff = 1
    while True:
        try:
            r, w = await open_agent_transport(opts)
            ch = await handshake(r, w, psk, "agent")
            await ch.send(T_HELLO, 0, json.dumps({"name": name, "version": VERSION}).encode())
            try:
                mtype, _, _ = await asyncio.wait_for(ch.recv(), 10)
            except asyncio.IncompleteReadError:
                raise ProtocolError("Hub hat abgelehnt (falscher Schlüssel?)")
            if mtype != T_WELCOME:
                raise ProtocolError("WELCOME erwartet")
            log.info("Mit Hub %s verbunden als '%s'", hub, name)
            backoff = 1
            peer = Peer(ch, name, allow=set(allow) if allow else None, role="agent")
            state["peer"] = peer
            await peer.run()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            log.warning("Hub %s: %s", hub, e or type(e).__name__)
        log.info("Neuer Versuch in %ds", backoff)
        await asyncio.sleep(backoff)
        backoff = min(backoff * 2, 60)


# ---------------------------------------------------------------------------
# Hilfsfunktionen / CLI
# ---------------------------------------------------------------------------

def split_hostport(s):
    s = s.strip()
    if s.startswith("["):                       # [::1]:22
        host, _, port = s[1:].partition("]:")
    else:
        host, _, port = s.rpartition(":")
    if not port.isdigit():
        raise ValueError(f"Port fehlt in '{s}'")
    return host or "0.0.0.0", int(port)


def normalize_target(s):
    host, port = split_hostport(s)
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def parse_forward(spec):
    """[bind:]lport=agent:host:port"""
    try:
        left, right = spec.split("=", 1)
        if ":" in left:
            bind, lport = left.rsplit(":", 1)
        else:
            bind, lport = "127.0.0.1", left
        agent, target = right.split(":", 1)
        return bind, int(lport), agent, normalize_target(target)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"'{spec}' – Format: [bind:]lokalport=agentname:zielhost:zielport")


def parse_agent_forward(spec):
    """[bind:]lport=zielhost:zielport  (Ziel aus Sicht des Hubs)"""
    try:
        left, right = spec.split("=", 1)
        if ":" in left:
            bind, lport = left.rsplit(":", 1)
        else:
            bind, lport = "127.0.0.1", left
        return bind, int(lport), normalize_target(right)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"'{spec}' – Format: [bind:]lokalport=zielhost:zielport")


def load_key(args):
    raw = os.environ.get("MINITAIL_KEY")
    if args.key_file:
        with open(args.key_file) as f:
            raw = f.read()
    if not raw:
        sys.exit("Kein Schlüssel: --key-file angeben oder MINITAIL_KEY setzen "
                 "(erzeugen mit: minitail.py genkey)")
    try:
        key = base64.b64decode(raw.strip(), validate=True)
    except Exception:
        sys.exit("Schlüssel ist kein gültiges Base64")
    if len(key) < 32:
        sys.exit("Schlüssel zu kurz – bitte mit 'genkey' erzeugen")
    return key


def main():
    ap = argparse.ArgumentParser(description="minitail – Mini-Tunnel à la Tailscale")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("genkey", help="neuen Schlüssel ausgeben")

    g = sub.add_parser("gencert", help="selbstsigniertes TLS-Zertifikat für den Hub")
    g.add_argument("--out", default="hub", help="Dateiname ohne Endung (-> .crt/.key)")
    g.add_argument("--cn", default="minitail-hub", help="Name im Zertifikat")
    g.add_argument("--days", type=int, default=3650)

    h = sub.add_parser("hub", help="Hub (erreichbarer Rechner, z. B. zu Hause)")
    h.add_argument("--key-file")
    h.add_argument("--listen", default="*:41700",
                   help="Adresse für Agents (*:port = IPv4 und IPv6)")
    h.add_argument("--forward", action="append", type=parse_forward, default=[],
                   help="[bind:]lokalport=agent:zielhost:zielport (mehrfach)")
    h.add_argument("--tls-cert", help="TLS-Zertifikat (PEM) -> HTTPS-Modus")
    h.add_argument("--tls-key", help="privater TLS-Schlüssel (PEM)")
    h.add_argument("--http", action="store_true",
                   help="HTTP-Upgrade ohne eigenes TLS (z. B. hinter nginx)")
    h.add_argument("--path", default="/minitail", help="URL-Pfad für das Upgrade")
    h.add_argument("--allow", action="append", type=normalize_target, default=[],
                   help="Rückrichtung: Ziel host:port, das Agents erreichen dürfen")

    a = sub.add_parser("agent", help="Agent (Rechner hinter NAT)")
    a.add_argument("--key-file")
    a.add_argument("--name", default=socket.gethostname())
    a.add_argument("--hub", required=True, help="host:port des Hubs")
    a.add_argument("--allow", action="append", type=normalize_target, default=[],
                   help="erlaubtes Ziel host:port (mehrfach)")
    a.add_argument("--https", action="store_true", help="Tunnel in TLS + HTTP verpacken")
    a.add_argument("--http", action="store_true", help="nur HTTP-Upgrade, ohne TLS (Tests)")
    a.add_argument("--pin", help="SHA-256-Fingerabdruck des Hub-Zertifikats")
    a.add_argument("--ca", help="CA-Datei statt Systemzertifikaten (ohne --pin)")
    a.add_argument("--sni", help="Hostname für TLS/HTTP, falls abweichend von --hub")
    a.add_argument("--path", default="/minitail", help="URL-Pfad für das Upgrade")
    a.add_argument("--proxy", help="HTTP-Proxy [user:pass@]host:port (CONNECT)")
    a.add_argument("--forward", action="append", type=parse_agent_forward, default=[],
                   help="Rückrichtung: [bind:]lokalport=zielhost:zielport beim Hub")

    args = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(message)s",
                        datefmt="%H:%M:%S")

    if args.cmd == "genkey":
        print(base64.b64encode(secrets.token_bytes(32)).decode())
        return
    if args.cmd == "gencert":
        generate_cert(args.out, args.cn, args.days)
        return

    psk = load_key(args)
    try:
        if args.cmd == "hub":
            ctx = None
            if args.tls_cert or args.tls_key:
                if not (args.tls_cert and args.tls_key):
                    sys.exit("--tls-cert und --tls-key gehören zusammen")
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                ctx.load_cert_chain(args.tls_cert, args.tls_key)
                with open(args.tls_cert, "rb") as f:
                    der = ssl.PEM_cert_to_DER_cert(f.read().decode())
                log.info("TLS-Fingerabdruck (für --pin): %s", cert_fingerprint(der))
            asyncio.run(Hub(psk, args.forward, http=args.http, path=args.path,
                            ssl_ctx=ctx, allow=args.allow).serve(args.listen))
        else:
            if not args.allow and not args.forward:
                sys.exit("Agent braucht mindestens ein --allow oder --forward")
            if args.pin and not args.https:
                sys.exit("--pin nur zusammen mit --https")
            asyncio.run(run_agent(args, psk))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
