import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as net from "node:net";
import * as tls from "node:tls";
import * as stream from "node:stream";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import * as lpstream from "@hardpointlabs/length-prefixed-stream";
import { createMlKem768 } from "mlkem";

const H7T_PEER_PUBKEY_HEADER = "H7T-Peer-PubKey";
const H7T_ORG_HEADER = "H7T-Org";

const CIPHER_ALGO = "aes-256-gcm";

const RELAY_HOST = "relay.hardpoint.dev";
const RELAY_PORT = 443;

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CA_CERT = fs.readFileSync(path.join(__dirname, "ca.crt"));

function getOidcToken(): string | undefined {
  return process.env.VERCEL_OIDC_TOKEN;
}

function createEncryptionTransforms(key: Buffer, ciphertext: Uint8Array): { encrypt: stream.Transform; decrypt: stream.Transform } {
  const ivLength = 12;
  const authTagLength = 16;

  const encrypt = new stream.Transform({
    construct(callback) {
      console.log("Sending ciphertext");
      this.push(ciphertext);
      callback();
    },
    transform(chunk: Buffer, _encoding, callback) {
      const iv = crypto.randomBytes(ivLength);
      const cipher = crypto.createCipheriv(CIPHER_ALGO, key, iv);
      cipher.setAAD(Buffer.alloc(0));
      const encrypted = Buffer.concat([cipher.update(chunk), cipher.final()]);
      const authTag = cipher.getAuthTag();

      // TODO - avoid copy here
      const result = Buffer.concat([iv, encrypted, authTag]);

      console.log("iv", crypto.createHash("sha256").update(iv).digest("hex"));
      console.log("tag", crypto.createHash("sha256").update(authTag).digest("hex"));
      console.log("ciphertext", crypto.createHash("sha256").update(Buffer.concat([encrypted, authTag])).digest("hex"));

      callback(null, result);
    },
  });

  const decrypt = new stream.Transform({
    transform(chunk: Buffer, _encoding, callback) {
      console.log("Got response %d bytes encrypted payload", chunk.length);
      try {
        const iv = chunk.subarray(0, ivLength);
        const authTag = chunk.subarray(chunk.length - authTagLength, chunk.length);
        const encrypted = chunk.subarray(ivLength, chunk.length - authTagLength);

        console.log("iv", crypto.createHash("sha256").update(iv).digest("hex"));
        console.log("tag", crypto.createHash("sha256").update(authTag).digest("hex"));
        console.log("ciphertext", crypto.createHash("sha256").update(Buffer.concat([encrypted, authTag])).digest("hex"));

        const decipher = crypto.createDecipheriv(CIPHER_ALGO, key, iv);
        decipher.setAuthTag(authTag);

        // TODO - also avoid copy here
        const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
        callback(null, decrypted);
      } catch (err) {
        callback(err as Error);
      }
    },
  });

  return { encrypt, decrypt };
}

async function connectTunnel({
  org_id,
  relayHost,
  relayPort = RELAY_PORT,
  token,
  service,
}: {
  org_id: string;
  relayHost: string;
  relayPort?: number;
  token: string;
  service: string;
}): Promise<stream.Duplex> {
  const sender = await createMlKem768();

  const rejectUnauthorized = relayHost === "localhost" ? false : true;

  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      relayPort,
      relayHost,
      {
        servername: relayHost,
        ca: CA_CERT,
        rejectUnauthorized: rejectUnauthorized,
        minVersion: "TLSv1.3"
      },
      () => {}
    );

    socket.on("secureConnect", () => {
      const connectRequest = [
        `CONNECT ${service} HTTP/1.1`,
        `Host: ${service}`,
        `Authorization: Bearer ${token}`,
        `${H7T_ORG_HEADER}: ${org_id}`,
        "",
        "",
      ].join("\r\n");

      socket.write(connectRequest);
    });

    let buffer = "";

    socket.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      if (buffer.includes("\r\n\r\n")) {
        if (!buffer.startsWith("HTTP/1.1 200") && !buffer.startsWith("HTTP/1.0 200")) {
          reject(new Error(`Tunnel failed: ${buffer.split("\r\n")[0]}`));
          socket.destroy();
          return;
        }

        const headerEndIndex = buffer.indexOf("\r\n\r\n");
        const headers = buffer.slice(0, headerEndIndex);
        const rest = buffer.slice(headerEndIndex + 4);

        const peerPubKeyMatch = headers.match(/H7T-Peer-PubKey:\s*([^\r\n]+)/i);
        if (!peerPubKeyMatch) {
          reject(new Error(`Missing ${H7T_PEER_PUBKEY_HEADER} header in response`));
          socket.destroy();
          return;
        }

        const peerPublicKey = Buffer.from(peerPubKeyMatch[1].trim(), "base64");

        const [ciphertext, sharedSecret] = sender.encap(peerPublicKey);
        const key = crypto.hkdfSync("sha256",
          Buffer.from(sharedSecret),
          Buffer.alloc(0),                    // salt (see note below)
          Buffer.alloc(0),   // context separation
          32)

        const kb = Buffer.from(key); // derived
        console.log("shared secret:", crypto.createHash("sha256").update(sharedSecret).digest("hex"))
        console.log("key from shared secret:", kb.toString("hex"));

        socket.removeAllListeners("data");

        if (rest?.length) {
          socket.unshift(Buffer.from(rest));
        }

        const encryptedSocket = wrapSocketWithEncryption(socket, key, ciphertext);
        resolve(encryptedSocket);
      }
    });

    socket.on("error", reject);
  });
}

function wrapSocketWithEncryption(socket: net.Socket, hkdfKey: ArrayBuffer, ciphertext: Uint8Array): stream.Duplex {
  const key = Buffer.from(hkdfKey); // derived
  console.log("key:", key.toString("hex"));

  const { encrypt, decrypt }: { encrypt: stream.Transform; decrypt: stream.Transform } = createEncryptionTransforms(key, ciphertext);

  const encoder: stream.Transform = new lpstream.Encoder();
  const decoder: stream.Transform = new lpstream.Decoder();

  encrypt.pipe(encoder).pipe(socket);
  socket.pipe(decoder).pipe(decrypt);

  return stream.Duplex.from({
    readable: decrypt,
    writable: encrypt
  });
}

function streamToSocketLike(rawSocket: stream.Duplex): TcpSocketLike {
  const sockLike = rawSocket as TcpSocketLike;

  sockLike.remoteHost = "TODO";
  sockLike.remotePort = -1;
  sockLike.serviceName = "TODO";

  const dispose = () => new Promise<void>((resolve) => {
    const cleanup = () => {
      sockLike.removeAllListeners();
      resolve();
    };

    const forceClose = () => {
      cleanup();
    };

    const timeoutId = setTimeout(forceClose, 2000);

    sockLike.on("close", () => {
      clearTimeout(timeoutId);
      cleanup();
    });

    sockLike.end();
  });

  sockLike[Symbol.asyncDispose] = dispose;

  sockLike.httpTransport = () => asHttpSocket(sockLike);

  return sockLike;
}

function socketLikeToUnixLike(duplex: stream.Duplex): ListeningUnixSocket {
  const sockLike = {} as ListeningUnixSocket;

  sockLike.remoteHost = "TODO";
  sockLike.remotePort = -1;
  sockLike.serviceName = "TODO";

  sockLike.path = generateSocketName();

  const server = net.createServer((clientSocket) => {
    clientSocket.pipe(duplex);
    duplex.pipe(clientSocket);

    clientSocket.on("error", (_err) => {
      duplex.end();
    });
  });

  sockLike.listen = () => new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error("Failed to start unix socket listener"));
    }, 5000);

    server.listen(sockLike.path, () => {
      clearTimeout(timeout);
      resolve();
    });

    server.on("error", (err) => {
      clearTimeout(timeout);
      reject(err);
    });
  });

  let disposed = false;

  const dispose = () => new Promise<void>((resolve, reject) => {
    if (disposed) {
      resolve();
      return;
    }
    disposed = true;

    duplex.end();
    server.close((_err) => {
      fs.unlink(sockLike.path, () => {
        if (_err) {
          reject(_err);
        } else {
          resolve();
        }
      });
    });
  });

  sockLike[Symbol.asyncDispose] = dispose;

  return sockLike;
}

function generateSocketName(): string {
  const dir = "/tmp/hardpoint";
  fs.mkdirSync(dir, { mode: 0o700, recursive: true });
  const randomSuffix = crypto.randomBytes(8).toString("hex");
  return path.join(dir, `${randomSuffix}.sock`);
}

export type SdkOptions = {
  org_id: string;
  token?: string;
  relayHost?: string;
  relayPort?: number;
}

export type ConnectOptions = {
  service: string;
}

type EncryptionScheme = "ML-KEM" | undefined;

export type Tunnel = {
  serviceName: string;
  remoteHost: string;
  remotePort: number;
  encryptionScheme: EncryptionScheme;
}

export type TcpSocketLike = Tunnel & AsyncDisposable & stream.Duplex & {
  httpTransport: () => HttpSocketLike
}

export type UnixSocketLike = Tunnel & AsyncDisposable & {
  path: string;
}

type ListeningUnixSocket = UnixSocketLike & {
  listen: () => Promise<void>;
}

export type HttpSocketLike = stream.Duplex & {
  setTimeout: (timeout?: number, callback?: () => void) => any;
  setNoDelay: (noDelay?: boolean) => any;
  setKeepAlive: (enable?: boolean, initialDelay?: number) => any;
  ref: () => any;
  unref: () => any;
  destroy: (error?: Error) => any;
}

function asHttpSocket(duplex: stream.Duplex): HttpSocketLike {
  const socket = duplex as HttpSocketLike;

  socket.setTimeout ??= () => socket;
  socket.setNoDelay ??= () => socket;
  socket.setKeepAlive ??= () => socket;
  socket.ref ??= () => socket;
  socket.unref ??= () => socket;

  // ensure destroy exists (usually does, but TS wants it explicit)
  socket.destroy ??= ((err?: Error) => {
    duplex.destroy(err);
    return socket;
  });

  process.nextTick(() => {
    socket.emit('connect');
  });

  return socket;
}

export class Sdk {
  private readonly org_id: string;
  private readonly token: string | undefined;
  private readonly relayHost: string;
  private readonly relayPort: number;

  public constructor(options: SdkOptions) {
    this.org_id = options.org_id;
    this.token = options.token ?? getOidcToken();
    this.relayHost = options.relayHost ?? RELAY_HOST;
    this.relayPort = options.relayPort ?? RELAY_PORT;
  }

  public async connect(options: ConnectOptions): Promise<TcpSocketLike> {
    if (!this.token) {
      throw new Error(
        "OIDC token not found. Set VERCEL_OIDC_TOKEN environment variable or pass token in getInstance()."
      );
    }

    const socket = await connectTunnel({
      org_id: this.org_id,
      relayHost: this.relayHost,
      relayPort: this.relayPort,
      token: this.token,
      service: options.service,
    });

    return streamToSocketLike(socket);
  }

  public async connectAndListen(options: ConnectOptions): Promise<UnixSocketLike> {
    if (!this.token) {
      throw new Error(
        "OIDC token not found. Set VERCEL_OIDC_TOKEN environment variable or pass token in getInstance()."
      );
    }

    const remoteSocket = await connectTunnel({
      org_id: this.org_id,
      relayHost: this.relayHost,
      relayPort: this.relayPort,
      token: this.token,
      service: options.service,
    });

    const handle = socketLikeToUnixLike(remoteSocket)
    await handle.listen();
    return handle;
  }
}