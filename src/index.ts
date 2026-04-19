import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as net from "node:net";
import * as tls from "node:tls";
import * as stream from "node:stream";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import * as lpstream from "@hardpointlabs/length-prefixed-stream";

const H7T_CLIENT_PUBKEY_HEADER = "H7T-Client-PubKey";
const H7T_PEER_PUBKEY_HEADER = "H7T-Peer-PubKey";
const H7T_ORG_HEADER = "H7T-Org";

const RELAY_HOST = "relay.hardpoint.dev";
const RELAY_PORT = 443;

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CA_CERT = fs.readFileSync(path.join(__dirname, "ca.crt"));

function getOidcToken(): string | undefined {
  return process.env.VERCEL_OIDC_TOKEN;
}

function connectTunnel({
  org_id,
  relayHost,
  relayPort = RELAY_PORT,
  token,
  service,
  publicKey,
}: {
  org_id: string;
  relayHost: string;
  relayPort?: number;
  token: string;
  service: string;
  publicKey: Buffer;
}): Promise<{ socket: net.Socket; peerPublicKey: Buffer }> {
  const rejectUnauthorized = relayHost === "localhost" ? false : true;
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      relayPort,
      relayHost,
      {
        servername: relayHost,
        ca: CA_CERT,
        rejectUnauthorized: rejectUnauthorized,
      },
      () => {}
    );

    socket.on("secureConnect", () => {
      const encodedPublicKey = publicKey.toString("base64");
      const connectRequest = [
        `CONNECT ${service} HTTP/1.1`,
        `Host: ${service}`,
        `Authorization: Bearer ${token}`,
        `${H7T_CLIENT_PUBKEY_HEADER}: ${encodedPublicKey}`,
        `${H7T_ORG_HEADER}: ${org_id}`,
        "",
        "",
      ].join("\r\n");

      socket.write(connectRequest);
    });

    let buffer = "";

    socket.on("data", (chunk) => {
      console.log("OH LAWD WE GOT THE DATA")
      buffer += chunk.toString("utf8");
      if (buffer.includes("\r\n\r\n")) {
        console.log(buffer)
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

        socket.removeAllListeners("data");

        if (rest?.length) {
          socket.unshift(Buffer.from(rest));
        }

        resolve({ socket, peerPublicKey });
      }
    });

    socket.on("error", reject);
  });
}

function performKeyExchange(
  keyExchange: KeyExchange,
  peerPublicKey: Buffer,
  rawSocket: net.Socket
): { framed: stream.Duplex; encrypt: stream.Transform; decrypt: stream.Transform } {
  const encoder = new lpstream.Encoder();
  const decoder = new lpstream.Decoder();

  const framed = new stream.Duplex({
    read() {},
    write(chunk, _encoding, callback) {
      encoder.write(chunk, callback);
    },
    final(callback) {
      encoder.end();
      callback();
    },
    destroy(error, callback) {
      rawSocket.destroy(error ?? undefined);
      callback(error ?? undefined);
    },
  });

  encoder.pipe(rawSocket);
  rawSocket.pipe(decoder);

  const sharedSecret = keyExchange.deriveSharedSecret(peerPublicKey);
  console.log("Derived shared secret!")
  const { encrypt, decrypt } = createCipherPair(sharedSecret);

  return { framed, encrypt, decrypt };
}

class KeyExchange {
  private readonly keyPair: crypto.ECDH;

  constructor(curve = "prime256v1") {
    this.keyPair = crypto.createECDH(curve);
    this.keyPair.generateKeys();
  }

  getPublicKey(): Buffer {
    return this.keyPair.getPublicKey();
  }

  deriveSharedSecret(remotePublicKey: Buffer): Buffer {
    return this.keyPair.computeSecret(remotePublicKey);
  }
}

function createCipherPair(sharedSecret: Buffer): { encrypt: stream.Transform; decrypt: stream.Transform } {
  const key = crypto.createHash("sha256").update(sharedSecret).digest();
  const ivLength = 12;
  const authTagLength = 16;

  const encrypt = new stream.Transform({
    transform(chunk, _encoding, callback) {
      const iv = crypto.randomBytes(ivLength);
      const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
      const encrypted = Buffer.concat([cipher.update(chunk), cipher.final()]);
      const authTag = cipher.getAuthTag();

      const result = Buffer.concat([iv, authTag, encrypted]);
      callback(null, result);
    },
  });

  const decrypt = new stream.Transform({
    transform(chunk, _encoding, callback) {
      try {
        const iv = chunk.subarray(0, ivLength);
        const authTag = chunk.subarray(ivLength, ivLength + authTagLength);
        const encrypted = chunk.subarray(ivLength + authTagLength);

        const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
        decipher.setAuthTag(authTag);

        const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
        callback(null, decrypted);
      } catch (err) {
        callback(err as Error);
      }
    },
  });

  return { encrypt, decrypt };
}

class TcpSocketHandleImpl implements TcpSocketHandle {
  public readonly connection: stream.Duplex;

  constructor(connection: stream.Duplex) {
    this.connection = connection;
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await this.dispose();
  }

  private async dispose(): Promise<void> {
    return new Promise<void>((resolve) => {
      const connection = this.connection;

      const cleanup = () => {
        connection.removeAllListeners();
        resolve();
      };

      const forceClose = () => {
        cleanup();
      };

      const timeoutId = setTimeout(forceClose, 2000);

      connection.on("close", () => {
        clearTimeout(timeoutId);
        cleanup();
      });

      connection.end();
    });
  }
}

function socketToDuplex(keyExchange: KeyExchange, peerPublicKey: Buffer, rawSocket: net.Socket): TcpSocketHandle {
  const { framed, encrypt, decrypt } = performKeyExchange(keyExchange, peerPublicKey, rawSocket);

  const duplex = new stream.Duplex({
    read() {},
    write(chunk, encoding, callback) {
      encrypt.write(chunk, encoding, callback);
    },
    final(callback) {
      encrypt.end();
      callback();
    },
    destroy(error, callback) {
      framed.destroy(error ?? undefined);
      callback(error ?? undefined);
    },
  });

  decrypt.on("data", (chunk) => {
    duplex.push(chunk);
  });

  decrypt.on("end", () => {
    duplex.push(null);
  });

  decrypt.on("error", (err: Error) => {
    duplex.destroy(err);
  });

  encrypt.pipe(framed);
  framed.pipe(decrypt);

  return new TcpSocketHandleImpl(duplex);
}

function generateSocketName(): string {
  const dir = "/tmp/hardpoint";
  fs.mkdirSync(dir, { mode: 0o700, recursive: true });
  const randomSuffix = crypto.randomBytes(8).toString("hex");
  return path.join(dir, `${randomSuffix}.sock`);
}

class UnixSocketHandleImpl implements UnixSocketHandle {
  public readonly path: string;
  private readonly keyExchange: KeyExchange;
  private readonly peerPublicKey: Buffer;
  private server!: net.Server;
  private readonly rawSocket: net.Socket;
  private readonly inputStream: stream.PassThrough;
  private readonly outputStream: stream.PassThrough;
  private disposed = false;

  constructor(keyExchange: KeyExchange, peerPublicKey: Buffer, rawSocket: net.Socket, socketPath: string) {
    this.keyExchange = keyExchange;
    this.peerPublicKey = peerPublicKey;
    this.path = socketPath;
    this.rawSocket = rawSocket;
    this.inputStream = new stream.PassThrough();
    this.outputStream = new stream.PassThrough();
  }

  async initialize(): Promise<void> {
    const { framed, encrypt, decrypt } = performKeyExchange(this.keyExchange, this.peerPublicKey, this.rawSocket);

    decrypt.on("data", (chunk) => {
      this.inputStream.write(chunk);
    });

    decrypt.on("end", () => {
      this.inputStream.end();
    });

    decrypt.on("error", () => {
      this.inputStream.end();
    });

    encrypt.pipe(framed);
    framed.pipe(decrypt);

    this.server = net.createServer((clientSocket) => {
      clientSocket.pipe(this.outputStream);
      this.inputStream.pipe(clientSocket);

      clientSocket.on("error", (_err) => {
        this.inputStream.end();
      });

      this.outputStream.on("error", (_err) => {
        clientSocket.end();
      });
    });
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await this.dispose();
  }

  private async dispose(): Promise<void> {
    return new Promise<void>((resolve) => {
      if (this.disposed) {
        resolve();
        return;
      }
      this.disposed = true;

      this.inputStream.end();
      this.outputStream.end();

      this.server.close((_err) => {
        this.rawSocket.destroy();
        fs.unlink(this.path, () => {
          resolve();
        });
      });
    });
  }

  listen(): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error("Failed to start unix socket listener"));
      }, 5000);

      this.server.listen(this.path, () => {
        clearTimeout(timeout);
        resolve();
      });

      this.server.on("error", (err) => {
        clearTimeout(timeout);
        reject(err);
      });
    });
  }
}

export interface SdkOptions {
  org_id: string;
  token?: string;
  relayHost?: string;
  relayPort?: number;
}

export interface ConnectOptions {
  service: string;
}

export interface TcpSocketHandle extends AsyncDisposable {
  readonly connection: stream.Duplex;
}

export interface UnixSocketHandle extends AsyncDisposable {
  readonly path: string;
}

export class Sdk {
  private readonly org_id: string;
  private readonly token: string | undefined;
  private readonly relayHost: string;
  private readonly relayPort: number;
  private readonly keyExchange: KeyExchange;

  public constructor(options: SdkOptions) {
    this.org_id = options?.org_id;
    this.token = options.token ?? getOidcToken();
    this.relayHost = options.relayHost ?? RELAY_HOST;
    this.relayPort = options.relayPort ?? RELAY_PORT;
    this.keyExchange = new KeyExchange();
  }

  private async getTunnelSocket(options: ConnectOptions): Promise<{ socket: net.Socket; peerPublicKey: Buffer }> {
    if (!this.token) {
      throw new Error(
        "OIDC token not found. Set VERCEL_OIDC_TOKEN environment variable or pass token in getInstance()."
      );
    }

    return connectTunnel({
      org_id: this.org_id,
      relayHost: this.relayHost,
      relayPort: this.relayPort,
      token: this.token,
      service: options.service,
      publicKey: this.keyExchange.getPublicKey(),
    });
  }

  async connect(options: ConnectOptions): Promise<TcpSocketHandle> {
    const { socket: rawSocket, peerPublicKey } = await this.getTunnelSocket(options);
    return socketToDuplex(this.keyExchange, peerPublicKey, rawSocket);
  }

  async connectAndListen(options: ConnectOptions): Promise<UnixSocketHandle> {
    const { socket: rawSocket, peerPublicKey } = await this.getTunnelSocket(options);
    const socketPath = generateSocketName();
    const handle = new UnixSocketHandleImpl(this.keyExchange, peerPublicKey, rawSocket, socketPath);
    await handle.initialize();
    await handle.listen();
    return handle;
  }
}
