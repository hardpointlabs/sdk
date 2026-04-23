import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as net from "node:net";
import * as tls from "node:tls";
import * as stream from "node:stream";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import * as lpstream from "@hardpointlabs/length-prefixed-stream";
import { createMlKem768 } from "mlkem";
import { Logger, noopLogger } from "./logging.js";

const H7T_PEER_PUBKEY_HEADER = "H7T-Peer-PubKey";
const H7T_ORG_HEADER = "H7T-Org";

const CIPHER_ALGO = "aes-256-gcm";

const RELAY_HOST = "relay.hardpoint.dev";
const RELAY_PORT = 443;

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CA_CERT = fs.readFileSync(path.join(__dirname, "ca.crt"));

function createEncryptionTransforms(logger: Logger, key: Buffer, ciphertext: Uint8Array): { encrypt: stream.Transform; decrypt: stream.Transform } {
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
  logger,
  org_id,
  relayHost,
  relayPort = RELAY_PORT,
  token,
  service,
}: {
  logger: Logger;
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

        const encryptedSocket = wrapSocketWithEncryption(logger, socket, key, ciphertext);
        resolve(encryptedSocket);
      }
    });

    socket.on("error", reject);
  });
}

function wrapSocketWithEncryption(logger: Logger, socket: net.Socket, hkdfKey: ArrayBuffer, ciphertext: Uint8Array): stream.Duplex {
  const key = Buffer.from(hkdfKey); // derived
  console.log("key:", key.toString("hex"));

  const { encrypt, decrypt }: { encrypt: stream.Transform; decrypt: stream.Transform } = createEncryptionTransforms(logger, key, ciphertext);

  const encoder: stream.Transform = new lpstream.Encoder();
  const decoder: stream.Transform = new lpstream.Decoder();

  encrypt.pipe(encoder).pipe(socket);
  socket.pipe(decoder).pipe(decrypt);

  return stream.Duplex.from({
    readable: decrypt,
    writable: encrypt
  });
}

function streamToSocketLike(rawSocket: stream.Duplex): StreamLike {
  const sockLike = rawSocket as StreamLike;

  sockLike.remoteHost = "TODO";
  sockLike.remotePort = -1;
  sockLike.serviceName = "TODO";

  sockLike.asSocket = () => asSocket(sockLike);

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
  org_id?: string;
  token?: string;
  relayHost?: string;
  relayPort?: number;
  logger: Logger;
}

export type SdkOptionsInput = Partial<Omit<SdkOptions, "logger">> & {
  logger?: Logger;
};

export type ConnectOptions = {
  service: string;
}

type EncryptionScheme = "ML-KEM" | undefined;

/**
 * Base type for connections to remote services established over a secure tunnel via the Hardpoint network.
 *
 * All tunnel types contain some common information that may be helpful, depending on the use case.
 */
export interface Tunnel {
  /**
   * Name of the service.
   * 
   * This corresponds with the name of a service(s) in the Hardpoint Dashboard. See the [documentation on services](https://docs.hardpoint.dev/hardpoint-connect/getting-started/add-services) for more information.
   */
  serviceName: string;
  /**
   * The host that we're connected to on the other side of the network.
   * 
   * This could be any IPv4 address, IPv6 address or valid hostname.
   * 
   * This can be necessary for several use-cases, such as:
   * 
   * * To perform SNI properly with a TLS-enabled service, or;
   * * To pass the correct host header to an HTTP server that validates them
   */
  remoteHost: string;
  /**
   * The resolved port that we're connected to on the other side of the network.
   *
   * This could be any valid port number.
   */
  remotePort: number;
  /**
   * The encryption scheme the tunnel is using.
   */
  encryptionScheme: EncryptionScheme;
}

/**
 * A bidirectional network stream to a service.
 *
 * Although this behaves as a reliable ordered stream of bytes, you should treat this this as a generic
 * `stream.Duplex` since it abstracts the underlying complexity of the tunnel without making
 * assumptions about what Layer 4 transport.
 * 
 * Where a concrete `net.Socket` is required, the {@link StreamLike.asSocket} method is available.
 *
 * This should be disposed of properly when no longer needed.
 */
export interface StreamLike extends Tunnel, stream.Duplex {
  /**
   * Exposes this tunnel as a socket.
   *
   * Use this for cases such as node's own `http` which expects low-level TCP primitive
   * access. Where possible, the owning {@link StreamLike} instance should be preferred, since
   * exact TCP semantics cannot be guaranteed.
   *
   * @returns reference to the same underlying {@link StreamLike} as a `net.Socket`
   */
  asSocket(): net.Socket
}

/**
 * A handle to a UNIX socket connected to a service.
 *
 * Unlike a {@link StreamLike} which can be treated like a regular stream over TCP,
 * you don't interact with this directly; instead, it exposes a {@link UnixSocketLike.path | path} property
 * which points to an ephemeral UNIX socket to be used in clients that can't accept a
 * `stream.Duplex` directly.
 *
 * As with {@link StreamLike}, this should be disposed of properly when no longer needed
 * to clean up associated network resources. See the main {@link Sdk} docs for details. Note that
 * failing to dispose of this will not just leak the underlying tunnel socket, but it will also leave
 * the UNIX socket listener open.
 */
export interface UnixSocketLike extends Tunnel, AsyncDisposable {
  /**
   * Path to the listening UNIX socket.
   *
   * Until the owning {@link UnixSocketLike} object is disposed, it should be assumed that
   * a listener is running at this path and is able to accept connections.
   *
   * In most serverless environments, the path is a random but unique location inside `/tmp`,
   * but no assumptions should be made about where it is created, and callers should treat
   * this as an opaque string.
   */
  path: string;
}

type ListeningUnixSocket = UnixSocketLike & {
  listen: () => Promise<void>;
}

function asSocket(duplex: stream.Duplex): net.Socket {
  const socket = duplex as net.Socket;

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

function getOrgId(fromOptions?: string): string | undefined {
  return fromOptions ?? process.env.HARDPOINT_ORG_ID;
}

function getToken(fromOptions?: string): string | undefined {
  return fromOptions ?? process.env.VERCEL_OIDC_TOKEN;
}

let _sdk: Sdk | undefined;

/**
 * The single touchpoint to the Hardpoint SDK.
 *
 * Use {@link Sdk.init} to create or retrieve the singleton instance.
 */
export class Sdk {
  private readonly logger: Logger;
  private readonly org_id: string;
  private readonly token: string;
  private readonly relayHost: string;
  private readonly relayPort: number;

  /**
   * Initialize or retrieve the singleton SDK instance.
   *
   * This should only be done once on application startup. See {@link SdkOptions} for configuration options.
   *
   * @param options SDK configuration options
   * @returns The singleton SDK instance
   */
  public static init(options: SdkOptionsInput = {}): Sdk {
    if (!_sdk) {
      _sdk = new Sdk(options);
    }
    return _sdk;
  }

  /**
   * Create a new SDK instance.
   *
   * This should only be done once on application startup. See {@link SdkOptions} for configuration options.
   */
  private constructor(options: SdkOptionsInput = {}) {
    const derivedToken = getToken(options.token)
    if (!derivedToken) {
      throw new Error(
        "OIDC token not found. Set VERCEL_OIDC_TOKEN environment variable or pass token in getInstance()."
      );
    }
    const derivedOrgId = getOrgId(options.org_id);
    if (!derivedOrgId) {
      throw new Error("Missing Org ID! See the docs at https://github.com/hardpointlabs/sdk to learn more");
    }

    this.logger = options.logger ?? noopLogger;
    this.org_id = derivedOrgId;
    this.token = derivedToken;
    this.relayHost = options.relayHost ?? RELAY_HOST;
    this.relayPort = options.relayPort ?? RELAY_PORT;
  }

  /**
   * Establish a tunnel to a service on your Hardpoint network.
   *
   * Locates the service and sets up an encrypted connection.
   *
   * @param options name of a Hardpoint service
   * @returns An encrypted tunnel to the desired service. For the most part you can treat
   * this like a regular socket and pass it to any client library that takes a stream.
   *
   * See the docs for concrete examples with specific client libraries.
   */
  public async connect(options: string | ConnectOptions): Promise<StreamLike> {
    const service = typeof options === "string" ? options : options.service;
    const socket = await connectTunnel({
      logger: this.logger,
      org_id: this.org_id,
      relayHost: this.relayHost,
      relayPort: this.relayPort,
      token: this.token,
      service: service,
    });

    return streamToSocketLike(socket);
  }

  /**
   * Establish a tunnel to a service on your Hardpoint network.
   *
   * Locates the service and sets up an encrypted connection. In contrast to {@link Sdk.connect},
   * this also creates a local UNIX socket listening for traffic from client libraries and pipes
   * data between the tunnel and the UNIX socket.
   *
   * This is useful for client libraries that cannot directly accept a `duplex.Stream`-like object.
   *
   * @param options name of a Hardpoint service
   * @returns A handle to the encrypted tunnel and UNIX socket ready to accept traffic. See {@link UnixSocketLike}
   * for more information.
   *
   * See the docs for concrete examples with specific client libraries.
   */
  public async connectAndListen(options: ConnectOptions): Promise<UnixSocketLike> {
    const service = typeof options === "string" ? options : options.service;
    const remoteSocket = await connectTunnel({
      logger: this.logger,
      org_id: this.org_id,
      relayHost: this.relayHost,
      relayPort: this.relayPort,
      token: this.token,
      service: service,
    });

    const handle = socketLikeToUnixLike(remoteSocket)
    await handle.listen();
    return handle;
  }
}