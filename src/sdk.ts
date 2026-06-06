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
import { chainedTokenProvider, TokenProvider } from "./auth.js";
import type { RequestContext } from "./request.js";
import type { StreamLike, UnixSocketLike } from "./streams.js";

const H7T_PEER_PUBKEY_HEADER = "H7T-Peer-PubKey";
const H7T_ORG_HEADER = "H7T-Org";

const CIPHER_ALGO = "aes-256-gcm";

const RELAY_HOST = "relay.hardpoint.dev";
const RELAY_PORT = 443;

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CA_CERT = fs.readFileSync(path.join(__dirname, "ca.crt"));

function logCipherDetails(logger: Logger, iv: Buffer, authTag: Buffer, finalChunk: Buffer) {
  logger.debug("got cipher details", {
    "iv": crypto.createHash("sha256").update(iv).digest("hex"),
    "tag": crypto.createHash("sha256").update(authTag).digest("hex"),
    "ciphertext": crypto.createHash("sha256").update(Buffer.concat([finalChunk, authTag])).digest("hex")
  });
}

function createEncryptionTransforms(logger: Logger, key: Buffer): { encrypt: stream.Transform; decrypt: stream.Transform } {
  const ivLength = 12;
  const authTagLength = 16;

  const encrypt = new stream.Transform({
    transform(chunk: Buffer, _encoding, callback) {
      const iv = crypto.randomBytes(ivLength);
      const cipher = crypto.createCipheriv(CIPHER_ALGO, key, iv);
      cipher.setAAD(Buffer.alloc(0));
      const encrypted = Buffer.concat([cipher.update(chunk), cipher.final()]);
      const authTag = cipher.getAuthTag();

      // TODO - avoid copy here
      const result = Buffer.concat([iv, encrypted, authTag]);

      logCipherDetails(logger, iv, authTag, encrypted);

      callback(null, result);
    },
  });

  const decrypt = new stream.Transform({
    transform(chunk: Buffer, _encoding, callback) {
      logger.debug(`Got response %d bytes encrypted payload ${chunk.length}`);
      try {
        const iv = chunk.subarray(0, ivLength);
        const authTag = chunk.subarray(chunk.length - authTagLength, chunk.length);
        const encrypted = chunk.subarray(ivLength, chunk.length - authTagLength);

        logCipherDetails(logger, iv, authTag, encrypted);

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
  orgId,
  relayHost,
  relayPort = RELAY_PORT,
  token,
  service,
}: {
  logger: Logger;
  orgId: string;
  relayHost: string;
  relayPort?: number;
  token: string;
  service: string;
}): Promise<stream.Duplex> {
  const sender = await createMlKem768();

  // ignore TLS warnings for local dev
  const rejectUnauthorizedCerts = relayHost === "localhost" ? false : true;

  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      relayPort,
      relayHost,
      {
        servername: relayHost,
        ca: CA_CERT,
        rejectUnauthorized: rejectUnauthorizedCerts,
        minVersion: "TLSv1.3"
      },
      () => {}
    );

    socket.on("secureConnect", () => {
      const connectRequest = [
        `CONNECT ${service} HTTP/1.1`,
        `Host: ${service}`,
        `Authorization: Bearer ${token}`,
        `${H7T_ORG_HEADER}: ${orgId}`,
        "",
        "",
      ].join("\r\n");

      socket.write(connectRequest);
    });

    let buffer = "";

    socket.on("data", (chunk) => {
      buffer += chunk.toString("utf8");
      if (buffer.includes("\r\n\r\n")) {
        if (!buffer.startsWith("HTTP/1.1 200")) {
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
          Buffer.alloc(0),   // salt
          Buffer.alloc(0),   // context separation
          32);

        const kb = Buffer.from(key); // derived
        logger.debug(`shared secret: ${crypto.createHash("sha256").update(sharedSecret).digest("hex")}`)
        logger.debug(`key from shared secret: ${kb.toString("hex")}`);

        socket.removeAllListeners("data");

        if (rest?.length) {
          // trim any remaining response headers we're not interested in
          socket.unshift(Buffer.from(rest));
        }

        // sending the SDK-side ciphertext back is the last part of the ML-KEM handshake
        logger.debug(`Sending ciphertext of length: ${ciphertext.length}`);
        // remote side expects us to be framed at this point; create a one-off lpstream encoder
        // to write the ciphertext back, ensuring we don't resolve the promise until the
        // key exchange is complete
        const encoder = new lpstream.Encoder();
        encoder.pipe(socket);
        encoder.write(ciphertext, () => {
          const encryptedSocket = wrapSocketWithEncryption(logger, socket, key);
          resolve(encryptedSocket);
        });
      }
    });

    socket.on("error", reject);
  });
}

function wrapSocketWithEncryption(logger: Logger, socket: net.Socket, hkdfKey: ArrayBuffer): stream.Duplex {
  const key = Buffer.from(hkdfKey); // derived
  logger.debug(`key: ${key.toString("hex")}`);

  const { encrypt, decrypt }: { encrypt: stream.Transform; decrypt: stream.Transform } = createEncryptionTransforms(logger, key);

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
  orgId: string;
  tokenProvider: TokenProvider;
  relayHost: string;
  relayPort: number;
  logger: Logger;
}

export type SdkOptionsInput = Partial<SdkOptions> & {orgId: string};

const defaultOptions: Pick<SdkOptions, "logger" | "tokenProvider" | "relayHost" | "relayPort"> = {
  logger: noopLogger,
  tokenProvider: chainedTokenProvider,
  relayHost: RELAY_HOST,
  relayPort: RELAY_PORT
};

function resolveOptions(input: SdkOptionsInput): SdkOptions {
  return {
    ...defaultOptions,
    ...input,
  };
}

export type ConnectOptions = {
  service: string;
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

let _sdk: Sdk | undefined;

/*
 * We have 2 orthogonal concepts we need to deal with;
 *
 * - Runtime environment (Vercel, CF Workers, e.t.c)
 * - Web framework in use
 *
 * We can auto-detect the first while allowing overrides, but the framework
 * must be set up by the user.
 */

/**
 * The single touchpoint to the Hardpoint SDK.
 *
 * Use {@link Sdk.init} to create or retrieve the singleton instance.
 */
export class Sdk {
  private readonly logger: Logger;
  private readonly orgId: string;
  private readonly tokenProvider: TokenProvider;
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
  public static init(options: SdkOptionsInput): Sdk {
    if (!_sdk) {
      const merged = resolveOptions(options);
      _sdk = new Sdk(merged);
    }
    return _sdk;
  }

  /**
   * Create a new SDK instance.
   *
   * This should only be done once on application startup. See {@link SdkOptions} for configuration options.
   */
  private constructor(options: SdkOptions) {
    this.logger = options.logger ?? noopLogger;
    this.orgId = options.orgId;
    this.tokenProvider = options.tokenProvider;
    this.relayHost = options.relayHost;
    this.relayPort = options.relayPort;
  }

  private async setupTunnel(options: string | ConnectOptions, ctx: RequestContext): Promise<stream.Duplex> {
    const service = typeof options === "string" ? options : options.service;
    const token = await this.tokenProvider(ctx);
    if (!token) {
      return Promise.reject("Unable to derive auth token to set up a tunnel! See the docs at https://github.com/hardpointlabs/sdk to learn more")
    }
    return connectTunnel({
      logger: this.logger,
      orgId: this.orgId,
      relayHost: this.relayHost,
      relayPort: this.relayPort,
      token: token!,
      service: service,
    });
  }

  /**
   * Establish a tunnel to a service on your Hardpoint network.
   *
   * Locates the service and sets up an encrypted connection.
   *
   * @param options name of a Hardpoint-defined service
   * @returns An encrypted tunnel to the desired service. For the most part you can treat
   * this like a regular socket and pass it to any client library that takes a stream.
   *
   * See the docs for concrete examples with specific client libraries.
   */
  public async connect(options: string | ConnectOptions, ctx: RequestContext): Promise<StreamLike> {
    const tunnel = await this.setupTunnel(options, ctx);
    return streamToSocketLike(tunnel);
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
  public async connectAndListen(options: string | ConnectOptions, ctx: RequestContext): Promise<UnixSocketLike> {
    const tunnel = await this.setupTunnel(options, ctx);
    const handle = socketLikeToUnixLike(tunnel);
    await handle.listen();
    return handle;
  }
}