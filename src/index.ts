import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as net from "node:net";
import * as tls from "node:tls";
import * as stream from "node:stream";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const RELAY_HOST = "relay.hardpoint.dev";
const RELAY_PORT = 443;

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CA_CERT = fs.readFileSync(path.join(__dirname, "ca.crt"));

function getOidcToken(): string | undefined {
  return process.env.VERCEL_OIDC_TOKEN;
}

function connectTunnel({
  relayHost,
  relayPort = RELAY_PORT,
  token,
  service,
}: {
  relayHost: string;
  relayPort?: number;
  token: string;
  service: string;
}): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      relayPort,
      relayHost,
      {
        servername: relayHost,
        ca: CA_CERT,
        rejectUnauthorized: true,
      },
      () => { }
    );

    socket.on("secureConnect", () => {
      const connectRequest = [
        `CONNECT ${service} HTTP/1.1`,
        `Host: ${service}`,
        `Authorization: Bearer ${token}`,
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
        const rest = buffer.slice(headerEndIndex + 4);

        socket.removeAllListeners("data");

        if (rest?.length) {
          socket.unshift(Buffer.from(rest));
        }

        resolve(socket);
      }
    });

    socket.on("error", reject);
  });
}

function socketToDuplex(socket: net.Socket): stream.Duplex {
  const duplex = new stream.Duplex({
    read() { },
    write(chunk, encoding, callback) {
      socket.write(chunk, encoding, callback);
    },
    destroy(error, callback) {
      socket.destroy(error ?? undefined);
      callback(error ?? undefined);
    },
  });

  socket.on("data", (chunk) => {
    duplex.push(chunk);
  });

  socket.on("close", () => {
    duplex.push(null);
  });

  socket.on("error", (err) => {
    duplex.emit("error", err);
  });

  return duplex;
}

function generateSocketName(): string {
  const randomSuffix = crypto.randomBytes(8).toString("hex");
  return path.join("/tmp", `hp-${randomSuffix}.sock`);
}

class UnixSocketHandle {
  private readonly socketPath: string;
  private readonly server: net.Server;
  private readonly tunnelSocket: net.Socket;
  private readonly inputStream: stream.PassThrough;
  private readonly outputStream: stream.PassThrough;
  private disposed = false;

  constructor(tunnelSocket: net.Socket, socketPath: string) {
    this.socketPath = socketPath;
    this.tunnelSocket = tunnelSocket;
    this.inputStream = new stream.PassThrough();
    this.outputStream = new stream.PassThrough();

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

  get socketName(): string {
    return this.socketPath;
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

      this.server.close(() => {
        this.tunnelSocket.destroy();
        this.inputStream.end();
        this.outputStream.end();

        fs.unlink(this.socketPath, () => {
          resolve();
        });
      });
    });
  }

  listen(): void {
    this.server.listen(this.socketPath);
  }
}

export interface SdkOptions {
  token?: string;
  relayHost?: string;
}

export interface ConnectOptions {
  service: string;
}

export interface UnixSocket {
  readonly socketName: string;
}

export class Sdk {
  private static instance: Sdk;
  private token: string | undefined;
  private relayHost: string;

  private constructor(options?: SdkOptions) {
    this.token = options?.token ?? getOidcToken();
    this.relayHost = options?.relayHost ?? RELAY_HOST;
  }

  static getInstance(options?: SdkOptions): Sdk {
    if (!Sdk.instance) {
      Sdk.instance = new Sdk(options);
    }
    return Sdk.instance;
  }

  private async getTunnelSocket(options: ConnectOptions): Promise<net.Socket> {
    if (!this.token) {
      throw new Error(
        "OIDC token not found. Set VERCEL_OIDC_TOKEN environment variable or pass token in getInstance()."
      );
    }

    return connectTunnel({
      relayHost: this.relayHost,
      token: this.token,
      service: options.service,
    });
  }

  async connect(options: ConnectOptions): Promise<stream.Duplex> {
    return this.getTunnelSocket(options).then((sock) => socketToDuplex(sock));
  }

  async connectAndListen(options: ConnectOptions): Promise<UnixSocket> {
    const tunnelSocket = await this.getTunnelSocket(options);
    const socketPath = generateSocketName();
    const handle = new UnixSocketHandle(tunnelSocket, socketPath);
    handle.listen();
    return handle;
  }
}
