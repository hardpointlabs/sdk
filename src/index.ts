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
  const rejectUnauthorized = relayHost === 'localhost' ? false : true;
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      relayPort,
      relayHost,
      {
        servername: relayHost,
        ca: CA_CERT,
        rejectUnauthorized: rejectUnauthorized,
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

function socketToDuplex(socket: net.Socket): TcpSocketHandle {
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
  private readonly server: net.Server;
  private readonly inputStream: stream.PassThrough;
  private readonly outputStream: stream.PassThrough;
  private disposed = false;

  constructor(tunnelSocket: net.Socket, socketPath: string) {
    this.path = socketPath;
    this.inputStream = new stream.PassThrough();
    this.outputStream = new stream.PassThrough();

    tunnelSocket.on("data", (chunk) => {
      this.inputStream.write(chunk);
    });

    tunnelSocket.on("close", () => {
      this.inputStream.end();
    });

    tunnelSocket.on("error", (err) => {
      this.inputStream.end(err);
    });

    this.outputStream.pipe(tunnelSocket);

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
        console.log(`Listening on ${this.path}`)
        resolve();
      });

      this.server.on("error", (err) => {
        clearTimeout(timeout);
        console.log(`Error in UNIX socket listener: ${err}`)
        reject(err);
      });
    });
  }
}

export interface SdkOptions {
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

  private readonly token: string | undefined;
  private readonly relayHost: string;
  private readonly relayPort: number;

  public constructor(options?: SdkOptions) {
    this.token = options?.token ?? getOidcToken();
    this.relayHost = options?.relayHost ?? RELAY_HOST;
    this.relayPort = options?.relayPort ?? RELAY_PORT;
  }

  private async getTunnelSocket(options: ConnectOptions): Promise<net.Socket> {
    if (!this.token) {
      throw new Error(
        "OIDC token not found. Set VERCEL_OIDC_TOKEN environment variable or pass token in getInstance()."
      );
    }

    return connectTunnel({
      relayHost: this.relayHost,
      relayPort: this.relayPort,
      token: this.token,
      service: options.service,
    });
  }

  async connect(options: ConnectOptions): Promise<TcpSocketHandle> {
    return this.getTunnelSocket(options).then((sock) => socketToDuplex(sock));
  }

  async connectAndListen(options: ConnectOptions): Promise<UnixSocketHandle> {
    const tunnelSocket = await this.getTunnelSocket(options);
    const socketPath = generateSocketName();
    const handle = new UnixSocketHandleImpl(tunnelSocket, socketPath);
    await handle.listen();
    return handle;
  }
}
