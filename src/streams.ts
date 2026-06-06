import { Socket } from "node:net";
import { Duplex } from "node:stream";
import { Sdk } from "./sdk.js";

/**
 * The encryption scheme used to encrypt traffic between the SDK and the remote agent.
 */
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
   * * To pass the correct host header to an HTTP server which validates them
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
 * assumptions about what Layer 4 transport is being used.
 *
 * Where a concrete `net.Socket` is required, the {@link StreamLike.asSocket} method is available.
 *
 * This should be disposed of properly when no longer needed.
 */
export interface StreamLike extends Tunnel, Duplex {
  /**
   * Exposes this tunnel as a socket.
   *
   * Use this for cases such as node's own `http` which expects low-level TCP primitive
   * access. Where possible, the owning {@link StreamLike} instance should be preferred, since
   * exact TCP semantics cannot be guaranteed.
   *
   * @returns reference to the same underlying {@link StreamLike} object as a `net.Socket`
   */
  asSocket(): Socket
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
