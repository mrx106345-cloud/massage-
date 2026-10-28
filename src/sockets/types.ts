import type { Server as IOServer } from 'socket.io';
import type { Socket } from 'socket.io';

export interface SocketContext {
  io: IOServer;
  users: Map<string, Set<Socket>>;
  httpServer: import('node:http').Server;
}
