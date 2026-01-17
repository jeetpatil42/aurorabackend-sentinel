import { Server, Socket } from 'socket.io';
import { verifyAccessToken } from '../utils/jwt';
import { getUserById } from '../services/auth';
import { supabaseAdmin } from '../db/supabaseAdmin';
import { logger } from '../config/logger';
import { calculateMotionIntensity } from '../risk/engine';

export interface AuthenticatedSocket extends Socket {
  userId?: string;
  userRole?: string;
}

export function setupSocketHandlers(io: Server): void {
  // Authentication middleware for sockets
  io.use(async (socket: AuthenticatedSocket, next) => {
    try {
      const token = socket.handshake.auth.token || socket.handshake.headers.authorization?.split(' ')[1];

      if (!token) {
        logger.warn('Socket auth failed: No token provided');
        return next(new Error('Authentication required'));
      }

      let payload;
      try {
        payload = verifyAccessToken(token);
      } catch (tokenError: any) {
        logger.warn('Socket auth failed: Token verification error', tokenError.message);
        return next(new Error('Invalid or expired token'));
      }

      let user;
      try {
        user = await getUserById(payload.userId);
      } catch (userError: any) {
        logger.warn('Socket auth failed: User lookup error', userError.message);
        return next(new Error('User lookup failed'));
      }

      if (!user) {
        logger.warn('Socket auth failed: User not found', payload.userId);
        return next(new Error('User not found'));
      }

      if (user.role === 'security' && !(user as any).security_approved) {
        logger.warn('Socket auth failed: Security account pending admin approval', payload.userId);
        return next(new Error('Security account pending admin approval'));
      }

      socket.userId = payload.userId;
      socket.userRole = user.role;

      next();
    } catch (error: any) {
      logger.error('Socket auth failed: Unexpected error', error.message || error);
      next(new Error('Authentication failed'));
    }
  });

  io.on('connection', (socket: AuthenticatedSocket) => {
    logger.debug(`Socket connected: ${socket.userId} (${socket.userRole})`);

    // Security personnel join security room
    if (socket.userRole === 'security') {
      socket.join('security_room');
      logger.debug(`Security user ${socket.userId} joined security_room`);
    }

    // Join user-specific room
    if (socket.userId) {
      socket.join(`user_${socket.userId}`);
    }

    // Handle joining SOS-specific room
    socket.on('join_sos', (sosId: string) => {
      socket.join(`sos_${sosId}`);
      logger.debug(`Socket ${socket.userId} joined sos_${sosId}`);
    });

    // Handle joining SOS chat room (restricted to student + assigned security responder)
    socket.on('join_sos_chat', async (sosId: string) => {
      try {
        const resolvedSosId = String(sosId || '').trim();
        if (!resolvedSosId) return;

        if (!socket.userId || !socket.userRole) {
          socket.emit('chat:error', { sosId: resolvedSosId, error: 'Authentication required' });
          return;
        }

        const { data: sosEvent, error: sosError } = await supabaseAdmin
          .from('sos_events')
          .select('id,user_id')
          .eq('id', resolvedSosId)
          .single();

        if (sosError || !sosEvent) {
          socket.emit('chat:error', { sosId: resolvedSosId, error: 'SOS event not found' });
          return;
        }

        const { data: chats } = await supabaseAdmin
          .from('sos_chats')
          .select('security_id')
          .eq('sos_id', resolvedSosId)
          .limit(1);

        const chat = Array.isArray(chats) && chats.length > 0 ? (chats[0] as any) : null;
        const assignedSecurityId = chat?.security_id as string | null | undefined;

        if (socket.userRole === 'student') {
          if ((sosEvent as any).user_id !== socket.userId) {
            socket.emit('chat:error', { sosId: resolvedSosId, error: 'Access denied' });
            return;
          }
        } else if (socket.userRole === 'security') {
          if (!assignedSecurityId || assignedSecurityId !== socket.userId) {
            socket.emit('chat:error', { sosId: resolvedSosId, error: 'Only the assigned security responder can access this chat' });
            return;
          }
        } else {
          socket.emit('chat:error', { sosId: resolvedSosId, error: 'Access denied' });
          return;
        }

        socket.join(`sos_chat_${resolvedSosId}`);
      } catch (e: any) {
        socket.emit('chat:error', { sosId, error: e?.message || 'Failed to join chat' });
      }
    });

    // Handle leaving SOS-specific room
    socket.on('leave_sos', (sosId: string) => {
      socket.leave(`sos_${sosId}`);
    });

    socket.on('leave_sos_chat', (sosId: string) => {
      socket.leave(`sos_chat_${sosId}`);
    });

    // Handle live feed data (from student devices)
    socket.on('live_feed', (data: any) => {
      if (!socket.userId) return;

      const audio = data?.audio || {};
      const motionRaw = data?.motion || {};

      const accelerationRaw = motionRaw?.acceleration ?? motionRaw?.accelerationMagnitude ?? motionRaw?.acceleration_magnitude;
      const shakeRaw = motionRaw?.shake ?? motionRaw?.jitter ?? motionRaw?.jitterValue;

      const acceleration = Number.isFinite(Number(accelerationRaw)) ? Number(accelerationRaw) : 0;
      const shake = Number.isFinite(Number(shakeRaw)) ? Number(shakeRaw) : 0;

      const motionScore = calculateMotionIntensity({
        accelerationMagnitude: acceleration,
        jitter: shake,
      });

      logger.debug('live_feed received', {
        userId: socket.userId,
        acceleration,
        shake,
        motionScore,
      });

      // Only rebroadcast to security room
      io.to('security_room').emit('live_feed', {
        ...data,
        userId: socket.userId,
        audio,
        motion: {
          ...motionRaw,
          acceleration,
          shake,
          accelerationMagnitude: acceleration,
          jitter: shake,
          score: motionScore,
        },
        timestamp: new Date().toISOString(),
      });
    });

    socket.on('chat:send', async (data: { sosId: string; message: string }) => {
      try {
        const sosId = String(data?.sosId || '').trim();
        const message = String(data?.message || '').trim();

        if (!socket.userId || !socket.userRole) {
          socket.emit('chat:error', { sosId, error: 'Authentication required' });
          return;
        }

        if (!sosId || !message) {
          socket.emit('chat:error', { sosId, error: 'Invalid chat message' });
          return;
        }

        const { data: sosEvent, error: sosError } = await supabaseAdmin
          .from('sos_events')
          .select('id,user_id,status')
          .eq('id', sosId)
          .single();

        if (sosError || !sosEvent) {
          socket.emit('chat:error', { sosId, error: 'SOS event not found' });
          return;
        }

        if ((sosEvent as any).status === 'resolved') {
          socket.emit('chat:error', { sosId, error: 'Chat is read-only after resolved' });
          return;
        }

        const { data: chats, error: chatError } = await supabaseAdmin
          .from('sos_chats')
          .select('id, security_id')
          .eq('sos_id', sosId)
          .limit(1);

        if (chatError) {
          socket.emit('chat:error', { sosId, error: chatError.message });
          return;
        }

        const chat = Array.isArray(chats) && chats.length > 0 ? (chats[0] as any) : null;
        if (!chat?.id) {
          socket.emit('chat:error', { sosId, error: 'Chat not found' });
          return;
        }

        if (socket.userRole === 'student') {
          if ((sosEvent as any).user_id !== socket.userId) {
            socket.emit('chat:error', { sosId, error: 'Access denied' });
            return;
          }
        } else if (socket.userRole === 'security') {
          if (chat.security_id !== socket.userId) {
            socket.emit('chat:error', { sosId, error: 'Only the assigned security responder can send messages' });
            return;
          }
        } else {
          socket.emit('chat:error', { sosId, error: 'Access denied' });
          return;
        }

        const { data: inserted, error: insertError } = await supabaseAdmin
          .from('sos_chat_messages')
          .insert({
            chat_id: chat.id,
            sender_id: socket.userId,
            message,
          })
          .select()
          .single();

        if (insertError) {
          socket.emit('chat:error', { sosId, error: insertError.message });
          return;
        }

        const sender = await getUserById(socket.userId);
        const payload = {
          ...inserted,
          sender_email: (sender as any)?.email,
          sender_name: (sender as any)?.name,
          sos_id: sosId,
        };

        io.to(`sos_chat_${sosId}`).emit('chat:message', payload);
      } catch (e: any) {
        socket.emit('chat:error', { sosId: data?.sosId, error: e?.message || 'Failed to send message' });
      }
    });

    socket.on('disconnect', () => {
      logger.debug(`Socket disconnected: ${socket.userId}`);
    });
  });
}
