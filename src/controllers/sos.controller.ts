import { Response } from 'express';
import { AuthRequest } from '../middlewares/auth';
import { createSOSEvent, getSOSEvents, getSOSEventById, updateSOSStatus, clearAllSOSHistory, getSOSEventHistory, logSOSEvent } from '../services/sos';
import { createRiskSnapshot } from '../services/sos';
import { supabaseAdmin } from '../db/supabaseAdmin';
import { isPointInPolygon } from '../utils/geojson';
import { env } from '../config/env';
import { logger } from '../config/logger';
import { getRiskZonesCached } from '../services/riskZonesCache';
import { v4 as uuidv4 } from 'uuid';

async function resolveUserDisplayByUserId(userId: string): Promise<{ email?: string; name?: string }> {
  const { data: userRow } = await supabaseAdmin
    .from('users')
    .select('email,name')
    .eq('id', userId)
    .single();

  if (userRow?.email || (userRow as any)?.name) {
    return { email: (userRow as any)?.email, name: (userRow as any)?.name };
  }

  try {
    const { data } = await supabaseAdmin.auth.admin.getUserById(userId);
    const email = data?.user?.email || undefined;
    const name = (data?.user as any)?.user_metadata?.name || undefined;
    return { email, name };
  } catch {
    return {};
  }
}

export const createSOS = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    if (!req.user) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }

    const { risk_score, factors, location, trigger_type, attachments } = req.body;

    logger.debug('Creating SOS event for user', { userId: req.user.id, risk_score });

    const event = await createSOSEvent({
      user_id: req.user.id,
      risk_score,
      factors,
      location,
      trigger_type: trigger_type || 'manual',
      attachments,
    });

    if (!event || !event.id) {
      logger.error('SOS event creation returned invalid event:', event);
      res.status(500).json({ error: 'Failed to create SOS event: Invalid response from database' });
      return;
    }

    logger.debug('SOS event created successfully:', event.id);

    // Ensure chat thread exists for this SOS (non-blocking)
    try {
      await supabaseAdmin.from('sos_chats').insert({
        sos_id: event.id,
        student_id: req.user.id,
      });
    } catch (chatError: any) {
      const msg = chatError?.message || chatError;
      if (typeof msg === 'string' && /duplicate|unique/i.test(msg)) {
        // Ignore
      } else {
        logger.warn('Failed to create sos_chats row (non-blocking):', msg);
      }
    }

    // Save initial risk snapshot
    await createRiskSnapshot({
      event_id: event.id,
      user_id: req.user.id,
      audio: factors?.audio || {},
      motion: factors?.motion || {},
      time: factors?.time || {},
      location: location || {},
      total: risk_score,
    });

    // Log zone_entered event if location is provided
    if (location && typeof location.lat === 'number' && typeof location.lng === 'number') {
      try {
        const riskZones = await getRiskZonesCached();

        if (riskZones && riskZones.length > 0) {
          let foundZone = false;
          for (const zone of riskZones) {
            if (isPointInPolygon(
              { lat: location.lat, lng: location.lng },
              zone.polygon
            )) {
              // Found a zone match
              await logSOSEvent({
                sos_id: event.id,
                type: 'zone_entered',
                risk_value: risk_score,
                meta: {
                  zoneName: zone.name,
                  zoneType: zone.type,
                  zone_type: zone.type,
                  zone_name: zone.name,
                  multiplier: zone.multiplier,
                },
              });
              foundZone = true;
              break;
            }
          }
          
          // If not inside any polygon, log normal zone
          if (!foundZone) {
            await logSOSEvent({
              sos_id: event.id,
              type: 'zone_entered',
              risk_value: risk_score,
              meta: {
                normal_zone: true,
              },
            });
          }
        } else {
          // No zones available, treat as normal zone
          await logSOSEvent({
            sos_id: event.id,
            type: 'zone_entered',
            risk_value: risk_score,
            meta: {
              normal_zone: true,
            },
          });
        }
      } catch (error: any) {
        // Log error but don't break SOS creation
        logger.warn('Failed to log zone_entered event:', error.message);
      }
    }

    const display = await resolveUserDisplayByUserId(event.user_id);
    const eventWithEmail = {
      ...event,
      email: display.email,
      name: display.name,
    };

    // Emit real-time event (handled by socket handler)
    const io = (req as any).io;
    if (io) {
      // Emit to security room
      io.to('security_room').emit('new_sos_alert', eventWithEmail);
      io.to('security_room').emit('sos:created', eventWithEmail);
      // Also emit to user's room
      if (req.user?.id) {
        io.to(`user_${req.user.id}`).emit('sos:created', eventWithEmail);
      }
      logger.debug(`Emitted SOS event to security_room and user_${req.user?.id}`);
    } else {
      logger.warn('Socket.io not available - SOS event not broadcasted');
    }

    res.status(201).json(eventWithEmail);
  } catch (error: any) {
    logger.error('Error creating SOS event:', error);
    res.status(400).json({ error: error.message || 'Failed to create SOS event' });
  }
};

async function getChatBundleForSOS(params: { sosId: string; requester: { id: string; role: string } }) {
  const { sosId, requester } = params;

  const sosEvent = await getSOSEventById(sosId);
  if (!sosEvent) {
    return { status: 404 as const, body: { error: 'SOS event not found' } };
  }

  const { data: chats, error: chatError } = await supabaseAdmin
    .from('sos_chats')
    .select('*')
    .eq('sos_id', sosId)
    .limit(1);

  if (chatError) {
    return { status: 500 as const, body: { error: chatError.message } };
  }

  const chat = Array.isArray(chats) && chats.length > 0 ? (chats[0] as any) : null;
  if (!chat) {
    return { status: 404 as const, body: { error: 'Chat not found' } };
  }

  const isStudent = requester.role === 'student';
  const isSecurity = requester.role === 'security';

  if (isStudent && sosEvent.user_id !== requester.id) {
    return { status: 403 as const, body: { error: 'Access denied' } };
  }

  // Only the assigned security responder can access chat from the security side
  if (isSecurity && chat.security_id !== requester.id) {
    return { status: 403 as const, body: { error: 'Access denied' } };
  }

  const { data: messages, error: msgError } = await supabaseAdmin
    .from('sos_chat_messages')
    .select('*')
    .eq('chat_id', chat.id)
    .order('created_at', { ascending: true });

  if (msgError) {
    return { status: 500 as const, body: { error: msgError.message } };
  }

  const senderIds = Array.from(new Set((messages || []).map((m: any) => m.sender_id).filter(Boolean)));
  const { data: senders } = senderIds.length
    ? await supabaseAdmin.from('users').select('id,email,name').in('id', senderIds)
    : ({ data: [] } as any);

  const senderEmailById = new Map<string, string>();
  const senderNameById = new Map<string, string>();
  (senders || []).forEach((u: any) => {
    if (u?.id && u?.email) senderEmailById.set(u.id, u.email);
    if (u?.id && u?.name) senderNameById.set(u.id, u.name);
  });

  const resolved = sosEvent.status === 'resolved';
  const securityDisplay = chat.security_id ? await resolveUserDisplayByUserId(chat.security_id) : {};

  return {
    status: 200 as const,
    body: {
      sos: sosEvent,
      chat: {
        ...chat,
        security_email: securityDisplay.email,
        security_name: securityDisplay.name,
      },
      read_only: resolved,
      messages: (messages || []).map((m: any) => ({
        ...m,
        sender_email: senderEmailById.get(m.sender_id),
        sender_name: senderNameById.get(m.sender_id),
      })),
    },
  };
}

export const getRecentSOSChat = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    if (!req.user) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }

    if (req.user.role !== 'student') {
      res.status(403).json({ error: 'Only students can access recent SOS chat' });
      return;
    }

    const { data: events, error } = await supabaseAdmin
      .from('sos_events')
      .select('*')
      .eq('user_id', req.user.id)
      .order('created_at', { ascending: false })
      .limit(1);

    if (error) {
      res.status(500).json({ error: error.message });
      return;
    }

    const recent = Array.isArray(events) && events.length > 0 ? (events[0] as any) : null;
    if (!recent?.id) {
      res.status(404).json({ error: 'No SOS event found' });
      return;
    }

    const bundle = await getChatBundleForSOS({ sosId: recent.id, requester: { id: req.user.id, role: req.user.role } });
    res.status(bundle.status).json(bundle.body);
  } catch (e: any) {
    res.status(500).json({ error: e?.message || 'Failed to fetch recent SOS chat' });
  }
};

export const getSOSChatById = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    if (!req.user) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }

    const { id } = req.params;
    const bundle = await getChatBundleForSOS({ sosId: id, requester: { id: req.user.id, role: req.user.role } });
    res.status(bundle.status).json(bundle.body);
  } catch (e: any) {
    res.status(500).json({ error: e?.message || 'Failed to fetch chat' });
  }
};

export const sendSOSChatMessage = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    if (!req.user) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }

    const { id } = req.params;
    const message = String((req.body as any)?.message || '').trim();
    if (!message) {
      res.status(400).json({ error: 'Message is required' });
      return;
    }

    const sosEvent = await getSOSEventById(id);
    if (!sosEvent) {
      res.status(404).json({ error: 'SOS event not found' });
      return;
    }

    if (sosEvent.status === 'resolved') {
      res.status(400).json({ error: 'Chat is read-only after resolved' });
      return;
    }

    const { data: chats, error: chatError } = await supabaseAdmin
      .from('sos_chats')
      .select('*')
      .eq('sos_id', id)
      .limit(1);

    if (chatError) {
      res.status(500).json({ error: chatError.message });
      return;
    }

    const chat = Array.isArray(chats) && chats.length > 0 ? (chats[0] as any) : null;
    if (!chat) {
      res.status(404).json({ error: 'Chat not found' });
      return;
    }

    if (req.user.role === 'student') {
      if (sosEvent.user_id !== req.user.id) {
        res.status(403).json({ error: 'Access denied' });
        return;
      }
    } else if (req.user.role === 'security') {
      if (chat.security_id !== req.user.id) {
        res.status(403).json({ error: 'Only the assigned security responder can send messages' });
        return;
      }
    } else {
      res.status(403).json({ error: 'Access denied' });
      return;
    }

    const { data: inserted, error: insertError } = await supabaseAdmin
      .from('sos_chat_messages')
      .insert({
        chat_id: chat.id,
        sender_id: req.user.id,
        message,
      })
      .select()
      .single();

    if (insertError) {
      res.status(500).json({ error: insertError.message });
      return;
    }

    const payload = {
      ...inserted,
      sender_email: req.user.email,
      sender_name: req.user.name,
      sos_id: id,
    };

    const io = (req as any).io;
    if (io) {
      io.to(`sos_chat_${id}`).emit('chat:message', payload);
    }

    res.json(payload);
  } catch (e: any) {
    res.status(500).json({ error: e?.message || 'Failed to send message' });
  }
};

export const getSOS = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    if (!req.user) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }

    const { status, limit, offset } = req.query;

    // Students can only see their own events
    // Security can see all events
    const filters: any = {};

    if (limit) {
      const parsedLimit = parseInt(limit as string, 10);
      if (!isNaN(parsedLimit) && parsedLimit > 0) {
        filters.limit = parsedLimit;
      }
    }

    if (offset) {
      const parsedOffset = parseInt(offset as string, 10);
      if (!isNaN(parsedOffset) && parsedOffset >= 0) {
        filters.offset = parsedOffset;
      }
    }

    if (req.user.role === 'student') {
      filters.user_id = req.user.id;
    }

    if (status && typeof status === 'string') {
      filters.status = status;
    }

    logger.debug('Fetching SOS events with filters:', filters);

    const events = await getSOSEvents(filters);

    // Enrich events with user email for security UI
    if (events.length > 0) {
      if (req.user.role === 'student') {
        const enriched = events.map((e) => ({
          ...e,
          email: req.user?.email,
          name: req.user?.name,
        }));
        res.json(enriched);
        return;
      }

      const userIds = Array.from(new Set(events.map((e) => e.user_id).filter(Boolean)));
      const { data: users } = await supabaseAdmin
        .from('users')
        .select('id,email,name')
        .in('id', userIds);

      const emailById = new Map<string, string>();
      const nameById = new Map<string, string>();
      (users || []).forEach((u: any) => {
        if (u?.id && u?.email) {
          emailById.set(u.id, u.email);
        }
        if (u?.id && u?.name) {
          nameById.set(u.id, u.name);
        }
      });

      const missingIds = userIds.filter((uid) => uid && !emailById.has(uid));
      if (missingIds.length > 0) {
        const resolved = await Promise.all(missingIds.map(async (uid) => ({ uid, display: await resolveUserDisplayByUserId(uid) })));
        resolved.forEach((r) => {
          if (r.uid && r.display?.email) emailById.set(r.uid, r.display.email);
          if (r.uid && r.display?.name) nameById.set(r.uid, r.display.name);
        });
      }

      const enriched = events.map((e) => ({
        ...e,
        email: emailById.get(e.user_id),
        name: nameById.get(e.user_id),
      }));

      res.json(enriched);
      return;
    }

    logger.debug(`Retrieved ${events.length} SOS events`);

    res.json(events);
  } catch (error: any) {
    logger.error('Error in getSOS:', error);
    res.status(500).json({ error: error.message || 'Failed to fetch SOS events' });
  }
};

export const getSOSById = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    if (!req.user) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }

    const { id } = req.params;
    const event = await getSOSEventById(id);

    if (!event) {
      res.status(404).json({ error: 'SOS event not found' });
      return;
    }

    // Students can only see their own events
    if (req.user.role === 'student' && event.user_id !== req.user.id) {
      res.status(403).json({ error: 'Access denied' });
      return;
    }

    const attachments = Array.isArray((event as any).attachments) ? ((event as any).attachments as string[]) : [];
    const envBucket = env.supabaseStorageBucket();
    const bucketCandidates = Array.from(
      new Set([
        envBucket,
        'sos-attachment',
        'sos-attachments',
      ].filter(Boolean))
    ) as string[];

    const attachment_urls: string[] = [];
    if (attachments.length > 0) {
      for (const path of attachments) {
        for (const bucketName of bucketCandidates) {
          const { data, error } = await supabaseAdmin.storage.from(bucketName).createSignedUrl(path, 60 * 60);
          if (error) {
            continue;
          }
          if (data?.signedUrl) {
            attachment_urls.push(data.signedUrl);
            break;
          }
        }
      }
    }

    const display = await resolveUserDisplayByUserId(event.user_id);

    res.json({
      ...event,
      email: display.email,
      name: display.name,
      attachment_urls,
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
};

export const updateStatus = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    if (!req.user) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }

    // Only security can update status
    if (req.user.role !== 'security') {
      res.status(403).json({ error: 'Only security personnel can update status' });
      return;
    }

    const { id } = req.params;
    const { status } = req.body;

    if (!['acknowledged', 'resolved'].includes(status)) {
      res.status(400).json({ error: 'Invalid status' });
      return;
    }

    const event = await updateSOSStatus(id, status, req.user.id);

    const attachments = Array.isArray((event as any).attachments) ? ((event as any).attachments as string[]) : [];
    const envBucket = env.supabaseStorageBucket();
    const bucketCandidates = Array.from(
      new Set([
        envBucket,
        'sos-attachment',
        'sos-attachments',
      ].filter(Boolean))
    ) as string[];

    const attachment_urls: string[] = [];
    if (attachments.length > 0) {
      for (const path of attachments) {
        for (const bucketName of bucketCandidates) {
          const { data, error } = await supabaseAdmin.storage.from(bucketName).createSignedUrl(path, 60 * 60);
          if (error) {
            continue;
          }
          if (data?.signedUrl) {
            attachment_urls.push(data.signedUrl);
            break;
          }
        }
      }
    }

    const display = await resolveUserDisplayByUserId(event.user_id);

    const eventWithEmail = {
      ...event,
      email: display.email,
      name: display.name,
      attachment_urls,
    };

    // Emit status update (handled by socket handler)
    const io = (req as any).io;
    if (io) {
      io.to('security_room').emit('sos-updated', eventWithEmail);
      io.to(`sos_${id}`).emit('sos-updated', eventWithEmail);
      // Also emit legacy event for backward compatibility
      io.to('security_room').emit('sos_status_update', eventWithEmail);
      io.to(`sos_${id}`).emit('sos_status_update', eventWithEmail);
    }

    res.json(eventWithEmail);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
};

export const clearHistory = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    if (!req.user) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }

    // Only security can clear history
    if (req.user.role !== 'security') {
      res.status(403).json({ error: 'Only security personnel can clear history' });
      return;
    }

    const result = await clearAllSOSHistory();

    res.json({ message: 'History cleared successfully', deleted: result.deleted });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
};

export const uploadSOSAttachments = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    if (!req.user) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }

    const envBucket = env.supabaseStorageBucket();
    const bucketCandidates = Array.from(
      new Set([
        envBucket,
        'sos-attachment',
        'sos-attachments',
      ].filter(Boolean))
    ) as string[];
    if (bucketCandidates.length === 0) {
      res.status(500).json({ error: 'Supabase storage bucket not configured' });
      return;
    }

    const files = ((req as any).files || []) as any[];
    if (!Array.isArray(files) || files.length === 0) {
      res.status(400).json({ error: 'No files uploaded' });
      return;
    }

    logger.debug('Uploading SOS attachments', { userId: req.user.id, files: files.length, bucketCandidates });

    const uploadedPaths: string[] = [];

    for (const file of files) {
      const originalname = typeof file?.originalname === 'string' ? file.originalname : '';
      const ext = originalname.includes('.') ? originalname.split('.').pop() : '';
      const suffix = ext ? `.${ext}` : '';
      const path = `sos/${req.user.id}/${uuidv4()}${suffix}`;

      if (!file?.buffer) {
        res.status(400).json({ error: 'Invalid uploaded file' });
        return;
      }

      let lastError: any = undefined;
      let uploaded = false;
      for (const bucketName of bucketCandidates) {
        const { error } = await supabaseAdmin.storage.from(bucketName).upload(path, file.buffer, {
          contentType: file?.mimetype,
          upsert: false,
        });
        if (!error) {
          uploaded = true;
          break;
        }
        lastError = error;
      }

      if (!uploaded) {
        logger.error('Error uploading SOS attachment:', { bucketCandidates, error: lastError });
        res.status(500).json({
          error:
            (lastError as any)?.message ||
            'Failed to upload attachment (check SUPABASE_STORAGE_BUCKET and that the bucket exists)',
        });
        return;
      }

      uploadedPaths.push(path);
    }

    res.json({ attachments: uploadedPaths });
  } catch (error: any) {
    logger.error('Error in uploadSOSAttachments:', error);
    res.status(500).json({ error: error.message || 'Failed to upload attachments' });
  }
};

/**
 * GET /api/sos/:id/events
 * Returns all events for a specific SOS
 */
export const getSOSEventHistoryController = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    if (!req.user) {
      res.status(401).json({ error: 'Authentication required' });
      return;
    }

    const { id } = req.params;
    
    // First verify the SOS exists and user has access
    const sosEvent = await getSOSEventById(id);
    if (!sosEvent) {
      res.status(404).json({ error: 'SOS event not found' });
      return;
    }

    // Students can only see their own events
    if (req.user.role === 'student' && sosEvent.user_id !== req.user.id) {
      res.status(403).json({ error: 'Access denied' });
      return;
    }

    // Get all events for this SOS
    const events = await getSOSEventHistory(id);

    res.json(events);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
};
