import { Router } from 'express';
import multer from 'multer';
import { authenticateToken } from '../middlewares/auth';
import { createSOS, getSOS, getSOSById, updateStatus, clearHistory, getSOSEventHistoryController, getRecentSOSChat, getSOSChatById, sendSOSChatMessage, uploadSOSAttachments } from '../controllers/sos.controller';

const router = Router();
const upload = multer({ storage: multer.memoryStorage() });

router.use(authenticateToken);

router.post('/', createSOS);
router.post('/attachments', upload.array('files', 5), uploadSOSAttachments);
router.get('/recent/chat', getRecentSOSChat);
router.get('/', getSOS);
router.get('/:id/events', getSOSEventHistoryController); // Must be before /:id route
router.get('/:id/chat', getSOSChatById);
router.post('/:id/chat/messages', sendSOSChatMessage);
router.get('/:id', getSOSById);
router.patch('/:id/status', updateStatus);
router.delete('/history', clearHistory);

export default router;
