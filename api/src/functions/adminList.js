const { app } = require('@azure/functions');
const { decryptText } = require('../lib/crypto');
const { listCards } = require('../lib/storage');
const { requireAdmin } = require('../lib/auth');

app.http('adminList', {
  methods: ['GET'],
  authLevel: 'anonymous',
  route: 'admin/cards',
  handler: async (request, context) => {
    try {
      const auth = requireAdmin(request);
      if (!auth.ok) return auth.response;

      const limit = Math.min(Number(request.query.get('limit') || 50), 500);
      const cards = await listCards(limit);

      const rows = cards.map((card) => ({
        uniqueId: card.uniqueId,
        name: decryptText(card.encryptedName),
        maskedPhone: card.maskedPhone,
        phone: decryptText(card.encryptedPhone),
        source: card.source,
        status: card.status,
        createdAt: card.createdAt
      }));

      return {
        status: 200,
        jsonBody: {
          ok: true,
          count: rows.length,
          rows
        }
      };
    } catch (error) {
      context.error(error);
      return {
        status: 500,
        jsonBody: {
          ok: false,
          message: 'Could not load admin records.'
        }
      };
    }
  }
});
