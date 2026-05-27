const { app } = require('@azure/functions');
const { listCards } = require('../lib/storage');
const { decryptText } = require('../lib/crypto');

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Admin-Key',
  'Cache-Control': 'no-store'
};

function json(status, body) {
  return { status, headers: corsHeaders, jsonBody: body };
}

function getAdminKey(request) {
  return String(request.headers.get('x-admin-key') || request.query.get('key') || '').trim();
}

function isAuthorized(request) {
  const expected = process.env.ADMIN_ACCESS_KEY;
  if (!expected) return false;
  return getAdminKey(request) === expected;
}

function safeDecrypt(value) {
  try {
    return decryptText(value);
  } catch (_) {
    return '';
  }
}

app.http('adminCards', {
  methods: ['GET', 'OPTIONS'],
  authLevel: 'anonymous',
  route: 'admin/cards',
  handler: async (request, context) => {
    if (request.method === 'OPTIONS') return { status: 204, headers: corsHeaders };

    try {
      if (!isAuthorized(request)) {
        return json(401, { ok: false, message: 'Unauthorized admin access.' });
      }

      const limitRaw = Number(request.query.get('limit') || 1000);
      const limit = Math.min(Math.max(limitRaw || 1000, 1), 5000);
      const cards = await listCards(limit);

      const rows = cards.map((card) => ({
        uniqueId: card.uniqueId || card.rowKey || '',
        name: safeDecrypt(card.encryptedName),
        phone: safeDecrypt(card.encryptedPhone),
        maskedPhone: card.maskedPhone || '',
        status: card.status || '',
        source: card.source || '',
        consentGiven: card.consentGiven === true,
        createdAt: card.createdAt || '',
        updatedAt: card.updatedAt || ''
      }));

      return json(200, {
        ok: true,
        count: rows.length,
        rows
      });
    } catch (error) {
      context.error(error);
      return json(500, { ok: false, message: 'Admin database load failed.' });
    }
  }
});
