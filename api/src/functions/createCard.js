const { app } = require('@azure/functions');
const { encryptText, decryptText, keyedHash, maskPhone } = require('../lib/crypto');
const { getCardByPhoneHash, upsertCard, listCards } = require('../lib/storage');

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Cache-Control': 'no-store'
};

function json(status, body) {
  return { status, headers: corsHeaders, jsonBody: body };
}

function cleanPhone(phone) {
  return String(phone || '').replace(/\D/g, '');
}

function cleanName(name) {
  return String(name || '')
    .replace(/[<>]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 80);
}

function makeCardId() {
  const prefix = process.env.CARD_PREFIX || 'NHPC-AZ';
  const now = Date.now().toString(36).toUpperCase();
  const random = Math.random().toString(36).slice(2, 6).toUpperCase();
  return `${prefix}-${now}-${random}`;
}

function safeDecrypt(value) {
  try {
    return decryptText(value);
  } catch (_) {
    return '';
  }
}

async function handleAdminRequest(request) {
  const expected = process.env.ADMIN_ACCESS_KEY;
  const provided = String(request.query.get('key') || '').trim();

  if (!expected || provided !== expected) {
    return json(401, { ok: false, message: 'Unauthorized admin access.' });
  }

  const limitRaw = Number(request.query.get('limit') || 5000);
  const limit = Math.min(Math.max(limitRaw || 5000, 1), 5000);
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
}

app.http('createCard', {
  methods: ['GET', 'POST', 'OPTIONS'],
  authLevel: 'anonymous',
  route: 'createCard',
  handler: async (request, context) => {
    if (request.method === 'OPTIONS') {
      return { status: 204, headers: corsHeaders };
    }

    try {
      if (request.method === 'GET') {
        if (request.query.get('admin') === '1') {
          return await handleAdminRequest(request);
        }
        return json(200, { ok: true, message: 'createCard API is live.' });
      }

      const body = await request.json().catch(() => ({}));

      // Honeypot: real users will never fill this hidden field.
      if (body.companyWebsite) {
        return json(400, { ok: false, message: 'Invalid request.' });
      }

      const name = cleanName(body.name);
      const phone = cleanPhone(body.phone);
      const consent = body.consent === true;
      const source = String(body.source || 'public-form').slice(0, 40);

      if (!name) {
        return json(400, { ok: false, message: 'Name is required.' });
      }

      if (!/^[0-9]{10}$/.test(phone)) {
        return json(400, { ok: false, message: 'Enter a valid 10-digit WhatsApp number.' });
      }

      if (!consent) {
        return json(400, { ok: false, message: 'Consent is required to generate the card.' });
      }

      const phoneHash = keyedHash(phone);
      const existing = await getCardByPhoneHash(phoneHash);

      if (existing) {
        return json(200, {
          ok: true,
          reused: true,
          uniqueId: existing.uniqueId,
          maskedPhone: existing.maskedPhone,
          message: 'Existing card reused for this number.'
        });
      }

      const uniqueId = makeCardId();
      const createdAt = new Date().toISOString();

      const baseData = {
        uniqueId,
        phoneHash,
        encryptedName: encryptText(name),
        encryptedPhone: encryptText(phone),
        maskedPhone: maskPhone(phone),
        status: 'active',
        source,
        consentGiven: true,
        createdAt,
        updatedAt: createdAt
      };

      await upsertCard({
        partitionKey: 'PHONE',
        rowKey: phoneHash,
        ...baseData
      });

      await upsertCard({
        partitionKey: 'CARD',
        rowKey: uniqueId,
        ...baseData
      });

      return json(201, {
        ok: true,
        reused: false,
        uniqueId,
        maskedPhone: maskPhone(phone),
        message: 'Card created successfully.'
      });
    } catch (error) {
      context.error(error);
      return json(500, {
        ok: false,
        message: request.method === 'GET' ? 'Admin database load failed.' : 'Card generation failed. Please contact the admin.'
      });
    }
  }
});
