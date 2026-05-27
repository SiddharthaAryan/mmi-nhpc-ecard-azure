const { app } = require('@azure/functions');
const { encryptText, keyedHash, maskPhone } = require('../lib/crypto');
const { getCardByPhoneHash, upsertCard } = require('../lib/storage');
const { requireAdmin } = require('../lib/auth');

function cleanPhone(phone) {
  return String(phone || '').replace(/\D/g, '');
}

function cleanName(name) {
  return String(name || 'MMI Family Member')
    .replace(/[<>]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 80) || 'MMI Family Member';
}

function makeCardId() {
  const prefix = process.env.CARD_PREFIX || 'NHPC-AZ';
  const now = Date.now().toString(36).toUpperCase();
  const random = Math.random().toString(36).slice(2, 6).toUpperCase();
  return `${prefix}-${now}-${random}`;
}

app.http('bulkCreate', {
  methods: ['POST'],
  authLevel: 'anonymous',
  route: 'admin/bulkCreate',
  handler: async (request, context) => {
    try {
      const auth = requireAdmin(request);
      if (!auth.ok) return auth.response;

      const body = await request.json().catch(() => ({}));
      const inputRows = Array.isArray(body.rows) ? body.rows : [];

      if (inputRows.length === 0) {
        return { status: 400, jsonBody: { ok: false, message: 'No rows received.' } };
      }

      if (inputRows.length > 1000) {
        return { status: 400, jsonBody: { ok: false, message: 'Upload max 1000 rows per batch.' } };
      }

      const output = [];
      const skipped = [];
      const seen = new Set();

      for (let i = 0; i < inputRows.length; i++) {
        const row = inputRows[i];
        const phone = cleanPhone(row.phone || row.Number || row.number || row.Mobile || row.mobile);
        const name = cleanName(row.name || row.Name || row['Full Name']);

        if (!/^[0-9]{10}$/.test(phone)) {
          skipped.push({ row: i + 1, reason: 'Invalid phone number' });
          continue;
        }

        if (seen.has(phone)) {
          skipped.push({ row: i + 1, reason: 'Duplicate inside upload', phone: maskPhone(phone) });
          continue;
        }

        seen.add(phone);
        const phoneHash = keyedHash(phone);
        const existing = await getCardByPhoneHash(phoneHash);

        if (existing) {
          output.push({
            serial: row.Serial || row.serial || i + 1,
            name,
            number: phone,
            maskedPhone: existing.maskedPhone,
            uniqueId: existing.uniqueId,
            status: 'Existing ID reused'
          });
          continue;
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
          source: 'bulk',
          consentGiven: true,
          createdAt,
          updatedAt: createdAt,
          createdBy: auth.email
        };

        await upsertCard({ partitionKey: 'PHONE', rowKey: phoneHash, ...baseData });
        await upsertCard({ partitionKey: 'CARD', rowKey: uniqueId, ...baseData });

        output.push({
          serial: row.Serial || row.serial || i + 1,
          name,
          number: phone,
          maskedPhone: maskPhone(phone),
          uniqueId,
          status: 'New ID generated'
        });
      }

      return {
        status: 200,
        jsonBody: {
          ok: true,
          createdOrReused: output.length,
          skippedCount: skipped.length,
          rows: output,
          skipped
        }
      };
    } catch (error) {
      context.error(error);
      return {
        status: 500,
        jsonBody: {
          ok: false,
          message: 'Bulk creation failed.'
        }
      };
    }
  }
});
